from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import subprocess
import uuid
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return import_module("run_m8_traceability")


def _source_binding(runner: Any) -> dict[str, Any]:
    binding: dict[str, Any] = {
        "git_commit": "a" * 40,
        "git_tree": "b" * 40,
        "clean_checkout": True,
        "source_files": [
            {
                "path": path,
                "bytes": index + 1,
                "sha256": f"{index + 1:x}" * 64,
                "git_mode": "100644",
                "git_blob": f"{index + 5:x}" * 40,
            }
            for index, path in enumerate(runner.SOURCE_PATHS)
        ],
    }
    binding["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(binding)
    )
    return binding


def _rehash_report(runner: Any, report: dict[str, Any]) -> None:
    report.pop("integrity", None)
    report["integrity"] = {"canonical_payload_sha256": runner._sha256_json(report)}


def _rehash_semantic_report(runner: Any, report: dict[str, Any]) -> None:
    projection = report["traceability_report"]
    gates = runner._acceptance_gates(
        projection,
        canonical_matches=True,
        source_bound=True,
    )
    report["open_state"] = runner._projection_open_state(projection)
    report["package_integrity_gates"] = gates
    report["package_integrity_accepted"] = all(gates.values())
    report["semantic_outcome_sha256"] = runner._sha256_json(
        runner._semantic_projection(projection, gates)
    )
    _rehash_report(runner, report)


def _private_evidence_path(
    runner: Any,
    tmp_path: Path,
    report: dict[str, Any] | bytes,
    *,
    suffix: str,
) -> Path:
    directory = tmp_path / f"{runner.OUTPUT_PREFIX}{suffix}"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "evidence.json"
    if isinstance(report, bytes):
        path.write_bytes(report)
    else:
        path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


def _run_git(root: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603 - test-owned repository fixture
        ("/usr/bin/git", "-C", str(root), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _repository(runner: Any, tmp_path: Path) -> Path:
    repository = (tmp_path / "repository").resolve()
    repository.mkdir()
    for relative in runner.SOURCE_PATHS:
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    _run_git(repository, "init", "-q")
    _run_git(repository, "add", "--", *runner.SOURCE_PATHS)
    _run_git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    return repository


def test_plan_is_fixed_read_only_and_claims_no_execution_or_acceptance(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("plan mode inspected source or rebuilt the projection")

    monkeypatch.setattr(runner, "_assert_clean_source", forbidden)
    monkeypatch.setattr(runner, "_rebuild_traceability_projection", forbidden)
    before = tuple(tmp_path.iterdir())

    plan = runner.build_plan()

    assert tuple(tmp_path.iterdir()) == before
    assert plan["schema_version"] == "aegis-ot-m8-traceability-plan-v1"
    assert plan["execution_mode"] == "plan_only"
    assert plan["execution_claimed"] is False
    assert plan["package_integrity_accepted"] is False
    assert plan["system_requirements_accepted"] is False
    assert plan["projection_contract"] == {
        "requirements_tracked": 223,
        "requirements_open": 223,
        "requirements_accepted": 0,
        "tbrs_tracked": 35,
        "tbrs_open": 35,
        "baseline_status": "proposed_not_approved",
        "end_state_accepted": False,
    }
    assert plan["source_paths"] == list(runner.SOURCE_PATHS)
    assert tuple(plan["acceptance_gate_names"]) == runner.ACCEPTANCE_GATE_NAMES


def test_rebuild_retains_the_entire_canonical_open_projection(runner: Any) -> None:
    projection = runner._rebuild_traceability_projection()

    runner._validate_projection(projection)
    assert projection["source"]["path"] == runner.DOCX_RELATIVE_PATH
    assert projection["source"]["status"] == "proposed_not_approved"
    assert projection["summary"]["requirements_tracked"] == 223
    assert projection["summary"]["requirements_open"] == 223
    assert projection["summary"]["requirements_accepted"] == 0
    assert projection["summary"]["tbrs_tracked"] == 35
    assert projection["summary"]["tbrs_open"] == 35
    assert projection["summary"]["end_state_accepted"] is False
    assert len(projection["requirements"]) == 223
    assert len(projection["tbrs"]) == 35
    assert all(
        record["verification"]["result"] == "not_assessed"
        and record["disposition"]["claim_state"] == "C0"
        and record["disposition"]["finding_status"] == "open"
        for record in projection["requirements"]
    )
    assert all(item["status"] == "open" for item in projection["tbrs"])


def test_package_acceptance_never_becomes_requirement_or_end_state_acceptance(
    runner: Any,
) -> None:
    projection = runner._rebuild_traceability_projection()
    report = runner._build_report(_source_binding(runner), projection)

    assert report["package_integrity_accepted"] is True
    assert all(report["package_integrity_gates"].values())
    assert report["system_acceptance"] == {
        "baseline_approved": False,
        "requirements_accepted": 0,
        "requirements_open": 223,
        "tbrs_open": 35,
        "end_state_accepted": False,
        "g7_completed": False,
        "independent_validation_established": False,
        "deployment_established": False,
        "operational_effectiveness_established": False,
    }
    assert "Acceptance means only" in report["acceptance_scope"]
    assert "not approval" in report["acceptance_scope"]
    assert "G7 completion" in report["acceptance_scope"]
    assert "deployment" in report["acceptance_scope"]
    assert report["external_boundaries"]["g7"]["status"] == "external_not_completed"
    assert (
        report["external_boundaries"]["independent_validation"]["status"]
        == "external_not_established"
    )
    assert report["external_boundaries"]["deployment"]["status"] == (
        "external_not_established"
    )


def test_semantic_hash_is_stable_across_run_metadata(runner: Any) -> None:
    projection = runner._rebuild_traceability_projection()
    binding = _source_binding(runner)
    first = runner._build_report(
        binding,
        projection,
        run_id=str(uuid.UUID(int=1)),
        generated_at=datetime(2026, 8, 26, 10, 0, tzinfo=UTC),
    )
    second = runner._build_report(
        binding,
        projection,
        run_id=str(uuid.UUID(int=2)),
        generated_at=datetime(2026, 8, 26, 11, 0, tzinfo=UTC),
    )

    assert first["run_id"] != second["run_id"]
    assert first["generated_at"] != second["generated_at"]
    assert first["semantic_outcome_sha256"] == second["semantic_outcome_sha256"]
    assert first["semantic_outcome_sha256"] == (
        "99013f7eeb7cd706736bf8cd92f00ee2d4efb41274636642ff1eddc7f5565cde"
    )
    assert first["integrity"] != second["integrity"]
    assert first["traceability_report"]["catalog_sha256"] == (
        "d03db35e241aae20e7e55d9cc4d363e0b3b7d1d64ec9c9031735c3f5a8b3a93e"
    )


def test_verifier_rejects_fully_rehashed_requirement_projection_tampering(
    runner: Any,
) -> None:
    projection = runner._rebuild_traceability_projection()
    binding = _source_binding(runner)
    report = runner._build_report(binding, projection)
    tampered = copy.deepcopy(report)
    first = tampered["traceability_report"]["requirements"][0]
    first["identity"]["normative_text"] += " Altered."
    first["change_history"][0]["new_text"] = first["identity"]["normative_text"]
    catalog_material = {
        "requirements": tampered["traceability_report"]["requirements"],
        "tbrs": tampered["traceability_report"]["tbrs"],
        "gates": tampered["traceability_report"]["gates"],
        "claim_states": tampered["traceability_report"]["claim_states"],
    }
    tampered["traceability_report"]["catalog_sha256"] = runner._sha256_json(
        catalog_material
    )
    _rehash_semantic_report(runner, tampered)

    with pytest.raises(runner.CampaignError, match="does not rebuild exactly"):
        runner._verify_report_payload(
            tampered,
            expected_source_binding=binding,
            expected_projection=projection,
        )


def test_verifier_rejects_rehashed_false_acceptance_and_tbr_closure(runner: Any) -> None:
    projection = runner._rebuild_traceability_projection()
    binding = _source_binding(runner)
    report = runner._build_report(binding, projection)

    accepted = copy.deepcopy(report)
    accepted["traceability_report"]["summary"]["requirements_accepted"] = 1
    accepted["traceability_report"]["summary"]["requirements_open"] = 222
    _rehash_semantic_report(runner, accepted)
    with pytest.raises(runner.CampaignError, match="exact open state"):
        runner._verify_report_payload(
            accepted,
            expected_source_binding=binding,
            expected_projection=projection,
        )

    closed_tbr = copy.deepcopy(report)
    closed_tbr["traceability_report"]["tbrs"][0]["status"] = "closed"
    _rehash_semantic_report(runner, closed_tbr)
    with pytest.raises(runner.CampaignError, match="TBRs are not explicitly open"):
        runner._verify_report_payload(
            closed_tbr,
            expected_source_binding=binding,
            expected_projection=projection,
        )


def test_source_binding_records_exact_clean_commit_tree_and_four_blobs(
    runner: Any,
    tmp_path: Path,
) -> None:
    repository = _repository(runner, tmp_path)

    binding = runner._source_binding(repository)

    assert binding["clean_checkout"] is True
    assert binding["git_commit"] == _run_git(repository, "rev-parse", "HEAD").strip()
    assert binding["git_tree"] == _run_git(repository, "rev-parse", "HEAD^{tree}").strip()
    assert [item["path"] for item in binding["source_files"]] == list(
        runner.SOURCE_PATHS
    )
    assert len({item["git_blob"] for item in binding["source_files"]}) == 4
    assert all(item["git_mode"] in {"100644", "100755"} for item in binding["source_files"])
    runner._verify_source_binding_shape(binding)


@pytest.mark.parametrize("drift", ["tracked", "untracked"])
def test_source_binding_rejects_any_checkout_drift(
    runner: Any,
    tmp_path: Path,
    drift: str,
) -> None:
    repository = _repository(runner, tmp_path)
    if drift == "tracked":
        path = repository / "pyproject.toml"
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        (repository / "unexpected.txt").write_text("drift\n", encoding="utf-8")

    with pytest.raises(runner.CampaignError, match="exact clean checkout"):
        runner._source_binding(repository)


def test_source_reader_rejects_symlink_hardlink_and_traversal_abuse(
    runner: Any,
    tmp_path: Path,
) -> None:
    repository = _repository(runner, tmp_path)
    module = repository / "src/aegis_ot/m8_traceability.py"
    alias = tmp_path / "module-alias.py"
    shutil.copy2(module, alias)
    module.unlink()
    module.symlink_to(alias)
    with pytest.raises(runner.CampaignError, match="regular non-symlink"):
        runner._read_regular_source(repository, "src/aegis_ot/m8_traceability.py")

    module.unlink()
    os.link(alias, module)
    assert _run_git(repository, "status", "--porcelain=v1") == ""
    with pytest.raises(runner.CampaignError, match="exactly one hard link"):
        runner._source_binding(repository)

    with pytest.raises(runner.CampaignError, match="unsafe"):
        runner._read_regular_source(repository, "../module-alias.py")


def test_source_binding_shape_requires_exact_paths_blobs_and_fingerprint(runner: Any) -> None:
    binding = _source_binding(runner)
    runner._verify_source_binding_shape(binding)

    missing = copy.deepcopy(binding)
    missing["source_files"].pop()
    missing["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(missing)
    )
    with pytest.raises(runner.CampaignError, match="exact source path set"):
        runner._verify_source_binding_shape(missing)

    wrong_blob = copy.deepcopy(binding)
    wrong_blob["source_files"][0]["git_blob"] = "c" * 41
    with pytest.raises(runner.CampaignError, match="noncanonical"):
        runner._verify_source_binding_shape(wrong_blob)

    wrong_fingerprint = copy.deepcopy(binding)
    wrong_fingerprint["source_fingerprint_sha256"] = "0" * 64
    with pytest.raises(runner.CampaignError, match="source fingerprint"):
        runner._verify_source_binding_shape(wrong_fingerprint)


def test_assert_clean_source_rejects_stale_module_import(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "_source_binding", lambda _root: _source_binding(runner))
    original = runner.m8.__file__
    monkeypatch.setattr(runner.m8, "__file__", str(tmp_path / "stale.py"))

    with pytest.raises(runner.CampaignError, match="imported from stale source"):
        runner._assert_clean_source()

    monkeypatch.setattr(runner.m8, "__file__", original)
    assert runner._assert_clean_source() == _source_binding(runner)


def test_retained_run_uses_unique_private_output_and_rebuilds_during_verification(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _source_binding(runner)
    projection = runner._rebuild_traceability_projection()
    rebuilds = 0

    def clean_source() -> dict[str, Any]:
        return copy.deepcopy(binding)

    def rebuild() -> dict[str, Any]:
        nonlocal rebuilds
        rebuilds += 1
        return copy.deepcopy(projection)

    monkeypatch.setattr(runner, "_assert_clean_source", clean_source)
    monkeypatch.setattr(runner, "_rebuild_traceability_projection", rebuild)

    first = runner.run_campaign(tmp_path)
    second = runner.run_campaign(tmp_path)

    assert first != second
    assert rebuilds == 4
    assert first.parent.parent == tmp_path
    assert first.parent.name.startswith(runner.OUTPUT_PREFIX)
    assert stat.S_IMODE(first.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert first.stat().st_nlink == 1
    retained_first = runner._load_report(first)
    retained_second = runner._load_report(second)
    assert retained_first["package_integrity_accepted"] is True
    assert retained_first["semantic_outcome_sha256"] == retained_second[
        "semantic_outcome_sha256"
    ]
    verification = runner.verify_evidence(first)
    assert rebuilds == 5
    assert verification["package_integrity_accepted"] is True
    assert verification["baseline_approved"] is False
    assert verification["requirements_open"] == 223
    assert verification["requirements_accepted"] == 0
    assert verification["tbrs_open"] == 35
    assert verification["end_state_accepted"] is False
    assert verification["g7_completed"] is False
    assert verification["independent_validation_established"] is False
    assert verification["deployment_established"] is False


def test_run_rejects_checkout_symlink_and_relative_output_parents(
    runner: Any,
    tmp_path: Path,
) -> None:
    with pytest.raises(runner.CampaignError, match="outside the source checkout"):
        runner._validate_output_parent(runner.ROOT)

    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(runner.CampaignError, match="canonical non-symlink"):
        runner._validate_output_parent(linked)

    with pytest.raises(runner.CampaignError, match="absolute traversal-free"):
        runner._validate_output_parent(Path("relative"))


def test_loader_rejects_duplicate_keys_and_nonfinite_json(
    runner: Any,
    tmp_path: Path,
) -> None:
    duplicate = _private_evidence_path(
        runner,
        tmp_path,
        b'{"outer":{"state":"open","state":"closed"}}',
        suffix="duplicate",
    )
    with pytest.raises(runner.CampaignError, match="duplicate JSON key"):
        runner._load_report(duplicate)

    nonfinite = _private_evidence_path(
        runner,
        tmp_path,
        b'{"value":NaN}',
        suffix="nonfinite",
    )
    with pytest.raises(runner.CampaignError, match="prohibited nonfinite"):
        runner._load_report(nonfinite)


def test_loader_rejects_symlink_hardlink_and_traversal_paths(
    runner: Any,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    symlink_directory = tmp_path / f"{runner.OUTPUT_PREFIX}symlink-file"
    symlink_directory.mkdir(mode=0o700)
    symlink_directory.chmod(0o700)
    symlink = symlink_directory / "evidence.json"
    symlink.symlink_to(target)
    with pytest.raises(runner.CampaignError, match="regular non-symlink"):
        runner._load_report(symlink)

    hard_linked = _private_evidence_path(
        runner,
        tmp_path,
        b"{}",
        suffix="hard-linked",
    )
    os.link(hard_linked, tmp_path / "outside-hard-link.json")
    with pytest.raises(runner.CampaignError, match="exactly one hard link"):
        runner._load_report(hard_linked)

    canonical = _private_evidence_path(
        runner,
        tmp_path,
        b"{}",
        suffix="traversal",
    )
    traversal = canonical.parent / ".." / canonical.parent.name / "evidence.json"
    with pytest.raises(runner.CampaignError, match="traversal-free"):
        runner._load_report(traversal)

    with pytest.raises(runner.CampaignError, match="absolute"):
        runner._load_report(Path(canonical.parent.name) / "evidence.json")


def test_loader_rejects_permissions_extra_content_and_size(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong_file_mode = _private_evidence_path(
        runner,
        tmp_path,
        b"{}",
        suffix="file-mode",
    )
    wrong_file_mode.chmod(0o644)
    with pytest.raises(runner.CampaignError, match="mode 0600"):
        runner._load_report(wrong_file_mode)

    wrong_directory_mode = _private_evidence_path(
        runner,
        tmp_path,
        b"{}",
        suffix="directory-mode",
    )
    wrong_directory_mode.parent.chmod(0o755)
    with pytest.raises(runner.CampaignError, match="mode 0700"):
        runner._load_report(wrong_directory_mode)

    extra = _private_evidence_path(
        runner,
        tmp_path,
        b"{}",
        suffix="extra",
    )
    (extra.parent / "unexpected").write_text("x", encoding="utf-8")
    with pytest.raises(runner.CampaignError, match="exactly evidence.json"):
        runner._load_report(extra)

    oversized = _private_evidence_path(
        runner,
        tmp_path,
        b"01234567890",
        suffix="oversized",
    )
    monkeypatch.setattr(runner, "MAX_EVIDENCE_BYTES", 10)
    with pytest.raises(runner.CampaignError, match="outside the verifier limit"):
        runner._load_report(oversized)


def test_loader_rejects_noncanonical_directory_symlink(
    runner: Any,
    tmp_path: Path,
) -> None:
    real = tmp_path / f"{runner.OUTPUT_PREFIX}real"
    real.mkdir(mode=0o700)
    real.chmod(0o700)
    evidence = real / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    evidence.chmod(0o600)
    linked = tmp_path / f"{runner.OUTPUT_PREFIX}linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(runner.CampaignError, match="canonical non-symlink"):
        runner._load_report(linked / "evidence.json")


def test_offline_verifier_requires_exact_current_source_binding(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = runner._rebuild_traceability_projection()
    retained_binding = _source_binding(runner)
    report = runner._build_report(retained_binding, projection)
    path = _private_evidence_path(
        runner,
        tmp_path,
        report,
        suffix="source-mismatch",
    )
    current_binding = copy.deepcopy(retained_binding)
    current_binding["git_commit"] = "c" * 40
    current_binding["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(current_binding)
    )
    monkeypatch.setattr(
        runner,
        "_assert_clean_source",
        lambda: copy.deepcopy(current_binding),
    )
    monkeypatch.setattr(
        runner,
        "_rebuild_traceability_projection",
        lambda: copy.deepcopy(projection),
    )

    with pytest.raises(runner.CampaignError, match="exact current source"):
        runner.verify_evidence(path)


def test_offline_verifier_detects_source_change_during_full_rebuild(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = runner._rebuild_traceability_projection()
    initial = _source_binding(runner)
    report = runner._build_report(initial, projection)
    path = _private_evidence_path(
        runner,
        tmp_path,
        report,
        suffix="source-change",
    )
    changed = copy.deepcopy(initial)
    changed["git_tree"] = "c" * 40
    changed["source_fingerprint_sha256"] = runner._sha256_json(
        runner._source_fingerprint_material(changed)
    )
    calls = 0

    def changing_source() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return copy.deepcopy(initial if calls == 1 else changed)

    monkeypatch.setattr(runner, "_assert_clean_source", changing_source)
    monkeypatch.setattr(
        runner,
        "_rebuild_traceability_projection",
        lambda: copy.deepcopy(projection),
    )

    with pytest.raises(runner.CampaignError, match="was being verified"):
        runner.verify_evidence(path)


def test_generation_time_and_payload_integrity_are_strict(runner: Any) -> None:
    projection = runner._rebuild_traceability_projection()
    binding = _source_binding(runner)
    report = runner._build_report(binding, projection)

    naive = copy.deepcopy(report)
    naive["generated_at"] = "2026-08-26T10:00:00"
    _rehash_report(runner, naive)
    with pytest.raises(runner.CampaignError, match="timezone-aware"):
        runner._verify_report_payload(
            naive,
            expected_source_binding=binding,
            expected_projection=projection,
        )

    corrupted = copy.deepcopy(report)
    corrupted["integrity"]["canonical_payload_sha256"] = "0" * 64
    with pytest.raises(runner.CampaignError, match="canonical payload digest"):
        runner._verify_report_payload(
            corrupted,
            expected_source_binding=binding,
            expected_projection=projection,
        )
