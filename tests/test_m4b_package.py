from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from aegis_ot.m4b_package import verify_m4b_package, write_m4b_experiment

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def retained_package(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path]:
    parent = tmp_path_factory.mktemp("m4b-retained-parent")
    output = parent / "package"
    anchor = parent / "root-anchor.json"
    write_m4b_experiment(
        output,
        trust_anchor_path=anchor,
        root_seed=20260825,
        seed_count=1,
        require_clean_checkout=False,
    )
    return output, anchor


def _writable_copy(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    for directory, _, files in os.walk(destination):
        os.chmod(directory, 0o755)  # noqa: S103 - isolated tamper-test copy
        for name in files:
            os.chmod(Path(directory) / name, 0o644)
    return destination


def test_writer_emits_externally_rooted_package_that_verifies_offline(
    retained_package: tuple[Path, Path],
) -> None:
    package, anchor = retained_package
    result = verify_m4b_package(package, anchor, checkout_root=ROOT)
    assert result["valid"] is True, result["errors"]
    assert result["root_trusted"] is True
    assert result["package_valid"] is True
    assert result["checkout_matches"] is True, result["checkout_errors"]
    assert result["session_count"] == 1
    assert isinstance(result["package_id"], str)
    assert len(result["package_id"]) == 64
    manifest = json.loads((package / "manifest.json").read_bytes())
    dirty_provenance = (
        manifest["git"]["working_tree_dirty_at_start"]
        or manifest["git"]["working_tree_dirty_at_end"]
    )
    assert result["experiment_accepted"] is (not dirty_provenance)
    assert manifest["transaction_record_count"] == 3
    assert manifest["probe_record_count"] == 4
    assert manifest["independent_evaluation_count"] == 1
    assert manifest["analyst"] == "Angelis Pseftis"
    assert anchor.parent == package.parent
    assert not (package / "trust").exists()
    assert package.stat().st_mode & 0o777 == 0o555
    assert (package / "manifest.json").stat().st_mode & 0o777 == 0o444
    assert anchor.stat().st_mode & 0o777 == 0o444


def test_writer_never_overwrites_output_or_anchor(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_m4b_experiment(
            output,
            trust_anchor_path=tmp_path / "unused-anchor.json",
            root_seed=1,
            seed_count=1,
            require_clean_checkout=False,
        )
    assert sentinel.read_text(encoding="utf-8") == "preserve"

    clean_output = tmp_path / "clean-output"
    anchor = tmp_path / "existing-anchor.json"
    anchor.write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_m4b_experiment(
            clean_output,
            trust_anchor_path=anchor,
            root_seed=1,
            seed_count=1,
            require_clean_checkout=False,
        )
    assert not clean_output.exists()
    assert anchor.read_text(encoding="utf-8") == "preserve"


def test_verifier_rejects_artifact_tamper(
    retained_package: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    retained, anchor = retained_package
    package = _writable_copy(retained, tmp_path / "tampered-artifact")
    path = package / "transactions/results.jsonl"
    path.write_bytes(path.read_bytes() + b" ")
    result = verify_m4b_package(package, anchor)
    assert result["package_valid"] is False
    assert any("artifact" in item for item in result["errors"])


def test_verifier_rejects_manifest_tamper(
    retained_package: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    retained, anchor = retained_package
    package = _writable_copy(retained, tmp_path / "tampered-manifest")
    path = package / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["root_seed"] += 1
    path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    result = verify_m4b_package(package, anchor)
    assert result["root_trusted"] is False
    assert result["package_valid"] is False


def test_verifier_rejects_wrong_external_anchor(
    retained_package: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    package, retained_anchor = retained_package
    anchor = tmp_path / "wrong-anchor.json"
    shutil.copy2(retained_anchor, anchor)
    os.chmod(anchor, 0o644)
    value = json.loads(anchor.read_bytes())
    value["anchor_id"] = "substituted-anchor"
    anchor.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    result = verify_m4b_package(package, anchor)
    assert result["root_trusted"] is False
    assert result["package_valid"] is False


def test_verifier_rejects_unregistered_extra_file(
    retained_package: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    retained, anchor = retained_package
    package = _writable_copy(retained, tmp_path / "extra-file")
    (package / "unregistered.txt").write_text("not in manifest", encoding="utf-8")
    result = verify_m4b_package(package, anchor)
    assert result["package_valid"] is False
    assert any("inventory" in item for item in result["errors"])
