"""Run the intended TLA+ model and targeted weakened configurations."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ModelCase:
    name: str
    scenario: str | None = None
    override: tuple[str, str] | None = None
    expected_invariant: str | None = None


CASES = (
    ModelCase("intended"),
    ModelCase(
        "weak-authentication",
        "unauthenticated",
        ("EnforceAuthentication", "FALSE"),
        "NoUnauthenticatedExecution",
    ),
    ModelCase(
        "weak-delegation",
        "delegation",
        ("EnforceDelegation", "FALSE"),
        "NoDelegationAmplification",
    ),
    ModelCase("weak-scope", "scope", ("EnforceScope", "FALSE"), "NoOutOfScopeExecution"),
    ModelCase("weak-safety", "unsafe", ("EnforceSafety", "FALSE"), "NoUnsafeModeledExecution"),
    ModelCase("weak-replay", "replay", ("EnforceReplay", "FALSE"), "NoReplay"),
    ModelCase(
        "weak-revocation",
        "revoked",
        ("EnforceRevocation", "FALSE"),
        "NoExecutionAfterEffectiveRevocation",
    ),
    ModelCase("weak-expiry", "expired", ("EnforceExpiry", "FALSE"), "NoExecutionAfterExpiry"),
    ModelCase("weak-policy", "policy", ("EnforcePolicy", "FALSE"), "PolicyVersionConsistency"),
    ModelCase("weak-freshness", "stale", ("EnforceFreshness", "FALSE"), "FreshProposalRequired"),
    ModelCase("weak-approval", "approval", ("EnforceApproval", "FALSE"), "HumanApprovalRequired"),
    ModelCase("weak-conflict", "conflict", ("EnforceConflict", "FALSE"), "NoConflictingExecution"),
    ModelCase("weak-toctou", "toctou", ("EnforceTOCTOU", "FALSE"), "NoTOCTOUExecution"),
    ModelCase(
        "weak-acknowledgment",
        "acknowledgment",
        ("EnforceAcknowledgment", "FALSE"),
        "AcknowledgmentRequired",
    ),
    ModelCase(
        "weak-decision-evidence",
        "evidence",
        ("WriteDecisionEvidence", "FALSE"),
        "EvidenceCompleteness",
    ),
    ModelCase(
        "weak-execution-evidence",
        "evidence",
        ("WriteExecutionEvidence", "FALSE"),
        "EvidenceCompleteness",
    ),
    ModelCase(
        "weak-quarantine",
        "compromise",
        ("EnforceQuarantine", "FALSE"),
        "NoQuarantinedExecution",
    ),
)

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_text(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def generated_config(base: str, case: ModelCase) -> str:
    if case.scenario is None:
        return base
    config = re.sub(
        r"(?m)^  Scenarios = \{.*\}$",
        f"  Scenarios = {{{case.scenario}}}",
        base,
    )
    if case.override is None:
        raise ValueError(f"weakened case {case.name} is missing an override")
    key, value = case.override
    config, count = re.subn(
        rf"(?m)^  {re.escape(key)} = (TRUE|FALSE)$",
        f"  {key} = {value}",
        config,
    )
    if count != 1:
        raise ValueError(f"could not apply exactly one override for {key}")
    return config


def parse_metric(pattern: str, output: str) -> int | None:
    matches = re.findall(pattern, output)
    return int(matches[-1].replace(",", "")) if matches else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jar", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    model = root / "formal" / "AegisAuthorization.tla"
    base_config_path = root / "formal" / "AegisAuthorization.cfg"
    output_dir = args.output_dir.resolve()
    git_commit = run_text(["git", "rev-parse", "HEAD"], root).stdout.strip()
    git_dirty = bool(run_text(["git", "status", "--porcelain"], root).stdout.strip())
    java_version = run_text(["java", "-version"], root).stderr.splitlines()[0]
    help_result = run_text(["java", "-jar", str(args.jar), "-help"], root)
    tool_output = ANSI.sub("", help_result.stdout + help_result.stderr)
    tool_match = re.search(r"Version ([^\n]+)", tool_output)
    tool_version = tool_match.group(1).strip() if tool_match else "unknown"

    output_dir.mkdir(parents=True, exist_ok=True)
    base_config = base_config_path.read_text(encoding="utf-8")
    results: list[dict[str, object]] = []
    failures: list[str] = []

    for case in CASES:
        case_dir = output_dir / case.name
        case_dir.mkdir(parents=True, exist_ok=True)
        config_path = case_dir / "AegisAuthorization.cfg"
        config_path.write_text(generated_config(base_config, case), encoding="utf-8")
        state_dir = case_dir / ".tlc-state"
        command = [
            "java",
            "-XX:+UseParallelGC",
            "-jar",
            str(args.jar.resolve()),
            "-cleanup",
            "-deadlock",
            "-noGenerateSpecTE",
            "-metadir",
            str(state_dir),
            "-workers",
            str(args.workers),
            "-config",
            str(config_path),
            str(model),
        ]
        started = time.perf_counter()
        completed = run_text(command, root)
        runtime_seconds = round(time.perf_counter() - started, 6)
        shutil.rmtree(state_dir, ignore_errors=True)
        output = ANSI.sub("", completed.stdout + completed.stderr)
        (case_dir / "tlc-output.txt").write_text(output, encoding="utf-8")
        violation_match = re.search(r"Invariant ([A-Za-z0-9_]+) is violated", output)
        observed_invariant = violation_match.group(1) if violation_match else None
        passed = (
            completed.returncode == 0
            if case.expected_invariant is None
            else completed.returncode != 0 and observed_invariant == case.expected_invariant
        )
        if not passed:
            failures.append(case.name)
        results.append(
            {
                **asdict(case),
                "passed_expectation": passed,
                "return_code": completed.returncode,
                "observed_invariant": observed_invariant,
                "states_generated": parse_metric(r"([0-9,]+) states generated", output),
                "distinct_states": parse_metric(r"([0-9,]+) distinct states found", output),
                "search_depth": parse_metric(
                    r"depth of the complete state graph search is ([0-9,]+)", output
                ),
                "runtime_seconds": runtime_seconds,
                "config_sha256": sha256(config_path),
            }
        )

    manifest = {
        "analyst": "Angelis Pseftis",
        "evidence_class": "bounded-formal-model-check",
        "tool": "TLC",
        "tool_version": tool_version,
        "tool_jar_sha256": sha256(args.jar),
        "java_version": java_version,
        "host": platform.platform(),
        "git_commit": git_commit,
        "git_dirty_at_start": git_dirty,
        "model_path": str(model.relative_to(root)),
        "model_sha256": sha256(model),
        "base_config_path": str(base_config_path.relative_to(root)),
        "base_config_sha256": sha256(base_config_path),
        "all_expectations_met": not failures,
        "failed_cases": failures,
        "cases": results,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
