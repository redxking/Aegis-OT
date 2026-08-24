# Reproducibility Protocol

Every reported experiment must include a manifest with the Git commit, dirty-tree
state, UTC timestamp, scenario catalog and hash, all master seeds, baselines,
policy, kernel and oracle versions, source hashes, host information, raw-data
location, result hashes, known limitations, and analyst.

Raw result files are append-only research evidence. Derived summaries and figures
must be generated from raw files by committed code. Timing comparisons may vary
by host and load. The raw hash includes timing; the deterministic outcome hash
excludes timing and is the cross-run outcome-reproduction check.

Formal model-check evidence must record the TLC version, model hash, configuration, state count, runtime, invariant result, and any counterexample trace. Passing only the intended model is insufficient; weakened variants must produce expected counterexamples.

## Local environment and PyCharm

Create one repository-local environment and install every dependency group used
by the verification and M3 paths:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,docs,simulation]"
```

In PyCharm, select `.venv/bin/python` as the project interpreter and the
repository root as the working directory. On Windows, use
`.venv\Scripts\python.exe`. A PyCharm terminal smoke run is:

```bash
.venv/bin/aegis-ot physical-experiment \
  --seed-count 1 \
  --seed 20260824 \
  --output-dir /private/tmp/aegis-m3-smoke
```

For a PyCharm run configuration, use `.venv/bin/aegis-ot` as the script path and
`physical-experiment --seed-count 1 --seed 20260824 --output-dir
/private/tmp/aegis-m3-smoke` as its parameters. Use
`.venv\Scripts\aegis-ot.exe` and a suitable temporary output directory on
Windows. The command starts a dynamically addressed loopback listener and one
spawned child process. It must not be changed to bind a non-loopback interface.
When `.venv` is activated, the same entry point can be invoked as
`aegis-ot physical-experiment`.

## Verification sequence

Run these commands from the repository root before recording an experiment:

```bash
.venv/bin/python scripts/export_schemas.py --check
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/python -m pytest \
  --cov=aegis_ot --cov-branch --cov-report=term-missing --cov-fail-under=90
docker compose config --quiet
AEGIS_TLA_JAR=/absolute/path/to/tla2tools-1.8.0.jar
.venv/bin/python scripts/run_formal.py \
  --jar "$AEGIS_TLA_JAR" \
  --output-dir /private/tmp/aegis-formal-check
```

The current local implementation produces 264 passing tests and 91.57 percent
branch-aware coverage. Ruff, strict mypy, schema-drift, bounded intended and
weakened formal-model checks, and Compose configuration validation are clean in
the same local development state. These observations are local evidence only.
They do not establish a remote CI result, container startup, deployed isolation,
physical validity, or independent replication.

Schema checking covers `ActionProposal` and the M3 physical-state, physical
command, candidate assessment, execution permit, acknowledgment,
closed-loop-result, and signed Modbus request/response contracts. Compose
configuration validation checks interpolation and structure; the current M3
experiment runs directly from the Python environment and is not exercised by
the Compose services.

## Controlled M3 run

The controlled M3 experiment is still pending. Before running it:

1. Commit the implementation and verification changes.
2. Confirm `git status --short` is empty.
3. Use a new, empty result directory; never overwrite a retained raw run.
4. Run all verification commands above.
5. Execute the 30-session command from the same `.venv`:

```bash
.venv/bin/aegis-ot physical-experiment \
  --seed-count 30 \
  --seed 20260824 \
  --output-dir results/m3-physical-modbus
```

Each seed starts one fresh virtual-device/plant child process. Each session runs
five deterministic conformance conditions in a fixed order: unknown identity,
stale state, wrong permit audience, nominal permitted execution, and permit
replay. The planned run therefore has 30 process sessions and 150 trial records.
Seeds vary identifiers and process sessions; they do not introduce stochastic
physical behavior.

The result directory must contain:

```text
manifest.json
trials.jsonl
events.jsonl
scenarios.json
summary.json
component-health.json
evidence-verification.json
benchmark/provenance.json
solver/configuration.json
```

The manifest records clean-start Git state, all seeds, process/session counts,
source and configuration hashes, artifact hashes, a timing-independent outcome
hash, host details, simulator and protocol versions, model digest, benchmark
provenance, solver settings, boundary description, analyst, and known
limitations. Wall-clock latency remains in the raw evidence but is excluded from
the deterministic outcome projection. A reproduction must use a separate output
directory and match the deterministic outcome hash before it is described as a
reproduction.

## M3 evidence boundary

The M3 implementation uses a spawned child process, PyModbus over host loopback,
and the pandapower 3.5.4 packaged CIGRE MV network. It is a balanced steady-state
AC power-flow and virtual-device experiment. It is not evidence of:

- HELICS coordination;
- OpenPLC or physical-PLC interoperability;
- electromagnetic-transient, subcycle-protection, relay-timing, or hardware-I/O
  behavior;
- segmented OT networking or multi-VM trust-boundary enforcement;
- SPIFFE/SPIRE or service-backed OPA deployment;
- field effectiveness, hardware-in-the-loop validation, independent replication,
  or external validation.

WP4 and M3 remain in progress until the controlled evidence run and the remaining
integration gates are completed. Tests and a manifest support only the exact
local implementation, configuration, conditions, and evidence recorded.
