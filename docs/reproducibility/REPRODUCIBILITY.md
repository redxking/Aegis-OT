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

For the bounded M4a capability smoke check, use:

```bash
.venv/bin/aegis-ot capability-smoke
```

In PyCharm, use `.venv/bin/aegis-ot` as the script path,
`capability-smoke` as the parameters, and the repository root as the working
directory. On Windows, use `.venv\Scripts\aegis-ot.exe`. If an editable install
has not yet been completed, use `.venv/bin/python` with parameters `-m
aegis_ot.cli capability-smoke` and configure `src` as a Sources Root or set
`PYTHONPATH=src`.

## Verification sequence

Run these commands from the repository root before recording an experiment:

```bash
.venv/bin/python scripts/export_schemas.py --check
.venv/bin/python scripts/build_public_demo.py --check
.venv/bin/ruff check .
.venv/bin/mypy src scripts/build_public_demo.py
.venv/bin/python -m pytest \
  --cov=aegis_ot --cov-branch --cov-report=term-missing --cov-fail-under=90
docker compose config --quiet
AEGIS_TLA_JAR=/absolute/path/to/tla2tools-1.8.0.jar
.venv/bin/python scripts/run_formal.py \
  --jar "$AEGIS_TLA_JAR" \
  --output-dir /private/tmp/aegis-formal-check
```

The isolated candidate tree produces 478 passing tests and 92.05 percent
branch-aware coverage. That run used the committed retained-evidence files while
leaving user-modified result files untouched in the primary working tree. Ruff,
strict mypy, and schema-drift checks are clean locally. The previously verified
bounded intended and weakened formal-model evidence is unchanged. These
observations are local evidence only. They do not establish a remote CI result,
container startup, deployed isolation, physical validity, or independent
replication.

Schema checking covers `ActionProposal`; the M3 physical-state, physical
command, candidate assessment, execution permit, acknowledgment,
closed-loop-result, and signed Modbus request/response contracts; and the M4a
action-request, signed-observation, execution-permit, PLC-acknowledgment,
closed-loop-result, and IPC-frame contracts. Compose
configuration validation checks interpolation and structure; the current M3
experiment runs directly from the Python environment and is not exercised by
the Compose services.

## M4a smoke-check evidence boundary

`capability-smoke` starts a deterministic local stack, performs one candidate
transaction, and reports the terminal state, live process identifiers,
component health counters, dispatch and retry counts, and whether the in-memory
transaction chain verified before shutdown. A successful run is a local
implementation smoke observation. It is not an experiment package.

The command does not export the signed pre/post observations, permit, PLC
acknowledgment, trust-anchor public keys, negative capability-probe results, or
orderly-restart replay provenance. The controller evidence chain exists only in
memory, and the temporary replay-reservation directory is removed when the
stack closes. The output therefore cannot be used as a retained, reproduced, or
offline-verifiable M4a result. A future evidence milestone requires an explicit
manifest, canonical artifact serialization, trust-anchor registration, hashes,
an offline verifier, a new output directory per run, and an independently
defined replication protocol.

The M4a topology is bounded to distinct spawned processes on one host under the
same OS user, filesystem, and clock. The separately keyed observer reads the
same authoritative deterministic plant used for candidate simulation, and its
post snapshot links directly to that transaction's pre snapshot rather than a
continuous global observation chain. Replay transfer covers one orderly
virtual-PLC child replacement within the running lab; host crash, power loss,
filesystem tampering, and full-stack restart are outside scope. The command does
not establish segmentation, hostile-coordinator isolation, concurrent-controller
behavior, HELICS, OpenPLC or physical-PLC behavior, hardware-in-the-loop,
external validation, operational effectiveness, or WP4 exit.

## Controlled M3 run

The operator run record identifies commit
`168b8bd61a13f70e0871d36e56acbe76a8ebb659` as the prepared clean checkout
for the primary controlled run and one local reproduction completed on
2026-08-24. The unsigned manifests record matching source and
`requirements.lock` hashes, host metadata, Python 3.14.7, pandapower 3.5.4, and
PyModbus 3.15.0; they do not attest the complete installed environment. The
primary package is retained at
`results/m3-physical-modbus`; the second package is retained separately at
`results/m3-physical-modbus-reproduction`. Do not overwrite either directory.

The recorded experiment commands were:

```bash
/private/tmp/aegis-ot-m3-run-venv-168b8bd/bin/aegis-ot physical-experiment \
  --seed-count 30 \
  --seed 20260824 \
  --output-dir /private/tmp/aegis-m3-controlled-168b8bd
/private/tmp/aegis-ot-m3-run-venv-168b8bd/bin/aegis-ot physical-experiment \
  --seed-count 30 \
  --seed 20260824 \
  --output-dir /private/tmp/aegis-m3-reproduction-168b8bd
```

Those two completed output trees were copied byte-for-byte into the retained
repository paths identified above; the original experiment directories were not
used as later-run destinations.

For a future repeat run:

1. Commit the implementation and verification changes.
2. Confirm `git status --short` is empty.
3. Use a new, empty result directory; never overwrite a retained raw run.
4. Run all verification commands above.
5. Execute the 30-session command from the same `.venv`:

```bash
.venv/bin/aegis-ot physical-experiment \
  --seed-count 30 \
  --seed 20260824 \
  --output-dir /private/tmp/aegis-m3-unique-run
```

Each seed starts one fresh virtual-device/plant child process. Each session runs
five deterministic conformance conditions in a fixed order: unknown identity,
stale state, a permit whose audience field is altered after signing, nominal
permitted execution, and permit replay. Each retained run therefore has 30
process sessions and 150 trial records. The altered field also invalidates the
original signature; because the device checks audience first, this condition
does not exercise a validly signed wrong-audience permit.
Seeds vary identifiers and process sessions; they do not introduce stochastic
physical behavior.

The primary and reproduction manifests each report 30 sessions, 150 trials, and
270 evidence events. From the matching clean checkout, both pass every
registered offline-verifier check and produce
the same deterministic outcome hash:

```text
150b32da0055da6086a8f858f8dab4425d06b5bfd836ba653a10c1f20adf9005
```

Verify the retained copies from a checkout whose source, schema, project, and
lock hashes match the manifest:

```bash
.venv/bin/aegis-ot verify-physical-evidence \
  --output-dir results/m3-physical-modbus
.venv/bin/aegis-ot verify-physical-evidence \
  --output-dir results/m3-physical-modbus-reproduction
```

The verifier opens no Modbus socket. It validates package/current-checkout
internal consistency; it does not authenticate the unsigned manifest, establish
custody, or independently verify the self-asserted historical Git and host
metadata. The second manifest records the same source and lock-file hashes,
host metadata, Python version, and selected component versions; it is therefore
a local outcome reproduction under matching recorded conditions, not proof of
an identical environment or independent replication.

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
hash, host details, simulator and protocol versions, model digest, boundary
description, analyst, and known limitations. It binds the separate benchmark
provenance and solver-configuration artifacts by hash. Wall-clock latency
remains in the raw evidence but is excluded from
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

The bounded local process-boundary evaluation is complete. WP4 remains in
progress until the HELICS, OpenPLC, segmented-deployment, hardware, and external
validation gates are separately implemented and evaluated. Tests and retained
manifests support only the exact local implementation, configuration,
conditions, and evidence recorded.
