# Aegis-OT

Aegis-OT is a defensive research implementation of an independently enforced runtime-assurance control plane for autonomous agents operating against simulated operational-technology environments.

The system treats an agent proposal as data, not authorization. A consequential action is eligible for execution only after the gateway validates workload identity, the complete delegation chain, policy, state freshness, replay status, modeled safety, and any required approval. The implementation does not connect to production OT and does not establish real-world effectiveness.

## Current evidence boundary

This repository is a reconstructed v0.1 foundation created after the original local project package was lost. Earlier commit hashes, test counts, documents, and preliminary results described in the handoff are historical user-provided information; they are not reproduced evidence in this repository. Only results generated from this repository and linked to a manifest may be reported as current measurements.

## Architecture

```text
telemetry -> bounded agent -> ActionProposal -> AegisGateway
                                           |-> identity/delegation
                                           |-> contextual policy
                                           |-> independent safety kernel
                                           |-> replay protection
                                           `-> evidence chain
                                                    |
                                  signed execution permit
                                                    |
                                      command translator
                                                    |
                              signed Modbus mailbox on loopback
                                                    |
                           spawned virtual-device/plant process
                              |-> permit-aware PyModbus device
                              `-> pandapower CIGRE MV model
                                                    |
                                 signed acknowledgment + readback
```

The gateway is the sole authorization route. The current M3 increment places the
virtual device and physical model in a spawned child process and carries commands
through a signed application mailbox over Modbus TCP bound to host loopback. This
is a real process and protocol boundary in the tested local configuration, but it
is not network segmentation, OpenPLC, a physical PLC, HELICS coordination, or a
multi-VM deployment. Development-mode identity, policy, and evidence components
also remain in process.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,docs,simulation]"
python scripts/export_schemas.py --check
pytest --cov=aegis_ot --cov-branch --cov-report=term-missing --cov-fail-under=90
ruff check .
python -m aegis_ot demo --output-dir results/demo
python -m aegis_ot experiment --trials-per-seed 36 --seed-count 30 \
  --seed 20260824 --output-dir results/m2-independent-oracle
```

Windows PowerShell activation is `.venv\Scripts\Activate.ps1`.

### PyCharm local setup

Create the environment from the repository root, then select
`.venv/bin/python` as the project interpreter in PyCharm. On Windows, select
`.venv\Scripts\python.exe`. Set the run configuration working directory to the
repository root so configuration, schemas, policy, and result paths resolve
consistently.

A PyCharm terminal can run a one-session M3 smoke check with the installed
console entry point:

```bash
.venv/bin/aegis-ot physical-experiment \
  --seed-count 1 \
  --seed 20260824 \
  --output-dir /private/tmp/aegis-m3-smoke
```

The equivalent PyCharm Python run configuration uses the script path
`.venv/bin/aegis-ot`, parameters `physical-experiment --seed-count 1 --seed
20260824 --output-dir /private/tmp/aegis-m3-smoke`, and the repository root as
its working directory. Use `.venv\Scripts\aegis-ot.exe` and a suitable temporary
directory on Windows. When the environment is activated, the same entry point
can be invoked as `aegis-ot physical-experiment`.

The current local M3 implementation has 264 passing tests and 91.57 percent
branch-aware coverage. Ruff, strict mypy, schema-drift, bounded formal-model,
and Compose-configuration checks are also clean locally. These are local
implementation-verification results; they are not an observed remote CI run,
independent replication, physical validation, or the pending controlled M3
experiment.

Run the same local verification path with:

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

Compose configuration validation proves that the file resolves; it does not
prove that the services started, that the M3 process ran in containers, or that
network trust boundaries were enforced.

## Containers

The default OPA and Python base images are pinned to verified multi-platform digests, so PyCharm can run Compose without defining environment variables:

```bash
docker compose up --build -d
docker compose ps
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8181/health
```

Copy `.env.example` to `.env` only when deliberately overriding an image. Overrides must remain version-and-digest pinned.

## Trust-boundary schemas

`ActionProposal` and the M3 physical-state, command, candidate, permit,
acknowledgment, closed-loop-result, and Modbus mailbox models are the
authoritative validation contracts. Regenerate and verify their public JSON
Schemas with:

```bash
python scripts/export_schemas.py
python scripts/export_schemas.py --check
```

Operation-specific parameters are closed sets. Unknown keys, nonnumeric values, non-finite values, out-of-range percentages, extra message fields, and timezone-naive timestamps are rejected before authorization evaluation.

## M3 physical and virtual-device experiment

The current M3 implementation uses the packaged pandapower 3.5.4 CIGRE MV
network with an Aegis-OT synthetic mission-priority load subset. It performs a
balanced steady-state AC Newton-Raphson power flow. A signed, short-lived,
single-use execution permit binds the exact proposal, command, candidate
assessment, model, topology, pre-state, expected post-state, policy, safety
version, evidence record, and device audience. The child process validates the
permit, independently repeats the candidate calculation, applies an accepted
command transactionally, and returns a signed acknowledgment. The parent
accepts completion only after acknowledgment verification and state readback.

The controlled experiment starts one fresh child process per master seed and
runs five fixed conformance conditions: unknown identity, stale state, wrong
permit audience, nominal permitted execution, and permit replay. The seeds vary
session identifiers and process instances, not the deterministic power-flow
physics. The intended 30-session run, which will produce 150 trial records, is
still pending. Run it only from a clean committed implementation into a new
result directory:

```bash
.venv/bin/aegis-ot physical-experiment \
  --seed-count 30 \
  --seed 20260824 \
  --output-dir results/m3-physical-modbus
```

The resulting package includes the manifest, raw trial and evidence JSONL,
scenario and summary files, per-session component health, evidence verification,
benchmark provenance, solver configuration, artifact hashes, and a
timing-independent deterministic outcome hash. Until that controlled run is
completed and retained, no M3 empirical result should be reported.

M3 remains bounded to localhost, a PyModbus virtual device, and steady-state
simulation. It does not model electromagnetic transients, subcycle protection,
relay timing, hardware I/O, field dynamics, or production OT. HELICS, OpenPLC,
SPIFFE/SPIRE, service-backed OPA enforcement, multi-VM isolation, field data,
hardware-in-the-loop testing, and external validation have not been completed.

## Bounded formal model

The TLA+ model covers submission, authorization or denial, dispatch,
acknowledgment, execution, full-chain delegation, ancestor revocation, grant
expiry, replay, policy and state consistency, approval, conflicting actions,
evidence, compromise, and quarantine. Run the intended model and all targeted
weakened variants with the pinned TLC JAR:

```bash
python scripts/run_formal.py \
  --jar /path/to/tla2tools.jar \
  --output-dir results/formal/<run-name>
```

The runner verifies the expected result for every case and records tool, model,
configuration, state-space, runtime, Git, host, and counterexample evidence.
See `docs/formal/conformance.md` for the explicit runtime mapping and gaps.
The committed M1 run is under `results/formal/m1-authorization-conformance`.

## Synthetic experiment

The M2 experiment uses 12 reviewed synthetic scenarios, eight control-path
baselines and ablations, 30 deterministic master seeds, Wilson 95 percent
intervals, and a separately implemented reference transition model. The
reference model uses conservative guardbands so kernel-oracle disagreements are
visible rather than forced to zero. It is independent at the code-path level;
it is not a power-flow simulator or evidence of field effectiveness. See
`docs/experiments/m2-method.md` for baseline and metric definitions.

## Safety and disclosure

Use only public, synthetic, or specifically authorized data and simulated assets. See `SECURITY.md`. Report vulnerabilities privately through the repository security advisory process when available.

## Authorship

Project owner, principal investigator, and author: Angelis Pseftis.
