# Aegis-OT

Aegis-OT is a defensive research implementation of an independently enforced runtime-assurance control plane for autonomous agents operating against simulated operational-technology environments.

The system treats an agent proposal as data, not authorization. A consequential
action is eligible for execution only after the gateway validates actor
authority, the complete delegation chain, policy, state freshness, replay
status, modeled safety, and any required approval reference. Application
workload identity is an explicit optional assurance layer. The implementation
does not connect to production OT and does not establish real-world
effectiveness.

## Status

WP4 remains open at the external-evidence boundary. The repository contains
retained formal, synthetic, same-host process, and single-host Docker evidence,
plus implemented M4g identity, M4i coordination, M4j six-host deployment, M5
compromise/degraded-operation, M6 fleet/economics, M7 replication, and M8
traceability code. A feature is described as experimentally supported only
when an immutable accepted result is retained under `results/`.

The default Docker path is locally executable. The M4j code can provision,
build, deploy, and probe its pinned six-VM topology on a compatible x86-64
VirtualBox host, but no accepted six-host result is retained in this repository.
See the [runnable lab guide](docs/reproducibility/M4J_LAB.md).

This is not a production control system. The repository does not establish
physical-PLC behavior, multi-host isolation, field effectiveness, deployment
readiness, or independent validation.

## Architecture

[![Aegis-OT architecture showing the sole authorization gateway, policy service, signed observer, candidate evaluator, OT adapter, synthetic plant, optional identity transport, bounded M4i coordination, and separate read-only evidence path](assets/diagrams/00-system-overview.svg)](assets/diagrams/00-system-overview.svg)

The gateway is the only authorization route. The agent can propose an action
but has no direct plant capability. The observer, candidate evaluator, and OT
adapter expose separate capture, simulation, and apply operations; only the OT
adapter reaches the consequential apply path. The public evidence demo is a
separate read-only service and does not expose the mutable research API.

The diagram shows the segmented capability configuration assembled with
`docker-compose.capability.yml` and its evidence boundary. M4i coordination has
an accepted single-host campaign retained under `results/`; the SPIRE/mTLS path
is implemented but has no immutable accepted campaign retained there. The
separate M4j contract defines a
six-host lab path; the retained depicted evidence remains single-host research
evidence against a synthetic plant.

### Understand the system

| Area | Maintained views |
|---|---|
| Boundary and behavior | [System context](assets/diagrams/01-system-context.svg) · [Functional decomposition](assets/diagrams/02-functional-decomposition.svg) · [Action transaction](assets/diagrams/05-action-transaction-sequence.svg) · [Outcome states](assets/diagrams/06-outcome-state-model.svg) |
| Deployment and trust | [Network segmentation](assets/diagrams/03-deployment-network.svg) · [Overlay stack](assets/diagrams/04-assurance-overlay-stack.svg) · [Identity lifecycle](assets/diagrams/07-identity-trust-lifecycle.svg) · [Replay and coordination](assets/diagrams/08-replay-effect-coordination.svg) |
| Evidence and demonstration | [Evidence lifecycle](assets/diagrams/09-evidence-reproducibility.svg) · [Public-demo data path](assets/diagrams/10-public-demo-data-path.svg) |
| Setup and assurance | [Developer workflow](assets/diagrams/11-developer-setup-verification.svg) · [Verification gates](assets/diagrams/12-verification-gates.svg) |

The [systems-engineering view set](docs/architecture/diagram-set.md) explains the
scope, source files, status language, and update contract for every diagram.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,docs,simulation]"
python scripts/export_schemas.py --check
python scripts/build_public_demo.py --check
python scripts/build_system_diagrams.py --check
pytest --cov=aegis_ot --cov-branch --cov-report=term-missing --cov-fail-under=90
ruff check .
python -m aegis_ot demo --output-dir /private/tmp/aegis-demo-local
python -m aegis_ot experiment --trials-per-seed 36 --seed-count 30 \
  --seed 20260824 --output-dir /private/tmp/aegis-m2-local
```

Use a new output path for every run. Do not overwrite the retained evidence
under `results/`.

Windows PowerShell activation is `.venv\Scripts\Activate.ps1`.

For PyCharm, select `.venv/bin/python` (or `.venv\Scripts\python.exe` on
Windows) and use the repository root as the working directory.

```bash
.venv/bin/aegis-ot physical-experiment \
  --seed-count 1 \
  --seed 20260824 \
  --output-dir /private/tmp/aegis-m3-smoke
```

Run the bounded M4a capability smoke check with:

```bash
.venv/bin/aegis-ot capability-smoke
```

## Verification

Run verification against the exact source state being assessed:

```bash
.venv/bin/python scripts/export_schemas.py --check
.venv/bin/python scripts/build_public_demo.py --check
.venv/bin/python scripts/build_system_diagrams.py --check
.venv/bin/ruff check .
PYTHONPATH=src .venv/bin/mypy src scripts/build_public_demo.py
PYTHONPATH=src .venv/bin/python -m pytest \
  --cov=aegis_ot --cov-branch --cov-report=term-missing --cov-fail-under=90
docker compose config --quiet
AEGIS_TLA_JAR=/absolute/path/to/tla2tools-1.8.0.jar
.venv/bin/python scripts/run_formal.py \
  --jar "$AEGIS_TLA_JAR" \
  --output-dir /private/tmp/aegis-formal-check
```

Compose configuration validation proves that the file resolves; it does not
prove that services started or that runtime trust boundaries were enforced. A
passing local suite is implementation evidence, not independent validation or
operational evidence.

## Containers

The default OPA and Python base images are pinned to verified multi-platform digests, so PyCharm can run Compose without defining environment variables:

```bash
docker compose up --build -d
docker compose ps
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8081/health
docker compose --profile experiment run --rm agent-probe
docker compose down
```

Port 8080 remains the read-only public evidence demo. Port 8081 is the bounded
M4d segmented-gateway research surface. OPA, the observer, OT adapter, and
synthetic simulation have no host-published ports.

Advanced experiment runners require a clean checkout, a unique Compose project
name, and a new output path. They refuse to overwrite retained evidence.

### Experiment runners

| Path | Runner | What it tests |
|---|---|---|
| M3 | `aegis-ot physical-experiment` | Loopback PyModbus and pandapower command path |
| M4d | `scripts/run_m4d_experiment.py` | Network segmentation, bypass denial, and service loss |
| M4e | `scripts/run_m4e_experiment.py` | Signed gateway/OT transport and hostile-message cases |
| M4f | `scripts/run_m4f_experiment.py` | Durable exact-envelope replay across OT-adapter replacement |
| M4g | `scripts/run_m4g_experiment.py` | Application workload credentials, rotation, restart-durable trust-sequence rejection, and replay attribution |
| M4i | `scripts/run_m4i_experiment.py` | At-most-one commit transmission, query recovery, restart recovery, and fail-closed journal corruption |
| SPIRE | `scripts/run_m4g_spire_mtls_experiment.py` | X.509-SVID issuance and internal mTLS; no accepted result is retained |

The default `docker compose up` path does not enable the optional assurance
overlays. Inspect an overlay composition deliberately before running it:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.auth.yml \
  -f docker-compose.replay.yml \
  --profile experiment config --quiet
```

The current restart-durable, actor-bound workload-identity and coordination
code has accepted single-host campaigns at
`results/m4g-workload-identity-evidence-v3.json` and
`results/m4i-coordination-evidence-v3.json`. The v2 and unsuffixed files remain
as immutable historical evidence for the preceding credential contracts. The
current M4g campaign establishes signed sequence-rollback rejection after
gateway and OT container recreation only while each verifier's trusted local
state volume remains intact. These results do not establish hostile-host or
storage rollback resistance, consensus, a rollback-resistant external anchor,
multi-host deployment, or exactly-once-effect behavior. The
[M4j lab guide](docs/reproducibility/M4J_LAB.md) provides the compatible-host
deployment and live-probe sequence.

Copy `.env.example` to `.env` only when deliberately overriding an image. Overrides must remain version-and-digest pinned.

## Public demonstration

After Compose starts the public demo service, open
`http://127.0.0.1:8080/demo` in a browser. The repository root redirects to the
same page. The demonstration is a self-contained, read-only explorer of the
retained M2 and M3 evidence: it shows the seven-stage transaction path, all five
registered M3 conditions, exact trial denominators and Wilson intervals, the M2
baseline comparison, and hashes binding the displayed summary to its source
artifacts.

The Compose-published application exposes only the read-only demonstration,
health, and packaged-evidence routes. It does not publish `/v1/decisions` or
`/v1/state`; requests to those paths have no public route. The page fetches only
packaged local assets and the read-only `/health` and `/v1/demo/evidence`
endpoints. It does not open a device socket, rerun an experiment, or issue a
control command. A running page therefore demonstrates the presentation and API
path, not physical validity, independent replication, production readiness, or
operational effectiveness.

The mutable research API is a separate local interface. Start it only for
deliberate local experimentation, bind it to loopback, and never expose it as a
public service:

```bash
.venv/bin/uvicorn aegis_ot.api:control_app --host 127.0.0.1 --port 8085
```

When started with that command, the loopback-bound application provides
`/v1/decisions` and `/v1/state`; it is not the application launched by the
default Compose configuration.

If a retained source manifest or summary changes, rebuild and verify the
packaged display data before committing it:

```bash
.venv/bin/python scripts/build_public_demo.py
.venv/bin/python scripts/build_public_demo.py --check
```

## Trust-boundary schemas

The generated schemas cover the public trust-boundary contracts for the base
gateway, M3 physical/Modbus path, M4 capability path, retained M4b package, and
the later segmented transport. The M4i coordination models are closed runtime
contracts but remain active implementation work. Regenerate and verify public
JSON Schemas with:

```bash
python scripts/export_schemas.py
python scripts/export_schemas.py --check
```

Operation-specific parameters are closed sets. Unknown keys, nonnumeric values, non-finite values, out-of-range percentages, extra message fields, and timezone-naive timestamps are rejected before authorization evaluation.

## Evidence summary

| Evidence set | Retained result | What it supports | What it does not support |
|---|---|---|---|
| M1 formal | Intended TLA+ model and weakened variants | Bounded authorization conformance and expected counterexamples | Runtime or deployment validation |
| M2 synthetic | Multi-seed synthetic baseline and ablation results | Deterministic control-path comparison | Physical-process effectiveness |
| M3 physical-model path | Primary and local-reproduction packages | Loopback PyModbus, pandapower, signed permit, acknowledgment, and replay behavior | Physical PLC, HIL, field, or latency claims |
| M4b-M4c capability path | Root-signed packages and fault campaigns | Same-host capability separation, consequence checks, replay, contradiction, and unknown-effect handling | Independent sensing, hostile-host resistance, or failure-rate estimates |
| M4d-M4f segmented path | Reproduced Docker experiment reports | Network membership, bypass denial, signed transport, and bounded durable replay | Multi-host isolation, exactly-once effects, or rollback resistance |
| M4g identity path | Accepted application-credential and intact-volume restart campaign | Workload credential rejection, rotation, stable replay attribution, and signed sequence rollback rejection after container recreation | Hostile-host/storage rollback resistance, protected key storage, multi-host execution, or external validation |
| M4i coordination | Accepted single-host coordination and recovery campaign | At-most-one commit transmission in the tested flow, query recovery, restart recovery, and fail-closed corrupt state | Consensus, hostile-host rollback resistance, independently anchored state, or exactly-once effects |
| M4j six-host deployment | Exact-source builder, six-role provisioning, SPIRE registration, workload deployer, signed probe, and network acceptance runner | A runnable compatible-host lab contract | A retained live six-host result, hostile-hypervisor resistance, or production readiness |
| M5 compromise and degraded operation | Deterministic admission, quarantine, recovery, and degraded-operation code and runners | Implemented fail-closed modeled behavior | Operational mission-continuity evidence or external validation |
| M6 fleet and economics | Deterministic logical fleet and sensitivity model with an offline verifier | Reproducible modeled scaling behavior | Empirical fleet performance or validated cost forecasts |
| M7-M8 replication and traceability | Signed replication-bundle code and evidence-backed requirements mapping | Reproducible packaging and explicit open-state tracking | Independent replication, publication, approval, or closure of open requirements/TBRs |

The registered terminal states are `not_dispatched`, `candidate_rejected`,
`plc_rejected`, `unknown_effect`, `observation_diverged`, and `completed`.
There is no automatic retry after consequential dispatch when the effect is
unknown.

## Evidence verification

Retained evidence is immutable. Verify it from a clean checkout matching the
recorded source bindings; a modified checkout should fail checkout-binding
checks.

```bash
.venv/bin/aegis-ot verify-physical-evidence \
  --output-dir results/m3-physical-modbus
.venv/bin/aegis-ot verify-physical-evidence \
  --output-dir results/m3-physical-modbus-reproduction
```

The verifier establishes package/current-checkout consistency. It does not
establish external custody or independent replication. Formal verification uses
the intended model plus targeted weakened variants:

```bash
python scripts/run_formal.py \
  --jar /path/to/tla2tools.jar \
  --output-dir results/formal/<run-name>
```

See `docs/architecture/diagram-set.md`, `docs/formal/conformance.md`, `docs/experiments/`, and
`docs/reproducibility/REPRODUCIBILITY.md` for methods, exact outcomes, hashes,
and limitations.

## Repository guide

The [documentation index](docs/README.md) provides the recommended reading
order without requiring readers to work through milestone history.

- `src/aegis_ot/`: gateway, control-path, evidence, identity, transport, and
  coordination implementation.
- `src/aegis_ot_independent/`: separate M4b consequence evaluator.
- `tests/`: unit, property, contract, integration, verifier, and Compose checks.
- `formal/`: TLA+ model, configurations, and weakened variants.
- `docs/architecture/` and `docs/adr/`: maintained systems-engineering views,
  system context, and controlling design decisions.
- `scripts/build_system_diagrams.py`: deterministic source for the generated
  architecture and workflow SVGs under `assets/diagrams/`.
- `docs/experiments/` and `docs/reproducibility/`: registered methods, evidence
  rules, and repeat-run procedures.
- `PROJECT_PLAN.md` and `CHANGELOG.md`: milestone history and implementation
  chronology.
- `results/`: retained experiment artifacts. Treat these as immutable research
  evidence; create new paths for new work.
- `docker-compose*.yml` and `infra/`: the base stack and optional assurance
  overlays.

For changes, preserve closed trust-boundary schemas and fail-closed outcomes,
add negative tests for rejection paths, and keep source state identifiable in
every experiment. Run the verification sequence above before describing a
change as locally verified. A passing local check does not imply CI acceptance,
independent validation, publication, deployment, or operational readiness.

## Safety and disclosure

Use only public, synthetic, or specifically authorized data and simulated assets. See `SECURITY.md`. Report vulnerabilities privately through the repository security advisory process when available.

## Authorship

Project owner, principal investigator, and author: Angelis Pseftis.
