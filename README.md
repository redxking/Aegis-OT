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
                                  authorization -> command adapter
                                                    |
                                      simulated PLC/process only
```

The gateway is the sole authorization route. Development-mode in-process components preserve interface boundaries but are not equivalent to independently deployed SPIRE, OPA, PLC, evidence, or simulation services.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev,docs]"
python scripts/export_schemas.py --check
pytest --cov=aegis_ot --cov-branch --cov-report=term-missing --cov-fail-under=90
ruff check .
python -m aegis_ot demo --output-dir results/demo
python -m aegis_ot experiment --trials-per-seed 36 --seed-count 30 \
  --seed 20260824 --output-dir results/m2-independent-oracle
```

Windows PowerShell activation is `.venv\Scripts\Activate.ps1`.

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

`ActionProposal` is the authoritative validation model. Regenerate and verify its public JSON Schema with:

```bash
python scripts/export_schemas.py
python scripts/export_schemas.py --check
```

Operation-specific parameters are closed sets. Unknown keys, nonnumeric values, non-finite values, out-of-range percentages, extra message fields, and timezone-naive timestamps are rejected before authorization evaluation.

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
