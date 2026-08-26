# System Context

The current cross-milestone architecture, behavior, deployment, trust, and
evidence views are maintained in the
[systems-engineering diagram set](diagram-set.md). The detailed M4a material
below remains the design record for that bounded capability slice; later
Compose overlays do not convert it into a production or fielded system.

## Planes and responsibilities

| Plane | Responsibility | Trust boundary |
|---|---|---|
| Observation | Acquire timestamped synthetic telemetry | Inputs may be delayed, replayed, or poisoned |
| Agent | Form bounded proposals | No direct control authority |
| Authorization | Verify identity, delegation, policy, freshness, replay, approval | Independently enforced gateway path |
| Safety | Predict candidate transition and enforce modeled invariants | Does not trust agent reasoning |
| Control | Translate authorized decisions into simulated commands | Rejects missing or stale authorization |
| Physical simulation | Produce resulting synthetic state | Not equivalent to real PLC or grid behavior |
| Evidence | Link proposal, decision, command, and outcome | Hash chaining is tamper-evident, not tamper-proof |

## Decision states

The current gateway emits `permit`, `deny`, or `require_approval`. The broader
decision enum also contains `quarantine`, `modify`, `defer`, `simulate`, and
`revoke`, but the gateway does not currently emit those outcomes. A required
approval is represented only by the presence of an approval reference; the
current implementation does not validate an approval authority or signature.

## Availability posture

The reconstruction baseline fails closed when identity, delegation, policy, state, replay, or safety validation cannot complete. Future degraded modes must define which recovery actions remain authorized, their scope, and their evidence requirements.

## WP4 M4a deterministic-local capability slice

M4a adds application-level capability separation on one host. The authoritative plant,
signed observer, and Python research virtual PLC run under distinct process identifiers.
The observer and PLC have distinct signing keys and boot epochs. The closed-loop
controller, which remains in the coordinator process, has only observation,
candidate-simulation, and PLC-dispatch ports; it has no plant-apply handle.

```text
Coordinator / lab harness
  gateway + translator + permit signer + in-memory evidence + admin/lifecycle
  controller (observe, simulate, dispatch once; no plant apply)
       | observe                 | simulate                 | execute once
       v                         v                          v
  signed-observer --------read-only capture--------> authoritative plant
                                                         ^          |
                                                         | apply    | spawns/owns
                                                         |          v
                                                   research virtual PLC
```

The enclosing coordinator is still privileged: the lab harness retains administrative
and lifecycle clients and the permit-signing key. All components share one operating
system, user, filesystem, host clock, and dependency environment. The pipes and static
operation allowlists are application interfaces, not network segmentation or isolation
from a hostile coordinator or host.

### Transaction flow and contracts

1. The observer captures and signs a pre-authorization plant snapshot with a fresh
   challenge, correlation identifier, observer sequence, key, and boot epoch.
2. The action request references that envelope by identifier, digest, and challenge.
   The controller resolves and verifies it before authorization.
3. A permitted proposal is translated and simulated through the plant's non-mutating
   candidate endpoint. Candidate and authoritative apply use the same plant and model;
   this is not independent model validation.
4. A signed permit binds the request, signed pre-observation, exact candidate and
   command, and target PLC identity, key, and boot epoch.
5. The controller calls the PLC at most once. The PLC verifies the current model and
   topology and reserves the transaction, then invokes the sole plant-apply endpoint.
   Plant apply atomically compares the expected pre-state version, state digest, and
   observation digest, and checks the expected post-state and topology digests before
   commit.
6. A signed PLC acknowledgment establishes `applied`, known no effect, or unknown
   effect. Only an applied acknowledgment triggers a separately captured signed post
   observation.
7. Completion requires the acknowledgment, post observation, and permit expectation to
   agree. The post envelope links directly to this transaction's pre envelope; it does
   not assert a continuous global observation chain. The coordinator supplies the
   correlation, challenge, permit, command, and ACK-digest values that the observer
   binds; the observer does not independently discover that execution metadata.

Canonical-JSON request and response frames carry closed typed contracts across local
multiprocessing pipes. The principal artifacts are the capability action request,
signed observation envelope, capability execution permit, PLC acknowledgment, atomic
plant-apply request, and closed-loop result. Schema structure does not replace live
signature, freshness, sequence, and trust-anchor verification.

### Terminal and retry semantics

| State | Effect-certainty meaning |
|---|---|
| `not_dispatched` | A prerequisite failed before the PLC call |
| `candidate_rejected` | The candidate was unsafe or inconsistent, including the narrowly defined signed PLC attestation rejection |
| `plc_rejected` | A valid signed PLC response establishes pre-dispatch or known-no-effect rejection |
| `unknown_effect` | A consequential PLC call occurred but the response, acknowledgment, or required post evidence cannot establish the effect |
| `observation_diverged` | Valid applied PLC evidence and valid signed post-observation evidence contradict one another |
| `completed` | One applied acknowledgment and the separately captured signed post observation match the authorized expected state |

There is no automatic retry in any terminal path. Replay reservations survive one
orderly PLC-child replacement inside the same running lab only. They do not survive or
claim protection for abnormal process death, host restart, ledger tampering, or repeated
replacement. Unknown effects require a future separately authorized reconciliation
workflow.

### Evidence and maturity boundary

The live M4a transaction is appended to an in-memory evidence chain. The
`capability-smoke` output is a summary, not a retained experiment package: it omits the
signed artifacts, trust-anchor public keys, capability-topology negative-probe results,
replay provenance, and a manifest. The evidence chain and mode-0600 temporary replay
ledger are not retained after normal lab shutdown. M4a therefore has no
offline-verifiable evidence exporter or verifier.

M4a local implementation acceptance does not establish WP4 completion, HELICS or
OpenPLC integration, PLC scan or hard-real-time behavior, network segmentation,
hardware/HIL performance, independent sensing, physical-model validity, external
validation or replication, deployment, or operational effectiveness. The controlling
design decision and remaining gates are recorded in
[ADR 0004](../adr/0004-capability-separated-deterministic-local-loop.md).
