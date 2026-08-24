# Threat Model

## Protected objectives

- No unauthenticated, out-of-scope, replayed, stale-state, or modeled-unsafe execution.
- Delegation never amplifies authority.
- Revocation becomes effective within a measured bound.
- Every issued decision has reconstructable evidence.
- Compromise of one agent remains bounded by delegated scope.

## Adversary capabilities

The experimental adversary may control an agent process, possess a valid but bounded credential, poison synthetic telemetry, replay proposals, forge malformed grants, delay service responses, or compromise a supervisor. The model does not assume compromise of all trusted gateway code, cryptographic libraries, host operating systems, and evidence anchors simultaneously.

## Primary validity risks

- Simplified supervisory physics.
- Shared host and process boundaries.
- Model assumptions that exclude unmodeled physical failure.
- Common-mode errors between safety logic and the independent oracle.
- Synthetic scenario prevalence and operator behavior.

## WP4 M4a threat-model refinement

### Protected assets and security objectives

For the deterministic-local M4a slice, the protected assets are the authoritative
pandapower state; the plant-apply capability; the permit, observer, and PLC private
keys; boot and sequence state; the exact request/permit/command transaction; replay
reservations; and the certainty attached to each terminal result.

The M4a controls are intended to establish the following bounded properties:

- the closed-loop controller cannot call plant apply through any capability it is
  given;
- observer and candidate-simulation endpoints cannot invoke apply;
- only the plant-spawned research virtual PLC receives the raw apply endpoint;
- a permit is bound to the signed pre-observation and the target PLC identity, key, and
  boot epoch;
- the PLC checks the current model and topology, and plant apply atomically compares the
  authorized state version, state digest, and observation digest before commit;
- a terminal result never reports more than one PLC-dispatch attempt or any automatic
  retry; and
- `completed` requires a valid applied PLC acknowledgment and a separate, valid signed
  post observation that matches the expected state.

### Components and compromise effects

| Compromised component or input | Bounded effect and residual exposure |
|---|---|
| Agent or action request | Remains subject to observation verification, authorization, translation, candidate safety, permit issuance, PLC verification, and atomic plant preconditions |
| Observation input or stale envelope | Signature, key/boot, plant-source, digest, phase, challenge, correlation, freshness, sequence, and direct transaction-link checks fail closed when they detect the condition |
| Controller object | It has observe, simulate, and dispatch ports but no plant-apply handle; a malicious controller can still consume its single dispatch path and is not isolated from its privileged enclosing coordinator |
| Signed-observer process or key | Can undermine observation-origin claims and sign false envelopes; its issued plant endpoint remains read-only, but M4a does not constrain a compromised same-user process or host |
| Research virtual PLC or PLC key | Can undermine acknowledgment and replay-enforcement claims and possesses the sole apply capability; separation does not defend the plant from a malicious PLC process |
| Authoritative plant process | Undermines both observed and simulated state and the application allowlists; no independent sensor or model can detect this common-mode compromise |
| Coordinator / lab harness | Retains the permit signer plus admin and lifecycle clients, so its compromise defeats the intended authorization and lifecycle trust assumptions even though the controller lacks raw apply |
| Local IPC response loss or corruption | Before consequential dispatch, processing fails closed; after the one PLC call, ambiguity is classified `unknown_effect` and is never automatically retried |
| Replay after an orderly PLC replacement | Exact request, permit ID, permit nonce, or command reuse is rejected from a temporary ledger available to one pre-provisioned replacement child |

### Observation and replay boundaries

The observer runs under a separate PID, boot epoch, and signing key from the PLC, but it
captures the same authoritative plant used for candidate simulation and apply. It is a
separately keyed signed observer, not an independent sensing path or independent ground
truth. The post envelope's predecessor digest links it directly to the corresponding
pre-authorization envelope. Intervening unrelated captures are allowed; M4a does not
claim a continuous global observation chain. The coordinator supplies the correlation,
challenge, permit, command, and ACK-digest fields that the observer signs; the observer
does not independently discover that execution metadata.

Replay reservations use a mode-0600 temporary local file and survive one orderly
PLC-child replacement while the same lab is running. The mechanism does not provide
`fsync` durability, integrity anchoring, abnormal-process-crash safety, host-restart
recovery, protection from a same-user attacker, or repeated-replacement lifecycle
support. The ledger is deleted during normal stack cleanup.

### Failure-state controls

The six closed-loop terminal states are `not_dispatched`, `candidate_rejected`,
`plc_rejected`, `unknown_effect`, `observation_diverged`, and `completed`. There is no
automatic redispatch. Invalid or missing evidence after the PLC call cannot be converted
to completion: it becomes `unknown_effect`, unless valid applied PLC evidence and a valid
transaction-bound post observation specifically establish a contradiction, which is
`observation_diverged`. Recovery from either condition is not implemented and requires
a separately authorized reconciliation design.

### Excluded adversaries and unsupported claims

The M4a boundary assumes the host operating system, same-user process controls, Python
runtime, cryptographic implementation, dependency environment, filesystem, host clock,
and coordinator trust anchors have not been comprehensively compromised. Static pipe
capabilities and separate processes are application-level controls; they are not
security zones, mutually hostile sandboxes, or transport authentication between
independent administrative domains.

M4a provides no retained signed transaction package or offline verifier. The local
smoke summary does not retain trust anchors, signed artifacts, capability-topology
negative-probe results, or replay provenance. Local implementation acceptance therefore
does not establish
HELICS/OpenPLC behavior, physical PLC or scan-cycle behavior, network segmentation,
hardware/HIL assurance, independent sensing or model validity, external validation or
replication, WP4 completion, deployment, or operational effectiveness.
