# ADR 0004: Capability-Separated Deterministic-Local Control Loop

- Status: Accepted for WP4 M4a local implementation acceptance; WP4 remains in progress
- Date: 2026-08-24
- Decision authority: Angelis Pseftis

## Context

M3 demonstrated a signed command transaction against a steady-state pandapower plant
through a local Modbus process boundary. Its parent process nevertheless retained the
authorization, control, and permit-signing functions together, while one child combined
the virtual device and authoritative plant. WP4 needs an intermediate step that makes
control capabilities explicit before distributed co-simulation, a PLC runtime, network
segmentation, or hardware is introduced.

M4a therefore separates the authoritative plant, signed observer, and research virtual
PLC into distinct local processes and restricts their application interfaces by static
operation allowlists. The increment is deliberately local and deterministic. It tests
transaction semantics, capability ownership, evidence correlation, and effect-certainty
classification; it does not establish an operational OT security boundary.

## Requirements and success criteria

The M4a implementation shall:

1. run the plant, observer, and virtual PLC under distinct process identifiers, with
   distinct observer and PLC boot epochs and signing keys;
2. keep the authoritative pandapower instance solely inside the plant process;
3. give the closed-loop controller only observation, candidate-simulation, and PLC
   dispatch ports, with no plant-apply handle;
4. make the plant-apply endpoint available only to the plant-spawned PLC child;
5. bind authorization and execution to an observer-signed pre-authorization snapshot,
   the target PLC identity, key, and boot epoch, and an exact candidate transition;
6. require a separately captured, observer-signed post-dispatch snapshot before
   reporting completion;
7. perform no more than one PLC dispatch attempt and no automatic retry;
8. classify every closed-loop request into one of six terminal states without
   converting missing evidence into a success claim; and
9. reject replay across one orderly PLC-child replacement within the same running lab.

M4a local implementation acceptance requires executable conformance tests and a local
smoke path that exercise these properties. It is not the WP4 exit gate and does not
require or claim HELICS, OpenPLC, physical PLC behavior, hardware-in-the-loop,
independent sensing, network segmentation, external validation, or a retained
replication package.

## Decision

### Component and capability ownership

```text
Coordinator / lab harness (one local process)
  gateway, translator, evidence chain, permit signer, lifecycle/admin clients
  closed-loop controller:
      observe/resolve + capture-post  ----> signed-observer process
      simulate candidate             ----> authoritative-plant process
      dispatch once                  ----> research virtual-PLC child
      no plant-apply capability

Signed-observer process                         Authoritative-plant process
  observer key + boot epoch                     pandapower plant + boot epoch
  bounded observation cache                     observer read-only capture endpoint
  read-only plant capture ------------->        candidate-simulation endpoint
                                                 sole apply endpoint
                                                        ^
                                                        |
                                         plant-spawned research virtual-PLC child
                                           PLC key + boot epoch
                                           permit/replay enforcement
```

The coordinator process owns the authorization gateway, trusted command translation,
the M4a permit-signing key, in-memory evidence chain, controller, and lab lifecycle. The
lab harness also retains plant, observer, and PLC administrative clients so it can
inspect health, perform the single orderly PLC-child replacement, and shut down the
stack. Consequently, the controller object has no plant-apply handle, but the enclosing
coordinator is still privileged. Capability separation must not be described as
isolation from a hostile coordinator.

The plant process is the sole owner of `PandapowerCigreMVPlant`. It exposes different
local pipe endpoints for administration, observer capture, candidate simulation, and
PLC operations. The plant creates the raw apply pipe internally and passes it directly
to the PLC child it spawns; the coordinator neither creates nor retains that endpoint.

The observer process receives only the plant's read-only capture capability. It owns an
observer signing key and boot epoch, applies monotonic observation sequencing, and
caches a bounded set of signed envelopes for resolution and transaction linking. Its
telemetry endpoint can capture a pre-authorization observation but cannot request a
post-dispatch capture. Its gateway endpoint can resolve a referenced pre-observation
and request a transaction-bound post observation. The coordinator supplies the
correlation, challenge, permit, command, and acknowledgment-digest fields that the
observer binds; the observer does not discover that execution metadata through an
independent path.

The Python research virtual-PLC child receives the sole plant-apply capability, the
permit-signing public key, observer public metadata, and separate admin and gateway
endpoints. It owns its acknowledgment key, boot epoch, scan counter, and replay
reservations. It is not OpenPLC, a physical PLC, a representation of a production PLC
scan cycle, or a hard-real-time component.

Runtime requests and responses across these endpoints use closed typed models encoded
as canonical JSON in bounded frames. Endpoint roles have static operation allowlists.
Bootstrap readiness metadata still crosses trusted local process pipes. This avoids
using arbitrary Python object deserialization as the runtime application protocol, but
it does not turn same-host multiprocessing pipes into a network or operating-system
security boundary.

### Closed-loop data flow

1. A telemetry client supplies a correlation identifier and fresh challenge to the
   observer. The observer captures the authoritative plant state through its read-only
   endpoint, signs a `pre_authorization` envelope, assigns a monotonic observer
   sequence, and caches the envelope.
2. The action request carries the proposal and only the observation identifier, signed
   envelope digest, and challenge reference. The controller resolves the cached
   envelope and verifies its signature, observer identity, key, boot epoch, plant
   source and model, digest, phase, challenge, correlation, freshness, and monotonic
   sequence before requesting authorization.
3. After a gateway permit decision, trusted translation produces the exact command.
   The controller requests a non-mutating candidate from the plant's simulation
   endpoint. The candidate must bind the same state version, value digest, observation
   digest, topology digest, model digest, and command.
4. The permit issuer signs an M3 execution permit plus the complete action-request
   digest, signed-observation reference, observer identity/key/boot, and target PLC
   identity/key/boot.
5. The controller makes at most one call to the PLC gateway. The PLC verifies the
   request, decision, candidate, permit, observer signature and bindings, target
   instance, time window, and replay state. It reserves the request digest, permit
   identifier, permit nonce, and command identifier before consequential dispatch.
6. The PLC verifies the current model and topology and requests the plant to apply the
   authorized command. The plant atomically compares the expected pre-state version,
   value digest, and observation digest, and checks the expected post-state and topology
   digests before commit. It either commits the validated candidate once, rejects with
   known no effect, or returns an outcome whose effect cannot be established.
7. The PLC returns a signed acknowledgment binding the full pre-state, request,
   permit, command, assessment, PLC identity/key/boot, scan, dispatch phase, and any
   established post-state.
8. Only after a valid `applied` acknowledgment does the controller ask the observer for
   a new post-dispatch capture. That signed envelope binds the permit identifier,
   command digest, PLC-acknowledgment digest, and the exact pre-authorization envelope
   for this transaction.
9. The controller reports `completed` only when the valid PLC acknowledgment, valid
   post observation, permit expectation, and authoritative state all agree.

The post envelope's `previous_envelope_digest` is a direct pre/post transaction link.
It is not a continuous global observation chain: unrelated captures may occur between
the transaction's pre- and post-observations. Observer boot, signature, challenge,
correlation, monotonic accepted sequence, and the direct predecessor link provide the
claims implemented by this increment. The correlation fields are coordinator-supplied,
so the observer signature establishes their binding to its capture, not independent
discovery of the command or PLC acknowledgment.

### Contracts

| Contract | Required security and consistency bindings |
|---|---|
| `CapabilityActionRequest` | Complete proposal plus correlation, observation ID, signed-envelope digest, and pre-observation challenge |
| `SignedObservationEnvelope` | Phase, correlation, challenge, observer ID/key/boot, monotonic sequence, capture/logical time, complete physical snapshot, digest, and Ed25519 signature; post phase additionally binds permit, command, ACK, and direct transaction predecessor |
| `CapabilityExecutionPermit` | Verified M3 permit plus request digest, pre-observation reference, observer ID/key/boot, target PLC ID/key/boot, signer ID, and signature |
| `PlcCommandAcknowledgment` | Request, permit, observation, command, assessment, proposal, decision, PLC ID/key/boot/scan, exactly one dispatch attempt, explicit dispatch phase, complete pre-state, conditional post-state, and PLC signature |
| Plant apply request | Exact authorized command; compare-and-set expectation for pre-state version, state, and observation digests; and expected post-state and topology digests. The PLC separately checks the current model and topology before invoking apply |
| `CapabilityClosedLoopResult` | One terminal status, nonempty reasons, zero or one dispatch attempts, literal zero automatic retries, structurally consistent evidence artifacts, and an in-memory evidence-record hash |

Schema validation establishes closed structure and internal correlations. Live
verification establishes signatures, trust anchors, freshness, sequence, and the
transaction evidence chain. A structurally valid serialized result is not by itself
cryptographic verification.

### Terminal, failure, and retry behavior

| Terminal state | Meaning |
|---|---|
| `not_dispatched` | Observation, authorization, translation, simulation availability, or permit issuance failed before the PLC call; zero dispatch attempts |
| `candidate_rejected` | The candidate was unsafe or did not bind the signed pre-state, or the PLC returned the narrowly defined signed candidate-attestation rejection |
| `plc_rejected` | A valid signed PLC acknowledgment establishes pre-dispatch or known-no-effect rejection, including an exact replay or compare-and-set rejection |
| `unknown_effect` | After the single consequential PLC call, the response, acknowledgment, dispatch outcome, or required post observation is unavailable or invalid; no verified post-state is asserted |
| `observation_diverged` | A valid applied PLC acknowledgment and a valid transaction-bound post observation exist, but the signed observed state contradicts the acknowledgment or permit expectation |
| `completed` | One valid applied acknowledgment and one valid separately captured signed post observation match the authorized expected state |

`dispatch_attempts` is the number of controller calls to the PLC gateway, not a claim
that a physical actuator moved. `automatic_retry_count` is always zero. A timeout or
malformed consequential response closes the ambiguous client connection and becomes
`unknown_effect`; the controller does not redispatch. Recovery and reconciliation after
an unknown effect require a separately authorized design that M4a does not implement.

Replay reservations are stored in a mode-0600 temporary local ledger and are available
to one pre-provisioned orderly replacement PLC child while the lab remains running.
The replacement has its own key and boot epoch and may use old-instance bindings only
to return `transaction_replayed`, `permit_replayed`, `permit_nonce_replayed`, or
`command_replayed`. This mechanism does not claim `fsync` durability, tamper resistance,
abnormal-process-crash recovery, host restart recovery, or multi-restart lifecycle
support. The temporary directory is deleted when the local lab closes.

Unauthorized operations are rejected without effect at the endpoint allowlist.
Malformed frames or response-protocol failures close only the offending connection when
the protocol is no longer trustworthy. Service shutdown responses act as quiescence
barriers for the local request loop. These behaviors improve deterministic failure
handling; they do not provide workload isolation against a malicious same-host process.

### Evidence boundary

The live controller appends the terminal transaction to an in-memory evidence chain.
The local `capability-smoke` path returns a human-inspectable summary after shutting
down the lab. It does not retain the signed pre/post envelopes, execution permit, PLC
acknowledgment, public trust anchors, capability-topology negative-probe results, replay
provenance, or a manifest-bound M4a experiment package. The in-memory evidence and
temporary replay ledger are not available for offline verification after normal
shutdown.

M4a therefore has no retained or offline-verifiable evidence package, exporter, or
verifier. Passing local tests or the smoke path is implementation evidence only. It is
not a completed experiment, independently reproduced result, externally validated
control system, deployment, operational-effectiveness finding, or WP4 exit.

## Trust boundaries and residual risks

The implementation provides application-level capability separation on one host. The
plant, observer, PLC, and coordinator still share the same operating system, user,
filesystem, host clock, Python runtime and dependency supply chain. A process with
sufficient same-user or host privilege may bypass, inspect, replace, or corrupt these
application boundaries. The coordinator also retains administrative lifecycle
authority and the permit private key.

The observer and candidate simulation both derive from the same authoritative plant
and model. Separate observer and PLC processes, keys, and boot epochs provide origin and
transaction separation; they do not provide an independent sensor, external clock,
independent physical model, or independent ground truth. Model error, solver error,
common-mode implementation error, and compromised-host behavior remain outside the
claims supported by M4a.

## Alternatives and tradeoffs

### Keep observer, PLC, and plant in one process

This would be simpler, but would not make the plant-apply capability or per-component
key and boot lifecycle explicit. It was rejected for M4a.

### Move immediately to HELICS, OpenPLC, segmented hosts, or hardware

Those environments could support stronger timing, protocol, administrative-domain, or
physical claims, but each introduces a different lifecycle, synchronization, network,
I/O, recovery, and safety case. Introducing them before the transaction contracts and
effect-certainty states stabilize would confound this increment. They remain separate
WP4 decisions and evidence gates.

### Treat the signed observer or candidate as independent validation

The separate process and key reduce accidental coupling and provide signed origin, but
both paths read or simulate the same plant and model on the same host. Calling either
independent sensing or model validation would exceed the evidence. That interpretation
is rejected.

### Automatically retry an ambiguous command

Retry could improve apparent availability but could repeat a consequential effect when
the first dispatch outcome is unknown. M4a instead terminates as `unknown_effect` and
requires a future, separately authorized reconciliation workflow.

## Validation and remaining gates

M4a local acceptance is based on typed-contract tests, controller failure-path tests,
process-loop tests, capability-negative probes, replay across one orderly replacement,
schema regeneration checks, static analysis, and a local smoke execution. These are
software-conformance results inside the described lab boundary.

Before a broader WP4 or operational claim, the project still requires separately
scoped work for distributed co-simulation and time management, OpenPLC or real PLC
semantics, network and administrative segmentation, durable replay and key lifecycle,
recovery and reconciliation, retained signed evidence with offline verification,
independent measurement or model validation, hardware or HIL evaluation, formal-model
extension where justified, an independently operated replication, and external
security and safety review.
