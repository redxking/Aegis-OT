# Security Policy

## Scope

Aegis-OT is defensive research software for synthetic and authorized simulation environments. It must not be connected to production control systems, utility networks, third-party infrastructure, or real operational credentials.

## Reporting

Do not publish a vulnerability before the project owner has had a reasonable opportunity to assess it. Use GitHub private vulnerability reporting when enabled or contact the project owner through a verified private channel.

## Security boundaries

- Agent proposals are untrusted input.
- Signatures authenticate data origin but do not authorize execution by themselves.
- The in-process v0.1 services are development approximations, not independent trust domains.
- The local hash chain is tamper-evident only while its trusted head is preserved.
- Simulator safety limits are research parameters, not production settings.

Never commit credentials, signing keys, tokens, sensitive OT data, packet captures containing secrets, CUI, or classified information.

## WP4 M4a deterministic-local boundary

M4a runs the authoritative plant, signed observer, and Python research virtual PLC in
separate local processes. The observer and PLC use distinct signing keys and boot
epochs. Static local-pipe operation allowlists separate administration, read-only plant
capture, candidate simulation, PLC dispatch, and plant apply.

The closed-loop controller receives only observer resolution/post-capture,
candidate-simulation, and PLC-dispatch ports. It has no plant-apply handle. The plant
creates the raw apply endpoint and gives it only to the PLC child it spawns. This is a
useful application-level capability boundary, but not a sandbox or an OT network zone.
The coordinator lab harness still owns the permit-signing key and administrative and
lifecycle clients. All processes share one operating system, user, filesystem, host
clock, runtime, and dependency environment. Do not represent M4a as protection from a
hostile coordinator, same-user process, or compromised host.

### Transaction controls

- Canonical-JSON request and response frames use closed typed models, bounded fields,
  static endpoint operations, request/response correlation, and boot-bound response
  counters.
- The observer-signed pre-state is verified for origin, key, boot, plant source, digest,
  phase, challenge, correlation, freshness, and accepted sequence before authorization.
- The execution permit binds the complete request and candidate to the exact signed
  observation and target PLC identity, key, and boot epoch.
- The PLC verifies the permit and observer artifacts, checks the current model and
  topology, reserves replay identifiers, and applies through an atomic plant
  compare-and-set over state version, state digest, and observation digest. Expected
  post-state and topology digests are also checked before commit.
- `completed` requires a valid signed applied acknowledgment and a separately captured,
  observer-signed post state that matches the permit expectation. The post envelope
  directly references that transaction's pre envelope; this is not a continuous global
  observation chain. The coordinator supplies the correlation and execution-digest
  fields that the observer binds; the observer does not independently discover them.

The observer reads the same authoritative plant used for simulation and apply. Process
and key separation authenticates origin inside the local design; it does not create an
independent sensor, an independent physical model, or external ground truth.

### Failure, retry, and lifecycle rules

Every request terminates as exactly one of `not_dispatched`, `candidate_rejected`,
`plc_rejected`, `unknown_effect`, `observation_diverged`, or `completed`. The controller
makes at most one PLC-dispatch call and never retries automatically. Any consequential
transport, response, acknowledgment, or post-observation ambiguity becomes
`unknown_effect` without a verified post-state. Recovery or redispatch requires a future
separately authorized reconciliation workflow.

Replay reservations cover the request digest, permit ID, permit nonce, and command ID.
They are written to a mode-0600 temporary ledger and are available to one orderly
replacement PLC child while the current local lab remains running. They are not
crash-safe or tamper-resistant, are not guaranteed durable by `fsync`, do not survive a
host restart, and do not support repeated PLC replacement. Normal lab cleanup deletes
the temporary ledger.

Treat the observer, PLC, plant, coordinator, and their private keys as trusted computing
base components for their respective claims. A compromised observer can invalidate
observation trust; a compromised PLC possesses the apply capability; a compromised
plant invalidates authoritative-state claims; and a compromised coordinator holds the
permit signer and lifecycle authority.

### Evidence and deployment restrictions

The live M4a controller uses an in-memory evidence chain. The `capability-smoke` command
prints a summary only; it is not a retained evidence package and omits signed artifacts,
public trust anchors, capability-topology negative-probe results, replay provenance,
and a manifest. M4a currently has no exporter or offline verifier for its signed
transaction.

Passing local M4a tests or the smoke command is implementation-conformance evidence,
not evidence of HELICS or OpenPLC integration, PLC scan or hard-real-time semantics,
network segmentation, hardware/HIL safety, independent sensing, physical accuracy,
external validation or replication, WP4 completion, production readiness, deployment,
or operational effectiveness. The prohibition on connecting Aegis-OT to production or
third-party control infrastructure remains unchanged.
