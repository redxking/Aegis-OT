# Aegis-OT Project Plan

## State as of 2026-08-26

The original package is unavailable. This repository is a clean reconstruction based on the controlled handoff. No earlier implementation, test, experiment, or document artifact is treated as recovered or independently verified.

| Work package | State | Current exit evidence |
|---|---|---|
| WP0 Governance and reproducibility | In progress | Canonical study revision 0.7, revision log, experiment and formal manifests, and reproducible outcome hashes established |
| WP1 Executable assurance kernel | Implementation complete; checkpoint verification pending | The capability, identity, coordination, compromise, fleet, release, and traceability implementation is present; exact M4j checkpoint verification replaces the stale historical test count |
| WP2 Formal specification | Bounded M1 complete | Intended model: 167,193 generated and 55,512 distinct states, depth 20, no reported violation; 16 weakened cases produced expected counterexamples; runtime gaps remain explicit |
| WP3 Single-host simulation | Bounded M2 complete | 8,640-record, 30-seed, eight-baseline run reproduced by outcome hash; independent physical evaluation remains open |
| WP4 Power-system and OT integration | In progress | M3/M4b-M4g retain bounded local evidence; M4i coordination and M4j exact-source six-host deployment code are implemented, while HELICS/OpenPLC, hardware, retained M4i/M4j campaigns, and external validation remain open |
| WP5 Multi-VM trust boundaries | Implemented; live acceptance pending | Six-role Vagrant/VirtualBox topology, exact package agreement, locked SSH transport, source-bound Ansible, SPIRE bootstrap, workload deployment, signed two-phase probe, and network acceptance runner are present; no live six-host result is retained |
| WP6 Operate-through-compromise | Implemented at deterministic model boundary | Fail-closed compromise, quarantine, recovery, and bounded degraded-operation code and campaign runners are present; operational mission-continuity evidence remains open |
| WP7 Scale and economics | Implemented at logical-model boundary | Deterministic fleet coordination and economic sensitivity code with offline verification is present; empirical fleet and cost validation remain open |
| WP8 Replication and traceability | Implementation complete; external gates open | Signed replication-bundle and release-security code are present; all 223 requirements and 35 TBRs are tracked, but independent replication, publication, approval, and closure of open requirements remain external gates |

## Milestone sequence

1. M0: controlled reconstruction baseline, clean install, tests, experiment manifest, and canonical study revision 0.1.
2. M1: expanded TLA+ model, weakened variants, model-check evidence, and runtime conformance tests.
3. M2: independent outcome oracle, stronger baselines, ablations, and multi-seed statistical analysis.
4. M3: public power-system model and local process/virtual-device command boundary.
5. M4a: capability-separated deterministic-local plant, signed-observer, and
   research virtual-PLC loop; retained evidence and broader WP4 integration
   remain separate gates.
6. M4b: immutable root-signed evidence, capability probes, restart/replay
   evaluation, and a separate-process topology-consequence check for the M4a
   loop under the same-host deterministic-local boundary.
7. M4c: same-host fault, contradiction, restart, ledger-crash, and stale-permit
   campaign for the capability loop.
8. M4d: bounded single-host Docker network segmentation and service-loss campaign.
9. M4e: ephemeral-key signed gateway/OT transport and hostile-peer/replay tests.
10. M4f: identity-bound durable exact-envelope replay admission across one
    orderly OT-adapter replacement, with liveness and corrupt-ledger tests.
11. M4: workload identity and revocation, full capability-contract transport,
    rollback-resistant coordination, and six-node deployment.
12. M5: operate-through-compromise and degraded-mode evaluation.
13. M6: logical fleet scaling and economic sensitivity model.
14. M7-M8: independent review, replication package, publication, and release.

## Immediate acceptance gates

- A clean editable install succeeds without `PYTHONPATH`.
- Security-critical rejection paths have positive, negative, and property-based tests.
- The committed ActionProposal schema is generated from and checked against the runtime model.
- Every experiment records code state, configuration, host, seeds, and result hashes.
- The outcome oracle is implemented separately from the gateway safety evaluator.
- The canonical DOCX is the only manuscript and identifies Angelis Pseftis as author and editor.
- Synthetic results remain labeled as local measurements under stated assumptions.

## Active M3 increment

Implemented and locally verified:

- Pandapower 3.5.4 CIGRE MV balanced steady-state AC power-flow adapter with
  model, input, topology, and state digests.
- Trusted resource-to-actuator translation and transactional candidate/commit
  behavior.
- Signed, short-lived, single-use execution permits bound to the exact proposal,
  command, decision evidence, model, topology, pre-state, and expected post-state.
- A spawned child process containing the permit-aware PyModbus virtual device
  and physical model, reached only through the tested Modbus TCP loopback path.
- Signed response and command acknowledgments, readback correlation, replay
  protection, stale-state rejection, candidate re-attestation, atomic rollback,
  concurrent compare-and-swap behavior, restart-epoch invalidation, and explicit
  unknown-effect handling.
- Generated public schemas for the M3 trust-boundary messages.
- An isolated candidate suite of 478 passing tests at 92.05 percent branch-aware
  coverage, together with clean ruff, strict mypy, and schema-drift checks. The
  candidate run used committed retained-evidence files while preserving the
  user-modified copies in the primary working tree.
- A retained primary controlled run and separate local reproduction, each
  containing 30 fresh child-process sessions, 150 trials, and 270 chained
  evidence events. Both pass the offline verifier from the matching clean
  checkout and reproduce deterministic outcome hash
  `150b32da0055da6086a8f858f8dab4425d06b5bfd836ba653a10c1f20adf9005`.
- Primary-package observations of 0 modeled effects and 0 unauthorized device
  applications under the registered 120-trial end-to-end non-nominal metric,
  30/30 nominal closed-loop completions, and 0/30 replay effects. The
  unauthorized-application denominator includes 60 gateway no-dispatch trials
  and is not conditional on device dispatch. The fail-fast runner observed 0/150
  unknown effects, and the narrow proposal/decision/terminal-hash trace indicator
  was complete for 150/150 trials. These are fixed-condition conformance checks,
  not field-rate or ambiguity-rate estimates.

Evidence boundary and remaining M3 gates:

- The process boundary is on one host and the protocol is bound to loopback; it
  is not segmented OT networking or multi-VM isolation.
- The device is a PyModbus research virtual device, not OpenPLC or a physical
  PLC.
- The simulator is balanced steady-state power flow, not transient, protection,
  hardware-in-the-loop, or field behavior.
- HELICS coordination, OpenPLC integration, multi-VM deployment, and external
  validation remain uncompleted work.
- The locally reproduced package records the same commit and lock-file hash,
  host metadata, Python version, and selected component versions; it is not
  independent replication. The unsigned
  package manifests establish internal consistency with the recorded checkout,
  not external authenticity, custody, or operational effectiveness.
- Exactly 90 trials per retained package contain signed device acknowledgments.
  The 60 gateway no-dispatch trials per package are recorded as verified/not
  applicable because no device acknowledgment should exist.

WP4 therefore remains in progress. Passing tests establish local implementation
behavior under the tested conditions; they do not satisfy the WP4 exit gate or
establish operational effectiveness.

## Active M4a capability-separation increment

Implemented, retained, and locally reproduced:

- Distinct spawned plant, signed-observer, and Python research virtual-PLC
  processes with distinct PIDs and separate observer/PLC signing keys and boot
  epochs.
- A closed-loop controller with observation, candidate-simulation, and PLC-
  dispatch ports but no plant-apply handle. The trusted local harness separately
  retains lifecycle administration and permit-signing authority.
- Canonical JSON application frames over private process pipes with static
  operation allowlists and generated public schemas.
- A sole plant-apply endpoint created inside the plant supervisor and passed
  directly to the virtual PLC; negative probes exercise unavailable apply
  operations on observer, simulation, telemetry, and coordinator-admin paths.
- Permit and compare-and-swap binding across PLC identity, key, boot epoch,
  model, topology, state version, state digest, pre-observation digest, and
  expected post-state.
- Completion requiring one transaction-valid PLC-signed applied acknowledgment
  plus a fresh separately observer-signed post snapshot directly linked to the
  transaction's pre-observation and matching the authorized state.
- Explicit `not_dispatched`, `candidate_rejected`, `plc_rejected`,
  `unknown_effect`, `observation_diverged`, and `completed` terminal states,
  with at most one dispatch attempt and no automatic retry.
- Replay reservations surviving one orderly PLC-child replacement while the
  local lab remains running.

Acceptance boundary:

- Separation is at the application/process-capability level on one host under
  one OS user, filesystem, and clock domain. It is not a security boundary
  against a hostile coordinator or host.
- The observer and candidate evaluator read the same authoritative deterministic
  plant. The observer is separately keyed and separately processed, but it is
  not an independently operated sensor or an independently validated model.
- Post-observation linkage is transaction-local, not a continuous global chain.
- Replay state is temporary and covers one orderly child replacement only; it
  is not durable across host crash, power loss, tampering, or full-stack restart.
- The smoke output is transient operational status, not a retained manifest,
  signed-artifact package, offline verifier, reproduced experiment, or
  replication result.
- HELICS, OpenPLC and physical-PLC integration, real-time scan semantics,
  segmented or multi-host deployment, hardware-in-the-loop, recovery evaluation,
  concurrent controllers, external validation, and operational effectiveness
  remain open. M4a does not satisfy the WP4 exit gate.

## Active M4b independent-consequence evidence increment

Implemented and locally conformance-tested:

- Closed M4b transaction, component-registration, capability-probe, orderly-
  restart, independent-evaluation, trust-anchor, manifest, and detached-
  signature contracts with generated schemas.
- A solver-neutral topology fixture derived from the registered CIGRE MV model
  and a separately implemented graph/Decimal consequence evaluator that does
  not import the Aegis-OT controller, pandapower, or its numerical stack.
- A file/process bridge that converts a retained M4a transaction into a closed
  independent-evaluation request, executes the separate evaluator process, and
  rejects malformed, unsigned, incorrectly bound, or exit-code-inconsistent
  reports.
- A live same-host lab test in which one completed line-isolation transaction
  crossed that process boundary and returned a signed `agree` report for the
  registered topology consequence.
- A stable pre-report transaction projection for evaluator binding. This
  removes the former circular dependency in which a transaction record could
  hash a report that itself hashed a request claiming to hash the final
  transaction record.
- An immutable, content-addressed package finalizer and offline verifier with an
  external Ed25519 trust anchor, detached manifest signature, exact artifact
  hashes and counts, canonical JSON/JSONL checks, closed schemas, transaction
  correlations, source/fixture/configuration bindings, and separate integrity,
  acceptance, and checkout-match results.
- Two separately finalized 30-session packages from clean detached checkout
  `ad3f3a9c861d53293c1b764226e33c7bcc991234`. Each package contains 90
  transaction records, 120 denied capability probes, 30 signed independent
  evaluations, and 30 orderly-restart replay attempts. Both passed the offline
  verifier with trusted roots, accepted experiment semantics, and matching
  checkout bindings.
- Across each package, 30 nominal transactions completed with exactly one
  dispatch and no automatic retry; 60 identity/freshness cases were not
  dispatched; all 120 capability probes were denied; all 30 replay attempts
  were rejected without a second state effect; and all 30 independent
  topology-connectivity evaluations returned `agree`.
- The two packages have different package IDs and signing keys but the same
  timing-independent deterministic outcome hash
  `02af9e6b29b55fbde8a7de2ba2c45754281f61f9439a182541ca27632d0c0ebf`.
  This is a same-code, same-host local reproduction, not an independent
  replication.
- The clean detached checkout passed 516 tests; ruff, strict mypy across 43
  source files, generated-schema drift, and neutral-topology-fixture drift
  checks were also clean. The single warning is an upstream Starlette/httpx
  deprecation warning and did not affect test outcomes.

Evidence boundary and next hypothesis-critical gate:

- M4b supports only the tested same-host deterministic-local proposition: the
  registered identity and freshness failures were stopped before dispatch,
  unavailable cross-role capabilities remained unavailable, the registered
  nominal command produced one exact modeled effect, orderly replacement did
  not permit replay, and a separately implemented topology-connectivity check
  agreed with the retained post-observation.
- The evaluator does not independently sense the plant and is not an independent
  AC power-flow solver. It checks signed retained observations against a neutral
  topology/load fixture using graph and decimal arithmetic. Agreement therefore
  does not validate the plant model, measurements, voltage or thermal behavior.
- The M4b package itself does not exercise signed contradiction,
  missing-observation, malformed evaluator input, lost-response/unknown-effect,
  concurrent-controller, crash-recovery, or hostile-host conditions. The
  subsequent M4c campaign below covers a bounded subset of these faults but is
  not a replacement for M4b's raw signed package.
- M4b is not external custody, independent replication, segmented or multi-host
  deployment, HELICS/OpenPLC integration, hardware-in-the-loop, field evidence,
  production readiness, operational effectiveness, or WP4 completion.
- The highest-value local claim-critical conditions are now covered by M4c.
  Identity/policy/control separation must next move across an actual segmented
  deployment before the central system claim can be tested beyond a single-host
  process-capability boundary.

## Active M4c fault and adversarial increment

Implemented and locally reproduced in its stronger v6 form from clean detached
checkout `b93f199ec8bff529dd58d145bbd56f90e0c3a233`:

- A five-condition live-process campaign, with a fresh capability-separated
  plant, observer, virtual PLC, and controller stack for every condition.
- One nominal control completed with a valid acknowledgment and signed post-
  observation. Three after-dispatch faults—PLC response loss after an actual
  commit, post-observation unavailability after an acknowledged commit, and a
  post-observation altered after signing—each terminated as `unknown_effect`
  with exactly one dispatch and zero automatic retry.
- A fifth condition started the observer in a fixed experiment profile that
  signed the transaction predecessor as the post-state. The envelope was
  structurally valid, correctly signed, and transaction-bound, but contradicted
  the PLC acknowledgment, permit expectation, and actual plant state. The
  controller returned `observation_diverged`; the separate evaluator returned a
  valid signed `contradict` report with served-load, total-load-served, and
  isolated-resource mismatches.
- In all five conditions, a separate follow-up signed capture observed the
  modeled feeder isolation at state version 1. This matters because the three
  fault cases did not mean “no effect”; they meant the controller lacked enough
  trustworthy completion evidence to claim a known outcome.
- The post-signature tamper initially exposed a controller defect: terminal
  result construction attempted to retain an internally inconsistent envelope
  and raised a validation exception. The controller now revalidates rejected
  envelopes, retains only the last known-valid observation, and returns the
  terminal `unknown_effect` result. A regression test covers the failure.
- A separate evaluator process received strict-JSON duplicate-key input,
  returned exit code 2 with a self-verifying signed `input_rejected` report, and
  rejected a post-signature alteration of that report.
- A valid, signed, fixture-bound evaluator request containing the nominal pre-
  observation and command but no post-observation returned a valid signed
  `indeterminate` report with reason `post_observation_unavailable`; it did not
  infer agreement or contradiction from incomplete consequence evidence.
- A sixth lifecycle condition closed the complete plant/observer/PLC/controller
  stack, retained an externally owned replay ledger, started a fresh stack with
  new process identities and observer/PLC boot epochs, and submitted the exact
  prior request, permit, observation, decision, and assessment. The new PLC
  returned a validly signed `transaction_replayed` rejection before dispatch;
  the fresh plant state and ledger contents were unchanged.
- The ledger persistence path now uses exclusive temporary-file creation,
  complete writes, file fsync, atomic replace, and parent-directory fsync. Two
  actual spawned crash workers exited immediately before replace and immediately
  after replace but before directory fsync. Before replace, the prior ledger was
  byte-for-byte unchanged and the uncommitted reservation absent. After replace,
  the reloaded ledger was valid and contained both reservations. The loader also
  rejects symlinks, oversize files, duplicate keys, extra/missing fields, and
  duplicate or noncanonical reservation sets.
- A final local TOCTOU condition prepared two distinct authorized transactions
  against the exact same signed pre-observation before either dispatch. The
  first applied and returned a valid committed acknowledgment. The second
  reached the PLC but returned a valid signed pre-dispatch
  `topology_digest_changed` rejection. The PLC observed two execute requests,
  retained one replay reservation, and the second transaction produced no state
  effect.
- The v1-v5 reports remain retained as historical increments. Two separately
  retained read-only v6 reports both met all registered criteria and reproduced
  deterministic projection hash
  `baeef9dfd25d945001244cdce5f13b43c14e0ea675ea5fdb2f5d2bcf0a1d8011`.
- The clean checkout passed 522 tests; ruff, strict mypy across 44 source files,
  schema drift, and topology-fixture drift checks were clean.

Evidence boundary and remaining critical tests:

- M4c is injected-port, same-host deterministic-local fault evidence. The
  retained JSON reports summarize the validated outcomes but do not retain the
  complete raw signed transaction/evidence artifacts or an external package
  trust anchor as M4b does. Git retention provides repository integrity after
  commit; it is not external custody or independent validation.
- The observed `unknown_effect` transitions support fail-closed outcome
  classification and no-retry behavior under the three registered injections.
  The signed contradiction supports explicit divergence classification under
  its registered profile. Five deterministic cases do not estimate failure
  rates, recovery times, or
  behavior under arbitrary faults.
- The replay result establishes persistence across an orderly full-stack
  shutdown and restart when the ledger directory remains available. It does not
  establish atomic durability under process kill during write, OS crash, power
  loss, filesystem corruption, rollback, deletion, or hostile-host tampering.
- The crash workers test the two registered write boundaries, not arbitrary
  instruction-level termination, kernel/filesystem defects, or whole-host power
  loss. The competing-permit condition is controlled sequential dispatch of two
  pre-prepared transactions, not a scheduler-distributed multi-controller rate
  test. Process crash during command dispatch, hostile coordinator/host,
  segmentation, HELICS/OpenPLC, and hardware conditions remain untested or lack
  retained experimental evidence.

## Active M4d segmented-container increment

Implemented and locally reproduced from clean detached checkout
`61fac4159163e7a92886263a4327dd1ef1a328ac`:

- Explicit `agent`, `trust`, `control_dmz`, and `simulation` Docker networks.
  The segmented gateway bridges the required planes; OPA is attached only to
  `trust`; the observer and OT adapter bridge `control_dmz` and `simulation`;
  the authoritative synthetic simulation is attached only to `simulation`.
- The existing read-only public demo remains the `gateway` service on loopback
  port 8080. The new assured-path experiment is a separate
  `segmented-gateway` service on loopback port 8081.
- The agent-only probe could reach the segmented gateway but could not resolve
  or connect directly to the observer, OT adapter, or simulation. Docker network
  inspection independently retained the actual container membership observed
  during each run.
- A contextual local policy check now requires agreement from the pinned OPA
  service before permit. Loss of OPA produced `policy_service_unavailable`, a
  deny decision, no OT dispatch, and no state-version change.
- A modeled-unsafe isolation was denied without dispatch. A safe isolation was
  permitted and executed exactly once, advancing the synthetic state from
  version 1 to version 2 and isolating only `feeder-1`. Exact proposal replay
  was denied without a second dispatch or state effect.
- Observer loss made the gateway observation route return HTTP 503 and recovered
  without a state change. OT-adapter loss made the action route return HTTP 503;
  after the adapter restarted, the observer confirmed that the authoritative
  state version had not changed.
- Two separately generated read-only evidence files bind the clean commit,
  resolved Compose SHA-256
  `7642a65edae03e46062ca53dbc681ae73e81c7f019ec706bce07afa535900d3a`,
  Docker host and image metadata, actual network membership, probe output, and
  all nine acceptance criteria. Both are accepted and share semantic outcome
  SHA-256
  `3d12b32085b6447320046884b085ab36039c404bb11db20afc3e81248e972aba`.
- The exact commit passed 528 tests; ruff, strict mypy across 46 source files,
  schema drift, public-demo drift, and Compose resolution checks were clean.

Evidence boundary and next hypothesis-critical gate:

- M4d establishes only the tested Docker network membership and observed
  in-container reachability on one local macOS/Docker Desktop host. Docker
  internal networks are not evidence of separate hosts, administrative domains,
  VM firewall enforcement, hostile-container resistance, or physical OT zones.
- The segmented path uses the v0.1 synthetic supervisory state and command
  adapter. It does not use the M3 pandapower/PyModbus path or the M4a/M4b signed
  observation, signed permit, signed PLC acknowledgment, and raw evidence
  package across containers.
- Actor identity remains an allowlisted identifier in the proposal body.
  Interservice HTTP is unsigned and unencrypted inside the local Docker
  networks. M4d therefore does not establish workload identity, peer
  authentication, message-origin integrity, or protection from a compromised
  trusted service.
- The retained files are local summaries with Git integrity after commit, not
  externally anchored signed packages, independent replication, external
  validation, operational effectiveness, production readiness, or WP4 exit.
- The next gate is to carry the M4 capability contracts across the network with
  cryptographically verified workload/service identity and signed permit and
  acknowledgment validation, then repeat bypass, service-loss, replay, stale-
  state, and hostile-peer tests before moving to the six-node deployment.

## Active M4e authenticated-transport increment

Implemented and locally reproduced from clean detached checkout
`0cd353c9eae9025c2515f845d09c2d3ad6c5e43c`:

- The optional authenticated Compose overlay provisions distinct ephemeral
  Ed25519 gateway and OT-adapter keypairs through Docker secrets. The gateway
  receives its private key and the OT public key; the OT adapter receives the
  gateway public key and its own private key. Private key bytes are not written
  into the repository or retained evidence.
- The gateway signs a closed, versioned execution envelope that binds the exact
  proposal and decision, OT audience, gateway key ID, unique transport nonce,
  issuance time, and five-second expiry. Authenticated OT mode rejects unsigned,
  wrong-key, altered-after-signing, wrong-audience, expired, or replayed
  envelopes before simulation dispatch.
- The OT adapter signs its execution result and binds it to the SHA-256 of the
  exact signed gateway request. The gateway verifies the expected OT key ID,
  request binding, and signature before returning the execution result.
- The normal agent-only campaign passed through this signed transport while
  preserving the M4d bypass, unsafe-denial, one-effect nominal, and proposal-
  replay results.
- A separate control-DMZ transport probe verified unsigned rejection (HTTP 403),
  forged-signature rejection (403), one valid controlled key-holder execution
  with a verified OT response signature (200), exact signed-envelope replay
  rejection (409), and post-signature nonce alteration rejection (403).
- Two read-only clean-checkout reports use separately generated keypairs but the
  same normalized Compose SHA-256
  `9247d5724d0abfccd9870d63d544f1be6ad3eadd43cec6fa112b55a9fee4a2f1`
  and semantic outcome SHA-256
  `5b5bb62a04702a8c45a75f728c2ced7e5e4221abe8ba25dd01843757c2a88dbd`.
  Both passed all six registered M4e criteria. Each retains only the public-key
  hashes and records `private_key_material_retained: false`; the runner stopped
  the keyed services and deleted the temporary key directory after each run.

Evidence boundary and next hypothesis-critical gate:

- M4e authenticates messages from possession of experiment-provisioned Ed25519
  keys. It does not establish SPIFFE/SPIRE workload identity, certificate
  lifecycle, TLS peer authentication, key revocation, protected key storage, or
  independent administrative domains.
- The controlled valid-key probe demonstrates the authority and replay behavior
  of a gateway-key holder; it is not an untrusted peer. Gateway-key compromise
  remains a trusted-boundary compromise with authority to issue signed permits.
- M4f closes the bounded exact-envelope replay-after-orderly-replacement test by
  moving the reservation to an identity-bound named-volume ledger. Crash and
  power-loss durability, rollback protection, multi-instance coordination, and
  key rotation during in-flight transactions remain untested.
- The signed envelope wraps the v0.1 `Decision` and synthetic command path. It
  does not yet carry the full M4a/M4b signed observation, candidate assessment,
  capability permit, PLC acknowledgment, or root-signed evidence package across
  containers.
- The retained JSON files are local experiment summaries, not raw signed-message
  packages, independent replication, external validation, production readiness,
  operational effectiveness, or WP4 exit.
- The next gate is workload-bound key/certificate issuance and revocation plus
  migration of the complete M4 capability transaction across authenticated
  channels. That path must then be retested under stale identity, hostile-peer,
  partition, restart, rollback, and outcome-reconciliation conditions.

## Active M4f durable authenticated-transport replay increment

Implemented and locally reproduced from clean detached checkout
`815712aa656905a28a3d4412137ba989506a7c3c`:

- The optional replay overlay attaches the OT adapter to a private Docker named
  volume initialized by a one-shot, networkless service. The initializer creates
  a mode-0700 directory and mode-0600 ledger, assigns them to runtime UID/GID
  65532, and exits before the unprivileged, read-only-root-filesystem OT adapter
  starts.
- The canonical ledger binds schema, OT audience, gateway key ID, and gateway
  public-key SHA-256. Each accepted transport nonce and complete signed-request
  SHA-256 is reserved before simulation dispatch through a complete write, file
  fsync, atomic replacement, and parent-directory fsync. Missing, malformed,
  noncanonical, oversized, symlinked, incorrectly permissioned, or identity-
  mismatched state fails closed.
- The full signed-transport campaign still passes. A separate request is signed,
  executed, and retained immediately before only the OT-adapter container is
  replaced. The unchanged OPA, observer, segmented gateway, and simulation
  container IDs and start times bind the tested fault to that adapter
  replacement.
- The exact still-valid retained envelope received HTTP 409 after replacement;
  the replay ledger and synthetic state remained at four reservations and state
  version 4. A fresh valid request then executed, advancing the ledger to five
  reservations and state to version 5. This demonstrates bounded liveness after
  reload rather than a permanently closed adapter.
- After deliberate ledger corruption, another fresh, signature-verified request
  received HTTP 503 and state remained at version 5. The fault therefore tests
  otherwise admissible work, not only a previously consumed nonce.
- The retained reports include exact signed messages, public verification keys,
  raw canonical ledger bytes and hash, request/response bindings, container
  identities, state transitions, cleanup outcomes, and 19 offline artifact
  checks. Both reports satisfy all 11 registered acceptance criteria and share
  semantic outcome SHA-256
  `447023e0541f7bc44e9f2c35421e19871b86b93e547abb23a779fc917eede1b4`.
- The primary and reproduction report files were generated with fresh keys,
  projects, and volumes and then independently rechecked from the exact clean
  source. Both record removal of their Compose project, replay and probe
  volumes, and private-key directory, with
  `private_key_material_retained: false`.
- The subsequent clean verification suite passed 708 tests at 91.61 percent
  branch-aware coverage without coverage exclusions or a reduced threshold.
  The M4f initializer and segmented runtime each reached 100 percent in that
  aggregate run; the M4b package verifier reached 91 percent. Ruff, strict mypy
  across 50 source files, schema, public-demo, topology-fixture, and base/M4f
  Compose-resolution checks were also clean. The one warning is an upstream
  Starlette/httpx deprecation warning.

Evidence boundary and next hypothesis-critical gate:

- M4f supports durable at-most-once admission of an exact authenticated
  envelope only across the registered orderly replacement of one OT-adapter
  container, with one Uvicorn process, one writer, an intact trusted volume, and
  unchanged gateway key identity. It does not establish exactly-once effects,
  semantic transaction deduplication, or a known outcome after a response is
  lost.
- The same inner proposal and decision can be signed under a new transport
  nonce. In the registered adversarial case, transport admitted that new
  envelope and the synthetic plant rejected it because its state version was
  stale. Replay safety therefore still depends on the inner state/capability
  contract; the ledger is not a semantic transaction registry.
- The host-filesystem process-exit checks exercise the pre-replace and post-
  replace write branches only. They are supplemental code-path evidence, not
  Docker-volume, abrupt-container-death, operating-system-crash, filesystem-
  failure, or power-loss durability evidence.
- An intact trusted volume does not resist deletion, snapshot rollback, or a
  hostile host. There is no external monotonic anchor and no coordination among
  multiple workers or replicas.
- Ephemeral Ed25519 experiment keys still do not establish SPIFFE/SPIRE
  workload identity, TLS peer authentication, certificate lifecycle,
  revocation, or protected key storage. The transport still wraps the v0.1
  synthetic proposal/decision path rather than the full M4a/M4b signed
  observation, assessment, permit, PLC acknowledgment, and evidence contracts.
- M4f is single-host synthetic evidence, not HELICS/OpenPLC or physical-device
  behavior, multi-host isolation, production readiness, operational
  effectiveness, independent replication, or external validation. WP4 remains
  in progress.
- The next shortest hypothesis-critical path is workload-bound key/certificate
  issuance and revocation together with migration of the full capability
  transaction across the segmented path. Rollback-resistant replay coordination
  and explicit lost-response reconciliation remain separate required gates.

## Read-only public demonstration increment

The local Compose service now publishes a packaged evidence explorer rather
than the mutable research decision API. The explorer presents the retained M2
and M3 records with exact conditional denominators, Wilson intervals, execution
and retention commits, and an explicit current-checkout mismatch. Its builder
recomputes M2 from raw trials, invokes the offline verifier on both retained M3
packages, checks historical Git bindings, and rejects pairwise reproduction
drift across the registered equivalence contract before regenerating the
packaged projection. The mutable decision and
state routes remain available only through a separately launched research
application documented for loopback-only use.

This public-demo increment improves public traceability and removes a default
exposed mutation surface. It did not itself add HELICS, an independently
operated observer, segmented deployment, or external validation, so it does not
advance the WP4 exit gate by itself. The later M4a local process work described
above is not represented as retained public-demo evidence.
