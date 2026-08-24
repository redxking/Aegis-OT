# M3 Steady-State Modbus Process-Boundary Experiment Method

- Author: Angelis Pseftis
- Status: Preregistered design executed; controlled run and local reproduction retained
- Experiment version: `m3-physical-modbus-v1`
- Deterministic projection version: `m3-outcome-projection-v1`
- Evidence boundary: localhost, separate-process, steady-state virtual-device experiment

The governing process-boundary and transaction decision is
[ADR 0003](../adr/0003-steady-state-modbus-process-boundary.md).

## Purpose and claim

This experiment evaluates whether the implemented Aegis-OT path preserves five bounded
authorization and execution invariants across a local Modbus process boundary:

1. an unknown identity is not dispatched;
2. an observation older than the configured freshness limit is not dispatched;
3. an altered permit with a nonmatching audience is rejected by the virtual device;
4. one correctly authorized command produces exactly one verified modeled effect; and
5. reuse of that permit produces no second modeled effect.

The unit under test is the complete local transaction from physical-state capture
through gateway decision, candidate power flow, signed permit, Modbus execute request,
signed acknowledgment, and simulator readback. The retained controlled run is evidence
about this implementation and these fixed conformance conditions. It does not estimate
field failure rates or establish power-system, PLC, network, or operational
effectiveness.

## Controlled result record

The operator run record identifies commit
`168b8bd61a13f70e0871d36e56acbe76a8ebb659` as the prepared clean checkout. The
unsigned primary manifest records
`working_tree_dirty_at_start: false`, analyst `Angelis Pseftis`, pandapower 3.5.4,
PyModbus 3.15.0, Python 3.14.7, macOS 26.6.2 arm64 host metadata, the lock-file hash,
and model digest
`49b0559c9a7158f9ec6c5ae84c27306dd28119ac0516f465e0b19f22a26f6035`.
Those historical Git and host fields remain self-asserted package metadata rather than
external attestation.

| Record | Primary controlled run | Local outcome reproduction |
|---|---|---|
| Directory | `results/m3-physical-modbus` | `results/m3-physical-modbus-reproduction` |
| Experiment ID | `m3-physical-modbus-v1-20260824T183511767906Z` | `m3-physical-modbus-v1-20260824T183813360253Z` |
| UTC interval | 2026-08-24 18:35:11.767906--18:36:08.939009 | 2026-08-24 18:38:13.360253--18:39:12.025797 |
| Sessions / trials / events | 30 / 150 / 270 | 30 / 150 / 270 |
| Offline verifier | Valid from matching clean checkout; all nine registered checks passed | Valid from matching clean checkout; all nine registered checks passed |
| Deterministic outcome SHA-256 | `150b32da0055da6086a8f858f8dab4425d06b5bfd836ba653a10c1f20adf9005` | Same |

The second manifest records the same source and lock-file hashes, host and operating
system metadata, Python and selected component versions, model, root seed, and fixed
conditions. Matching the deterministic hash demonstrates local outcome reproduction
under those recorded conditions. It does not establish an identical installed
environment and is not independent replication.

### Observed conformance outcomes

| Condition | Trials | Gateway/device result | Modeled state effects | Unknown effects |
|---|---:|---|---:|---:|
| Unknown identity | 30 | Gateway denied; not dispatched | 0 | 0 |
| Stale state | 30 | Gateway denied; not dispatched | 0 | 0 |
| Wrong-audience permit | 30 | Signed device rejection | 0 | 0 |
| Nominal permitted execution | 30 | Applied, signed acknowledgment, and readback matched | 30 | 0 |
| Permit replay | 30 | Signed device replay rejection | 0 additional | 0 |

In the primary package, the observed modeled-effect rate and the registered end-to-end
unauthorized-device-application rate were both 0/120; the two-sided 95 percent Wilson
upper bound for each was 0.0310192. The latter denominator includes 60 gateway-denied
trials that never reached the device and is not a conditional device-acceptance rate.
Nominal closed-loop completion was 30/30, with a Wilson lower bound of 0.886487.
Stale-state execution and duplicate-replay effect were each 0/30, with an upper bound
of 0.113513. Unknown effects were 0/150, but the runner treats any unknown effect as a
failed controlled run; this is a conformance-completeness check, not an empirical
ambiguity-rate estimate. The registered narrow trace indicator--proposal, decision,
and nonempty terminal-evidence hash--was complete for 150/150 trials, with a lower
bound of 0.975030. The stronger package-integrity and semantic checks are reported by
the offline verifier. Zero observed events do not establish an impossible event or a
field failure rate.

Exactly 90 trials in each retained package contain signed device acknowledgments: 30
wrong-audience rejections, 30 nominal applications, and 30 replay rejections. The 60
gateway-denied trials per package contain no device acknowledgment and are counted as
acknowledgment verified under the preregistered not-applicable convention because
dispatch did not occur. The distinction is material and must be retained in downstream
reporting.

The primary package's deterministic nominal post-state had minimum voltage 0.9528655131773979 per unit,
maximum line loading 54.60778755493034 percent, 100 percent synthetic priority-load
service, and zero registered voltage, thermal, or supervisory unsafe-state flags. The
same values in all 30 sessions reflect the single fixed physical model, operating
point, and command; they are not independent physical samples. Controlled nominal
end-to-end host latency had mean 180.551161 ms, median 180.117542 ms, and range
177.116417--184.416541 ms. Latency is single-host descriptive evidence, is excluded
from the deterministic outcome hash, and is not a real-time or OT performance bound.

Both retained packages passed the implementation's offline verifier from the matching
clean checkout. A separate
read-only package audit also recomputed the artifact, source, schema, configuration,
summary, and deterministic hashes without finding an internal discrepancy. Neither
check is external validation: the manifests are unsigned, verification keys are inside
the packages, candidate and authoritative plant paths share the same model, and the
readback comes from that same virtual-device process.

## Preregistered design

The controlled run uses base seed `20260824`. Python's deterministic
`random.Random(seed).getrandbits(63)` derivation produces 30 master seeds. Each master
seed creates one fresh authorization laboratory and one fresh spawned virtual-device
process. Each session executes all five conditions once in the fixed order below, for
30 observations per condition and 150 trial records in total.

The session reference time is `2026-08-24T18:00:00+00:00` plus ten seconds times the
zero-based session index. The fixed time is a reproducibility fixture, not evidence of
clock synchronization or real-time execution. Seeds vary proposal identifiers and
process sessions; they do not vary the physical network, command, load profile, solver,
or condition parameters. Device boot epochs and cryptographic keys are generated anew
and are not derived from the master seed.

Conditions are deliberately not randomized. Within a session, the first three
conditions must have no effect, the nominal condition changes the plant once, and the
replay condition then acts on the consumed nominal permit. Consequently, observations
within a session are ordered and dependent; they are not 150 independent samples of a
physical population.

## System under test

The parent process holds the authorization gateway, evidence chain, trusted command
translator, permit issuer, controller, and verified Modbus client. A spawned child owns
the PyModbus server, permit-enforcing virtual device, acknowledgment key, and
authoritative pandapower plant. Traffic is Modbus TCP bound to `127.0.0.1` on an
ephemeral port. The experiment is designed for one client.

The dependency set pins pandapower 3.5.4 and PyModbus 3.15.0. The plant instantiates
`pandapower.networks.create_cigre_network_mv(with_der="all")` and uses a balanced
steady-state AC Newton-Raphson power flow. The solver configuration is:

| Parameter | Value |
|---|---:|
| algorithm | `nr` |
| calculate voltage angles | `true` |
| initialization | `auto` |
| numba | `false` |
| tolerance | `1e-8` MVA |
| maximum iterations | 20 |
| modeled step | 1.0 second |

The supervisory limits are 0.90--1.10 per-unit voltage, 100 percent maximum line
loading, 90 percent minimum total load served, and 80 percent minimum synthetic
priority load served. Aegis defines packaged load indices 12, 13, 16, and 17 as the
synthetic priority set. The tested nominal command isolates `feeder-1`, which maps to
line index 4, `Line 5-6`, by setting its service state to zero.

The benchmark comes from pandapower's packaged CIGRE MV constructor. pandapower 3.5.4
is distributed under BSD 3-Clause. The priority designation, resource names, element
bindings, command semantics, and supervisory envelope are Aegis transformations, not
CIGRE semantics. Use of the software and adapter under their software licenses does not
resolve separate rights in the underlying CIGRE benchmark publication.

## Conditions and expected observations

| Order | Condition | Injection and path | Preregistered terminal observation |
|---:|---|---|---|
| 1 | `unknown_identity` | Actor is changed to `agent:untrusted`. | Gateway returns `not_dispatched`; no execute request; no state change. |
| 2 | `stale_state` | Controller time is advanced to six seconds after the captured observation; the gateway limit is five seconds. | Gateway returns `not_dispatched`; no execute request; no state change. |
| 3 | `wrong_audience_permit` | A prerequisite permit is issued, then its audience field is changed to `virtual-device:wrong-audience` before submission. | Device returns a signed rejection; actuator and plant value remain unchanged. |
| 4 | `nominal_permitted_execution` | The normal closed-loop path requests isolation of `feeder-1`. | `completed`; one state-version and modeled-state change; applied acknowledgment and matching safe readback. |
| 5 | `permit_replay` | The exact permit, command, proposal, decision, and assessment from condition 4 are submitted again. | Device returns a signed replay rejection; no second state change. |

Changing the audience after signing also invalidates the original Ed25519 signature.
The virtual device currently checks the audience before the signature and returns
`permit_wrong_audience`. This condition therefore evaluates the implemented
altered-audience rejection path; it does not isolate rejection of a still-valid
signature created for a different audience. That stronger condition requires a
separately issued, validly signed wrong-audience fixture.

## Procedure

1. Record the Git commit and dirty-tree state. Use the pinned project and lock-file
   dependencies. A dirty or unknown source state must be labeled and is not suitable as
   the sole basis for a release claim.
2. Start a new laboratory for the session. Confirm that the child PID differs from the
   parent PID. The client verifies the health exchange's signed wire response; retain
   the returned health payload, boot identity, component metadata, and initial physical
   snapshot. The current component artifact does not retain the signed health envelope.
3. Execute the five conditions exactly once in the registered order. Do not retry an
   execute operation after the Modbus commit point. Preserve any `unknown_effect` as the
   terminal disposition.
4. For every condition that reaches record materialization, record the trial artifact,
   pre-state, verified post-state, physical metrics, evidence disposition, and available
   stage latency. An unknown effect has no verified post-state; the current fail-fast
   runner aborts instead of adding that case to a completed `trials.jsonl` file.
5. Verify the session evidence hash chain after all five conditions. Record the event
   chain, trace counts, acknowledgment-verification counts, and process metadata.
6. Stop the child process. Begin the next master seed with a new laboratory, device boot
   epoch, device key, permit key, evidence chain, and baseline plant.
7. After all 30 sessions finish, require one stable instantiated `model_digest` across
   sessions, derive the summary and deterministic projection, write the registered
   artifacts, and compute the manifest hashes.

The intended command is:

```shell
python -m aegis_ot physical-experiment \
  --seed-count 30 \
  --seed 20260824 \
  --output-dir results/m3-physical-modbus
```

The controlled output directory must be new or empty. Do not merge records from
different source states or selectively replace a failed seed. If an assertion,
process, or write fails, retain the source state and terminal log as failure evidence;
do not describe the run as completed. A later full rerun is a distinct run and must
carry its own manifest and hashes.

## Transaction and evidence checks

The snapshot contract carries two SHA-256 bindings. The physical-value `state_digest`
excludes observation metadata. The `observation_digest` binds that value digest to UTC
capture time, capture sequence, source identifier, and clock domain. Candidate-contract
validation and the permit and acknowledgment transaction paths call digest verification.
Merely deserializing or retaining every other snapshot does not prove its digests; a
full artifact audit must invoke `verify_digest()` on each retained snapshot. The permit
binds the pre-state value and observation envelope and the expected next value and
topology.

Before dispatch, the child validates the permit signature, audience, time window,
proposal and decision, command and candidate digests, evidence and policy versions,
pre-state value, observation, topology, model, and one-time identifiers. It re-runs the
candidate, checks expiry again, reserves the permit, nonce, and command identifiers,
and performs a compare-and-swap-style plant commit against the expected pre-state. The
authoritative network is replaced only after the candidate solve converges, remains
inside the supervisory limits, and matches the permitted post-state and topology.

The wire client verifies canonical framing, response payload digest, request digest,
transaction and operation, device and key identifiers, boot epoch, Ed25519 signature,
state-version hint, and a monotonically advancing device transaction counter. For an
applied command, transaction acknowledgment verification also binds the permit,
proposal, decision, command, candidate, pre-state, expected post-state, actuator
setpoint, and readback.

`unknown_effect` is mandatory whenever an execute may have crossed the commit point but
the response or readback cannot establish the disposition. Such a result has no
verified `post_state`, is never retried automatically, and fails the registered
condition assertion. The last state actually observed may be retained for
reconciliation, but it is not relabeled as a verified effect.

## Measures

The following definitions are fixed before the controlled run:

- `state_changed`: pre- and post-observation state versions differ or their physical
  value digests differ. An observation-envelope-only change is not a physical state
  change.
- `device_applied`: a command acknowledgment is present with status `applied`.
- `unknown_effect`: terminal closed-loop status is `unknown_effect`.
- `trace_complete`: the runner has a proposal, decision, and nonempty terminal
  execution-evidence record hash. This is a narrow structural measure, not an
  independent audit of every artifact.
- `acknowledgment_verified`: the acknowledgment passes the registered transaction
  verification when one is expected. For gateway no-dispatch conditions, the field is
  true by not-applicable convention when no acknowledgment exists; it does not mean a
  device acknowledgment was received.
- `physical safe`: the recorded observation reports convergence, no supervisory-limit
  violation, and `unsafe_state == false` under the configured steady-state limits.

Per condition, the summary records the trial count, state-effect count and rate,
device-applied count and rate, unknown-effect count, trace-complete count,
acknowledgment-verified count, and available latency distributions.

Aggregate proportions are:

- denied-command state-effect rate across the four non-nominal conditions, denominator
  120 in a complete run;
- registered end-to-end unauthorized-device-application rate across those same
  120 records, including 60 gateway no-dispatch trials and therefore not
  conditional on device dispatch;
- stale-state execution rate, denominator 30;
- duplicate replay effect rate, denominator 30;
- nominal closed-loop completion rate, denominator 30;
- fail-fast unknown-effect conformance-completeness check across all 150 records,
  not an empirical ambiguity-rate estimate; and
- evidence trace-completeness rate across all 150 records.

For nominal post-states, record minimum voltage, maximum line loading, priority load
served, unsafe-state count, voltage-violation count, and thermal-violation count. Value
statistics include count, mean, median, population standard deviation, minimum, p50,
p95, p99, and maximum. They also include the sample standard deviation and a two-sided
95 percent normal-approximation interval for the sample mean.

Available wall-clock stages are reported in milliseconds with count, mean, median,
population and sample standard deviation, a two-sided 95 percent normal-approximation
interval for the sample mean, minimum, p50, p95, p99, and maximum. Stage keys are
path-dependent and missing stages are not imputed. The runner records child startup
separately. It records gateway decision, candidate simulation, permit issuance, Modbus
execute, state read or readback, and end-to-end timing where the relevant instrumented
path exposes them. The current nominal closed-loop instrumentation does not separately
time command translation; the manual wrong-audience path does. Cross-condition latency
comparisons must account for those different paths. These mean intervals characterize
repeat sessions on the measured host; they are not OT latency bounds.

Observed proportions use a two-sided 95 percent Wilson score calculation. With zero
observed events the reported lower endpoint is zero; with all observations successful
the upper endpoint is one. These intervals describe repetition of the fixed software
conditions, not model-form uncertainty, cyber-adversary prevalence, hardware
reliability, or field risk. Zero observed failures does not establish that failure is
impossible.

The runner is a fail-fast conformance harness. Because any `unknown_effect` violates a
condition assertion, a completed summary can only report zero unknown effects. The
registered unknown-effect count is therefore a completeness check for a conformant run,
not an estimator of the implementation's post-commit ambiguity rate. Estimating that
rate requires a separate fault-injection design that retains failed and indeterminate
trials instead of aborting them.

## Preregistered conformance gate

The run is conformant only if all of the following are true:

- every session contains the five conditions in the exact registered order;
- `unknown_identity` and `stale_state` are `not_dispatched` with no state effect;
- `wrong_audience_permit` and `permit_replay` are `device_rejected` with no state
  effect;
- `nominal_permitted_execution` is `completed` with exactly one state effect;
- every recorded terminal state is safe under the registered steady-state envelope;
- every trace is structurally complete under the definition above;
- every present acknowledgment verifies, and the no-dispatch cases contain no
  acknowledgment;
- every session evidence chain verifies; and
- all fresh processes instantiate one stable model digest.

The runner aborts on a condition that violates its expected status, effect, evidence,
or safety assertion. An abort is a failed controlled run, not an excluded observation.
Passing this gate is conformance evidence for these fixtures; it is not independent
validation or a field-safety certificate.

## Artifacts and hashes

A completed run writes the following evidence set:

| Artifact | Content |
|---|---|
| `trials.jsonl` | One full, timing-inclusive record per condition. |
| `events.jsonl` | Hash-chained gateway and terminal evidence records. |
| `scenarios.json` | Fixed condition catalog and execution order. |
| `summary.json` | Registered counts, rates, intervals, physical values, and latency summaries. |
| `component-health.json` | Per-session process, verified health payload, public verification keys, startup, and initial-state metadata. |
| `evidence-verification.json` | Per-session chain and structural verification counts. |
| `benchmark/provenance.json` | Constructor, version, license boundary, model, and transformation provenance. |
| `solver/configuration.json` | Solver options, limits, step, numeric interpretation, and exclusions. |
| `manifest.json` | Run identity, environment, source/configuration/artifact hashes, and summary. |

The manifest records start and completion times, Git commit and dirty state, all master
seeds, counts, host characteristics, component versions, process boundary, and known
limitations. It stores SHA-256 values for the eight non-manifest artifacts; the
timing-inclusive `trials.jsonl` hash is therefore host-run-specific. It also records
source-file hashes for every Python module in the first-party `aegis_ot` package; hashes of
`pyproject.toml`, `requirements.lock`, and canonical scenario, solver, and benchmark
configuration; the instantiated model digest; the packaged constructor source hash;
the installed pandapower and PyModbus license-file hashes when available; and the Aegis
plant-adapter implementation hash. It also hashes each of the eight exported M3 JSON
schemas for candidate assessment, closed-loop result, acknowledgment, permit, request,
response, command, and physical state.

`deterministic_outcome_sha256` hashes canonical compact JSON Lines containing session
and seed, condition, terminal and decision outcomes, reasons, device and acknowledgment
dispositions, effect and evidence flags, pre- and post-state versions, and selected
post-state safety and physical values rounded to 12 decimal places. It excludes
wall-clock latency, run timestamps, boot and key identifiers, random artifact
identifiers, signatures, and the full evidence records. Equality of this hash is a
bounded cross-run outcome-reproduction check; it is not proof that two runs had
identical timing, cryptographic artifacts, hosts, or complete internal state.

Hashes provide integrity and reproducibility anchors for captured bytes. They do not
provide independent timestamping, source attestation, licensing clearance, physical
accuracy, or external validation.

## Offline retained-evidence verification

After generation, verify the retained package from the checkout whose source,
configuration, lock file, and schemas are expected to match the run:

```shell
aegis-ot verify-physical-evidence \
  --output-dir results/m3-physical-modbus
```

The command emits JSON containing `valid`, an error list, the result of each check
group, record counts, the retained deterministic-outcome hash, and the claim boundary.
It exits with status 1 when `valid` is false. A check not reached because an earlier
parse failed is reported as `null`, not as passing. At most 100 detailed errors are
returned; a final marker reports the number omitted. A valid report requires every
implemented check group to pass:

- `manifest`: `manifest.json` is a closed, strict JSON object with the registered
  experiment, projection, timestamp, Git, host, count, configuration, and run-identifier
  fields. The identifier must derive exactly from the parseable UTC start timestamp,
  completion cannot precede start, count fields are exact JSON integers, and Git and host
  records have closed typed shapes. Duplicate keys and non-finite constants are rejected.
- `artifact_hashes`: every required artifact is represented in the manifest and its
  retained bytes match the recorded SHA-256 value; additional artifact entries are not
  accepted for this fixed package version. Manifest paths are resolved inside the output
  directory; absolute paths, symlinked or non-regular files, and traversal outside the
  package are rejected. Each file is limited to 32 MiB and the registered artifact set
  to 128 MiB. The format accepts at most 100 sessions, which bounds `trials.jsonl` at
  500 records and `events.jsonl` at 900 records; a global JSON Lines ceiling of 100,000
  remains defense in depth. Hashing and parsing use the same bounded captured bytes.
- `record_counts`: seed, session, condition, trial, event, component-health, and
  evidence-verification counts and session sets agree. Master seeds must be unique. A
  complete run must contain five trials and nine evidence records per retained master
  seed.
- `event_chains`: outer wrappers and inner evidence records have closed field sets and
  exact JSON types. Each session has the registered integer master seed, contiguous
  integer outer and inner sequence numbers, correct previous-hash linkage, recomputed
  record hashes, and no duplicate record hash. The event set must equal the decision and
  terminal records referenced by trials. Decision and terminal payloads must exactly
  match the retained transaction artifacts by canonical JSON, including number and
  Boolean types; missing, extra, or contradictory fields fail.
- `trial_semantics`: every session has the five registered conditions in order and the
  correct master seed. Process metadata must contain typed positive and distinct child
  and parent PIDs, the loopback host, a valid TCP port, protocol version 1, a finite
  nonnegative startup time, the registered device/audience/key identifiers, and the
  manifest model digest. Each session must use a unique boot epoch, device identifier,
  device public key, and permit public key; evidence record hashes cannot be reused
  across sessions. Each condition is rechecked against its registered terminal
  status, state-effect, evidence, acknowledgment, and safety expectations. Trial envelope
  and artifact fields are closed and canonical, with exact JSON types. Exact ordered
  denial reasons, complete absence of post-decision artifacts for the two gateway-denial
  fixtures, decision state/policy/safety bindings, finite nonnegative timings, model
  identity, and physical-state continuity from the component initial state through replay
  are enforced. Every physical observation is bound to the registered CIGRE MV model,
  pandapower simulator, `pandapower-cigre-mv-process` source, and `UTC` clock domain;
  observation time and sequence cannot regress within a session. A missing component row
  prevents this check from passing even when the separate record-count check already
  reports the omission.
- `deterministic_outcome`: the verifier rebuilds the timing-independent projection from
  retained trials and compares its SHA-256 value with the manifest.
- `summary`: the verifier recomputes the full summary from retained trials and requires
  it to match both `summary.json` and the copy embedded in the manifest.
- `configuration_bindings`: canonical digests of the retained scenario, solver, and
  benchmark records must match the manifest. The scenario catalog, solver, benchmark
  provenance and model binding, component versions, experiment configuration, stated
  boundary, limitations, and analyst field must equal the registered design by canonical
  JSON, including JSON number and Boolean types.
- `checkout_bindings`: the source hash map must contain every current first-party
  `aegis_ot` Python module, and the schema hash map must contain exactly the eight
  registered M3 schema paths. Those files, `pyproject.toml`, and `requirements.lock`
  must match the verifier's current checkout byte for byte.

For each trial, typed artifact validation reconstructs the retained proposal, decision,
command, candidate, permit, acknowledgment, and physical states. The verifier then:

- calls `verify_digest()` on the retained pre- and post-state snapshots;
- reconstructs each registered non-replay proposal and verifies the exact unknown-
  identity and stale-state injection semantics;
- recomputes `state_changed`, `device_applied`, no-acknowledgment fields, and the
  post-state physical metrics;
- checks decision outcome and proposal/decision identifiers;
- reconstructs the trusted command mapping and permit-issuance prerequisites;
- checks the permit's proposal, decision, command, candidate, pre-state, expected
  post-state, topology, model, evidence, policy, and safety bindings;
- verifies the permit with the per-session permit public key and requires its audience
  to match the retained device, except that the registered wrong-audience fixture must
  preserve a nonmatching audience and an invalid changed signature while restoring the
  expected audience reproduces a valid original signature;
- requires canonical padded URL-safe Base64 for retained public keys and signatures;
- verifies each device acknowledgment and its transaction bindings with the retained
  per-session device public key and requires the exact registered signed disposition;
  and
- requires the replay condition to reuse the nominal proposal, decision, command,
  candidate, and permit without producing a second physical-state transition.

The component artifact retains the public permit-verification key and the device public
key required for those offline checks. It retains a health payload that the live client
already accepted after signed-response verification. It does not retain the signed
health wire envelope, so the offline verifier does not reverify that exchange. The
schema files are hash-bound to the package and current checkout; typed trial validation
uses the current Pydantic contracts rather than treating the exported JSON Schema files
as an independent validator. Explicit state-digest checks cover each trial's retained
pre-state and post-state. The component's initial state and its correlation with the
verified health payload and process metadata are also audited.

The manifest is unsigned. Its artifact hashes, public keys, summaries, and configuration
digests are therefore package-internal claims rather than externally authenticated
anchors. A valid report establishes consistency among the retained package, retained
keys, registered logic, and current checkout. It does not establish package origin,
custody, creation time, third-party authenticity, independent replication, model
validity, or field-device identity. External authenticity would require a protected
signing identity or independently anchored digest and a documented custody process.
The Git and host fields are structurally checked but remain self-asserted package
metadata; the verifier does not independently establish the historical host or dirty-tree
state.
Verification also assumes the local package remains stable while it is being read; it
is not a defense against a privileged process racing directory components during the
offline check.

## Limitations and prohibited interpretations

- The plant is a balanced steady-state model. It does not model electromagnetic
  transients, frequency dynamics, relay or protection timing, subcycle behavior,
  communications timing effects on physics, controller dynamics, or hardware I/O.
- Candidate and authoritative execution use deep copies but the same pandapower model,
  adapter, solver, limits, and child process. Candidate agreement is not an independent
  physical oracle.
- Acknowledgment and readback originate from the same virtual-device process and model.
  They are not independent sensor or field telemetry.
- The Modbus server is a custom Python/PyModbus application mailbox on loopback with one
  intended client. It does not establish generic Modbus-device interoperability,
  multi-client safety, transport confidentiality, network segmentation, or
  cyber-resilience against host compromise.
- Replay state, device keys, and plant state are in memory. Boot-specific audiences
  reject prior-boot permits, but this is not durable device identity or persistent
  replay protection.
- The wire client distinguishes pre-commit transport failure from post-commit ambiguity,
  but the controller conservatively labels any device-execute exception
  `unknown_effect`. The terminal label therefore does not prove that dispatch began.
- Fixed deterministic conditions and 30 process sessions do not represent independent
  physical operating points or a field population. Host latency is environment-specific.
- The wrong-audience fixture combines audience alteration with signature invalidation;
  it does not isolate a validly signed permit issued to a different device.
- The experiment contains no field data, hardware measurement, independent replication,
  or external validation.
- This method does not exercise or claim HELICS, OpenPLC, a physical PLC, a segmented OT
  network, containers, hardware-in-the-loop, field validation, operational deployment,
  or WP4 completion.
