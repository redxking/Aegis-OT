# ADR 0003: Steady-State Plant Behind a Signed Local Modbus Process Boundary

- Status: Accepted for the bounded M3 implementation; controlled evaluation pending
- Date: 2026-08-24
- Decision authority: Angelis Pseftis

## Context

M2 separated the gateway safety kernel from a rule-based experimental oracle, but
neither path was a power-system solver or a control-protocol boundary. M3 needs a
narrower, evidence-producing increment: evaluate an exact command against a public
steady-state network model, authorize that command once, carry it across a process
boundary, and distinguish a verified effect from a rejection or an indeterminate
post-dispatch outcome.

This decision does not make the laboratory an OT deployment. The selected boundary is
one host, one controller client, one spawned virtual-device process, and Modbus TCP over
the host loopback interface. It is intended to expose transaction and evidence semantics
before introducing distributed co-simulation, PLC runtimes, or hardware. The controlled
evaluation procedure is defined separately in the
[M3 experiment method](../experiments/m3-method.md).

## Decision

### Exact trust and process boundary

The parent Python process is the authorization and orchestration side. It contains the
identity, delegation, policy, supervisory safety, and evidence services; the trusted
proposal-to-command mapping; the execution-permit issuer and its Ed25519 private key;
the closed-loop controller; and the verified Modbus client.

A spawned child Python process is the virtual device and plant side. It contains the
PyModbus TCP server and register mailbox, the permit-enforcing virtual control device,
its in-memory replay sets, the authoritative pandapower network instance, and the
Ed25519 private key used to sign both wire responses and command acknowledgments. Of
the permit issuer's key pair, the child receives only the public key. Each child boot
generates a new boot epoch, device identifier, acknowledgment key pair, and audience
value. The parent receives bootstrap metadata and the device public key through the
local process pipe.

```text
Parent process                                      Spawned child process

proposal -> gateway -> evidence -> translator      PyModbus register mailbox
                    -> candidate request  --------> candidate deep copy + power flow
                    -> signed permit      --------> permit-enforcing virtual device
                    -> execute/readback   --------> authoritative pandapower plant
                    <- signed response/ACK <------- device response key

                         Modbus TCP on 127.0.0.1
```

The process boundary protects against accidental in-process coupling and makes
transport ambiguity observable. It is not an independent host, administrative domain,
network security zone, or hardware trust boundary. The parent and child still share one
operating system, user context, filesystem, and host clock. The bootstrap pipe and local
host are trusted for this increment. Modbus TCP is neither encrypted nor authenticated
at the transport layer; integrity and authorization controls are implemented in the
application artifacts and signed responses. The Modbus mailbox is designed for the single
Aegis client created by the laboratory factory; it is not a multi-client arbitration or
industrial interoperability design.

### Plant model and benchmark transformation

The authoritative plant is instantiated from
`pandapower.networks.create_cigre_network_mv(with_der="all")`. Aegis-OT pins
pandapower 3.5.4 and PyModbus 3.15.0 for this increment. pandapower 3.5.4 is the
[official 3.5.4 release](https://github.com/e2nIEE/pandapower/releases/tag/v3.5.4),
and the project is distributed under the
[BSD 3-Clause license](https://github.com/e2nIEE/pandapower/blob/v3.5.4/LICENSE).
The packaged CIGRE network is described in the
[pandapower CIGRE network documentation](https://pandapower.readthedocs.io/en/latest/networks/cigre.html).

Aegis applies an explicit synthetic transformation after instantiation:

| Aegis resource | Packaged element | Allowed command |
|---|---|---|
| `feeder-1` | line index 4, `Line 5-6` | service state 0 or 1 |
| `feeder-2` | line index 6, `Line 8-9` | service state 0 or 1 |
| `battery-1` | storage index 0, `Battery 1` | -1.0 to +1.0 MW injection |

Load indices 12, 13, 16, and 17 are designated as an Aegis synthetic
mission-priority subset. That label is not part of the original CIGRE semantics. For
storage, Aegis positive injection is represented as negative pandapower `p_mw`, because
pandapower uses positive storage power for charging.

The supervisory envelope is 0.90--1.10 per-unit voltage, no line loading above 100
percent, at least 90 percent total load served, and at least 80 percent of the synthetic
priority load served. The solver is a balanced steady-state AC Newton-Raphson power
flow with the configuration recorded in the experiment manifest.

The pandapower constructor and the Aegis adapter remain subject to their respective
software licenses. The generated provenance record hashes the installed pandapower
license file, constructor source, instantiated model, and Aegis transformation. It does
not determine or grant separate rights in the underlying CIGRE benchmark publication.

### State value and observation envelope

A physical snapshot separates the modeled value from the circumstances of observation:

- `state_digest` binds the modeled value, including the model, dynamic input, topology,
  state version, simulation time, solver disposition, physical metrics, and actuator
  state. It excludes observation time, source, sequence, and clock-domain fields.
- `observation_digest` binds `state_digest` to `observed_at`,
  `observation_sequence`, `observation_source_id`, and
  `observation_clock_domain`.
- `model_digest` binds the static instantiated network, pandapower version, solver
  options, supervisory limits, synthetic priority set, and resource bindings.
- `input_digest` binds the mutable calculation inputs and service states.
- `topology_digest` binds indexed connectivity and in-service or switch state for the
  bus, line, switch, transformer, and external-grid tables.

A state capture may advance the observation sequence and envelope without changing the
physical value digest or state version. An authorized plant commit advances the state
version and simulation time exactly once. A candidate projects the next physical value
on a deep copy; its predicted observation envelope is not treated as the future capture
time. The permit therefore binds the pre-action value and observation envelope, but
binds the expected post-action value and topology rather than a predicted post-action
observation timestamp.

This split prevents a fresh timestamp from masquerading as a changed plant value and
prevents an old observation envelope from being reused as current evidence. It does not
establish that the host clock is externally trusted or synchronized.

### Permit, transaction, acknowledgment, and unknown effect

The permit issuer validates the typed proposal, gateway permit decision, command,
candidate assessment, and the referenced hash-chained evidence record before signing.
An `execution-permit-v1` is canonical-JSON/Ed25519 bound to:

- a unique permit identifier and nonce;
- the complete proposal digest and the gateway decision identifier;
- the exact embedded command and command digest;
- the candidate-assessment digest;
- the pre-state version, value digest, observation digest, topology digest, and model
  digest;
- the expected next state version, value digest, and topology digest;
- the evidence-record hash and policy and safety versions;
- the boot-specific device audience, signing-key identifier, issuance time, and expiry.

The default permit lifetime is two seconds. The device checks audience, signing key,
signature, time window, proposal and decision correlation, evidence and version
bindings, candidate integrity, one-time identifiers, and the current state. It then
re-simulates the candidate while holding the device lock, checks expiry again, and
reserves the permit identifier, nonce, and command identifier before dispatch. The
plant applies the command to a deep copy under its own lock, verifies the expected
pre-state by version and digest, solves, rejects unsafe or divergent results, and only
then replaces the authoritative in-memory network. This is atomic within the child
process; it is not a distributed transaction or durable database commit.

The Modbus application mailbox uses canonical JSON, fixed-capacity holding-register
frames, request and payload SHA-256 digests, operation and transaction correlation, and
a signed response. The signed response also binds the device, key, boot epoch, and a
monotonically increasing device transaction counter. The client rejects a counter that
does not advance within its connection.

A signed command acknowledgment reports one of three dispositions:

- `applied`: the child committed the expected modeled state and reports its post-state
  digest, version, simulation time, and actuator setpoint;
- `rejected`: the child asserts that it did not dispatch an effect and binds the
  unchanged pre-state and actuator value; or
- `unknown_effect`: execution passed a point after which the implementation cannot
  establish whether an effect occurred. It must not assert a verified post-state.

The controller reports `completed` only after verifying the acknowledgment signature
and transaction bindings and matching a separate post-execute readback to the expected
post-state. At the wire-client layer, a transport or protocol failure after the execute
commit becomes an unknown effect and prohibits automatic retry; a failure known to be
before commit remains a transport failure. The controller conservatively maps any
exception returned by its device `execute` call to `unknown_effect`, so it may also
classify a known pre-commit communication failure as unknown. An unavailable
post-dispatch readback, an invalid or mismatched acknowledgment, or an unclassified
post-dispatch failure also produces `unknown_effect`. The controller records the last
state it actually observed and leaves the verified `post_state` absent. Recovery
requires a separately authorized reconciliation workflow; it is not implemented by
this decision.

Here, `applied`, `read back`, and `device scan` describe the in-memory virtual-device
process. They do not establish physical breaker movement, an independent sensor
observation, a PLC scan cycle, or hard real-time completion.

### Retained evidence and offline verification

Each experiment session retains the permit issuer's public key and the child device's
public response and acknowledgment key so that the transaction signatures can be
checked after the live process exits. The live client verifies the signed health wire
response, but `component-health.json` retains only the verified health payload, not the
signed wire envelope. Offline verification therefore cannot replay or independently
verify that health-response signature.

The retained package is checked with:

```shell
aegis-ot verify-physical-evidence \
  --output-dir results/m3-physical-modbus
```

The verifier checks the manifest and required artifact hashes; registered session,
seed, condition, trial, and event counts; exact event references and payloads; physical
state continuity, digests, and derived fields; decision, permit, and acknowledgment
transaction bindings; retained permit and device signatures; the deterministic
projection and summary; the exact registered runtime configuration and analyst field;
all eight M3 schema hashes; and hashes for every first-party `aegis_ot` Python module,
the project file, and the dependency lock. The retained process record must also contain
a typed positive child PID distinct from the parent PID, the loopback host, a valid TCP
port, protocol version 1, a finite nonnegative startup time, and the registered device,
audience, and key identifiers. It returns a structured check report and exits
unsuccessfully when any check fails. A check that cannot be reached because a required
dependency is missing is not reported as passing.

For the fixed v1 evidence format, manifest, trial, event, component-health, and
verification records use closed field sets and exact JSON-type comparisons. The verifier
accepts only regular files, caps each retained file at 32 MiB, caps the registered
artifact set at 128 MiB, accepts at most 100 sessions, and consequently caps the v1 trial
and event streams at 500 and 900 records. Error output is capped at 100 detailed entries
plus an omitted-count marker. These bounds limit malformed local-package resource
consumption; they are not a general hostile-host sandbox.

This is an internal-consistency verifier, not an external trust anchor. The manifest is
not signed, timestamped by an independent authority, or anchored outside the package.
The verification keys are themselves retained inside that unsigned package. A valid
report therefore does not establish who produced the package, whether it existed at a
particular time, whether its keys belong to a field device, or whether the model is
physically valid. Current-checkout comparison also means that a source or schema change
can make an older package fail local verification without proving that the older
package was originally corrupt. Verification assumes the local package is not replaced
or modified concurrently while it is being read; the verifier is not a defense against
a privileged process racing intermediate directory components. Git and host metadata are
shape-checked but remain unsigned, self-asserted historical claims.

## Alternatives considered

### Keep the plant and enforcement path in the parent process

This is simpler and remains useful for unit tests, but it cannot exercise transport
correlation, post-commit ambiguity, process lifecycle, or boot-bound audiences. It was
not selected as the M3 execution boundary.

### Use HELICS for the first physical-model increment

HELICS would support distributed co-simulation, but it would add federation timing and
lifecycle concerns before the signed command transaction is stable. It is deferred and
is not exercised by this implementation.

### Use OpenPLC or PLC hardware now

Those paths are necessary for later protocol and hardware claims, but they require a
different safety case, I/O mapping, timing method, network boundary, and recovery plan.
They are deferred; the current child is a Python/PyModbus virtual device, not OpenPLC or
a PLC.

### Treat candidate simulation as an independent outcome oracle

The candidate is non-mutating and is re-run before commit, but it uses the same
pandapower model, adapter, solver options, and process as the authoritative apply path.
It reduces time-of-check/time-of-use drift; it does not provide independent physics or
model-form validation. This interpretation is rejected.

## Consequences

The design provides an auditable, boot-bound, one-time authorization transaction and a
fail-closed distinction between rejected, completed, and unknown effects. It also adds
process startup cost, transport and key-lifecycle dependencies, and a reconciliation
obligation whenever execution crosses the commit point without verifiable readback.

The following limitations remain design constraints, not completed capabilities:

- one host, unencrypted loopback transport, one intended client, and one global mailbox
  transaction;
- ephemeral keys and in-memory replay state rather than durable device identity or a
  persistent replay ledger;
- a shared child process for enforcement, candidate simulation, authoritative apply,
  and readback;
- a steady-state solver with no electromagnetic transients, frequency dynamics,
  protection timing, subcycle behavior, controller dynamics, or hardware I/O;
- no independent sensor, second simulator, field data, external replication, or
  operational validation; and
- no HELICS federation, OpenPLC runtime, physical PLC, segmented OT network, container
  boundary, or WP4 completion claim.

## Required follow-on work

- Complete the preregistered M3 controlled run only from a recorded source and
  dependency state, and report failures rather than replacing them with successful
  reruns.
- Add explicit recovery and reconciliation semantics for post-commit unknown effects.
- Add fault injection at each pre-commit and post-commit transport stage.
- Introduce durable replay and key lifecycle controls before any persistent or
  multi-client device claim.
- Require an independent measurement or model path before asserting physical accuracy
  or field consequence assurance.
- Scope HELICS, OpenPLC, network segmentation, and hardware-in-the-loop as separate
  decisions with their own evidence gates.
