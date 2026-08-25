# ADR 0006: Authenticated segmented execution transport

- Status: Accepted for the M4e local experiment; WP4 remains in progress
- Date: 2026-08-25
- Author: Angelis Pseftis

## Decision

Add an optional authenticated Compose overlay to the M4d network topology. For
each experiment run, the runner generates separate Ed25519 gateway and OT-
adapter keypairs and distributes only the minimum required key material through
Docker secrets. The gateway signs a closed request containing the exact proposal
and decision, intended OT audience, gateway key ID, transport nonce, issue time,
and expiry. The OT adapter verifies that request before dispatch and signs a
response bound to the SHA-256 of the complete signed request. The gateway
verifies the OT key ID, request binding, and response signature.

The OT adapter rejects unsigned requests when authenticated mode is enabled and
maintains a process-local set of accepted transport nonces. A separate
control-DMZ probe exercises an untrusted unsigned request, a wrong-key signature,
a valid controlled gateway-key request, exact replay of that signed request, and
alteration after signing.

## Rationale

M4d established network placement but trusted unsigned HTTP bodies between the
gateway and OT adapter. Network isolation alone cannot distinguish the gateway
from another peer that reaches the control DMZ. M4e introduces explicit message
origin and transaction binding without prematurely claiming that experiment
keys are production workload identities.

## Acceptance

The ordinary agent campaign must still pass through the signed path. Unsigned,
wrong-key, and altered signed requests must receive HTTP 403 before simulation
dispatch. One valid controlled key-holder request must execute once and return a
valid OT signature bound to the request. Exact replay of that signed envelope
must receive HTTP 409 without a second execution. A retained run requires a
clean checkout, a normalized Compose hash, public-key hashes, raw probe results,
and explicit confirmation that private key material was not retained.

## Consequences and limits

Ed25519 message signatures establish possession of the experiment-provisioned
keys under the tested conditions. They do not establish SPIFFE/SPIRE workload
identity, TLS peer authentication, certificate or revocation lifecycle,
hardware-protected keys, or separate administrative domains. A controlled probe
given the gateway private key is intentionally authoritative; it is not evidence
that a peer without that key can bypass the gateway.

Transport replay state is in OT-adapter process memory and is lost on restart.
The envelope currently wraps the v0.1 synthetic `Decision`, not the complete
M4a/M4b signed observation, candidate, permit, acknowledgment, and evidence
contracts. M4e is therefore bounded authenticated-transport evidence, not WP4
completion, production readiness, operational effectiveness, or external
validation.
