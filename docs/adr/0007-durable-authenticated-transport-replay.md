# ADR 0007: Durable authenticated-transport replay admission

- Status: Accepted for the M4f local experiment; WP4 remains in progress
- Date: 2026-08-25
- Author: Angelis Pseftis

## Decision

Extend the optional authenticated Compose path with an explicitly initialized,
identity-bound replay ledger on a Docker named volume. The OT adapter runs as a
single unprivileged process and reserves the exact transport nonce and complete
signed-request SHA-256 before dispatching an accepted request to the synthetic
simulation. Each reservation is written as canonical JSON through a same-
directory temporary file, followed by file fsync, atomic replacement, and
parent-directory fsync.

The ledger header binds its schema version, OT audience, gateway key ID, and
gateway public-key SHA-256. Startup and request handling fail closed if the
ledger is missing, noncanonical, oversized, malformed, incorrectly permissioned,
symlinked, or bound to another gateway identity. The bounded experiment
replaces only the OT-adapter container while retaining the intact volume and
same gateway key identity, then submits the exact signed envelope created and
accepted immediately before replacement.

## Rationale

M4e authenticated the gateway-to-OT request and OT-to-gateway response, but its
accepted-nonce set existed only in OT-adapter process memory. An adapter restart
therefore reopened the exact transport envelope while its signature and
validity window remained acceptable. Persisting the admission reservation
before dispatch closes that specific restart-replay gap under the tested
single-writer and trusted-volume conditions.

This is an admission guarantee, not an execution-outcome protocol. If the
adapter reserves and dispatches a request but its response is lost, the caller
must classify the outcome as unknown and reconcile against independently
observed state. It must not automatically retry the signed envelope.

## Acceptance

The paired clean-checkout campaign must retain and independently verify the
signed requests and responses, exact request hashes, public keys, canonical
ledger bytes, ledger identity, and prepared reservation. After replacement, the
exact still-valid signed envelope must receive HTTP 409 without changing the
synthetic state or ledger. A fresh authorized request must then execute and
advance state, demonstrating liveness. After deliberate ledger corruption, a
fresh otherwise valid signed request must receive HTTP 503 without a modeled
effect.

The OT-adapter container ID and boot epoch must change, while the OPA, observer,
segmented-gateway, and simulation container IDs and start times remain
unchanged. Cleanup must remove both named volumes and the ephemeral key
directory, and retained evidence must contain no private key material.

## Evidence

Two campaigns executed from clean commit
`815712aa656905a28a3d4412137ba989506a7c3c`. Both retained reports are
accepted, satisfy all 11 registered acceptance criteria and all 19 offline
artifact-verification checks, and reproduce semantic outcome SHA-256
`447023e0541f7bc44e9f2c35421e19871b86b93e547abb23a779fc917eede1b4`.
Their path-normalized Compose documents share SHA-256
`7eff33811df8a91c259e1f19b9335114df62a32a2435ea2d137d6f0e9e18cc19`.

The exact prepared envelope was rejected after adapter replacement with HTTP
409 and no state change. A fresh envelope then advanced synthetic state from
version 4 to 5. A later fresh envelope presented after ledger corruption was
rejected with HTTP 503 and state remained at version 5. Re-signing the same
inner action with a fresh transport nonce is not treated as the same envelope;
in the registered probe, transport admitted it and the synthetic plant rejected
the stale state version.

## Consequences and limits

M4f supports durable at-most-once admission of the exact signed envelope only
across the registered orderly replacement of one OT-adapter container, with one
writer, an intact trusted named volume, and unchanged gateway key identity. It
does not establish exactly-once effects, a known outcome after response loss,
semantic transaction deduplication, hostile-host rollback resistance, an
external monotonic anchor, or coordination among multiple workers or replicas.

The host-filesystem process-exit checks exercise two write-code boundaries but
are supplemental code-path evidence. They are not evidence of Docker-volume
durability under abrupt container death, operating-system crash, power loss,
filesystem failure, deletion, or malicious rollback.

The experiment still uses ephemeral Ed25519 message keys and the v0.1 synthetic
proposal/decision path. It does not establish SPIFFE/SPIRE identity, TLS peer
authentication, key or certificate revocation, protected key storage, the full
M4a/M4b capability transaction across containers, HELICS/OpenPLC or physical-
device behavior, multi-host isolation, production readiness, operational
effectiveness, or external validation.
