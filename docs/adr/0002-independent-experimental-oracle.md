# ADR 0002: Independent Experimental Outcome Oracle

- Status: Accepted for reconstruction baseline
- Date: 2026-08-24
- Decision authority: Angelis Pseftis

## Decision

The gateway safety kernel and the experiment outcome oracle must compute candidate
state through separate implementations. The oracle receives the proposal and
pre-action state, not the kernel's predicted state. It uses independently encoded
decimal arithmetic and conservative reference guardbands. Experiments record
disagreements rather than treating the enforcer's own result as ground truth.

## Limitation

Separate code paths remove the original circular comparison but do not establish
physical independence. Both implementations remain simplified deterministic rules.
A later milestone must use a justified public power-system simulator; the current
human-reviewed scenario catalog is synthetic and is not field truth.
