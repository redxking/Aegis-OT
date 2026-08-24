# ADR 0002: Independent Experimental Outcome Oracle

- Status: Accepted for reconstruction baseline
- Date: 2026-08-24
- Decision authority: Angelis Pseftis

## Decision

The gateway safety kernel and the experiment outcome oracle must be separate implementations. Experiments record disagreements rather than treating the enforcer's own result as ground truth.

## Limitation

Two simplified rule implementations are not independent physical validation. A later milestone must use a justified public power-system simulator and a reviewed scenario truth set.
