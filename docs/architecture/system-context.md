# System Context

## Planes and responsibilities

| Plane | Responsibility | Trust boundary |
|---|---|---|
| Observation | Acquire timestamped synthetic telemetry | Inputs may be delayed, replayed, or poisoned |
| Agent | Form bounded proposals | No direct control authority |
| Authorization | Verify identity, delegation, policy, freshness, replay, approval | Independently enforced gateway path |
| Safety | Predict candidate transition and enforce modeled invariants | Does not trust agent reasoning |
| Control | Translate authorized decisions into simulated commands | Rejects missing or stale authorization |
| Physical simulation | Produce resulting synthetic state | Not equivalent to real PLC or grid behavior |
| Evidence | Link proposal, decision, command, and outcome | Hash chaining is tamper-evident, not tamper-proof |

## Decision states

The initial executable implementation supports `permit`, `deny`, `require_approval`, and `quarantine`. `modify`, `defer`, `simulate`, and `revoke` remain modeled outcomes for later command-path integration.

## Availability posture

The reconstruction baseline fails closed when identity, delegation, policy, state, replay, or safety validation cannot complete. Future degraded modes must define which recovery actions remain authorized, their scope, and their evidence requirements.
