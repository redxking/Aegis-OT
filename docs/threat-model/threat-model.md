# Threat Model

## Protected objectives

- No unauthenticated, out-of-scope, replayed, stale-state, or modeled-unsafe execution.
- Delegation never amplifies authority.
- Revocation becomes effective within a measured bound.
- Every issued decision has reconstructable evidence.
- Compromise of one agent remains bounded by delegated scope.

## Adversary capabilities

The experimental adversary may control an agent process, possess a valid but bounded credential, poison synthetic telemetry, replay proposals, forge malformed grants, delay service responses, or compromise a supervisor. The model does not assume compromise of all trusted gateway code, cryptographic libraries, host operating systems, and evidence anchors simultaneously.

## Primary validity risks

- Simplified supervisory physics.
- Shared host and process boundaries.
- Model assumptions that exclude unmodeled physical failure.
- Common-mode errors between safety logic and the independent oracle.
- Synthetic scenario prevalence and operator behavior.
