# ADR 0001: Independent Enforcement Boundary

- Status: Accepted for reconstruction baseline
- Date: 2026-08-24
- Decision authority: Angelis Pseftis

## Context

An autonomous agent can be authenticated and still be compromised, misled, stale, or faulty. Identity alone therefore cannot authorize a consequential OT action.

## Decision

Agents submit typed `ActionProposal` objects. Only the Aegis-OT gateway may issue an authorization decision. The gateway evaluates identity, full-chain delegation, contextual policy, replay status, state freshness, modeled safety, and approval state before an adapter may execute a command.

The v0.1 implementation may host components in one process for testability, but each component has a narrow interface and is labeled a development approximation. Later milestones deploy identity, policy, evidence, PLC, and simulation functions across independently controlled boundaries.

## Consequences

This adds latency and availability dependencies. Fail-open behavior is prohibited for consequential actions. Explicit recovery actions require separately bounded authority rather than bypass access.
