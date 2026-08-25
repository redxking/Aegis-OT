# ADR 0005: Bounded segmented-container assurance path

- Status: Accepted for the M4d local experiment; WP4 remains in progress
- Date: 2026-08-25
- Author: Angelis Pseftis

## Decision

Add a minimum single-host Docker topology that places the agent, OPA, gateway,
observer, OT adapter, and authoritative synthetic simulation on explicitly
separate networks. The segmented gateway is the only component attached to the
agent network and the control DMZ. OPA is reachable only through the trust
network. The observer and OT adapter bridge the control DMZ to the simulation
network, while the simulation joins only that final network.

The agent submits a typed proposal through the segmented gateway. The gateway
resolves the exact observation it previously issued, applies the existing
identity, delegation, freshness, replay, contextual-policy, and surrogate-safety
checks, and requires OPA agreement before a permit decision. The OT adapter
accepts only a matching permit decision and sends the request to the simulation,
which independently rechecks proposal/decision correlation and state version
before applying the synthetic transition.

## Rationale

M4a-M4c established application capability separation and fault semantics on one
host but did not test a network policy boundary. Moving the complete pandapower,
signed-observer, permit, PLC, and evidence package across containers in one step
would conflate network placement, transport identity, key distribution, physical
simulation, and evidence-retention failures. M4d isolates the network-placement
question first and retains evidence of the actual memberships and negative
reachability tests.

## Acceptance

An accepted run requires the agent container to reach the segmented gateway but
not the observer, OT adapter, or simulation directly; deny a modeled-unsafe
action without dispatch; execute one safe action and advance state exactly once;
deny exact replay without dispatch; deny when OPA is unavailable without state
change; make observation unavailable when the observer is stopped; and preserve
state when the OT adapter is unavailable. The runner requires a clean checkout
and retains the Git commit, resolved Compose hash, Docker/image metadata, actual
network inventory, raw condition results, and a normalized semantic hash.

## Consequences and limits

This decision creates real Docker network separation on one local host and a
service-backed OPA gate. It does not create cryptographic workload identity or
authenticate interservice HTTP. The synthetic simulation is not the M3
pandapower/PyModbus path, OpenPLC, HELICS, a physical PLC, or field behavior.
The gateway and trusted service containers are not treated as mutually hostile,
and Docker Desktop is not equivalent to separate hosts or administrative zones.
The result is therefore an M4d network-placement and service-loss finding, not
WP4 completion, production readiness, operational effectiveness, or external
validation.

The next increment must carry signed observation, permit, acknowledgment, and
replay contracts across the network while introducing verifiable workload and
service identities. Only then can hostile-peer, credential-revocation, route-
bypass, partition, and multi-host tests support a broader trust-boundary claim.
