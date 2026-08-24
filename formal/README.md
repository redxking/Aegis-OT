# Formal model scope

`AegisAuthorization.tla` is a bounded state-machine model of proposal submission,
authorization or denial, dispatch, command acknowledgment, execution, delegation,
ancestor revocation, expiry, replay control, policy and state consistency, approval,
conflict exclusion, evidence creation, compromise, and quarantine.

The intended configuration enables every enforcement switch and explores all
committed scenarios. Weakened configurations change exactly one enforcement
switch and narrow the scenario set so TLC must find the expected counterexample.
Those switches are model-test instrumentation; they are not runtime settings.

The model establishes properties only for its explicit abstraction, constants,
fairness condition, and bounded state space. It is not a proof of the Python
implementation, a physical process, transport security, or operational safety.
