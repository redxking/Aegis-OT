# Security Policy

## Scope

Aegis-OT is defensive research software for synthetic and authorized simulation environments. It must not be connected to production control systems, utility networks, third-party infrastructure, or real operational credentials.

## Reporting

Do not publish a vulnerability before the project owner has had a reasonable opportunity to assess it. Use GitHub private vulnerability reporting when enabled or contact the project owner through a verified private channel.

## Security boundaries

- Agent proposals are untrusted input.
- Signatures authenticate data origin but do not authorize execution by themselves.
- The in-process v0.1 services are development approximations, not independent trust domains.
- The local hash chain is tamper-evident only while its trusted head is preserved.
- Simulator safety limits are research parameters, not production settings.

Never commit credentials, signing keys, tokens, sensitive OT data, packet captures containing secrets, CUI, or classified information.
