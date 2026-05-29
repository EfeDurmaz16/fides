# Adversarial Simulation

FIDES includes a local adversarial simulation endpoint and CLI command.

Current implementation anchors:

- `services/agentd/src/index.ts`
- `packages/cli/src/commands/simulate.ts`

## Command

```bash
agentd simulate adversarial
```

## Scenarios

- fake agent
- fake publisher
- malicious DHT pointer
- tampered AgentCard
- expired runtime attestation
- revoked agent
- collusive trust attestations
- context laundering
- high-risk capability abuse
- broken evidence chain

Current behavior is a working local prototype. The next hardening step is to wire each scenario to real protocol objects and evidence events.
