# Adversarial Simulation

FIDES includes a local adversarial simulation endpoint and CLI command. The
current harness executes against local daemon state and protocol primitives; it
does not just return a static scenario manifest.

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

## Current Behavior

The simulation creates local identities and an adversarial AgentCard, then runs
each scenario through the relevant FIDES primitive:

- policy and trust evaluation for fake agents and fake publishers
- signed DHT pointer verification for malicious pointer tampering
- canonical AgentCard signature verification for tampered cards
- MockTEE verification for expired runtime attestations
- revocation-aware policy denial for revoked agents
- trust scoring with peer-signal downweighting for collusion
- capability-specific reputation and context-boundary penalties
- high-risk policy gating for payment execution attempts
- EvidenceEvent hash-chain verification for broken evidence chains

Each scenario emits a local EvidenceEvent reference. The endpoint reports
`status: "detected"` only when every scenario is detected by the relevant
primitive.

Limitations:

- The harness uses local daemon memory, not durable storage.
- DHT, relay, and registry transport behavior is still local/mock.
- Payment execution remains Sardis-specific; FIDES only demonstrates authority
  denial, approval gating, and dry-run control.
