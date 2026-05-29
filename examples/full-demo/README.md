# Full Demo

This directory captures the executable full-demo contract for FIDES v2.

Run the manifest:

```bash
pnpm exec tsx examples/full-demo/run.ts
```

Run the local daemon endpoint:

```bash
agentd demo run
```

`agentd demo run` creates local demo identities, signs and registers AgentCards,
publishes candidates through local registry/relay/DHT surfaces, runs discovery,
computes trust and reputation, evaluates policy, issues scoped sessions, invokes
the invoice and payment dry-run paths, records incident and revocation state, and
verifies the local EvidenceEvent hash chain.

Current limitations:

- DHT, relay, and registry are local mock providers.
- Demo state is held in the current daemon process.
- Payment execution remains Sardis-specific; FIDES only demonstrates dry-run
  payment preparation authority.
