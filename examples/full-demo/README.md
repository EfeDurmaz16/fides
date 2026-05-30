# Full Demo

This directory captures the executable full-demo contract for FIDES v2.

Run the manifest:

```bash
pnpm exec tsx examples/full-demo/run.ts
```

Run the local daemon endpoint:

```bash
pnpm agentd demo run --agentd-url http://localhost:7345
```

Start the local daemon first with `pnpm agentd:dev`. In an installed package
context, the same command is available as `agentd demo run`.

`pnpm agentd demo run` creates local demo identities, signs and registers
AgentCards, publishes candidates through local registry/relay/DHT surfaces, runs
discovery, computes trust and reputation, evaluates policy, issues scoped
sessions, invokes the invoice and payment dry-run paths, records incident and
revocation state, and verifies the local EvidenceEvent hash chain.

The demo also exercises the signed provider metadata surfaces:

- registry discovery returns a verified signed `RegistryIndexRecord`
- relay discovery returns a signed AgentCard reference and AgentCard hash
- DHT discovery returns a signed pointer record with valid pointer verification
- all discovery/provider results keep `authorityGranted: false`

Current limitations:

- DHT, relay, and registry are local mock providers.
- Demo state is held in the current daemon process.
- Payment execution remains Sardis-specific; FIDES only demonstrates dry-run
  payment preparation authority.
