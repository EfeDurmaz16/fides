# SDK Reference

The public SDK is Promise-based and does not require Effect.

Current implementation anchors:

- `packages/sdk/src/fides-client.ts`
- `packages/sdk/src/agentd/client.ts`

## FidesClient

```typescript
import { FidesClient } from '@fides/sdk'

const client = new FidesClient({ daemonUrl: 'http://localhost:4817' })

const identity = await client.identity.createAgent({ name: 'Invoice Agent' })
const identities = await client.identity.list()
const sameIdentity = await client.identity.show(identity.identity.did)
const card = await client.cards.create({
  identity: identity.identity,
  name: 'Invoice Agent',
  capabilities: [{ id: 'invoice.reconcile', riskClass: 'medium' }],
})
await client.cards.sign({ id: identity.identity.did })
await client.cards.verify(identity.identity.did)
await client.cards.get(identity.identity.did)
await client.agents.register({ agentCardId: identity.identity.did })
await client.agents.list()
await client.agents.inspect(identity.identity.did)
const results = await client.discovery.find({ capability: 'invoice.reconcile' })
```

`identity.createAgent`, `identity.list`, and `identity.show` target the root
`agentd` identity API. The API does not return private keys. The facade is
intentionally thin. The AgentCard helpers target root `agentd` AgentCard
endpoints and use daemon-held local identity keys for signing. Agent
registration and discovery return candidates only; `authorityGranted` remains
`false` until policy evaluation and session grant issuance. Advanced authority
flows can use `AgentdClient`.
