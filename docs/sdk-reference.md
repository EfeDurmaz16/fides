# SDK Reference

The public SDK is Promise-based and does not require Effect.

Current implementation anchors:

- `packages/sdk/src/fides-client.ts`
- `packages/sdk/src/agentd/client.ts`

## FidesClient

```typescript
import { FidesClient } from '@fides/sdk'

const client = new FidesClient({ daemonUrl: 'http://localhost:4817' })

const identity = await client.identity.createAgent()
const card = await client.cards.create({
  name: 'Invoice Agent',
  capabilities: [{ id: 'invoice.reconcile', riskClass: 'medium' }],
})
await client.cards.sign(card as { id: string })
await client.agents.register(card as Record<string, unknown>)
const results = await client.discovery.find({ capability: 'invoice.reconcile' })
```

The facade is intentionally thin. Advanced authority flows can use `AgentdClient`.
