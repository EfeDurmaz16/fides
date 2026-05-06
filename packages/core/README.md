# @fides/core

Core trust primitives for FIDES.

This package includes agent identities, canonical signing, AgentCards, capability descriptors, delegation tokens, session storage helpers, passkey binding primitives, revocation records, domain verification, and trust anchors.

## Installation

```bash
npm install @fides/core
```

## Usage

```typescript
import { createIdentity, createDelegationToken, classifyCapabilityRisk } from '@fides/core'

const principal = createIdentity('did:fides:principal', 'principal')
const agent = createIdentity('did:fides:agent', 'agent')

const token = createDelegationToken({
  delegator: principal.did,
  delegatee: agent.did,
  capabilities: ['payments.execute'],
  capabilityId: 'payments.execute',
  constraints: { maxActions: 3 },
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
})

const risk = classifyCapabilityRisk('payments.execute')
```

## License

MIT
