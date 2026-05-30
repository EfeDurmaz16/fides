# @fides/core

Core trust primitives for FIDES.

This package includes agent identities, canonical signing, AgentCards, capability descriptors, delegation tokens, session storage helpers, passkey binding primitives, revocation records, domain verification, and trust anchors.

## Installation

```bash
npm install @fides/core
```

## Usage

```typescript
import {
  createAgentIdentity,
  createPrincipalIdentity,
  createDelegationToken,
  signDelegationToken,
  classifyCapabilityRisk,
} from '@fides/core'

const { identity: principal, privateKey: principalPrivateKey } = await createPrincipalIdentity({
  type: 'individual',
  displayName: 'Operator',
})
const { identity: agent } = await createAgentIdentity()

const token = await signDelegationToken(createDelegationToken({
  delegator: principal.did,
  delegatee: agent.did,
  capabilities: ['payments.execute'],
  constraints: { maxActions: 3 },
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
}), principalPrivateKey)

const risk = classifyCapabilityRisk('payments.execute')
```

## License

MIT
