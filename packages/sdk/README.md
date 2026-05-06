# @fides/sdk

Decentralized trust and authentication protocol for autonomous AI agents.

## Installation

```bash
npm install @fides/sdk
```

## Quick Start

```typescript
import { Fides, TrustLevel } from '@fides/sdk'

const fides = new Fides({
  discoveryUrl: 'http://localhost:3100',
  trustUrl: 'http://localhost:3200',
})

// Create identity
const { did } = await fides.createIdentity({ name: 'My Agent' })

// Sign HTTP requests (with automatic Content-Digest for body integrity)
const signed = await fides.signRequest({
  method: 'POST',
  url: 'https://example.com/api',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ data: 'hello' }),
})

// Verify requests
const result = await fides.verifyRequest(incomingRequest)

// Trust attestations
await fides.trust('did:fides:...', TrustLevel.HIGH)

// Reputation scores
const score = await fides.getReputation('did:fides:...')
```

## agentd Client

```typescript
import { AgentdClient } from '@fides/sdk'

const agentd = new AgentdClient({
  baseUrl: 'http://localhost:7345',
  apiKey: process.env.FIDES_API_KEY,
})

const decision = await agentd.authorize({
  agentDid: 'did:fides:agent',
  capabilityId: 'payments.execute',
  sessionId: 'sess_123',
  audience: 'agentd',
})

const session = await agentd.createSignedSession({
  delegator: 'did:fides:principal',
  delegatee: 'did:fides:agent',
  capabilities: ['payments.execute'],
  capabilityId: 'payments.execute',
  privateKey: process.env.DELEGATOR_PRIVATE_KEY_HEX!,
})

await agentd.recordSignedRevocation({
  did: 'did:fides:agent',
  reason: 'operator disabled',
  revokedBy: 'did:fides:principal',
  privateKey: process.env.REVOKER_PRIVATE_KEY_HEX!,
})

await agentd.recordSignedIncident({
  actor: 'did:fides:agent',
  reportedBy: 'did:fides:principal',
  type: 'policy_violation',
  severity: 'high',
  description: 'attempted payment outside approved policy',
  privateKey: process.env.REPORTER_PRIVATE_KEY_HEX!,
})

const pending = await agentd.listPendingPropagations(25)
const retry = await agentd.retryPropagations(25)
```

## Registry Client

```typescript
import { RegistryClient } from '@fides/sdk'

const registry = new RegistryClient({
  baseUrl: 'http://localhost:7346',
  apiKey: process.env.FIDES_API_KEY,
})

await registry.register({
  id: 'did:fides:agent',
  name: 'Payment Agent',
  version: '1.0.0',
  capabilities: [{ id: 'payments.execute', name: 'Payments' }],
  protocols: ['mcp'],
  endpoints: [],
  security: { authentication: ['api-key'], encryption: ['tls1.3'] },
  metadata: {},
})

const card = await registry.getCard('did:fides:agent')
const matches = await registry.search('Payment')
await registry.setMode('did:fides:agent', 'private')
await registry.updateMetadata('did:fides:agent', { owner: 'ops' })
```

## API

| Function | Description |
|----------|-------------|
| `generateKeyPair()` | Generate Ed25519 keypair |
| `generateDID(publicKey)` | Create DID from public key |
| `signRequest(request, privateKey, options)` | Sign HTTP request (RFC 9421) |
| `verifyRequest(request, publicKey, options)` | Verify HTTP request signature |
| `createAttestation(issuer, subject, level, key)` | Create signed trust attestation |
| `verifyAttestation(attestation, publicKey)` | Verify attestation signature |
| `AgentdClient.authorize(request)` | Check local agentd authorization decisions |
| `AgentdClient.createSession(request)` | Create delegated agentd sessions |
| `AgentdClient.createSignedSession(options)` | Create and sign a delegation token before opening a session |
| `AgentdClient.recordRevocation(request)` | Submit signed authority revocations |
| `AgentdClient.recordSignedRevocation(options)` | Create and sign an authority revocation before submission |
| `AgentdClient.recordIncident(request)` | Submit signed authority incidents |
| `AgentdClient.recordSignedIncident(options)` | Create and sign an authority incident before submission |
| `AgentdClient.listPendingPropagations(limit)` | Inspect due authority propagation retries |
| `AgentdClient.retryPropagations(limit)` | Replay due authority propagation records |
| `RegistryClient.register(card)` | Publish an AgentCard to the hosted registry |
| `RegistryClient.getCard(did)` | Read a public AgentCard, returning `null` when it is missing |
| `RegistryClient.search(query)` | Search public registry cards |
| `RegistryClient.setMode(did, mode)` | Switch a registry card between `public` and `private` |
| `RegistryClient.updateMetadata(did, metadata)` | Merge operator metadata into a registry card |

### Trust Levels

| Level | Value | Description |
|-------|-------|-------------|
| `NONE` | 0 | No trust |
| `LOW` | 25 | Minimal trust |
| `MEDIUM` | 50 | Standard collaboration |
| `HIGH` | 75 | Sensitive operations |
| `ABSOLUTE` | 100 | Full delegation |

## Requirements

- Node.js >= 20.0.0

## License

MIT
