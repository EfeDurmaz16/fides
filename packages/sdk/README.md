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

const session = await agentd.createSession({
  token: signedDelegationToken,
  capabilityId: 'payments.execute',
  audience: 'agentd',
  delegatorPublicKey: process.env.DELEGATOR_PUBLIC_KEY_HEX,
})

await agentd.recordRevocation({
  record: signedRevocationRecord,
  revokerPublicKey: process.env.REVOKER_PUBLIC_KEY_HEX,
})

await agentd.recordIncident({
  record: signedIncidentRecord,
  reporterPublicKey: process.env.REPORTER_PUBLIC_KEY_HEX,
})

const pending = await agentd.listPendingPropagations(25)
const retry = await agentd.retryPropagations(25)
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
| `AgentdClient.recordRevocation(request)` | Submit signed authority revocations |
| `AgentdClient.recordIncident(request)` | Submit signed authority incidents |
| `AgentdClient.listPendingPropagations(limit)` | Inspect due authority propagation retries |
| `AgentdClient.retryPropagations(limit)` | Replay due authority propagation records |

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
