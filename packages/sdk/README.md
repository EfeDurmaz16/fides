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

## API

| Function | Description |
|----------|-------------|
| `generateKeyPair()` | Generate Ed25519 keypair |
| `generateDID(publicKey)` | Create DID from public key |
| `signRequest(request, privateKey, options)` | Sign HTTP request (RFC 9421) |
| `verifyRequest(request, publicKey, options)` | Verify HTTP request signature |
| `createAttestation(issuer, subject, level, key)` | Create signed trust attestation |
| `verifyAttestation(attestation, publicKey)` | Verify attestation signature |

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
