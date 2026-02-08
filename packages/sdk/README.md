# @fides/sdk

Decentralized trust and authentication protocol for autonomous AI agents.

## Installation

```bash
npm install @fides/sdk
# or
pnpm add @fides/sdk
# or
yarn add @fides/sdk
```

## Quick Start

```typescript
import { Fides } from '@fides/sdk'

// Initialize FIDES client
const fides = new Fides({
  discoveryUrl: 'http://localhost:3000',
  trustGraphUrl: 'http://localhost:3001',
})

// Generate identity
const identity = await fides.createIdentity('My Agent')
console.log('DID:', identity.did)

// Sign HTTP request
const signature = await fides.signRequest({
  method: 'GET',
  url: 'https://api.example.com/data',
  headers: { 'content-type': 'application/json' },
})

// Verify signed request
const result = await fides.verifyRequest({
  method: 'GET',
  url: 'https://api.example.com/data',
  headers: {
    'signature-input': signature.signatureInput,
    'signature': signature.signature,
  },
})

// Build trust
await fides.attestTrust('did:fides:...', 80)

// Check reputation
const reputation = await fides.getReputation('did:fides:...')
```

## Features

- **Cryptographic Identity**: Ed25519-based DIDs for verifiable agent identities
- **Request Authentication**: RFC 9421 HTTP message signatures for secure communication
- **Decentralized Trust**: Distributed trust attestations with graph-based reputation scoring
- **Agent Autonomy**: Self-sovereign identity without reliance on central authorities

## Core APIs

### Identity Management

```typescript
import { generateKeyPair, generateDID, MemoryKeyStore } from '@fides/sdk'

// Generate keypair
const keyPair = await generateKeyPair()

// Create DID
const did = generateDID(keyPair.publicKey)

// Store keys securely
const keystore = new MemoryKeyStore()
await keystore.storeKey(did, keyPair)
```

### HTTP Signature Signing

```typescript
import { signRequest } from '@fides/sdk'

const signature = await signRequest({
  method: 'POST',
  url: 'https://api.example.com/endpoint',
  headers: {
    'content-type': 'application/json',
  },
  keyId: did,
  privateKey: keyPair.privateKey,
})

// Add to request headers
headers['signature-input'] = signature.signatureInput
headers['signature'] = signature.signature
```

### HTTP Signature Verification

```typescript
import { verifyRequest, IdentityResolver } from '@fides/sdk'

const resolver = new IdentityResolver('http://localhost:3000')

const result = await verifyRequest({
  method: 'POST',
  url: 'https://api.example.com/endpoint',
  headers: {
    'content-type': 'application/json',
    'signature-input': req.headers['signature-input'],
    'signature': req.headers['signature'],
  },
  resolver,
})

if (result.verified) {
  console.log('Request verified from:', result.did)
}
```

### Trust Attestations

```typescript
import { TrustClient, TrustLevel } from '@fides/sdk'

const trustClient = new TrustClient({
  baseUrl: 'http://localhost:3001',
  keystore,
  did,
})

// Create attestation
await trustClient.attest('did:fides:...', TrustLevel.HIGH)

// Get reputation
const reputation = await trustClient.getReputation('did:fides:...')
console.log('Score:', reputation.score)
console.log('Attestations:', reputation.attestations.length)
```

## Documentation

For complete documentation, examples, and protocol specifications, visit:
[https://github.com/anthropic-ai/fides](https://github.com/anthropic-ai/fides)

## Requirements

- Node.js >= 20.0.0

## License

MIT
