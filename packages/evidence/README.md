# @fides/evidence

Tamper-evident evidence chains for FIDES.

This package provides hash-chained evidence events, Merkle root computation,
Merkle inclusion proofs, privacy levels, and verification helpers for audit
trails produced by autonomous agents and trust services.

## Installation

```bash
npm install @fides/evidence
```

## Usage

```typescript
import {
  appendEvidenceEvent,
  buildEvidenceMerkleProof,
  createEvidenceChain,
  verifyEvidenceChain,
  verifyMerkleProof,
} from '@fides/evidence'

let chain = createEvidenceChain()

chain = appendEvidenceEvent(chain, {
  id: 'evt_1',
  type: 'invoke',
  timestamp: new Date().toISOString(),
  actor: 'did:fides:agent',
  action: 'payments.execute',
  payload: { amount: '10.00' },
  privacy: { level: 'redacted' },
}, 'signature-hex')

const valid = verifyEvidenceChain(chain)
const proof = buildEvidenceMerkleProof(chain, 'evt_1')
const included = verifyMerkleProof(proof)
```

## License

MIT
