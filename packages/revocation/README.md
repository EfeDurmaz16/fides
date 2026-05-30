# @fides/revocation

Revocation record entrypoints for FIDES v2 identities, keys, AgentCards,
capabilities, sessions, attestations, and publishers.

Revocation records disable compromised or withdrawn authority surfaces.
Revocation must be checked before trust, policy, session issuance, and
invocation.

## Installation

```bash
npm install @fides/revocation
```

## Usage

```typescript
import {
  createRevocationRecordV2,
  isRevocationValid,
  signRevocationRecordV2,
  verifySignedRevocationRecordV2Issuer,
} from '@fides/revocation'
```

## Status

This package provides signed revocation primitives and validation helpers.
Network propagation, registry fan-out, and incident-driven automated response
belong in daemon, registry, or federation adapters.

## License

MIT
