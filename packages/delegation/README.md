# @fides/delegation

DelegationToken and SessionGrant entrypoints for scoped FIDES v2 authority.

Delegation tokens model authority transfer. Session grants are the short-lived,
audience-bound authorization artifacts used before capability invocation. Both
are signed with the shared canonical object signing model.

## Installation

```bash
npm install @fides/delegation
```

## Usage

```typescript
import {
  createDelegationToken,
  createSessionGrantV2,
  signSessionGrantV2,
  verifySignedSessionGrantV2Issuer,
} from '@fides/delegation'
```

## Status

This package exposes scoped authority primitives only. Discovery results, trust
scores, and policy decisions do not grant authority until a valid delegation or
session object is issued and verified.

## License

MIT
