# @fides/invocation

Capability invocation entrypoints for FIDES v2 policy-before-execution flows.

Invocation is the post-discovery authority path. Callers should verify the
session grant, requester signature, schema compatibility, revocation state, kill
switch state, and policy decision before executing capability logic.

## Installation

```bash
npm install @fides/invocation
```

## Usage

```typescript
import {
  createInvocationRequest,
  evaluateInvocationPreflight,
  signInvocationRequest,
  verifySignedInvocationRequestIssuer,
} from '@fides/invocation'
```

## Status

The package exposes protocol and validation helpers. It does not run untrusted
agent code or provide a sandbox; execution hosts must supply their own runtime
isolation and use FIDES decisions as authority inputs.

## License

MIT
