# @fides/identity

Identity entrypoints for FIDES v2 agents, publishers, principals, and trust
anchors.

Domains are optional. Domain verification is one trust anchor among GitHub,
email, package registry, wallet, passkey, organization invitation, runtime
attestation, build attestation, peer attestation, and evidence history.

## Installation

```bash
npm install @fides/identity
```

## Usage

```typescript
import {
  createAgentIdentity,
  createPrincipalIdentity,
  createPublisherIdentity,
  createTrustAnchorDistribution,
  isValidFidesDid,
} from '@fides/identity'
```

## Status

`@fides/identity` exposes domainless, hosted, domain-verified, and
organization-oriented identity primitives. A valid cryptographic identity is
not a trust grant; trust anchors, evidence, reputation, runtime attestation,
revocation, and policy still need to be evaluated.

## License

MIT
