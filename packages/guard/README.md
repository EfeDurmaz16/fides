# @fides/guard

Pre-execution guard decision engine for FIDES v2.

`@fides/guard` combines the policy engine, trust context, runtime attestation
status, evidence chain status, revocation state, and kill-switch state into a
single allow/deny/approval/dry-run decision before an agent capability is
invoked.

Discovery is intentionally not authority. A discovered agent must still pass the
guard path before execution.

## Install

```sh
pnpm add @fides/guard
```

## Usage

```ts
import { createTrustContext, evaluateGuard } from '@fides/guard'

const trust = createTrustContext({
  reputationScore: 0.9,
  verifiedIdentity: true,
  delegationValid: true,
  attestationFresh: true,
  policyAllowed: true,
  evidenceChainValid: true,
})

const decision = await evaluateGuard({
  agentDid: 'did:fides:agent:invoice',
  capabilityId: 'invoice.reconcile',
  policy,
  trust,
})

if (decision.decision !== 'allow') {
  throw new Error(decision.explanation)
}
```

## Status

This package is part of the FIDES v2 local-first TypeScript implementation. It
is production-shaped for the public SDK surface, while external policy,
attestation, registry, DHT, and relay integrations remain adapter-ready.
