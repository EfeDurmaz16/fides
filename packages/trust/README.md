# @fides/trust

Capability-specific trust scoring entrypoints for FIDES v2.

Trust is a signal. Policy is the authority. This package computes explainable
trust results for a specific agent, capability, principal context, and runtime
state. Scores should be consumed by policy evaluators and user interfaces, not
treated as permission grants.

## Installation

```bash
npm install @fides/trust
```

## Usage

```typescript
import { computeTrustResult, trustBandForScore } from '@fides/trust'

const trust = computeTrustResult({
  agentId: 'did:fides:agent',
  capability: 'invoice.reconcile',
})

console.log(trust.band, trust.reasons)
```

## Status

`@fides/trust` is a typed facade over core trust primitives. The model is
capability-specific and explainable; production deployments should tune weights
and evidence sources for their risk domain.

## License

MIT
