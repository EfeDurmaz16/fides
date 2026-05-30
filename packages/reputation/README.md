# @fides/reputation

Capability-specific reputation entrypoints for FIDES v2.

Reputation is scoped to capability and context. There is no global popularity
score.

## Installation

```bash
npm install @fides/reputation
```

## Usage

```typescript
import {
  computeCapabilityReputation,
  createReputationRecord,
} from '@fides/reputation'
```

## Status

`@fides/reputation` exposes typed scoring helpers for capability-specific,
principal-aware, publisher-weighted signals. Reputation remains an input to
trust and policy; it does not grant permission to invoke an agent.

## License

MIT
