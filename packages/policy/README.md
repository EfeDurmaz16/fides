# @fides/policy

Deterministic policy evaluation for FIDES.

This package evaluates policy bundles against request and trust context before an agent action executes. Decisions are explicit: `allow`, `deny`, `approve-required`, or `dry-run`.

## Installation

```bash
npm install @fides/policy
```

## Usage

```typescript
import { evaluatePolicy } from '@fides/policy'

const result = evaluatePolicy({
  id: 'default',
  version: '1.0.0',
  defaultAction: 'deny',
  rules: [
    {
      id: 'trusted-agent',
      condition: { field: 'reputationScore', operator: 'gte', value: 0.8 },
      action: 'allow',
    },
  ],
}, { reputationScore: 0.91 })
```

## License

MIT
