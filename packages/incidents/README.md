# @fides/incidents

Incident record entrypoints for FIDES v2 reporting, resolution, and trust
impact.

Incident records capture reported failures, abuse, policy violations, and
runtime safety issues. They are evidence-linked inputs for trust, reputation,
and policy decisions.

## Installation

```bash
npm install @fides/incidents
```

## Usage

```typescript
import {
  aggregateIncidentImpact,
  createIncidentRecordV2,
  resolveIncidentRecordV2,
  signIncidentRecordV2,
  verifySignedIncidentRecordV2Issuer,
} from '@fides/incidents'
```

## Status

This package provides signed incident protocol objects and resolution helpers.
It does not operate a federation or moderation network by itself; propagation
and registry integration remain daemon or adapter responsibilities.

## License

MIT
