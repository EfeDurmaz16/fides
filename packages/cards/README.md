# @fides/cards

AgentCard, capability descriptor, capability ontology, and risk taxonomy
entrypoints for FIDES v2.

AgentCards describe who an agent is, who published it, which capabilities it
claims, which transports it supports, what policy requirements apply, and which
protocol versions are compatible. A signed AgentCard is a candidate record, not
an authorization grant.

## Installation

```bash
npm install @fides/cards
```

## Usage

```typescript
import {
  classifyCapabilityRisk,
  createCapabilityDescriptor,
  signAgentCard,
  verifySignedAgentCardIdentity,
} from '@fides/cards'
```

## Status

`@fides/cards` is a framework-agnostic facade over the v2 AgentCard and
capability ontology primitives. It preserves the invariant that discovery and
metadata verification never equal authority.

## License

MIT
