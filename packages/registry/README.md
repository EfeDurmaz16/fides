# @fides/registry

Registry and federation record entrypoints for FIDES v2.

Registries publish signed index records and peering records. They help agents
find candidates, but they are not an authority source: consumers still verify
AgentCards, evaluate trust, check revocations and incidents, then run policy
before any session grant or invocation.

## Installation

```bash
npm install @fides/registry
```

## Usage

```typescript
import {
  createRegistryIndexRecord,
  createRegistryPeerRecord,
  signRegistryIndexRecord,
  verifySignedRegistryIndexRecord,
} from '@fides/registry'
```

## Status

The current package exposes framework-agnostic protocol record helpers. Hosted,
public, private, and federated registry network implementations are still local
mock or adapter-ready surfaces in this v2 snapshot.

## License

MIT
