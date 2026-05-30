# @fides/discovery

Composable agent discovery providers for FIDES.

This package defines the discovery provider interface plus local, well-known, registry, relay, and DHT-ready provider implementations. Use it when an agent runtime needs to resolve AgentCards through multiple sources with deterministic priority and fallback behavior.

Discovery resolves candidates, not authority. Local and DHT-backed discovery can
work without an HTTP endpoint URL when the runtime already has the AgentCard or
can resolve it from a signed pointer. Endpoint URLs are transport metadata and
may be added later through relay, registry, well-known, or adapter-specific
channels.

## Installation

```bash
npm install @fides/discovery
```

## Usage

```typescript
import { DiscoveryOrchestrator, LocalDiscoveryProvider } from '@fides/discovery'

const provider = new LocalDiscoveryProvider()
const discovery = new DiscoveryOrchestrator([provider])

const result = await discovery.resolve('did:fides:agent')
```

For capability search without requiring a URL:

```typescript
const candidates = await discovery.discover({ capability: 'invoice.reconcile' })
```

The returned candidates must still pass signature verification, trust scoring,
policy evaluation, and scoped session grant issuance before invocation.

## License

MIT
