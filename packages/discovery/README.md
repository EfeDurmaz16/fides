# @fides/discovery

Composable agent discovery providers for FIDES.

This package defines the discovery provider interface plus local, well-known, registry, relay, and DHT-ready provider implementations. Use it when an agent runtime needs to resolve AgentCards through multiple sources with deterministic priority and fallback behavior.

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

## License

MIT
