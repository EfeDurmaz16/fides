# @fides/dht

DHT pointer record entrypoints for FIDES v2 discovery.

DHT records are signed pointers only. They are never trust sources and never
grant authority.

## Installation

```bash
npm install @fides/dht
```

## Usage

```typescript
import {
  createDHTPointerRecord,
  hashAgentCard,
  hashCapability,
  signDHTPointerRecord,
  verifyDHTPointerRecord,
} from '@fides/dht'
```

## Status

`@fides/dht` contains framework-agnostic pointer helpers. The current local DHT
behavior is simulator-grade; libp2p/Kademlia or other production DHT networks
should plug in through adapters and still follow the same verification flow.

## License

MIT
