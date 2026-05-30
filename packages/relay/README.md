# @fides/relay

Relay discovery entrypoints for NAT-hidden FIDES v2 agents.

Relay discovery supplies presence, rendezvous, endpoint hints, and signed
AgentCard references. It does not decide trust or grant authority.

## Installation

```bash
npm install @fides/relay
```

## Usage

```typescript
import { RelayDiscoveryProvider } from '@fides/relay'
```

## Status

The exported provider is a local discovery facade over `@fides/discovery`.
Production relay servers should treat relay data as candidate metadata only:
consumers must still verify AgentCards, evaluate trust and policy, and issue a
scoped session grant before invocation.

## License

MIT
