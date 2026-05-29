# DHT Discovery

DHT discovery provides signed pointers. It is not a trust source.

Current implementation anchors:

- `packages/core/src/dht.ts`
- `packages/discovery/src/dht-provider.ts`

## Pointer Record

DHT records point from capability hash to AgentCard location and hash. They include agent ID, publisher ID, expiry, sequence, and signature.

## Flow

1. Hash the requested capability.
2. Query DHT for pointers.
3. Verify pointer signature and expiry.
4. Resolve AgentCard.
5. Verify AgentCard hash and signature.
6. Continue to trust and policy.

The in-memory DHT simulator is local mock infrastructure. A libp2p/Kademlia adapter should implement the same provider contract later.
