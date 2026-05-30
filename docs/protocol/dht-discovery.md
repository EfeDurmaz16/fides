# DHT Discovery

DHT discovery provides signed pointers. It is not a trust source.

Current implementation anchors:

- `packages/core/src/dht.ts`
- `packages/discovery/src/dht-provider.ts`
- `services/agentd/src/index.ts`

## Pointer Record

DHT records point from capability hash to AgentCard location and hash. They include agent ID, publisher ID, expiry, sequence, and signature.
Pointer signature verification is issuer-bound: the verification method must
match `publisher_id`. A valid signature from any other DID over the pointer
payload is rejected, because DHT only provides pointers and must not let a third
party speak for the publisher named in the record.

The local daemon can publish a signed DHT pointer from an already registered
local AgentCard without the caller supplying a URL. In that case it uses a
`local://agent-cards/<card-id>` reference, hashes the daemon-held AgentCard, and
signs the pointer with the local agent identity. External or unresolved pointer
publishes are accepted only as local mock records and are marked unverified.

## Flow

1. Hash the requested capability.
2. Query DHT for pointers.
3. Verify pointer signature and expiry.
4. Resolve AgentCard.
5. Verify AgentCard hash, agent identity, advertised capability, and signature.
6. Continue to trust and policy.

`/dht/find` and `/discover/dht` verify signed local pointer records before
returning them. Expired, tampered, or AgentCard-hash-mismatched pointers are
reported as rejected pointers and do not become authority. A pointer is also
rejected when it claims a capability that the resolved AgentCard does not
advertise.

The package-level `DHTDiscoveryProvider` also rejects invalid pointers before
returning candidates. Tampered pointer hashes, expired pointers, AgentCard hash
mismatches, and locally revoked agent IDs are filtered out. A returned DHT
candidate therefore only means "this signed pointer resolved to this AgentCard";
it still does not grant trust or authority.

`DHTDiscoveryProvider.register` accepts only identity-bound signed AgentCards.
The AgentCard proof verification method must match the advertised
`identity.did`, otherwise the card is not stored in the DHT simulator.

The in-memory DHT simulator is local mock infrastructure. A libp2p/Kademlia adapter should implement the same provider contract later.
