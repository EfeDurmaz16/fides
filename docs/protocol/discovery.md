# Discovery

Discovery resolves capability intent into candidate AgentCards. Discovery never grants authority.

Current implementation anchors:

- `packages/core/src/discovery.ts`
- `packages/discovery/src/provider.ts`
- `packages/discovery/src/orchestrator.ts`
- `packages/discovery/src/local-provider.ts`
- `packages/discovery/src/well-known-provider.ts`
- `packages/discovery/src/registry-provider.ts`
- `packages/discovery/src/relay-provider.ts`
- `packages/discovery/src/dht-provider.ts`
- `packages/discovery/src/federation-provider.ts`
- `services/agentd/src/index.ts`

## Flow

1. Receive `DiscoveryQuery`.
2. Query enabled providers.
3. Verify signed records where available.
4. Verify AgentCards.
5. Check protocol version compatibility.
6. Check capability compatibility.
7. Compute trust.
8. Evaluate policy.
9. Return ranked candidates with explanations.
10. Emit evidence.

The current implementation supports capability-query providers and candidate explanations. Trust/policy/evidence integration remains an incremental hardening area.

Root `agentd` local, well-known, registry, relay, locally resolvable DHT, and
local mock federation discovery now apply protocol version negotiation before
returning provider results. A query can send `supported_versions` and
`required_versions`; each matching local AgentCard contributes its
`protocolVersions`. Compatible candidates, records, and pointers include a
`versionNegotiation` record. Incompatible matches are filtered out of the
active result set and returned in `rejectedCandidates`, `rejectedRecords`, or
`rejectedPointers` with a `VERSION_INCOMPATIBLE` error envelope. This keeps
discovery useful for explainability without treating an incompatible candidate
as invokable.

Federation discovery is deliberately candidate-only. The local mock federation
provider verifies signed `RegistryPeerRecord` metadata and ignores expired or
non-search peers, but a federated candidate remains untrusted until the normal
AgentCard, trust, reputation, revocation, incident, policy, session, and
evidence pipeline completes.
