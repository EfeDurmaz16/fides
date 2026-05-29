# Discovery

Discovery resolves capability intent into candidate AgentCards. Discovery never grants authority.

Current implementation anchors:

- `packages/core/src/discovery.ts`
- `packages/discovery/src/provider.ts`
- `packages/discovery/src/orchestrator.ts`
- `packages/discovery/src/local-provider.ts`
- `packages/discovery/src/well-known-provider.ts`
- `packages/discovery/src/registry-provider.ts`

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

Root `agentd` local and well-known discovery now apply protocol version
negotiation before returning candidates. A query can send `supported_versions`
and `required_versions`; each matching AgentCard contributes its
`protocolVersions`. Compatible candidates include a `versionNegotiation` record.
Incompatible matches are filtered out of `candidates` and returned in
`rejectedCandidates` with a `VERSION_INCOMPATIBLE` error envelope. This keeps
discovery useful for explainability without treating an incompatible candidate
as invokable.
