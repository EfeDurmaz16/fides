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
