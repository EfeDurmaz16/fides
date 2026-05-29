# Delegation and Sessions

Delegation expresses scoped authority. Session grants bind that authority to a concrete requester, target, principal, capability, scopes, policy hash, and trust result hash.

Current implementation anchors:

- `packages/core/src/delegation.ts`
- `packages/core/src/session-store.ts`

## SessionGrant Fields

- `session_id`
- `requester_agent_id`
- `target_agent_id`
- `principal_id`
- `capability`
- `scopes`
- `constraints`
- `policy_hash`
- `trust_result_hash`
- `issued_at`
- `expires_at`
- `nonce`
- `audience`
- `issuer`
- canonical signature

Replay protection is required through nonce tracking.
