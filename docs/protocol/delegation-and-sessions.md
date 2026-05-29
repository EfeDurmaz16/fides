# Delegation and Sessions

Delegation expresses scoped authority. Session grants bind that authority to a concrete requester, target, principal, capability, scopes, policy hash, and trust result hash.

Current implementation anchors:

- `packages/core/src/delegation.ts`
- `packages/core/src/session-store.ts`
- `packages/core/src/invocation.ts`

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

## Invocation Binding

An invocation must bind to a scoped `SessionGrant`. The root local daemon
creates an `InvocationRequest`, performs policy preflight, emits hash-only
evidence events, creates an `InvocationResult`, and signs that result with the
target agent identity using the canonical object signing model. The signed
result is evidence that the target agent identity produced the invocation
outcome; it still does not bypass policy, revocation, or evidence verification.
