# Delegation and Sessions

Delegation expresses scoped authority. Session grants bind that authority to a concrete requester, target, principal, capability, scopes, policy hash, and trust result hash.

Current implementation anchors:

- `packages/core/src/delegation.ts`
- `packages/core/src/session-store.ts`
- `packages/core/src/invocation.ts`

## SessionGrant Fields

- `id`
- `session_id`
- `subject`
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

`id` and `session_id` are the same value for compatibility with older call
sites. `subject` is the target agent id, so the shared protocol object envelope
binds to the same target as the session authority.

Replay protection is required through nonce tracking.

## Invocation Binding

An invocation must bind to a scoped `SessionGrant`. The root local daemon can
accept a caller-supplied signed `InvocationRequest`; when supplied, the daemon
verifies its canonical proof and checks that it matches the session, input hash,
and dry-run mode before policy preflight. `InvocationRequest` includes `id`,
`issuer`, `subject`, session binding fields, capability, scopes, input hash,
optional schema hashes, `issued_at`, and `payload_hash`; the subject is the
target agent id.

The daemon validates the request body against the capability input schema before
execution and validates generated outputs against the capability output schema
before returning a successful result. The daemon then emits hash-only evidence
events, creates an `InvocationResult`, and signs that result with the target
agent identity using the canonical object signing model. `InvocationResult`
includes `id`, `issuer`, `subject`, request id, status, output hash or error
code, evidence refs, `created_at`, and `payload_hash`; the subject is the
invocation request id. The signed request proves requester intent, and the
signed result proves that the target agent identity produced the invocation
outcome; neither proof bypasses policy, revocation, schema, or evidence
verification.
