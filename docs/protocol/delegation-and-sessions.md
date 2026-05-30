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

Signed `SessionGrant` verification has two levels. `verifySignedSessionGrantV2`
checks the canonical Ed25519 proof. `verifySignedSessionGrantV2Issuer` also
requires `proof.verificationMethod` to equal the grant `issuer`, which is the
authority-safe check for session acceptance paths. A valid signature from a
different DID over an otherwise valid grant payload is not enough to establish
session authority.

The root local daemon issues `SessionGrantV2` records through a local authority
DID and returns the canonical signed grant as `signedSession`. Stored sessions
without a signed grant are not hydrated from local state, and invocation rejects
sessions whose signed grant no longer verifies against the grant issuer.

## Invocation Binding

An invocation must bind to a scoped `SessionGrant`. The root local daemon can
accept a caller-supplied signed `InvocationRequest`; when supplied, the daemon
verifies its canonical proof and checks that it matches the session, input hash,
and dry-run mode before policy preflight. `InvocationRequest` includes `id`,
`issuer`, `subject`, session binding fields, capability, scopes, input hash,
optional schema hashes, `issued_at`, and `payload_hash`; the subject is the
target agent id.

Core exposes `validateInvocationRequestAgainstSessionGrant` so SDKs, daemons,
and adapters can reject requests that mutate the signed request payload, swap
session ids, change requester/target/principal identity, request a different
capability, exceed granted scopes, use an expired grant, or target an audience
outside the grant. This keeps discovery, trust, and policy separate from actual
authority: invocation authority is the scoped `SessionGrant`, not the discovered
AgentCard or DHT/registry pointer.

The root `/invoke` daemon endpoint applies this validator to caller-supplied
signed invocation requests before policy preflight. The signed request must also
match the submitted input hash and dry-run mode, so a valid requester signature
cannot widen scopes or replay authority over different invocation input. The
proof verification method must match the request `issuer`; a signature from a
different DID over an otherwise valid requester payload is rejected.

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
