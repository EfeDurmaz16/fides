# Canonical Object Signing

FIDES v2 uses one object-level signing model for signed protocol objects. Transport signatures such as HTTP Message Signatures remain separate from protocol-object signatures.

Current implementation anchors:

- `packages/core/src/canonical-signer.ts`
- `packages/core/src/protocol.ts`

## Model

1. Serialize the payload with deterministic canonical JSON.
2. Hash the canonical payload with SHA-256.
3. Sign the digest with Ed25519.
4. Attach a proof that names the verification method, purpose, and canonicalization algorithm.

Signed objects should include or derive:

- `schema_version`
- `id`
- `issuer`
- `subject` when applicable
- `created_at` or `issued_at`
- `expires_at` when applicable
- `payload_hash`
- `signature` or canonical `proof`

## Rule

No package should invent a separate signing format for AgentCards, DHT records, approvals, sessions, invocations, revocations, incidents, registry records, or attestations.
