# Revocation

Revocation records disable authority or metadata that should no longer be trusted.

Current implementation anchor:

- `packages/core/src/revocation.ts`

## Target Types

- key
- identity
- agent
- AgentCard
- capability
- session
- attestation
- publisher

Revocation must be checked before trust, policy, session, and invocation flows complete.

`RevocationRecordV2` uses the shared protocol object envelope: `id`, `issuer`,
`subject`, timestamps, and `payload_hash`. The subject is the revoked target id,
so policy and evidence can bind to the exact authority surface being disabled.

Signed revocation verification has two levels. `verifySignedRevocationRecordV2`
checks the canonical Ed25519 proof. `verifySignedRevocationRecordV2Issuer`
additionally requires `proof.verificationMethod` to equal the record `issuer`.
Authority paths should use the issuer-bound verifier so another DID cannot sign
an otherwise valid revocation payload on behalf of the stated issuer.

## Evidence

The local root daemon appends a hash-only `revocation.recorded` event when a
revocation record is created. The event links the issuer, target, target type,
and upstream evidence refs without storing sensitive payloads by default.
