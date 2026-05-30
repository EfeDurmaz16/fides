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

## Evidence

The local root daemon appends a hash-only `revocation.recorded` event when a
revocation record is created. The event links the issuer, target, target type,
and upstream evidence refs without storing sensitive payloads by default.
