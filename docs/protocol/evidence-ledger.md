# Evidence Ledger

FIDES evidence is append-only, hash-chained, privacy-aware audit material.

Current implementation anchors:

- `packages/evidence/src/index.ts`
- `packages/core/src/invocation.ts`

## Event Classes

The event taxonomy includes agent registration, discovery, trust computation, policy evaluation, approval, session, invocation, attestation, revocation, incident, and kill switch events.

## Integrity

Each event links to the previous event hash. Verification detects broken chains. Export should preserve enough metadata to audit without leaking sensitive inputs or outputs.
