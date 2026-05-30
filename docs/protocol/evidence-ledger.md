# Evidence Ledger

FIDES evidence is append-only, hash-chained, privacy-aware audit material.

Current implementation anchors:

- `packages/evidence/src/index.ts`
- `packages/core/src/invocation.ts`

## Event Classes

The event taxonomy includes agent registration, discovery, trust computation, policy evaluation, approval, session, invocation, attestation, revocation, incident, and kill switch events.

Current root `agentd` mutations append hash-only lifecycle evidence for:

- approval requests, grants, and denials
- kill switch activation
- revocation records
- incident reports
- session grants and denials
- invocation attempts and results
- runtime attestation issuance and verification

## Integrity

Each event links to the previous event hash. Verification detects broken
chains. The evidence package can also compute Merkle roots and generate
Merkle inclusion proofs for individual events, so an exported event can be
verified against an anchored root without disclosing the entire log.

Export should preserve enough metadata to audit without leaking sensitive
inputs or outputs.
