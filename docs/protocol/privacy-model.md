# Evidence Privacy Model

FIDES evidence is privacy-aware by default. Sensitive inputs and outputs should not be stored directly unless explicitly configured.

Current implementation anchors:

- `packages/evidence/src/index.ts`
- `packages/core/src/invocation.ts`

## Modes

- `public`: event metadata and configured payload are visible.
- `private`: local-only visibility.
- `redacted`: sensitive values removed, metadata retained.
- `hash_only`: input/output stored as hashes only.

## Defaults

For capability invocation and policy decisions, default to `hash_only` or `redacted` for input/output. Store enough metadata to audit what happened without leaking secrets.

## Evidence Refs

Protocol objects should carry `evidence_refs` instead of copying sensitive evidence payloads into every object.
