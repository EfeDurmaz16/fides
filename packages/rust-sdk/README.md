# FIDES Rust Adapter Contract

FIDES v2 is TS-first. Rust is adapter-ready, not required for the first working
version.

This directory documents the future Rust boundary for performance-critical or
audit-critical primitives. The active TypeScript contract lives in
`@fides/adapters` as `RustPrimitiveAdapter`.

## Intended Sources

- AGIT Rust core concepts for hash chains, lineage, DAG primitives, Merkle
  proofs, canonicalization, and high-performance hashing.
- FIDES TypeScript protocol objects for the canonical wire model.

## Adapter Surfaces

Future Rust adapters may implement:

- canonical JSON serialization
- hashing
- canonical object signing
- canonical object signature verification
- evidence hash-chain append and verification helpers
- Merkle proof creation and verification
- DAG primitives for evidence lineage

## Hard Constraints

- Rust must not become a runtime dependency for the TypeScript SDK, CLI, daemon,
  or public protocol objects.
- Rust adapters must preserve the FIDES canonical object signing model.
- Rust adapters must not introduce a separate wire format.
- Public SDK APIs remain Promise-based TypeScript APIs.
- Effect, if used internally, must not leak into Rust adapter protocol objects.
- No Rust crate is required or published yet.

## Current Status

Adapter-ready contract only. No Rust crate is required or published yet.

Use `@fides/adapters` for the current manifest and coverage helpers:

```ts
import {
  createRustPrimitiveAdapterManifest,
  validateRustPrimitiveAdapterCoverage,
} from '@fides/adapters'

const manifest = createRustPrimitiveAdapterManifest({
  name: 'AGIT Rust primitive adapter',
  surfaces: ['canonical_json', 'hashing', 'evidence_hash_chain'],
})

validateRustPrimitiveAdapterCoverage(manifest, [
  'canonical_json',
  'hashing',
])
```
