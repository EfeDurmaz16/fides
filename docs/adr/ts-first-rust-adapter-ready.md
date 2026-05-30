# ADR: TS-First, Rust Adapter-Ready

## Status

Accepted.

## Decision

FIDES v2 is implemented first in TypeScript/Node. Rust is adapter-ready but not required for the first working version.

## Context

The existing repository is a TypeScript monorepo with packages, services, CLI, SDK, and tests. AGIT has useful Rust primitives for future hashing, canonicalization, Merkle/DAG, and evidence-chain performance work.

## Consequences

- Public protocol objects remain language-neutral JSON.
- TypeScript owns first runtime implementation.
- Rust adapters may be added later behind stable interfaces.
