# @fides/adapters

Interface-only interop adapters for FIDES v2.

This package describes how external protocols map into FIDES identity, AgentCards, capabilities, delegation, policy, evidence, and invocation records. It intentionally avoids runtime dependencies on MCP, A2A, OAPS, OSP, AP2, x402, Sardis, or payment SDKs.

## Contract

- `AdapterManifest` declares the adapter kind, version, supported protocol
  surfaces, and whether the adapter is payment-specific.
- `AdapterMapping` maps an external protocol identifier to FIDES identities and
  capability IDs.
- `InteropMappingSet` maps richer protocol surfaces into FIDES-native shapes:
  identity, AgentCards, capabilities, discovery candidates, trust, policy,
  delegation, sessions, approvals, invocation, evidence, attestations,
  revocations, incidents, and payment action-flow references.
- `RustPrimitiveAdapter` is the optional Rust/AGIT primitive boundary for
  canonical JSON, hashing, canonical object signing, signature verification,
  evidence hash-chain operations, Merkle proofs, and DAG primitives.

Payment execution remains outside generic FIDES. AP2, x402, and Sardis adapters
can expose payment action-flow mappings, but FIDES treats those as interop
references for policy, authority, and evidence.

## Rust Adapter Readiness

FIDES v2 is TS-first. Rust is not required at runtime for the first working
version. The Rust primitive adapter contract exists so a future AGIT/Rust core
can accelerate or harden primitives without changing public protocol objects or
Promise-based SDK APIs.

Rust adapters must preserve the single canonical signing model used by FIDES.
They may implement:

- canonical JSON serialization
- hashing
- canonical object signing and verification
- evidence hash-chain append/verify helpers
- Merkle proof creation/verification
- DAG primitives for evidence lineage

Protocol objects remain framework-agnostic JSON. Adapters must not introduce a
Rust-specific wire format.

## License

MIT
