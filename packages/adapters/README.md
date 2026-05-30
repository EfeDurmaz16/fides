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

Payment execution remains outside generic FIDES. AP2, x402, and Sardis adapters
can expose payment action-flow mappings, but FIDES treats those as interop
references for policy, authority, and evidence.

## License

MIT
