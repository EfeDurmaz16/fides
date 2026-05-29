# Interop Adapters

FIDES exposes adapter interfaces for external protocols without runtime dependencies on those protocols.

Current implementation anchor:

- `packages/adapters/src/index.ts`

## Adapter Kinds

- MCP
- A2A
- OAPS
- OSP
- AP2
- x402
- Sardis

Adapters map identity, AgentCards, capabilities, delegation, policy, evidence, invocation, and payment/action flows where relevant.

Payment-specific execution remains outside generic FIDES.
