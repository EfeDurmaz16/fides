# Interop Adapters

FIDES exposes adapter interfaces for external protocols without runtime dependencies on those protocols.

Current implementation anchor:

- `packages/adapters/src/index.ts`
- `packages/adapters/README.md`

## Adapter Kinds

- MCP
- A2A
- OAPS
- OSP
- AP2
- x402
- Sardis

Adapters map identity, AgentCards, capabilities, trust, delegation, policy,
evidence, invocation, and payment/action flows where relevant.

Payment-specific execution remains outside generic FIDES.

## Adapter Contract

Adapters declare an `AdapterManifest` with supported protocol surfaces:

- identity
- AgentCard
- capability
- discovery
- trust
- policy
- delegation
- session
- approval
- invocation
- evidence
- attestation
- revocation
- incident
- payment action flow

`AdapterMapping` is the lightweight cross-reference record. `InteropMappingSet`
is the richer adapter-ready shape for moving external protocol data into
FIDES-owned runtime objects without making FIDES depend on external SDKs.

AP2, x402, and Sardis are marked payment/action-flow adapters. They can map
payment-specific flows into FIDES policy, authority, and evidence references,
but generic FIDES does not execute payments.
