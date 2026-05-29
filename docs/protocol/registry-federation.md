# Registry and Federation

Registries publish and search signed AgentCard index records. Federation enables registry peering and propagation of revocations/incidents.

Current implementation anchors:

- `packages/core/src/registry.ts`
- `services/registry/src/index.ts`

## Registry Modes

- hosted
- public
- private

## Records

- `RegistryIndexRecord`: signed AgentCard index entry.
- `RegistryPeerRecord`: signed registry peering metadata.

Federation peering records are adapter-ready and should not imply trust. Peers provide discovery and propagation surfaces; FIDES still verifies identity, signatures, revocations, incidents, trust, and policy.
