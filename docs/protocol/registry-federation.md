# Registry and Federation

Registries publish and search signed AgentCard index records. Federation enables registry peering and propagation of revocations/incidents.

Current implementation anchors:

- `packages/core/src/registry.ts`
- `services/registry/src/index.ts`
- `services/agentd/src/index.ts`

## Registry Modes

- hosted
- public
- private

## Records

- `RegistryIndexRecord`: signed AgentCard index entry.
- `RegistryPeerRecord`: signed registry peering metadata.

The local daemon registry alias now emits core-compatible signed
`RegistryIndexRecord` metadata for registered local AgentCards. A published
record includes:

- `agentCardUrl`, using `local://agent-cards/<card-id>`
- `agentCardHash`, matching the canonical AgentCard hash
- `registryIndexRecord`, the canonical index payload
- `registryIndexProof`, the canonical signature proof
- `registryIndexVerified`, the daemon's local verification result

Search and discovery verify signed local registry index records before returning
them. A valid registry index record still does not grant invocation authority.

Federation peering records are adapter-ready and should not imply trust. Peers provide discovery and propagation surfaces; FIDES still verifies identity, signatures, revocations, incidents, trust, and policy.
