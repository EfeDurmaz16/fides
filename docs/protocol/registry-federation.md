# Registry and Federation

Registries publish and search signed AgentCard index records. Federation enables registry peering and propagation of revocations/incidents.

Current implementation anchors:

- `packages/core/src/registry.ts`
- `packages/discovery/src/federation-provider.ts`
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
them. Unsigned local registry records are reported as rejected records, not
active candidates. A valid registry index record still does not grant
invocation authority.
Authority-safe ingestion should use `verifySignedRegistryIndexRecordIssuer`,
which verifies both the canonical Ed25519 proof and that
`proof.verificationMethod` equals the record `issuer`.

Federation peering records are adapter-ready and should not imply trust. Peers
provide discovery and propagation surfaces; FIDES still verifies identity,
signatures, revocations, incidents, trust, and policy.
Authority-safe peering ingestion should use `verifySignedRegistryPeerRecordIssuer`
for the same issuer-bound proof check.

`LocalFederationDiscoveryProvider` is the local mock federation implementation.
It accepts signed `RegistryPeerRecord` values plus peer discovery providers,
verifies the peer record signature, ignores expired peers, and only queries
peers that advertise `registry_search`. Returned candidates are marked with
provider `federation`, `verified: false`, and an explanation that federation is
not authority. The provider does not publish or deregister AgentCards directly;
those operations belong to the source registry peer.

Federated discovery flow:

1. Load configured signed `RegistryPeerRecord` entries.
2. Reject expired or unsigned/tampered peer records.
3. Query peers that advertise `registry_search`.
4. Return candidate AgentCards with federation provenance.
5. Continue the normal FIDES pipeline: AgentCard verification, protocol version
   negotiation, trust/reputation scoring, policy evaluation, scoped SessionGrant
   issuance, and evidence recording.
