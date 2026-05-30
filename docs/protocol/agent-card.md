# AgentCard

An AgentCard is signed agent metadata. It is not authority.

Current implementation anchors:

- `packages/core/src/agent-card.ts`
- `packages/core/src/capability.ts`

## Required v2 Content

- `agent_id`
- publisher identity reference
- public keys
- capabilities
- endpoints
- transports
- policy requirements
- trust anchors
- runtime attestations
- supported protocol versions
- creation and expiry timestamps
- revocation URL or revocation record reference
- canonical signature

`normalizeAgentCard()` makes signed cards self-describing before canonical
signing:

- `schema_version` defaults to `fides.agent_card.v1`
- `agent_id` defaults to `identity.did`
- `publicKeys` defaults to the Ed25519 public key encoded in the `did:fides`
  identifier
- `transports` defaults from endpoint transport metadata
- `protocolVersions` defaults to the current FIDES protocol version

The root local `agentd` AgentCard creation endpoint stores normalized cards,
not sparse request bodies. When available, it carries local publisher identity,
agent trust anchors, runtime attestations, revocation metadata, public keys, and
transport metadata into the stored card before signing. This keeps the unsigned
inspection endpoint and signed payload aligned.

AgentCard verification has two levels. `verifySignedAgentCard` validates the
card shape and canonical Ed25519 proof. `verifySignedAgentCardIdentity` also
requires `proof.verificationMethod` to equal `identity.did`, which is the
discovery-safe check for AgentCard ingestion. A valid signature from another DID
does not prove that the advertised agent identity published the card.

## Rule

Discovery may return AgentCards, but invocation requires trust evaluation, policy evaluation, and a scoped session grant.
