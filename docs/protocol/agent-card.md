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

## Rule

Discovery may return AgentCards, but invocation requires trust evaluation, policy evaluation, and a scoped session grant.
