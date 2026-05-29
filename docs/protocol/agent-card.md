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

## Rule

Discovery may return AgentCards, but invocation requires trust evaluation, policy evaluation, and a scoped session grant.
