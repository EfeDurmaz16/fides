# Relay Discovery

Relay discovery supports NAT-hidden agents and online rendezvous. Relay is not authority and must not decide trust.

Current implementation anchors:

- `packages/discovery/src/relay-provider.ts`
- `services/relay/src/index.ts`
- `services/agentd/src/index.ts`
- `packages/sdk/src/relay/client.ts`

## Relay Provides

- online presence
- rendezvous
- endpoint hints
- signed AgentCard references

The local daemon relay alias builds relay records from registered local
AgentCards. When the card has been signed, the relay record includes:

- `agentCardUrl`, using a local `local://agent-cards/<card-id>` reference
- `agentCardHash`, the canonical AgentCard hash
- `signedAgentCard`, indicating whether the daemon has a signed AgentCard
- `agentCardProof`, the canonical AgentCard proof metadata

These fields let a caller resolve and verify the AgentCard after rendezvous.
They do not make the relay a trust anchor.

## Relay Must Not Provide

- trust scores
- permission decisions
- policy grants
- payment authority

All relay candidates still pass AgentCard verification, trust evaluation, policy evaluation, and session grant issuance.
