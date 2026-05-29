# Relay Discovery

Relay discovery supports NAT-hidden agents and online rendezvous. Relay is not authority and must not decide trust.

Current implementation anchors:

- `packages/discovery/src/relay-provider.ts`
- `services/relay/src/index.ts`
- `packages/sdk/src/relay/client.ts`

## Relay Provides

- online presence
- rendezvous
- endpoint hints
- signed AgentCard references

## Relay Must Not Provide

- trust scores
- permission decisions
- policy grants
- payment authority

All relay candidates still pass AgentCard verification, trust evaluation, policy evaluation, and session grant issuance.
