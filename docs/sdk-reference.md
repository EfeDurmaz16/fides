# SDK Reference

The public SDK is Promise-based and does not require Effect.

Current implementation anchors:

- `packages/sdk/src/fides-client.ts`
- `packages/sdk/src/agentd/client.ts`

## FidesClient

```typescript
import { FidesClient } from '@fides/sdk'

const client = new FidesClient({ daemonUrl: 'http://localhost:4817' })

const identity = await client.identity.createAgent({ name: 'Invoice Agent' })
const identities = await client.identity.list()
const sameIdentity = await client.identity.show(identity.identity.did)
const card = await client.cards.create({
  identity: identity.identity,
  name: 'Invoice Agent',
  capabilities: [{ id: 'invoice.reconcile', riskClass: 'medium' }],
})
await client.cards.sign({ id: identity.identity.did })
await client.cards.verify(identity.identity.did)
await client.cards.get(identity.identity.did)
await client.agents.register({ agentCardId: identity.identity.did })
await client.agents.list()
await client.agents.inspect(identity.identity.did)
const results = await client.discovery.find({ capability: 'invoice.reconcile' })
const trust = await client.trust.evaluate({
  agentId: identity.identity.did,
  capability: 'invoice.reconcile',
})
const reputation = await client.reputation.update({
  agentId: identity.identity.did,
  capability: 'invoice.reconcile',
  successfulInvocations: 3,
})
const policy = await client.policy.evaluate({
  principalId: 'did:fides:principal',
  requesterAgentId: 'did:fides:requester',
  agentId: identity.identity.did,
  capability: 'invoice.reconcile',
  requestedScopes: ['invoice:read'],
})
const approval = await client.approvals.create({
  principalId: 'did:fides:principal',
  requesterAgentId: 'did:fides:requester',
  agentId: identity.identity.did,
  capability: 'payments.prepare',
  requestedScopes: ['payments:prepare'],
  riskLevel: 'high',
})
await client.approvals.approve(approval.approval.id, {
  approverId: 'did:fides:approver',
})
const killSwitch = await client.killSwitch.enable({
  issuer: 'did:fides:operator',
  targetType: 'capability',
  target: 'deploy.preview',
  reason: 'Pause preview deploys during incident response.',
})
await client.killSwitch.disable(killSwitch.rule.id)
const session = await client.sessions.request({
  principalId: 'did:fides:principal',
  requesterAgentId: 'did:fides:requester',
  agentId: identity.identity.did,
  capability: 'invoice.reconcile',
  requestedScopes: ['invoice:read'],
})
const invocation = await client.invoke({
  sessionId: session.session.session_id,
  input: { invoiceId: 'inv_123' },
})
```

`identity.createAgent`, `identity.list`, and `identity.show` target the root
`agentd` identity API. The API does not return private keys. The facade is
intentionally thin. The AgentCard helpers target root `agentd` AgentCard
endpoints and use daemon-held local identity keys for signing. Agent
registration and discovery return candidates only; `authorityGranted` remains
`false`. Trust and reputation APIs return capability-scoped signals, and policy
evaluation explains the decision but still requires session grant issuance
before invocation. Session request and invocation helpers use the same root
local daemon API. Approval and kill switch helpers expose local authority
controls, with kill switch rules overriding normal policy while active.
Advanced authority flows can use `AgentdClient`.
