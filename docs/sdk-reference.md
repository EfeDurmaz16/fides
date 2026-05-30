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
// Discovery returns candidates only. It does not grant authority.
const candidate = results.candidates?.[0]
if (candidate?.authority !== 'candidate_only') {
  throw new Error('Unexpected authoritative discovery result')
}
await client.discovery.local({ capability: 'invoice.reconcile' })
await client.discovery.registry({
  capability: 'invoice.reconcile',
  supported_versions: ['fides.v2.0'],
  required_versions: ['fides.v2.0'],
})
await client.discovery.relay({
  capability: 'invoice.reconcile',
  supported_versions: ['fides.v2.0'],
})
await client.discovery.dht({ capability: 'invoice.reconcile' })
await client.discovery.federation({ capability: 'invoice.reconcile' })
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
// policy.policy.decision is one of:
// allow, deny, require_approval, dry_run_only, scope_limit, risk_limit.
// A policy response never grants invocation authority by itself.
await client.delegations.create({
  delegator: 'did:fides:principal',
  delegatee: 'did:fides:requester',
  capabilities: ['invoice.reconcile'],
  audience: [identity.identity.did],
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
const revocation = await client.revocations.create({
  issuer: 'did:fides:operator',
  targetType: 'agent',
  targetId: identity.identity.did,
  reason: 'Compromised deployment key.',
})
await client.revocations.get(revocation.record.id)
const incident = await client.incidents.report({
  reporter: 'did:fides:principal',
  targetAgentId: identity.identity.did,
  severity: 'high',
  category: 'unauthorized_action',
  description: 'Attempted invocation outside delegated authority.',
})
await client.incidents.resolve(incident.record.id, { status: 'resolved' })
const attestation = await client.attestations.create({
  agentId: identity.identity.did,
  codeHash: `sha256:${'a'.repeat(64)}`,
  runtimeHash: `sha256:${'b'.repeat(64)}`,
  policyHash: `sha256:${'c'.repeat(64)}`,
})
await client.attestations.verify(attestation.attestation.attestation_id)
await client.attestations.github({
  identity: identity.identity.did,
  handle: 'fides-dev',
})
await client.attestations.email({
  identity: identity.identity.did,
  email: 'dev@example.com',
})
await client.attestations.domain({
  identity: identity.identity.did,
  domain: 'example.com',
})
await client.attestations.package({
  identity: identity.identity.did,
  registry: 'npm',
  package: '@fides/example-agent',
})
await client.attestations.wallet({
  identity: identity.identity.did,
  address: '0x...',
})
await client.registry.start()
await client.registry.publish({ agentCardId: identity.identity.did })
await client.registry.search({
  capability: 'invoice.reconcile',
  supported_versions: ['fides.v2.0'],
})
await client.relay.start()
await client.relay.register({ agentId: identity.identity.did })
await client.relay.discover({
  capability: 'invoice.reconcile',
  supported_versions: ['fides.v2.0'],
})
await client.dht.publish({
  capability: 'invoice.reconcile',
  agentId: identity.identity.did,
})
await client.dht.find({ capability: 'invoice.reconcile' })
await client.wellKnown.fides()
await client.wellKnown.agents()
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
  // signedRequest may be supplied when the requester signs an InvocationRequest.
})
if (!invocation.signedResultVerified) {
  throw new Error('Invocation result signature did not verify')
}
const evidence = await client.evidence.append({
  type: 'capability.invoked',
  actor: 'did:fides:requester',
  subject: identity.identity.did,
  capability: 'invoice.reconcile',
  input: { invoiceId: 'inv_123' },
})
await client.evidence.inspect(evidence.event.event_id)
await client.evidence.verify()
await client.evidence.export({ privacy_mode: 'hash_only', include_metadata: false })
```

`identity.createAgent`, `identity.list`, and `identity.show` target the root
`agentd` identity API. The API does not return private keys. The facade is
intentionally thin. The AgentCard helpers target root `agentd` AgentCard
endpoints and use daemon-held local identity keys for signing. Agent
registration and discovery return candidates only; `authorityGranted` remains
`false`. Trust and reputation APIs return capability-scoped signals, and policy
evaluation explains the decision but still requires session grant issuance
before invocation. Delegation helpers create local DelegationToken intents; the
daemon signs them when the delegator identity is locally managed, but they still
do not grant invocation authority without policy and a scoped SessionGrant.
Session request and invocation helpers use the same root
local daemon API. Approval and kill switch helpers expose local authority
controls, with kill switch rules overriding normal policy while active.
Revocation and incident helpers expose local governance records that feed root
session policy decisions. Attestation helpers include local mock identity trust
anchors for GitHub, email, domain, package registry, and wallet claims, plus
runtime MockTEE attestations that can satisfy high-risk session policy when
passed as an `attestationId`. Registry, relay, DHT, federation, and well-known
helpers expose the local mock discovery surfaces. They return candidate records
or pointers only; they do not convert discovery into authority. Discovery,
registry, relay, and federation helpers accept `supported_versions` and
`required_versions` so callers can request protocol compatibility filtering.
`dht.publish` can publish a signed local pointer without an AgentCard URL when
`agentId` or `agentCardId` refers to a registered local AgentCard. Failed SDK
calls throw `FidesClientError`; when
the daemon returns a protocol `ErrorEnvelope`, the typed envelope is available
on `error.error` with stable `code`, `category`, `severity`, `retryable`,
`message`, and `details` fields.
`client.invoke()` accepts an optional signed `InvocationRequest`; if supplied,
the daemon verifies it before execution and returns `signedRequestVerified`.
`client.invokeSigned()` creates that canonical `InvocationRequest`, signs it
with the requester key, and submits it with the session id and input:

```ts
const invocation = await client.invokeSigned({
  sessionGrant: session.session,
  input: { invoiceId: 'inv_123' },
  privateKey: requesterPrivateKey,
  inputSchema: {
    type: 'object',
    required: ['invoiceId'],
    properties: { invoiceId: { type: 'string' } },
  },
})
```

The response includes the `InvocationResult`, the canonical `signedResult`
proof when the local target identity can sign it, and `signedResultVerified`
from daemon-side verification.
Advanced authority flows can use `AgentdClient`. `AgentdClient.health()` reads
`GET /health` and returns typed authority-store and local-state-store status,
including the SQLite snapshot path when the daemon exposes it.

## AGIT / Rust Primitive Bridge

`AgitPrimitiveBridge` gives the SDK an adapter-ready boundary for future
AGIT/Rust primitives without requiring Rust in the first working FIDES v2
runtime.

```ts
import { AgitPrimitiveBridge } from '@fides/sdk'

const bridge = new AgitPrimitiveBridge()

const canonical = await bridge.canonicalizeJson({ b: 2, a: 1 })
const hash = await bridge.hashObject({ event_id: 'evt_1' })
const chained = await bridge.appendEvidenceHash({
  previousEventHash: '0',
  eventPayload: { event_id: 'evt_1', type: 'policy.evaluated' },
})
const proof = await bridge.createMerkleProof({
  leaves: [hash, chained.eventHash],
  leaf: chained.eventHash,
})
```

The bridge delegates to a supplied `RustPrimitiveAdapter` when present.
Otherwise it uses TypeScript canonical JSON and SHA-256 fallbacks. Public SDK
APIs remain Promise-based, and protocol objects stay FIDES-native JSON.
