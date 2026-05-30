# @fides/sdk

Promise-based TypeScript SDK for the FIDES v2 Agent Trust Fabric.

FIDES v2 resolves capabilities to verified agent candidates, then runs trust,
policy, delegation, session, invocation, and evidence workflows through the
local `agentd` authority path. Discovery is candidate discovery only; it never
grants invocation authority by itself.

## Installation

```bash
npm install @fides/sdk
# or
pnpm add @fides/sdk
```

## Quick Start

```typescript
import { FidesClient } from '@fides/sdk'

const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

const principal = await client.identity.createPrincipal({ name: 'Demo Principal' })
const requester = await client.identity.createAgent({ name: 'Requester Agent' })
const target = await client.identity.createAgent({ name: 'Invoice Agent' })

const card = await client.cards.create({
  agentId: target.did,
  name: 'Invoice Agent',
  capabilities: [
    {
      id: 'invoice.reconcile',
      riskLevel: 'medium',
      requiredScopes: ['invoice:read'],
      supportedControls: ['dry_run', 'policy_proof'],
      supportsDryRun: true,
      supportsPolicyProof: true,
    },
  ],
})

await client.cards.sign({ id: card.card.id })
await client.agents.register({ agentCardId: card.card.id })

const discovery = await client.discovery.local({ capability: 'invoice.reconcile' })
console.log(discovery.authorityGranted) // false

const trust = await client.trust.evaluate({
  agentId: target.did,
  capability: 'invoice.reconcile',
})

const policy = await client.policy.evaluate({
  principalId: principal.did,
  requesterAgentId: requester.did,
  agentId: target.did,
  capability: 'invoice.reconcile',
  requestedScopes: ['invoice:read'],
})

const session = await client.sessions.request({
  principalId: principal.did,
  requesterAgentId: requester.did,
  agentId: target.did,
  capability: 'invoice.reconcile',
  requestedScopes: ['invoice:read'],
})

const result = await client.invoke({
  sessionId: session.session.session_id,
  input: { invoiceId: 'inv_123' },
})

await client.evidence.verify()

console.log({ trust: trust.trust.band, policy: policy.policy.decision, result })
```

## agentd Client

High-level local daemon facade:

```typescript
import { FidesClient } from '@fides/sdk'

const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

const identity = await client.identity.createAgent({ name: 'Invoice Agent' })
const identities = await client.identity.list()
const sameIdentity = await client.identity.show(identity.identity.did)

const card = await client.cards.create({
  identity: identity.identity,
  name: 'Invoice Agent',
  capabilities: [{ id: 'invoice.reconcile', requiredScopes: ['invoice:read'] }],
})
const signed = await client.cards.sign({ id: identity.identity.did })
const verified = await client.cards.verify(identity.identity.did)

const registration = await client.agents.register({ agentCardId: identity.identity.did })
if (registration.authority !== 'candidate_only' || registration.authorityGranted !== false) {
  throw new Error('Registration must remain candidate-only')
}
const agents = await client.agents.list()
const candidateAgent = await client.agents.inspect(identity.identity.did)
const candidates = await client.discovery.find({ capability: 'invoice.reconcile' })
await client.discovery.local({ capability: 'invoice.reconcile' })
await client.discovery.registry({ capability: 'invoice.reconcile' })
await client.discovery.relay({ capability: 'invoice.reconcile' })
await client.discovery.dht({ capability: 'invoice.reconcile' })
const providerResults = await client.discovery.allProviders({ capability: 'invoice.reconcile' })
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
const session = await client.sessions.request({
  principalId: 'did:fides:principal',
  requesterAgentId: 'did:fides:requester',
  agentId: identity.identity.did,
  capability: 'invoice.reconcile',
  requestedScopes: ['invoice:read'],
})
if (session.authorityMode === 'dry_run_only' && session.allowedActions?.includes('dry_run')) {
  // Dry-run-only sessions are simulation authority, not execution authority.
}
const invocation = await client.invoke({
  sessionId: session.session.session_id,
  input: { invoiceId: 'inv_123' },
})
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

The local identity API returns public identity data only; it does not return
private keys. SDK identity response types model only public records (`did`,
`type`, `publicKeyHex`, `createdAt`, and the public `identity` object).
AgentCard signing uses the daemon-held local identity key.
Registration and discovery produce candidate records only; discovery does not
grant authority to invoke the agent. Root agent registration/list/detail
responses preserve `authority: "candidate_only"`, `authorityGranted: false`,
`verified`, and machine-readable `reasons`. Standalone discovery responses
preserve `verified: false`, `authorityGranted: false`, and machine-readable
`reasons` so SDK callers do not accidentally treat metadata discovery as trust
or permission. `client.discovery.allProviders()` queries local, well-known,
registry, relay, DHT, and federation surfaces and preserves partial provider
failures as `ok: false` results instead of granting authority or dropping
successful candidates. Trust and reputation are capability-scoped signals; policy
decisions still require scoped session grants before invocation.
Root session and invocation helpers use the local daemon preflight path and are
currently in-memory. Session responses preserve `authorityMode` and
`allowedActions`; full sessions return `authorityGranted: true`, while
dry-run-only sessions return `authorityGranted: false`, include
`allowedActions: ["dry_run"]`, and carry
`session.constraints.dryRunOnly: true`. Approval and kill switch helpers expose
local authority controls, with active kill switch rules overriding normal
policy. Kill switch helpers return typed `KillSwitchRule` responses; an enabled
rule is an authority override that denies or limits policy, not a session grant.
Approval helpers return typed `ApprovalRequest` / `ApprovalDecision` responses
and keep `authorityGranted: false`; approval records inform policy but do not
grant invocation authority by themselves. Revocation and incident helpers expose
local governance records that feed root session policy decisions. Revocation
helpers return typed `RevocationRecordV2` responses, and active revocations are
authority overrides that deny matching trust and policy paths rather than grant
new authority. Incident helpers return typed `IncidentRecordV2` responses; open
incidents are policy-review inputs that affect trust and session policy until
resolved. Attestation helpers return typed local identity trust-anchor responses
or `RuntimeAttestation` responses. Runtime attestation helpers issue and verify
local MockTEE attestations that can satisfy high-risk session policy when passed
as an `attestationId`. Evidence helpers append hash-only events by default, inspect
individual events, verify the root hash chain, and export the current local
ledger.

## AGIT / Rust Primitive Bridge

```typescript
import { AgitPrimitiveBridge } from '@fides/sdk'

const bridge = new AgitPrimitiveBridge()

const canonical = await bridge.canonicalizeJson({ b: 2, a: 1 })
const objectHash = await bridge.hashObject({ event_id: 'evt_1' })
const chained = await bridge.appendEvidenceHash({
  previousEventHash: '0',
  eventPayload: { event_id: 'evt_1', type: 'policy.evaluated' },
})
const proof = await bridge.createMerkleProof({
  leaves: [objectHash, chained.eventHash],
  leaf: chained.eventHash,
})
```

`AgitPrimitiveBridge` is TS-first and works without Rust. A future AGIT/Rust
adapter can be supplied for canonical JSON, hashing, evidence hash-chain,
Merkle, and DAG primitives while preserving FIDES protocol objects and the
Promise-based SDK surface.

```typescript
import { AgentdClient } from '@fides/sdk'

const agentd = new AgentdClient({
  baseUrl: 'http://localhost:7345',
  apiKey: process.env.FIDES_API_KEY,
})

const decision = await agentd.authorize({
  agentDid: 'did:fides:agent',
  capabilityId: 'payments.execute',
  sessionId: 'sess_123',
  audience: 'agentd',
})

const card = await agentd.getCard('did:fides:agent')
const domain = await agentd.verifyDomain('example.com', 'did:fides:agent')

const session = await agentd.createSignedSession({
  delegator: 'did:fides:principal',
  delegatee: 'did:fides:agent',
  capabilities: ['payments.execute'],
  capabilityId: 'payments.execute',
  privateKey: process.env.DELEGATOR_PRIVATE_KEY_HEX!,
})

await agentd.recordSignedRevocation({
  did: 'did:fides:agent',
  reason: 'operator disabled',
  revokedBy: 'did:fides:principal',
  privateKey: process.env.REVOKER_PRIVATE_KEY_HEX!,
})

await agentd.recordSignedIncident({
  actor: 'did:fides:agent',
  reportedBy: 'did:fides:principal',
  type: 'policy_violation',
  severity: 'high',
  description: 'attempted payment outside approved policy',
  privateKey: process.env.REPORTER_PRIVATE_KEY_HEX!,
})

const pending = await agentd.listPendingPropagations(25)
const retry = await agentd.retryPropagations(25)
```

## Legacy Discovery Clients

`DiscoveryClient` and `AgentDiscoveryClient` remain exported for compatibility
with the older standalone discovery service. New FIDES v2 code should prefer
`FidesClient.discovery.*` through local `agentd`, because that path preserves
AgentCard verification, protocol negotiation, trust/policy explainability,
candidate-only discovery, and evidence recording.

## Registry Client

```typescript
import { RegistryClient } from '@fides/sdk'

const registry = new RegistryClient({
  baseUrl: 'http://localhost:7346',
  apiKey: process.env.FIDES_API_KEY,
})

await registry.register({
  id: 'did:fides:agent',
  name: 'Payment Agent',
  version: '1.0.0',
  publisher: {
    did: 'did:fides:publisher',
    name: 'Example Publisher',
    verified: false,
    verificationMethod: 'manual',
    organization: {
      did: 'did:fides:org',
      name: 'Example Org',
      domain: 'example.com',
      verified: true,
      verificationMethod: 'dns',
    },
  },
  capabilities: [{ id: 'payments.execute', name: 'Payments' }],
  protocols: ['mcp'],
  endpoints: [],
  security: { authentication: ['api-key'], encryption: ['tls1.3'] },
  metadata: {},
})

const card = await registry.getCard('did:fides:agent')
const matches = await registry.search('Payment')
await registry.setMode('did:fides:agent', 'private')
await registry.updateMetadata('did:fides:agent', { owner: 'ops' })
```

Cards that claim `publisher.verified: true` or `publisher.organization.verified: true`
are accepted only when the registry can match those DNS-backed claims against
discovery verification state.

## Relay Client

```typescript
import { RelayClient } from '@fides/sdk'

const relay = new RelayClient({
  baseUrl: 'http://localhost:7347',
  apiKey: process.env.FIDES_API_KEY,
})

const accepted = await relay.send({
  to: 'did:fides:agent',
  from: 'did:fides:principal',
  payload: { type: 'fides.agent_card', card },
})

const pending = await relay.poll('did:fides:agent')
const status = await relay.getMessage(accepted.relayId)
await relay.deleteMessage(accepted.relayId)
```

## Platform Client

```typescript
import { PlatformClient } from '@fides/sdk'

const platform = new PlatformClient({
  baseUrl: 'http://localhost:3600',
  apiKey: process.env.FIDES_API_KEY,
})

const topology = await platform.topology()

await platform.storePasskeyBinding({
  principalDid: 'did:fides:principal',
  credentialId: 'credential-id',
  publicKey: 'provider-public-key',
  relyingPartyId: 'example.com',
  signCount: 1,
  createdAt: new Date().toISOString(),
})

const credentials = await platform.listPasskeyCredentials('did:fides:principal')
const binding = await platform.getPasskeyBinding('credential-id')
await platform.deletePasskeyBinding('credential-id')

await platform.storeTrustAnchor({
  did: 'did:fides:anchor',
  name: 'Example Root Anchor',
  publicKey: '00'.repeat(32),
  attestation: {
    payload: { did: 'did:fides:anchor' },
    proof: {
      type: 'Ed25519Signature2024',
      created: new Date().toISOString(),
      verificationMethod: 'did:fides:issuer#key-1',
      proofPurpose: 'assertionMethod',
      canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1',
      proofValue: 'signature',
    },
  },
  status: 'active',
  scopes: ['identity.organization'],
  issuerDid: 'did:fides:issuer',
  createdAt: new Date().toISOString(),
})

const anchors = await platform.listTrustAnchors('active')
const distribution = await platform.trustAnchorDistribution({
  requiredScope: 'identity.organization',
  trustedIssuerDids: ['did:fides:issuer'],
})
```

## API

| Function | Description |
|----------|-------------|
| `generateKeyPair()` | Generate Ed25519 keypair |
| `generateDID(publicKey)` | Create DID from public key |
| `signRequest(request, privateKey, options)` | Sign HTTP request (RFC 9421) |
| `verifyRequest(request, publicKey, options)` | Verify HTTP request signature |
| `createAttestation(issuer, subject, level, key)` | Create signed trust attestation |
| `verifyAttestation(attestation, publicKey)` | Verify attestation signature |
| `AgentdClient.authorize(request)` | Check local agentd authorization decisions |
| `AgentdClient.getCard(did)` | Read an AgentCard through agentd, preserving private versus missing card errors |
| `AgentdClient.verifyDomain(domain, did)` | Verify a domain-to-DID DNS TXT binding through agentd |
| `DiscoveryClient.verifyDomain(did, domain?)` | Verify and persist a registered identity domain in discovery |
| `DiscoveryClient.verifyOrganizationDomain(did, domain?)` | Verify and persist a registered organization domain in discovery |
| `AgentdClient.createSession(request)` | Create delegated agentd sessions |
| `AgentdClient.createSignedSession(options)` | Create and sign a delegation token before opening a session |
| `AgentdClient.recordRevocation(request)` | Submit signed authority revocations |
| `AgentdClient.recordSignedRevocation(options)` | Create and sign an authority revocation before submission |
| `AgentdClient.recordIncident(request)` | Submit signed authority incidents |
| `AgentdClient.recordSignedIncident(options)` | Create and sign an authority incident before submission |
| `AgentdClient.listPendingPropagations(limit)` | Inspect due authority propagation retries |
| `AgentdClient.retryPropagations(limit)` | Replay due authority propagation records |
| `TrustClient.getRevocation(did)` | Read latest trust-graph authority revocation state |
| `RegistryClient.register(card)` | Publish an AgentCard to the hosted registry |
| `RegistryClient.getCard(did)` | Read a public AgentCard, returning `null` when it is missing |
| `RegistryClient.search(query)` | Search public registry cards |
| `RegistryClient.setMode(did, mode)` | Switch a registry card between `public` and `private` |
| `RegistryClient.updateMetadata(did, metadata)` | Merge operator metadata into a registry card |
| `RelayClient.send(message)` | Enqueue a relay message for a target DID |
| `RelayClient.poll(did)` | Poll and deliver pending relay messages for a DID |
| `RelayClient.getMessage(relayId)` | Read relay message status by ID |
| `RelayClient.deleteMessage(relayId)` | Delete a relay message by ID |
| `RelayClient.stats()` | Read relay service queue statistics |
| `PlatformClient.topology()` | Read configured platform service URLs |
| `PlatformClient.storePasskeyBinding(binding)` | Store or update a verified passkey credential binding |
| `PlatformClient.listPasskeyCredentials(principalDid)` | List a principal's passkey credential descriptors |
| `PlatformClient.getPasskeyBinding(credentialId)` | Read a stored passkey credential binding, returning `null` when missing |
| `PlatformClient.deletePasskeyBinding(credentialId)` | Delete a stored passkey credential binding |
| `PlatformClient.storeTrustAnchor(anchor)` | Store or update a governed trust-anchor record |
| `PlatformClient.listTrustAnchors(status?)` | List governed trust anchors, optionally filtered by status |
| `PlatformClient.trustAnchorDistribution(options?)` | Read a deterministic active trust-anchor distribution bundle |
| `PlatformClient.getTrustAnchor(did)` | Read a governed trust anchor, returning `null` when missing |
| `PlatformClient.updateTrustAnchorStatus(did, update)` | Suspend, reactivate, or revoke a governed trust anchor |
| `PlatformClient.deleteTrustAnchor(did)` | Hard-delete a governed trust-anchor record |

### Trust Levels

| Level | Value | Description |
|-------|-------|-------------|
| `NONE` | 0 | No trust |
| `LOW` | 25 | Minimal trust |
| `MEDIUM` | 50 | Standard collaboration |
| `HIGH` | 75 | Sensitive operations |
| `ABSOLUTE` | 100 | Full delegation |

## Requirements

- Node.js >= 22.0.0

## License

MIT
