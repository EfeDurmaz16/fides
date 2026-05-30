# Getting Started with FIDES v2

FIDES v2 is a local-first Agent Trust Fabric. It resolves capabilities to
verified agent candidates, then evaluates identity, trust, policy, delegation,
runtime attestation, revocation, incidents, and evidence before any invocation
authority is granted.

Discovery is not authority. Identity is not trust. Trust is not permission.
Policy and scoped session grants are the authority path.

## Prerequisites

- Node.js 22+
- pnpm
- Git

Optional:

- Docker/PostgreSQL if you want to exercise legacy backing services or external
  authority-store modes.

## Install And Build

```bash
git clone https://github.com/EfeDurmaz16/fides.git
cd fides
pnpm install
pnpm build
```

The examples below assume the `agentd` binary is on your `PATH`. From a fresh
checkout, you can run the same commands through the root workspace script:

```bash
pnpm agentd <command>
```

## Start The Local Daemon

The root v2 API is served by `agentd` on `http://localhost:7345`.

```bash
pnpm agentd:dev
```

In another shell:

```bash
curl http://localhost:7345/health
```

Local daemon state is stored in `~/.fides/fides.sqlite` by default. Use
`AGENTD_SQLITE_PATH=/path/to/fides.sqlite` for a specific database file or
`AGENTD_LOCAL_STATE=memory` for an ephemeral run.

## Create Local Identities

Create a principal, publisher, requester agent, and target agent.

```bash
agentd identity create --type principal --name "Demo Principal" --agentd-url http://localhost:7345
agentd identity create --type publisher --name "Demo Publisher" --agentd-url http://localhost:7345
agentd identity create --type agent --name "Requester Agent" --agentd-url http://localhost:7345
agentd identity create --type agent --name "Invoice Agent" --agentd-url http://localhost:7345
```

List identities:

```bash
agentd identity list --agentd-url http://localhost:7345
```

Private keys are not returned by the daemon API.
Replace the placeholder DIDs below with the values returned by these commands.

## Add Trust Anchors

Domains are optional. A publisher can use domainless anchors such as GitHub,
email, package registry, wallet, passkey, organization invitation, runtime
attestation, build attestation, or peer attestation.

```bash
agentd attest github --identity did:fides:publisher --handle fides-dev --agentd-url http://localhost:7345
agentd attest email --identity did:fides:publisher --email dev@example.com --agentd-url http://localhost:7345
agentd attest package --identity did:fides:publisher --registry npm --package @fides/example-agent --agentd-url http://localhost:7345
```

Attestations add evidence and trust signals. They do not grant invocation
authority.

## Create And Sign An AgentCard

Create an AgentCard for a capability.

```bash
agentd card create \
  --did did:fides:invoice-agent \
  --name "Invoice Agent" \
  --capabilities '[{"id":"invoice.reconcile","riskLevel":"medium","requiredScopes":["invoice:read"],"supportedControls":["dry_run","policy_proof"],"supportsDryRun":true,"supportsPolicyProof":true}]' \
  --agentd-url http://localhost:7345
```

Sign and verify the card:

```bash
agentd card sign did:fides:invoice-agent --agentd-url http://localhost:7345
agentd card verify did:fides:invoice-agent --agentd-url http://localhost:7345
```

All signed protocol objects use the shared canonical signing model.

## Register For Discovery

Register the signed AgentCard as a local discovery candidate.

```bash
agentd register did:fides:invoice-agent --agentd-url http://localhost:7345
agentd agents list --agentd-url http://localhost:7345
```

Registration only makes the agent discoverable. It does not grant authority.

## Discover By Capability

Local discovery:

```bash
agentd discover --capability invoice.reconcile --provider local --agentd-url http://localhost:7345
```

Registry, relay, DHT, and federation-ready discovery:

```bash
agentd registry start --agentd-url http://localhost:7345
agentd registry publish did:fides:invoice-agent --agentd-url http://localhost:7345
agentd registry search --capability invoice.reconcile --supported-versions fides.v2.0 --agentd-url http://localhost:7345

agentd relay start --agentd-url http://localhost:7345
agentd relay register did:fides:invoice-agent --agentd-url http://localhost:7345
agentd relay discover --capability invoice.reconcile --supported-versions fides.v2.0 --agentd-url http://localhost:7345

agentd dht start --agentd-url http://localhost:7345
agentd dht publish --capability invoice.reconcile --agent-id did:fides:invoice-agent --agentd-url http://localhost:7345
agentd dht find --capability invoice.reconcile --agentd-url http://localhost:7345
```

DHT records are signed pointers only. They are not trust sources.

## Evaluate Trust And Reputation

Trust is capability-specific.

```bash
agentd trust did:fides:invoice-agent --capability invoice.reconcile --agentd-url http://localhost:7345
```

Reputation is also capability-specific and can be principal/publisher-aware.

```bash
agentd reputation update \
  --agent did:fides:invoice-agent \
  --capability invoice.reconcile \
  --successful-invocations 8 \
  --failed-invocations 1 \
  --agentd-url http://localhost:7345

agentd reputation get did:fides:invoice-agent --agentd-url http://localhost:7345
```

Trust and reputation are signals. Policy is the authority.

## Evaluate Policy

```bash
agentd policy evaluate \
  --agent did:fides:invoice-agent \
  --capability invoice.reconcile \
  --requested-scopes invoice:read \
  --agentd-url http://localhost:7345
```

Policy decisions include machine-readable reasons, human-readable reasons,
required controls, and evidence refs. They are never just booleans.

## Request A Session Grant

```bash
agentd session request did:fides:invoice-agent \
  --capability invoice.reconcile \
  --requested-scopes invoice:read \
  --agentd-url http://localhost:7345

agentd session verify sess_... --agentd-url http://localhost:7345
```

A `SessionGrant` is scoped by requester, target, principal, capability, scopes,
constraints, audience, expiry, nonce, policy hash, and trust-result hash.

## Invoke A Capability

```bash
agentd invoke --session-id sess_... --input invoice.json --agentd-url http://localhost:7345
```

For high-risk actions, request dry-run or approval-gated behavior:

```bash
agentd invoke --dry-run did:fides:payment-agent \
  --capability payments.prepare \
  --input payment.json \
  --requested-scopes payments:prepare \
  --agentd-url http://localhost:7345
```

Generic FIDES keeps payment execution dry-run only. Payment-specific execution
belongs in Sardis.

## Runtime Attestation

High-risk capabilities can require runtime attestation or approval.

```bash
agentd attest runtime \
  --agent did:fides:payment-agent \
  --code-hash sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --runtime-hash sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --policy-hash sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --agentd-url http://localhost:7345

agentd attest verify att_... --agentd-url http://localhost:7345
```

MockTEE is local and adapter-ready. Production TEE providers are future
adapters.

## Evidence

Evidence defaults to hash-only or redacted handling for sensitive inputs and
outputs.

```bash
agentd evidence verify --agentd-url http://localhost:7345
agentd evidence export --privacy-mode hash_only --no-metadata --agentd-url http://localhost:7345
```

Evidence is append-only and hash-chained.

## Revocations, Incidents, And Kill Switches

```bash
agentd revoke agent did:fides:invoice-agent --reason "compromised key" --agentd-url http://localhost:7345
agentd incident report did:fides:invoice-agent --severity high --category unauthorized_action --description "policy bypass" --agentd-url http://localhost:7345
agentd killswitch enable --capability payments.prepare --reason "incident response" --agentd-url http://localhost:7345
```

Active revocations and kill switches override normal trust and policy
evaluation.

## Run The Full Demo

```bash
agentd demo run --agentd-url http://localhost:7345
```

The demo creates identities, signs AgentCards, registers agents, publishes
registry/relay/DHT records, evaluates trust and policy, creates sessions,
invokes dry-run and allowed capabilities, emits evidence, reports an incident,
records a revocation, and verifies the evidence hash chain.

## Run The Adversarial Simulation

```bash
agentd simulate adversarial --agentd-url http://localhost:7345
```

The simulation covers fake agents, fake publishers, malicious DHT pointers,
tampered AgentCards, expired runtime attestations, revoked agents, collusive
trust attestations, context laundering, high-risk capability abuse, and broken
evidence chains.

## TypeScript SDK

Use `FidesClient` for the Promise-based v2 SDK surface.

```typescript
import { FidesClient } from '@fides/sdk'

const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

const identity = await client.identity.createAgent({ name: 'Invoice Agent' })

const card = await client.cards.create({
  agentId: identity.identity.did,
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

const discovered = await client.discovery.local({ capability: 'invoice.reconcile' })
console.log(discovered.authorityGranted) // false

const trust = await client.trust.evaluate({
  agentId: identity.identity.did,
  capability: 'invoice.reconcile',
})

const policy = await client.policy.evaluate({
  agentId: identity.identity.did,
  capability: 'invoice.reconcile',
  requestedScopes: ['invoice:read'],
})

const session = await client.sessions.request({
  agentId: identity.identity.did,
  capability: 'invoice.reconcile',
  requestedScopes: ['invoice:read'],
})

const result = await client.invoke({
  sessionId: session.session.session_id,
  input: { invoiceId: 'inv_123' },
})

console.log({ trust: trust.trust.band, policy: policy.policy.decision, result })
```

## Verification Commands

Useful checks while developing:

```bash
pnpm --filter @fides/core test
pnpm --filter @fides/sdk test
pnpm --filter @fides/sdk build
pnpm --filter @fides/sdk lint
pnpm --filter @fides/agentd test
```

## Next Steps

- Read `docs/architecture/fides-v2-agent-trust-fabric.md`.
- Read `docs/protocol/canonical-object-signing.md`.
- Read `docs/protocol/discovery.md`.
- Read `docs/protocol/evidence-ledger.md`.
- Read `docs/cli-reference.md`.
- Read `docs/sdk-reference.md`.
