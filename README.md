# FIDES — verifiable identity, authority, and pre-execution trust controls for AI agents

> **Latin:** *fides* = trust, faith, confidence

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22-brightgreen.svg)](https://nodejs.org/)
[![CI](https://github.com/EfeDurmaz16/fides/actions/workflows/ci.yml/badge.svg)](https://github.com/EfeDurmaz16/fides/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/EfeDurmaz16/fides/pulls)

**Signed agent identity, capability-aware delegation, deterministic policy guards, tamper-evident evidence, runtime attestation, and kill switches for autonomous agent systems.**

FIDES is an agent trust fabric for deciding whether an autonomous agent is known, authorized, delegated, attested, and safe to execute before an action crosses a boundary.

---

## Why FIDES?

As AI agents become increasingly autonomous, they face critical challenges in secure collaboration:

- **No verifiable identity** — Agents cannot prove who they are or what they're authorized to do
- **No capability semantics** — No standard way to describe what an agent can do and at what risk level
- **No pre-execution guards** — Actions execute without policy evaluation or trust verification
- **No audit trail** — No tamper-evident record of agent actions and decisions
- **No emergency control** — No way to revoke capabilities or halt rogue agents

FIDES solves these problems with a layered trust protocol built specifically for AI agent ecosystems.

---

## Key Features

- **AgentCards** — Self-describing agent manifests with capabilities, endpoints, and security profiles
- **CapabilityDescriptors** — Typed capability definitions with risk classification (critical/high/medium/low)
- **Policy Engine** — Deterministic rule evaluation with pre-execution guards (allow/deny/approve-required/dry-run)
- **Evidence Ledger** — Hash-chained, Merkle-rooted event log with privacy levels (public/private/redacted/hash-only)
- **Runtime Attestation** — TEE-ready adapter boundary with a mock provider for local verification
- **Guard Decision Engine** — Multi-factor decision pipeline combining trust, evidence, attestation, and policy
- **Kill Switch** — Emergency shutdown at global, agent, capability, or principal level
- **Delegation** — Capability delegation with constraints (spend limits, action counts, context restrictions)
- **Discovery Providers** — Multi-provider agent discovery (well-known, registry, relay, local, DHT-ready)
- **Ed25519 Identity** — DID-based identities with canonical JSON signing
- **Trust Graph** — Weighted, capability-specific reputation with transitive trust scoring

**Current implementation status:** [docs/status/fides-v2-implementation-status.md](docs/status/fides-v2-implementation-status.md)

---

## Quick Start

### Installation

```bash
pnpm install
pnpm build
```

### Start agentd

```bash
pnpm agentd:dev
curl http://localhost:7345/health
```

### CLI authority path

The examples below assume the `agentd` binary is on your `PATH`. From the
monorepo, use `pnpm agentd <command>`.
Replace placeholder DIDs with the IDs returned by `identity create`.
Use `pnpm --silent agentd ... --json` when piping JSON output to another tool,
because pnpm prints script banners by default.

```bash
agentd identity create --type principal --name "Demo Principal" --agentd-url http://localhost:7345
agentd identity create --type publisher --name "Demo Publisher" --agentd-url http://localhost:7345
agentd identity create --type agent --name "Invoice Agent" --agentd-url http://localhost:7345

agentd card create --did did:fides:invoice-agent --name "Invoice Agent" --capabilities '[{"id":"invoice.reconcile","riskLevel":"medium","requiredScopes":["invoice:read"]}]' --agentd-url http://localhost:7345
agentd card sign did:fides:invoice-agent --agentd-url http://localhost:7345
agentd register did:fides:invoice-agent --agentd-url http://localhost:7345

agentd discover --capability invoice.reconcile --provider local --agentd-url http://localhost:7345
agentd trust did:fides:invoice-agent --capability invoice.reconcile
agentd graph inspect did:fides:invoice-agent --agentd-url http://localhost:7345
agentd policy evaluate --agent did:fides:invoice-agent --capability invoice.reconcile --requested-scopes invoice:read --agentd-url http://localhost:7345
agentd session request did:fides:invoice-agent --capability invoice.reconcile --requested-scopes invoice:read --agentd-url http://localhost:7345
agentd invoke --session-id sess_... --input invoice.json --agentd-url http://localhost:7345
agentd evidence verify --agentd-url http://localhost:7345
```

Discovery returns candidates only. Policy and scoped SessionGrants are the
authority path.

### TypeScript SDK

```typescript
import { FidesClient } from '@fides/sdk'

const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

const principal = await client.identity.createPrincipal({ name: 'Demo Principal' })
const requester = await client.identity.createAgent({ name: 'Requester Agent' })
const target = await client.identity.createAgent({ name: 'Invoice Agent' })

const card = await client.cards.create({
  agentId: target.did,
  name: 'Invoice Agent',
  capabilities: [{ id: 'invoice.reconcile', riskLevel: 'medium', requiredScopes: ['invoice:read'] }],
})

await client.cards.sign({ id: card.card.id })
await client.agents.register({ agentCardId: card.card.id })

const candidates = await client.discovery.local({ capability: 'invoice.reconcile' })
console.log(candidates.authorityGranted) // false

await client.trust.evaluate({ agentId: target.did, capability: 'invoice.reconcile' })
await client.policy.evaluate({
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

await client.invoke({ sessionId: session.session.session_id, input: { invoiceId: 'inv_123' } })
await client.evidence.verify()
```

---

## Architecture

```
intent/capability + constraints
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│ Discovery providers                                          │
│ local · well-known · registry · relay · DHT · federation     │
│ Output: verified candidates only, never authority            │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Verification and scoring                                     │
│ signed AgentCards · protocol versions · trust anchors        │
│ capability-specific trust · reputation · incidents           │
│ revocations · runtime attestations                           │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Policy-before-execution                                      │
│ allow · deny · require_approval · dry_run_only               │
│ scope_limit · risk_limit · kill switch override              │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Scoped authority                                             │
│ DelegationToken · SessionGrant · nonce · expiry · audience   │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Invocation and evidence                                      │
│ validate input/output · execute or dry-run · signed result   │
│ hash-chained EvidenceEvents · redacted/hash-only by default  │
└──────────────────────────────────────────────────────────────┘
```

---

## Packages

| Package | Description |
|---------|-------------|
| `@fides/core` | Core primitives: identity, signing, AgentCard, delegation, capability risk classification |
| `@fides/policy` | Policy engine with expression evaluation, pre-execution guards, and rule bundles |
| `@fides/guard` | Guard decision engine combining trust, evidence, attestation, and policy into allow/deny decisions |
| `@fides/evidence` | Evidence ledger with hash-chained events, Merkle root computation, and privacy levels |
| `@fides/runtime` | Runtime attestation adapter interfaces, mock attestation, and kill switch (global/agent/capability/principal) |
| `@fides/discovery` | Discovery provider architecture with priority-based orchestration |
| `@fides/sdk` | TypeScript SDK for identity, RFC 9421 signing, trust graph, agentd authority APIs, and hosted registry APIs |
| `@fides/shared` | Shared types, constants, and utilities |
| `@fides/cli` | Command-line interface for agent management and diagnostics |
| `@fides/rust-sdk` | Rust SDK (planned) |

---

## Services

| Service | Description |
|---------|-------------|
| `@fides/discovery-service` | AgentCard resolution via `.well-known` endpoint hosting |
| `@fides/trust-graph` | Trust edge storage, reputation scoring, and capability-specific trust computation |
| `@fides/registry-service` | Hosted AgentCard registry with public/private modes, search, metadata, metrics, and durable Postgres storage |
| `@fides/relay-service` | Message relay for agents behind NAT/firewalls |
| `@fides/agentd` | Agent daemon for lifecycle management and local policy enforcement |
| `@fides/platform-api` | Platform metadata API for health, version, and service topology |
| `@fides/policy-engine` | Standalone policy evaluation service |

### agentd production authority store

`agentd` defaults to a local file-backed authority store. For production, run it with Postgres:

```bash
export AGENTD_AUTHORITY_STORE=postgres
export DATABASE_URL=postgresql://...
pnpm --filter @fides/agentd db:migrate
pnpm --filter @fides/agentd dev
```

When using Stripe Projects with a resource named `fides-authority-db`, map the generated connection string before running migrations:

```bash
source .env
export AGENTD_DATABASE_URL="$FIDES_AUTHORITY_DB_CONNECTION_STRING"
pnpm --filter @fides/agentd db:migrate
```

Set `AGENTD_DB_AUTO_MIGRATE=false` when migrations are managed externally. `/health` reports the active authority store kind and readiness.
Manual and startup migrations record applied ids and statement checksums in `agentd_schema_migrations`; with `AGENTD_DB_AUTO_MIGRATE=false`, `agentd` refuses to start unless the authority tables and migration ledger are present and checksums match the current migrations.

For local agentd lifecycle control through the CLI:

```bash
pnpm --filter @fides/cli fides daemon start --port 7345
pnpm --filter @fides/cli fides daemon status --agentd-url http://localhost:7345
pnpm --filter @fides/cli fides daemon status --agentd-url http://localhost:7345 --json
pnpm --filter @fides/cli fides daemon stop
```

`daemon start` launches the configured command in the background, writes a pid file to `~/.fides/agentd.pid`, and appends logs to `~/.fides/agentd.log`. Use `--sqlite-path`, `--local-state memory`, and `--authority-store-path` to isolate demo state. Use `--command`, `--args`, `--pid-file`, and `--log-file` when running outside the pnpm workspace layout.

To smoke test the actual local daemon plus CLI demo/simulation path with
isolated state:

```bash
pnpm smoke:agentd
```

To verify that the documented agentd OpenAPI surface matches the routes
implemented by the local daemon:

```bash
pnpm api:audit
```

For production agentd mutations through the CLI, export the same API key used by the service:

```bash
export FIDES_API_KEY="$SERVICE_API_KEY"
pnpm --filter @fides/cli fides session create --agentd-url https://agentd.example.com --capability payments.execute --token-file token.json --delegator-public-key "$DELEGATOR_PUBLIC_KEY_HEX"
pnpm --filter @fides/cli fides revoke agent did:fides:agent --agentd-url https://agentd.example.com --revoked-by did:fides:principal --reason "disabled" --private-key-hex "$REVOCATION_PRIVATE_KEY_HEX"
pnpm --filter @fides/cli fides incident report --agentd-url https://agentd.example.com --actor did:fides:agent --type policy_violation --severity high --description "merchant policy bypass" --reporter did:fides:principal --private-key-hex "$REPORTER_PRIVATE_KEY_HEX"
pnpm --filter @fides/cli fides propagation pending --agentd-url https://agentd.example.com --limit 25
pnpm --filter @fides/cli fides propagation retry --agentd-url https://agentd.example.com --limit 25
pnpm --filter @fides/cli fides authorize check --agentd-url https://agentd.example.com --agent-did did:fides:agent --capability payments.execute --session-id "$SESSION_ID" --audience agentd
pnpm --filter @fides/cli fides card proxy did:fides:agent --agentd-url https://agentd.example.com
```

When `--delegator-public-key` is provided, `agentd` verifies the DelegationToken signature before creating the session.
For revocation and incident writes, the CLI derives the signer public key from `--private-key-hex` and sends it as `revokerPublicKey` or `reporterPublicKey`.
Use `fides propagation pending` and `fides propagation retry` to inspect and replay failed authority propagation outbox records.
Use `fides authorize check` to smoke-test the same local guard decision path used before agent execution.
Set `AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION=true` to make this verification fail-closed for session, revocation, and incident writes.

---

## Project Structure

```
fides/
├── packages/
│   ├── core/              # v2 core primitives (identity, signing, delegation, AgentCard)
│   ├── policy/            # Policy engine and rule evaluation
│   ├── guard/             # Guard decision engine
│   ├── evidence/          # Evidence ledger (hash chain, Merkle root)
│   ├── runtime/           # Runtime attestation and kill switch
│   ├── discovery/         # Discovery provider architecture
│   ├── sdk/               # TypeScript SDK
│   ├── shared/            # Shared types and constants
│   ├── cli/               # Command-line interface
│   └── rust-sdk/          # Rust SDK (planned)
├── services/
│   ├── discovery/         # AgentCard resolution service
│   ├── trust-graph/       # Trust and reputation service
│   ├── registry/          # Agent registration service
│   ├── relay/             # Message relay service
│   ├── agentd/            # Agent daemon
│   ├── platform-api/      # Platform metadata API
│   └── policy-engine/     # Policy evaluation service
├── apps/
│   └── web/               # Web dashboard
├── tests/
│   ├── e2e/               # End-to-end tests
│   └── adversarial/       # Adversarial security tests
└── docs/
    └── protocol/
        └── fides-v2-spec.md  # Full protocol specification
```

---

## Development

### Prerequisites

- Node.js >= 22
- pnpm (package manager)
- Docker (for PostgreSQL)

### Setup

```bash
git clone https://github.com/EfeDurmaz16/fides.git
cd fides

pnpm install
pnpm build
```

### Commands

| Command | Description |
|---------|-------------|
| `pnpm build` | Build all packages |
| `pnpm test` | Run test suite |
| `pnpm lint` | Lint codebase |
| `pnpm typecheck` | Type-check TypeScript |
| `pnpm examples:typecheck` | Type-check example agents and demo manifests |
| `pnpm examples:audit` | Verify canonical v2 example agents and capability/risk contracts |
| `pnpm cli:audit` | Verify the implemented `agentd` CLI surface against the v2 command contract |
| `pnpm api:audit` | Verify documented `agentd` API routes against the implementation |
| `pnpm dev` | Start services in watch mode |
| `pnpm clean` | Clean build artifacts |
| `pnpm demo` | Run the primitive-level v2 demo |
| `pnpm demo:authority` | Run the authority path demo through service routes |

### Running the Demo

```bash
pnpm build
pnpm demo
pnpm demo:authority
```

The demo exercises all 9 subsystems: identity creation, AgentCard validation, risk classification, delegation tokens, policy evaluation, evidence ledger, runtime attestation, kill switch, and guard decisions.

The authority path demo additionally exercises the service route path: AgentCard registration, standalone policy evaluation, delegated session creation, nonce replay rejection, authorization evidence append, session revocation, and agent revocation denial.

---

## Security

FIDES v2 implements defense-in-depth across multiple layers:

- **Canonical Signing** — All signed objects use canonical JSON encoding (recursive key sorting, no whitespace) to prevent signature malleability
- **Ed25519 Cryptography** — Fast, secure elliptic curve signatures via @noble/ed25519
- **Evidence Chain Integrity** — Hash-chained events with Merkle root verification; tampering breaks the chain
- **Kill Switch** — Emergency capability/agent shutdown with precedence rules (global > agent > capability)
- **TEE Attestation** — Trusted Execution Environment adapter boundary with mock local attestation
- **Privacy Levels** — Evidence events support public/private/redacted/hash-only visibility
- **Delegation Constraints** — Spend limits, action counts, and context restrictions on delegated capabilities
- **Pre-Execution Guards** — Multi-factor decision pipeline before any capability execution

> **Security disclosure:** Report vulnerabilities via [SECURITY.md](SECURITY.md)

---

## Protocol Specification

FIDES v2 implements a complete trust fabric with:

- **Identity Layer** — Ed25519 keypairs with `did:fides:` identifiers and canonical JSON signing
- **AgentCard Layer** — Self-describing manifests with capabilities, endpoints, and security profiles
- **Trust Graph Layer** — Weighted, capability-specific reputation with transitive trust (depth-based weighting)
- **Policy Layer** — Deterministic rule evaluation with pre-execution guard pipeline
- **Evidence Layer** — Hash-chained, Merkle-rooted event log with privacy controls
- **Runtime Layer** — TEE attestation and emergency kill switch
- **Discovery Layer** — Multi-provider orchestration with priority-based resolution

**Full specification:** [docs/protocol/fides-v2-spec.md](docs/protocol/fides-v2-spec.md)

---

## Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch** — `git checkout -b feature/amazing-feature`
3. **Make your changes** — Follow TypeScript best practices
4. **Add tests** — Ensure `pnpm test` passes
5. **Commit changes** — `git commit -m 'Add amazing feature'`
6. **Push to branch** — `git push origin feature/amazing-feature`
7. **Open a Pull Request**

**Guidelines:**
- Write clear commit messages
- Add tests for new features
- Update documentation as needed
- Follow existing code style
- Ensure CI passes

---

## License

MIT License — see [LICENSE](LICENSE) for details

---

<div align="center">

**Built with cryptographic trust**

[Documentation](docs/) • [Protocol Spec](docs/protocol/fides-v2-spec.md) • [Contributing](#contributing)

</div>
