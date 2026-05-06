# FIDES — verifiable identity, authority, and pre-execution trust controls for AI agents

> **Latin:** *fides* = trust, faith, confidence

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-brightgreen.svg)](https://nodejs.org/)
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

---

## Quick Start

### Installation

```bash
pnpm install
pnpm build
```

### Basic Usage

```typescript
import { createIdentity, classifyCapabilityRisk, createDelegationToken } from '@fides/core'
import { evaluatePolicy } from '@fides/policy'
import { evaluateGuard, createTrustContext } from '@fides/guard'
import { createEvidenceChain, appendEvidenceEvent } from '@fides/evidence'
import { MockTEEProvider, InMemoryKillSwitch } from '@fides/runtime'

// Create agent identities
const alice = createIdentity('did:fides:alice', 'agent', { name: 'Alice Assistant' })
const charlie = createIdentity('did:fides:charlie', 'principal', { name: 'Charlie User' })

// Classify capability risk
const risk = classifyCapabilityRisk('email:send')  // 'high'

// Delegate capabilities with constraints
const token = createDelegationToken({
  delegator: charlie.did,
  delegatee: alice.did,
  capabilities: ['email:send', 'calendar:create'],
  constraints: { maxActions: 10, maxSpend: '10.00', allowedContexts: ['work'] },
  expiresAt: new Date(Date.now() + 3600000).toISOString(),
})

// Evaluate policy
const policy = {
  id: 'default', version: '1.0.0',
  rules: [
    { id: 'trust', condition: { operator: 'gte', field: 'reputationScore', value: 0.8 }, action: 'allow', explanation: 'High trust' },
  ],
  defaultAction: 'deny',
}
const result = evaluatePolicy(policy, { reputationScore: 0.9 })

// Build evidence chain
let chain = createEvidenceChain()
chain = appendEvidenceEvent(chain, {
  id: 'e1', type: 'invoke', timestamp: new Date().toISOString(),
  actor: alice.did, action: 'email:send', payload: {},
  privacy: { level: 'redacted' },
}, 'signature-hex')

// Run guard decision
const trust = createTrustContext({
  reputationScore: 0.9, capabilityScore: 0.95,
  attestation: await new MockTEEProvider().attest(alice.did),
  evidenceChain: chain, killSwitchEngaged: false, recentIncidents: 0,
})
const decision = await evaluateGuard({
  agentDid: alice.did, capabilityId: 'email:send',
  policy, context: { requestCount: 10 }, trust,
})
// decision.decision → 'allow' | 'deny' | 'approve-required' | 'dry-run'
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              AI Agent                                   │
│                                                                         │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────────────┐ │
│  │ @fides/    │ │ @fides/    │ │ @fides/    │ │ @fides/              │ │
│  │ core       │ │ policy     │ │ guard      │ │ evidence             │ │
│  │            │ │            │ │            │ │                      │ │
│  │ Identity   │ │ Policy     │ │ Decision   │ │ Hash-chain           │ │
│  │ Signing    │ │ Rules      │ │ Pipeline   │ │ Merkle root          │ │
│  │ AgentCard  │ │ Expressions│ │ KillSwitch │ │ Privacy levels       │ │
│  │ DelegationToken evaluation │ │ Attestation│ │ Event log            │ │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └──────────┬───────────┘ │
│        │              │              │                   │             │
│  ┌─────┴──────────────┴──────────────┴───────────────────┴──────────┐ │
│  │                    @fides/discovery                               │ │
│  │         well-known · registry · relay · DHT · local               │ │
│  └──────────────────────────────┬────────────────────────────────────┘ │
│  ┌──────────────────────────────┴────────────────────────────────────┐ │
│  │                    @fides/runtime                                 │ │
│  │         TEE Attestation · Kill Switch · Runtime verification      │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ @fides/         │   │ @fides/         │   │ @fides/         │
│ discovery-svc   │   │ trust-graph     │   │ registry-svc    │
│                 │   │                 │   │                 │
│ AgentCard       │   │ Trust edges     │   │ Agent           │
│ resolution      │   │ Reputation      │   │ registration    │
│ .well-known     │   │ BFS scoring     │   │ Capability pub  │
└─────────────────┘   └────────┬────────┘   └────────┬────────┘
                               │                     │
                    ┌──────────┴─────────────────────┴──────────┐
                    ▼                     ▼                     ▼
           ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
           │ @fides/         │  │ @fides/         │  │ @fides/         │
           │ relay-svc       │  │ agentd          │  │ platform-api    │
           │                 │  │                 │  │                 │
           │ NAT traversal   │  │ Agent daemon    │  │ REST/gRPC       │
           │ Message relay   │  │ Lifecycle mgmt  │  │ Admin API       │
           └─────────────────┘  └─────────────────┘  └─────────────────┘
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
| `@fides/sdk` | Legacy v1 SDK (Ed25519 identity, RFC 9421 signing, trust graph) |
| `@fides/shared` | Shared types, constants, and utilities |
| `@fides/cli` | Command-line interface for agent management and diagnostics |
| `@fides/rust-sdk` | Rust SDK (planned) |

---

## Services

| Service | Description |
|---------|-------------|
| `@fides/discovery-service` | AgentCard resolution via `.well-known` endpoint hosting |
| `@fides/trust-graph` | Trust edge storage, reputation scoring, and capability-specific trust computation |
| `@fides/registry-service` | Central agent registration and capability publishing |
| `@fides/relay-service` | Message relay for agents behind NAT/firewalls |
| `@fides/agentd` | Agent daemon for lifecycle management and local policy enforcement |
| `@fides/platform-api` | Platform REST/gRPC API (stub) |
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
Manual and startup migrations record applied ids in `agentd_schema_migrations`; with `AGENTD_DB_AUTO_MIGRATE=false`, `agentd` refuses to start unless the authority tables and migration ledger are present.

For production agentd mutations through the CLI, export the same API key used by the service:

```bash
export FIDES_API_KEY="$SERVICE_API_KEY"
pnpm --filter @fides/cli fides session create --agentd-url https://agentd.example.com --capability payments.execute --token-file token.json --delegator-public-key "$DELEGATOR_PUBLIC_KEY_HEX"
pnpm --filter @fides/cli fides revoke agent did:fides:agent --agentd-url https://agentd.example.com --revoked-by did:fides:principal --reason "disabled" --private-key-hex "$REVOCATION_PRIVATE_KEY_HEX"
pnpm --filter @fides/cli fides incident report --agentd-url https://agentd.example.com --actor did:fides:agent --type policy_violation --severity high --description "merchant policy bypass" --reporter did:fides:principal --private-key-hex "$REPORTER_PRIVATE_KEY_HEX"
pnpm --filter @fides/cli fides propagation pending --agentd-url https://agentd.example.com --limit 25
pnpm --filter @fides/cli fides propagation retry --agentd-url https://agentd.example.com --limit 25
```

When `--delegator-public-key` is provided, `agentd` verifies the DelegationToken signature before creating the session.
For revocation and incident writes, the CLI derives the signer public key from `--private-key-hex` and sends it as `revokerPublicKey` or `reporterPublicKey`.
Use `fides propagation pending` and `fides propagation retry` to inspect and replay failed authority propagation outbox records.
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
│   ├── sdk/               # Legacy v1 SDK
│   ├── shared/            # Shared types and constants
│   ├── cli/               # Command-line interface
│   └── rust-sdk/          # Rust SDK (planned)
├── services/
│   ├── discovery/         # AgentCard resolution service
│   ├── trust-graph/       # Trust and reputation service
│   ├── registry/          # Agent registration service
│   ├── relay/             # Message relay service
│   ├── agentd/            # Agent daemon
│   ├── platform-api/      # Platform API (stub)
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

- Node.js >= 20 (recommend v22)
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
