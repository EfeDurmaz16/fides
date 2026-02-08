# FIDES: Decentralized Trust & Authentication Protocol for AI Agents

## Implementation Plan (Revision 2)

---

## 1. Context

### 1.1 Original Request

Build FIDES — a decentralized trust and authentication protocol for autonomous AI agents. The system provides identity, trust, policy, and gateway layers enabling agents to authenticate with each other without leaking API keys, requiring browser flows, or relying on fragmented auth mechanisms.

### 1.2 Why FIDES

The AI agent ecosystem lacks a standard for inter-agent authentication. Today, agents rely on shared API keys (insecure), OAuth browser flows (impossible for headless agents), or bespoke token exchanges (fragmented). FIDES provides:

- **Decentralized identity** — agents own their cryptographic identity, no central authority required
- **Standard signing** — RFC 9421 HTTP Message Signatures, not a proprietary scheme
- **Transitive trust** — agents can reason about trust through a graph, not just pairwise secrets
- **Zero credential sharing** — authentication via public-key cryptography, private keys never leave the agent

### 1.3 Environment

- **Working directory**: `/Users/efebarandurmaz/fides/` (greenfield, empty)
- **Available toolchains**: Node v20.19.5 + pnpm 10.18.1, Bun 1.3.4
- **Target stack**: TypeScript-only monorepo (no Go, no Python, no Rust for MVP)
- **No existing code** — everything is built from scratch

### 1.4 Open Questions — Resolved

| Question | Resolution | Rationale |
|----------|-----------|-----------|
| Blockchain for trust attestations? | **No for MVP. Use signed JSON + Merkle roots.** | Blockchain adds massive complexity with minimal MVP value. Signed attestations with Merkle tree anchoring gives immutability guarantees without chain dependency. Can add optional blockchain anchoring in v2. |
| Key rotation without breaking trust graph? | **Key succession chain pattern.** Each key signs its successor before expiry. Trust edges reference the identity (DID), not raw public keys. A `key_history` table tracks the chain. | |
| Privacy of trust relationships? | **Trust scores are public, individual edges are private by default.** Agents can opt-in to public trust edges. Aggregate reputation is visible; who-trusts-whom is not, unless both parties consent. | |
| Pricing model? | **Defer to post-MVP.** All services are free-tier. Stub billing integration points but don't implement Stripe. | |
| Rust SDK priority? | **Not in MVP scope.** TypeScript SDK is primary. Stub the `packages/rust-sdk/` directory with a README only. | |
| DID format compliance? | **`did:fides` is a custom DID method inspired by W3C DID Core but NOT claiming full conformance for MVP.** Format: `did:fides:<base58(ed25519_pubkey)>`. A future version may register as a proper W3C DID method. Document the deviations from DID Core spec in protocol-spec.md. | |
| Nonce / replay protection? | **Deferred to post-MVP.** Rationale: RFC 9421 signatures include `created` and `expires` timestamps which provide basic replay window protection. Full nonce-based replay prevention requires server-side nonce tracking (adds state complexity). For MVP, the `expires` field in Signature-Input limits the replay window to a configurable duration (default: 300 seconds). Document this limitation. | |
| Key storage encryption? | **AES-256-GCM with PBKDF2 key derivation.** Private keys stored in `~/.fides/keys/` are encrypted at rest when a passphrase is provided. KDF: PBKDF2 with SHA-256, 600,000 iterations. File permissions: `0600` (owner read/write only). Unencrypted storage available for CI/automated environments via `--no-encrypt` flag. | |
| Service language? | **TypeScript-only for all services.** Multi-language MVP is project-killing complexity. Both discovery and trust-graph services use Hono + Drizzle ORM + PostgreSQL. Eliminates Go/TS type drift, separate toolchains, and simplifies E2E testing. | |

---

## 2. MVP Scope Definition

### 2.1 What IS in MVP

The minimum viable FIDES that demonstrates clear value:

1. **TypeScript SDK** — Keypair generation (Ed25519), HTTP request signing (RFC 9421), signature verification
2. **CLI tool** — Key management, identity registration, manual trust operations
3. **Discovery Service** — TypeScript HTTP server (Hono) that serves `/.well-known/fides.json` and resolves agent identities via PostgreSQL
4. **Trust Graph API** — TypeScript HTTP server (Hono + Drizzle ORM) with PostgreSQL for storing trust edges, computing reputation scores, and transitive trust queries
5. **Monorepo scaffolding** — Turborepo + pnpm workspaces, shared configs, CI-ready structure
6. **Integration tests** — End-to-end flow: agent A creates identity, agent B discovers A, A signs request to B, B verifies

### 2.2 What is NOT in MVP

- Python policy engine (stubbed with hardcoded policies)
- Neo4j (PostgreSQL-only for trust graph; adjacency list + recursive CTE for transitive trust)
- Next.js dashboard (stubbed route only)
- Stripe billing
- Rust SDK (README placeholder only)
- NATS/Kafka event streaming
- Clickhouse analytics
- OAuth/legacy gateway wrapping (stubbed interfaces only)
- Blockchain anchoring
- Redis (not needed for MVP — PostgreSQL handles all persistence)
- Cloudflare Workers / KV / Wrangler (services run as standard Node.js/Hono servers)
- Full W3C DID Core compliance (custom `did:fides` method for now)
- Nonce-based replay prevention (rely on RFC 9421 timestamp expiry for MVP)

### 2.3 Core Deliverables

| Deliverable | Demonstrates |
|-------------|-------------|
| SDK: `fides.createIdentity()` | Agent can generate Ed25519 keypair and DID |
| SDK: `fides.signRequest(req)` | Agent can sign HTTP requests per RFC 9421 |
| SDK: `fides.verifyRequest(req)` | Receiving agent can verify signatures |
| Discovery: `GET /.well-known/fides.json` | Public key discovery without central authority |
| Discovery: `POST /identities` | Agent identity registration |
| Trust API: `POST /trust` | Agent A attests trust in agent B |
| Trust API: `GET /trust/:id/score` | Reputation query |
| Trust API: `GET /trust/:from/:to` | Transitive trust path query |
| CLI: `fides init` | Generate keys and register identity |
| CLI: `fides trust <agent-id>` | Create trust attestation |
| E2E test | Full flow proving the system works |

---

## 3. Work Objectives

### 3.1 Core Objective

Build a working FIDES MVP where two AI agents can: (1) create cryptographic identities, (2) discover each other's public keys, (3) sign and verify HTTP requests, and (4) establish and query trust relationships.

### 3.2 Definition of Done

- All unit tests pass (`pnpm test` from repo root)
- E2E integration test passes (two agents complete full auth + trust flow)
- Discovery service runs locally via `pnpm --filter discovery dev`
- Trust Graph API runs locally via `pnpm --filter trust-graph dev`
- Both services connect to PostgreSQL via `docker compose up -d`
- SDK is importable as `@fides/sdk` with full TypeScript types
- CLI runs `fides init`, `fides sign`, `fides verify`, `fides trust`

---

## 4. Monorepo Structure (Final)

```
fides/
├── .github/
│   └── workflows/
│       └── ci.yml
├── packages/
│   ├── sdk/                    # @fides/sdk — TypeScript SDK
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── identity/
│   │   │   │   ├── keypair.ts          # Ed25519 key generation
│   │   │   │   ├── did.ts              # DID generation & parsing
│   │   │   │   └── keystore.ts         # Secure key storage
│   │   │   ├── signing/
│   │   │   │   ├── http-signature.ts   # RFC 9421 implementation
│   │   │   │   ├── verify.ts           # Signature verification
│   │   │   │   └── canonicalize.ts     # Message canonicalization
│   │   │   ├── discovery/
│   │   │   │   ├── client.ts           # Discovery service client
│   │   │   │   └── resolver.ts         # Identity resolution
│   │   │   ├── trust/
│   │   │   │   ├── client.ts           # Trust graph API client
│   │   │   │   ├── attestation.ts      # Trust attestation creation/verification
│   │   │   │   └── types.ts            # Trust types
│   │   │   └── types/
│   │   │       └── index.ts            # Shared type definitions
│   │   ├── test/
│   │   │   ├── identity.test.ts
│   │   │   ├── signing.test.ts
│   │   │   ├── discovery.test.ts
│   │   │   └── trust.test.ts
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── vitest.config.ts
│   ├── cli/                    # @fides/cli — CLI tool
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── commands/
│   │   │   │   ├── init.ts             # fides init
│   │   │   │   ├── sign.ts             # fides sign <url>
│   │   │   │   ├── verify.ts           # fides verify
│   │   │   │   ├── trust.ts            # fides trust <agent-id>
│   │   │   │   ├── discover.ts         # fides discover <agent-id>
│   │   │   │   └── status.ts           # fides status
│   │   │   └── utils/
│   │   │       ├── config.ts           # ~/.fides/ config management
│   │   │       └── output.ts           # Terminal output formatting
│   │   ├── test/
│   │   │   └── commands.test.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   ├── shared/                 # @fides/shared — Shared types & utils
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── types.ts               # Protocol-wide type definitions
│   │   │   ├── errors.ts              # Error type hierarchy
│   │   │   └── constants.ts           # Protocol constants
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── rust-sdk/               # Placeholder
│       └── README.md
├── services/
│   ├── discovery/              # TypeScript HTTP server (Hono)
│   │   ├── src/
│   │   │   ├── index.ts               # Hono app entry point
│   │   │   ├── routes/
│   │   │   │   ├── well-known.ts       # /.well-known/fides.json
│   │   │   │   ├── identities.ts       # POST/GET /identities
│   │   │   │   └── health.ts           # GET /health
│   │   │   ├── db/
│   │   │   │   ├── schema.ts           # Drizzle schema for identities
│   │   │   │   └── client.ts           # Drizzle PostgreSQL client
│   │   │   └── types.ts
│   │   ├── test/
│   │   │   └── routes.test.ts
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── drizzle.config.ts
│   ├── trust-graph/            # TypeScript HTTP server (Hono + Drizzle)
│   │   ├── src/
│   │   │   ├── index.ts               # Hono app entry point
│   │   │   ├── routes/
│   │   │   │   ├── trust.ts            # POST /v1/trust, GET /v1/trust/:did/score, GET /v1/trust/:from/:to
│   │   │   │   ├── identities.ts       # GET /v1/identities/:did
│   │   │   │   └── health.ts           # GET /health
│   │   │   ├── services/
│   │   │   │   ├── trust-service.ts    # Trust business logic
│   │   │   │   ├── graph.ts            # Graph traversal (BFS transitive trust)
│   │   │   │   └── scoring.ts          # Reputation scoring algorithm
│   │   │   ├── db/
│   │   │   │   ├── schema.ts           # Drizzle schema (identities, trust_edges, key_history, reputation_scores)
│   │   │   │   ├── client.ts           # Drizzle PostgreSQL client
│   │   │   │   └── migrations/
│   │   │   │       └── 001_initial.sql # SQL migration
│   │   │   ├── middleware/
│   │   │   │   └── logger.ts           # Request logging middleware
│   │   │   └── types.ts
│   │   ├── test/
│   │   │   ├── routes.test.ts
│   │   │   ├── trust-service.test.ts
│   │   │   └── graph.test.ts
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── drizzle.config.ts
│   ├── policy-engine/          # Stubbed for MVP
│   │   ├── README.md
│   │   └── stub/
│   │       └── policies.json          # Hardcoded policy examples
│   └── platform-api/           # Stubbed for MVP
│       └── README.md
├── apps/
│   └── web/                    # Stubbed for MVP
│       └── README.md
├── tests/
│   └── e2e/
│       ├── full-flow.test.ts          # E2E: identity -> discovery -> signing -> trust
│       ├── setup.ts                   # Test infrastructure setup
│       └── package.json
├── docs/
│   ├── architecture.md
│   ├── protocol-spec.md
│   └── getting-started.md
├── docker-compose.yml                 # PostgreSQL only for local dev
├── package.json                       # Root workspace config
├── pnpm-workspace.yaml
├── turbo.json
├── tsconfig.base.json
├── .gitignore
├── .env.example
└── README.md
```

---

## 5. Task Breakdown

### PHASE 1: Monorepo Scaffolding (Foundation)

**Estimated effort: ~1 hour**

**Must complete first — everything depends on this.**

#### Task 1.1: Initialize monorepo root

**Files to create:**
- `/Users/efebarandurmaz/fides/package.json` — Root package.json with pnpm workspaces
- `/Users/efebarandurmaz/fides/pnpm-workspace.yaml` — Workspace definitions
- `/Users/efebarandurmaz/fides/turbo.json` — Turborepo pipeline config (build, test, lint)
- `/Users/efebarandurmaz/fides/tsconfig.base.json` — Shared TypeScript config (strict mode, ESM, paths)
- `/Users/efebarandurmaz/fides/.gitignore` — Node, IDE ignores (no Go or Python needed)
- `/Users/efebarandurmaz/fides/.env.example` — Template env vars (DATABASE_URL, DISCOVERY_PORT, TRUST_GRAPH_PORT)
- `/Users/efebarandurmaz/fides/README.md` — Project overview (see Task 7.1 for content requirements)

**Acceptance criteria:**
- `pnpm install` runs without errors from repo root
- `pnpm -r exec echo "ok"` reaches all workspaces
- Turborepo pipelines defined for `build`, `test`, `lint`, `typecheck`

#### Task 1.2: Create shared package

**Files to create:**
- `/Users/efebarandurmaz/fides/packages/shared/package.json` — `@fides/shared`, ESM, TypeScript
- `/Users/efebarandurmaz/fides/packages/shared/tsconfig.json` — Extends base config
- `/Users/efebarandurmaz/fides/packages/shared/src/index.ts` — Re-exports
- `/Users/efebarandurmaz/fides/packages/shared/src/types.ts` — Core protocol types: `AgentIdentity`, `KeyPair`, `TrustAttestation`, `TrustEdge`, `SignedMessage`, `DiscoveryDocument`
- `/Users/efebarandurmaz/fides/packages/shared/src/errors.ts` — Error hierarchy: `FidesError`, `SignatureError`, `DiscoveryError`, `TrustError`, `KeyError`
- `/Users/efebarandurmaz/fides/packages/shared/src/constants.ts` — Protocol constants: `ALGORITHM = 'ed25519'`, `SIGNATURE_HEADER = 'Signature'`, `SIGNATURE_INPUT_HEADER = 'Signature-Input'`, `WELL_KNOWN_PATH = '/.well-known/fides.json'`, `DEFAULT_TRUST_DECAY = 0.85`, `MAX_TRUST_DEPTH = 6`, `DEFAULT_SIGNATURE_EXPIRY_SECONDS = 300`

**Acceptance criteria:**
- `pnpm --filter @fides/shared build` succeeds
- Types are importable: `import { AgentIdentity } from '@fides/shared'`

#### Task 1.3: Docker Compose for local services

**Files to create:**
- `/Users/efebarandurmaz/fides/docker-compose.yml` — PostgreSQL 16 only (no Redis)

**Acceptance criteria:**
- `docker compose up -d` starts PostgreSQL
- Can connect to PostgreSQL on localhost:5432
- No Redis container present

---

### PHASE 2: Identity Layer (TypeScript SDK Core)

**Estimated effort: ~3-4 hours**

**Depends on: Phase 1 complete**

#### Task 2.1: Ed25519 keypair generation

**Files to create:**
- `/Users/efebarandurmaz/fides/packages/sdk/package.json` — `@fides/sdk`, depends on `@fides/shared`, `@noble/ed25519`, `@noble/hashes`
- `/Users/efebarandurmaz/fides/packages/sdk/tsconfig.json`
- `/Users/efebarandurmaz/fides/packages/sdk/vitest.config.ts`
- `/Users/efebarandurmaz/fides/packages/sdk/src/index.ts` — Public API surface
- `/Users/efebarandurmaz/fides/packages/sdk/src/identity/keypair.ts` — `generateKeyPair()`: returns `{ publicKey, privateKey }` as Uint8Array; `exportPublicKeyPem()`, `importPrivateKeyPem()`; uses `@noble/ed25519` (pure JS, no native deps)
- `/Users/efebarandurmaz/fides/packages/sdk/src/identity/did.ts` — `generateDID(publicKey)`: creates `did:fides:<base58-encoded-pubkey>`; `parseDID(did)`: extracts public key; DID format: `did:fides:<base58check(ed25519_pubkey)>`. Note: this is a custom DID method inspired by but not fully conformant with W3C DID Core spec. Document deviations.
- `/Users/efebarandurmaz/fides/packages/sdk/src/identity/keystore.ts` — `FileKeyStore` class: stores keys in `~/.fides/keys/`; encrypted at rest with AES-256-GCM (PBKDF2, SHA-256, 600k iterations) when passphrase provided; file permissions set to `0600`; `--no-encrypt` mode for CI; `MemoryKeyStore` for testing
- `/Users/efebarandurmaz/fides/packages/sdk/test/identity.test.ts` — Tests: key generation determinism, DID round-trip, keystore save/load, PEM export/import, encrypted keystore round-trip

**Acceptance criteria:**
- `generateKeyPair()` returns valid Ed25519 keypair
- `generateDID()` produces deterministic DID from public key
- `parseDID()` recovers public key from DID
- Keystore saves and loads keys correctly (both encrypted and unencrypted)
- Encrypted keystore uses AES-256-GCM with PBKDF2-derived key
- Key files have `0600` permissions on Unix systems
- All tests pass: `pnpm --filter @fides/sdk test`

#### Task 2.2: RFC 9421 HTTP Message Signatures

**Implementation strategy:** Evaluate `node-http-message-signatures` (from the Misskey/ActivityPub ecosystem) as the primary implementation path. This library has production usage in the Fediverse for HTTP signature handling.

- If the library supports Ed25519 and the component coverage we need (`@method`, `@target-uri`, `@authority`, `content-type`, `content-digest`), wrap it with our FIDES-specific API.
- If the library is unsuitable (e.g., missing Ed25519 support, incompatible API, or unmaintained), document the specific reasons in a code comment and implement from the RFC directly.
- RFC specification: https://www.rfc-editor.org/rfc/rfc9421
- Test vectors: https://www.rfc-editor.org/rfc/rfc9421#appendix-B

**Files to create:**
- `/Users/efebarandurmaz/fides/packages/sdk/src/signing/canonicalize.ts` — `canonicalizeHeaders(request, components)`: implements RFC 9421 signature base creation; covers `@method`, `@target-uri`, `@authority`, `@path`, `content-type`, `content-digest`; produces deterministic string for signing
- `/Users/efebarandurmaz/fides/packages/sdk/src/signing/http-signature.ts` — `signRequest(request, privateKey, options?)`: takes a Request-like object, signs per RFC 9421; adds `Signature` and `Signature-Input` headers; `options` allows choosing which components to sign; default components: `@method`, `@target-uri`, `@authority`, `content-type`, `content-digest`; includes `created` and `expires` fields in Signature-Input for replay window protection (default expiry: 300s)
- `/Users/efebarandurmaz/fides/packages/sdk/src/signing/verify.ts` — `verifyRequest(request, publicKey)`: extracts `Signature` and `Signature-Input` headers; reconstructs signature base; verifies Ed25519 signature; checks `expires` timestamp (reject if expired); returns `{ valid: boolean, keyId: string, components: string[] }`
- `/Users/efebarandurmaz/fides/packages/sdk/test/signing.test.ts` — Tests: sign-then-verify round trip, tampered body detection, tampered header detection, missing signature rejection, expired signature rejection, multiple signatures, RFC 9421 Appendix B test vectors where applicable

**Acceptance criteria:**
- Sign a request, verify it — passes
- Tamper with body after signing — verification fails
- Tamper with headers after signing — verification fails
- Expired signature (past `expires` timestamp) — verification fails
- Missing/malformed signature — returns `{ valid: false }` with clear error
- Implementation either wraps `node-http-message-signatures` or documents why it was unsuitable
- All tests pass

#### Task 2.3: Discovery service client in SDK

**Files to create:**
- `/Users/efebarandurmaz/fides/packages/sdk/src/discovery/client.ts` — `DiscoveryClient` class: `register(identity)` — POST to discovery service; `resolve(agentId)` — GET from discovery service; `resolveFromWellKnown(domain)` — fetch `/.well-known/fides.json`; configurable base URL
- `/Users/efebarandurmaz/fides/packages/sdk/src/discovery/resolver.ts` — `IdentityResolver` class: tries `.well-known` first, falls back to central discovery; caches results in memory with TTL; `resolve(agentIdOrDomain)` — unified resolution
- `/Users/efebarandurmaz/fides/packages/sdk/test/discovery.test.ts` — Tests using msw (Mock Service Worker) to mock HTTP

**Acceptance criteria:**
- Client can register and resolve identities (against mock)
- Resolver tries `.well-known` first, falls back to discovery service
- Cache works correctly with TTL expiry

#### Task 2.4: Trust client in SDK

**Files to create:**
- `/Users/efebarandurmaz/fides/packages/sdk/src/trust/types.ts` — `TrustLevel` enum (none, low, medium, high, absolute); `TrustAttestation` interface; `TrustScore` interface; `TrustPath` interface
- `/Users/efebarandurmaz/fides/packages/sdk/src/trust/attestation.ts` — `createAttestation(from, to, level, privateKey)`: creates signed trust attestation; `verifyAttestation(attestation, publicKey)`: verifies attestation signature; attestation includes: subject DID, issuer DID, trust level, timestamp, expiry, signature
- `/Users/efebarandurmaz/fides/packages/sdk/src/trust/client.ts` — `TrustClient` class: `attest(targetId, level)` — POST trust attestation; `getScore(agentId)` — GET reputation score; `getPath(from, to)` — GET trust path; configurable base URL
- `/Users/efebarandurmaz/fides/packages/sdk/test/trust.test.ts` — Tests: attestation creation/verification, client operations against mock

**Acceptance criteria:**
- Can create and verify trust attestations
- Attestation tampering is detected
- Client methods work against mock API

#### Task 2.5: SDK public API and high-level Fides class

**Files to modify:**
- `/Users/efebarandurmaz/fides/packages/sdk/src/index.ts` — Export the `Fides` class as the primary high-level API

**The `Fides` class provides:**
```typescript
const fides = new Fides({ discoveryUrl, trustUrl });
await fides.createIdentity();       // generates keys, registers with discovery
await fides.signRequest(request);   // signs an outgoing HTTP request
await fides.verifyRequest(request); // verifies an incoming signed request
await fides.trust(agentId, level);  // creates trust attestation
await fides.getReputation(agentId); // queries trust score
await fides.resolve(agentId);       // resolves agent identity
```

**Acceptance criteria:**
- High-level API wraps all lower-level modules
- Can be used with `import { Fides } from '@fides/sdk'`
- TypeScript types are fully exported

---

### PHASE 3: Discovery Service (TypeScript + Hono + PostgreSQL)

**Estimated effort: ~2 hours**

**Depends on: Phase 1 complete, Phase 2 types defined**

#### Task 3.1: Discovery service scaffolding

**Files to create:**
- `/Users/efebarandurmaz/fides/services/discovery/package.json` — `hono`, `@hono/node-server`, `drizzle-orm`, `drizzle-kit`, `postgres` (pg driver), vitest
- `/Users/efebarandurmaz/fides/services/discovery/tsconfig.json`
- `/Users/efebarandurmaz/fides/services/discovery/drizzle.config.ts` — Drizzle Kit config pointing to PostgreSQL
- `/Users/efebarandurmaz/fides/services/discovery/src/index.ts` — Hono app entry: creates app, registers routes, starts Node.js HTTP server via `@hono/node-server`
- `/Users/efebarandurmaz/fides/services/discovery/src/db/client.ts` — Drizzle PostgreSQL client (connects to same database as trust-graph, different schema/tables if needed)
- `/Users/efebarandurmaz/fides/services/discovery/src/db/schema.ts` — Drizzle schema: `identities` table (did TEXT PK, public_key TEXT, metadata JSONB, domain TEXT, created_at TIMESTAMP, updated_at TIMESTAMP)
- `/Users/efebarandurmaz/fides/services/discovery/src/types.ts` — Service-specific types

**Acceptance criteria:**
- `pnpm --filter discovery dev` starts local HTTP server
- Server responds to `GET /health` with 200

#### Task 3.2: Identity registration and resolution

**Files to create:**
- `/Users/efebarandurmaz/fides/services/discovery/src/routes/identities.ts` — `POST /identities`: validates identity payload (DID, public key, metadata); stores in PostgreSQL via Drizzle; returns 201; `GET /identities/:did`: returns identity document; 404 if not found; `GET /identities?domain=X`: lookup by domain
- `/Users/efebarandurmaz/fides/services/discovery/src/routes/well-known.ts` — `GET /.well-known/fides.json`: returns the discovery document for the agent hosted at this domain; includes public key, DID, endpoints, supported algorithms
- `/Users/efebarandurmaz/fides/services/discovery/src/routes/health.ts` — `GET /health`: returns `{ status: "ok", version: "0.1.0" }`

**Acceptance criteria:**
- Register identity via POST, retrieve via GET — round trip works
- `.well-known/fides.json` returns valid discovery document
- Invalid payloads return 400 with clear error messages
- Non-existent DIDs return 404

#### Task 3.3: Discovery service tests

**Files to create:**
- `/Users/efebarandurmaz/fides/services/discovery/test/routes.test.ts` — Integration tests using Hono's test client (app.request()): register identity, resolve identity, well-known endpoint, error cases, duplicate registration handling

**Acceptance criteria:**
- All tests pass with `pnpm --filter discovery test`

---

### PHASE 4: Trust Graph Service (TypeScript + Hono + Drizzle + PostgreSQL)

**Estimated effort: ~3-4 hours**

**Depends on: Phase 1 complete (docker-compose for PostgreSQL)**

#### Task 4.1: Trust graph service scaffolding

**Files to create:**
- `/Users/efebarandurmaz/fides/services/trust-graph/package.json` — `hono`, `@hono/node-server`, `drizzle-orm`, `drizzle-kit`, `postgres`, vitest; depends on `@fides/shared`
- `/Users/efebarandurmaz/fides/services/trust-graph/tsconfig.json`
- `/Users/efebarandurmaz/fides/services/trust-graph/drizzle.config.ts` — Drizzle Kit config
- `/Users/efebarandurmaz/fides/services/trust-graph/src/index.ts` — Hono app entry: creates app, registers routes, runs migrations, starts HTTP server
- `/Users/efebarandurmaz/fides/services/trust-graph/src/types.ts` — Service-specific types

**Acceptance criteria:**
- `pnpm --filter trust-graph dev` starts local HTTP server
- Server responds to `GET /health` with 200
- Server connects to PostgreSQL on startup

#### Task 4.2: PostgreSQL schema and migrations

**Files to create:**
- `/Users/efebarandurmaz/fides/services/trust-graph/src/db/schema.ts` — Drizzle schema matching the SQL below
- `/Users/efebarandurmaz/fides/services/trust-graph/src/db/client.ts` — Drizzle PostgreSQL client
- `/Users/efebarandurmaz/fides/services/trust-graph/src/db/migrations/001_initial.sql`:

```sql
-- Identities known to the trust graph
CREATE TABLE identities (
    did TEXT PRIMARY KEY,
    public_key BYTEA NOT NULL,
    metadata JSONB DEFAULT '{}',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trust edges between agents
CREATE TABLE trust_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_did TEXT NOT NULL REFERENCES identities(did),
    target_did TEXT NOT NULL REFERENCES identities(did),
    trust_level SMALLINT NOT NULL CHECK (trust_level BETWEEN 0 AND 100),
    attestation JSONB NOT NULL,          -- the signed attestation blob
    signature BYTEA NOT NULL,            -- Ed25519 signature
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE(source_did, target_did)       -- one active edge per pair
);

-- Key succession chain for rotation
CREATE TABLE key_history (
    did TEXT NOT NULL REFERENCES identities(did),
    public_key BYTEA NOT NULL,
    successor_key BYTEA,                 -- signed by this key
    succession_signature BYTEA,          -- proof that old key authorized new key
    active_from TIMESTAMPTZ NOT NULL,
    active_until TIMESTAMPTZ,
    PRIMARY KEY (did, public_key)
);

-- Materialized reputation scores (refreshed periodically)
CREATE TABLE reputation_scores (
    did TEXT PRIMARY KEY REFERENCES identities(did),
    score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    direct_trusters INT NOT NULL DEFAULT 0,
    transitive_trusters INT NOT NULL DEFAULT 0,
    last_computed TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_trust_edges_source ON trust_edges(source_did) WHERE revoked_at IS NULL;
CREATE INDEX idx_trust_edges_target ON trust_edges(target_did) WHERE revoked_at IS NULL;
CREATE INDEX idx_trust_edges_expires ON trust_edges(expires_at) WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
```

**Acceptance criteria:**
- Migrations run successfully against local PostgreSQL
- Drizzle schema matches SQL migration
- CRUD operations work for identities and trust edges
- Unique constraint prevents duplicate edges

#### Task 4.3: Trust graph traversal and scoring

**Files to create:**
- `/Users/efebarandurmaz/fides/services/trust-graph/src/services/graph.ts` — `findTrustPath(db, from, to, maxDepth)`: BFS traversal through trust edges; returns `TrustPath` with intermediate nodes and cumulative trust score; respects `MAX_TRUST_DEPTH = 6`; trust decays by `TRUST_DECAY = 0.85` per hop
- `/Users/efebarandurmaz/fides/services/trust-graph/src/services/scoring.ts` — `computeReputationScore(db, did)`: aggregates direct trust edges + transitive trust; weighted average with decay; normalizes to 0.0-1.0 range; `refreshAllScores(db)`: batch recomputation for materialized view
- `/Users/efebarandurmaz/fides/services/trust-graph/src/services/trust-service.ts` — `TrustService` class: orchestrates db + graph + scoring; `createTrust(attestation)`: validates attestation signature, stores edge, triggers score update; `getTrust(from, to)`: returns direct trust or transitive path; `getScore(did)`: returns reputation score

**Acceptance criteria:**
- BFS finds shortest trust path between agents
- Trust decays correctly over hops (hop 1: 1.0, hop 2: 0.85, hop 3: 0.7225, etc.)
- Reputation score aggregates correctly
- Cycles in trust graph don't cause infinite loops
- All graph logic is type-safe TypeScript sharing types from `@fides/shared`

#### Task 4.4: HTTP API routes

**Files to create:**
- `/Users/efebarandurmaz/fides/services/trust-graph/src/routes/trust.ts` — Hono routes: `POST /v1/trust`, `GET /v1/trust/:did/score`, `GET /v1/trust/:from/:to`
- `/Users/efebarandurmaz/fides/services/trust-graph/src/routes/identities.ts` — Hono routes: `GET /v1/identities/:did`
- `/Users/efebarandurmaz/fides/services/trust-graph/src/routes/health.ts` — `GET /health`
- `/Users/efebarandurmaz/fides/services/trust-graph/src/middleware/logger.ts` — Request logging middleware using Hono's built-in logger or custom structured logging

**Acceptance criteria:**
- All endpoints respond with correct HTTP status codes
- Invalid input returns 400 with descriptive error
- JSON responses match the `@fides/shared` TypeScript types exactly (no type drift — single language!)

#### Task 4.5: Trust graph tests

**Files to create:**
- `/Users/efebarandurmaz/fides/services/trust-graph/test/routes.test.ts` — HTTP route tests using Hono's test client
- `/Users/efebarandurmaz/fides/services/trust-graph/test/trust-service.test.ts` — Trust service unit tests
- `/Users/efebarandurmaz/fides/services/trust-graph/test/graph.test.ts` — Graph traversal tests: direct path, transitive path, no path, cycle handling, max depth, decay calculation

**Acceptance criteria:**
- All tests pass: `pnpm --filter trust-graph test`
- Graph traversal handles edge cases (cycles, disconnected nodes, expired edges)

---

### PHASE 5: CLI Tool

**Estimated effort: ~2 hours**

**Depends on: Phase 2 (SDK), Phase 3 (Discovery), Phase 4 (Trust API)**

#### Task 5.1: CLI scaffolding with Commander.js

**Files to create:**
- `/Users/efebarandurmaz/fides/packages/cli/package.json` — `@fides/cli`, depends on `@fides/sdk`, `commander`, `chalk`, `ora`
- `/Users/efebarandurmaz/fides/packages/cli/tsconfig.json`
- `/Users/efebarandurmaz/fides/packages/cli/src/index.ts` — Commander program setup, global options (--discovery-url, --trust-url, --key-dir)
- `/Users/efebarandurmaz/fides/packages/cli/src/utils/config.ts` — Config file management (`~/.fides/config.json`); stores: discovery URL, trust URL, active identity DID, key directory
- `/Users/efebarandurmaz/fides/packages/cli/src/utils/output.ts` — Pretty output helpers: success/error/info/table formatting

**Acceptance criteria:**
- `pnpm --filter @fides/cli build` succeeds
- Running the built CLI with `--help` prints usage information with program name, version, and list of available commands
- Running with `--version` prints the version from package.json
- Global options `--discovery-url`, `--trust-url`, `--key-dir` are parsed and passed to subcommands
- Config file is created at `~/.fides/config.json` on first use if it does not exist

#### Task 5.2: CLI commands

**Files to create:**
- `/Users/efebarandurmaz/fides/packages/cli/src/commands/init.ts` — `fides init`: generates Ed25519 keypair; creates DID; stores keys in `~/.fides/keys/`; registers with discovery service; prints DID and public key
- `/Users/efebarandurmaz/fides/packages/cli/src/commands/sign.ts` — `fides sign <url> [--method GET] [--body '{}']`: signs an HTTP request; prints curl command with signature headers
- `/Users/efebarandurmaz/fides/packages/cli/src/commands/verify.ts` — `fides verify <url> --signature <sig> --signature-input <input>`: verifies a signed request; prints verification result
- `/Users/efebarandurmaz/fides/packages/cli/src/commands/trust.ts` — `fides trust <agent-did> [--level high]`: creates and submits trust attestation; prints attestation details
- `/Users/efebarandurmaz/fides/packages/cli/src/commands/discover.ts` — `fides discover <agent-did-or-domain>`: resolves agent identity; prints public key, endpoints, trust score
- `/Users/efebarandurmaz/fides/packages/cli/src/commands/status.ts` — `fides status`: shows current identity, key info, trust connections

**Acceptance criteria:**
- `fides init` creates identity and registers it
- `fides sign` produces valid RFC 9421 signatures
- `fides verify` correctly validates signatures
- `fides trust` creates signed attestations
- `fides discover` resolves identities
- All commands have `--help` with clear descriptions

#### Task 5.3: CLI tests

**Files to create:**
- `/Users/efebarandurmaz/fides/packages/cli/test/commands.test.ts` — Test each command in isolation with mocked services

**Acceptance criteria:**
- All CLI tests pass

---

### PHASE 6: Integration Tests and Documentation

**Estimated effort: ~2-3 hours**

**Depends on: All previous phases**

#### Task 6.1: End-to-end integration test

**Files to create:**
- `/Users/efebarandurmaz/fides/tests/e2e/package.json` — Test dependencies: vitest, @fides/sdk
- `/Users/efebarandurmaz/fides/tests/e2e/setup.ts` — Start local services (discovery Hono server, trust-graph Hono server, PostgreSQL via docker-compose); tear down after tests
- `/Users/efebarandurmaz/fides/tests/e2e/full-flow.test.ts`:

```
Test: "Two agents complete full authentication and trust flow"

1. Agent A creates identity (keypair + DID)
2. Agent A registers with discovery service
3. Agent B creates identity
4. Agent B registers with discovery service
5. Agent B resolves Agent A via discovery
6. Agent A signs an HTTP request
7. Agent B verifies Agent A's signature using discovered public key
8. Agent A creates trust attestation for Agent B (level: high)
9. Agent B queries their reputation score
10. Agent C creates identity and trusts Agent A
11. Query transitive trust: C -> A -> B (should find path with decay)
```

**Acceptance criteria:**
- Full flow completes without errors
- Signature verification succeeds for valid signatures
- Signature verification fails for tampered requests
- Trust path is found transitively with correct decay
- All services are TypeScript — single `pnpm test` runs everything

#### Task 6.2: Documentation

**Files to create:**
- `/Users/efebarandurmaz/fides/docs/architecture.md` — System architecture overview with diagrams (ASCII)
- `/Users/efebarandurmaz/fides/docs/protocol-spec.md` — Protocol specification: identity format (including `did:fides` deviations from W3C DID Core), signing algorithm, trust attestation format, discovery protocol, replay protection via timestamp expiry (and deferred nonce strategy)
- `/Users/efebarandurmaz/fides/docs/getting-started.md` — Quick start guide: install, create identity, sign first request

**Acceptance criteria:**
- Docs accurately describe the implemented system
- Getting started guide is followable by a developer
- Protocol spec documents `did:fides` format and its relationship to W3C DID Core
- Protocol spec documents replay protection approach and limitations

#### Task 6.3: CI configuration

**Files to create:**
- `/Users/efebarandurmaz/fides/.github/workflows/ci.yml` — GitHub Actions: lint + typecheck + test for all TypeScript packages (SDK, CLI, discovery, trust-graph); E2E tests with Docker Compose PostgreSQL service

**Acceptance criteria:**
- CI would pass on push (can verify structure but not run remotely)
- Single-language pipeline — no Go build step needed

---

### PHASE 7: Stubs and Placeholders

**Estimated effort: ~30 minutes**

**Can be done in parallel with other phases.**

#### Task 7.1: Stub remaining services and root README

**Files to create:**
- `/Users/efebarandurmaz/fides/services/policy-engine/README.md` — Description of future Python policy engine
- `/Users/efebarandurmaz/fides/services/policy-engine/stub/policies.json` — Example policies in JSON format showing what NL parsing would produce
- `/Users/efebarandurmaz/fides/services/platform-api/README.md` — Description of future tRPC platform API
- `/Users/efebarandurmaz/fides/apps/web/README.md` — Description of future Next.js dashboard
- `/Users/efebarandurmaz/fides/packages/rust-sdk/README.md` — Description of future Rust SDK

**Acceptance criteria:**
- Each stub README contains: (1) component name and purpose (1-2 sentences), (2) planned tech stack, (3) planned MVP features (bullet list), (4) status: "Not yet implemented — placeholder for future development"
- Root README (`/Users/efebarandurmaz/fides/README.md`) must contain at minimum:
  - Project name and one-line description
  - "Why FIDES" section (3-4 sentences on the problem it solves)
  - Prerequisites (Node.js, pnpm, Docker)
  - Quick start instructions (`pnpm install`, `docker compose up -d`, `pnpm dev`)
  - Monorepo structure overview (packages, services, apps)
  - Link to `docs/getting-started.md` for detailed guide
  - License placeholder

---

## 6. Dependency Graph

```
Phase 1: Monorepo Scaffolding
    ├── Phase 2: Identity Layer (SDK)
    │       ├── Phase 5: CLI Tool ──────────────┐
    │       └── Phase 3: Discovery Service (TS) │
    │               └── Phase 6: E2E Tests ◄────┤
    ├── Phase 4: Trust Graph (TS + Drizzle) ────┘
    └── Phase 7: Stubs (parallel)
```

**Critical path:** Phase 1 -> Phase 2 -> Phase 3 + Phase 4 (parallel) -> Phase 5 -> Phase 6

**Parallelizable:**
- Phase 3 (Discovery) and Phase 4 (Trust Graph) can be built in parallel after Phase 2 types are defined
- Phase 7 (Stubs) can be done at any time

**Total estimated effort: ~12-15 hours**

---

## 7. Commit Strategy

| Commit | Content | Phase |
|--------|---------|-------|
| `feat: initialize monorepo with pnpm workspaces and turborepo` | Phase 1.1, 1.2, 1.3 | 1 |
| `feat(sdk): implement Ed25519 identity layer with DID generation` | Phase 2.1 | 2 |
| `feat(sdk): implement RFC 9421 HTTP message signatures` | Phase 2.2 | 2 |
| `feat(sdk): add discovery and trust clients` | Phase 2.3, 2.4, 2.5 | 2 |
| `feat(discovery): implement Hono discovery service with PostgreSQL` | Phase 3.1, 3.2, 3.3 | 3 |
| `feat(trust-graph): implement TypeScript trust graph service with Drizzle + PostgreSQL` | Phase 4.1-4.5 | 4 |
| `feat(cli): implement FIDES CLI tool` | Phase 5.1-5.3 | 5 |
| `test: add E2E integration tests` | Phase 6.1 | 6 |
| `docs: add architecture, protocol spec, and getting started guide` | Phase 6.2, 6.3, 7.1 | 6/7 |

---

## 8. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| RFC 9421 implementation complexity | High | High | Evaluate `node-http-message-signatures` first (production-tested in Misskey/ActivityPub). Fall back to manual implementation using RFC Appendix B test vectors. Start with minimal component set (`@method`, `@target-uri`, `content-digest`). |
| `@noble/ed25519` compatibility edge cases | Low | Medium | Already pure JS, no native deps. Well-tested in production. Fallback: `tweetnacl`. |
| PostgreSQL recursive CTE performance for deep trust traversal | Medium | Medium | Limit depth to 6 hops. Materialize reputation scores. Index trust edges. Can add Neo4j later if needed. |
| Drizzle ORM learning curve | Low | Low | Well-documented, type-safe. Team can fall back to raw SQL via `drizzle-orm/sql` if needed. |
| Key rotation complexity | Medium | Medium | MVP: simple key succession. Key history table tracks chain. Full rotation protocol in v2. |
| Scope creep into policy/gateway layers | High | High | Hard boundary: these are stubs only. README files explain future plans. No implementation. |
| Replay attacks via signature reuse | Medium | Medium | MVP uses RFC 9421 `created`/`expires` timestamps (300s window). Full nonce tracking deferred to v2 with documented justification. |

---

## 9. Technical Decisions

| Decision | Choice | Alternatives Considered |
|----------|--------|------------------------|
| All services language | **TypeScript** | Go for trust-graph (rejected: multi-language MVP complexity), Rust (rejected: overkill for MVP) |
| HTTP framework (services) | **Hono** | Express (heavier), Fastify (more complex), Koa (less ecosystem) |
| ORM | **Drizzle ORM** | Prisma (heavier, code generation), Knex (less type-safe), raw SQL (less maintainable) |
| Database | **PostgreSQL** (single instance for both services) | SQLite (not suitable for concurrent services), MongoDB (wrong model for graph data) |
| Crypto library | `@noble/ed25519` + `@noble/hashes` | `tweetnacl` (less maintained), Node crypto (less portable) |
| DID method | `did:fides:<base58(pubkey)>` (custom, W3C-inspired) | `did:key` (more standard but less readable), `did:web` (requires domain) |
| RFC 9421 | Evaluate `node-http-message-signatures`, fall back to manual | Pure manual implementation (higher risk), `http-signature` npm (draft spec, not RFC 9421) |
| Test framework (TS) | `vitest` | `jest` (slower, worse ESM support) |
| Monorepo tool | `turborepo` | `nx` (heavier), `lerna` (deprecated) |
| Trust scoring | Weighted BFS with exponential decay | PageRank (too complex for MVP), simple average (too naive) |

---

## 10. Guardrails

### MUST Have
- All cryptographic operations use audited libraries (noble suite)
- Private keys never leave the local keystore (never sent over network)
- Private keys encrypted at rest with AES-256-GCM (PBKDF2, 600k iterations) when passphrase set
- Key files have `0600` permissions on Unix systems
- All trust attestations are cryptographically signed
- All HTTP signatures follow RFC 9421 with `created`/`expires` timestamps
- Type safety across the entire TypeScript codebase (strict mode)
- Tests for every public API method
- Single language (TypeScript) for all packages and services

### MUST NOT Have
- No blockchain integration in MVP
- No LLM/AI calls in MVP (policy engine is stubbed)
- No payment/billing integration
- No Cloudflare Workers / Wrangler / KV (standard Node.js HTTP servers only)
- No Redis (PostgreSQL handles all persistence)
- No Go code (TypeScript only)
- No breaking changes to the type interfaces once defined (they are the contract)
- No storing private keys in any service (keys stay client-side)

---

## 11. Success Criteria

The MVP is successful when:

1. **Identity**: An agent can generate an Ed25519 identity and register it with the discovery service in under 1 second
2. **Signing**: An agent can sign and verify HTTP requests per RFC 9421, with tests proving tamper detection and expired signature rejection
3. **Discovery**: An agent can discover another agent's public key via the discovery service (PostgreSQL-backed, not KV)
4. **Trust**: An agent can create trust attestations, and transitive trust paths are computable across up to 6 hops
5. **CLI**: A developer can run `fides init && fides trust <did>` from the command line
6. **E2E**: The full flow (identity -> discovery -> signing -> verification -> trust) passes in an automated test
7. **Developer Experience**: A new developer can clone the repo, run `pnpm install && docker compose up -d && pnpm dev`, and have everything working within 5 minutes
8. **Single Language**: The entire codebase is TypeScript — one `pnpm test` from root runs all tests across all packages and services
