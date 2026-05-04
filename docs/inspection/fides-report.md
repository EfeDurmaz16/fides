# FIDES Repository Inspection Report

## 1. Repo Purpose

**FIDES** (Latin: trust, faith, confidence) is a decentralized trust and authentication protocol for autonomous AI agents. It provides:

- Cryptographic identity management (Ed25519 keypairs + custom DIDs)
- RFC 9421 HTTP Message Signatures for request authentication
- Distributed trust attestations and reputation scoring
- Agent discovery with A2A (Agent-to-Agent) protocol compatibility

**Tech stack:** TypeScript/Node.js monorepo (pnpm + Turbo), Hono web framework, Drizzle ORM, PostgreSQL, @noble/ed25519 for pure-JS cryptography.

---

## 2. Main Packages / Modules

### Packages (`/Users/efebarandurmaz/fides/packages/`)

| Package | Path | Purpose |
|---------|------|---------|
| `@fides/sdk` | `packages/sdk/` | Core protocol implementation (identity, signing, trust, discovery) |
| `@fides/shared` | `packages/shared/` | Shared types, constants, errors |
| `@fides/cli` | `packages/cli/` | Command-line interface (`fides init`, `sign`, `verify`, `trust`, `discover`, `status`) |
| `rust-sdk` | `packages/rust-sdk/` | Stub — only contains README.md |

### Services (`/Users/efebarandurmaz/fides/services/`)

| Service | Path | Purpose |
|---------|------|---------|
| `discovery` | `services/discovery/` | Identity registration & resolution service (Hono + PostgreSQL) |
| `trust-graph` | `services/trust-graph/` | Trust relationship management & reputation scoring service |
| `platform-api` | `services/platform-api/` | Stub — only README.md |
| `policy-engine` | `services/policy-engine/` | Stub — README.md + `stub/policies.json` |

### Apps (`/Users/efebarandurmaz/fides/apps/`)

| App | Path | Purpose |
|-----|------|---------|
| `web` | `apps/web/` | Stub — only README.md |

---

## 3. Existing Primitives with Exact File Paths

### Identity Layer

| Primitive | File Path |
|-----------|-----------|
| Ed25519 keypair generation | `packages/sdk/src/identity/keypair.ts` |
| DID creation / parsing / validation (`did:fides:<base58-pubkey>`) | `packages/sdk/src/identity/did.ts` |
| In-memory keystore | `packages/sdk/src/identity/keystore.ts` (class `MemoryKeyStore`) |
| File-based encrypted keystore (AES-256-GCM + PBKDF2) | `packages/sdk/src/identity/keystore.ts` (class `FileKeyStore`) |
| Key rotation | `packages/sdk/src/identity/rotation.ts` |
| Revocation record | `packages/sdk/src/identity/rotation.ts` (`createRevocation`) |

### Signing Layer (RFC 9421 HTTP Message Signatures)

| Primitive | File Path |
|-----------|-----------|
| Request canonicalization & signature base creation | `packages/sdk/src/signing/canonicalize.ts` |
| HTTP request signing | `packages/sdk/src/signing/http-signature.ts` |
| HTTP request verification (with nonce replay protection, Content-Digest check) | `packages/sdk/src/signing/verify.ts` |
| In-memory nonce store | `packages/sdk/src/signing/nonce-store.ts` |

### Trust Layer

| Primitive | File Path |
|-----------|-----------|
| Trust attestation creation & verification | `packages/sdk/src/trust/attestation.ts` |
| Trust levels enum | `packages/sdk/src/trust/types.ts` (`TrustLevel.NONE/LOW/MEDIUM/HIGH/ABSOLUTE`) |
| Trust client (HTTP client to trust-graph service) | `packages/sdk/src/trust/client.ts` |

### Discovery Layer

| Primitive | File Path |
|-----------|-----------|
| Discovery client (register/resolve identities) | `packages/sdk/src/discovery/client.ts` |
| Identity resolver (with caching, well-known fallback) | `packages/sdk/src/discovery/resolver.ts` |
| Agent discovery client (register agents, capabilities, heartbeat) | `packages/sdk/src/discovery/agent-client.ts` |
| A2A protocol compatibility converters | `packages/sdk/src/discovery/a2a.ts` |

### Security & Observability

| Primitive | File Path |
|-----------|-----------|
| Sliding-window rate limiter | `packages/sdk/src/security/rate-limiter.ts` |
| Rate-limit middleware | `packages/sdk/src/security/rate-limit-middleware.ts` |
| Content validator | `packages/sdk/src/security/content-validator.ts` |
| Content-validation middleware | `packages/sdk/src/security/content-validation-middleware.ts` |
| Prometheus metrics collector | `packages/sdk/src/observability/metrics.ts` |
| Metrics middleware | `packages/sdk/src/observability/metrics-middleware.ts` |

### Integrations

| Primitive | File Path |
|-----------|-----------|
| agit (AgentGit) commit signer | `packages/sdk/src/integrations/agit.ts` (`AgitCommitSigner`) |
| agit trust-gated access controller | `packages/sdk/src/integrations/agit.ts` (`TrustGatedAccess`) |

### Services (Server-side)

| Primitive | File Path |
|-----------|-----------|
| Discovery service entrypoint | `services/discovery/src/index.ts` |
| Discovery DB schema (identities, agents) | `services/discovery/src/db/schema.ts` |
| Identity routes (`POST /identities`, `GET /identities/:did`) | `services/discovery/src/routes/identities.ts` |
| Agent routes (`/agents`, heartbeat, deregister) | `services/discovery/src/routes/agents.ts` |
| Well-known routes (`/.well-known/fides.json`, `/.well-known/agent.json`) | `services/discovery/src/routes/well-known.ts` |
| Trust-graph service entrypoint | `services/trust-graph/src/index.ts` |
| Trust-graph DB schema (identities, trust_edges, key_history, reputation_scores) | `services/trust-graph/src/db/schema.ts` |
| Trust service (create trust, get score, get path) | `services/trust-graph/src/services/trust-service.ts` |
| BFS trust graph traversal | `services/trust-graph/src/services/graph.ts` |
| Reputation scoring algorithm | `services/trust-graph/src/services/scoring.ts` |
| Graph edge utilities (filter, forward/reverse index) | `services/trust-graph/src/services/edge-utils.ts` |
| Trust routes (`POST /v1/trust`, `GET /v1/trust/:did/score`, `GET /v1/trust/:from/:to`) | `services/trust-graph/src/routes/trust.ts` |

### Shared Types & Constants

| Primitive | File Path |
|-----------|-----------|
| All shared types (AgentIdentity, TrustAttestation, TrustScore, AgentCard, etc.) | `packages/shared/src/types.ts` |
| Protocol constants (ALGORITHM, DEFAULT_TRUST_DECAY, MAX_TRUST_DEPTH, etc.) | `packages/shared/src/constants.ts` |
| Error hierarchy (FidesError, SignatureError, DiscoveryError, TrustError, KeyError) | `packages/shared/src/errors.ts` |

### CLI

| Command | File Path |
|---------|-----------|
| CLI entrypoint | `packages/cli/src/index.ts` |
| `fides init` | `packages/cli/src/commands/init.ts` |
| `fides sign` | `packages/cli/src/commands/sign.ts` |
| `fides verify` | `packages/cli/src/commands/verify.ts` |
| `fides trust` | `packages/cli/src/commands/trust.ts` |
| `fides discover` | `packages/cli/src/commands/discover.ts` |
| `fides status` | `packages/cli/src/commands/status.ts` |

---

## 4. Key Term Search Results

| Term | Status | Notes |
|------|--------|-------|
| **identity** | FOUND | Extensively implemented across SDK and services |
| **agent** | FOUND | Core concept; AgentCard, AgentDiscoveryClient, etc. |
| **did** | FOUND | Custom `did:fides:<base58-pubkey>` format |
| **signature** | FOUND | RFC 9421 HTTP Message Signatures + attestation signatures |
| **ed25519** | FOUND | Exclusive algorithm via `@noble/ed25519` |
| **attestation** | FOUND | Signed trust attestations with payload verification |
| **trust** | FOUND | Central primitive; trust edges, levels, graph, scoring |
| **reputation** | FOUND | Reputation scoring with direct + transitive trust |
| **graph** | FOUND | BFS traversal on trust edges with decay |
| **discovery** | FOUND | Discovery service + well-known fallback |
| **registry** | NOT FOUND | Only mentioned in docs as future "on-chain revocation registry" |
| **capability** | FOUND | Agent skills/capabilities in discovery (A2A-compatible) |
| **policy** | PARTIAL | Stubbed policy-engine service exists; no runtime policy enforcement |
| **delegation** | NOT FOUND | Only mentioned in docs as future feature |
| **session** | NOT FOUND | Only `.omc/sessions/` metadata files (unrelated) |
| **grant** | NOT FOUND | Only appears in MIT license text |
| **evidence** | NOT FOUND | No occurrences |
| **event** | NOT FOUND | No event system |
| **ledger** | NOT FOUND | No occurrences |
| **hash** | FOUND | SHA-256 for Content-Digest and agit state hashing |
| **merkle** | NOT FOUND | Only mentioned in `.omc/plans/` as future consideration |
| **revocation** | PARTIAL | `createRevocation` exists in rotation.ts but no active revocation mechanism |
| **incident** | NOT FOUND | No occurrences |
| **runtime** | FOUND | Docker build stages labeled "runtime" |
| **tee** | NOT FOUND | No trusted execution environment support |
| **dht** | NOT FOUND | No distributed hash table |
| **relay** | NOT FOUND | No relay infrastructure |
| **federation** | NOT FOUND | No federation logic |
| **well-known** | FOUND | `/.well-known/fides.json` and `/.well-known/agent.json` supported |

---

## 5. What Is Reusable

### Highly Reusable Components

1. **Identity Primitives** (`packages/sdk/src/identity/`)
   - `generateKeyPair`, `generateDID`, `parseDID`, `isValidDID` — pure functions, zero service dependency
   - `MemoryKeyStore` / `FileKeyStore` — pluggable interface for any key storage need

2. **RFC 9421 Signing Stack** (`packages/sdk/src/signing/`)
   - `signRequest`, `verifyRequest`, `createSignatureBase`, `parseSignatureInput` — can be reused for any HTTP signing use case
   - Includes Content-Digest (body integrity) and nonce replay protection

3. **Trust Attestation Primitives** (`packages/sdk/src/trust/attestation.ts`)
   - `createAttestation`, `verifyAttestation` — self-contained signing/verification of JSON payloads

4. **Rate Limiter** (`packages/sdk/src/security/rate-limiter.ts`)
   - Pure in-memory sliding-window rate limiter; framework-agnostic

5. **Metrics Collector** (`packages/sdk/src/observability/metrics.ts`)
   - Zero-dependency Prometheus exposition format collector

6. **Graph Algorithms** (`services/trust-graph/src/services/graph.ts`, `scoring.ts`, `edge-utils.ts`)
   - Pure functions for BFS trust path finding and reputation scoring; no DB dependency at the algorithm layer

7. **A2A Converters** (`packages/sdk/src/discovery/a2a.ts`)
   - Bidirectional conversion between FIDES AgentCard and Google A2A Agent Card format

8. **Shared Types & Constants** (`packages/shared/`)
   - TypeScript interfaces and error classes used across all packages

---

## 6. What Is Missing

### Protocol / Cryptographic Gaps

- **Registry**: No decentralized registry implementation. Discovery is centralized PostgreSQL.
- **Delegation**: No delegation primitives (no delegated signing, no proxy attestations).
- **Session Management**: No session tokens, no grant mechanism, no OAuth/OIDC bridge.
- **Evidence / Proofs**: No verifiable credentials, no zero-knowledge proofs, no structured evidence collection.
- **Ledger / Merkle Trees**: No immutable log or Merkle anchoring of attestations.
- **Revocation**: `createRevocation` exists as a data structure but there is no active revocation service, CRL, or on-chain registry.
- **Incident Response**: No incident logging, reporting, or automated response system.
- **TEE Support**: No trusted execution environment integration.
- **DHT / P2P Discovery**: Discovery relies on centralized HTTP service; no distributed resolution.
- **Relay / Federation**: No cross-domain federation protocol; services are standalone.

### Service Gaps

- **Policy Engine**: Stubbed only (`services/policy-engine/README.md` describes future LLM-backed engine; `services/policy-engine/stub/policies.json` is a static JSON example).
- **Platform API**: Stubbed only.
- **Web Dashboard**: Stubbed only (`apps/web/README.md` describes future UI).
- **Rust SDK**: Only README exists.

### Operational / Security Gaps (Acknowledged in Docs)

- No nonce tracking on the server side (client SDK has `NonceStore`, but services do not enforce it).
- No key recovery mechanism.
- No HSM support.
- No rate limiting on trust attestations at the protocol level.
- No negative trust attestations.
- No time-based reputation decay (trust edges do not age).
- Sybil attack vulnerability acknowledged in scoring algorithm.

---

## 7. Conflicts Noticed

1. **Repository URL Mismatch**
   - Root `package.json` and `@fides/sdk/package.json` list `"url": "https://github.com/anthropic-ai/fides"`
   - README badge and contributing section list `https://github.com/EfeDurmaz16/fides`
   - **Conflict**: Two different GitHub organizations claimed.

2. **DID Method vs. W3C Compliance**
   - The README and architecture docs state DID format is `did:fides:<base58-pubkey>` and explicitly note it is **not W3C DID Core compliant**.
   - The protocol spec says it is "inspired by but not compliant with" W3C DID Core.
   - **Conflict**: If interoperability with broader DID ecosystems is a goal, this simplified format will break compatibility.

3. **Trust Decay Formula Discrepancy**
   - `docs/protocol-spec.md` describes reputation aggregation as: `sum(direct) * 1.0 + sum(transitive_depth_2) * 0.5 + sum(depth_3_to_6) * 0.25` divided by total paths.
   - The actual implementation in `services/trust-graph/src/services/scoring.ts` uses: `combinedScore = (directScore * 0.7) + (min(transitiveScore, 1.0) * 0.3)` with BFS capped at 3 hops for transitive scoring.
   - **Conflict**: Spec and implementation do not match in algorithm or max depth.

4. **Nonce Replay Protection Claim**
   - `docs/architecture.md` and `docs/protocol-spec.md` state "No nonce tracking in MVP (deferred to v2)".
   - However, `packages/sdk/src/signing/http-signature.ts` generates a nonce, and `packages/sdk/src/signing/verify.ts` checks it against a `NonceStore`.
   - **Conflict**: Docs say it's missing, but client SDK partially implements it. Server services do not appear to enforce nonce checking.

5. **Package Name Inconsistency**
   - Root `package.json`: `"name": "fides"`
   - SDK `package.json`: `"name": "@fides/sdk"`
   - CLI `package.json`: `"name": "@fides/cli"`
   - Discovery service `package.json`: `"name": "discovery"` (not `@fides/discovery`)
   - Trust-graph service `package.json`: `"name": "trust-graph"` (not `@fides/trust-graph`)
   - **Conflict**: Services are not namespaced under `@fides/`, making them prone to naming collisions if published.

6. **Key Rotation DID Change**
   - `rotateKey` in `packages/sdk/src/identity/rotation.ts` generates a **new keypair and therefore a new DID**.
   - This is technically key replacement rather than rotation, because the DID changes. The protocol spec and architecture docs mention "key rotation and revocation" as a future v2 feature.
   - **Conflict**: The current `rotateKey` breaks all existing trust edges since the DID changes, which is not how DID key rotation typically works.

---

## 8. Recommended Action for FIDES v2

1. **Keep FIDES as the main repo** — it has the most complete runtime (services, SDK, CLI, tests, CI).
2. **Preserve identity and signing primitives** — they are solid foundations.
3. **Fix spec/implementation discrepancies** before building on top (trust decay formula, nonce protection, DID rotation).
4. **Add missing layers**: delegation, session, evidence, policy, runtime attestation, DHT/relay, federation.
5. **Evolve service names** to `@fides/discovery`, `@fides/trust-graph`, etc. for consistency.
6. **Normalize DID rotation** to use the same DID with a new key, or document why FIDES uses DID-changing replacement.
