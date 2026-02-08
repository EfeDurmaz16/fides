# FIDES Architecture

## System Overview

FIDES is a decentralized trust and authentication protocol for autonomous AI agents. It provides cryptographic identity management, HTTP message signing, distributed trust attestations, and reputation scoring to enable secure agent-to-agent interactions.

The system consists of:
- TypeScript SDK with Ed25519 identity and RFC 9421 HTTP message signatures
- Command-line interface for agent operations
- Discovery service for identity registration and resolution
- Trust graph service for managing trust relationships and computing reputation scores

## Architecture Diagram

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  @fides/cli │────▶│   @fides/sdk    │────▶│  @fides/shared   │
└─────────────┘     └────────┬────────┘     └──────────────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
          ┌─────────────┐   ┌──────────────┐
          │  Discovery   │   │ Trust Graph  │
          │   Service    │   │   Service    │
          └──────┬───────┘   └──────┬───────┘
                 │                   │
                 └───────┬───────────┘
                         ▼
                    ┌──────────┐
                    │PostgreSQL│
                    └──────────┘
```

## Components

### @fides/shared
Shared types, error classes, and constants used across all packages.

**Key exports:**
- `Identity` type: DID, public key, metadata
- `TrustAttestation` type: Trust statement schema
- `FidesError` hierarchy: Base error classes
- Constants: Default trust levels, signature parameters

**Dependencies:** None (pure types and constants)

### @fides/sdk
Core library providing the complete FIDES protocol implementation.

**Key modules:**
- **Identity**: Ed25519 keypair generation, DID creation (`did:fides:<base58-pubkey>`), secure key storage with AES-256-GCM encryption
- **Signing**: RFC 9421 HTTP Message Signatures with ed25519 algorithm
- **Discovery Client**: Identity registration and resolution against discovery service
- **Trust Client**: Trust attestation creation, verification, and retrieval
- **Fides Class**: High-level API combining all capabilities

**Dependencies:**
- `@noble/ed25519` (cryptography)
- `@fides/shared` (types)

### @fides/cli
Command-line interface for FIDES operations.

**Commands:**
- `fides init`: Create new agent identity
- `fides sign`: Sign HTTP requests
- `fides verify`: Verify signed requests
- `fides trust`: Issue trust attestations
- `fides discover`: Resolve identities and check reputation
- `fides status`: Show local agent status

**Dependencies:**
- `commander` (CLI framework)
- `chalk` (terminal colors)
- `ora` (spinners)
- `@fides/sdk` (protocol implementation)

### Discovery Service
Identity registration and resolution service using Hono and PostgreSQL.

**Endpoints:**
- `POST /identities`: Register new identity
- `GET /identities/:did`: Resolve identity
- `GET /.well-known/fides.json`: Well-known identity document

**Database schema:**
- `identities` table: did (PK), public_key, metadata, created_at, updated_at

**Features:**
- DID-based identity lookup
- Metadata storage (name, description, endpoints)
- `.well-known` protocol support for decentralized resolution

**Dependencies:** Hono, Drizzle ORM, PostgreSQL

### Trust Graph Service
Trust relationship management and reputation scoring service.

**Endpoints:**
- `POST /trust`: Create trust attestation
- `GET /trust/:did`: Get trust attestations for a DID
- `POST /trust/verify`: Verify trust attestation signature
- `GET /reputation/:did`: Compute reputation score

**Database schema:**
- `trust_attestations` table: id (PK), issuer_did, subject_did, trust_level, issued_at, expires_at, signature, payload

**Features:**
- BFS graph traversal for trust path finding
- Exponential decay: 0.85 per hop, max depth 6
- Reputation aggregation from direct and transitive trust
- Trust attestation verification

**Dependencies:** Hono, Drizzle ORM, PostgreSQL

## Data Flow

### Identity Creation
1. Agent runs `fides init --name "My Agent"`
2. SDK generates Ed25519 keypair
3. SDK creates DID from public key: `did:fides:<base58(pubkey)>`
4. SDK encrypts private key with AES-256-GCM (user password)
5. SDK stores encrypted key locally
6. SDK registers identity with discovery service
7. Discovery service stores DID + metadata in PostgreSQL

### Signed HTTP Request
1. Agent prepares HTTP request (method, URL, headers, body)
2. SDK creates signature base string per RFC 9421
3. SDK signs with Ed25519 private key
4. SDK adds `Signature-Input` and `Signature` headers
5. Recipient receives request
6. Recipient extracts DID from `keyid` parameter
7. Recipient resolves DID via discovery service
8. Recipient verifies signature with public key
9. Recipient checks timestamp replay protection

### Trust Attestation
1. Issuer agent trusts subject agent
2. SDK creates trust attestation payload (issuer DID, subject DID, trust level, timestamps)
3. SDK signs payload with issuer's private key
4. SDK sends attestation to trust graph service
5. Trust graph service verifies signature
6. Trust graph service stores attestation in PostgreSQL
7. Subject can query attestations for their DID

### Reputation Scoring
1. Agent queries reputation for target DID
2. Trust graph service performs BFS from query DID
3. For each hop: trust_score *= 0.85 (exponential decay)
4. Maximum depth: 6 hops
5. Aggregate direct trust (depth 1) and transitive trust (depth 2-6)
6. Return reputation score + trust paths

## Key Design Decisions

### TypeScript-Only for MVP
- **Decision**: Use TypeScript for all components (no Go, no Rust)
- **Rationale**: Faster development, unified tooling, strong ecosystem
- **Trade-offs**: Performance vs. velocity (optimize later if needed)

### Ed25519 via @noble/ed25519
- **Decision**: Use @noble/ed25519 library for cryptography
- **Rationale**: Audited, pure JavaScript, no native dependencies
- **Trade-offs**: Slightly slower than native code, but secure and portable

### RFC 9421 HTTP Message Signatures
- **Decision**: Implement RFC 9421 for request authentication
- **Rationale**: Modern, standardized, flexible signing framework
- **Signed Components**: `@method`, `@target-uri`, `@authority`, `content-type`
- **Trade-offs**: More complex than custom JWT, but interoperable

### BFS Trust Traversal with Exponential Decay
- **Decision**: 0.85 decay per hop, max depth 6
- **Rationale**: Balance between trust propagation and limiting spam
- **Trade-offs**: Tunable parameters (may need adjustment based on usage)

### PostgreSQL as Single Database
- **Decision**: Use PostgreSQL for both discovery and trust graph services
- **Rationale**: Simple deployment, ACID guarantees, good graph query support
- **Trade-offs**: Not specialized graph DB, but sufficient for MVP scale

### Hono Framework
- **Decision**: Use Hono for HTTP services instead of Express/Fastify
- **Rationale**: Lightweight, TypeScript-first, edge-ready
- **Trade-offs**: Smaller ecosystem than Express, but modern and fast

### DID Format Simplification
- **Decision**: `did:fides:<base58-pubkey>` (not W3C DID Core compliant)
- **Rationale**: Simplified for AI agents, avoid DID document complexity
- **Trade-offs**: Not interoperable with W3C DID ecosystem, but easier to implement

### AES-256-GCM Key Storage
- **Decision**: Encrypt private keys with AES-256-GCM using PBKDF2-derived keys
- **Rationale**: Strong encryption, password-based protection
- **Parameters**: PBKDF2 with SHA-256, 600k iterations
- **Trade-offs**: User must remember password (no recovery mechanism in MVP)

## Security Considerations

### Replay Protection
- HTTP signatures include `created` and `expires` timestamps
- 300-second validity window
- **Limitation**: No nonce tracking in MVP (deferred to v2)

### Clock Drift
- **Limitation**: No clock drift tolerance in MVP
- Services reject signatures with invalid timestamps
- Agents must have synchronized clocks

### Key Management
- Private keys stored encrypted on disk
- No key rotation in MVP (deferred to v2)
- No HSM support in MVP

### Trust Spam
- No rate limiting on trust attestations in MVP
- Exponential decay limits impact of distant trust
- **Future**: Add reputation-weighted trust scoring

## Deployment Architecture

### Development
```
docker compose up -d          # PostgreSQL
pnpm dev                      # All services in parallel
```

### Production (Future)
- Containerize services with Docker
- Deploy to Kubernetes or cloud platform
- Separate PostgreSQL instances per service
- API gateway for rate limiting and authentication
- Horizontal scaling for discovery and trust graph services

## Performance Characteristics

### Identity Resolution
- O(1) database lookup by DID
- Caching via `.well-known` for self-hosted identities

### Trust Graph Traversal
- BFS: O(V + E) where V = vertices (agents), E = edges (trust attestations)
- Depth limit (6) bounds complexity
- Database indexes on issuer_did and subject_did

### Signature Verification
- O(1) cryptographic verification
- Ed25519 ~50k verifications/sec on modern CPU

## Future Extensions

### Planned
- Rust SDK for performance-critical agents
- Policy engine for automated trust decisions
- Platform API for multi-agent coordination
- Web dashboard for trust graph visualization
- Key rotation and revocation
- Nonce-based replay protection
- WebAuthn integration for human agents

### Under Consideration
- Zero-knowledge proofs for private trust attestations
- Threshold signatures for multi-agent identities
- Cross-chain identity anchoring
- Reputation decay over time
- Trust attestation types (beyond numeric levels)
