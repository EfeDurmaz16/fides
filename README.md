# FIDES

**Decentralized Trust & Authentication Protocol for AI Agents**

FIDES (Federated Identity and Decentralized Endorsement System) is a protocol enabling autonomous AI agents to establish cryptographic identities, authenticate requests, and build trust relationships through a decentralized attestation network.

## Why FIDES?

As AI agents become increasingly autonomous, they need robust mechanisms to identify themselves, authenticate requests, and establish trust with other agents and services. Traditional authentication systems designed for humans don't translate well to autonomous agents operating at scale. FIDES addresses this by providing:

- **Cryptographic Identity**: Ed25519-based DIDs for verifiable agent identities
- **Request Authentication**: RFC 9421 HTTP message signatures for secure communication
- **Decentralized Trust**: Distributed trust attestations with graph-based reputation scoring
- **Agent Autonomy**: Self-sovereign identity without reliance on central authorities

## Prerequisites

- **Node.js 18+** (recommend Node.js 22)
- **pnpm** package manager
- **Docker** (for PostgreSQL)
- **Git**

## Quick Start

### 1. Install

```bash
git clone https://github.com/yourusername/fides.git
cd fides
pnpm install
```

### 2. Start Services

```bash
docker compose up -d
pnpm build
pnpm dev
```

This starts:
- PostgreSQL database on port 5432
- Discovery service on http://localhost:3000
- Trust graph service on http://localhost:3001

### 3. Create Your First Agent Identity

```bash
fides init --name "My Agent"
```

### 4. Sign and Verify Requests

```bash
# Sign a request
fides sign https://api.example.com/data --method GET

# Verify a signed request
fides verify --method GET --url https://api.example.com/data --signature-input "..." --signature "..."
```

### 5. Build Trust Relationships

```bash
# Trust another agent
fides trust did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa --level high

# Check reputation
fides discover did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa
```

## Monorepo Structure

```
fides/
├── packages/
│   ├── shared/         # Shared types, errors, constants
│   ├── sdk/            # Core FIDES protocol implementation
│   │   ├── identity/   # Ed25519 identity and DID generation
│   │   ├── signing/    # RFC 9421 HTTP message signatures
│   │   ├── discovery/  # Discovery client
│   │   ├── trust/      # Trust client
│   │   └── fides.ts    # High-level API
│   ├── cli/            # Command-line interface
│   └── rust-sdk/       # Rust SDK (planned)
├── services/
│   ├── discovery/      # Identity registration & resolution service
│   ├── trust-graph/    # Trust attestation & reputation service
│   ├── policy-engine/  # Policy enforcement service (planned)
│   └── platform-api/   # Platform coordination API (planned)
├── apps/
│   └── web/            # Web dashboard (planned)
├── docs/
│   ├── architecture.md     # System architecture overview
│   ├── protocol-spec.md    # Detailed protocol specification
│   └── getting-started.md  # Complete setup and usage guide
└── tests/              # Integration tests
```

## Core Components

### @fides/sdk
TypeScript SDK implementing the complete FIDES protocol:
- Ed25519 identity generation and management
- DID creation (`did:fides:<base58-pubkey>`)
- RFC 9421 HTTP message signatures
- Discovery and trust clients
- High-level Fides API

### @fides/cli
Command-line interface for FIDES operations:
- `fides init` - Create agent identity
- `fides sign` - Sign HTTP requests
- `fides verify` - Verify signed requests
- `fides trust` - Issue trust attestations
- `fides discover` - Resolve identities and check reputation
- `fides status` - View agent status

### Discovery Service
Identity registration and resolution service (Hono + PostgreSQL):
- Register DIDs with public keys and metadata
- Resolve DIDs to identity documents
- `.well-known/fides.json` support for self-hosted identities

### Trust Graph Service
Trust attestation and reputation service (Hono + PostgreSQL):
- Create and verify trust attestations
- BFS graph traversal with exponential decay (0.85 per hop, max 6 hops)
- Reputation scoring from direct and transitive trust

## Key Features

### Cryptographic Identity
- Ed25519 keypairs for signing and verification
- DID format: `did:fides:<base58-encoded-public-key>`
- AES-256-GCM encrypted key storage with PBKDF2 derivation

### HTTP Message Signatures
- RFC 9421 compliant request signing
- Signature components: `@method`, `@target-uri`, `@authority`, `content-type`
- Timestamp-based replay protection (300-second validity window)

### Trust Network
- Signed trust attestations (0-100 trust levels)
- Graph-based reputation computation
- Exponential trust decay per hop
- Multiple trust path aggregation

### Decentralized Resolution
- Central discovery service for convenience
- `.well-known` protocol for self-hosted identities
- Fallback resolution order

## Documentation

- **[Getting Started Guide](./docs/getting-started.md)** - Complete setup and tutorial
- **[Architecture Overview](./docs/architecture.md)** - System design and components
- **[Protocol Specification](./docs/protocol-spec.md)** - Detailed protocol documentation

## Development

### Build

```bash
pnpm build
```

### Run Tests

```bash
pnpm test
```

### Type Check

```bash
pnpm typecheck
```

### Run Development Servers

```bash
pnpm dev
```

### Lint

```bash
pnpm lint
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Roadmap

### Current (v1.0-alpha)
- Core protocol implementation
- TypeScript SDK and CLI
- Discovery and trust graph services
- Basic trust attestations and reputation

### Planned (v1.1)
- Key rotation and revocation
- Nonce-based replay protection
- Rate limiting and spam prevention
- Negative trust attestations

### Future
- Rust SDK for performance-critical agents
- Policy engine for automated trust decisions
- Web dashboard for trust visualization
- Zero-knowledge proofs for private attestations
- Threshold signatures for multi-agent identities

## License

MIT

---

Built with TypeScript, Hono, Drizzle ORM, and PostgreSQL.
