# FIDES

> **Latin:** *fides* = trust, faith, confidence

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-brightgreen.svg)](https://nodejs.org/)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/yourusername/fides)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/yourusername/fides/pulls)

**Decentralized trust and authentication protocol for autonomous AI agents**

---

## Why FIDES?

As AI agents become increasingly autonomous, they face critical challenges in secure communication:

- **No verifiable identity** — Agents cannot prove who they are without centralized authorities
- **No trust mechanism** — No standard way to establish trust relationships between agents
- **Request tampering** — HTTP requests lack cryptographic integrity protection
- **Reputation opacity** — No way to discover an agent's trustworthiness through network effects

FIDES solves these problems with a decentralized, cryptographically secure trust protocol built specifically for AI agents.

---

## Key Features

- **⚡ Ed25519 Identity** — DID-based identities with secure elliptic curve cryptography
- **📝 RFC 9421 HTTP Message Signatures** — Standardized request signing and verification
- **🕸️ Decentralized Trust Graph** — Distributed trust attestations with BFS traversal
- **🔗 Transitive Trust with Decay** — Reputation propagates through the network (0.85 decay/hop)
- **🔒 Zero-dependency Crypto** — Pure JavaScript cryptography via @noble/ed25519
- **📘 TypeScript-first** — End-to-end type safety for robust agent development

---

## Quick Start

### Installation

```bash
npm install @fides/sdk
```

### Basic Usage

```typescript
import { Fides, TrustLevel } from '@fides/sdk'

// Initialize FIDES client
const fides = new Fides({
  discoveryUrl: 'http://localhost:3100',
  trustUrl: 'http://localhost:3200'
})

// Create agent identity
const { did } = await fides.createIdentity({
  name: 'My AI Agent'
})

// Sign a request
const signed = await fides.signRequest({
  method: 'POST',
  url: 'https://agent-b.example.com/api/task',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ task: 'collaborate' })
})

// Verify incoming request
const result = await fides.verifyRequest(incomingRequest)
if (result.valid) {
  // Request is authentic and unmodified
}

// Trust another agent
await fides.trust('did:fides:7nK9fV3h...', TrustLevel.HIGH)

// Check reputation
const score = await fides.getReputation('did:fides:7nK9fV3h...')
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AI Agent                             │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              @fides/sdk                             │   │
│  │                                                     │   │
│  │  • Identity (Ed25519 keypairs, DIDs)               │   │
│  │  • Signing (RFC 9421 HTTP signatures)              │   │
│  │  • Trust (Attestations, verification)              │   │
│  │  • Discovery (Identity resolution)                 │   │
│  └──────────────┬──────────────────┬───────────────────┘   │
└─────────────────┼──────────────────┼──────────────────────┘
                  │                  │
                  ▼                  ▼
        ┌─────────────────┐  ┌─────────────────┐
        │   Discovery      │  │  Trust Graph    │
        │    Service       │  │    Service      │
        │                  │  │                 │
        │  • Register DIDs │  │  • Attestations │
        │  • Resolve keys  │  │  • Reputation   │
        │  • .well-known   │  │  • BFS graph    │
        └────────┬─────────┘  └────────┬────────┘
                 │                     │
                 └──────────┬──────────┘
                            ▼
                    ┌──────────────┐
                    │  PostgreSQL  │
                    └──────────────┘
```

---

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `generateKeyPair()` | Generate Ed25519 keypair for agent identity |
| `generateDID(publicKey)` | Create DID from public key (did:fides:base58) |
| `signRequest(request, privateKey, options)` | Sign HTTP request per RFC 9421 |
| `verifyRequest(request, publicKey)` | Verify HTTP request signature |
| `createAttestation(issuerDid, subjectDid, level, privateKey)` | Create signed trust attestation |
| `verifyAttestation(attestation, publicKey)` | Verify attestation signature |

### Fides Class (High-level API)

| Method | Description |
|--------|-------------|
| `createIdentity(metadata?)` | Create new identity and register with discovery |
| `signRequest(request)` | Sign request with current identity |
| `verifyRequest(request)` | Verify request and resolve signer identity |
| `trust(subjectDid, level)` | Create and submit trust attestation |
| `getReputation(did)` | Get aggregated reputation score |
| `resolve(didOrDomain)` | Resolve DID to identity information |

### Key Stores

| Class | Description |
|-------|-------------|
| `MemoryKeyStore` | In-memory key storage (development only) |
| `FileKeyStore` | AES-256-GCM encrypted file storage |

---

## Trust Levels

| Level | Value | Description |
|-------|-------|-------------|
| `NONE` | 0 | No trust established |
| `LOW` | 25 | Minimal trust, limited interaction |
| `MEDIUM` | 50 | Moderate trust, standard collaboration |
| `HIGH` | 75 | Strong trust, sensitive operations |
| `ABSOLUTE` | 100 | Complete trust, full delegation |

> **Note:** Trust propagates through the network with 0.85 exponential decay per hop (max 6 hops)

---

## Protocol Specification

FIDES implements a complete decentralized trust protocol with:

- **Identity Layer**: Ed25519 keypairs + `did:fides:<base58-pubkey>` identifiers
- **Authentication Layer**: RFC 9421 HTTP Message Signatures with ed25519 algorithm
- **Trust Layer**: Signed attestations stored in distributed trust graph
- **Reputation Layer**: BFS graph traversal with exponential decay scoring

**Full specification:** [docs/protocol-spec.md](docs/protocol-spec.md)

---

## Project Structure

```
fides/
├── packages/
│   ├── sdk/              # Core protocol implementation
│   │   ├── identity/     # Keypairs, DIDs, key storage
│   │   ├── signing/      # RFC 9421 HTTP signatures
│   │   ├── trust/        # Attestations, verification
│   │   └── discovery/    # Identity resolution
│   ├── cli/              # Command-line interface
│   └── shared/           # Shared types and constants
├── services/
│   ├── discovery/        # Identity registration service
│   └── trust/            # Trust graph service
├── docs/
│   ├── architecture.md   # System design
│   ├── protocol-spec.md  # Protocol details
│   └── getting-started.md # Tutorial
└── scripts/
    └── two-agents-demo.ts # Demo script
```

---

## Development

### Prerequisites

- Node.js >= 20 (recommend v22)
- pnpm (package manager)
- Docker (for PostgreSQL)

### Setup

```bash
# Clone repository
git clone https://github.com/yourusername/fides.git
cd fides

# Install dependencies
pnpm install

# Start PostgreSQL
docker compose up -d

# Build all packages
pnpm build

# Start development servers
pnpm dev
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

### Running the Demo

```bash
# Build packages first
pnpm build

# Run two-agent demo
npx tsx scripts/two-agents-demo.ts
```

---

## Security

FIDES uses industry-standard cryptography and security practices:

- **Ed25519 signatures** — Fast, secure elliptic curve cryptography via @noble/ed25519
- **Timing-safe comparisons** — Constant-time signature verification prevents timing attacks
- **AES-256-GCM encryption** — Password-protected private key storage
- **PBKDF2 key derivation** — 600k iterations with SHA-256
- **Replay protection** — Timestamp-based signature expiration (300s window)

> **Security disclosure:** Report vulnerabilities to [SECURITY.md](SECURITY.md)

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

MIT License - see [LICENSE](LICENSE) for details

---

<div align="center">

**Built with cryptographic trust** 🔐

[Documentation](docs/) • [Architecture](docs/architecture.md) • [Getting Started](docs/getting-started.md)

</div>
