# Getting Started with FIDES

This guide will walk you through setting up FIDES, creating your first agent identity, and performing basic trust operations.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js 18+** (recommend Node.js 22 for best compatibility)
- **pnpm** (package manager): `npm install -g pnpm`
- **Docker** (for PostgreSQL): [Install Docker](https://docs.docker.com/get-docker/)
- **Git** (for cloning the repository)

**System Requirements:**
- Operating System: macOS, Linux, or Windows with WSL2
- RAM: 4GB minimum, 8GB recommended
- Disk Space: 2GB for dependencies and databases

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/fides.git
cd fides
```

### 2. Install Dependencies

```bash
pnpm install
```

This will install all dependencies for the monorepo, including:
- `@fides/sdk` (protocol implementation)
- `@fides/cli` (command-line interface)
- Discovery service dependencies
- Trust graph service dependencies

### 3. Start PostgreSQL

Start the PostgreSQL database using Docker Compose:

```bash
docker compose up -d
```

This will start:
- PostgreSQL 16 on port 5432
- Database name: `fides`
- Username: `fides`
- Password: `fides`

**Verify PostgreSQL is running:**
```bash
docker ps
```

You should see a container named `fides-postgres-1` in the running state.

### 4. Build All Packages

```bash
pnpm build
```

This compiles TypeScript to JavaScript for all packages and services.

### 5. Start Development Servers

Start all services in development mode:

```bash
pnpm dev
```

This starts:
- **Discovery Service** on `http://localhost:3000`
- **Trust Graph Service** on `http://localhost:3001`

**Verify services are running:**
```bash
curl http://localhost:3000/.well-known/fides.json
curl http://localhost:3001/trust
```

## Quick Start Tutorial

### 1. Create Your First Identity

Create a new agent identity using the CLI:

```bash
fides init --name "My First Agent"
```

**Interactive prompts:**
- Enter a password to encrypt your private key
- Confirm password

**Output:**
```
✓ Generated Ed25519 keypair
✓ Created DID: did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd
✓ Encrypted and stored private key
✓ Registered identity with discovery service

Identity created successfully!
DID: did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd
```

**Where are my keys stored?**
- Location: `~/.fides/keys/<did>.json`
- Format: AES-256-GCM encrypted private key
- **Important:** Keep your password safe! Lost password = lost identity (no recovery in MVP)

### 2. Check Your Identity Status

View your local identity:

```bash
fides status
```

**Output:**
```
Agent Status
────────────
DID:        did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd
Name:       My First Agent
Created:    2026-02-08T12:00:00Z
Key File:   ~/.fides/keys/did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd.json
```

### 3. Sign an HTTP Request

Sign an HTTP request to authenticate as your agent:

```bash
fides sign https://api.example.com/data --method GET
```

**Interactive prompt:**
- Enter your password to unlock private key

**Output:**
```
Signed Request
──────────────
Method:  GET
URL:     https://api.example.com/data

Headers:
  Signature-Input: sig1=("@method" "@target-uri" "@authority" "content-type");created=1707350400;expires=1707350700;keyid="did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd";alg="ed25519"
  Signature: sig1=:K2qGKOhSeP48aJPVBzE3k0V/9t0GCuXsXWqNrBUzpwQeZdq0SnN0Kt7UKQR6e9+flKABcTJL32FWnvBx/2DhBw==:

Copy these headers to your HTTP client or use them in your application.
```

**Usage in curl:**
```bash
curl -H "Signature-Input: sig1=..." \
     -H "Signature: sig1=:...:" \
     https://api.example.com/data
```

### 4. Verify a Signed Request

Verify a request you received from another agent:

```bash
fides verify \
  --method GET \
  --url https://api.example.com/data \
  --signature-input 'sig1=("@method" "@target-uri" "@authority");created=1707350400;expires=1707350700;keyid="did:fides:ABC...";alg="ed25519"' \
  --signature 'sig1=:K2qGKOhSeP48aJP...=='
```

**Output:**
```
✓ Signature verified successfully
✓ Issuer: did:fides:ABC...
✓ Timestamp valid (not expired)

Request is authentic.
```

### 5. Trust Another Agent

Issue a trust attestation for another agent:

```bash
fides trust did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa --level high
```

**Trust Levels:**
- `low`: 25
- `medium`: 50
- `high`: 75
- `max`: 100
- Or specify a number: `--level 85`

**Interactive prompt:**
- Enter your password to sign the attestation

**Output:**
```
✓ Created trust attestation
✓ Signed with your private key
✓ Submitted to trust graph service

Trust attestation created!
Issuer:  did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd
Subject: did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa
Level:   75
```

### 6. Discover an Agent and Check Reputation

Look up another agent's identity and reputation:

```bash
fides discover did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa
```

**Output:**
```
Agent Information
─────────────────
DID:         did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa
Name:        Another Agent
Description: Demo agent for testing
Public Key:  <base64-encoded-key>

Reputation Score
────────────────
Overall:    68.5
Direct:     75.0 (1 attestation)
Transitive: 60.0 (3 paths)
Paths:      4 total

Trust Paths:
  1. You → Another Agent (direct, trust: 75.0)
  2. You → Alice → Another Agent (2 hops, trust: 51.0)
  3. You → Bob → Charlie → Another Agent (3 hops, trust: 34.2)
```

## Using the SDK

For programmatic access, use the `@fides/sdk` package in your TypeScript/JavaScript applications.

### Installation

```bash
npm install @fides/sdk
# or
pnpm add @fides/sdk
```

### Basic Example

```typescript
import { Fides } from '@fides/sdk'

// Initialize FIDES client
const fides = new Fides({
  discoveryUrl: 'http://localhost:3000',
  trustUrl: 'http://localhost:3001',
})

// Create a new identity
const { did, publicKey } = await fides.createIdentity({
  name: 'My SDK Agent',
  password: 'secure-password-123',
})
console.log(`Identity created: ${did}`)

// Sign an HTTP request
const signedRequest = await fides.signRequest({
  method: 'GET',
  url: 'https://api.example.com/data',
  headers: {
    'Content-Type': 'application/json',
  },
  password: 'secure-password-123',
})

console.log('Signed headers:', signedRequest.headers)

// Issue a trust attestation
await fides.trust({
  subjectDid: 'did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa',
  trustLevel: 75,
  password: 'secure-password-123',
})

// Get reputation score
const reputation = await fides.getReputation(
  'did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa'
)
console.log(`Reputation score: ${reputation.score}`)
console.log(`Trust paths: ${reputation.pathCount}`)
```

### Verifying Requests

```typescript
import { Fides } from '@fides/sdk'

const fides = new Fides({
  discoveryUrl: 'http://localhost:3000',
  trustUrl: 'http://localhost:3001',
})

// Verify a signed request
const isValid = await fides.verifyRequest({
  method: 'POST',
  url: 'https://api.example.com/data',
  headers: {
    'Signature-Input': 'sig1=...',
    'Signature': 'sig1=:...=',
  },
})

if (isValid) {
  console.log('Request is authentic!')
} else {
  console.log('Invalid signature or expired request')
}
```

### Discovering Identities

```typescript
import { Fides } from '@fides/sdk'

const fides = new Fides({
  discoveryUrl: 'http://localhost:3000',
  trustUrl: 'http://localhost:3001',
})

// Resolve a DID to identity information
const identity = await fides.discover('did:fides:7nK9fV3h...')
console.log(`Name: ${identity.metadata.name}`)
console.log(`Public Key: ${identity.publicKey}`)
console.log(`Created: ${identity.createdAt}`)
```

### Building Trust Relationships

```typescript
import { Fides } from '@fides/sdk'

const fides = new Fides({
  discoveryUrl: 'http://localhost:3000',
  trustUrl: 'http://localhost:3001',
})

// Trust multiple agents
const agentsToTrust = [
  { did: 'did:fides:Alice...', level: 80 },
  { did: 'did:fides:Bob...', level: 65 },
  { did: 'did:fides:Charlie...', level: 90 },
]

for (const agent of agentsToTrust) {
  await fides.trust({
    subjectDid: agent.did,
    trustLevel: agent.level,
    password: 'secure-password-123',
  })
  console.log(`Trusted ${agent.did} at level ${agent.level}`)
}

// Compute reputation for all trusted agents
for (const agent of agentsToTrust) {
  const rep = await fides.getReputation(agent.did)
  console.log(`${agent.did}: ${rep.score} (${rep.pathCount} paths)`)
}
```

## Advanced Usage

### Custom Discovery Service

Run your own discovery service on a different port:

```bash
cd services/discovery
PORT=4000 pnpm dev
```

Update your CLI or SDK configuration:

```typescript
const fides = new Fides({
  discoveryUrl: 'http://localhost:4000',
  trustUrl: 'http://localhost:3001',
})
```

### Self-Hosted Identity (.well-known)

Host your identity document at `https://yourdomain.com/.well-known/fides.json`:

```json
{
  "did": "did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd",
  "publicKey": "base64-encoded-public-key",
  "metadata": {
    "name": "My Self-Hosted Agent",
    "description": "Autonomous agent with self-sovereign identity",
    "endpoints": {
      "api": "https://yourdomain.com/api",
      "trust": "https://yourdomain.com/trust"
    }
  }
}
```

FIDES will resolve your DID from `.well-known` before falling back to the central discovery service.

### Running Tests

Run the test suite to verify your installation:

```bash
pnpm test
```

**Test coverage:**
- Identity generation and DID creation
- Ed25519 signing and verification
- RFC 9421 HTTP message signatures
- Trust attestation creation and verification
- BFS trust graph traversal
- Reputation scoring

### Database Management

**View database contents:**
```bash
docker exec -it fides-postgres-1 psql -U fides -d fides
```

**Useful SQL queries:**
```sql
-- List all identities
SELECT did, metadata->>'name' as name, created_at FROM identities;

-- List all trust attestations
SELECT issuer_did, subject_did, trust_level, issued_at FROM trust_attestations;

-- Count attestations per agent
SELECT subject_did, COUNT(*) as attestation_count
FROM trust_attestations
GROUP BY subject_did
ORDER BY attestation_count DESC;
```

**Reset database:**
```bash
docker compose down -v
docker compose up -d
pnpm build
pnpm dev
```

## Troubleshooting

### PostgreSQL Connection Issues

**Error:** `ECONNREFUSED` or `Connection refused`

**Solution:**
1. Check Docker is running: `docker ps`
2. Restart PostgreSQL: `docker compose restart`
3. Check database URL in `.env` files

### CLI Not Found

**Error:** `fides: command not found`

**Solution:**
1. Build packages: `pnpm build`
2. Link CLI globally: `cd packages/cli && pnpm link --global`
3. Or use via pnpm: `pnpm -C packages/cli start init --name "Agent"`

### Signature Verification Fails

**Error:** `Invalid signature`

**Possible causes:**
1. **Clock drift:** Ensure system clocks are synchronized (use NTP)
2. **Expired signature:** Signatures valid for 300 seconds only
3. **Wrong keyid:** Verify DID matches the signing agent
4. **Tampered request:** Any modification invalidates signature

**Debug:**
```bash
fides verify --debug ...
```

### Trust Graph Empty

**Error:** `No trust paths found`

**Explanation:** No trust attestations exist yet. You need to create trust relationships first.

**Solution:**
```bash
fides trust did:fides:targetAgent --level high
```

## Next Steps

Now that you have FIDES running, explore:

1. **Architecture**: Read [docs/architecture.md](./architecture.md) to understand system design
2. **Protocol Spec**: Review [docs/protocol-spec.md](./protocol-spec.md) for detailed protocol documentation
3. **Build an Agent**: Create an autonomous agent using the SDK
4. **Trust Network**: Build a network of trusted agents
5. **Integrate Services**: Use HTTP message signatures to authenticate service requests

## Getting Help

- **Issues**: Open an issue on GitHub
- **Discussions**: Join the community discussions
- **Documentation**: See `docs/` directory for detailed guides
- **Examples**: Check `examples/` directory for sample code

## Security Best Practices

1. **Protect Your Password**: Your private key is encrypted with your password. Lost password = lost identity.
2. **Use Strong Passwords**: Minimum 12 characters, mix of letters/numbers/symbols
3. **Backup Keys**: Copy `~/.fides/keys/` to secure backup location
4. **HTTPS Only**: Always use HTTPS for production services
5. **Verify Signatures**: Always verify request signatures before processing
6. **Monitor Trust**: Regularly review incoming trust attestations
7. **Keep Software Updated**: Update FIDES packages regularly for security patches

## What's Next?

- Explore the [Architecture documentation](./architecture.md)
- Dive into the [Protocol Specification](./protocol-spec.md)
- Build your first autonomous agent application
- Join the FIDES community and contribute!
