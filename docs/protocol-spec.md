# FIDES Protocol Specification

## Overview

FIDES (Federated Identity and Decentralized Endorsement System) is a protocol enabling autonomous AI agents to establish cryptographic identities, authenticate requests, and build trust relationships.

**Version**: 1.0.0-alpha
**Status**: Draft
**Last Updated**: 2026-02-08

## Identity Layer

### DID Format

FIDES uses a custom DID method for agent identities:

```
did:fides:<base58-encoded-ed25519-public-key>
```

**Examples:**
```
did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd
did:fides:7nK9fV3hP8xRqW2mTgJvCz4YpLnH5QbM3kD6sF2gR9Xa
```

### Relationship to W3C DID Core

FIDES DIDs are **inspired by** but **not compliant with** W3C DID Core Specification (v1.0):

**Similarities:**
- Uses `did:` URI scheme
- Method-specific identifier (`fides`)
- Decentralized identifier resolution

**Differences:**
- Simplified for AI agent use cases
- Does not implement full DID document resolution
- No support for multiple verification methods
- No support for service endpoints in DID document
- Direct public key encoding instead of document indirection

**Rationale:** Reduced complexity for autonomous agents while maintaining core decentralization principles.

### Ed25519 Keypair Generation

**Algorithm:** Ed25519 (RFC 8032)
**Library:** `@noble/ed25519` (audited, pure JavaScript)

**Process:**
1. Generate 32-byte random seed using cryptographically secure RNG
2. Derive Ed25519 keypair from seed
3. Public key: 32 bytes
4. Private key: 64 bytes (seed + public key)

**TypeScript Example:**
```typescript
import * as ed25519 from '@noble/ed25519'

const privateKey = ed25519.utils.randomPrivateKey()
const publicKey = await ed25519.getPublicKey(privateKey)
```

### DID Creation

**Process:**
1. Generate Ed25519 keypair
2. Encode public key (32 bytes) as Base58
3. Construct DID: `did:fides:` + Base58(publicKey)

**Base58 Alphabet:** Bitcoin Base58 (excludes 0, O, I, l)

### Key Storage

**Encryption:** AES-256-GCM
**Key Derivation:** PBKDF2 with SHA-256
**Iterations:** 600,000
**Salt:** 16-byte random salt per key

**Encrypted Key Format:**
```json
{
  "version": 1,
  "did": "did:fides:...",
  "encrypted": "<base64-encoded-ciphertext>",
  "salt": "<base64-encoded-salt>",
  "iv": "<base64-encoded-iv>",
  "tag": "<base64-encoded-auth-tag>"
}
```

**Storage Location:** `~/.fides/keys/<did>.json`

**Security Properties:**
- Private key never stored in plaintext
- Password required to decrypt
- Authenticated encryption (GCM prevents tampering)
- Unique IV per encryption operation

**Limitations:**
- No key recovery mechanism (lost password = lost identity)
- No key rotation in MVP
- No hardware security module (HSM) support in MVP

## HTTP Message Signatures (RFC 9421)

FIDES implements HTTP Message Signatures per RFC 9421 for request authentication.

### Signed Components

**Required Components:**
- `@method`: HTTP method (GET, POST, etc.)
- `@target-uri`: Full request URI
- `@authority`: Host header value
- `content-type`: Content-Type header (if present)

**Component Identifiers:**
- Derived components prefixed with `@` (e.g., `@method`)
- HTTP headers lowercase (e.g., `content-type`)

### Signature Algorithm

**Algorithm Identifier:** `ed25519`
**Key Type:** Ed25519 public key
**Signature Format:** 64-byte Ed25519 signature, Base64-encoded

### Signature-Input Header

**Format:**
```
Signature-Input: sig1=("<component1>" "<component2>" ...);created=<unix-timestamp>;expires=<unix-timestamp>;keyid="<did>";alg="ed25519"
```

**Example:**
```
Signature-Input: sig1=("@method" "@target-uri" "@authority" "content-type");created=1707350400;expires=1707350700;keyid="did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd";alg="ed25519"
```

**Parameters:**
- `created`: UNIX timestamp of signature creation
- `expires`: UNIX timestamp of signature expiration
- `keyid`: DID of signing agent
- `alg`: Signature algorithm (always `ed25519`)

### Signature Header

**Format:**
```
Signature: sig1=:<base64-signature>:
```

**Example:**
```
Signature: sig1=:K2qGKOhSeP48aJPVBzE3k0V/9t0GCuXsXWqNrBUzpwQeZdq0SnN0Kt7UKQR6e9+flKABcTJL32FWnvBx/2DhBw==:
```

### Signature Base String

The signature base string is constructed per RFC 9421 Section 2.5:

```
"@method": <METHOD>
"@target-uri": <URI>
"@authority": <AUTHORITY>
"content-type": <CONTENT-TYPE>
"@signature-params": ("<component1>" "<component2>" ...);created=<unix>;expires=<unix>;keyid="<did>";alg="ed25519"
```

**Example:**
```
"@method": GET
"@target-uri": https://api.example.com/data
"@authority": api.example.com
"content-type": application/json
"@signature-params": ("@method" "@target-uri" "@authority" "content-type");created=1707350400;expires=1707350700;keyid="did:fides:5XqKCvJHVqQ8pBbNvCFz8JpqhP6ZcJW3M7FqHGxWJQYd";alg="ed25519"
```

### Signing Process

1. Extract signature components from HTTP request
2. Construct signature base string per RFC 9421
3. Sign base string with Ed25519 private key
4. Base64-encode signature
5. Add `Signature-Input` and `Signature` headers to request

### Verification Process

1. Extract `Signature-Input` header
2. Parse signature parameters (components, created, expires, keyid, alg)
3. Validate timestamp (check created < now < expires)
4. Resolve keyid (DID) to public key via discovery service
5. Reconstruct signature base string from request
6. Verify signature with Ed25519 public key
7. Accept/reject request based on verification result

### Replay Protection

**Mechanism:** Timestamp-based expiration
**Validity Window:** 300 seconds (5 minutes)
**Clock Tolerance:** None (strict timestamp checking in MVP)

**Properties:**
- `created` must be <= current time
- `expires` must be > current time
- `expires - created` <= 300 seconds

**Limitations:**
- No nonce tracking in MVP (deferred to v2)
- Replay attacks possible within validity window
- Requires synchronized clocks between agents

**Future Enhancements:**
- Per-agent nonce tracking
- Clock drift tolerance configuration
- Configurable validity windows per use case

## Trust Attestations

### Trust Statement Schema

A trust attestation is a signed statement from an issuer agent about a subject agent.

**TypeScript Interface:**
```typescript
interface TrustAttestation {
  id: string                // UUID v4
  issuerDid: string         // did:fides:...
  subjectDid: string        // did:fides:...
  trustLevel: number        // 0-100 (integer)
  issuedAt: number          // UNIX timestamp
  expiresAt: number | null  // UNIX timestamp or null (no expiration)
  signature: string         // Base64-encoded Ed25519 signature
  payload: string           // JSON payload (signed data)
}
```

### Trust Levels

**Numeric Range:** 0-100

**Semantic Levels:**
- `0`: No trust / Distrust
- `1-25`: Low trust
- `26-50`: Medium trust
- `51-75`: High trust
- `76-100`: Maximum trust

**Note:** Semantic levels are guidelines; applications may define custom interpretations.

### Payload Format

The signed payload is a JSON string containing:

```json
{
  "id": "<uuid>",
  "issuerDid": "did:fides:...",
  "subjectDid": "did:fides:...",
  "trustLevel": 75,
  "issuedAt": 1707350400,
  "expiresAt": 1739486400
}
```

### Signing Process

1. Create trust attestation payload (JSON object)
2. Serialize to canonical JSON string (no whitespace)
3. Sign JSON string with issuer's Ed25519 private key
4. Base64-encode signature
5. Store attestation with signature

### Verification Process

1. Extract `payload` and `signature` from attestation
2. Resolve `issuerDid` to public key
3. Verify signature over payload with issuer's public key
4. Parse payload and validate schema
5. Check attestation has not expired (`expiresAt` > now)
6. Accept/reject attestation based on verification

### Attestation Lifecycle

**Creation:**
- Issuer creates attestation
- Issuer signs with private key
- Issuer submits to trust graph service

**Storage:**
- Trust graph service verifies signature
- Trust graph service stores in PostgreSQL
- Indexed by issuer_did and subject_did

**Retrieval:**
- Query by subject_did to get all attestations about an agent
- Query by issuer_did to get all attestations from an agent
- Filter by expiration (exclude expired)

**Revocation:**
- Not implemented in MVP
- Future: Revocation list or on-chain revocation registry

## Trust Graph

### Graph Structure

**Nodes:** Agent identities (DIDs)
**Edges:** Trust attestations (directed)
**Edge Weight:** Trust level (0-100)

**Properties:**
- Directed graph (trust is not symmetric)
- Weighted edges (trust level varies)
- Dynamic (attestations added over time)

### BFS Traversal

**Algorithm:** Breadth-first search from query agent to target agent

**Parameters:**
- **Max Depth:** 6 hops
- **Decay Factor:** 0.85 per hop
- **Starting Trust:** 100 (self-trust)

**Pseudocode:**
```
function findTrustPaths(queryDid, targetDid, maxDepth=6):
  queue = [(queryDid, 100, 0, [queryDid])]
  visited = {queryDid}
  paths = []

  while queue not empty:
    (currentDid, currentTrust, depth, path) = queue.dequeue()

    if depth >= maxDepth:
      continue

    attestations = getAttestations(currentDid)

    for attestation in attestations:
      nextDid = attestation.subjectDid
      nextTrust = currentTrust * (attestation.trustLevel / 100) * 0.85
      nextPath = path + [nextDid]

      if nextDid == targetDid:
        paths.append((nextPath, nextTrust, depth + 1))

      if nextDid not in visited:
        visited.add(nextDid)
        queue.enqueue((nextDid, nextTrust, depth + 1, nextPath))

  return paths
```

### Trust Decay

**Formula:** `trust_at_depth_n = trust_at_depth_n-1 * attestation_level * 0.85`

**Example:**
- Direct trust (depth 1): Attestation level 80 → 80 * 0.85 = 68
- 2-hop trust (depth 2): 68 * 60 * 0.85 = 34.68
- 3-hop trust (depth 3): 34.68 * 70 * 0.85 = 20.62

**Rationale:**
- Exponential decay limits trust propagation distance
- Prevents trust spam from distant nodes
- Incentivizes direct relationships

### Reputation Scoring

**Aggregation Function:**
```
reputation_score = (
  sum(direct_trust) * 1.0 +
  sum(transitive_trust_depth_2) * 0.5 +
  sum(transitive_trust_depth_3_to_6) * 0.25
) / total_paths
```

**Weights:**
- Direct trust (depth 1): 100% weight
- 2-hop trust (depth 2): 50% weight
- 3-6 hop trust (depth 3-6): 25% weight

**Output:**
```json
{
  "did": "did:fides:...",
  "score": 72.5,
  "directTrust": 85,
  "transitiveTrust": 60,
  "pathCount": 12
}
```

**Limitations:**
- No decay over time (trust attestations don't age)
- Equal weight for all paths (no preference for high-trust issuers)
- Simple averaging (vulnerable to Sybil attacks)

**Future Enhancements:**
- PageRank-style reputation
- Time-weighted decay
- Weighted by issuer reputation
- Negative trust attestations

## Discovery Protocol

### Central Discovery Service

**Base URL:** Configurable (default: `http://localhost:3100`)

**Endpoints:**

#### Register Identity
```
POST /identities
Content-Type: application/json

{
  "did": "did:fides:...",
  "publicKey": "<base64-public-key>",
  "metadata": {
    "name": "Agent Name",
    "description": "Agent description",
    "endpoints": {
      "trust": "https://agent.example.com/trust",
      "api": "https://agent.example.com/api"
    }
  }
}

Response: 201 Created
{
  "did": "did:fides:...",
  "created": true
}
```

#### Resolve Identity
```
GET /identities/:did

Response: 200 OK
{
  "did": "did:fides:...",
  "publicKey": "<base64-public-key>",
  "metadata": {
    "name": "Agent Name",
    "description": "Agent description",
    "endpoints": {...}
  },
  "createdAt": "2026-02-08T12:00:00Z",
  "updatedAt": "2026-02-08T12:00:00Z"
}

Response: 404 Not Found
{
  "error": "Identity not found"
}
```

### .well-known Protocol

Agents may host their own identity documents at:

```
https://<agent-domain>/.well-known/fides.json
```

**Format:**
```json
{
  "did": "did:fides:...",
  "publicKey": "<base64-public-key>",
  "metadata": {
    "name": "Agent Name",
    "description": "Self-hosted agent",
    "endpoints": {...}
  }
}
```

### Resolution Order

When resolving a DID:

1. **Check .well-known first** (if DID metadata includes domain)
   - `GET https://<domain>/.well-known/fides.json`
   - Verify `did` field matches requested DID
   - Verify `publicKey` matches DID derivation

2. **Fallback to central discovery**
   - `GET <discovery-url>/identities/<did>`

**Benefits:**
- Decentralization: Agents control their own identities
- Redundancy: Central discovery as backup
- Flexibility: Mix of self-hosted and centralized identities

## Trust Graph Service

### Endpoints

#### Create Trust Attestation
```
POST /trust
Content-Type: application/json

{
  "issuerDid": "did:fides:...",
  "subjectDid": "did:fides:...",
  "trustLevel": 75,
  "expiresAt": 1739486400,
  "signature": "<base64-signature>",
  "payload": "<json-string>"
}

Response: 201 Created
{
  "id": "<uuid>",
  "created": true
}
```

#### Get Trust Attestations
```
GET /trust/:did

Response: 200 OK
{
  "attestations": [
    {
      "id": "<uuid>",
      "issuerDid": "did:fides:...",
      "subjectDid": "did:fides:...",
      "trustLevel": 75,
      "issuedAt": 1707350400,
      "expiresAt": 1739486400,
      "signature": "<base64-signature>"
    },
    ...
  ]
}
```

#### Verify Trust Attestation
```
POST /trust/verify
Content-Type: application/json

{
  "attestation": {...}
}

Response: 200 OK
{
  "valid": true,
  "issuerPublicKey": "<base64-public-key>"
}
```

#### Get Reputation Score
```
GET /reputation/:did

Response: 200 OK
{
  "did": "did:fides:...",
  "score": 72.5,
  "directTrust": 85,
  "transitiveTrust": 60,
  "pathCount": 12,
  "paths": [
    {
      "path": ["did:fides:A", "did:fides:B", "did:fides:C"],
      "trust": 68.5,
      "depth": 2
    },
    ...
  ]
}
```

## Security Considerations

### Threat Model

**In Scope:**
- Request forgery (mitigated by signatures)
- Identity spoofing (mitigated by Ed25519 keypairs)
- Replay attacks (partially mitigated by timestamps)
- Trust spam (mitigated by decay)

**Out of Scope (MVP):**
- Denial of service attacks
- Database compromise
- Private key theft from compromised systems
- Social engineering attacks

### Known Limitations

1. **No Nonce Tracking:** Replay attacks possible within 300-second window
2. **No Clock Drift Tolerance:** Strict timestamp checking requires synchronized clocks
3. **No Key Rotation:** Lost/compromised keys cannot be rotated
4. **No Revocation:** Trust attestations cannot be revoked
5. **No Rate Limiting:** Trust attestation spam not prevented
6. **Centralized Discovery:** Single point of failure (mitigated by .well-known)
7. **Simple Trust Decay:** Vulnerable to Sybil attacks

### Recommended Practices

1. **Secure key storage:** Encrypt private keys, use strong passwords
2. **HTTPS only:** All HTTP traffic must use TLS
3. **Time synchronization:** Use NTP to synchronize clocks
4. **Validate inputs:** Check DID format, trust levels, timestamps
5. **Audit trust attestations:** Review incoming trust before relying on it
6. **Monitor reputation:** Track reputation changes over time
7. **Backup keys:** Store encrypted backups in secure locations

## Future Protocol Extensions

### Planned for v2
- Nonce-based replay protection
- Key rotation and revocation
- Negative trust attestations
- Trust attestation types (capability, authorization, delegation)
- Clock drift tolerance configuration
- Rate limiting and spam prevention

### Under Consideration
- Zero-knowledge proofs for private attestations
- Threshold signatures for multi-agent identities
- Cross-chain DID anchoring
- Reputation decay over time
- Verifiable credentials integration
- OAuth 2.0 / OpenID Connect bridges
