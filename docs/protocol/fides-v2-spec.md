# FIDES v2 Protocol Specification

**Version:** 2.0.0
**Protocol ID:** `fides-v2.0.0`
**Status:** Draft

---

## Table of Contents

1. [Overview](#1-overview)
2. [Identity](#2-identity)
3. [AgentCard](#3-agentcard)
4. [Capabilities](#4-capabilities)
5. [Trust Graph](#5-trust-graph)
6. [Delegation](#6-delegation)
7. [Policy Engine](#7-policy-engine)
8. [Evidence Ledger](#8-evidence-ledger)
9. [Runtime Attestation](#9-runtime-attestation)
10. [Guard Decision Engine](#10-guard-decision-engine)
11. [Discovery](#11-discovery)
12. [Kill Switch](#12-kill-switch)
13. [Registry Service](#13-registry-service)
14. [Relay Service](#14-relay-service)
15. [Error Taxonomy](#15-error-taxonomy)

---

## 1. Overview

FIDES v2 is a decentralized trust fabric for AI agents. It provides:

- **Identity:** Cryptographic DIDs with AgentCard v2 descriptors
- **Trust Graph:** Weighted, capability-specific reputation with transitive trust
- **Policy Engine:** Deterministic rule evaluation with pre-execution guards
- **Evidence Ledger:** Hash-chained, Merkle-rooted event log with privacy levels
- **Runtime Attestation:** TEE-based execution environment verification
- **Delegation:** Capability delegation with constraints and session grants
- **Discovery:** Multi-provider agent discovery (well-known, registry, DHT, relay)
- **Kill Switch:** Emergency capability/agent/global shutdown

### Protocol Objects

All protocol objects are JSON-serializable and signed using canonical JSON encoding (recursive key sorting, no whitespace).

```
PROTOCOL_VERSION = "fides-v2.0.0"
```

---

## 2. Identity

### 2.1 DID Format

```
did:fides:<identifier>
```

Where `<identifier>` is a unique string (typically a public key fingerprint or UUID).

### 2.2 Identity Types

```typescript
interface Identity {
  did: string
  type: 'agent' | 'publisher' | 'principal' | 'trust-anchor'
  publicKey: Uint8Array  // Ed25519 public key
  metadata: Record<string, unknown>
  createdAt: string  // ISO 8601
}
```

### 2.3 Canonical Signing

All signed objects use canonical JSON encoding:

```typescript
interface SignedObject<T> {
  payload: T
  signature: string  // hex-encoded Ed25519 signature
  signerDid: string
  algorithm: 'ed25519'
}
```

Canonical JSON rules:
1. Object keys sorted recursively (lexicographic)
2. No whitespace
3. Unicode characters escaped as `\uXXXX`
4. Numbers in canonical form (no trailing zeros)

---

## 3. AgentCard

### 3.1 Structure

```typescript
interface AgentCard {
  id: string
  did: string
  name: string
  description: string
  version: string
  publisher?: string
  homepage?: string
  capabilities: CapabilityDescriptor[]
  protocols: string[]  // e.g., ["mcp", "a2a", "x402"]
  endpoints: AgentEndpoint[]
  security: SecurityProfile
  metadata: Record<string, unknown>
}

interface AgentEndpoint {
  url: string
  protocol: string
  capabilities: string[]  // capability IDs served at this endpoint
}

interface SecurityProfile {
  authentication: ('api-key' | 'oauth2' | 'mtls' | 'did-auth')[]
  encryption: ('tls1.3' | 'age')[]
  attestation?: 'tee-required' | 'tee-optional' | 'none'
}
```

### 3.2 Discovery

AgentCards are published at:
```
https://<agent-domain>/.well-known/fides-agent-card.json
```

---

## 4. Capabilities

### 4.1 Capability Descriptor

```typescript
interface CapabilityDescriptor {
  id: string  // e.g., "email:send", "web:search", "payment:charge"
  name: string
  description: string
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
  parameters: CapabilityParameter[]
  output: CapabilityOutput
  constraints: CapabilityConstraint[]
  metadata: Record<string, unknown>
}

interface CapabilityParameter {
  name: string
  type: 'string' | 'number' | 'boolean' | 'object' | 'array'
  required: boolean
  description: string
}

interface CapabilityOutput {
  type: string
  description: string
}

interface CapabilityConstraint {
  type: 'rate-limit' | 'spend-limit' | 'scope-limit' | 'time-limit'
  value: unknown
}
```

### 4.2 Risk Classification

```typescript
function classifyCapabilityRisk(capability: CapabilityDescriptor): {
  level: 'critical' | 'high' | 'medium' | 'low'
  factors: string[]
}
```

Risk factors:
- **Critical:** Financial operations, data deletion, system access
- **High:** Data modification, external communication, PII access
- **Medium:** Data read, computation, internal operations
- **Low:** Status queries, health checks, metadata access

---

## 5. Trust Graph

### 5.1 Trust Edges

```typescript
interface TrustEdge {
  sourceDid: string
  targetDid: string
  trustLevel: number  // 0-100
  capabilityId?: string  // null = general trust
  context?: string
  attestation: Record<string, unknown>
  signature: string
  createdAt: string
  expiresAt?: string
  revokedAt?: string
}
```

### 5.2 Reputation Scoring

Algorithm (spec-compliant):
- Direct trust (depth 1): weight 1.0
- Transitive depth 2: weight 0.5
- Transitive depth 3+: weight 0.25
- Final score = weighted sum / total paths, capped at 1.0

### 5.3 Capability Scoring

```typescript
interface CapabilityScore {
  did: string
  capabilityId: string
  score: number  // 0-1
  invocationCount: number
  incidentCount: number
  lastComputed: string
}
```

Score formula:
```
score = base_trust × (1 - incident_penalty) × success_rate_factor
```

### 5.4 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/trust` | Create trust edge |
| GET | `/v1/trust/:did/score` | Get reputation score |
| GET | `/v1/trust/:from/:to` | Get trust path |
| GET | `/v1/trust/:did/capability/:capId` | Get capability score |
| POST | `/v1/trust/:did/capability/:capId/invoke` | Record invocation |
| POST | `/v1/incidents` | Record incident |
| GET | `/v1/incidents/:did` | Get incidents |

---

## 6. Delegation

### 6.1 DelegationToken

```typescript
interface DelegationToken {
  id: string
  delegator: string  // DID
  delegatee: string  // DID
  capabilities: string[]
  constraints: DelegationConstraint
  issuedAt: string
  expiresAt: string
  nonce: string
  audience?: string[]
  signature: string
}

interface DelegationConstraint {
  maxActions?: number
  maxSpend?: string
  allowedContexts?: string[]
  forbiddenContexts?: string[]
}
```

### 6.2 SessionGrant

```typescript
interface SessionGrant {
  id: string
  token: DelegationToken
  sessionKey: string  // Ed25519 key pair for session
  expiresAt: string
  boundTo?: string  // target DID
}
```

### 6.3 Validation

A DelegationToken is valid if:
1. All required fields present
2. Not expired
3. Signature verified against delegator's public key
4. Delegatee DID matches the requesting agent

---

## 7. Policy Engine

### 7.1 PolicyBundle

```typescript
interface PolicyBundle {
  id: string
  version: string
  rules: PolicyRule[]
  defaultAction: 'allow' | 'deny' | 'approve-required'
}

interface PolicyRule {
  id: string
  condition: PolicyExpression
  action: 'allow' | 'deny' | 'approve-required' | 'dry-run'
  explanation: string
}
```

### 7.2 Expressions

| Operator | Description |
|----------|-------------|
| `eq` | Field equals value |
| `neq` | Field not equals value |
| `lt` | Field less than value |
| `lte` | Field less than or equal |
| `gt` | Field greater than value |
| `gte` | Field greater than or equal |
| `in` | Field in array value |
| `all` | All values in array field |
| `any` | Any value in array field |

### 7.3 Pre-Execution Pipeline

Guards run before policy evaluation:
- **allow:** Continue
- **warn:** Continue but flag for dry-run
- **block:** Immediate deny

---

## 8. Evidence Ledger

### 8.1 EvidenceEvent

```typescript
interface EvidenceEvent {
  id: string
  type: string
  timestamp: string
  actor: string
  action: string
  target?: string
  payload: unknown
  privacy: EvidencePrivacy
  prevHash: string
  hash: string
  signature: string
}

interface EvidencePrivacy {
  level: 'public' | 'private' | 'redacted' | 'hash-only'
  redactionKey?: string
}
```

### 8.2 Hash Chain

Each event's hash is computed over the canonical JSON of the event (excluding the `hash` field itself), with `prevHash` pointing to the previous event's hash.

### 8.3 Merkle Root

The Merkle root is computed over all event hashes in the chain using SHA-256:
- Leaf nodes: event hashes
- Internal nodes: SHA-256(left + right)
- Odd nodes at any level: promoted to next level

### 8.4 Privacy Levels

| Level | Payload Visibility |
|-------|-------------------|
| `public` | Full payload visible |
| `private` | Payload nullified on export |
| `redacted` | Payload replaced with `[REDACTED]` |
| `hash-only` | Only hash verifiable, payload nullified |

---

## 9. Runtime Attestation

### 9.1 RuntimeAttestation

```typescript
interface RuntimeAttestation {
  id: string
  agentDid: string
  provider: string  // e.g., "aws-nitro", "intel-sgx", "amd-sev"
  measurement: string  // TEE measurement hash
  timestamp: string
  expiresAt: string
  evidence: unknown  // Provider-specific evidence
  signature: string
}
```

### 9.2 TEE Adapter Interface

```typescript
interface TEEAdapter {
  readonly provider: string
  attest(agentDid: string): Promise<RuntimeAttestation>
  verify(attestation: RuntimeAttestation): Promise<boolean>
}
```

---

## 10. Guard Decision Engine

### 10.1 Decision Flow

1. **Kill switch check** → immediate deny if engaged
2. **Attestation check** → deny if invalid/expired and required
3. **Evidence chain** → deny if hash chain broken
4. **Incident rate** → deny if ≥5 incidents in 24h
5. **Trust score** → factor into decision (low score = warn)
6. **Pre-execution pipeline** → block/warn/allow
7. **Policy evaluation** → final decision

### 10.2 GuardRequest

```typescript
interface GuardRequest {
  agentDid: string
  capabilityId: string
  policy: PolicyBundle
  context: Record<string, unknown>
  trust: TrustContext
}

interface TrustContext {
  reputationScore: number
  capabilityScore?: number
  attestationValid: boolean
  attestation?: RuntimeAttestation
  evidenceChain?: EvidenceChain
  killSwitchEngaged: boolean
  recentIncidents: number
}
```

### 10.3 GuardDecision

```typescript
interface GuardDecision {
  decision: 'allow' | 'deny' | 'approve-required' | 'dry-run'
  explanation: string
  factors: Array<{
    source: string
    factor: string
    weight: number
    description: string
  }>
  policyResult?: PolicyResult
}
```

---

## 11. Discovery

### 11.1 Provider Interface

```typescript
interface DiscoveryProvider {
  readonly name: string
  readonly priority: number
  discover(did: string): Promise<AgentCard | null>
  search(query: DiscoveryQuery): Promise<AgentCard[]>
}
```

### 11.2 Providers

| Provider | Priority | Description |
|----------|----------|-------------|
| `well-known` | 100 | `.well-known/fides-agent-card.json` |
| `local` | 90 | mDNS/local network discovery |
| `registry` | 80 | Central registry service |
| `relay` | 70 | Relay network discovery |
| `dht` | 60 | Distributed hash table (libp2p) |

### 11.3 Orchestrator

The `DiscoveryOrchestrator` queries providers in priority order, returning the first successful result. Multiple providers can be queried in parallel for search operations.

---

## 12. Kill Switch

### 12.1 Targets

```typescript
interface KillSwitchTarget {
  type: 'global' | 'agent' | 'capability' | 'principal'
  did?: string
  id?: string
}
```

### 12.2 Precedence

1. Global kill overrides all
2. Agent kill overrides capability kills for that agent
3. Capability kill affects all agents for that capability

---

## 13. Registry Service

### 13.1 Purpose

Central registry for agent registration and capability publishing.

### 13.2 Modes

- **Public:** Anyone can register
- **Private:** Requires approval

### 13.3 API (Stub)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/register` | Register agent |
| GET | `/v1/agents/:did` | Get agent info |
| GET | `/v1/search` | Search agents |
| POST | `/v1/capabilities` | Publish capability |

---

## 14. Relay Service

### 14.1 Purpose

Message relay for agents behind NAT/firewalls or with dynamic addresses. Relay deployments can use process-local memory for lightweight development or a schema-versioned file snapshot for durable production restarts.

### 14.2 API (Stub)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/relay` | Relay message |
| GET | `/v1/relay/:id` | Get message status |

---

## 15. Error Taxonomy

All FIDES errors use the `TrustError` class with category classification:

| Category | Code Prefix | Description |
|----------|-------------|-------------|
| `identity` | `IDENTITY_*` | DID resolution, key management |
| `trust` | `TRUST_*` | Trust edge, scoring |
| `policy` | `POLICY_*` | Policy evaluation |
| `delegation` | `DELEGATION_*` | Token validation |
| `evidence` | `EVIDENCE_*` | Chain integrity |
| `discovery` | `DISCOVERY_*` | Provider failures |
| `attestation` | `ATTESTATION_*` | TEE verification |
| `network` | `NETWORK_*` | Connectivity |
| `protocol` | `PROTOCOL_*` | Version mismatch |
| `authorization` | `AUTHZ_*` | Permission denied |
| `runtime` | `RUNTIME_*` | Kill switch, execution |
| `internal` | `INTERNAL_*` | System errors |

---

## Appendix A: Protocol Version Negotiation

All FIDES v2 implementations MUST include the protocol version in:
1. HTTP headers: `X-Fides-Protocol: fides-v2.0.0`
2. AgentCard: `protocols` array
3. Signed objects: implicit via canonical JSON format

Implementations SHOULD reject requests with incompatible protocol versions.

## Appendix B: Migration from v1

v1 → v2 migration notes:
- Trust decay formula changed: `direct*0.7 + transitive*0.3` → `direct*1.0 + depth2*0.5 + depth3+*0.25`
- AgentCard v2 adds `capabilities`, `security`, `endpoints`
- Policy engine adds pre-execution pipeline
- Evidence ledger adds Merkle root computation
- New packages: `@fides/guard`, `@fides/discovery`, `@fides/runtime`
