# FIDES v2 / Agent Trust Fabric — Architecture

## 1. Should FIDES Become the Main Home for Agent Trust Fabric?

**Yes.**

FIDES is the only repository among the five with a complete runtime: services (discovery, trust-graph), SDK (`@fides/sdk`), CLI (`fides`), tests, CI/CD, and Docker deployment. AGIT, OSP, OAPS, and Sardis each have significant gaps (stub implementations, missing CI, incomplete Rust core, or payment-specific scope creep). FIDES should evolve into the Agent Trust Fabric, absorbing reusable concepts from the other repos while keeping their domain-specific implementations separate.

---

## 2. Which Packages Should Remain in FIDES?

All existing FIDES packages remain and are extended:

- `@fides/sdk` — Core protocol (identity, signing, trust, discovery)
- `@fides/shared` — Shared types, constants, errors
- `@fides/cli` — CLI extended with new commands

New packages:

- `@fides/core` — Identity v2, AgentCards, capabilities, delegation, policy, evidence primitives
- `@fides/discovery` — Discovery provider architecture (local, well-known, registry, relay, DHT)
- `@fides/runtime` — Runtime attestation, TEE adapters, session grants
- `@fides/evidence` — Evidence ledger, hash chain, event streaming

Services:

- `discovery` — Extended with registry + federation
- `trust-graph` — Extended with reputation v2 + incidents
- `policy-engine` — Stub → full implementation
- `registry` — New (or merged into discovery)
- `relay` — New mock relay server
- `agentd` — New local daemon

---

## 3. Which Concepts Should Be Imported from AGIT?

- **Hash-chained audit log** (`compute_audit_hash` pattern) → `@fides/evidence`
- **Canonical JSON + SHA-256 content addressing** → `@fides/core` canonical object signing
- **Guard framework** (Allow/Warn/Block) → `@fides/policy` guard concept
- **ApprovalStore pattern** → `@fides/core` ApprovalRequest/ApprovalDecision
- **Merkle tree construction** → `@fides/evidence` Merkle proof support

**Not imported:** Full VCS (commit/branch/merge), SQLite/Postgres/S3 storage backends, Python ExecutionEngine, three-way merge.

---

## 4. Which Concepts Should Be Imported from OSP?

- **Registry server pattern** (Axum-based) → FIDES registry service (Hono-based)
- **Service lifecycle semantics** (provision, rotate, deprovision, status) → FIDES agent lifecycle
- **JSON Schema discipline** → All FIDES v2 protocol objects get JSON Schema
- **Credential rotation pattern** → FIDES key rotation and delegation token rotation
- **URI scheme pattern** (`osp://`) → FIDES `fides://` URI scheme for referencing agents/capabilities

**Not imported:** Provider adapters, service provisioning, encrypted credential delivery, payment rails.

---

## 5. Which Concepts Should Be Imported from OAPS?

- **ActorCard** → FIDES `AgentCard`
- **CapabilityCard** → FIDES `CapabilityDescriptor`
- **DelegationToken** → `@fides/core` DelegationToken
- **PolicyBundle + evaluatePolicy** → `@fides/policy` PolicyBundle + evaluator
- **EvidenceEvent + EvidenceChain** → `@fides/evidence`
- **ApprovalRequest + ApprovalDecision** → `@fides/core`
- **Version negotiation** (`negotiateVersion`) → `@fides/core`
- **Error taxonomy** (`ErrorObject` with 12 categories) → `@fides/shared` error hierarchy
- **Handshake protocol** → `@fides/runtime` session establishment
- **Well-known discovery** (`.well-known/aicp.json`) → FIDES `.well-known/fides.json`

**Not imported:** Full AICP interaction/task lifecycle, WebSocket binding, payment adapters (x402, MPP, AP2), commerce domain schemas.

---

## 6. Which Concepts Should Be Imported from Sardis?

- **Pre-execution pipeline pattern** → `@fides/policy` PolicyEngine
- **Kill switch primitive** → `@fides/runtime` KillSwitch
- **Approval flow pattern** → `@fides/core` ApprovalRequest/ApprovalDecision
- **Evidence ledger pattern** → `@fides/evidence`
- **Mandate chain abstraction** → `@fides/core` MandateChain
- **High-risk action handling** → `@fides/policy` risk taxonomy

**Not imported:** Payment-specific models (stablecoin, MPC wallet, spending limits, merchants, compliance/KYA/AML, AP2/TAP/x402 settlement).

---

## 7. What Should Remain Separate and Only Be Integrated Through Adapters?

| Domain | Repo | Adapter Interface |
|--------|------|-------------------|
| Agent VCS / state versioning | AGIT | `AgitEvidenceAdapter` |
| Service provisioning / provider adapters | OSP | `OSPProvisioningAdapter` |
| Payment execution / stablecoin | Sardis | `SardisPaymentAdapter` |
| A2A protocol runtime | Google A2A | `A2AAdapter` |
| MCP server runtime | MCP | `MCPAdapter` |
| x402 payment challenges | x402 | `X402Adapter` |
| TEE attestation (Nitro, SGX, SEV) | Vendor SDKs | `TEEAttestationAdapter` |
| On-chain anchoring | EVM / Solana | `LedgerAnchorAdapter` |

---

## 8. Final Package Structure

```
fides/
├── packages/
│   ├── @fides/sdk/              # Existing: identity, signing, trust, discovery client
│   ├── @fides/shared/           # Existing: types, constants, errors (extended)
│   ├── @fides/cli/              # Existing: CLI (extended)
│   ├── @fides/core/             # NEW: identity v2, AgentCard, CapabilityDescriptor,
│   │                             #      DelegationToken, SessionGrant, PolicyBundle,
│   │                             #      ApprovalRequest, ApprovalDecision, MandateChain,
│   │                             #      canonical object signing, version negotiation
│   ├── @fides/discovery/        # NEW: discovery providers (local, well-known, registry,
│   │                             #      relay, DHT), provider orchestration
│   ├── @fides/runtime/          # NEW: runtime attestation, TEE adapters, session grants,
│   │                             #      kill switch
│   ├── @fides/evidence/         # NEW: evidence ledger, hash chain, Merkle proofs,
│   │                             #      event streaming, privacy model
│   └── @fides/policy/           # NEW: policy engine, risk taxonomy, guardrails,
│                                 #      pre-execution pipeline
├── services/
│   ├── discovery/               # Extended: identity + agent registry, well-known,
│   │                             #      federation peering
│   ├── trust-graph/             # Extended: reputation v2, incident penalties,
│   │                             #      novelty penalties, runtime safety score
│   ├── policy-engine/           # Full implementation: evaluate policies, approvals,
│   │                             #      kill switch enforcement
│   ├── registry/                # NEW: hosted registry (public/private mode)
│   ├── relay/                   # NEW: mock relay server for discovery
│   └── agentd/                  # NEW: local daemon (HTTP API, SDK proxy)
├── apps/
│   └── web/                     # Future: trust fabric dashboard
├── schemas/                     # NEW: JSON Schemas for all protocol objects
├── examples/                    # NEW: demo agents, end-to-end scripts
└── tests/
    ├── e2e/                     # Extended: full trust fabric flows
    └── adversarial/             # NEW: adversarial simulation harness
```

---

## 9. Final Protocol Model

### Protocol Object Hierarchy

```
SignedObject (abstract)
├── AgentCard
├── CapabilityDescriptor
├── TrustAttestation
├── DelegationToken
├── SessionGrant
├── PolicyBundle
├── ApprovalRequest
├── ApprovalDecision
├── EvidenceEvent
├── RevocationRecord
├── IncidentRecord
├── RuntimeAttestation
└── MandateChain
```

### Canonical Signing Model

Every signed protocol object follows this pattern:

```typescript
interface SignedObject<T> {
  payload: T;
  proof: {
    type: "Ed25519Signature2024";
    created: string;          // ISO 8601
    verificationMethod: DID;  // did:fides:<pubkey>
    proofPurpose: "assertionMethod" | "authentication" | "delegation" | "capabilityInvocation";
    canonicalizationAlgorithm: "https://fides.dev/canonical-json/v1";
    proofValue: string;       // base58-encoded signature
  };
}
```

Canonicalization: deterministic JSON (sorted keys, no whitespace, explicit nulls) → SHA-256 digest → Ed25519 sign.

### Protocol Version

- Current protocol version: `fides-v2.0.0`
- Version negotiation: OAPS `negotiateVersion` pattern adapted
- Compatibility promise: minor versions are additive; major versions require explicit handshake

---

## 10. Implementation Order

### Phase 0: Foundation (Milestones 1-3)
1. Stabilize FIDES core (fix spec/impl discrepancies)
2. Identity v2 (agent, publisher, principal)
3. AgentCards and capabilities

### Phase 1: Discovery & Registry (Milestones 4-6)
4. Discovery provider architecture
5. Registry and relay
6. DHT discovery

### Phase 2: Trust & Policy (Milestones 7-9)
7. Trust and reputation v2
8. Policy engine
9. Delegation and sessions

### Phase 3: Evidence & Runtime (Milestones 10-12)
10. Evidence ledger
11. Revocation and incidents
12. Runtime attestation

### Phase 4: Developer Surface (Milestones 13-15)
13. CLI and API
14. Examples and full demo
15. Docs and tests

---

## Protocol Layers

### 1. Identity Layer
- AgentIdentity, PublisherIdentity, PrincipalIdentity
- Domainless individual identity
- Platform-hosted identity
- Domain-verified identity
- Organization-verified identity
- Trust anchors

### 2. Attestation Layer
- Trust attestation creation/verification
- Signed AgentCards
- Capability attestations
- Canonical object signing

### 3. Agent Metadata Layer
- AgentCard schema and validation
- CapabilityDescriptor schema and validation
- Endpoint metadata
- Transport metadata
- Policy requirements

### 4. Discovery Layer
- LocalDiscoveryProvider
- WellKnownDiscoveryProvider
- RegistryDiscoveryProvider
- RelayDiscoveryProvider
- DHTDiscoveryProvider
- Provider orchestration

### 5. Trust Layer
- Trust graph v2
- Direct trust edges
- Transitive trust with decay
- Trust anchors

### 6. Reputation Layer
- Capability-specific reputation
- Context-specific trust
- Incident penalties
- Novelty penalties
- Runtime safety score

### 7. Policy Layer
- PolicyBundle evaluation
- Risk taxonomy
- Guardrails (Allow / Warn / Block)
- Pre-execution pipeline
- High-risk capability handling
- Revoked agent denial
- Invalid runtime attestation denial

### 8. Delegation Layer
- DelegationToken
- SessionGrant
- Scoped authority
- Expiry
- Nonce / replay protection
- Audience restriction

### 9. Invocation Layer
- Capability invocation authorization
- Mandate chain verification
- Approval gating
- Kill switch enforcement

### 10. Evidence Layer
- EvidenceEvent
- Hash chain
- Merkle proofs
- Privacy model (public, private, redacted, hash-only)
- Evidence export

### 11. Revocation Layer
- RevocationRecord
- CRL-style lists
- On-chain revocation registry (adapter)
- Propagation interfaces

### 12. Incident Layer
- IncidentRecord
- Classification taxonomy
- Policy impact
- Trust impact
- Automated response

### 13. Registry Layer
- Hosted registry (public/private)
- Federation peering
- Relay discovery
- DHT pointers

### 14. Transport Layer
- HTTP + RFC 9421 signatures
- WebSocket (adapter-ready)
- DHT/relay (adapter-ready)

### 15. Developer Layer
- CLI (`fides`)
- SDK (`@fides/sdk`, `@fides/core`)
- Local daemon (`agentd`)
- Examples and demos
- Documentation and specs

---

## Protocol Hardening Components

### 1. Canonical Object Signing Model
- **Schema:** `schemas/signed-object.schema.json`
- **Interface:** `CanonicalSigner<T>` / `CanonicalVerifier<T>` in `@fides/core`
- **Docs:** `docs/protocol/canonical-signing.md`
- **Implementation:** Pure TypeScript, `@noble/ed25519`, deterministic JSON canonicalization
- **Integration:** All protocol objects inherit from `SignedObject`

### 2. Protocol Version Negotiation
- **Schema:** `schemas/version-negotiation.schema.json`
- **Interface:** `negotiateVersion(supported: VersionSupport[], requested: VersionSupport[]): VersionNegotiationResult`
- **Docs:** `docs/protocol/version-negotiation.md`
- **Implementation:** Ported from OAPS `@oaps/core`
- **Integration:** Handshake protocol, discovery, WebSocket binding

### 3. Stable Typed Error Vocabulary
- **Schema:** `schemas/error-object.schema.json`
- **Interface:** `FidesError` hierarchy extended with OAPS categories
- **Docs:** `docs/protocol/errors.md`
- **Implementation:** `@fides/shared/src/errors.ts` extended
- **Integration:** All packages throw typed errors; CLI maps to exit codes

### 4. Privacy Model for Evidence
- **Schema:** `schemas/evidence-privacy.schema.json`
- **Interface:** `EvidencePrivacy { level: "public" | "private" | "redacted" | "hash-only"; redactionKey?: string; }`
- **Docs:** `docs/protocol/evidence-privacy.md`
- **Implementation:** `@fides/evidence` applies privacy level before appending to chain
- **Integration:** Evidence export, compliance, audit

### 5. Trust and Policy Explainability
- **Schema:** `schemas/decision-explanation.schema.json`
- **Interface:** `DecisionExplanation { decision: "allow" | "deny" | "approve-required"; factors: ExplanationFactor[]; }`
- **Docs:** `docs/protocol/explainability.md`
- **Implementation:** Policy engine and trust graph return explanations with every decision
- **Integration:** CLI `fides explain`, SDK `policy.evaluateWithExplanation()`

### 6. Adversarial Simulation Harness
- **Schema:** `schemas/adversarial-scenario.schema.json`
- **Interface:** `SimulationHarness { run(scenario: Scenario): SimulationResult; }`
- **Docs:** `docs/testing/adversarial.md`
- **Implementation:** `tests/adversarial/` — Sybil attacks, replay attacks, policy bypass attempts
- **Integration:** CI runs adversarial suite on every PR

### 7. Capability Ontology and Risk Taxonomy
- **Schema:** `schemas/capability-ontology.schema.json`, `schemas/risk-taxonomy.schema.json`
- **Interface:** `CapabilityClassifier`, `RiskAssessor`
- **Docs:** `docs/protocol/capabilities.md`, `docs/protocol/risk.md`
- **Implementation:** `@fides/policy` — deterministic risk classification for every capability
- **Integration:** Policy engine, approval gating, kill switch

### 8. ApprovalRequest and ApprovalDecision Primitives
- **Schema:** `schemas/approval-request.schema.json`, `schemas/approval-decision.schema.json`
- **Interface:** `ApprovalRequest`, `ApprovalDecision` in `@fides/core`
- **Docs:** `docs/protocol/approvals.md`
- **Implementation:** Ported from OAPS, extended with FIDES signing
- **Integration:** Policy engine, high-risk action handling, SDK

### 9. Kill Switch Primitives
- **Schema:** `schemas/kill-switch.schema.json`
- **Interface:** `KillSwitch { engage(target: KillSwitchTarget): void; disengage(target: KillSwitchTarget): void; isEngaged(target: KillSwitchTarget): boolean; }`
- **Docs:** `docs/protocol/kill-switch.md`
- **Implementation:** `@fides/runtime` — in-memory + persistent state
- **Integration:** Policy engine, daemon, CLI `fides killswitch`

### 10. Adapter Interfaces
- **Schema:** `schemas/adapter-manifest.schema.json`
- **Interface:** `ProtocolAdapter { readonly protocol: string; handshake(): Promise<void>; invoke(capability: string, params: unknown): Promise<unknown>; }`
- **Docs:** `docs/adapters/README.md`
- **Implementation:** `@fides/core` base adapter class + per-protocol adapters in `packages/adapters/`
- **Integration:** MCP, A2A, OAPS, OSP, AP2, x402, Sardis
