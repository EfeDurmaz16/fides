# Gap Analysis

This document classifies the status of every required feature for FIDES v2 / Agent Trust Fabric.

## Status Legend

| Status | Meaning |
|--------|---------|
| ✅ already implemented | Exists in FIDES today, usable |
| 🟡 partially implemented | Exists but incomplete, stubbed, or has known issues |
| 📦 exists in another repo | Implemented in AGIT, OSP, OAPS, or Sardis |
| 🔀 should be ported | Concept exists elsewhere, needs porting into FIDES |
| ❌ missing | Not found in any repo |
| ⏭️ not needed | Out of scope for FIDES v2 |
| ⚠️ dangerous / should avoid | Known anti-pattern or security risk |

---

## Feature Gap Matrix

| # | Feature | Status | Notes |
|---|---------|--------|-------|
| 1 | **Local daemon** | ❌ missing | No `agentd` exists |
| 2 | **Agent identity** | ✅ already implemented | Ed25519 + DID in `@fides/sdk` |
| 3 | **Publisher identity** | ❌ missing | No concept of publisher separate from agent |
| 4 | **Principal identity** | ❌ missing | No concept of acting principal |
| 5 | **Domainless individual identity** | 🟡 partially implemented | FIDES DID is domainless but lacks individual attestation |
| 6 | **Platform-hosted identity** | ❌ missing | No hosted identity provider |
| 7 | **Domain-verified identity** | ❌ missing | No DNS/ domain attestation |
| 8 | **Organization-verified identity** | ❌ missing | No org attestation |
| 9 | **Trust anchors** | 🟡 partially implemented | Trust graph exists but no explicit anchor primitive |
| 10 | **Signed AgentCards** | 🟡 partially implemented | `AgentCard` type exists but no canonical signing model |
| 11 | **Capability descriptors** | 🟡 partially implemented | Basic capabilities in discovery, no formal descriptor |
| 12 | **Local discovery** | ❌ missing | No mDNS / local network discovery |
| 13 | **Local network discovery interface** | ❌ missing | No LAN discovery protocol |
| 14 | **Well-known discovery** | ✅ already implemented | `/.well-known/fides.json` supported |
| 15 | **Hosted registry** | ❌ missing | Discovery service is centralized PostgreSQL, not a public registry |
| 16 | **Public registry API** | ❌ missing | No public registry endpoints |
| 17 | **Private registry mode** | ❌ missing | No private/enterprise registry concept |
| 18 | **Relay-based discovery** | ❌ missing | No relay infrastructure |
| 19 | **DHT-based discovery** | ❌ missing | No DHT implementation |
| 20 | **Federation-ready registry peering** | ❌ missing | No federation |
| 21 | **Trust graph** | ✅ already implemented | BFS traversal + scoring in `services/trust-graph/` |
| 22 | **Reputation engine** | ✅ already implemented | Direct + transitive scoring |
| 23 | **Capability-specific reputation** | ❌ missing | Reputation is global, not per-capability |
| 24 | **Trust scoring** | ✅ already implemented | `scoring.ts` |
| 25 | **Policy engine** | 🟡 partially implemented | Stubbed service only |
| 26 | **Delegation tokens** | ❌ missing | Not found in FIDES |
| 27 | **Session grants** | ❌ missing | Not found in FIDES |
| 28 | **Capability invocation** | 🟡 partially implemented | HTTP signing covers auth but not capability-level authz |
| 29 | **Evidence ledger** | ❌ missing | Not found in FIDES |
| 30 | **Hash-chained evidence events** | ❌ missing | Not found in FIDES; AGIT has hash-chained audit log |
| 31 | **Revocation records** | 🟡 partially implemented | `createRevocation` exists as data structure only |
| 32 | **Incident records** | ❌ missing | Not found |
| 33 | **Runtime attestation** | ❌ missing | Not found |
| 34 | **TEE-ready attestation** | ❌ missing | Not found |
| 35 | **Mock TEE provider** | ❌ missing | Not found |
| 36 | **Container image attestation provider interface** | ❌ missing | Not found |
| 37 | **Reproducible build attestation interface** | ❌ missing | Not found |
| 38 | **GitHub attestation** | ❌ missing | Not found |
| 39 | **Email attestation** | ❌ missing | Not found |
| 40 | **Domain attestation** | ❌ missing | Not found |
| 41 | **Package registry attestation** | ❌ missing | Not found |
| 42 | **Wallet attestation** | ❌ missing | Not found |
| 43 | **Passkey identity interface** | ❌ missing | Not found |
| 44 | **CLI** | ✅ already implemented | `fides` CLI exists |
| 45 | **Local HTTP API** | 🟡 partially implemented | Discovery and trust-graph services have HTTP APIs but no unified local API |
| 46 | **TypeScript SDK** | ✅ already implemented | `@fides/sdk` |
| 47 | **Example agents** | 🟡 partially implemented | Some examples in AGIT and Sardis, limited in FIDES |
| 48 | **End-to-end demo** | 🟡 partially implemented | `tests/e2e/full-flow.test.ts` exists but is basic |
| 49 | **Threat model** | ❌ missing | Not found |
| 50 | **Protocol documentation** | ✅ already implemented | `docs/protocol-spec.md`, `docs/architecture.md` |
| 51 | **Test suite** | ✅ already implemented | Good coverage in SDK and services |
| 52 | **Migration/versioning system** | 🟡 partially implemented | No explicit migration system; OAPS has version negotiation |
| 53 | **Security review checklist** | ❌ missing | Not found |
| 54 | **Future production hardening notes** | ❌ missing | Not found |

---

## Gap Summary by Layer

### Identity Layer
- **Strong:** Basic Ed25519 DID identity, keystore, key rotation
- **Weak:** No publisher, principal, or multi-level identity. No domain/org attestation. No trust anchors.
- **Action:** Extend identity system with AgentIdentity, PublisherIdentity, PrincipalIdentity, and attestation providers.

### Attestation Layer
- **Strong:** RFC 9421 HTTP signatures, trust attestations
- **Weak:** No canonical object signing for non-HTTP objects. No capability-specific attestations.
- **Action:** Implement `CanonicalSigner` for all protocol objects.

### Agent Metadata Layer
- **Strong:** `AgentCard` type exists, A2A compatibility
- **Weak:** No formal `CapabilityDescriptor`. No signed AgentCards. No policy requirements metadata.
- **Action:** Port OAPS `ActorCard` + `CapabilityCard` into FIDES `AgentCard` + `CapabilityDescriptor`.

### Discovery Layer
- **Strong:** Well-known discovery, identity resolver with caching
- **Weak:** No local, relay, DHT, or registry discovery. No federation.
- **Action:** Build provider architecture with 5 providers.

### Trust Layer
- **Strong:** Trust graph, BFS traversal, reputation scoring
- **Weak:** Spec/implementation mismatch in scoring formula. No time-based decay. No negative attestations.
- **Action:** Fix discrepancies, add capability-specific reputation, time decay, negative attestations.

### Policy Layer
- **Strong:** Stub exists
- **Weak:** No actual policy engine. No runtime enforcement. No guardrails.
- **Action:** Port OAPS policy evaluator + Sardis pre-execution pipeline.

### Delegation Layer
- **Strong:** Nothing
- **Weak:** No delegation tokens, no session grants, no scoped authority.
- **Action:** Port OAPS DelegationToken, create SessionGrant.

### Evidence Layer
- **Strong:** Nothing
- **Weak:** No evidence system at all.
- **Action:** Port OAPS EvidenceEvent + EvidenceChain, add AGIT hash-chain semantics, Merkle proofs.

### Revocation Layer
- **Strong:** `createRevocation` data structure
- **Weak:** No active revocation service, no CRL, no propagation.
- **Action:** Build RevocationRecord, CRL service, propagation interfaces.

### Incident Layer
- **Strong:** Nothing
- **Weak:** No incident system.
- **Action:** Create IncidentRecord, classification, automated response.

### Runtime Layer
- **Strong:** Nothing
- **Weak:** No runtime attestation, no TEE support.
- **Action:** Create RuntimeAttestation, MockTEEProvider, adapter interfaces.

### Developer Layer
- **Strong:** CLI, SDK, tests, docs
- **Weak:** No local daemon, limited examples, no adversarial tests.
- **Action:** Build `agentd`, add examples, add adversarial harness.

---

## Critical Gaps (Blockers for v2)

These gaps must be resolved before FIDES v2 can be considered functional:

1. **Identity v2** — Agent, publisher, principal separation
2. **Canonical object signing** — All protocol objects must be signed consistently
3. **Policy engine** — Runtime policy enforcement is core to "trust fabric"
4. **Delegation tokens** — Without delegation, there is no agent economy
5. **Evidence ledger** — Without evidence, behavior is not verifiable
6. **Revocation system** — Without revocation, compromised agents cannot be stopped
7. **Runtime attestation** — Without runtime proof, high-risk actions cannot be authorized

---

## Quick Wins (Low Effort, High Value)

1. **Fix spec/implementation discrepancies** — Trust decay formula, nonce protection docs
2. **Normalize package names** — `@fides/discovery`, `@fides/trust-graph`
3. **Port OAPS error taxonomy** — Extend `FidesError` with categories
4. **Port OAPS version negotiation** — Add to `@fides/core`
5. **Add hash-chain to evidence** — Simple SHA-256 chaining pattern from AGIT
6. **Add kill switch primitive** — Simple boolean flag + propagation from Sardis pattern
