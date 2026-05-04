# Cross-Repo Primitive Map

This document maps key primitives across the five inspected repositories and determines the best source and action for each primitive in FIDES v2.

## Architecture Decisions (Context)

Before reading this map, the following decisions have been made:

1. **TS-first, Rust adapter-ready.** FIDES v2 is implemented in TypeScript/Node. AGIT's Rust core may be used later through adapters for evidence chain, hashing, canonicalization, or other performance-critical primitives.
2. **OAPS concepts are ported into FIDES, not imported as a runtime dependency.** OAPS remains the spec/source of semantic compatibility. FIDES owns the runtime types.
3. **Sardis contributes generic patterns only:** policy-before-execution, guardrails, evidence ledger, approvals, kill switch, high-risk action handling. Sardis payment-specific domain models stay in Sardis: stablecoins, MPC wallets, payment rails, merchants, compliance, spending limits.
4. **FIDES owns the generic authority/trust/evidence layer.** Sardis owns the payment-specific authority model.
5. **Effect may be used for internal runtime orchestration** (service layers, typed errors, workflows, discovery/provider orchestration, daemon, CLI workflows, DHT/relay/registry orchestration).
6. **Protocol objects, crypto, canonical JSON, signing primitives, and public schemas must remain framework-agnostic.**
7. **Public SDK should expose Promise-based APIs, with optional Effect-native APIs later.**

---

## Primitive Map

| Primitive | FIDES | AGIT | OSP | OAPS | Sardis | Best source | Action |
|-----------|-------|------|-----|------|--------|-------------|--------|
| **Agent identity** | `did:fides:<base58>` (`packages/sdk/src/identity/did.ts`) | FIDES integration | None | `ActorRef` (`packages/core/src/index.ts:36`) | `KYA` (`packages/sardis-compliance/src/sardis_compliance/kya.py`) | FIDES | Extend with publisher + principal identity |
| **Publisher identity** | Not found | Not found | Not found | `ActorCard.publisher` (conceptual) | Not found | OAPS concept | Create new in FIDES |
| **Principal identity** | Not found | Not found | `principal_id` (spec only) | `ActorRef` | Embedded in mandates | OAPS concept | Create new in FIDES |
| **DID / key format** | `did:fides:<base58>` | `FidesIdentity` | None | `actor_id` string | None | FIDES | Reuse, document W3C non-compliance |
| **Signing** | RFC 9421 + Ed25519 (`packages/sdk/src/signing/`) | Ed25519 DID-signed commits | Ed25519 (`osp-crypto`) | `Proof`, canonical JSON | Ed25519 policy attestation | FIDES | Reuse, extend for new object types |
| **HTTP message signatures** | Full implementation (`packages/sdk/src/signing/`) | Not found | Not found | Not found | Not found | FIDES | Reuse |
| **Trust attestation** | `createAttestation` (`packages/sdk/src/trust/attestation.ts`) | Trust-gated merge | Not found | `trust-attestation.json` schema | Not found | FIDES | Extend with capability-scoped attestations |
| **Trust graph** | BFS + scoring (`services/trust-graph/src/services/`) | Not found | Not found | Not found | Not found | FIDES | Extend with context-specific trust |
| **Reputation** | Direct + transitive (`services/trust-graph/src/services/scoring.ts`) | Not found | Not found | Not found | Not found | FIDES | Extend with capability-specific reputation |
| **Capability descriptor** | Basic in discovery (`packages/sdk/src/discovery/agent-client.ts`) | Not found | `ServiceOffering` (schema) | `CapabilityCard` (`packages/core/src/index.ts:81`) | Not found | OAPS | Port into FIDES |
| **Agent card** | `AgentCard` (`packages/shared/src/types.ts`) | Not found | `ServiceManifest` | `ActorCard` (`packages/core/src/index.ts:68`) | Agent cards in `sardis-a2a` | OAPS + FIDES | Merge concepts, port into FIDES |
| **Discovery** | Discovery service + well-known (`services/discovery/`) | Not found | `discover()` methods | `.well-known/aicp.json` | Not found | FIDES + OAPS | Extend FIDES with OAPS discovery patterns |
| **Well-known discovery** | `/.well-known/fides.json` | Not found | Not found | `/.well-known/aicp.json` | Not found | FIDES + OAPS | Merge both paths into FIDES |
| **Hosted registry** | Not found | Not found | `osp-registry` (Axum, SQLite) | Not found | Not found | OSP concept | Port concept into FIDES (TypeScript/Hono) |
| **Public registry API** | Not found | Not found | Registry routes (`osp-registry/src/routes.rs`) | Not found | Not found | OSP concept | Create new in FIDES |
| **Private registry mode** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Relay-based discovery** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **DHT-based discovery** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Federation-ready registry peering** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Delegation token** | Not found | Not found | Not found | `DelegationToken` (`packages/core/src/index.ts:117`) | Embedded in `mandate_tree.py` | OAPS | Port into FIDES |
| **Session grant** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Policy bundle** | Stub (`services/policy-engine/stub/policies.json`) | `GuardChain` (`guard.rs`) | Not found | `PolicyBundle` (`packages/policy/src/index.ts:24`) | `policy_dsl.py` | OAPS | Port into FIDES |
| **Policy engine** | Stub only | `GuardChain`, `ApprovalStore` | Not found | `evaluatePolicy()` (`packages/policy/src/index.ts:162`) | `pre_execution_pipeline.py` | OAPS + Sardis patterns | Port OAPS evaluator + Sardis pipeline pattern |
| **Intent** | Not found | Not found | Not found | `Intent` (`packages/core/src/index.ts:93`) | `mandates.py` | OAPS | Port into FIDES |
| **Evidence event** | Not found | Hash-chained audit log (`repo.rs:653-698`) | Not found | `EvidenceEvent` (`packages/core/src/index.ts:272`) + `EvidenceChain` | `policy_evidence.py`, ledger | OAPS + AGIT | Port OAPS evidence + AGIT hash-chain |
| **Hash chain** | SHA-256 for Content-Digest | `compute_audit_hash` (`repo.rs:653-698`) | Not found | `EvidenceChain` (`packages/evidence/src/index.ts`) | Merkle ledger | AGIT + OAPS | Merge AGIT chaining + OAPS schema |
| **Merkle proof** | Not found | `MerkleNode` (`state.rs:192-317`) | Not found | Not found | `merkle_tree.py` | AGIT + Sardis | Port concept for evidence verification |
| **Revocation** | `createRevocation` (`rotation.ts`) — data only | Not found | Not found | Not found | Not found | FIDES | Extend into active revocation system |
| **Incident** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Runtime attestation** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **TEE** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Approval workflow** | Not found | `ApprovalStore` (`approval.rs`) | Not found | `ApprovalRequest`/`ApprovalDecision` (`packages/core/src/index.ts:141-154`) | `approval_service.py` | OAPS + AGIT | Port OAPS primitives + AGIT guard pattern |
| **Kill switch** | Not found | Not found | Not found | Not found | `kill_switch.py` | Sardis | Port concept, genericize in FIDES |
| **Service lifecycle** | Not found | Not found | `ProvisionRequest`/`ProvisionResponse` | Not found | Not found | OSP concept | Port concept for agent lifecycle |
| **Provisioning** | Not found | Not found | `provision()` (SDKs) | Not found | Not found | OSP concept | Port concept for agent registration |
| **Rotation** | `rotateKey` (DID-changing) | Not found | `rotateCredentials()` | Not found | Not found | FIDES + OSP | Extend FIDES key rotation + credential rotation |
| **Deprovisioning** | Not found | Not found | `deprovision()` (SDKs) | Not found | Not found | OSP concept | Port concept for agent deregistration |
| **CLI** | `fides` CLI (`packages/cli/`) | `agit` CLI (`python/agit/cli/app.py`) | `osp` CLI (mostly stubs) | Python conformance CLI | `sardis` CLI (Python) | FIDES | Extend FIDES CLI |
| **SDK** | `@fides/sdk` (`packages/sdk/`) | Python + TS SDKs | `@osp/client`, Go SDK | `@oaps/core` etc. | `@sardis/sdk`, `sardis-sdk-python` | FIDES | Extend FIDES SDK |
| **Examples** | Limited | 16 demos | YAML examples | 100+ JSON payloads | Many Python/TS demos | FIDES + all | Create new FIDES examples |
| **Tests** | Good coverage (`packages/sdk/test/`, `services/*/test/`) | Rust + Python + TS tests | Conformance tests (Python) | Node built-in test runner | 208 test files | FIDES | Extend FIDES test suite |
| **Docs** | `docs/` (architecture, protocol spec) | `ARCHITECTURE.md`, `docs/` | `spec/`, `docs/` | `spec/`, `SPEC.md` | `docs-site/`, business docs | FIDES + OAPS spec | Extend FIDES docs |
| **Canonical object signing** | Partial (HTTP signatures) | `canonical_serialize` (`hash.rs`) | `canonicalJson` (`crypto.ts`) | `canonicalJson` (`core/src/index.ts`) | Not found | AGIT + OAPS | Create unified canonical signing model |
| **Version negotiation** | Not found | Not found | Not found | `negotiateVersion` (`core/src/index.ts:512`) | Not found | OAPS | Port into FIDES |
| **Typed error vocabulary** | `FidesError` hierarchy (`packages/shared/src/errors.ts`) | `AgitError` (`error.rs`) | `ErrorResponse` schema | `ErrorObject` (`core/src/index.ts:253`) | Exception hierarchy | FIDES + OAPS | Extend FIDES errors with OAPS categories |
| **Privacy model for evidence** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Trust explainability** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Adversarial simulation** | Not found | Not found | Not found | Not found | Not found | None | Create new in FIDES |
| **Capability ontology** | Not found | Not found | `ServiceManifest` taxonomy | `CapabilityCard` | Not found | OAPS | Port into FIDES |
| **Risk taxonomy** | Not found | `BlastRadiusReport` / `RiskLevel` | Not found | `compareRiskClass` | Anomaly engine | AGIT + Sardis | Port concepts into FIDES |
| **Adapter interfaces** | A2A converter (`packages/sdk/src/discovery/a2a.ts`) | FIDES, A2A, MCP, LangGraph integrations | MCP server | MCP, A2A, x402, auth-web adapters | A2A, MCP, protocol verifiers | All | Create unified adapter framework in FIDES |

---

## Action Legend

| Action | Meaning |
|--------|---------|
| **Reuse existing** | Use FIDES implementation as-is or with minor tweaks |
| **Extend existing** | Build on top of FIDES implementation, add new features |
| **Port from another repo** | Take concept/type/algorithm from another repo, reimplement in FIDES namespace |
| **Create new** | No suitable source found; build from scratch |
| **Leave as adapter-ready** | Define interface, expect external implementation |
| **Leave as spec-complete** | Document the interface/protocol, no implementation yet |

---

## Recommended Priority Order

1. **Reuse FIDES identity + signing** — solid foundation
2. **Port OAPS core primitives** — DelegationToken, PolicyBundle, EvidenceEvent, ActorCard, CapabilityCard, ApprovalRequest/Decision
3. **Port AGIT hash-chain semantics** — for evidence ledger integrity
4. **Port Sardis patterns** — pre-execution pipeline, kill switch, approval flow
5. **Port OSP concepts** — registry pattern, service lifecycle, credential rotation
6. **Create new** — session grants, runtime attestation, TEE, DHT/relay/federation, incidents, adversarial simulation
7. **Leave as adapter-ready** — MCP, A2A, x402, AP2, OSP, Sardis runtime adapters
