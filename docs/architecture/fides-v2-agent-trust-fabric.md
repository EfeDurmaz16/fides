# FIDES v2 Agent Trust Fabric

FIDES v2 is the trust, authority, policy, delegation, runtime attestation, and evidence layer for agent-to-agent systems.

It is not an agent app store. It is not a naive agent directory. Discovery is only the first step. A discovered agent is a candidate, not an authority.

## Thesis

Agents should not just call each other. They should know:

- who they are calling,
- who published that agent,
- who the request is on behalf of,
- what capability is being requested,
- whether the agent is trusted for that specific capability,
- what policy applies,
- what authority was delegated,
- what runtime or build evidence exists,
- what revocations or incidents apply,
- what evidence is left behind.

Discovery without trust becomes spam.
Trust without authority becomes unsafe.
Authority without evidence becomes unauditable.

## ARP Analogy

ARP answers: "Who has this IP address?"

FIDES v2 answers: "Who can perform this capability under these constraints, and can they prove identity, trust, authority, safety, and evidence?"

Mapping:

- ARP resolves IP address to MAC address.
- FIDES resolves capability plus constraints to verified agent candidates.
- ARP assumes a local broadcast domain.
- FIDES supports local, well-known, registry, relay, DHT, and federation-ready discovery.
- ARP has weak trust.
- FIDES verifies signatures, AgentCards, publisher identity, trust anchors, reputation, runtime attestation, revocations, incidents, and policy constraints.
- ARP returns an address.
- FIDES returns candidates, explanations, policy decisions, scoped session grants, and evidence.

The ARP-like step is only discovery. Authority comes later through policy and session grants.

## Hard Constraints

- FIDES v2 is TS-first and Rust adapter-ready.
- AGIT Rust may later be used through adapters for evidence chains, canonicalization, hashing, Merkle/DAG primitives, and performance-sensitive work.
- Rust is not required for the first working v2.
- OAPS concepts are ported into FIDES-owned runtime types.
- FIDES must not depend on `@oaps/core` as a runtime dependency.
- Sardis contributes generic patterns only: policy-before-execution, guardrails, evidence, approvals, kill switch, high-risk handling, mandate-chain abstraction.
- Payment-specific domain stays in Sardis: stablecoins, MPC wallets, rails, merchants, compliance, spending limits, payment-specific mandates.
- Effect may be used internally for services, workflows, typed errors, dependency injection, provider orchestration, daemon and CLI workflows.
- Protocol objects, schemas, crypto, canonical JSON, signing, AgentCards, EvidenceEvents, DHT records, SessionGrants, attestations, revocations, and incidents remain framework-agnostic.
- Public SDK APIs are Promise-based. Effect-native APIs may be added later.

## Current Baseline

The repo is already a TypeScript monorepo with:

- `packages/core` for identity, signing, AgentCards, capabilities, delegation, sessions, revocation, incidents, trust anchors, domain/passkey verification.
- `packages/evidence` for hash-chained evidence and Merkle roots.
- `packages/runtime` for MockTEE, attestation adapters, and kill switch.
- `packages/discovery` for local, well-known, registry, relay, and DHT providers.
- `packages/policy` and `packages/guard` for policy and pre-execution decisions.
- `packages/sdk` and `packages/cli` for developer surfaces.
- `services/agentd`, `discovery`, `trust-graph`, `registry`, `relay`, `policy-engine`, and `platform-api`.

The baseline is strong but uneven: several objects are present as prototypes, not final protocol contracts.

## Protocol Layers

### 1. Identity Layer

Owns:

- `AgentIdentity`
- `PublisherIdentity`
- `PrincipalIdentity`
- domainless identity
- platform-hosted identity
- domain-verified identity
- organization-verified identity
- trust anchors

Rules:

- Domain must not be required.
- Identity must not equal trust.
- A valid cryptographic identity can still be low trust.
- Publisher identity and principal identity must be separate from agent identity.

Current anchors:

- `packages/core/src/identity.ts`
- `packages/core/src/trust-anchor.ts`
- `packages/core/src/domain-verifier.ts`
- `packages/core/src/passkey.ts`

Required hardening:

- Replace loose identity creation with real Ed25519 keypair issuance.
- Add publisher type taxonomy.
- Add non-domain trust anchors: GitHub, email, npm, PyPI, wallet, passkey, organization invitation, runtime attestation, build attestation, peer attestation.

### 2. Attestation Layer

Owns:

- trust attestations,
- identity attestations,
- runtime attestations,
- build/container attestations,
- peer attestations,
- MockTEE.

Rules:

- Attestation is evidence, not automatic authority.
- High-risk capabilities may require valid runtime attestation or approval.

Current anchors:

- `packages/runtime/src/index.ts`
- `packages/core/src/trust-anchor.ts`

Required hardening:

- Add signed `Attestation` and `RuntimeAttestation` protocol objects.
- Add `NullAttestationProvider`.
- Integrate runtime/build attestation into trust and policy scoring.

### 3. Agent Metadata Layer

Owns:

- signed AgentCards,
- capability descriptors,
- capability ontology,
- risk taxonomy,
- endpoint metadata,
- transport metadata,
- policy requirements.

Rules:

- AgentCards are signed metadata, not authority.
- Capability reputation is scoped by capability.

Current anchors:

- `packages/core/src/agent-card.ts`
- `packages/core/src/capability.ts`

Required hardening:

- Add required v2 AgentCard fields: agent id, publisher, public keys, trust anchors, runtime attestations, protocol versions, revocation URL/ref, expiry, signature.
- Add capability namespace/action/resource fields and supported controls.
- Add ontology entries and risk classes.

### 4. Discovery Layer

Owns:

- local discovery,
- well-known discovery,
- hosted/private/public registry discovery,
- relay discovery,
- DHT discovery,
- federation-ready discovery,
- discovery orchestration.

Rules:

- Discovery never grants authority.
- DHT and relay must never be trust sources.
- Discovery results must include verification and explainability.

Current anchors:

- `packages/discovery/src/provider.ts`
- `packages/discovery/src/orchestrator.ts`
- `packages/discovery/src/local-provider.ts`
- `packages/discovery/src/well-known-provider.ts`
- `packages/discovery/src/registry-provider.ts`
- `packages/discovery/src/relay-provider.ts`
- `packages/discovery/src/dht-provider.ts`

Required hardening:

- Change provider API from DID-only resolution to capability-query discovery.
- Verify signed records and AgentCards.
- Filter by version and capability compatibility.
- Compute trust and policy candidate explanations.
- Emit evidence for discovery.

### 5. Trust Layer

Owns:

- trust graph,
- trust score,
- trust bands,
- trust reasons,
- context-specific scoring,
- runtime safety score.

Rules:

- Trust score is a signal.
- Policy is the authority.

Current anchors:

- `services/trust-graph/src/services/trust-service.ts`
- `services/trust-graph/src/services/graph.ts`
- `services/trust-graph/src/services/capability-scoring.ts`

Required hardening:

- Add componentized `TrustResult`: IdentityScore, PublisherScore, TrustAnchorScore, CapabilityFitScore, EvidenceScore, PolicyComplianceScore, RuntimeSafetyScore, PeerAttestationScore, IncidentPenalty, NoveltyPenalty, ContextBoundaryPenalty.
- Add trust bands: unknown, low, medium, high, verified.
- Make explanations first-class and machine-readable.

### 6. Reputation Layer

Owns:

- capability-specific reputation,
- principal-specific reputation where possible,
- publisher-weighted reputation,
- incident penalty,
- novelty penalty,
- context boundary penalty.

Rules:

- No global popularity score.
- `calendar.schedule` reputation must not imply `payments.execute` reputation.

Current anchors:

- `services/trust-graph/src/db/migrations/003_capability_scoring.sql`
- `services/trust-graph/src/services/capability-scoring.ts`

Required hardening:

- Add time-aware and context-aware reputation record.
- Add publisher-weight and principal-scope inputs.
- Integrate incidents and revocations.

### 7. Policy Layer

Owns:

- policy-before-execution,
- guardrails,
- risk model,
- kill switch,
- approval model,
- pure evaluator,
- optional Effect workflow wrapper.

Rules:

- Every decision includes machine-readable reasons, human-readable reasons, required controls, and evidence refs.
- No policy decision may return only a boolean.
- Kill switch overrides normal trust and policy.

Current anchors:

- `packages/policy/src/index.ts`
- `packages/guard/src/index.ts`
- `services/policy-engine/src/index.ts`

Required hardening:

- Add decision actions: allow, deny, require_approval, dry_run_only, scope_limit, risk_limit.
- Add requested policy inputs.
- Normalize `approve-required` / `dry-run` compatibility names.
- Add first-class approval and kill switch objects.

### 8. Delegation Layer

Owns:

- `DelegationToken`,
- `SessionGrant`,
- scoped authority,
- expiry,
- audience restriction,
- nonce/replay protection,
- principal-to-agent delegation,
- agent-to-agent delegation.

Current anchors:

- `packages/core/src/delegation.ts`
- `packages/core/src/session-store.ts`
- `services/agentd/src/index.ts`

Required hardening:

- Add requested v2 `SessionGrant` fields.
- Bind session grants to policy hash and trust result hash.
- Sign grants with canonical model.
- Enforce replay protection consistently.

### 9. Invocation Layer

Owns:

- capability invocation,
- input validation,
- output validation,
- dry-run,
- approval-gated execution,
- policy-before-execution.

Current anchors:

- `packages/guard/src/index.ts`
- `services/agentd/src/index.ts`

Required hardening:

- Add signed `InvocationRequest` and `InvocationResult`.
- Verify `SessionGrant`.
- Validate schemas.
- Check revocations and kill switch.
- Emit evidence for every state transition.

### 10. Evidence Layer

Owns:

- EvidenceEvent,
- hash chain,
- verification,
- export,
- redacted/hash-only evidence,
- privacy model,
- tamper detection.

Rules:

- Default to hash-only or redacted for sensitive input/output.
- Store hashes and metadata by default.

Current anchors:

- `packages/evidence/src/index.ts`
- `services/agentd/src/storage.ts`

Required hardening:

- Add requested event fields and event taxonomy.
- Sign evidence events.
- Add evidence refs.
- Add Merkle proofs and stronger export format.
- Add AGIT adapter-ready interface.

### 11. Revocation Layer

Owns:

- key revocation,
- identity revocation,
- AgentCard revocation,
- capability revocation,
- session revocation,
- attestation revocation,
- publisher revocation.

Current anchors:

- `packages/core/src/revocation.ts`
- `services/agentd/src/index.ts`
- `services/trust-graph/src/db/migrations/002_revocations.sql`

Required hardening:

- Add revocation target taxonomy.
- Make revocations first-class signed protocol objects with schema versions.
- Propagate revocations across registry/relay/DHT/federation interfaces.

### 12. Incident Layer

Owns:

- incident records,
- severity,
- categories,
- evidence refs,
- resolution,
- trust/policy impact.

Current anchors:

- `packages/core/src/revocation.ts`
- `services/agentd/src/index.ts`
- `services/trust-graph/src/db/migrations/002_revocations.sql`

Required hardening:

- Add requested categories.
- Add resolution status.
- Integrate into trust, reputation, discovery filtering, and policy.

### 13. Registry Layer

Owns:

- hosted registry,
- public registry mode,
- private registry mode,
- signed RegistryIndexRecord,
- RegistryPeerRecord,
- federation peering,
- revocation/incident propagation.

Current anchors:

- `services/registry/src/`
- `packages/discovery/src/registry-provider.ts`

Required hardening:

- Add signed index and peer records.
- Add federation interfaces and local mock federation provider.
- Add propagation for revocations and incidents.

### 14. Transport Layer

Owns:

- HTTP API,
- relay protocol,
- DHT pointer resolution,
- adapter boundaries for MCP/A2A/OAPS/OSP/AP2/x402/Sardis.

Current anchors:

- `services/agentd/src/index.ts`
- `services/relay/src/index.ts`
- `packages/sdk/src/*/client.ts`

Required hardening:

- Add explicit adapter interfaces.
- Keep transport-specific signing separate from canonical protocol-object signing.

### 15. Runtime Layer

Owns:

- daemon workflows,
- service orchestration,
- storage,
- local-first runtime,
- optional Effect service layers.

Current anchors:

- `services/agentd`
- `packages/runtime`

Required hardening:

- Add local SQLite storage target under `~/.fides/`.
- Add migrations and local config.
- Preserve Postgres service stores where already used by services.

### 16. Developer Layer

Owns:

- CLI,
- SDK,
- examples,
- docs,
- demos,
- adversarial simulation.

Current anchors:

- `packages/cli`
- `packages/sdk`
- `examples`
- `tests/adversarial`

Required hardening:

- Add `agentd` command surface or alias.
- Add full demo.
- Add manual DX runbook.
- Add complete SDK examples.

### 17. Interop Layer

Owns adapter interfaces for:

- MCP,
- A2A,
- OAPS,
- OSP,
- AP2,
- x402,
- Sardis.

Rules:

- These adapters map identity, cards, capabilities, delegation, policy, evidence, invocation, and payment/action flows where relevant.
- Payment execution remains Sardis-specific.

Required hardening:

- Add `packages/adapters` with interface-only first pass.
- Add mapping docs and example adapters.

## Target Package Structure

The target shape is:

```text
packages/
  core/
  crypto/
  identity/
  attestations/
  cards/
  discovery/
  dht/
  relay/
  registry/
  trust/
  reputation/
  policy/
  delegation/
  invocation/
  evidence/
  revocation/
  incidents/
  runtime-effect/
  adapters/
  daemon/
  cli/
  sdk/
examples/
  calendar-agent/
  invoice-agent/
  payment-agent/
  malicious-agent/
  requester-agent/
  full-demo/
docs/
  inspection/
  architecture/
  protocol/
  api/
  cli/
  sdk/
  threat-model/
  adr/
```

Implementation should respect existing package names first. Split packages only when it removes real complexity or matches the target architecture cleanly. Do not churn package names just to match the tree.

## Security Rules

- Deny by default for invalid signatures, active revocations, active kill switch, expired sessions, and broken evidence chains.
- Discovery result never grants authority.
- Trust score never grants permission.
- Policy-before-execution is mandatory for invocation.
- Evidence defaults to hash-only or redacted for sensitive payloads.
- Signed objects use one canonical signing model.
- DHT pointers are not trust roots.
- Relay presence is not trust.

## First Publishable Slice

The first publishable v2 slice should include:

1. Consolidated protocol object model.
2. Canonical signer hardening.
3. Version negotiation and typed error vocabulary.
4. Identity v2 hardening.
5. Signed AgentCards and capability ontology.
6. Evidence v2 with signed events.
7. Capability-query discovery with local/registry/well-known providers.
8. DHT signed pointer records.
9. Policy/trust/reputation v2 decision explanations.
10. CLI/API/SDK demo path.
