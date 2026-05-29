# OAPS Repository Inspection Report

Source repo: `/Users/efebarandurmaz/OAPS`

Note: the repo is branded in places as AICP while still using OAPS names in code and paths. This report reflects current local files and is read-only evidence for FIDES v2.

## 1. Repo Purpose

OAPS/AICP is a protocol suite for cross-protocol agentic control-plane semantics: identity references, delegation, mandates, intents, tasks, approvals, execution outcomes, evidence, and payment coordination. It contains specs, schemas, examples, conformance fixtures, and TypeScript reference implementations.

Local evidence:

- `/Users/efebarandurmaz/OAPS/README.md`
- `/Users/efebarandurmaz/OAPS/spec/core/FOUNDATION-DRAFT.md`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/package.json`

## 2. Main Packages / Modules

| Area | Path | Purpose |
|---|---|---|
| Reference monorepo | `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/` | Primary TS reference workspace. |
| Core | `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/core/src/index.ts` | Types, IDs, version negotiation, canonical JSON hashing, auth binding checks, state transitions, mandate and approval guards. |
| Evidence | `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/evidence/src/index.ts` | Append-only hash-linked evidence chain builder/verifier. |
| Policy | `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/policy/src/index.ts` | Deterministic JSONLogic-style policy evaluator with fail-closed errors and context hashing. |
| MCP adapter | `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/mcp-adapter/src/index.ts` | MCP tool discovery, capability mapping, policy enforcement, approval gating, invocation, evidence emission. |
| HTTP reference | `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/http/src/index.ts` | Well-known discovery, actor cards, capabilities, interactions, approval/reject/revoke, evidence, events, idempotency. |
| Discovery | `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/discovery/src/index.ts` | Actor-card discovery and capability matching. |
| Profile adapters | `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/a2a-adapter`, `auth-web-adapter`, `x402-adapter`, `webhook-binding`, `websocket-binding` | Profile/transport adapters. |
| AOSL draft | `/Users/efebarandurmaz/OAPS/reference/aosl-monorepo/` | Separate draft runtime/IR/CLI line. |
| Python starter | `/Users/efebarandurmaz/OAPS/reference/oaps-python/pyproject.toml` | Minimal Python interop starter. |

## 3. Existing Primitives

- Actor/identity references exist through `ActorRef`, `ActorCard`, `identity_profile`, and `trust_credentials`: `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/core/src/index.ts`, `/Users/efebarandurmaz/OAPS/schemas/actor-card.json`, `/Users/efebarandurmaz/OAPS/spec/core/FOUNDATION-DRAFT.md`.
- DID is permitted as method-agnostic actor ID/profile, but I could not find DID resolution or DID signature verification runtime.
- Generic `Proof` exists on envelopes; webhook HMAC signing/verification exists. HTTP Signature support is documented as missing: `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/core/src/index.ts`, `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/webhook-binding/src/index.ts`, `/Users/efebarandurmaz/OAPS/PROTOCOL-GAP-ANALYSIS.md`.
- `auth-fides-tap` profile draft defines trust tiers, attestation semantics, stronger actor binding, signed/attested delegation chains, and explicitly notes no dedicated FIDES/TAP verifier exists: `/Users/efebarandurmaz/OAPS/profiles/auth-fides-tap-draft.md`.
- Capability discovery and matching exist: `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/discovery/src/index.ts`; `.well-known/oaps.json` exists in HTTP reference: `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/http/src/index.ts`.
- `DelegationToken`, mandate, approval request/decision, and revoke flows exist: `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/core/src/index.ts`, `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/http/src/index.ts`.
- Policy context covers intent, actor, capability, delegation, approval, environment, economic, merchant, risk, and evidence namespaces: `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/policy/src/index.ts`.
- Evidence events are hash-linked with previous and current event hashes; HTTP exposes evidence/events replay: `/Users/efebarandurmaz/OAPS/schemas/foundation/evidence-event.json`, `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/evidence/src/index.ts`, `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/http/src/index.ts`.
- MCP runtime is the stable implementation-backed slice; A2A/x402/auth-web/webhook packages exist but are partial/profile-level in places.

## 4. Relevant Files

- `/Users/efebarandurmaz/OAPS/README.md`
- `/Users/efebarandurmaz/OAPS/PROTOCOL-GAP-ANALYSIS.md`
- `/Users/efebarandurmaz/OAPS/VERSIONING.md`
- `/Users/efebarandurmaz/OAPS/profiles/auth-fides-tap-draft.md`
- `/Users/efebarandurmaz/OAPS/spec/core/FOUNDATION-DRAFT.md`
- `/Users/efebarandurmaz/OAPS/schemas/actor-card.json`
- `/Users/efebarandurmaz/OAPS/schemas/capability-card.json`
- `/Users/efebarandurmaz/OAPS/schemas/foundation/actor.json`
- `/Users/efebarandurmaz/OAPS/schemas/foundation/capability.json`
- `/Users/efebarandurmaz/OAPS/schemas/foundation/mandate.json`
- `/Users/efebarandurmaz/OAPS/schemas/foundation/evidence-event.json`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/core/src/index.ts`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/evidence/src/index.ts`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/policy/src/index.ts`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/discovery/src/index.ts`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/http/src/index.ts`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/mcp-adapter/src/index.ts`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/auth-web-adapter/src/index.ts`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/x402-adapter/src/index.ts`
- `/Users/efebarandurmaz/OAPS/reference/oaps-monorepo/packages/webhook-binding/src/index.ts`

## 5. Reusable Components

- Use OAPS as semantic source for actor refs, delegation, mandate, approval, envelopes, versioning, canonical JSON, hashes, state transitions, policy context, and error taxonomy.
- Reuse OAPS evidence shape as a minimal hash-linked event model, but FIDES must add signed events, privacy modes, Merkle/export, append-only persistence, and verification.
- Reuse OAPS policy evaluator ideas, but FIDES must add trust/reputation/runtime/revocation/kill-switch-aware authority evaluation.
- Reuse MCP adapter flow as FIDES interop adapter inspiration.
- Reuse auth-web subject binding shape as an adapter, not as cryptographic identity.

## 6. Missing Components

I could not find:

- Ed25519 implementation.
- DID resolver or DID document validation.
- `did:key` support.
- Signed delegation/mandate envelopes with FIDES-level verification.
- Cryptographic attestation verification runtime.
- Trust graph or reputation runtime.
- Merkle tree.
- Append-only ledger backend.
- Incident model.
- TEE runtime attestation.
- DHT, relay, federation runtime.
- Generic privacy runtime.
- Dedicated kill-switch primitive beyond revoke/fail-closed semantics.
- GitHub Actions CI workflows; `.github` appears to contain ownership/issue template files only.

## 7. Conflicts With FIDES v2 Architecture

- Naming/version split: public README says AICP, repo/code still says OAPS, and version constants differ across docs and generated constants.
- Schema drift exists between foundation schemas and generated legacy constants for actor and capability kinds.
- Mandate spec/type/schema fields differ (`authorized_actor`/`scope`/`expiry` vs `principal`/`delegatee`/`action`/`expires_at`).
- Reference auth relies heavily on bearer/session subject binding and webhook HMAC, so FIDES must not treat OAPS auth as high-assurance identity.
- OAPS includes payment coordination profiles; FIDES should port only generic control semantics and leave payment execution to Sardis.

## 8. Recommended Action

Port OAPS concepts into FIDES, but do not depend on `@oaps/core` at runtime.

Concrete mapping direction:

- `ActorRef` -> FIDES `PrincipalIdentity` / `AgentIdentity` references.
- `ActorCard` -> FIDES `AgentCard`.
- `CapabilityCard` -> FIDES `CapabilityDescriptor` / ontology entry.
- `DelegationToken` and `Mandate` -> FIDES signed `DelegationToken` and `SessionGrant`.
- `ApprovalRequest` / `ApprovalDecision` -> FIDES approval primitives.
- `EvidenceEvent` -> FIDES signed privacy-aware evidence event.
- OAPS version negotiation and error taxonomy -> FIDES-owned version/error vocabularies.

FIDES must add the missing high-assurance layer: DID resolution, Ed25519 signing/verification, trust graph/reputation semantics, revocation registry, runtime attestation, incident handling, DHT/relay/federation, and evidence hardening.
