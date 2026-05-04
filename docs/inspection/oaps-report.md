# OAPS Repository Inspection Report

## 1. Repo Purpose

**Protocol name:** AICP — Agent Interaction Control Protocol
**Repository:** OAPS — Open Agentic Primitive Standard (historical slug preserved)

This repository hosts the AICP protocol specification, JSON Schemas, conformance suite, reference implementations, and profile drafts. AICP is designed as a **composing semantic super-protocol** that sits above existing agent ecosystems (MCP, A2A, x402, MPP, AP2, OSP, etc.) and standardizes the horizontal primitive layer they do not define consistently: identity references, delegation, mandates, intents, tasks, approvals, execution outcomes, evidence, and payment coordination.

Public-facing brand is **AICP**; the repo slug remains `OAPS` to preserve history.

---

## 2. Main Packages / Modules

### Reference Implementations

| Line | Package / Module | Path | Language | Status |
|------|------------------|------|----------|--------|
| TypeScript monorepo | `reference/oaps-monorepo` | `reference/oaps-monorepo` | TypeScript (pnpm workspace) | **Stable** — primary runtime-backed slice |
| Python interoperability | `reference/oaps-python` | `reference/oaps-python` | Python | **Stable** — conformance manifest consumer |
| AOSL monorepo | `reference/aosl-monorepo` | `reference/aosl-monorepo` | TypeScript (pnpm workspace) | **Draft** — parallel runtime effort |

### OAPS Monorepo Packages (`reference/oaps-monorepo/packages/*`)

| Package | Path | Role | Runtime Backing |
|---------|------|------|-----------------|
| `@oaps/core` | `packages/core/src/index.ts` | Shared contracts, IDs, version negotiation, hashing, auth checks, state machines, handshake protocol | Yes |
| `@oaps/evidence` | `packages/evidence/src/index.ts` | SHA256 hashing, hash-linked chain builder, chain verifier | Yes |
| `@oaps/policy` | `packages/policy/src/index.ts` | `oaps-policy-v1` deterministic policy evaluator, context hashing | Yes |
| `@oaps/mcp-adapter` | `packages/mcp-adapter/src/index.ts` | MCP capability mapping, policy enforcement, approval gating, evidence emission | Yes |
| `@oaps/http` | `packages/http/src/index.ts` | Reference HTTP server, well-known discovery, interaction/approval/evidence endpoints, idempotency, file-backed state | Yes |
| `@oaps/discovery` | `packages/discovery/src/index.ts` | Actor card discovery via `.well-known/aicp.json` and DNS TXT fallback | Yes |
| `@oaps/context` | `packages/context/src/index.ts` | Interaction context management, message/transition/delegation tracking, replay windows | Yes |
| `@oaps/websocket-binding` | `packages/websocket-binding/src/index.ts` | WebSocket binding with handshake, version negotiation, frame validation, evidence streaming | Yes |
| `@oaps/webhook-binding` | `packages/webhook-binding/src/index.ts` | Webhook binding stub | Partial |
| `@oaps/a2a-adapter` | `packages/a2a-adapter/src/index.ts` | A2A task/status mapping to AICP semantics, delegation, evidence | Yes |
| `@oaps/x402-adapter` | `packages/x402-adapter/src/index.ts` | x402 payment challenge/authorization/settlement/refund/void mapping | Yes |
| `@oaps/auth-web-adapter` | `packages/auth-web-adapter/src/index.ts` | Web auth (session/bearer) subject binding, delegation verification | Yes |
| `@oaps/hono` | `packages/hono/src/index.ts` | Hono-compatible HTTP wrapper (simplified reference stack) | Yes |
| `@oaps/hono-node-server` | `packages/hono-node-server/src/index.ts` | Node server wrapper | Yes |

### AOSL Monorepo Packages (`reference/aosl-monorepo/packages/*`)

| Package | Path | Role |
|---------|------|------|
| `@aosl/core` | `packages/core/src/types.ts` | Core types (Actor, Intent, Task, Delegation, EvidenceEvent, etc.) |
| `@aosl/runtime` | `packages/runtime/src/index.ts` | Runtime exports (policy, evidence, plan) |
| `@aosl/cli` | `packages/cli/src/index.ts` | CLI scaffold (`aosl CLI booting...`) |
| `@aosl/ir` | `packages/ir/src/index.ts` | IR types and validation |
| `@aosl/linter` | `packages/linter/src/index.ts` | Linter |
| `@aosl/sdk-ts` | `packages/sdk-ts/src/index.ts` | SDK effects and task utilities |

---

## 3. Existing Primitives with Exact File Paths

### Core Types (OAPS Monorepo)

Defined in `reference/oaps-monorepo/packages/core/src/index.ts`:

- `ActorRef` — line 36
- `Endpoint` — line 42
- `Proof` — line 48
- `Money` — line 55
- `Action` — line 60
- `ActorCard` — line 68
- `CapabilityCard` — line 81
- `Intent` — line 93
- `Task` — line 104
- `DelegationToken` — line 117
- `Mandate` — line 130
- `ApprovalRequest` — line 141
- `ApprovalDecision` — line 154
- `Challenge` — line 165
- `ExecutionRequest` — line 179
- `ExecutionResult` — line 187
- `InteractionCreated` — line 195
- `InteractionUpdated` — line 203
- `InteractionTransition` — line 211
- `TaskTransition` — line 224
- `ErrorObject` — line 253 (with `ErrorCategory` union at line 239)
- `ExtensionDescriptor` — line 261
- `EvidenceEvent` — line 272
- `EnvelopeRefs` / `Envelope<TPayload>` — line 285-308
- `VersionSupport` / `VersionNegotiationResult` — line 310-320

### Handshake Protocol (OAPS Monorepo)

In `reference/oaps-monorepo/packages/core/src/index.ts` lines 904-1103:

- `HandshakeBinding` — line 907
- `HandshakeStep` — line 909
- `HandshakeProposal` — line 911
- `HandshakeAcceptance` — line 925
- `HandshakeRejection` — line 935
- `validateHandshakeProposal()` — line 941
- `evaluateHandshakeProposal()` — line 1001
- `buildHandshakeEvidence()` — line 1085

### Policy Types (OAPS Monorepo)

In `reference/oaps-monorepo/packages/policy/src/index.ts`:

- `PolicyExpression` — line 6
- `PolicyRule` — line 18
- `PolicyBundle` — line 24
- `PolicyContext` — line 31
- `PolicyResult` — line 45
- `evaluatePolicy()` — line 162
- `hashPolicyContext()` — line 158

### Evidence Types (OAPS Monorepo)

In `reference/oaps-monorepo/packages/evidence/src/index.ts`:

- `EvidenceChain` — line 3
- `createEvidenceChain()` — line 7
- `appendEvidenceEvent()` — line 23
- `verifyEvidenceChain()` — line 44
- `hashEvidenceValue()` — line 19

### Discovery Types (OAPS Monorepo)

In `reference/oaps-monorepo/packages/discovery/src/index.ts`:

- `ActorCardDiscovery` — line 10
- `fetchActorCard()` — line 174
- `resolveActorCard()` — line 213

### AOSL Core Types (Separate Namespace)

In `reference/aosl-monorepo/packages/core/src/types.ts`:

- `Actor`, `ActorRef`, `Capability`, `Intent`, `Interaction`, `Task`, `Delegation`, `Mandate`, `ApprovalRequest`, `ApprovalDecision`, `Challenge`, `EvidenceEvent`, `ErrorObject`, `ExecutionResult`, `PaymentCoordination`, `EffectDescriptor`

---

## 4. Key Term Search Results

| Term | Status | Exact Locations |
|------|--------|-----------------|
| **DelegationToken** | Found | `reference/oaps-monorepo/packages/core/src/index.ts:117`; `packages/context/src/index.ts`; `packages/mcp-adapter/src/index.ts`; `packages/a2a-adapter/src/index.ts`; `packages/auth-web-adapter/src/index.ts`; `spec/core/HANDSHAKE-DRAFT.md`; `SPEC.md:45`; `examples/integrations/multi-agent-demo/src/demo.ts` |
| **PolicyBundle** | Found | `reference/oaps-monorepo/packages/policy/src/index.ts:24`; `packages/mcp-adapter/src/index.ts`; `packages/http/src/index.ts`; `SPEC.md:45`; `examples/integrations/mcp-governance-demo/src/demo.ts` |
| **Intent** | Found | `reference/oaps-monorepo/packages/core/src/index.ts:93`; `packages/mcp-adapter/src/index.ts`; `packages/a2a-adapter/src/index.ts`; `spec/core/FOUNDATION-DRAFT.md`; `examples/integrations/multi-agent-demo/src/demo.ts` |
| **Evidence** | Found | `reference/oaps-monorepo/packages/evidence/src/index.ts`; `packages/core/src/index.ts:272`; `packages/websocket-binding/src/index.ts`; `packages/context/src/index.ts`; pervasive across repo |
| **A2A** | Found | `reference/oaps-monorepo/packages/a2a-adapter/src/index.ts`; `profiles/a2a-draft.md`; `conformance/fixtures/profiles/a2a/index.v1.json`; `examples/a2a/`; `docs/REVIEW-PACKET-A2A.md` |
| **MCP** | Found | `reference/oaps-monorepo/packages/mcp-adapter/src/index.ts`; `profiles/mcp.md`; `conformance/fixtures/profiles/mcp/index.v1.json`; `examples/mcp/`; `docs/REVIEW-PACKET-MCP.md` |
| **AP2** | Found | `profiles/ap2-draft.md`; `conformance/fixtures/profiles/ap2/index.v1.json`; `examples/ap2/`; `docs/REVIEW-PACKET-PAYMENT.md` |
| **x402** | Found | `reference/oaps-monorepo/packages/x402-adapter/src/index.ts`; `profiles/x402-draft.md`; `conformance/fixtures/profiles/x402/index.v1.json`; `examples/x402/` |
| **MPP** | Found | `profiles/mpp-draft.md`; `conformance/fixtures/profiles/mpp/index.v1.json`; `examples/mpp/` |
| **discovery** | Found | `reference/oaps-monorepo/packages/discovery/src/index.ts`; `spec/core/DISCOVERY-DRAFT.md`; `schemas/foundation/actor-card-discovery.json` |
| **well-known** | Found | `reference/oaps-monorepo/packages/discovery/src/index.ts:218` (`/.well-known/aicp.json`); `packages/http/src/index.ts:286` (`/.well-known/oaps.json`); `spec/core/DISCOVERY-DRAFT.md`; `examples/well-known-oaps.json` |
| **version negotiation** | Found | `reference/oaps-monorepo/packages/core/src/index.ts:512` (`negotiateVersion`); `packages/http/src/index.ts:328`; `packages/websocket-binding/src/index.ts:323,497`; `schemas/foundation/version-negotiation.json`; `spec/core/FOUNDATION-DRAFT.md:79` (CC6) |
| **JSON Schema** | Found | `schemas/` directory contains ~40 schemas; `README.md` mentions JSON Schemas; validation scripts exist |
| **error vocabulary** | **Not found as explicit phrase** | However, `schemas/foundation/error-object.json` defines canonical `ErrorCategory` enum: `authentication`, `authorization`, `validation`, `capability`, `discovery`, `transport`, `execution`, `economic`, `settlement`, `timeout`, `versioning`, `internal` |

---

## 5. CLI Entrypoints, SDK Exports, Examples, Tests

### CLI Entrypoints

1. **TypeScript reference server** (direct execution):
   - `reference/oaps-monorepo/packages/http/src/index.ts` lines 790-819 — `startReferenceServer()` runs when executed directly via `node`

2. **Python CLI** (`oaps-python`):
   - Entrypoint: `reference/oaps-python/src/oaps_python/cli.py`
   - Commands: `validate`, `inventory`, `check` (fixture-check), `validate-result`, `validate-declaration`, `compatibility`, `compare-results`, `compare-declarations`
   - Module: `python -m oaps_python`

3. **AOSL CLI** (scaffold only):
   - `reference/aosl-monorepo/packages/cli/src/index.ts` — minimal boot message, not a full CLI

4. **Monorepo scripts**:
   - `reference/oaps-monorepo/scripts/validate-spec-pack.mjs` — validates examples against JSON Schemas
   - `reference/oaps-monorepo/scripts/validate-conformance-pack.mjs` — validates TCK manifest and fixture indexes
   - `reference/oaps-monorepo/scripts/generate-core-schema-constants.mjs` — derives core constants from schema pack

### SDK Exports

- `@oaps/core` — main export from `packages/core/src/index.ts`
- `@oaps/evidence` — main export from `packages/evidence/src/index.ts`
- `@oaps/policy` — main export from `packages/policy/src/index.ts`
- `@oaps/mcp-adapter` — main export from `packages/mcp-adapter/src/index.ts`
- `@oaps/http` — main export from `packages/http/src/index.ts`
- `@oaps/discovery` — main export from `packages/discovery/src/index.ts`
- `@oaps/context` — main export from `packages/context/src/index.ts`
- `@oaps/websocket-binding` — main export from `packages/websocket-binding/src/index.ts`
- `@oaps/a2a-adapter` — main export from `packages/a2a-adapter/src/index.ts`
- `@oaps/x402-adapter` — main export from `packages/x402-adapter/src/index.ts`
- `@oaps/auth-web-adapter` — main export from `packages/auth-web-adapter/src/index.ts`

### Examples

- `examples/` — 100+ example JSON payloads
- `examples/integrations/multi-agent-demo/` — A2A-style delegation chain demo
- `examples/integrations/mcp-governance-demo/` — MCP governance demo
- `examples/integrations/stripe-aicp-demo/` — Stripe payment intent demo

### Tests

Each TypeScript package uses Node.js built-in test runner (`node --test`):
- `packages/core/src/index.test.ts`
- `packages/evidence/src/index.test.ts`
- `packages/policy/src/index.test.ts`
- `packages/mcp-adapter/src/index.test.ts`
- `packages/http/src/index.test.ts`
- `packages/discovery/src/index.test.ts`
- `packages/context/src/index.test.ts`
- `packages/websocket-binding/src/index.test.ts`
- `packages/a2a-adapter/src/index.test.ts`
- `packages/x402-adapter/src/index.test.ts`
- `packages/auth-web-adapter/src/index.test.ts`

Python tests:
- `reference/oaps-python/tests/test_types.py`
- `reference/oaps-python/tests/test_evidence.py`
- `reference/oaps-python/tests/test_validation.py`
- `reference/oaps-python/tests/test_manifest.py`

---

## 6. Schemas / Spec Files

### JSON Schemas (`schemas/`)

**Foundation schemas** (`schemas/foundation/`):
- `actor.json`, `capability.json`, `intent.json`, `task.json`, `delegation.json`, `mandate.json`
- `approval-request.json`, `approval-decision.json`, `challenge.json`, `execution-result.json`
- `evidence-event.json`, `error-object.json`, `extension-descriptor.json`
- `interaction.json`, `interaction-transition.json`, `task-transition.json`
- `interaction-context.json`, `handshake.json`, `version-negotiation.json`
- `actor-card-discovery.json`, `message.json`, `common.json`

**Legacy schemas** (`schemas/` root):
- `actor-card.json`, `capability-card.json`, `intent.json`, `delegation-token.json`
- `approval-request.json`, `approval-decision.json`, `envelope.json`, `error.json`
- `evidence-event.json`, `execution-request.json`, `execution-result.json`
- `interaction-created.json`, `interaction-updated.json`

**Profile schemas** (`schemas/profiles/`):
- `profile-support-declaration.json`, `payment-challenge.json`, `trust-attestation.json`
- `provisioning-operation.json`, `subject-binding-assertion.json`

**Payment schemas** (`schemas/payment/`):
- `payment-authorization.json`, `mandate-chain.json`, `payment-session.json`

**Domain schemas** (`schemas/domain/`):
- `order-intent.json`, `commercial-evidence.json`, `fulfillment-commitment.json`, `merchant-authorization.json`

**Binding schemas** (`schemas/bindings/`):
- `webhook-registration.json`, `webhook-envelope.json`, `websocket-message.json`

### Spec Documents

- `spec/core/FOUNDATION-DRAFT.md` — hard-normative semantic core
- `spec/core/STATE-MACHINE-DRAFT.md` — interaction/task lifecycles
- `spec/core/HANDSHAKE-DRAFT.md` — handshake protocol
- `spec/core/DISCOVERY-DRAFT.md` — discovery semantics
- `spec/core/SHARED-CONTEXT-DRAFT.md` — shared context semantics
- `spec/bindings/http-binding-draft.md`
- `spec/bindings/websocket-binding-draft.md`
- `spec/bindings/jsonrpc-binding-draft.md`
- `spec/bindings/grpc-binding-draft.md`
- `spec/bindings/events-binding-draft.md`
- `spec/bindings/webhook-binding-draft.md`
- `spec/domain/commerce-draft.md`
- `spec/profiles/aosl-runtime-draft.md`
- `spec/profiles/agent-client-draft.md`
- `SPEC.md` — consolidated legacy draft spec pack

### Conformance Suite

- `conformance/manifest/oaps-tck.manifest.v1.json` — TCK manifest
- `conformance/taxonomy/scenario-taxonomy.v1.json` — scenario taxonomy
- `conformance/fixtures/index.v1.json` — fixture index
- `conformance/fixtures/core/index.v1.json` — core fixtures
- `conformance/fixtures/bindings/*/index.v1.json` — binding fixtures
- `conformance/fixtures/profiles/*/index.v1.json` — profile fixtures
- `conformance/results/result-schema.v1.json` — result schema
- `conformance/results/compatibility-declaration-schema.v1.json` — declaration schema

---

## 7. CI / Config Files

### GitHub Configuration
- `.github/CODEOWNERS`
- `.github/ISSUE_TEMPLATE/cosigner.yml`
- `.github/ISSUE_TEMPLATE/config.yml`
- `.github/ISSUE_TEMPLATE/review-feedback.md`

**No GitHub Actions workflows found.** No `.github/workflows/` directory exists.

### Project Config
- `reference/oaps-monorepo/pnpm-workspace.yaml` — pnpm workspace definition
- `reference/oaps-monorepo/package.json` — root package.json (private, `type: "module"`, `packageManager: "pnpm@10.32.1"`)
- `reference/aosl-monorepo/package.json` — root package.json (private, `type: "module"`, `packageManager: "pnpm@10.32.1"`)
- `reference/oaps-python/pyproject.toml` — Python project config
- `.gitignore`
- `.codex/config.toml` — Codex harness config

---

## 8. What Is Reusable

### Highly Reusable (Stable, Tested, Runtime-Backed)

1. **`@oaps/core`** — The entire core primitive layer is reusable:
   - `generateId`, `canonicalJson`, `sha256Prefixed`
   - `negotiateVersion` (version negotiation logic)
   - `assertInvokeIntent`, `assertAuthenticatedActor`, `promoteIntentToTask`
   - `assertInteractionTransition`, `assertTaskTransition`
   - `buildEnvelope`, `buildHandshakeEvidence`, `evaluateHandshakeProposal`
   - `assertMandateAuthorizes`, `mandateCoversAction`, `isMandateExpired`
   - `assertApprovalDecisionTargets`
   - `parseBearerToken`, `compareRiskClass`, `riskClassRequiresApproval`
   - All type definitions (`ActorCard`, `CapabilityCard`, `Intent`, `Task`, `DelegationToken`, `Mandate`, `ApprovalRequest`, `ApprovalDecision`, `Challenge`, `EvidenceEvent`, `ErrorObject`, `Envelope`, etc.)

2. **`@oaps/evidence`** — Evidence chain builder and verifier are fully reusable.

3. **`@oaps/policy`** — The `oaps-policy-v1` evaluator with `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in`, `all`, `any` expressions is reusable.

4. **`@oaps/discovery`** — Actor card discovery via `.well-known/aicp.json` with DNS TXT fallback.

5. **`@oaps/context`** — Interaction context manager with message/transition/delegation tracking and replay.

6. **`@oaps/auth-web-adapter`** — Bearer/session authentication, subject binding, delegation verification.

7. **HTTP Reference Server** (`@oaps/http`) — Full working server with:
   - Bearer token auth
   - Idempotency with file-backed state
   - Interaction lifecycle (create, message append, approve, reject, revoke)
   - Evidence replay with `after`/`limit` pagination
   - MCP adapter integration

8. **WebSocket Binding** (`@oaps/websocket-binding`) — Full server/client with handshake, version negotiation, frame types, evidence emission, replay.

9. **Profile Adapters** (mapping layers):
   - `@oaps/mcp-adapter` — Maps MCP tools to `CapabilityCard`, enforces policy, approval gates, evidence
   - `@oaps/a2a-adapter` — Maps A2A tasks/statuses to AICP interaction/task states
   - `@oaps/x402-adapter` — Maps x402 challenge/authorization/settlement to AICP primitives

10. **Python Interoperability Layer**:
    - `reference/oaps-python/aicp/types.py` — Dataclass primitives
    - `reference/oaps-python/aicp/evidence.py` — Evidence chain in Python
    - `reference/oaps-python/aicp/validation.py` — Validation utilities
    - `reference/oaps-python/src/oaps_python/cli.py` — Full conformance CLI (validate, inventory, fixture-check, compatibility declaration)

11. **JSON Schemas** — 40+ schemas under `schemas/` covering foundation, profiles, payments, domain, and bindings.

12. **Conformance Manifest and Fixtures** — Machine-readable TCK manifest, taxonomy, and fixture packs for 17 scopes (core, 5 bindings, 11 profiles/domains).

---

## 9. What Is Missing

1. **No Cargo.toml** — This is not a Rust repository; it is TypeScript + Python.

2. **No GitHub Actions CI** — No automated CI/CD pipelines exist. Tests must be run manually via `pnpm test` or `node --test`.

3. **No dedicated "error vocabulary" document** — While `ErrorObject` schema exists with 12 canonical categories, there is no standalone prose document cataloging all error codes used across the suite.

4. **gRPC and Events/Webhooks runtime support** — The spec drafts exist (`spec/bindings/grpc-binding-draft.md`, `spec/bindings/events-binding-draft.md`, `spec/bindings/webhook-binding-draft.md`), but there is no runtime-backed implementation beyond fixture stubs.

5. **A2A end-to-end runtime** — The A2A adapter exists as a mapping layer with tests, but there is no live A2A client/server integration in the reference slice.

6. **Payment profile runtimes** — x402, MPP, and AP2 adapters are mapping layers only. No live payment rail integration exists.

7. **Commerce and Jobs domain families** — These are conceptual/long-term. Only `schemas/domain/` and `examples/commerce/` have draft fixtures.

8. **Registry infrastructure** — No registry or lookup service implementation exists.

9. **External governance / cosigner structure** — Still draft/concept per `CHARTER.md` and `governance/RF_PATENT_PLEDGE.md`.

10. **Full AOSL monorepo integration** — The AOSL monorepo (`reference/aosl-monorepo`) is a parallel effort with its own type system. It is not yet wired into the OAPS reference slice.

---

## 10. Conflicts and Issues Noticed

### Critical: Two Competing Type Systems

**OAPS monorepo** (`reference/oaps-monorepo/packages/core/src/index.ts`) and **AOSL monorepo** (`reference/aosl-monorepo/packages/core/src/types.ts`) define **overlapping but incompatible** primitives:

| Primitive | OAPS Style | AOSL Style |
|-----------|------------|------------|
| ActorRef field names | `actor_id` (snake_case) | `actorId` (camelCase) |
| Intent field names | `intent_id`, `actor_ref`, `capability_ref` | `id`, `actorRef`, `capabilityRef` |
| Delegation field names | `delegation_id`, `delegator`, `delegatee` | `id`, `fromActorRef`, `toActorRef` |
| EvidenceEvent field names | `event_id`, `interaction_id`, `event_type`, `prev_event_hash`, `event_hash` | `id`, `interactionId`, `eventType`, `hash`, `prevHash`, `payloadHash` |
| Error categories | 12 categories including `economic`, `settlement`, `versioning` | 9 categories: `validation`, `permission`, `policy`, `timeout`, `network`, `execution`, `payment`, `auth`, `evidence` |
| ApprovalDecision values | `'approve'`, `'reject'`, `'modify'` | `"approved"`, `"rejected"`, `"modified"` |

**Impact:** The AOSL monorepo is **not interchangeable** with the OAPS monorepo. Any attempt to merge them without a type bridge will cause breakage.

### Schema Inconsistency (Documented in Repo)

- `AUDIT-FIX-LIST.md` line 67 notes: schemas use `"$ref": "foundation/common.json#/$defs/..."` with relative path prefix, but `$id` uses `https://oaps.dev/schemas/foundation/...`. This inconsistency may confuse JSON Schema tools.

### Maturity Downgrades

- `docs/MATURITY-MATRIX.md` and `AUDIT-MATURITY-MATRIX.md` show that ACP, AP2, MPP, and UCP profiles were **downgraded from "Draft" to "Concept"** on 2026-04-11 because they are 2.4-3.2 KB stubs with minimal substance and no runtime backing.

### Naming Drift

- The repository is called `OAPS`, the protocol is branded `AICP`, and earlier drafts used the name `Pact` (retired to avoid confusion with `pact.io`). This creates potential confusion in imports, URLs, and documentation.

### AOSL vs AICP Boundary Ambiguity

- `docs/AICP-AOSL-BOUNDARY.md` exists to clarify the boundary, but the presence of two monorepos with overlapping concerns (`runtime`, `evidence`, `policy`, `core`) suggests the separation is still being negotiated.

### Well-Known Path Inconsistency

- Discovery draft (`spec/core/DISCOVERY-DRAFT.md`) specifies `/.well-known/aicp.json`
- HTTP binding and legacy examples use `/.well-known/oaps.json`
- Both paths are implemented in different packages (`discovery` vs `http`)

---

## 11. Recommended Action for FIDES v2

1. **Port OAPS core primitives into FIDES namespace** — Do not depend on `@oaps/core` as a package. Instead, adapt the concepts (DelegationToken, PolicyBundle, EvidenceEvent, ActorCard, CapabilityCard, ApprovalRequest, ApprovalDecision) into `@fides/core` with FIDES-compatible naming and signing.
2. **Use OAPS schemas as compatibility reference** — Maintain a mapping document showing how FIDES types correspond to OAPS/AICP schemas.
3. **Adopt OAPS version negotiation logic** (`negotiateVersion`) for FIDES protocol handshake.
4. **Adopt OAPS error taxonomy** (`ErrorObject` with 12 categories) as the basis for FIDES typed errors, extended with FIDES-specific categories.
5. **Reuse OAPS evidence chain pattern** (`@oaps/evidence`) — port the hash-linked builder/verifier into `@fides/evidence`.
6. **Reuse OAPS policy evaluator pattern** (`@oaps/policy`) — port the deterministic expression evaluator into `@fides/policy`.
7. **Avoid the AOSL monorepo types** — they are incompatible with OAPS types. Use OAPS monorepo as the canonical reference.
8. **Use OAPS handshake protocol** as the basis for FIDES session establishment, with FIDES-specific extensions for trust score and runtime attestation.
