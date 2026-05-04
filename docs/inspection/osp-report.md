# OSP Repository Inspection Report

## 1. Repo Purpose

**Open Service Protocol (OSP)** is an open standard (Apache 2.0) that enables AI agents to discover, provision, and manage developer services (databases, hosting, auth, analytics, etc.) programmatically without browser-based signup flows. It is positioned as "what MCP is to tool access, OSP is to service provisioning."

**Key claim:** Payment-rail agnostic, provider-neutral, machine-first protocol with encrypted credential delivery (Ed25519 / x25519-xsalsa20-poly1305).

---

## 2. Main Packages / Modules

| Package | Path | Language | Description |
|---|---|---|---|
| **Spec** | `spec/osp-v1.0.md` | Markdown | Core protocol specification (~9,600 lines, v1.1 draft) |
| **Schemas** | `schemas/` | JSON Schema | Draft 2020-12 schemas + 14 example manifests |
| **osp-core** | `osp-core/crates/` | Rust (8 crates) | Rust workspace: crypto, manifest, vault, CLI, provider adapters, registry, conformance, SDK |
| **TypeScript SDK** | `reference-implementation/typescript/` | TypeScript | `@osp/client` v0.2.0 — client, types, crypto, resolver, MCP server, plugins |
| **Python SDK** | `reference-implementation/python/` | Python | `osp-client` v0.2.0 — async client, Pydantic types, FastAPI/Django integrations |
| **Go SDK** | `osp-sdk-go/` | Go | `osp-sdk-go` — full client + provider + crypto (142 tests) |
| **Provider Framework (TS)** | `packages/provider-framework/typescript/` | TypeScript | Express middleware for building OSP providers |
| **Provider Framework (Py)** | `packages/provider-framework/python/` | Python | FastAPI router for building OSP providers |
| **MCP Server** | `packages/mcp-server/` | TypeScript | `@osp/mcp-server` — MCP tools exposing OSP operations |
| **Sardis Integration** | `sardis-integration/` | TypeScript | Payment rail, MCP extension, CLI bridge for Sardis |
| **Conformance Tests** | `conformance-tests/python/` | Python | pytest conformance suite (crypto, identity, sandbox, etc.) |
| **Skills** | `skills/` | Markdown | 10 provider skill files (Supabase, Neon, Vercel, Clerk, etc.) |
| **Examples** | `examples/` | YAML | `osp.yaml` project examples (Next.js + Supabase + Clerk, Python + Neon + Resend) |
| **Website** | `website/` | Next.js | Marketing site |
| **Docs** | `docs/` | Markdown | Getting started, provider/agent guides, security model, IETF draft |

---

## 3. Existing Primitives (with Exact File Paths)

### A. Core Types / Schema Primitives

| Primitive | File Path |
|---|---|
| `ServiceManifest` | `schemas/service-manifest.schema.json` |
| `ServiceOffering` | Embedded in schema above + SDK types |
| `ServiceTier` | Embedded in schema above + SDK types |
| `ProvisionRequest` | `schemas/provision-request.schema.json` |
| `ProvisionResponse` | `schemas/provision-response.schema.json` |
| `CredentialBundle` | `schemas/credential-bundle.schema.json` |
| `UsageReport` | `schemas/usage-report.schema.json` |
| `WebhookEvent` | `schemas/webhook-event.schema.json` |
| `HealthResponse` | `schemas/health-response.schema.json` |
| `CostSummary` | `schemas/cost-summary.schema.json` |
| `ErrorResponse` | `schemas/error-response.schema.json` |

### B. SDK Type Definitions

| Language | File Path | Notes |
|---|---|---|
| TypeScript | `reference-implementation/typescript/src/types.ts` | 861 lines, exhaustive v1.1 + v1.2 types |
| Python | `reference-implementation/python/src/osp/types.py` | 863 lines, Pydantic v2 models |
| Go | `osp-sdk-go/types.go` | 765 lines, structs + enums |

### C. Client SDKs

| Language | File Path | Methods Implemented |
|---|---|---|
| TypeScript | `reference-implementation/typescript/src/client.ts` | `discover`, `discoverFromRegistry`, `provision`, `getCredentials`, `rotateCredentials`, `getStatus`, `deprovision`, `getUsage`, `checkHealth`, `getHealth`, `getCostSummary`, `estimate`, `dispute`, `getEvents`, `registerWebhook`, `deleteWebhook`, `exportResource`, `clearCache` |
| Python | `reference-implementation/python/src/osp/client.py` | Same set as TypeScript (async) |
| Go | `osp-sdk-go/client.go` | `Discover`, `DiscoverAndVerify`, `Provision`, `Deprovision`, `Rotate`, `Status`, `Usage`, `Health`, `Credentials`, `GetEvents`, `RegisterWebhook`, `DeleteWebhook`, `Estimate`, `Dispute`, `ExportResource` |
| Rust | `osp-core/crates/osp-sdk/src/client.rs` | `discover`, `provision`, `deprovision`, `health`, `decrypt_credentials`, `verify_manifest`, `list_providers` (minimal) |

### D. Crypto Primitives

| Language | File Path | Primitives |
|---|---|---|
| Rust | `osp-core/crates/osp-crypto/src/` | Ed25519 signing, x25519 key agreement, xsalsa20-poly1305 encryption, canonical JSON, base64url encoding |
| Go | `osp-sdk-go/crypto.go` | KeyPair generation, Ed25519 signing/verification, x25519 ECDH, NaCl box encryption/decryption |
| TypeScript | `reference-implementation/typescript/src/crypto.ts` | `verifyEd25519`, `canonicalJson`, `decryptCredentials`, `generateAgentKeyPair`, `base64urlEncode`/`Decode` |

### E. CLI Entrypoints

| CLI | File Path | Status |
|---|---|---|
| Rust CLI | `osp-core/crates/osp-cli/src/main.rs` | Entrypoint |
| Rust CLI commands | `osp-core/crates/osp-cli/src/commands/mod.rs` | **Mostly stubs** — `init`, `discover`, `provision` have some impl; `status`, `deprovision`, `rotate`, `estimate`, `setup`, `apply`, `drift`, `join`, `import`, `share`, `onboard` print placeholder text |
| Rust CLI parser | `osp-core/crates/osp-cli/src/cli.rs` | 18 commands defined with `clap` |
| MCP Server CLI | `packages/mcp-server/package.json` | `"bin": { "osp-mcp-server": "dist/cli.js" }` |
| Sardis CLI | `sardis-integration/package.json` | Exports `./cli` |

### F. Provider Adapters / Frameworks

| Framework | File Path | Description |
|---|---|---|
| Rust adapters | `osp-core/crates/osp-provider/src/adapters/` | 8 adapters: neon, posthog, railway, resend, supabase, turso, upstash, vercel (+ rest_client) |
| Rust provider port | `osp-core/crates/osp-provider/src/port.rs` | Trait definition (`OSPProviderAdapter`) |
| TS provider framework | `packages/provider-framework/typescript/src/middleware.ts` | Express middleware (`createOSPProvider`) |
| Py provider framework | `packages/provider-framework/python/src/osp_provider/router.py` | FastAPI router (`create_osp_router`) |

### G. Registry

| Component | File Path | Description |
|---|---|---|
| Registry server | `osp-core/crates/osp-registry/src/server.rs` | Axum server |
| Registry routes | `osp-core/crates/osp-registry/src/routes.rs` | REST routes |
| Registry models | `osp-core/crates/osp-registry/src/models.rs` | SQLite-backed models |
| Registry DB | `osp-core/crates/osp-registry/src/db.rs` | SQLite connection |

### H. Vault / Credential Storage

| Component | File Path | Description |
|---|---|---|
| Rust vault | `osp-core/crates/osp-vault/src/store.rs` | AES-256-GCM encrypted credential store with keyring integration |
| Rust vault env | `osp-core/crates/osp-vault/src/env.rs` | Env var generation from credentials |
| Rust vault resolver | `osp-core/crates/osp-vault/src/resolver.rs` | OSP URI resolver (`osp://provider/offering/credential_key`) |

### I. Resolver / URI Scheme

| Component | File Path | Description |
|---|---|---|
| TypeScript | `reference-implementation/typescript/src/resolver.ts` | `OSPResolver`, `parseOSPUri`, `buildOSPUri`, `isOSPUri` |
| Rust | `osp-core/crates/osp-vault/src/resolver.rs` | URI resolution |

---

## 4. What Is Reusable

### Highly Reusable
- **JSON Schemas** (`schemas/`) — These are the canonical definitions. Any new implementation should import these directly.
- **TypeScript Types** (`reference-implementation/typescript/src/types.ts`) — Exhaustive, well-commented, covers v1.1 and v1.2 extensions.
- **Python Types** (`reference-implementation/python/src/osp/types.py`) — Pydantic v2 models with validation; reusable for any Python service.
- **Go Types + Client** (`osp-sdk-go/types.go`, `client.go`) — Production-quality HTTP client with retries, typed errors, and full lifecycle methods.
- **Crypto implementations** — Go (`crypto.go`) and Rust (`osp-crypto`) have complete Ed25519/x25519/xsalsa20-poly1305 stacks.
- **Provider Framework types** — Both TS and Python frameworks export reusable `ServiceManifest`, `ProvisionRequest`, `ProvisionResponse`, etc.

### Partially Reusable
- **Rust `osp-sdk`** (`osp-core/crates/osp-sdk/src/client.rs`) — Very minimal; only basic discover/provision/deprovision/health. Missing most v1.1 features.
- **Rust `osp-cli`** — Command structure is well-designed (18 commands), but implementations are stubs. The `clap` definitions in `osp-core/crates/osp-cli/src/cli.rs` are reusable as a CLI spec.
- **MCP Server** (`packages/mcp-server/src/`) — Exposes OSP tools for Claude/GPT agents; reusable if you need MCP integration.
- **Provider Adapters** (Rust) — The adapter trait in `osp-core/crates/osp-provider/src/port.rs` is a good reference, but the 8 concrete adapters are mostly mock/stub implementations returning hardcoded JSON.

---

## 5. What Is Missing

### Critical Gaps in Implementation

1. **No actual ownership primitive in code**
   - The spec mentions `principal_id` and "resource ownership" in terminology (`spec/osp-v1.0.md` line 282), but **no SDK or framework models an `Owner` or `Ownership` type**. Ownership is only a conceptual spec term.

2. **Rust CLI is largely unimplemented**
   - `osp-core/crates/osp-cli/src/commands/mod.rs` contains extensive stubs. Commands like `status`, `deprovision`, `rotate`, `upgrade`, `estimate`, `setup`, `apply`, `drift`, `join`, `import`, `share`, `onboard` do nothing except `println!`.

3. **Rust SDK lacks most v1.1 features**
   - No A2A delegation, NHI, FinOps, cost summary, events, webhooks, disputes, export, or estimate support in `osp-core/crates/osp-sdk/src/client.rs`.

4. **No real registry deployment / runtime**
   - The registry crate (`osp-registry`) has server code but there is no evidence of a running instance or seed data. The Dockerfile and fly.toml exist but no deployed artifact.

5. **Provider adapters are stubs**
   - Adapters in `osp-core/crates/osp-provider/src/adapters/` return hardcoded credential JSON and do not make actual API calls to provider services (e.g., Vercel adapter returns `{"vercel_token": "fake_token"}`).

6. **No actual `osp.yaml` parser / runtime**
   - Examples exist (`examples/*/osp.yaml`) but no CLI or library actually parses and provisions from these files. The `Apply` command in the Rust CLI is a stub.

7. **No TypeScript Config (`osp.config.ts`) implementation**
   - The README advertises "TypeScript Config — `osp.config.ts` with Pulumi-style programmatic configuration." **Not found anywhere in the repository.**

8. **Missing schema files**
   - No dedicated `cost-summary.schema.json` at root level (only referenced in code).
   - No `a2a-delegation.schema.json`, `nhi-token.schema.json`, or `finops-config.schema.json` as standalone files.

9. **No actual payment integration**
   - The `sardis-integration` package exists but is mostly scaffolding. No real payment flow, escrow contract interaction, or settlement logic.

10. **No Python/TypeScript vault implementation**
    - Only Rust (`osp-vault`) has credential vault logic. Python and TypeScript SDKs have no encrypted local credential store.

11. **No `lifecycle` module as a first-class abstraction**
    - While "lifecycle" is used as a term (status, provisioning, deprovisioning), there is no unified `LifecycleManager` or state machine in any SDK.

12. **No `ownership` transfer endpoint implemented**
    - Spec mentions cross-project resource sharing and `principal_id`, but no `POST /osp/v1/share/{resource_id}` or ownership transfer is actually implemented in any SDK.

---

## 6. Conflicts & Issues Noticed

### A. Version Inconsistencies
- **README** says "Spec v1.1 Features" and badge says `v1.1--draft`.
- **Spec file** is named `osp-v1.0.md` but contains v1.1 sections.
- **TypeScript types** mention `v1.2` in comments (`// v1.2: agent identity, sandbox mode, idempotency`) but there is no v1.2 spec document.
- **Go SDK** has `userAgent = "osp-sdk-go/1.0"` while the README claims it supports v1.1.

### B. Schema vs. Code Drift
- The JSON Schema (`service-manifest.schema.json`) uses `mf_[a-z0-9_]+$` pattern for `manifest_id`, but the spec text example uses a UUID v4 (`a1b2c3d4-e5f6-7890-abcd-ef1234567890`). These are incompatible.
- The spec's `ProvisionRequest` has a `metadata` object with structured tag conventions, but the JSON Schema (`provision-request.schema.json`) does not include a `metadata` field at all.
- Go `types.go` defines `CredentialType` but is missing `"short_lived_token"` (the schema has it, TypeScript has it, Go does not).

### C. Checked-in Dependencies
- **`node_modules`** checked into git:
  - `sardis-integration/node_modules`
  - `website/node_modules`
  - `reference-implementation/typescript/node_modules`
- **`.venv`** checked into git:
  - `reference-implementation/python/.venv`
- These should be `.gitignore`d but are present. The `.gitignore` at root only ignores `.DS_Store` and `tmp/`.

### D. Duplicate / Orphan Content
- **`.claude/worktrees/`** directory contains what appears to be multiple agent worktree copies of the same files (spec, docs, LICENSE). These are not part of the main repo structure and appear to be artifacts from Claude Code sessions. They duplicate content and bloat the repo.

### E. Package Naming Conflicts
- The TypeScript SDK is named `@osp/client` in `reference-implementation/typescript/package.json`, but the Rust CLI binary is named `osp`. No actual conflict, but the namespace is shared.
- The MCP server is `@osp/mcp-server` but depends on `@modelcontextprotocol/sdk` as a peer dependency. The Sardis integration also peer-depends on `@osp/client >=0.1.0` but the actual client is `0.2.0`.

### F. Missing Tests for Rust Core
- The README claims 46 tests for Rust, but many crates (`osp-cli`, `osp-registry`, `osp-sdk`, `osp-provider`) contain minimal or stub test implementations. The `osp-cli` commands have no real tests.

### G. Endpoint Path Inconsistencies
- The **getting-started docs** (`docs/getting-started.md`) list endpoints like `/osp/v1/resources/{id}/credentials` and `/osp/v1/resources/{id}/upgrade`.
- The **spec** lists `/osp/v1/credentials/{resource_id}` and has no `upgrade` endpoint (only tier change within `ProvisionRequest`).
- The **TypeScript client** uses whatever path is in the manifest endpoints (e.g., `:resource_id`), while the **Go SDK** uses the manifest's endpoint paths directly. No single canonical path is enforced across docs, spec, and code.

### H. Cargo.toml Claims vs. Reality
- `Cargo.toml` lists `osp-crypto`, `osp-manifest`, `osp-vault`, `osp-cli`, `osp-provider`, `osp-registry`, `osp-conformance`, `osp-sdk`.
- Several of these crates have incomplete implementations (CLI stubs, provider adapters returning fake data, registry not deployed).

---

## 7. Recommended Action for FIDES v2

1. **Reuse OSP registry concept** as inspiration for FIDES Agent Registry — the Axum-based registry server pattern (`osp-registry/src/server.rs`) is a good reference.
2. **Reuse OSP service lifecycle semantics** (provision, rotate, deprovision, status) for FIDES agent/service lifecycle management.
3. **Reuse JSON Schema discipline** — OSP has well-structured schemas. FIDES v2 should adopt the same rigor for all protocol objects.
4. **Reuse credential rotation pattern** from OSP for FIDES key rotation and delegation token rotation.
5. **Do NOT depend on OSP Rust crates** — they are largely stubs. Port concepts into TypeScript.
6. **Consider OSP's `ServiceManifest` / `ServiceOffering` pattern** as a model for FIDES `CapabilityDescriptor` and `AgentCard` versioning.
