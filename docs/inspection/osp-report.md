# OSP Repository Inspection Report

Source repo: `/Users/efebarandurmaz/osp`

Note: the OSP worktree is dirty and behind origin. This report reflects current local files and is read-only evidence for FIDES v2.

## 1. Repo Purpose

OSP is an open protocol for agent-driven service discovery, provisioning, credential delivery, rotation, deprovisioning, registry lookup, conformance, SDKs, MCP tooling, and provider integrations.

Local evidence:

- Core framing: `/Users/efebarandurmaz/osp/README.md`, `/Users/efebarandurmaz/osp/spec/osp-v1.0.md`.
- Main Rust workspace: `/Users/efebarandurmaz/osp/osp-core/Cargo.toml`.

## 2. Main Packages / Modules

| Area | Path | Purpose |
|---|---|---|
| Rust workspace | `/Users/efebarandurmaz/osp/osp-core/Cargo.toml` | `osp-crypto`, `osp-manifest`, `osp-vault`, `osp-cli`, `osp-provider`, `osp-registry`, `osp-conformance`, `osp-sdk`. |
| TypeScript reference SDK | `/Users/efebarandurmaz/osp/reference-implementation/typescript/src/index.ts` | Client, types, crypto, resolver, MCP server exports. |
| Python SDK | `/Users/efebarandurmaz/osp/reference-implementation/python/src/osp/__init__.py` | Types, client, manifest, resolver, provider. |
| Go SDK | `/Users/efebarandurmaz/osp/osp-sdk-go/types.go` | Discovery/provisioning/credential/usage types. |
| MCP server | `/Users/efebarandurmaz/osp/packages/mcp-server/src/server.ts` | Discover, provision, status, deprovision, rotate tools. |
| Provider frameworks | `/Users/efebarandurmaz/osp/packages/provider-framework/typescript/src/middleware.ts`, `/Users/efebarandurmaz/osp/packages/provider-framework/python/src/osp_provider/router.py` | Express/FastAPI provider scaffolding. |
| Sardis integration | `/Users/efebarandurmaz/osp/sardis-integration/src/payment/types.ts` | Wallet, escrow, mandate, ledger models. |

## 3. Existing Primitives

- Identity methods are specified for Ed25519 DID, OAuth2 client, and API key identities in `/Users/efebarandurmaz/osp/spec/osp-v1.0.md`; Rust has `AgentIdentity` and `AgentIdentityMethod` in `/Users/efebarandurmaz/osp/osp-core/crates/osp-manifest/src/types.rs`.
- Signature/canonical/Ed25519 primitives exist in Rust crypto: `/Users/efebarandurmaz/osp/osp-core/crates/osp-crypto/src/lib.rs`, `/Users/efebarandurmaz/osp/osp-core/crates/osp-crypto/src/signing.rs`, `/Users/efebarandurmaz/osp/osp-core/crates/osp-crypto/src/canonical.rs`.
- Credential encryption exists via Ed25519-to-X25519 and XSalsa20-Poly1305 in `/Users/efebarandurmaz/osp/osp-core/crates/osp-crypto/src/encryption.rs`; JSON schema exists at `/Users/efebarandurmaz/osp/schemas/credential-bundle.schema.json`.
- Discovery/registry primitives include well-known manifest fetching and registry models: `/Users/efebarandurmaz/osp/osp-core/crates/osp-manifest/src/fetch.rs`, `/Users/efebarandurmaz/osp/osp-core/crates/osp-registry/src/models.rs`.
- Delegation/capability shapes exist as A2A capabilities and delegation chain structs: `/Users/efebarandurmaz/osp/osp-core/crates/osp-manifest/src/types.rs`.
- Trust/reputation exists as trust tier and registry reputation metadata: `/Users/efebarandurmaz/osp/osp-core/crates/osp-manifest/src/types.rs`, `/Users/efebarandurmaz/osp/osp-core/crates/osp-registry/src/models.rs`.
- Event/evidence concepts are schema/spec-level lifecycle events and dispute/compliance evidence, not a FIDES evidence ledger: `/Users/efebarandurmaz/osp/schemas/webhook-event.schema.json`, `/Users/efebarandurmaz/osp/spec/osp-v1.0.md`.
- Sardis mandate/policy/approval examples exist in `/Users/efebarandurmaz/osp/sardis-integration/src/payment/types.ts`.
- Revocation is documented in `/Users/efebarandurmaz/osp/docs/security-model.md` and `/Users/efebarandurmaz/osp/spec/osp-v1.0.md`, but no standalone revocation registry/service was found.

## 4. Relevant Files

- `/Users/efebarandurmaz/osp/README.md`
- `/Users/efebarandurmaz/osp/spec/osp-v1.0.md`
- `/Users/efebarandurmaz/osp/osp-core/Cargo.toml`
- `/Users/efebarandurmaz/osp/osp-core/crates/osp-crypto/src/canonical.rs`
- `/Users/efebarandurmaz/osp/osp-core/crates/osp-crypto/src/signing.rs`
- `/Users/efebarandurmaz/osp/osp-core/crates/osp-crypto/src/encryption.rs`
- `/Users/efebarandurmaz/osp/osp-core/crates/osp-manifest/src/types.rs`
- `/Users/efebarandurmaz/osp/osp-core/crates/osp-manifest/src/fetch.rs`
- `/Users/efebarandurmaz/osp/osp-core/crates/osp-manifest/src/verify.rs`
- `/Users/efebarandurmaz/osp/osp-core/crates/osp-registry/src/models.rs`
- `/Users/efebarandurmaz/osp/packages/mcp-server/src/server.ts`
- `/Users/efebarandurmaz/osp/schemas/service-manifest.schema.json`
- `/Users/efebarandurmaz/osp/schemas/provision-request.schema.json`
- `/Users/efebarandurmaz/osp/schemas/credential-bundle.schema.json`
- `/Users/efebarandurmaz/osp/schemas/webhook-event.schema.json`
- `/Users/efebarandurmaz/osp/sardis-integration/src/payment/types.ts`
- `/Users/efebarandurmaz/osp/sardis-integration/src/payment/ledger.ts`

## 5. Reusable Components

- Canonical JSON and Ed25519 signing/verification as comparison material for FIDES signed protocol objects.
- Manifest verification flow for signed registry/discovery objects.
- Identity/delegation/NHI schemas as draft input, not final FIDES authority schemas.
- Registry models and service lifecycle vocabulary for FIDES registry/federation and OSP adapter mapping.
- Sardis `SpendingMandate` and `SpendingPolicy` as payment-specific examples of grants/mandates, not generic FIDES core.

## 6. Missing Components

I could not find:

- Merkle tree or transparency log.
- Tamper-evident FIDES-style evidence ledger.
- TEE/runtime attestation implementation.
- DHT or relay discovery.
- Federation runtime.
- Kill-switch primitives.
- Generic signed action/envelope model separate from OSP manifests, usage reports, credential bundles, and webhooks.
- Implemented DID resolution or nonce-signature verification beyond structural/offline conformance assertions.

## 7. Conflicts With FIDES v2 Architecture

- OSP spec says agent identity is a non-goal in one place while later formalizing OSP agent identity methods. FIDES must own generic identity/authority, while OSP owns service lifecycle.
- JSON Schema and Rust manifest shapes drift, especially around provider fields.
- `AgentIdentity` exists under `$defs` in a provision-request schema but is not exposed as a top-level accepted property.
- Crypto algorithm descriptions differ between Rust/spec and TypeScript helper paths.
- OSP service provisioning, credential delivery, pricing, provider manifest, and deprovisioning are adjacent but not FIDES core.

## 8. Recommended Action

Use OSP as the source for service lifecycle and registry/provisioning adapter semantics:

- discovery/provision/rotate/deprovision vocabulary,
- signed service manifest verification ideas,
- provider registry/search concepts,
- credential rotation/deprovisioning boundaries,
- MCP server integration shape.

Do not directly import OSP schemas into FIDES v2 authority objects. FIDES should define its own `AgentCard`, `DelegationToken`, `SessionGrant`, `EvidenceEvent`, `RevocationRecord`, and `TrustGraphEdge`, then provide an OSP adapter that maps FIDES authority to OSP service lifecycle operations.
