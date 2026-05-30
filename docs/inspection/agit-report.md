# AGIT Repository Inspection Report

Source repo: `/Users/efebarandurmaz/agit`

Note: the AGIT worktree is dirty. This report reflects current local files and is read-only evidence for FIDES v2.

## 1. Repo Purpose

AGIT is a Git-like version-control and audit system for AI agent state: content-addressed commits, branch/merge/revert, JSON state diffing, audit logs, SDK bindings, REST API, MCP/A2A/FIDES integrations.

Local evidence:

- Project docs and repo purpose: `/Users/efebarandurmaz/agit/README.md`, `/Users/efebarandurmaz/agit/ARCHITECTURE.md`.
- Multi-language package roots: `/Users/efebarandurmaz/agit/Cargo.toml`, `/Users/efebarandurmaz/agit/pyproject.toml`, `/Users/efebarandurmaz/agit/ts-sdk/package.json`.

## 2. Main Packages / Modules

| Area | Path | Purpose |
|---|---|---|
| Rust core | `/Users/efebarandurmaz/agit/crates/agit-core/src/lib.rs` | Repository orchestration, objects, refs, state diff/merge, hashing, storage, guards, approvals, events, causal graph, encryption. |
| Python SDK/CLI/server | `/Users/efebarandurmaz/agit/python/agit/engine/executor.py`, `/Users/efebarandurmaz/agit/python/agit/cli/app.py`, `/Users/efebarandurmaz/agit/python/agit/server/routes.py` | Execution engine, Typer CLI, FastAPI server. |
| TypeScript SDK | `/Users/efebarandurmaz/agit/ts-sdk/src/index.ts`, `/Users/efebarandurmaz/agit/ts-sdk/src/client.ts`, `/Users/efebarandurmaz/agit/ts-sdk/src/types.ts` | TS client and integration exports. |
| Native bindings | `/Users/efebarandurmaz/agit/crates/agit-python/Cargo.toml`, `/Users/efebarandurmaz/agit/crates/agit-node/Cargo.toml` | PyO3 and napi-rs packaging. |
| CI | `/Users/efebarandurmaz/agit/.github/workflows/ci.yml` | Rust, Python, TS, and security checks. |

## 3. Existing Primitives

- Identity / DID / Ed25519 / signatures exist only in adapters, not AGIT core. Python FIDES integration generates `did:fides:<base58(pubkey)>`, signs state hashes with PyNaCl, and verifies signatures in `/Users/efebarandurmaz/agit/python/agit/integrations/fides.py`.
- TypeScript FIDES integration delegates identity/signing/verification/reputation to external `@fides/sdk`: `/Users/efebarandurmaz/agit/ts-sdk/src/integrations/fides.ts`, `/Users/efebarandurmaz/agit/ts-sdk/package.json`.
- Agent state exists as a core primitive in `/Users/efebarandurmaz/agit/crates/agit-core/src/state.rs`.
- Evidence/event/audit-like primitives exist as commits, storage logs, event bus, and server event bus: `/Users/efebarandurmaz/agit/crates/agit-core/src/objects.rs`, `/Users/efebarandurmaz/agit/crates/agit-core/src/storage/mod.rs`, `/Users/efebarandurmaz/agit/crates/agit-core/src/events.rs`, `/Users/efebarandurmaz/agit/python/agit/server/event_bus.py`.
- Hash/canonical/Merkle-adjacent primitives exist: canonical JSON serialization, SHA-256 object hashing, state hash, and Merkle tree diff in `/Users/efebarandurmaz/agit/crates/agit-core/src/hash.rs` and `/Users/efebarandurmaz/agit/crates/agit-core/src/state.rs`.
- Trust/reputation/attestation are adapter calls and committed audit payloads, not AGIT-native protocol objects: `/Users/efebarandurmaz/agit/python/agit/integrations/fides.py`, `/Users/efebarandurmaz/agit/ts-sdk/src/integrations/fides.ts`.
- Policy/approval/guardrails partially exist as commit guards, blast-radius analysis, pending approvals, validators, and safety docs: `/Users/efebarandurmaz/agit/crates/agit-core/src/guard.rs`, `/Users/efebarandurmaz/agit/crates/agit-core/src/blast_radius.rs`, `/Users/efebarandurmaz/agit/crates/agit-core/src/approval.rs`, `/Users/efebarandurmaz/agit/python/agit/engine/validator.py`, `/Users/efebarandurmaz/agit/docs/plans/2026-03-11-safety-layer-design.md`.
- Graph primitive is a commit causal graph, not a trust graph: `/Users/efebarandurmaz/agit/crates/agit-core/src/causal.rs`.
- MCP and A2A integrations exist: `/Users/efebarandurmaz/agit/python/agit/integrations/mcp_server.py`, `/Users/efebarandurmaz/agit/tests/integration/test_mcp_server.py`, `/Users/efebarandurmaz/agit/python/agit/integrations/a2a.py`, `/Users/efebarandurmaz/agit/ts-sdk/src/integrations/a2a.ts`.

## 4. Relevant Files

- `/Users/efebarandurmaz/agit/crates/agit-core/src/hash.rs`
- `/Users/efebarandurmaz/agit/crates/agit-core/src/objects.rs`
- `/Users/efebarandurmaz/agit/crates/agit-core/src/state.rs`
- `/Users/efebarandurmaz/agit/crates/agit-core/src/events.rs`
- `/Users/efebarandurmaz/agit/crates/agit-core/src/storage/mod.rs`
- `/Users/efebarandurmaz/agit/crates/agit-core/src/guard.rs`
- `/Users/efebarandurmaz/agit/crates/agit-core/src/blast_radius.rs`
- `/Users/efebarandurmaz/agit/crates/agit-core/src/approval.rs`
- `/Users/efebarandurmaz/agit/crates/agit-core/src/causal.rs`
- `/Users/efebarandurmaz/agit/python/agit/integrations/fides.py`
- `/Users/efebarandurmaz/agit/ts-sdk/src/integrations/fides.ts`
- `/Users/efebarandurmaz/agit/python/agit/integrations/mcp_server.py`
- `/Users/efebarandurmaz/agit/python/agit/integrations/a2a.py`

## 5. Reusable Components

- Deterministic canonical hashing and content-addressed object model from `/Users/efebarandurmaz/agit/crates/agit-core/src/hash.rs` and `/Users/efebarandurmaz/agit/crates/agit-core/src/objects.rs`.
- Append-style audit/event surfaces and storage abstraction from `/Users/efebarandurmaz/agit/crates/agit-core/src/storage/mod.rs` and `/Users/efebarandurmaz/agit/crates/agit-core/src/events.rs`.
- Guard chain and blast-radius scoring as prior art for pre-action policy enforcement: `/Users/efebarandurmaz/agit/crates/agit-core/src/guard.rs`, `/Users/efebarandurmaz/agit/crates/agit-core/src/blast_radius.rs`.
- Approval request model from `/Users/efebarandurmaz/agit/crates/agit-core/src/approval.rs`, with a durability caveat.
- Causal graph for future evidence/root-cause analysis: `/Users/efebarandurmaz/agit/crates/agit-core/src/causal.rs`.

## 6. Missing Components

I could not find core implementations for:

- Revocation records.
- Incident records.
- TEE/runtime attestations.
- DHT, relay, federation, or well-known discovery.
- AP2, x402, TAP, mandate-chain, delegation token, session authority, grants.
- Registry/capability registry.
- Provision/rotate/deprovision lifecycle.
- Privacy-preserving evidence.
- Canonical FIDES v2 schemas.

The closest matches are generic REST schemas in `/Users/efebarandurmaz/agit/python/agit/server/models.py`, FIDES adapters in `/Users/efebarandurmaz/agit/python/agit/integrations/fides.py` and `/Users/efebarandurmaz/agit/ts-sdk/src/integrations/fides.ts`, and safety primitives in `/Users/efebarandurmaz/agit/crates/agit-core/src/guard.rs`.

## 7. Conflicts With FIDES v2 Architecture

- FIDES claims in AGIT docs are stronger than AGIT core implementation: DID signing and trust are adapter-level, not Rust-core verifiable protocol primitives.
- Python and TypeScript FIDES signing models differ: Python signs a SHA-256 state hash directly; TypeScript delegates to external FIDES request signing.
- Approval storage is not durable enough as-is for FIDES v2.
- AGIT is a VCS/evidence substrate, not the canonical identity/trust/authority runtime.

## 8. Recommended Action

Use AGIT as a Rust adapter-ready evidence and lineage substrate, not as the FIDES v2 primitive source of truth. Port concepts, not dependencies:

- canonical hashing,
- content-addressed objects,
- commit/state lineage,
- Merkle/state diff concepts,
- event/audit surfaces,
- guard/blast-radius ideas,
- causal graph.

Do not import AGIT's current FIDES adapters as protocol canon. FIDES must own the identity, signing envelope, revocation, delegation/session, evidence, and trust graph types.
