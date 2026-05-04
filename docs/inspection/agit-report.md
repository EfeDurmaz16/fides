# AGIT Repository Inspection Report

## 1. Repo Purpose

**AgentGit (agit)** is a purpose-built version control system for AI agents. It provides Git-like semantics (commit, branch, merge, diff, revert, log) over structured JSON agent state, with a high-performance Rust core, Python (PyO3) and TypeScript (napi-rs) SDKs, and integrations for 8+ agent frameworks (Claude SDK, OpenAI Agents, LangGraph, CrewAI, Google ADK, Vercel AI, MCP, Google A2A, and FIDES trust protocol).

**Key docs read:**
- `README.md`
- `ARCHITECTURE.md`
- `agit-technical-due-diligence.md`
- `Cargo.toml`
- `pyproject.toml`

---

## 2. Main Packages / Modules

```
/Users/efebarandurmaz/agit/
├── crates/
│   ├── agit-core/          # Rust VCS engine (SHA-256 DAG, Merkle diff, merge, GC, encryption)
│   ├── agit-python/        # PyO3 bindings (cdylib)
│   └── agit-node/          # napi-rs bindings (cdylib)
├── python/agit/            # Python SDK + CLI + integrations + server
│   ├── cli/app.py          # Typer CLI
│   ├── engine/executor.py  # ExecutionEngine wrapper
│   ├── integrations/       # FIDES, A2A, LangGraph, CrewAI, etc.
│   ├── server/             # FastAPI routes, auth, middleware, circuit breaker
│   ├── swarm/              # Multi-agent orchestrator + consensus
│   └── ui/                 # Streamlit dashboards
├── ts-sdk/src/             # TypeScript SDK
│   ├── client.ts           # AgitClient + PureTsRepository fallback
│   ├── types.ts            # Shared TS types
│   └── integrations/       # TS hooks for Claude, OpenAI, LangGraph, A2A, FIDES, MCP, Vercel
├── web/                    # Next.js 15 dashboard
├── vscode-extension/       # VS Code extension
├── examples/               # 16 runnable demo scripts
├── tests/                  # Python test suite
└── docs/                   # Architecture plans + markdown docs
```

---

## 3. Existing Primitives (with Exact File Paths)

### Core VCS Primitives (Rust)

| Primitive | File Path | Description |
|-----------|-----------|-------------|
| `Blob` / `Commit` | `crates/agit-core/src/objects.rs` | Content-addressed blob + commit struct with parent hashes forming a DAG |
| `Hash` (SHA-256) | `crates/agit-core/src/types.rs` | 64-char hex string wrapper |
| `compute_hash` / `canonical_serialize` | `crates/agit-core/src/hash.rs` | Git-style `<type> <len>\0<content>` SHA-256 hashing with deterministic JSON key sorting |
| `AgentState` / `StateDiff` / `DiffEntry` / `MergeConflict` | `crates/agit-core/src/state.rs` | Full agent state, recursive JSON diff, three-way merge |
| `MerkleNode` / `merkle_diff` | `crates/agit-core/src/state.rs` | Merkle tree over JSON subtrees for O(log N) diffing |
| `Repository` | `crates/agit-core/src/repo.rs` | Main orchestrator: commit, branch, checkout, merge, diff, revert, log, gc, retention, squash |
| `RefStore` / `Head` | `crates/agit-core/src/refs.rs` | In-memory branch + HEAD reference management |
| `StorageBackend` trait | `crates/agit-core/src/storage/mod.rs` | Pluggable async storage interface |
| `SqliteStorage` | `crates/agit-core/src/storage/sqlite.rs` | SQLite backend (WAL mode, bundled) |
| `PostgresStorage` | `crates/agit-core/src/storage/postgres.rs` | PostgreSQL backend (deadpool, multi-tenant namespacing) |
| `S3Storage` | `crates/agit-core/src/storage/s3.rs` | S3 backend (zstd compression, SQS notifications, server-side AES-256) |
| `AgitEvent` / `InMemoryEventBus` | `crates/agit-core/src/events.rs` | Append-only event log + synchronous callbacks |
| `CausalGraph` / `CausalEdge` / `CausalNode` | `crates/agit-core/src/causal.rs` | Petgraph-backed causal dependency graph across commits |
| `GuardChain` / `CommitGuard` / `GuardContext` | `crates/agit-core/src/guard.rs` | Pre-commit guard framework with Allow/Warn/Block decisions |
| `DestructiveActionGuard` | `crates/agit-core/src/guard.rs` | Blocks commits with excessive key deletion |
| `BlastRadiusGuard` | `crates/agit-core/src/guard.rs` | Blocks commits above a blast-radius risk threshold |
| `BlastRadiusReport` / `RiskLevel` | `crates/agit-core/src/blast_radius.rs` | Diff-based risk scoring (weighted added/removed/modified) |
| `ApprovalStore` / `PendingApproval` / `ApprovalStatus` | `crates/agit-core/src/approval.rs` | In-memory approval workflow for high-risk commits |
| `StateEncryptor` (AES-256-GCM + Argon2id) | `crates/agit-core/src/encryption.rs` | Field-level encryption with per-context salt derivation |
| `GcResult` / `SquashResult` / `gc` / `squash` | `crates/agit-core/src/gc.rs` | Mark-and-sweep GC + commit range squashing |
| `BisectSession` / `BisectResult` / `BisectState` | `crates/agit-core/src/bisect.rs` | Binary search through commit history to find regressions |
| `RetentionPolicy` / `RetentionResult` | `crates/agit-core/src/retention.rs` | Configurable auto-cleanup (age, count, protected branches, log pruning) |
| `Migration` / `MigrationResult` / `migrate_data` / `apply_schema_migrations` | `crates/agit-core/src/migration.rs` | Schema versioning + cross-backend data migration |
| `AgitError` enum | `crates/agit-core/src/error.rs` | Comprehensive error types via `thiserror` |
| `ActionType` / `MergeStrategy` / `ChangeType` / `ObjectType` | `crates/agit-core/src/types.rs` | Core enums |

### Audit / Integrity Primitives

| Primitive | File Path | Description |
|-----------|-----------|-------------|
| Hash-chained audit log | `crates/agit-core/src/repo.rs` (lines 653-698) | `compute_audit_hash` chains log entries via SHA-256 of previous integrity hash |
| `LogEntry` / `LogFilter` | `crates/agit-core/src/storage/mod.rs` | Structured audit log entries |

### Python SDK Primitives

| Primitive | File Path | Description |
|-----------|-----------|-------------|
| `ExecutionEngine` | `python/agit/engine/executor.py` | High-level wrapper with auto-commit, PII masking, validation, retry |
| `AgitFidesEngine` / `FidesIdentity` | `python/agit/integrations/fides.py` | DID-signed commits (Ed25519), trust-gated merge, attestation |
| `AgitA2AExecutor` / `AgitA2AClient` | `python/agit/integrations/a2a.py` | A2A protocol wrapper with branch-per-context versioning |
| CLI (`agit`) | `python/agit/cli/app.py` | Full Typer CLI (init, commit, branch, checkout, log, diff, merge, revert, status, audit, retry, gc, bisect, causal-graph, retention, squash, doctor, monitor, identity) |

### TypeScript SDK Primitives

| Primitive | File Path | Description |
|-----------|-----------|-------------|
| `AgitClient` | `ts-sdk/src/client.ts` | High-level client with native binding + pure-TS fallback |
| `PureTsRepository` | `ts-sdk/src/client.ts` | In-memory fallback implementing full three-way merge + BFS merge base |
| `AgitEventStream` | `ts-sdk/src/client.ts` | SSE event stream client with exponential backoff reconnect |

---

## 4. Search Results for Key Terms

| Term | Found? | Locations / Notes |
|------|--------|-------------------|
| **version control** | Yes | README, CLI help, types, docs throughout |
| **DAG** | Yes | `Commit.parent_hashes` forms DAG; `CausalGraph` uses `petgraph::DiGraph` in `crates/agit-core/src/causal.rs` |
| **Merkle** | Yes | `MerkleNode` and `merkle_diff` in `crates/agit-core/src/state.rs` (lines 192-317) |
| **merge lineage** | Partial | Merge base via BFS in `repo.rs` (L450-488); no explicit "merge lineage" index, but causal graph captures `BranchMerge` edges |
| **evidence** | No | No standalone "evidence" primitive. Closest is hash-chained audit log and FIDES signatures |
| **versioning** | Yes | README, SDKs, examples; "state versioning" is core value prop |
| **signed state** | Yes | FIDES integration signs state hash with Ed25519 in `python/agit/integrations/fides.py` |
| **content addressing** | Yes | `Blob.hash()` and `Commit.hash()` use SHA-256 over canonical serialized content in `objects.rs` + `hash.rs` |
| **hash chain** | Yes | Audit log entries chain `integrity_hash` -> `prev_integrity_hash` in `repo.rs` (L653-698) |
| **commit** | Yes | Ubiquitous; core primitive in `objects.rs`, `repo.rs`, all SDKs, CLI |
| **event** | Yes | `AgitEvent` enum in `crates/agit-core/src/events.rs`; SSE streaming in TS SDK |

---

## 5. CLI Entrypoints, SDK Exports, Examples, Tests

### CLI Entrypoint
- **Command:** `agit`
- **Entrypoint:** `python/agit/cli/app.py` -> `main()`
- **Registered in:** `pyproject.toml` line 56: `agit = "agit.cli.app:main"`

### SDK Exports
- **Python SDK exports:** `python/agit/__init__.py` -> `ExecutionEngine`, `RetryEngine`, `ValidatorRegistry`, `PyRepository`, `PyAgentState`, etc.
- **TypeScript SDK exports:** `ts-sdk/src/index.ts` -> `AgitClient`, types, and all framework integration hooks.

### Examples (16 runnable demos)
All located in `examples/`:
- `fides_demo.py`, `a2a_demo.py`, `langgraph_demo.py`, `claude_demo.py`, `openai_demo.py`, `crewai_demo.py`, `google_adk_demo.py`, `vercel_ai_demo.py`, `mcp_demo.py`, `swarm_demo.py`, `multi_sdk_demo.py`, `openclaw_demo.py`, `legal_review.py`, `finance_trade.py`, `health_agent.py`

### Tests
- **Rust tests:** `cargo test --workspace` (CI runs these). Core crate has inline `#[cfg(test)]` modules in nearly every file.
- **Python tests:** `tests/` with subdirs: `cli/`, `core/`, `engine/`, `integration/`, `benchmarks/`
- **TypeScript tests:** `cd ts-sdk && npm test` (vitest)

---

## 6. Schemas / Specs / CI / Config

### CI / Config Files
- **GitHub CI:** `.github/workflows/ci.yml`
  - Security scanning (TruffleHog secrets, Trivy container scan)
  - Rust (fmt, clippy, test, observability feature test)
  - Python (maturin build, ruff, mypy, contract checks, pytest)
  - TypeScript (napi build, tsc, vitest)
- **Release workflow:** `.github/workflows/release.yml` (cosign signing, SBOM)
- **Makefile:** `Makefile` (build, test, lint, format, dev, clean)
- **Docker:** `docker/Dockerfile`
- **Rust toolchain:** `rust-toolchain.toml`

### Schemas
- **SQLite schema:** Defined in `SqliteStorage::initialize()` at `crates/agit-core/src/storage/sqlite.rs` (lines 49-94) — tables: `objects`, `refs`, `logs`, plus indexes.
- **PostgreSQL schema:** Defined in `PostgresStorage::initialize()` at `crates/agit-core/src/storage/postgres.rs` (lines 102-147) — same tables with `BYTEA`/`JSONB` types.
- **S3 layout:** Documented in `crates/agit-core/src/storage/s3.rs` (lines 22-28) — `objects/<hash>`, `refs/<name>`, `logs/<agent_id>/<timestamp>_<uuid>.json`.
- **Schema migrations:** `crates/agit-core/src/migration.rs` — currently at version 2.

---

## 7. What Is Reusable

1. **Rust core VCS primitives** (`objects.rs`, `hash.rs`, `state.rs`, `refs.rs`) — The Blob/Commit DAG, SHA-256 content addressing, Merkle diff, and three-way merge are cleanly separated from storage and can be reused as a library.
2. **`StorageBackend` trait + implementations** (`storage/mod.rs`, `sqlite.rs`, `postgres.rs`, `s3.rs`) — Well-abstracted async trait. SQLite and Postgres backends are production-ready with migrations.
3. **Merkle diff algorithm** (`state.rs`) — Novel O(log N) JSON diffing. Highly reusable for any structured-state versioning use case.
4. **Guard framework** (`guard.rs`) — Trait-based pre-commit guards with built-in destructive-action and blast-radius guards. Easy to extend.
5. **Event bus** (`events.rs`) — Simple in-process append-only event log with callbacks. Useful for any repository mutation streaming.
6. **Causal graph** (`causal.rs`) — Petgraph-based DAG analysis with root-cause tracing and critical path finding.
7. **Python `ExecutionEngine`** (`executor.py`) — Auto-commit wrapper pattern with PII masking and validation hooks.
8. **FIDES signing logic** (`fides.py`) — Ed25519 DID-signed state commits with verification. Portable to other contexts.
9. **Pure-TypeScript fallback repository** (`client.ts` lines 109-345) — Full in-memory VCS with three-way merge, useful for browser/edge environments without native binaries.

---

## 8. What Is Missing

1. **Distributed consensus / sharding** — Explicitly documented as a known limitation in README. No Raft/Paxos/BFT. Single-writer architecture only.
2. **Horizontal scaling** — No multi-region replication, no read replicas for Postgres backend beyond the connection pool.
3. **Prometheus / Grafana observability stack** — Rust core has feature-gated `tracing::instrument`, but no Prometheus exporter or OTel metrics. Python has stub modules for Prometheus/OTel but no active exporters wired in.
4. **OIDC / SAML SSO** — RBAC exists (`python/agit/server/auth.py`) but no SSO integration.
5. **`Arc<Cow<AgentState>>` optimization** — `AgentState` is cloned on every commit. The due diligence notes this as a remaining medium bottleneck for states > 100MB.
6. **S3 log pruning** — `delete_logs_before` and `prune_logs_excess` return `Ok(0)` in S3 backend (deferred to S3 lifecycle policies).
7. **CLI `squash` is a stub** — `python/agit/cli/app.py` line 567-569: it checks out the branch and commits the current state with a squash message, rather than using the Rust `gc::squash` logic.
8. **Real A2A / FIDES SDK availability** — TS `package.json` lists `@fides/sdk` and `a2a-sdk` as optional peer dependencies. These packages do not appear to be on npm (likely placeholders or private).
9. **Python stub vs native parity gaps** — `executor.py` uses many `hasattr` checks (`audit_log`, `bisect_start`, `get_causal_graph`, `preview_retention`, etc.) indicating the pure-Python stub backend lacks features present in the Rust core.
10. **No "evidence" primitive** — There is signed state (FIDES) and hash-chained audit logs, but no standalone tamper-proof "evidence" envelope or notarization primitive separate from the commit/log flow.

---

## 9. Conflicts / Inconsistencies Noticed

1. **Repository URL mismatch:**
   - `README.md` line 1 CI badge points to `EfeDurmaz16/agit`.
   - `pyproject.toml` lines 32-35 point to `anthropics/agit` (Homepage, Documentation, Repository, Issues).
   - `ts-sdk/package.json` lines 9-11 also point to `anthropics/agit`.
   - **Conflict:** The repo appears to be a fork or personal copy under `EfeDurmaz16`, but package metadata claims `anthropics` as the owner.

2. **Due diligence claims vs. code:**
   - The due diligence file claims "zero .unwrap() in production Rust code" and "constant-time HMAC comparisons." However, I did not find HMAC usage in the core — the audit chain uses plain SHA-256 concatenation, not HMAC. Also, some non-test code uses `.unwrap()` in serialization helpers (e.g., `canonical_serialize` in `hash.rs` line 39: `serde_json::to_string(value).unwrap_or_default()` — benign but not zero).
   - The due diligence claims "Fernet encryption in Python fallback layer." The actual Python stubs file (`python/agit/_stubs.py`) was not fully read, but the due diligence says XOR was replaced with Fernet. If the stub file still uses a naive fallback, that would be a conflict.

3. **S3 `delete_logs_before` / `prune_logs_excess` silently no-op:**
   - These methods return `Ok(0)` without deleting anything. This is a behavioral gap that could surprise operators expecting retention policies to work on S3.

4. **CLI `gc` command does not actually run GC when using stubs:**
   - `app.py` line 367-373 just counts reachable history and prints a message. It does not invoke `engine.gc()`.

5. **Python `PyProject.toml` `requires-python` is `>=3.12`** while the `classifiers` only list 3.12 and 3.13. This is consistent but strict; many enterprises are still on 3.11.

6. **TS SDK `package.json` peer dependencies include `@fides/sdk` and `a2a-sdk`** with versions `>=0.1.0`. These are not real packages on npm as of this inspection. The TS integration files import from these modules but are likely stubs or aspirational.

7. **The `agit-technical-due-diligence.md` file contains speculative valuation and funding recommendations** ($16M-$24M post-money, $4M-$6M round) that appear to be generated content rather than actual investor documents. This is not a code conflict but a metadata inconsistency — the file reads like an LLM-generated investment memo embedded in the repo.

8. **Rust `cargo.toml` workspace does not include `crates/agit-node` in the default members** but `Cargo.toml` at root lists it in `members`. The `agit-node` crate has a `package.json` inside it (`crates/agit-node/package.json`) suggesting it is built with `napi-rs` and npm, not pure Cargo. This is a hybrid build setup that requires both Rust and Node toolchains.

---

## 10. Recommended Action for FIDES v2

1. **Reuse AGIT hash-chain semantics** for FIDES evidence ledger — the `compute_audit_hash` pattern chaining `prev_integrity_hash` is directly portable.
2. **Reuse canonical JSON + SHA-256 content addressing** patterns from `crates/agit-core/src/hash.rs` for canonical object signing in FIDES.
3. **Reuse Guard framework concept** (Allow/Warn/Block) as inspiration for FIDES policy engine guards, especially for high-risk action handling.
4. **Reuse ApprovalStore pattern** for FIDES ApprovalRequest/ApprovalDecision primitives.
5. **Do NOT import AGIT as a runtime dependency** for FIDES v2. Instead, port the concepts into TypeScript. A future Rust adapter can bridge to `agit-core` for performance-critical workloads.
6. **AGIT's Merkle diff is too specific to VCS** for direct reuse in FIDES, but the Merkle tree construction pattern (`MerkleNode`) is reusable for evidence verification.
