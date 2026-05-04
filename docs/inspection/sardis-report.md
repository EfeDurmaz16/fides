# Sardis Repository Inspection Report

## 1. Repo Purpose

**Sardis** is a Payment OS for the Agent Economy. It provides non-custodial MPC wallets with natural language spending policies for AI agents. The stack prevents financial hallucinations via a real-time policy firewall, executes stablecoin payments (primarily USDC) on **Base** and **Tempo**, supports multi-chain funding via CCTP v2, virtual cards via Stripe Issuing, and protocol gateways for AP2, TAP, x402, A2A, and UCP.

**Build systems used:**
- **Python**: `uv` + `hatchling` (root `pyproject.toml` and per-package `pyproject.toml` files)
- **JS/TS**: `pnpm` monorepo (`pnpm-workspace.yaml`, root `package.json`)
- **Contracts**: Foundry (`contracts/foundry.toml`)

---

## 2. Main Packages / Modules

### Core Infrastructure (Python)

| Package | Path | Purpose |
|---------|------|---------|
| `sardis-core` | `packages/sardis-core` | Domain models, policy engine, orchestrator, state machine, exceptions |
| `sardis-api` | `packages/sardis-api` | FastAPI REST API (v2), routers, middleware, repositories |
| `sardis-chain` | `packages/sardis-chain` | Blockchain execution, chain routing, Tempo integration, CCTP |
| `sardis-protocol` | `packages/sardis-protocol` | AP2/TAP/x402 mandate verification, reason codes |
| `sardis-ledger` | `packages/sardis-ledger` | Append-only audit ledger, Merkle anchoring, reconciliation |
| `sardis-compliance` | `packages/sardis-compliance` | KYC/AML/SAR (Didit, Elliptic, Chainalysis, OFAC, etc.) |
| `sardis-wallet` | `packages/sardis-wallet` | Wallet management, MPC via Turnkey, spending limits |
| `sardis-cards` | `packages/sardis-cards` | Virtual cards (Stripe Issuing) |
| `sardis-checkout` | `packages/sardis-checkout` | Merchant checkout flows |
| `sardis-guardrails` | `packages/sardis-guardrails` | Kill switch, anomaly engine, fraud detection, transaction caps |
| `sardis-mpp` | `packages/sardis-mpp` | Multi-party payments (Stripe LASO virtual cards) |
| `sardis-a2a` | `packages/sardis-a2a` | Agent-to-agent protocol (agent cards, discovery, messages) |
| `sardis-ucp` | `packages/sardis-ucp` | Unified Commerce Protocol adapters |
| `sardis-ramp` | `packages/sardis-ramp` | On/off ramp |

### SDKs & Clients

| Package | Path | Purpose |
|---------|------|---------|
| `sardis-sdk-python` | `packages/sardis-sdk-python` | Production Python SDK (sync + async) |
| `sardis-sdk-js` | `packages/sardis-sdk-js` | TypeScript SDK (CJS + ESM + browser UMD) |
| `sardis` (top-level) | `sardis/` | Simplified public Python SDK (simulation mode + delegates to `sardis-sdk`) |
| `sardis-cli` | `packages/sardis-cli` | Python CLI (`sardis` command) |
| `sardis-mcp-server` | `packages/sardis-mcp-server` | MCP server for Claude/Cursor/ChatGPT |

### Framework Integrations (Python)

`sardis-langchain`, `sardis-crewai`, `sardis-openai-agents`, `sardis-adk`, `sardis-autogpt`, `sardis-browser-use`, `sardis-composio`, `sardis-guardrails`, `sardis-coinbase`, `sardis-striga`, `sardis-lightspark`, `sardis-activepieces`, `sardis-agentkit`, `sardis-e2b`, `sardis-gpt`, `sardis-openclaw`, `sardis-stagehand`, `sardis-telegram-bot`, `n8n-nodes-sardis`

### Frontend / Apps

| Package | Path |
|---------|------|
| `app-landing` | `apps/landing` |
| `app-dashboard` | `apps/dashboard` |
| `canvas-site` | `apps/canvas-site` |
| `docs-site` | `docs-site` |
| `sardis-checkout-ui` | `packages/sardis-checkout-ui` |

### Smart Contracts

Located at `contracts/` (Foundry). Key contracts:
- `SardisPolicyModule.sol`
- `SardisLedgerAnchor.sol`
- `RefundProtocol.sol`
- `SardisJobManager.sol`
- `SardisIdentityRegistry.sol`
- `SardisVerifyingPaymaster.sol`

---

## 3. Existing Primitives (with Exact File Paths)

### Policy & Guardrails

- **Spending Policy Engine**: `packages/sardis-core/src/sardis_v2_core/spending_policy.py`
- **Natural Language Policy Parser**: `packages/sardis-core/src/sardis_v2_core/nl_policy_parser.py`
- **Policy DSL**: `packages/sardis-core/src/sardis_v2_core/policy_dsl.py`
- **Policy Evidence / Audit Trail**: `packages/sardis-core/src/sardis_v2_core/policy_evidence.py`
- **Policy Attestation (Ed25519 envelopes)**: `packages/sardis-core/src/sardis_v2_core/policy_attestation.py`
- **PreExecutionPipeline**: `packages/sardis-core/src/sardis_v2_core/pre_execution_pipeline.py`
- **Drift Policy Integrator**: `packages/sardis-core/src/sardis_v2_core/drift_policy_integrator.py`
- **Kill Switch**: `packages/sardis-guardrails/src/sardis_guardrails/kill_switch.py`
- **Transaction Caps (auto-triggers kill switch)**: `packages/sardis-guardrails/src/sardis_guardrails/transaction_caps.py`
- **Anomaly Engine**: `packages/sardis-guardrails/src/sardis_guardrails/anomaly_engine.py`

### Payment & Orchestration

- **Payment Orchestrator (single chokepoint)**: `packages/sardis-core/src/sardis_v2_core/orchestrator.py`
- **Payment Object (one-time payment primitive)**: `packages/sardis-core/src/sardis_v2_core/payment_object.py`
- **Payment State Machine (22-state lifecycle)**: `packages/sardis-core/src/sardis_v2_core/state_machine.py`
- **Unified Payment**: `packages/sardis-core/src/sardis_v2_core/unified_payment.py`
- **Settlement Lock**: `packages/sardis-core/src/sardis_v2_core/settlement_lock.py`

### Mandate & Approval

- **Mandates (Intent/Cart/Payment)**: `packages/sardis-core/src/sardis_v2_core/mandates.py`
- **Spending Mandate**: `packages/sardis-core/src/sardis_v2_core/spending_mandate.py`
- **Mandate Tree / Delegation**: `packages/sardis-core/src/sardis_v2_core/mandate_tree.py`
- **Approval Service**: `packages/sardis-core/src/sardis_v2_core/approval_service.py`
- **Approval Context**: `packages/sardis-core/src/sardis_v2_core/approval_context.py`

### Ledger & Audit

- **Ledger Engine**: `packages/sardis-ledger/src/sardis_ledger/engine.py`
- **Merkle Tree**: `packages/sardis-ledger/src/sardis_ledger/merkle_tree.py`
- **On-chain Anchor**: `packages/sardis-ledger/src/sardis_ledger/anchor.py`
- **Immutable Records**: `packages/sardis-ledger/src/sardis_ledger/immutable.py`
- **Reconciliation**: `packages/sardis-ledger/src/sardis_ledger/reconciliation.py`

### Protocol Verifiers

- **AP2 Verifier / Schemas**: `packages/sardis-protocol/src/sardis_protocol/verifier.py`, `packages/sardis-protocol/src/sardis_protocol/schemas.py`
- **TAP Validation**: `packages/sardis-protocol/src/sardis_protocol/tap.py`
- **TAP Keys / JWKS**: `packages/sardis-protocol/src/sardis_protocol/tap_keys.py`
- **x402 Protocol**: `packages/sardis-protocol/src/sardis_protocol/x402.py`
- **x402 Settlement**: `packages/sardis-protocol/src/sardis_protocol/x402_settlement.py`
- **Reason Codes (AP2/TAP/x402/UCP)**: `packages/sardis-protocol/src/sardis_protocol/reason_codes.py`

### Chain Execution

- **Chain Executor (EVM + ERC-4337)**: `packages/sardis-chain/src/sardis_chain/executor.py`
- **Tempo Executor (type 0x76)**: `packages/sardis-chain/src/sardis_chain/tempo/executor.py`
- **Tempo Fee Payer**: `packages/sardis-chain/src/sardis_chain/tempo/fee_payer.py`
- **CCTP Forwarding**: `packages/sardis-chain/src/sardis_chain/cctp_forwarding.py`
- **Bridge (intent-based, Base<->Tempo)**: `packages/sardis-chain/src/sardis_chain/bridge.py`
- **Gas Optimizer**: `packages/sardis-chain/src/sardis_chain/gas_optimizer.py`

### Compliance

- **Compliance Engine**: `packages/sardis-compliance/src/sardis_compliance/checks.py`
- **KYC**: `packages/sardis-compliance/src/sardis_compliance/kyc.py`
- **KYA (Know Your Agent)**: `packages/sardis-compliance/src/sardis_compliance/kya.py`
- **Sanctions**: `packages/sardis-compliance/src/sardis_compliance/sanctions.py`
- **Travel Rule**: `packages/sardis-compliance/src/sardis_compliance/travel_rule.py`

### Wallet & MPC

- **Wallet Manager**: `packages/sardis-wallet/src/sardis_wallet/manager.py`
- **Turnkey Client**: `packages/sardis-wallet/src/sardis_wallet/turnkey_client.py`
- **Spending Limits**: `packages/sardis-wallet/src/sardis_wallet/spending_limits.py`

---

## 4. CLI Entrypoints, SDK Exports, Examples, Tests

### CLI Entrypoints

- **Primary CLI (Python)**: `packages/sardis-cli/src/sardis_cli/main.py`
  - Commands: `agents`, `wallets`, `payments`, `holds`, `chains`, `policies`, `cards`, `spending`, `mandates`, `approvals`, `ledger`, `fiat`, `groups`, `demo`
  - Entry script: `sardis` (installed via pyproject.toml scripts)
- **MCP Server CLI (Node)**: `packages/sardis-mcp-server/src/cli.ts`
  - Binary: `sardis-mcp-server` (npm)
- **Placeholder/Minimal CLIs**:
  - `sardis-cli-go/` — effectively empty (only `dist/` exists)
  - `sardis-cli-js/` — minimal (only `dist/` and `node_modules`)

### SDK Exports

- **Python SDK (`sardis-sdk`)**: `packages/sardis-sdk-python/src/sardis_sdk/__init__.py`
  - Exports: `SardisClient`, `AsyncSardisClient`, models, errors, pagination, bulk ops
- **TypeScript SDK (`@sardis/sdk`)**: `packages/sardis-sdk-js/src/index.ts`
  - Exports: `SardisClient`, errors, types, integrations (LangChain, OpenAI, Vercel AI)
- **Top-level `sardis` package**: `sardis/__init__.py`
  - Simulation-first wrapper; re-exports `AsyncSardisClient` when `sardis-sdk` is installed

### Examples

Located at `examples/`:
- `quickstart_5min.py`
- `simple_payment.py`
- `agent_to_agent.py`
- `budget_allocation_demo.py`
- `crewai_finance_team.py`
- `langchain_sardis_agent.py`
- `openai_agents_payment.py`
- `google_adk_agent.py`
- `vercel_ai_payment.ts`
- And several subdirectories (`crewai-procurement-team/`, `langchain-payment-agent/`, etc.)

### Tests

- **Root integration tests**: `tests/` — **208 test files**
  - Covers: audit, compliance, chain, protocol, ledger, wallet, guardrails, ZK, fraud, migrations, load, e2e
- **Package-level tests**:
  - `packages/sardis-protocol/tests/`
  - `packages/sardis-ledger/tests/`
  - `packages/sardis-wallet/tests/`
  - `packages/sardis-sdk-python/tests/`
  - `packages/sardis-mcp-server/src/__tests__/`
  - `packages/sardis-sdk-js/__tests__/`

---

## 5. Schemas / Spec Files & CI / Config

### Schemas / Specs

- **OpenAPI Schema Generator**: `packages/sardis-api/src/sardis_api/openapi_schema.py`
  - Generated dynamically by FastAPI; no committed static `openapi.json`
- **OpenAPI Actions (ChatGPT)**: `packages/sardis-api/openapi/chatgpt-actions.yaml`
- **Composio OpenAPI**: `packages/sardis-composio/openapi.yaml`
- **Protocol Schemas (Pydantic)**: `packages/sardis-protocol/src/sardis_protocol/schemas.py`
- **MCC Codes JSON**: `packages/sardis-core/src/sardis_v2_core/data/mcc_codes.json`

### CI / Config

- **Main CI**: `.github/workflows/ci.yml`
  - Python lint (ruff), root tests (pytest with 40% cov minimum), package tests, TS build/test, contract build, security scan
- **Release Workflows**:
  - `release-python-sdk.yml`
  - `release-python-integrations.yml`
  - `release-npm.yml`
  - `publish.yml`
- **Deploy Workflows**:
  - `deploy-api-cloudrun.yml`
  - `deploy-dashboard.yml`
  - `deploy-landing.yml`
- **Other**: `codeql.yml`, `secret-scan.yml`, `security-scan.yml`, `fuzz.yml`, `nightly-sandbox-e2e.yml`
- **Dependabot**: `.github/dependabot.yml`

---

## 6. What is Reusable

1. **Policy Engine** (`spending_policy.py`, `nl_policy_parser.py`, `policy_dsl.py`) — deterministic NL-to-policy parsing is domain-agnostic for spending controls.
2. **PreExecutionPipeline** — composable hook chain pattern with fail-closed defaults can be reused for any transactional approval flow.
3. **Protocol Verifiers** (`verifier.py`, `tap.py`, `x402.py`) — mandate chain verification and signature validation are standalone.
4. **Kill Switch** (`kill_switch.py`) — global/per-agent/per-rail/per-chain emergency stop primitive.
5. **Ledger Engine + Merkle Tree** — append-only audit with cryptographic anchoring.
6. **Exception Hierarchy** (`exceptions.py`) — well-structured error taxonomy with HTTP mapping.
7. **Circuit Breaker / Retry / Logging** — generic resilience primitives in `sardis-core`.
8. **SDK Client Patterns** — both Python and TS SDKs have clean resource-based architectures.
9. **MCP Tool Definitions** — 40+ tools in `sardis-mcp-server` that wrap the API.
10. **Smart Contract Patterns** — `SardisPolicyModule.sol` (Safe module) and `SardisLedgerAnchor.sol` (Merkle root anchor).

---

## 7. What is Missing

The following are explicitly **not found** or are **gaps**:

- **No static OpenAPI spec**: There is no committed `openapi.json`; it is generated at runtime by FastAPI.
- **No Rust/Cargo core**: Despite `sardis-cli-go` and `sardis-solana-program` directories, there is no significant Rust codebase; `sardis-cli-go` is effectively empty.
- **No dedicated `authority` primitive module**: Authority/delegation logic is embedded inside `mandates.py`, `approval_service.py`, and `spending_mandate.py` rather than being a standalone reusable package.
- **No standalone `evidence` export service**: Evidence exists as `policy_evidence.py` and within the ledger, but there is no top-level `evidence` package or router dedicated to evidence export.
- **No `spending` standalone package**: Spending tracking is split between `sardis-core` (`spending_tracker.py`) and `sardis-wallet` (`spending_limits.py`).
- **No comprehensive API documentation source files**: `docs/` contains business plans, deployment guides, and marketing content, but no structured technical API reference markdown.
- **No architecture decision records (ADRs)** in the docs directory.

---

## 8. Conflicts Noticed

1. **Dual API directories**:
   - Main API code is in `packages/sardis-api/`
   - A legacy/separate `api/` directory exists at `api/` containing subfolders like `api/`, `checkout/`, `dashboard/`, `landing/` — these appear to be older deployment artifacts or proxy configs. This is confusing.

2. **Internal package naming inconsistency**:
   - The installable PyPI package is `sardis-core`, but the Python import path is `sardis_v2_core` (`packages/sardis-core/src/sardis_v2_core/`).
   - Similarly, `packages/sardis-api/src/sardis_api/` is correct, but there is also a stray file at `packages/sardis-api/src/sardis_v2_api/routes/budgets.py` — an orphaned module.

3. **Multiple CLI packages**:
   - Real CLI: `packages/sardis-cli/` (Python, fully featured)
   - Placeholders: `packages/sardis-cli-go/` (empty) and `packages/sardis-cli-js/` (minimal dist only). These create ambiguity about the official CLI.

4. **Overlapping wallet/spending domains**:
   - `sardis-core` exports `Wallet`, `TokenLimit`, `SpendingPolicy`, and `SpendingTracker`.
   - `sardis-wallet` also contains `manager.py` and `spending_limits.py`.
   - The boundary between core domain models and wallet operational logic is blurry.

5. **Top-level `sardis/` vs `packages/sardis-sdk-python/`**:
   - The top-level `sardis/` package is a simulation wrapper that optionally imports `sardis_sdk`.
   - This means there are two Python "SDK" surfaces: `sardis` (simple) and `sardis_sdk` (production). This is intentional but can confuse consumers about which to use.

6. **MCP Server binary naming**:
   - `package.json` defines `sardis-mcp` and `sardis-mcp-server` binaries pointing to the same file.

7. **Version drift**:
   - Root `pyproject.toml` says version `1.1.0`.
   - `sardis-core/__init__.py` says `0.3.0`.
   - `sardis-sdk-python/__init__.py` says `1.0.0`.
   - `package.json` (monorepo root) says `0.2.0`.
   - `sardis-mcp-server` says `1.1.0`.
   - These versions are not aligned.

---

## 9. Recommended Action for FIDES v2

1. **Port generic patterns, NOT payment domain models:**
   - **Port**: PreExecutionPipeline pattern, policy engine concept, kill switch primitive, approval flow, evidence ledger pattern, mandate chain abstraction.
   - **Leave in Sardis**: stablecoin, MPC wallet, payment rails, merchants, compliance/KYA/AML, spending limits, AP2/TAP/x402 settlement logic.

2. **Reuse Sardis error taxonomy** as inspiration for FIDES typed errors, but keep FIDES error categories protocol-focused (auth, trust, policy, evidence, runtime).

3. **Reuse ledger anchoring pattern** (`SardisLedgerAnchor.sol`, `merkle_tree.py`) for FIDES evidence Merkle root anchoring, but implement it in TypeScript with adapter interfaces for on-chain anchoring.

4. **Do NOT create a FIDES-Sardis runtime dependency.** Instead, define adapter interfaces so Sardis can integrate FIDES trust/evidence layer, and FIDES can reference Sardis as a downstream consumer.

5. **Kill switch primitive** should be genericized in FIDES (per-agent, per-capability, per-principal emergency stop) and Sardis should specialize it for payment rails.
