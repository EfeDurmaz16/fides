# Sardis Repository Inspection Report

Source repo: `/Users/efebarandurmaz/sardis`

Note: this report is read-only evidence for FIDES v2. Sardis is a consumer/integration source for generic patterns only; payment-specific authority remains in Sardis.

## 1. Repo Purpose

Sardis is a financial authority layer for AI agents. It enforces mandates, deterministic policy, approvals, revocation, and audit evidence before wallets, cards, stablecoins, payment APIs, and x402 move money.

Local evidence:

- Public framing: `/Users/efebarandurmaz/sardis/README.md`.
- FastAPI composition root: `/Users/efebarandurmaz/sardis/apps/api/server/main.py`.
- Python package root: `/Users/efebarandurmaz/sardis/packages/sardis/pyproject.toml`.
- TypeScript SDK package: `/Users/efebarandurmaz/sardis/packages/sardis-js/package.json`.

## 2. Main Packages / Modules

| Area | Path | Purpose |
|---|---|---|
| Python SDK | `/Users/efebarandurmaz/sardis/packages/sardis/` | Core, ledger, chain, UCP, protocol, compliance, guardrails, wallet, integrations. |
| API server | `/Users/efebarandurmaz/sardis/apps/api/server/main.py` | FastAPI application composition. |
| TypeScript SDK | `/Users/efebarandurmaz/sardis/packages/sardis-js/` | TS client resources for core, ledger, chain, UCP, protocol, compliance, guardrails, checkout, wallet, ramp, integrations, webhooks. |
| MCP server | `/Users/efebarandurmaz/sardis/packages/sardis-mcp-server/` | Payment, policy, agent, trust, project tools. |
| Contracts | `/Users/efebarandurmaz/sardis/contracts/src/` | Identity, reputation, ledger anchor, job/validation registries, refund protocol. |

## 3. Existing Generic Primitives

- FIDES DID format and helpers: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/fides_did.py`.
- Sardis agent identity records with Ed25519/ECDSA verification, versioning, rotation, and revocation: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/identity.py`.
- DID bridge linking Sardis agents to FIDES DIDs with Ed25519 ownership proof, but with in-memory default storage: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/did_bridge.py`.
- FIDES API surface for registration, identity lookup, trust score, trust path, trust attestation, and policy-history verification: `/Users/efebarandurmaz/sardis/apps/api/server/routes/identity/fides_identity.py`.
- FIDES trust adapter wrapper over FIDES `/v1/trust/*`: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/fides_trust_adapter.py`.
- Trust/reputation/attestation model with KYA, transaction history, compliance, reputation, behavioral consistency, and transitive trust: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/trust_infrastructure.py`, `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/kya_trust_scoring.py`.
- Agent Auth discovery/capability/grant/session-like API with `.well-known/agent-configuration`, capability execution, registration, status, request-capability, and revoke: `/Users/efebarandurmaz/sardis/apps/api/server/routes/identity/agent_auth.py`.
- Signed attestation envelopes with canonical JSON, SHA-256 binding, optional Ed25519 signature, and verification: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/attestation_envelope.py`.
- Policy history uses AGIT or an in-memory SHA-256 hash-chain fallback: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/agit_policy_engine.py`.
- On-chain Merkle root anchor contract: `/Users/efebarandurmaz/sardis/contracts/src/SardisLedgerAnchor.sol`.
- Evidence export endpoints for ledger entries, side effects, idempotency records, policy decisions, and webhook evidence: `/Users/efebarandurmaz/sardis/apps/api/server/routes/evidence/records.py`.
- A2A agent-card discovery and trust table: `/Users/efebarandurmaz/sardis/packages/sardis-js/src/resources/a2a.ts`, `/Users/efebarandurmaz/sardis/apps/api/server/routes/protocol/a2a.py`.
- AP2 mandate models and verifier with proof payloads, nonce/replay, domain checks, canonicalization, and version fields: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/core/mandates.py`, `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/protocol/verifier.py`, `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/protocol/schemas.py`.
- Privacy primitives for payment/privacy protocols: `/Users/efebarandurmaz/sardis/packages/sardis/src/sardis/protocol/paladin_privacy.py`.

## 4. Payment-Specific Items To Keep Separate

These are Sardis-domain primitives and should not move into generic FIDES core:

- Payment mandates, AP2, TAP, x402, MPP.
- Spending policies, wallet/card/ramp/funding/escrow resources.
- Merchant/service payment directory.
- Stablecoin and payment rails.
- Compliance/KYA/AML.
- Payment kill switch scoped to global/org/agent/rail/chain: `/Users/efebarandurmaz/sardis/apps/api/server/kill_switch_dep.py`.
- x402 facilitator routes: `/Users/efebarandurmaz/sardis/apps/api/server/routes/protocol/x402.py`.
- MCP paid API proxy/project provisioning: `/Users/efebarandurmaz/sardis/packages/sardis-mcp-server/src/tools/proxy.ts`, `/Users/efebarandurmaz/sardis/packages/sardis-mcp-server/src/tools/projects.ts`.

## 5. Reusable Components

Reuse conceptually, not by runtime dependency:

- FIDES DID encoding/parsing.
- DID bridge ownership proof shape.
- Ed25519 verification.
- Attestation envelope canonicalization.
- Policy-before-execution pipeline.
- Evidence/hash-chain and export shape.
- Trust path adapter shape.
- Reason-code taxonomy.
- A2A AgentCard and trust table patterns.
- Approval and high-risk action patterns.
- Kill switch semantics, generalized beyond payments.

## 6. Missing Components

I could not find generic FIDES-ready source primitives for:

- DHT discovery.
- Relay discovery.
- Federation runtime.
- TEE/runtime attestation.
- Generic privacy-preserving identity/evidence protocol beyond payment/privacy transaction primitives.

## 7. Conflicts With FIDES v2 Architecture

- FIDES functionality currently lives inside Sardis API routes and payment/KYA context; extraction requires removing payment-control-plane assumptions.
- The FIDES trust adapter degrades to `0.0` / empty path and documents that it should never block payments. That is unacceptable as a generic FIDES authority core unless fail-open/fail-closed behavior is explicit and policy-governed.
- DID bridge and TrustFramework are in-memory by default, so they are not durable FIDES primitives as-is.
- Attestation envelopes can be unsigned when no signing key is provided. FIDES v2 should make unsigned envelopes debug-only or draft-only.
- MCP paid API proxy has fail-open policy-check behavior, which conflicts with authority-layer semantics.
- Some contracts exist for identity/reputation, but `contracts/AUDIT_SURFACE.md` says only `SardisLedgerAnchor` and `RefundProtocol` are intended production custom deployments; do not treat ERC-8004-style contracts as FIDES-ready without a separate decision.

## 8. Recommended Action

Use Sardis as the primary source of generic authority patterns:

- policy-before-execution,
- guardrails,
- evidence ledger/export,
- approval flow,
- kill switch,
- high-risk action handling,
- mandate-chain abstraction.

Keep payment-specific execution in Sardis. FIDES should expose generic primitives and a Sardis adapter; Sardis should consume FIDES for agent identity, trust, delegation, evidence, and policy context around payment-specific mandates.
