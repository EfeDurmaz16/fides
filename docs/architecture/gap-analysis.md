# FIDES v2 Gap Analysis

This gap analysis compares the current local FIDES implementation with the requested FIDES v2 Agent Trust Fabric.

## Summary

FIDES is not a blank slate. It already has a strong TypeScript monorepo, packages, services, CLI, SDK, docs, tests, and several v2-shaped primitives.

The main gaps are not lack of code. They are:

- protocol-object coherence,
- signing envelope consistency,
- capability-query discovery,
- DHT pointer semantics,
- first-class approval/invocation/version/error objects,
- local daemon storage target,
- interop adapter package,
- complete CLI/API/SDK/demo alignment.

## Baseline Strengths

| Area | Current evidence | Assessment |
|---|---|---|
| TS-first monorepo | `package.json`, `pnpm-workspace.yaml`, `turbo.json` | Strong. Keep. |
| Core package | `packages/core/src/` | Good start, needs consolidation/hardening. |
| Canonical signing | `packages/core/src/canonical-signer.ts` | Present, must become the one signing model. |
| Policy/guard | `packages/policy/src/index.ts`, `packages/guard/src/index.ts` | Present, needs richer v2 decisions. |
| Evidence | `packages/evidence/src/index.ts` | Present, needs signed v2 event model. |
| Runtime attestation | `packages/runtime/src/index.ts` | Present, needs schema alignment and integration. |
| Discovery providers | `packages/discovery/src/` | Present, needs capability-query and verification pipeline. |
| Trust graph | `services/trust-graph/src/` | Present, needs v2 component scoring. |
| Agent daemon | `services/agentd/src/` | Present, needs requested API/CLI/storage alignment. |
| Registry/relay services | `services/registry/src/`, `services/relay/src/` | Present, prototype-to-v2 hardening needed. |
| SDK | `packages/sdk/src/` | Present, Promise-based. |
| CLI | `packages/cli/src/` | Present as `fides`; requested surface is `agentd`. |
| Tests | `packages/*/test`, `services/*/test`, `tests/e2e`, `tests/adversarial` | Strong baseline. |

## Blocking Architecture Gaps

### 1. Protocol Object Model

Current state:

- Core objects exist across `packages/core`, `packages/shared`, package-specific types, and service-local payloads.
- There are multiple AgentCard and identity shapes.
- Signed objects use `SignedObject<T>` in some places, raw `signature` fields in others.

Required:

- One framework-agnostic protocol object model with shared signed fields:
  - `schema_version`
  - `id`
  - `issuer`
  - `subject` where applicable
  - `created_at` or `issued_at`
  - `expires_at` where applicable
  - `payload_hash`
  - `signature`

Action:

- Create/extend protocol modules under `packages/core`.
- Keep compatibility exports until services/SDK/CLI migrate.

### 2. Identity v2 Hardening

Current state:

- `packages/core/src/identity.ts` defines Agent/Publisher/Principal types.
- `createIdentity` accepts an external DID and fills `publicKey` with random bytes, not a real keypair.

Required:

- Real Ed25519 keypair issuance.
- Publisher type taxonomy.
- Domainless, hosted, domain-verified, org-verified identities.
- Trust anchors beyond domain.

Action:

- Add `packages/core/src/identity-v2.ts` or harden `identity.ts`.
- Preserve existing exports but make new creation path cryptographically correct.

### 3. Signing Consistency

Current state:

- `SignedObject<T>` proof model exists.
- Delegation/revocation/incident use raw hex `signature` fields.
- HTTP request signing exists separately.

Required:

- One canonical signing model for all signed protocol objects.
- HTTP signatures remain transport-level, not object-level protocol signing.

Action:

- Add a signed envelope and helper functions.
- Migrate object-specific signing to shared helpers.

### 4. Discovery Semantics

Current state:

- Discovery provider interface resolves by DID.
- DHT provider stores direct AgentCards.

Required:

- Discover by `DiscoveryQuery` containing capability, constraints, principal, policy context, and versions.
- Providers return `DiscoveryCandidate[]`.
- Verification pipeline:
  1. verify signed records,
  2. verify AgentCards,
  3. check version compatibility,
  4. check capability compatibility,
  5. compute trust,
  6. evaluate policy,
  7. emit evidence.
- DHT provides signed pointers only.

Action:

- Extend provider API while preserving existing `resolve` compatibility.
- Add signed `DHTPointerRecord`.

### 5. Trust/Reputation v2

Current state:

- Trust graph and capability scoring exist.
- Guard explainability exists.

Required:

- `TrustResult` with component scores, band, reasons, risk flags, evidence refs, required controls.
- Capability-specific, principal-specific, publisher-weighted reputation.
- Incident, novelty, and context-boundary penalties.

Action:

- Add new types to core/shared.
- Extend trust graph service scoring incrementally.

### 6. Policy/Approval/Kill Switch

Current state:

- Policy evaluator returns `allow`, `deny`, `approve-required`, `dry-run`.
- Guard handles approval and kill switch context.
- Kill switch package exists.

Required:

- Decision vocabulary includes `require_approval`, `dry_run_only`, `scope_limit`, `risk_limit`.
- First-class `ApprovalRequest`, `ApprovalDecision`, `ApprovalPolicy`.
- Kill switch rules for agent, publisher, capability, session, principal, high-risk class.

Action:

- Add protocol objects and compatibility mapping.
- Move approval from context flag to durable signed object lifecycle.

### 7. Delegation/Session/Invocation

Current state:

- DelegationToken and SessionGrant exist.
- Agentd authorizes sessions and invocation-style checks.

Required:

- SessionGrant fields: session_id, requester_agent_id, target_agent_id, principal_id, capability, scopes, constraints, policy_hash, trust_result_hash, issued_at, expires_at, nonce, signature.
- Signed InvocationRequest and InvocationResult.
- Input/output validation.
- Evidence events for invocation lifecycle.

Action:

- Add v2 objects first.
- Then adapt agentd route logic.

### 8. Evidence v2

Current state:

- Evidence events have id/type/timestamp/actor/action/target/payload/privacy/prevHash/hash/signature.
- Merkle root is computed.

Required:

- Event taxonomy and fields:
  - event_id,
  - actor,
  - subject,
  - principal,
  - capability,
  - input_hash,
  - output_hash,
  - policy_hash,
  - decision,
  - risk_level,
  - privacy_mode,
  - prev_event_hash,
  - signature.
- Default redacted/hash-only behavior.
- Export and tamper detection.

Action:

- Add EvidenceEvent v2 and compatibility adapter.
- Keep current chain verifier until migration is complete.

### 9. Version/Error Vocabularies

Current state:

- Error classes exist but are broad.
- Versioning error exists, not a negotiation protocol.

Required:

- `ErrorEnvelope` with code/category/severity/retryable/message/details.
- Stable codes such as `IDENTITY_INVALID_SIGNATURE`, `POLICY_DENIED`, `DHT_POINTER_TAMPERED`.
- `VersionNegotiationRecord` with supported/required/negotiated versions and compatibility errors.

Action:

- Add to `packages/core` and export via SDK/CLI/API.

### 10. Interop Adapters

Current state:

- Some A2A-like types exist.
- No unified `packages/adapters` package.

Required:

- MCP, A2A, OAPS, OSP, AP2, x402, Sardis adapter interfaces.

Action:

- Add interface-only package first.
- Provide mapping docs.

### 11. Local Daemon Storage

Current state:

- Agentd supports file-backed and Postgres authority stores.

Required:

- Local-first SQLite with versioned migrations and `~/.fides/` config layout.

Action:

- Add SQLite adapter without removing existing Postgres support.

### 12. CLI/API/Demo

Current state:

- CLI binary is `fides`.
- Agentd API is `/v1/*`.
- Examples exist.

Required:

- `agentd` command surface.
- Requested endpoint set.
- Full demo and adversarial simulation command.

Action:

- Add `agentd` binary/alias or `fides agentd`.
- Add compatibility routes where practical.
- Add `demo run` and `simulate adversarial`.

## Cross-Repo Import Boundaries

| Repo | Bring into FIDES | Do not bring |
|---|---|---|
| AGIT | Hashing, lineage, Merkle/state diff concepts, audit/event ideas, causal graph, Rust adapter option | VCS semantics as core protocol, current FIDES adapter as canon |
| OAPS | Actor/delegation/mandate/approval/evidence/version/error semantics | Runtime dependency on `@oaps/core`, payment profile execution |
| OSP | Registry/provision/rotate/deprovision adapter semantics | Service lifecycle as FIDES core authority |
| Sardis | Policy-before-execution, approvals, kill switch, evidence, mandate-chain abstraction | Stablecoins, wallets, merchants, compliance, spending limits, payment rails |

## Definition of Publishable v2 Prototype

Publishable prototype means:

- Core packages build.
- Signed protocol objects are coherent.
- Discovery returns verified candidates, not authority.
- Policy-before-execution gates invocation.
- Evidence is hash-chained and privacy-aware.
- DHT uses signed pointers only.
- CLI/SDK/demo can run a full local scenario.
- Adversarial simulation demonstrates tampering, revocation, expired attestation, and evidence-chain failure.
- Docs and tests report current limitations honestly.
