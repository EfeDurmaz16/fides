# FIDES Repository Inspection Report

Status: current local inspection on branch `fides-v2-agent-trust-fabric`, fast-forwarded to local `main` at `7e52774`.

## 1. Repo Purpose

FIDES is a TypeScript/Node monorepo for verifiable identity, authority, pre-execution trust controls, evidence, discovery, runtime attestation, and daemon/service APIs for AI agents.

Local evidence:

- Root package metadata describes FIDES as a decentralized trust and authentication protocol for AI agents: `package.json`.
- README frames FIDES as an agent trust fabric with signed identity, delegation, policy guards, tamper-evident evidence, runtime attestation, and kill switches: `README.md`.
- Workspace layout uses pnpm and Turbo: `pnpm-workspace.yaml`, `turbo.json`.

## 2. Main Packages / Modules

| Area | Path | Current role |
|---|---|---|
| Core protocol primitives | `packages/core/src/` | Identity v2 shapes, trust anchors, domain/passkey verification, canonical object signing, AgentCard, capabilities, delegation, sessions, revocation, incidents. |
| Policy | `packages/policy/src/index.ts` | Deterministic rules and Sardis-style pre-execution guard pipeline. |
| Guard | `packages/guard/src/index.ts` | Unified authorization decision engine over policy, trust, evidence, attestation, revocation, approval, and kill switch state. |
| Evidence | `packages/evidence/src/index.ts` | Hash-chained evidence events, Merkle root computation, privacy export modes. |
| Runtime | `packages/runtime/src/index.ts` | Runtime attestation interfaces, MockTEE, HTTP TEE adapters, build/container/package/GitHub attestation adapters, kill switch. |
| Discovery | `packages/discovery/src/` | Local, well-known, registry, relay, and in-memory DHT discovery provider architecture. |
| SDK | `packages/sdk/src/` | Promise-based clients for signing, discovery, registry, relay, trust, platform, agentd, and FIDES facade. |
| CLI | `packages/cli/src/` | `fides` CLI with commands for init, sign, verify, trust, discover, card, policy, runtime, killswitch, daemon, delegate, session, revoke, incident, propagation, authorize, relay, identity. |
| Shared | `packages/shared/src/` | Shared types, constants, errors, service auth, metrics, security helpers. |
| Local daemon | `services/agentd/src/` | Local HTTP API and authority store for sessions, policy, evidence, revocations, incidents, propagation, and authorization checks. |
| Trust graph service | `services/trust-graph/src/` | Identity/trust-edge storage, trust paths, capability-scoped scores, revocations, incidents. |
| Discovery service | `services/discovery/src/` | Identity and AgentCard discovery, well-known routes, domain/org verification migrations. |
| Registry service | `services/registry/src/` | Hosted registry with public/private modes and durable storage. |
| Relay service | `services/relay/src/` | Relay registration/discovery service with storage. |
| Policy service | `services/policy-engine/src/` | HTTP policy evaluation service. |
| Platform API | `services/platform-api/src/` | Platform metadata/topology API. |
| Examples | `examples/` | Calendar, invoice, payment, requester, and demo scripts. |
| Tests | `packages/*/test`, `services/*/test`, `tests/e2e`, `tests/adversarial` | Package, service, e2e, and adversarial coverage. |

## 3. Existing Primitives

| Primitive | Status | Local evidence |
|---|---|---|
| Agent identity | Present, shallow v2 shape | `packages/core/src/identity.ts`, `packages/shared/src/types.ts`. |
| Publisher identity | Present, limited verification methods | `packages/core/src/identity.ts`, `packages/core/src/domain-verifier.ts`. |
| Principal identity | Present, limited | `packages/core/src/identity.ts`. |
| Domainless identity | Present | `packages/core/src/identity.ts` issues domainless `did:fides` identities from Ed25519 keypairs and deprecated DID-based construction now fails closed when the DID cannot decode to a bound public key. |
| Platform-hosted identity | Partial | Shared and docs mention platform identity, but no first-class hosted identity lifecycle was found. |
| Domain/org verified identity | Present for DNS TXT verification | `packages/core/src/domain-verifier.ts`, `services/discovery/src/db/migrations/003_identity_domain_verification.sql`, `services/discovery/src/db/migrations/004_organization_domain_verification.sql`. |
| Trust anchors | Present | `packages/core/src/trust-anchor.ts`. |
| Canonical object signing | Present | `packages/core/src/canonical-signer.ts`. |
| HTTP message signatures | Present in SDK | `packages/sdk/src/signing/`. |
| Signed AgentCards | Present, evolving | `packages/core/src/agent-card.ts` defines `SignedAgentCard`, canonical signing, schema/agent id normalization, public key defaults, endpoint-derived transports, protocol versions, trust anchors, runtime attestations, revocation references, and validation. |
| Capability descriptors | Present, evolving | `packages/core/src/capability.ts` has id, namespace, action, resource, schemas, risk, scopes, supported controls, dry-run, approval, runtime attestation, and policy-proof metadata. |
| Capability ontology | Present, seed taxonomy | `packages/core/src/capability.ts` defines `DEFAULT_CAPABILITY_ONTOLOGY`, lookup helpers, and ontology-backed descriptor defaults before heuristic risk classification. |
| Local discovery | Present | `packages/discovery/src/local-provider.ts`. |
| Well-known discovery | Present | `packages/discovery/src/well-known-provider.ts`, `services/discovery/src/routes/well-known.ts`. |
| Registry discovery | Present | `packages/discovery/src/registry-provider.ts`, `services/registry/src/`. |
| Relay discovery | Present, prototype | `packages/discovery/src/relay-provider.ts`, `services/relay/src/`. |
| DHT discovery | Present, local simulator | `packages/core/src/dht.ts` defines signed `DHTPointerRecord`; `packages/discovery/src/dht-provider.ts` rejects tampered, expired, hash-mismatched, or revoked pointer candidates. |
| Federation | Present, local mock | `packages/core/src/registry.ts` defines `RegistryPeerRecord`; `packages/discovery/src/federation-provider.ts` verifies signed peer records for candidate-only federation discovery. |
| Trust graph | Present | `services/trust-graph/src/services/graph.ts`, `services/trust-graph/src/services/trust-service.ts`. |
| Capability-specific reputation | Partial | `services/trust-graph/src/db/migrations/003_capability_scoring.sql`, `services/trust-graph/src/services/capability-scoring.ts`. |
| Context-specific trust scoring | Partial | Trust edges include optional capability/context, but no full v2 scoring component model. |
| Policy engine | Present, simple | `packages/policy/src/index.ts`, `services/policy-engine/src/index.ts`. |
| Delegation tokens | Present | `packages/core/src/delegation.ts`. |
| Session grants | Present, not v2-complete | `packages/core/src/delegation.ts`, `packages/core/src/session-store.ts`, `services/agentd/src/index.ts`. |
| Capability invocation | Partial | Guard/agentd authorization exists; no generic signed InvocationRequest/InvocationResult protocol object found. |
| Runtime attestation | Present | `packages/core/src/runtime-attestation.ts` defines canonical-hashable v2 `RuntimeAttestation` objects; `packages/runtime/src/index.ts` provides MockTEE, HTTP TEE, build, container, package, and GitHub adapter-ready providers. |
| TEE-ready attestation | Present as adapter boundary | `packages/runtime/src/index.ts`. |
| MockTEE | Present | `packages/runtime/src/index.ts`. |
| Evidence ledger | Present, package-level | `packages/evidence/src/index.ts`; persisted locally by agentd authority store. |
| Revocation records | Present | `packages/core/src/revocation.ts`, `services/agentd/src/index.ts`, `services/trust-graph/src/db/migrations/002_revocations.sql`. |
| Incident records | Present | `packages/core/src/revocation.ts`, `services/agentd/src/index.ts`, `services/trust-graph/src/db/migrations/002_revocations.sql`. |
| Approval primitives | Partial | Guard and policy can require approval; I could not find first-class ApprovalRequest/ApprovalDecision protocol objects in core. |
| Kill switch | Present | `packages/runtime/src/index.ts`, `packages/cli/src/commands/killswitch.ts`, `services/agentd/src/index.ts`. |
| Evidence privacy | Present, basic | `packages/evidence/src/index.ts` supports public/private/redacted/hash-only export modes. |
| Version negotiation | Present | `packages/core/src/versioning.ts`, `packages/core/src/discovery.ts`, and `packages/discovery/src/orchestrator.ts` negotiate and filter discovery candidates by protocol compatibility. |
| Typed errors | Partial | `packages/shared/src/errors.ts` has broad classes, but not stable code/category/severity/retryable envelopes. |
| Explainability | Partial | Guard and policy return factors/explanations in `packages/guard/src/index.ts` and `packages/policy/src/index.ts`. |
| Adversarial simulation | Present as test, incomplete harness | `tests/adversarial/adversarial.test.ts`; no `agentd simulate adversarial` command found. |
| Interop adapters | Partial | SDK and CLI have A2A/FIDES-era surfaces; explicit MCP/A2A/OAPS/OSP/AP2/x402/Sardis adapter package not found. |
| CLI | Present, command name is `fides` | `packages/cli/src/index.ts`. Requested `agentd` CLI naming is not present. |
| Local HTTP API | Present at `/v1/*`, not requested exact endpoint set | `services/agentd/src/index.ts`, `docs/api/agentd.yaml`. |
| SDK | Present | `packages/sdk/src/index.ts`, `packages/sdk/src/fides.ts`. |
| Examples/demo | Present, not full requested v2 demo | `examples/`. |
| Tests | Present | Package/service/e2e tests exist. |

## 4. Relevant Files

- Monorepo/workspace: `package.json`, `pnpm-workspace.yaml`, `turbo.json`, `tsconfig.base.json`.
- Public repo docs: `README.md`, `docs/getting-started.md`, `docs/deployment.md`, `docs/threat-model.md`.
- Current inspection/architecture docs: `docs/inspection/*.md`, `docs/architecture/*.md`.
- Protocol docs: `docs/protocol-spec.md`, `docs/protocol/fides-v2-spec.md`.
- OpenAPI specs: `docs/api/agentd.yaml`, `docs/api/discovery.yaml`, `docs/api/registry.yaml`, `docs/api/relay.yaml`, `docs/api/trust-graph.yaml`, `docs/api/platform-api.yaml`.
- Core primitives: `packages/core/src/index.ts`, `packages/core/src/canonical-signer.ts`, `packages/core/src/identity.ts`, `packages/core/src/agent-card.ts`, `packages/core/src/capability.ts`, `packages/core/src/delegation.ts`, `packages/core/src/revocation.ts`, `packages/core/src/trust-anchor.ts`, `packages/core/src/domain-verifier.ts`, `packages/core/src/passkey.ts`.
- Runtime/evidence/policy/guard: `packages/runtime/src/index.ts`, `packages/evidence/src/index.ts`, `packages/policy/src/index.ts`, `packages/guard/src/index.ts`.
- Discovery providers: `packages/discovery/src/provider.ts`, `packages/discovery/src/orchestrator.ts`, `packages/discovery/src/local-provider.ts`, `packages/discovery/src/well-known-provider.ts`, `packages/discovery/src/registry-provider.ts`, `packages/discovery/src/relay-provider.ts`, `packages/discovery/src/dht-provider.ts`.
- Local authority daemon: `services/agentd/src/index.ts`, `services/agentd/src/storage.ts`, `services/agentd/src/db/migrations/001_authority_store.sql`.
- Trust graph: `services/trust-graph/src/services/trust-service.ts`, `services/trust-graph/src/services/graph.ts`, `services/trust-graph/src/services/capability-scoring.ts`, `services/trust-graph/src/db/migrations/001_initial.sql`, `services/trust-graph/src/db/migrations/002_revocations.sql`, `services/trust-graph/src/db/migrations/003_capability_scoring.sql`.
- CLI: `packages/cli/src/index.ts`, `packages/cli/src/commands/*.ts`.
- SDK: `packages/sdk/src/agentd/client.ts`, `packages/sdk/src/discovery/client.ts`, `packages/sdk/src/registry/client.ts`, `packages/sdk/src/relay/client.ts`, `packages/sdk/src/trust/client.ts`, `packages/sdk/src/platform/client.ts`.
- Tests: `packages/core/test/`, `packages/evidence/test/`, `packages/runtime/test/`, `packages/discovery/test/`, `packages/guard/test/`, `packages/policy/test/`, `packages/sdk/test/`, `services/*/test/`, `tests/e2e/`, `tests/adversarial/`.

## 5. Reusable Components

- Keep the TypeScript monorepo as the v2 home. It already matches the TS-first constraint.
- Reuse `packages/core/src/canonical-signer.ts`, but harden it into the single envelope for all signed protocol objects with required shared fields.
- Reuse `packages/evidence/src/index.ts`, but evolve EvidenceEvent into the requested privacy-aware signed protocol object with input/output/policy hashes and event taxonomy.
- Reuse `packages/runtime/src/index.ts` for MockTEE and attestation adapter boundaries.
- Reuse `services/agentd/src/storage.ts` and `services/agentd/src/db/migrations/001_authority_store.sql` as the starting local authority store, but move toward SQLite/local-first storage for the daemon target if required.
- Reuse `services/trust-graph` algorithms and storage for v2 trust/reputation, but replace the score model with the requested explainable component model.
- Reuse `packages/discovery` provider architecture, but replace DID-only resolution with capability-query discovery candidates.
- Reuse CLI/service/SDK scaffolding, but align naming and endpoints to the requested `agentd` v2 surface.

## 6. Missing Components

I could not find these in the repo as complete v2 implementations:

- `PublisherIdentity` types for anonymous/self-signed/verified_individual/platform_hosted/domain_verified/organization_verified.
- Full trust anchor set for GitHub/email/npm/PyPI/wallet/passkey/org invitation/runtime/build/peer attestation.
- Unified protocol object family with `schema_version`, `id`, `issuer`, `subject`, `payload_hash`, and `signature`.
- Capability ontology entries with namespace/action/resource/control semantics.
- Signed DHT pointer records and tests for tampering, expiry, card hash mismatch, and revocation.
- Federation peering records/runtime.
- First-class ApprovalRequest, ApprovalDecision, ApprovalPolicy protocol objects.
- InvocationRequest and InvocationResult protocol objects and generic invocation executor.
- Full version negotiation.
- Stable ErrorEnvelope vocabulary with code/category/severity/retryable/details.
- MCP/A2A/OAPS/OSP/AP2/x402/Sardis adapter package.
- `agentd demo run` and `agentd simulate adversarial` CLI commands.
- Requested local SQLite daemon storage layout.

## 7. Conflicts With FIDES v2 Architecture

- `createIdentity` in `packages/core/src/identity.ts` accepts a DID and fills `publicKey` with random bytes, but does not create or bind an Ed25519 keypair. That is unsafe for v2 identity issuance.
- There are two AgentCard shapes: `packages/core/src/agent-card.ts` and `packages/shared/src/types.ts`. They need consolidation.
- DHT provider currently stores AgentCards directly; v2 requires DHT to provide signed pointers only and never act as a trust source.
- Policy actions use `approve-required` and `dry-run`; the user-facing spec uses `require_approval`, `dry_run_only`, `scope_limit`, and `risk_limit`. This needs vocabulary normalization or compatibility mapping.
- CLI binary is `fides`, while requested commands are under `agentd`. Decide whether `agentd` becomes an alias/binary or a subcommand.
- Service APIs use `/v1/*` and differ from the requested local HTTP API paths. Add compatibility routes or document versioned API mapping.
- FIDES currently contains payment examples such as `payments.execute`; generic FIDES must keep execution payment-specific behavior in Sardis and support only generic dry-run/payment-prep patterns.

## 8. Recommended Action

Treat the current repo as an advanced prototype, not a blank MVP. The v2 work should be a hardening and consolidation pass:

1. Freeze the current implemented surface as baseline.
2. Consolidate core protocol objects under `packages/core`.
3. Add missing v2 protocol objects and stable error/version vocabularies.
4. Convert discovery from DID resolution to capability + constraints resolution.
5. Replace DHT direct-card storage with signed pointer records.
6. Promote approvals, invocation, revocation, incidents, and evidence into first-class signed objects.
7. Align CLI/API/SDK/demo surfaces to `agentd` v2.
8. Keep AGIT/OAPS/OSP/Sardis as semantic or adapter inputs only; no runtime dependency on OAPS.
