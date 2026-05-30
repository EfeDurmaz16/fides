# FIDES v2 Implementation Plan

This plan is designed for a long-running coding goal on branch `fides-v2-agent-trust-fabric`.

Work style:

- Use atomic commits.
- Run `git status` before edits.
- Preserve untracked local instruction/config files unless explicitly asked otherwise.
- Do not touch dirty sibling repos except read-only inspection.
- Docs first, then code.
- Verify after each meaningful milestone.
- Do not claim completion without test/typecheck/demo status.

## Phase 0: Inspection and Architecture Docs

Status: started.

Deliverables:

- `docs/inspection/fides-report.md`
- `docs/inspection/agit-report.md`
- `docs/inspection/osp-report.md`
- `docs/inspection/oaps-report.md`
- `docs/inspection/sardis-report.md`
- `docs/inspection/cross-repo-primitive-map.md`
- `docs/architecture/fides-v2-agent-trust-fabric.md`
- `docs/architecture/gap-analysis.md`
- `docs/architecture/implementation-plan.md`
- `docs/architecture/implementation-agent-prompt.md`

Commits:

- `docs: add fides v2 inspection reports`
- `docs: add fides v2 architecture plan`

Verification:

- `pnpm typecheck` after docs if package scripts tolerate doc-only changes.
- `git diff --check`.

## Milestone 1: Stabilize Protocol Foundation

Goal: establish a coherent v2 protocol surface without breaking existing services.

Tasks:

1. Add v2 protocol constants and version list.
2. Add `ErrorEnvelope` and stable error vocabulary.
3. Add `VersionNegotiationRecord` and helper functions.
4. Add `ProtocolObject` and `SignedProtocolObject` base types.
5. Add compatibility helpers from current `SignedObject<T>`.
6. Add tests for canonical hash stability and error/version records.

Primary files:

- `packages/core/src/protocol.ts`
- `packages/core/src/errors.ts`
- `packages/core/src/versioning.ts`
- `packages/core/src/canonical-signer.ts`
- `packages/core/src/index.ts`
- `packages/core/test/*`
- `packages/shared/src/errors.ts`

Commit:

- `feat(core): add protocol versioning and error envelopes`

Verification:

- `pnpm --filter @fides/core test`
- `pnpm --filter @fides/core typecheck`

## Milestone 2: Identity v2

Goal: harden identity around real cryptographic issuance and trust anchors.

Tasks:

1. Replace loose identity creation with real Ed25519 keypair creation.
2. Add `AgentIdentity`, `PublisherIdentity`, `PrincipalIdentity` v2 fields.
3. Add publisher types: anonymous, self_signed, verified_individual, platform_hosted, domain_verified, organization_verified.
4. Add trust anchor types: domain, GitHub, email, npm, PyPI, wallet, passkey, organization invitation, runtime attestation, build attestation, peer attestation.
5. Keep domain and org DNS verification.
6. Add tests for domainless identity and trust anchor validation.

Primary files:

- `packages/core/src/identity.ts`
- `packages/core/src/trust-anchor.ts`
- `packages/core/src/domain-verifier.ts`
- `packages/core/src/passkey.ts`
- `packages/core/test/identity.test.ts`
- `packages/core/test/trust-anchor.test.ts`

Commit:

- `feat(identity): harden fides identity v2`

Verification:

- `pnpm --filter @fides/core test`
- `pnpm --filter @fides/core typecheck`

## Milestone 3: AgentCards and Capability Ontology

Goal: signed AgentCards that describe capability, risk, transport, policy, and trust metadata.

Tasks:

1. Add AgentCard v2 fields from the pivot.
2. Add `CapabilityDescriptor` fields: namespace, action, resource, capability id, input/output schemas, risk class, scopes, controls, dry-run, approval, policy proof.
3. Add `CapabilityOntologyEntry`.
4. Add risk classes and sample capabilities.
5. Add signed AgentCard creation/verification helpers.
6. Add compatibility mapping for current AgentCard shapes.

Primary files:

- `packages/core/src/agent-card.ts`
- `packages/core/src/capability.ts`
- `packages/core/src/canonical-signer.ts`
- `packages/core/test/agent-card.test.ts`
- `packages/core/test/capability.test.ts`

Commit:

- `feat(cards): add signed agent cards and capability ontology`

Verification:

- `pnpm --filter @fides/core test`
- `pnpm --filter @fides/core typecheck`

## Milestone 4: Evidence v2

Goal: signed, privacy-aware, hash-chained evidence events.

Tasks:

1. Add EvidenceEvent v2 with requested fields and event taxonomy.
2. Default sensitive payloads to hash-only/redacted.
3. Add input/output/policy/decision hashing helpers.
4. Add signed event append/verify.
5. Add Merkle proof-ready export shape.
6. Add compatibility adapter from current evidence event.

Primary files:

- `packages/evidence/src/index.ts`
- `packages/evidence/test/evidence.test.ts`
- `packages/core/src/protocol.ts`

Commit:

- `feat(evidence): add signed privacy-aware evidence events`

Verification:

- `pnpm --filter @fides/evidence test`
- `pnpm --filter @fides/evidence typecheck`

## Milestone 5: Discovery v2 and DHT Pointers

Goal: discovery returns verified candidates and never authority.

Tasks:

1. Add `DiscoveryQuery` and `DiscoveryCandidate`.
2. Extend provider interface with `discover(query): Promise<DiscoveryCandidate[]>`.
3. Preserve old `resolve(did)` as compatibility.
4. Add verification pipeline in orchestrator.
5. Add signed `DHTPointerRecord`.
6. Replace DHT direct-card lookup with pointer publish/find path while keeping compatibility methods behind tests.
7. Add DHT tests: valid pointer, tamper rejection, expiry, card hash mismatch, revoked agent.

Primary files:

- `packages/discovery/src/provider.ts`
- `packages/discovery/src/orchestrator.ts`
- `packages/discovery/src/dht-provider.ts`
- `packages/discovery/src/local-provider.ts`
- `packages/discovery/src/registry-provider.ts`
- `packages/discovery/src/relay-provider.ts`
- `packages/discovery/test/*`
- `packages/core/src/discovery.ts`
- `packages/core/src/dht.ts`

Commits:

- `feat(discovery): add capability query provider contract`
- `feat(dht): add signed pointer records`

Verification:

- `pnpm --filter @fides/discovery test`
- `pnpm --filter @fides/discovery typecheck`

## Milestone 6: Trust and Reputation v2

Goal: capability-specific trust and explainable scoring.

Tasks:

1. Add `TrustResult`, trust bands, score component types.
2. Add `ReputationRecord`.
3. Extend trust graph service scoring with component explanations.
4. Integrate incidents, novelty, context boundary, publisher weighting.
5. Add API/SDK compatibility layer.

Primary files:

- `packages/core/src/trust.ts`
- `services/trust-graph/src/services/trust-service.ts`
- `services/trust-graph/src/services/capability-scoring.ts`
- `services/trust-graph/src/routes/trust.ts`
- `packages/sdk/src/trust/client.ts`

Commit:

- `feat(trust): add explainable capability trust results`

Verification:

- `pnpm --filter @fides/trust-graph test`
- `pnpm --filter @fides/sdk test`

## Milestone 7: Policy, Approvals, Kill Switch

Goal: policy-before-execution with durable approval and kill switch primitives.

Tasks:

1. Add decision vocabulary compatibility.
2. Add `ApprovalRequest`, `ApprovalDecision`, `ApprovalPolicy`.
3. Add `KillSwitchRule` protocol object.
4. Wire guard/policy to durable approval state.
5. Add evidence events for approval and kill-switch lifecycle.

Primary files:

- `packages/core/src/approval.ts`
- `packages/core/src/kill-switch.ts`
- `packages/policy/src/index.ts`
- `packages/guard/src/index.ts`
- `packages/runtime/src/index.ts`
- `services/agentd/src/index.ts`

Commits:

- `feat(policy): add approval primitives`
- `feat(policy): add kill switch rules`

Verification:

- `pnpm --filter @fides/policy test`
- `pnpm --filter @fides/guard test`
- `pnpm --filter @fides/agentd test`

## Milestone 8: Delegation, Sessions, Invocation

Goal: signed scoped authority and generic invocation flow.

Tasks:

1. Harden `DelegationToken`.
2. Add v2 `SessionGrant`.
3. Add replay protection and audience restriction tests.
4. Add `InvocationRequest` and `InvocationResult`.
5. Add dry-run/approval-required/denied/allowed/failed status flow.
6. Emit evidence events.

Primary files:

- `packages/core/src/delegation.ts`
- `packages/core/src/session-store.ts`
- `packages/core/src/invocation.ts`
- `services/agentd/src/index.ts`
- `packages/sdk/src/agentd/client.ts`

Commits:

- `feat(delegation): add signed session grants`
- `feat(invocation): add capability invocation objects`

Verification:

- `pnpm --filter @fides/core test`
- `pnpm --filter @fides/agentd test`
- `pnpm --filter @fides/sdk test`

## Milestone 9: Revocation, Incidents, Runtime Attestation

Goal: revocation/incident/attestation become first-class v2 signed objects.

Tasks:

1. Add revocation target taxonomy.
2. Add incident categories and resolution status.
3. Add `RuntimeAttestation` v2 schema fields.
4. Add `NullAttestationProvider`.
5. Integrate invalid/expired attestations into policy/trust.

Primary files:

- `packages/core/src/revocation.ts`
- `packages/core/src/runtime-attestation.ts`
- `packages/runtime/src/index.ts`
- `services/agentd/src/index.ts`
- `services/trust-graph/src/services/trust-service.ts`

Commits:

- `feat(revocation): add v2 revocation records`
- `feat(incidents): add incident resolution records`
- `feat(attestations): add runtime attestation v2`

Verification:

- `pnpm --filter @fides/core test`
- `pnpm --filter @fides/runtime test`
- `pnpm --filter @fides/trust-graph test`

## Milestone 10: Registry, Relay, Federation

Goal: hosted/public/private registry, relay presence, and federation-ready records.

Tasks:

1. Add signed `RegistryIndexRecord`.
2. Add `RegistryPeerRecord`.
3. Add public/private mode docs and tests.
4. Add local mock federation provider.
5. Add revocation/incident propagation interfaces.
6. Keep relay as presence/rendezvous only.

Primary files:

- `services/registry/src/`
- `services/relay/src/`
- `packages/core/src/registry.ts`
- `packages/core/src/federation.ts`
- `packages/discovery/src/registry-provider.ts`
- `packages/discovery/src/relay-provider.ts`

Commits:

- `feat(registry): add signed index records`
- `feat(registry): add federation peer records`
- `feat(relay): clarify relay discovery authority boundaries`

Verification:

- `pnpm --filter @fides/registry-service test`
- `pnpm --filter @fides/relay-service test`
- `pnpm --filter @fides/discovery test`

## Milestone 11: Adapters

Goal: FIDES has explicit interop boundaries.

Tasks:

1. Add `packages/adapters`.
2. Add interfaces for MCP, A2A, OAPS, OSP, AP2, x402, Sardis.
3. Add mapping docs.
4. Add simple no-network tests.

Primary files:

- `packages/adapters/`
- `docs/protocol/interop-adapters.md`

Commit:

- `feat(adapters): add interop adapter interfaces`

Verification:

- `pnpm --filter @fides/adapters test`
- `pnpm --filter @fides/adapters typecheck`

## Milestone 12: Agentd CLI/API/SDK Alignment

Goal: make local developer flow match the requested `agentd` surface.

Tasks:

1. Add `agentd` binary or alias.
2. Add missing CLI commands:
   - identity create/list/show,
   - attest,
   - card create/sign/verify/inspect,
   - registry/relay/dht,
   - demo run,
   - simulate adversarial.
3. Add requested local HTTP endpoints as compatibility routes where needed.
4. Add SDK methods matching the example.
5. Add local SQLite store if still pending.

Primary files:

- `packages/cli/src/index.ts`
- `packages/cli/src/commands/`
- `services/agentd/src/index.ts`
- `services/agentd/src/storage.ts`
- `packages/sdk/src/`
- `docs/api/agentd.yaml`
- `docs/cli-reference.md`
- `docs/sdk-reference.md`

Commits:

- `feat(cli): add agentd command surface`
- `feat(api): add fides v2 local endpoints`
- `feat(sdk): add promise client v2 flow`

Verification:

- `pnpm --filter @fides/cli test`
- `pnpm --filter @fides/agentd test`
- `pnpm --filter @fides/sdk test`

## Milestone 13: Examples, Demo, Adversarial Simulation

Goal: prove the full local DX.

Tasks:

1. Add example agent folders.
2. Add full demo scenario.
3. Add malicious agent.
4. Add adversarial simulation harness.
5. Add manual DX script/runbook.

Primary files:

- `examples/calendar-agent/`
- `examples/invoice-agent/`
- `examples/payment-agent/`
- `examples/malicious-agent/`
- `examples/requester-agent/`
- `examples/full-demo/`
- `tests/adversarial/`
- `docs/adversarial-simulation.md`

Commits:

- `feat(examples): add fides v2 demo agents`
- `feat(sim): add adversarial simulation harness`

Verification:

- `pnpm test`
- `agentd demo run`
- `agentd simulate adversarial`

## Milestone 14: Docs Completion

Goal: make the repo publishable.

Tasks:

1. Add protocol docs from the pivot.
2. Add ADRs.
3. Update README and getting started.
4. Add API/CLI/SDK references.
5. Add threat model.
6. Document limitations honestly.

Primary files:

- `docs/protocol/*.md`
- `docs/adr/*.md`
- `docs/threat-model.md`
- `docs/getting-started.md`
- `docs/api-reference.md`
- `docs/cli-reference.md`
- `docs/sdk-reference.md`
- `README.md`

Commits:

- `docs: add fides v2 protocol docs`
- `docs: add fides v2 getting started`

Verification:

- `pnpm verify`
- Manual CLI demo.

## Final Completion Contract

Final report must include:

1. What was implemented.
2. What is production-like.
3. What is working prototype.
4. What is local mock.
5. What is adapter-ready.
6. What is spec-complete.
7. Package overview.
8. CLI command overview.
9. API endpoint overview.
10. SDK example.
11. How to run tests.
12. How to run demo.
13. How to run adversarial simulation.
14. Known limitations.
15. Future hardening steps.
16. Commit history summary.
