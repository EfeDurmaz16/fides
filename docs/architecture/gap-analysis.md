# Gap Analysis

This document classifies the current status of every required FIDES v2 / Agent Trust Fabric feature after the first implementation pass. It is evidence-based and uses local files in this repository as the source of truth.

## Status Legend

| Status | Meaning |
|--------|---------|
| Implemented | Usable in code with tests or service routes |
| Prototype | Usable local implementation, but not production-grade |
| Mock | Intentionally local or fake provider for development/testing |
| Adapter-ready | Interface or provider boundary exists; external production adapter is not implemented |
| Spec-complete | Documented architecture/protocol exists; runtime implementation is not present |
| Missing | Not implemented in this repository |
| Avoid | Deliberately not included because it would weaken the trust-fabric boundary |

## Feature Gap Matrix

| # | Feature | Status | Evidence / notes |
|---|---------|--------|------------------|
| 1 | Local daemon | Prototype | `services/agentd/src/index.ts`, `services/agentd/test/routes.test.ts`; local HTTP API proxies identity/card/trust and hosts local policy/evidence/attestation/killswitch endpoints. |
| 2 | Agent identity | Implemented | `packages/core/src/identity.ts`, `packages/sdk/src/identity/*`, `packages/core/test/identity.test.ts`, `packages/sdk/test/identity.test.ts`. |
| 3 | Publisher identity | Prototype | `PublisherIdentity` in `packages/core/src/identity.ts`; verification providers are not production-backed. |
| 4 | Principal identity | Prototype | `PrincipalIdentity` in `packages/core/src/identity.ts`; session/principal binding is basic. |
| 5 | Domainless individual identity | Prototype | DID-based identity exists in SDK/core; individual proofing is not production-backed. |
| 6 | Platform-hosted identity | Spec-complete | Architecture describes it, but `services/platform-api` is metadata/topology only and does not host identity issuance or verification. |
| 7 | Domain-verified identity | Prototype | `PublisherIdentity.verificationMethod = "dns"`, `packages/core/src/domain-verifier.ts`, `fides identity domain verify`, `GET /v1/identities/domain/verify`, and discovery `POST /identities/{did}/domain/verify`; registry AgentCards do not yet enforce publisher verification. |
| 8 | Organization-verified identity | Spec-complete | Org identity is modeled through `PrincipalIdentity.type = "organization"` but no org verifier exists. |
| 9 | Trust anchors | Prototype | `TrustAnchor` type exists in `packages/core/src/identity.ts`; no anchor governance or distribution service yet. |
| 10 | Signed AgentCards | Implemented | `AgentCard` and `SignedAgentCard` in `packages/core/src/agent-card.ts`; canonical signing in `packages/core/src/canonical-signer.ts`; tests in `packages/core/test/agent-card.test.ts`. |
| 11 | Capability descriptors | Implemented | `CapabilityDescriptor` and risk classifier in `packages/core/src/capability.ts`; tests in `packages/core/test/capability.test.ts`. |
| 12 | Local discovery | Prototype | `packages/discovery/src/local-provider.ts`; file-backed local provider, not mDNS. |
| 13 | Local network discovery interface | Adapter-ready | Provider abstraction exists in `packages/discovery/src/provider.ts`; LAN/mDNS transport not implemented. |
| 14 | Well-known discovery | Implemented | `services/discovery/src/routes/well-known.ts`, `packages/discovery/src/well-known-provider.ts`, route tests. |
| 15 | Hosted registry | Prototype | `services/registry/src/index.ts`; file-backed registry with public/private modes. |
| 16 | Public registry API | Prototype | `services/registry/src/index.ts` exposes card registration, lookup, search, stats, mode updates. |
| 17 | Private registry mode | Prototype | `services/registry/src/index.ts`, registry route tests cover private mode. |
| 18 | Relay-based discovery | Prototype | `services/relay/src/index.ts`, `packages/discovery/src/relay-provider.ts`; relay is in-memory. |
| 19 | DHT-based discovery | Mock | `packages/discovery/src/dht-provider.ts`; local/in-memory or pointer-level behavior, no libp2p production network. |
| 20 | Federation-ready registry peering | Spec-complete | Architecture reserves the layer; peering protocol/runtime is not implemented. |
| 21 | Trust graph | Implemented | `services/trust-graph/src/services/graph.ts`, route/service tests. |
| 22 | Reputation engine | Implemented | `services/trust-graph/src/services/scoring.ts`, tests in `services/trust-graph/test/*`. |
| 23 | Capability-specific reputation | Prototype | `services/trust-graph/src/services/capability-scoring.ts`, `services/trust-graph/test/capability-scoring.test.ts`. |
| 24 | Trust scoring | Implemented | Direct/transitive scoring in `services/trust-graph/src/services/scoring.ts`. |
| 25 | Policy engine | Implemented | `packages/policy/src/index.ts`, `packages/policy/test/policy.test.ts`; `services/policy-engine/src/index.ts` exposes standalone evaluation routes; `agentd` uses it in `/v1/policy/evaluate`. |
| 26 | Delegation tokens | Implemented | `packages/core/src/delegation.ts`, `packages/core/test/delegation.test.ts`. |
| 27 | Session grants | Implemented | `SessionGrant` helpers plus `SessionStore`, `InMemorySessionStore`, `FileSessionStore`, nonce replay rejection, and session invocation authorization in `packages/core/src/session-store.ts`; route coverage in `services/agentd/test/routes.test.ts`. |
| 28 | Capability invocation | Prototype | Guard/policy decision path exists in `packages/guard/src/index.ts`; `services/agentd/src/index.ts` exposes `/v1/authorize`; actual remote invocation transport is adapter-ready. |
| 29 | Evidence ledger | Implemented | `packages/evidence/src/index.ts`, `services/agentd/src/index.ts`, tests in `packages/evidence/test/evidence.test.ts`. |
| 30 | Hash-chained evidence events | Implemented | `appendEvidenceEvent` and `verifyEvidenceChain` in `packages/evidence/src/index.ts`. |
| 31 | Revocation records | Implemented | `packages/core/src/revocation.ts`, core tests, and `agentd` revocation API routes. |
| 32 | Incident records | Implemented | `IncidentRecord` and impact aggregation in `packages/core/src/revocation.ts`; `agentd` incident API routes feed authorization context. |
| 33 | Runtime attestation | Prototype | `packages/runtime/src/index.ts`, `services/agentd/src/index.ts`, runtime tests. |
| 34 | TEE-ready attestation | Adapter-ready | `TEEAdapter` interface in `packages/runtime/src/index.ts`; production vendor adapters are not implemented. |
| 35 | Mock TEE provider | Mock | `MockTEEProvider` in `packages/runtime/src/index.ts`, `packages/runtime/test/runtime.test.ts`. |
| 36 | Container image attestation provider interface | Missing | No container image attestation interface exists yet. |
| 37 | Reproducible build attestation interface | Missing | No reproducible build attestation interface exists yet. |
| 38 | GitHub attestation | Missing | No GitHub verifier/provider exists yet. |
| 39 | Email attestation | Missing | No email verifier/provider exists yet. |
| 40 | Domain attestation | Prototype | DNS TXT verifier helper exists in `packages/core/src/domain-verifier.ts`; CLI, agentd, and discovery have Node DNS verification, with discovery persistence for verified identity domains. |
| 41 | Package registry attestation | Missing | No npm/PyPI/crates registry attestation provider exists yet. |
| 42 | Wallet attestation | Missing | Deliberately left out of FIDES core; Sardis should own payment/wallet-specific proofing. |
| 43 | Passkey identity interface | Missing | No WebAuthn/passkey abstraction exists yet. |
| 44 | CLI | Prototype | `packages/cli/src/index.ts` plus v2 commands for cards, policy, runtime, killswitch; daemon control is thin. |
| 45 | Local HTTP API | Prototype | `services/agentd/src/index.ts`; local API tests in `services/agentd/test/routes.test.ts`. |
| 46 | TypeScript SDK | Implemented | `packages/sdk/src/*`, SDK tests. |
| 47 | Example agents | Prototype | `examples/calendar-agent.ts`, `examples/invoice-agent.ts`, `examples/payment-agent.ts`, `examples/requester-agent.ts`. |
| 48 | End-to-end demo | Prototype | `examples/demo.ts`, `scripts/two-agents-demo.ts`, `scripts/authority-path-demo.ts`, `tests/e2e/full-flow.test.ts`. |
| 49 | Threat model | Spec-complete | `docs/threat-model.md`. |
| 50 | Protocol documentation | Spec-complete | `docs/protocol/fides-v2-spec.md`, `docs/protocol-spec.md`, architecture docs. |
| 51 | Test suite | Implemented | `pnpm test` covers 15 packages and the service routes. |
| 52 | Migration/versioning system | Spec-complete | `docs/migration-v1-v2.md`; runtime migration tooling is not implemented. |
| 53 | Security review checklist | Spec-complete | `SECURITY.md`, `docs/threat-model.md`; no automated checklist gate yet. |
| 54 | Future production hardening notes | Spec-complete | `docs/deployment.md`, `docs/threat-model.md`, implementation plan notes. |

## Current Reality by Layer

### Production-like

- Existing v1 identity/signing SDK primitives: Ed25519 key generation, DID parsing, keystore, HTTP request signing and verification.
- Trust graph service primitives: trust edge validation, graph traversal, trust/reputation scoring tests.
- Core canonical signing, AgentCard validation, delegation signatures, evidence hash-chain verification, policy evaluator tests.

### Working prototype

- `agentd` local HTTP API.
- Hosted registry service with file persistence and public/private mode.
- Relay service with in-memory queues and TTL.
- Discovery provider orchestration.
- Guard decision engine integrating trust, evidence, runtime attestation, incidents, kill switch, and policy.
- Example agents and local demo scripts, including an authority path demo through service routes.

### Local mock

- `MockTEEProvider` runtime attestation.
- DHT discovery provider behavior.
- Example-agent signatures in `examples/*`.

### Adapter-ready

- Runtime TEE adapters.
- Local network/mDNS discovery.
- DHT/libp2p discovery.
- Federation peering.
- Domain verification helper plus CLI, agentd, and discovery DNS verification; registry AgentCard publisher enforcement remains adapter-ready.
- External payment/action control plane integration through Sardis, not FIDES core.

### Still missing

- Production attestation providers: Nitro, SGX, SEV, container image, reproducible build, GitHub, email, package registry, passkey.
- Federation registry peering implementation.
- Real mDNS/libp2p transport.
- Platform metadata API under `services/platform-api/`.

## Remaining Blockers for a Production FIDES v2

1. Durable trust-fabric state: registry, evidence, revocation, and incidents need real storage contracts; sessions now have a file-backed local store but not a production database adapter.
2. Production attestation providers: the TEE/build/package/passkey providers are interfaces or missing, and domain verification still needs registry AgentCard publisher enforcement.
3. Federation semantics: registry peering, revocation propagation, conflict handling, and trust-anchor governance need implementation.
4. Authority separation hardening: identity, trust score, and policy are separated conceptually, but remote invocation execution remains adapter-ready rather than implemented.
5. Service packaging: platform-api and policy-engine now have standalone service packages, Dockerfiles, compose wiring, and CI image builds; they still need production persistence/auth/metrics beyond health and topology/evaluation routes.

## Next Implementation Slice

1. Add production storage adapters for registry, evidence, revocation, incidents, and session state.
2. Promote revocation/incidents into trust-graph APIs and propagation semantics.
3. Add production attestation providers for Nitro, SGX, SEV, container image, reproducible build, GitHub, email, package registry, and passkeys.
4. Enforce verified publisher domains during AgentCard registration and updates.
5. Extend the authority path demo into a multi-process demo that starts discovery, trust-graph, registry, relay, policy-engine, agentd, and platform-api.
