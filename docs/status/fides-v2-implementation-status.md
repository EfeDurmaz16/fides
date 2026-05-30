# FIDES v2 Implementation Status

This document records the current implementation status for the FIDES v2 Agent
Trust Fabric. It is not a completion claim for the full project pivot. It is a
grounded status snapshot for local development, manual DX, and open-source
readiness work.

Last verified locally: 2026-05-30.

## What Was Implemented

- Local-first `agentd` HTTP API for identity, attestations, AgentCards, agent
  registration, discovery, trust, reputation, policy, approvals, delegation,
  sessions, invocation, evidence, revocation, incidents, kill switch, registry,
  relay, DHT, demo, and adversarial simulation.
- Promise-based `FidesClient` SDK surface for the root v2 `agentd` API.
- `agentd` CLI command surface, plus root workspace scripts:
  - `pnpm agentd <command>`
  - `pnpm agentd:dev`
- CLI surface audit for the requested `agentd` command groups and critical
  options.
- Canonical signing model for signed protocol objects.
- Typed error envelopes on root v2 identity, AgentCard, discovery, trust,
  reputation, policy, session, invocation, approval, kill switch, revocation,
  incident, attestation, and evidence failure paths.
- Signed AgentCards and capability descriptors.
- Candidate-only discovery across local, well-known, registry, relay, DHT, and
  federation-ready surfaces.
- Signed registry index records, signed relay AgentCard references, and signed
  DHT pointer records.
- Discovery publish and presence writes explicitly return `authorityGranted:
  false`; publishing to registry, relay, or DHT never grants invocation
  authority.
- Root discovery endpoints append hash-only `discovery.performed` evidence
  events and return `evidenceRefs`/`evidence_refs` without granting authority.
- Capability-specific trust and reputation scoring with explainability.
- Policy-before-execution with approval, dry-run, revocation, incident, runtime
  attestation, and kill switch inputs.
- Canonically signed `DelegationTokenV2` records with issuer-bound verification,
  scoped capabilities, audience restriction, expiry, nonce, and payload hash.
- `agentd` `/v1/sessions` accepts canonical `SignedDelegationTokenV2` payloads
  and verifies the issuer-bound proof without requiring an external
  `delegatorPublicKey`; legacy token sessions remain supported.
- `agentd session create` auto-detects canonical signed delegation-token input
  and sends it as `signedToken`; legacy token input remains available with
  optional `--delegator-public-key`.
- Scoped SessionGrants and invocation preflight.
- `agentd invoke --sign` fetches or creates a SessionGrant, verifies the
  requester private key resolves to `requester_agent_id`, signs a canonical
  `InvocationRequest`, and submits it as `signedRequest`.
- SessionGrants now carry supported protocol versions, optional required
  versions, and the negotiated protocol version used for authority.
- Hash-chained EvidenceEvents with verification and export.
- Runtime attestation schema and local MockTEE provider.
- Local SQLite daemon snapshot store for v2 local state, with mirror tables for
  identities, trust anchors, attestations, AgentCards, agents, capabilities,
  discovery records, DHT records, registry records, relay records, trust
  results, reputation records, policy decisions, approvals, delegations,
  sessions, evidence events, revocations, incidents, and kill switch rules.
- Public target-structure facade packages for crypto, identity, attestations,
  cards, trust, reputation, delegation, invocation, DHT, relay, registry,
  revocation, incidents, adapters, guard, runtime-effect, and daemon.
- Public facade packages include export contract tests and no longer depend on
  empty-test fallback behavior.
- Publishable package hygiene and dry-run pack checks now cover all 25
  non-private packages under `packages/*`, and fail if a publishable package is
  omitted from the public package gate.
- Rust remains adapter-ready rather than required: `pnpm rust-adapter:audit`
  verifies `packages/rust-sdk` stays documentation-only, has no Rust/package
  runtime manifest, and matches the `@fides/adapters` Rust primitive surfaces.
- Canonical v2 example agent catalog for calendar, invoice, payment, requester,
  and malicious agents, with audited capability IDs, risk classes, required
  scopes, and authority notes.
- Example agents now have target-structure directories with runnable
  `index.ts` entrypoints and per-agent READMEs; legacy top-level
  `examples/<agent>.ts` wrappers remain for compatibility.
- Standalone example scripts use dot-separated v2 capability IDs for calendar,
  invoice, payment, and email flows; the example audit rejects the legacy
  `namespace:action` IDs that previously remained in examples and verifies the
  target example-agent directories exist.
- Full local demo and adversarial simulation endpoints.
- Public docs refreshed around `agentd`, `FidesClient`, candidate-only
  discovery, and authority-via-policy/session.

## Production-Like

- Canonical object signing and verification primitives.
- Typed error vocabulary and `ErrorEnvelope` response shape, including root v2
  validation and resource lookup failures.
- `agentd` scoped API key enforcement on protected mutation routes.
- Postgres authority-store migration and health-check path for `agentd`.
- SQLite local-state snapshot and mirror-table persistence for local inspection.
- Revocation, incident, kill switch, session, and evidence policy hooks.
- SDK type coverage for the main root v2 API responses.
- CLI HTTP helpers preserve root v2 `ErrorEnvelope` codes in command output,
  and the CLI entrypoint catches async command failures with stable formatting.
- OpenAPI route audit and response-shape contract coverage for root `agentd`
  demo, adversarial simulation, and non-authoritative discovery write
  responses.
- CLI command-surface audit for the requested root command groups.
- OpenAPI contract coverage for evidence-producing discovery responses.
- Publishable package gate for all non-private package manifests, including
  README/LICENSE/package metadata and dry-run package contents.
- Root `CONTRIBUTING.md` documents protocol invariants, security-sensitive
  review areas, docs expectations, and local verification gates for external
  contributors.
- Root `RELEASE_NOTES.md` records the current v2 snapshot, production-like
  surfaces, working prototypes, local mocks, adapter-ready surfaces, verified
  gates, known limits, and release checklist.
- Public package README quality is now enforced by `pnpm package:hygiene` so
  publishable facade packages include installation, usage, status, and boundary
  guidance instead of placeholder package pages.
- OpenAPI contract coverage for version-bound `SessionGrantV2` responses.
- Core tests for issuer-bound `DelegationTokenV2` canonical signatures and
  payload-hash tamper detection.
- Core and agentd route tests cover canonical delegation-session creation,
  issuer mismatch rejection, and nonce replay protection.
- CLI tests cover canonical signed delegation-token submission to `/v1/sessions`.
- CLI tests cover canonical signed invocation request submission and issuer
  proof verification.
- `pnpm cli:audit` now checks 59 command/help surfaces across the Phase 22 CLI
  matrix, including identity, attestations, cards, discovery providers, policy,
  sessions, invocation, approvals, evidence, revocation, incidents, kill switch,
  delegation, daemon, demo, and adversarial simulation commands.
- `pnpm smoke:agentd` starts an isolated local daemon and exercises root
  `pnpm agentd` CLI flows for demo, signed invocation, canonical signed
  delegation-token session creation, all-provider discovery, and adversarial
  simulation.
- Canonical example catalog audit for the requested demo agents and
  capability/risk contracts.
- Example audit coverage rejects legacy standalone example capability names so
  docs, demos, and scripts stay aligned with the v2 ontology.
- CI and npm publish workflows use the same full `pnpm verify` gate used
  locally.
- CI also runs `pnpm smoke:agentd`, so signed CLI authority flows, local daemon
  DX, all-provider discovery, demo, and adversarial simulation are PR-gated.

## Working Prototype

- Local `agentd` v2 authority path.
- Identity creation and local key-backed signing for prototype flows.
- AgentCard create/sign/verify/register/discover.
- Capability-specific trust and reputation.
- Policy evaluation and session request.
- Invocation with dry-run, denial modes, and optional canonical signed
  invocation requests through SDK and CLI.
- Evidence append, inspect, verify, and export.
- Full demo scenario.
- Adversarial simulation harness.

## Local Mock

- Registry discovery uses local mock registry records.
- Relay discovery uses local mock presence and endpoint hints.
- DHT discovery uses local in-memory pointer records.
- Federation discovery uses local mock federation provider behavior.
- MockTEE is the local runtime attestation provider.
- Generic FIDES payment flow is dry-run only; payment execution remains
  Sardis-specific.

## Adapter-Ready

- AGIT/Rust bridge for canonical JSON, hashing, hash chain, Merkle, and DAG
  primitives.
- libp2p/Kademlia DHT adapter boundary.
- Relay transport adapter boundary.
- Real TEE providers: AWS Nitro, Intel SGX, AMD SEV.
- Container image and reproducible build attestation providers.
- MCP, A2A, OAPS, OSP, AP2, x402, and Sardis adapter interfaces.
- Federation peering and propagation interfaces.

## Spec-Complete Or Documentation-First

- OAPS concepts are mapped into FIDES-owned runtime types and docs; FIDES does
  not depend on `@oaps/core` at runtime.
- Sardis contributes generic authority/trust/evidence patterns only; payment
  domain remains Sardis-specific.
- Effect is documented as an internal orchestration option only; protocol
  objects and SDK APIs remain framework-agnostic.
- Public protocol docs exist for identity, AgentCards, discovery, DHT, relay,
  registry/federation, trust, reputation, policy, delegation/sessions,
  evidence, runtime attestation, revocation, incidents, approvals, kill switch,
  interop adapters, version negotiation, privacy, and error vocabulary.

## Package Overview

| Area | Current location |
|------|------------------|
| Protocol objects and signing | `packages/core` |
| Canonical JSON, hashing, signing facade | `packages/crypto` |
| Identity and trust anchors | `packages/identity` |
| Runtime attestations | `packages/attestations` |
| AgentCards and capabilities | `packages/cards` |
| Evidence ledger | `packages/evidence` |
| Trust scoring | `packages/trust` |
| Reputation scoring | `packages/reputation` |
| Policy evaluator | `packages/policy` |
| Delegation and sessions | `packages/delegation` |
| Invocation | `packages/invocation` |
| Guard decision pipeline | `packages/guard` |
| Runtime attestation and kill switch | `packages/runtime` |
| Effect-ready runtime workflow boundary | `packages/runtime-effect` |
| Discovery providers | `packages/discovery` |
| DHT pointer records | `packages/dht` |
| Relay discovery facade | `packages/relay` |
| Registry and federation records | `packages/registry` |
| Revocation records | `packages/revocation` |
| Incident records | `packages/incidents` |
| SDK | `packages/sdk` |
| CLI | `packages/cli` |
| Local daemon/API | `services/agentd` |
| Local daemon package boundary | `packages/daemon` |
| Adapters | `packages/adapters` |

Some target packages are currently domain facades over the TS-first core
implementation. This keeps public imports aligned with the v2 architecture
while preserving a single canonical protocol-object implementation.

## CLI Command Overview

Primary local commands:

```bash
pnpm agentd identity create --type agent
pnpm agentd card create
pnpm agentd card sign <card-id>
pnpm agentd register <card-id>
pnpm agentd discover --capability invoice.reconcile
pnpm agentd trust <agent-id> --capability invoice.reconcile
pnpm agentd graph inspect <agent-id>
pnpm agentd reputation <agent-id> --capability invoice.reconcile
pnpm agentd policy evaluate --agent <agent-id> --capability invoice.reconcile
pnpm agentd session request <agent-id> --capability invoice.reconcile
pnpm agentd invoke --session-id <session-id> --input invoice.json
pnpm agentd evidence verify
pnpm agentd demo run
pnpm agentd simulate adversarial
```

Use `pnpm --silent agentd ... --json` when piping JSON output.

## API Endpoint Overview

Primary root v2 API:

- `GET /health`
- `POST /identities`
- `GET /identities`
- `GET /identities/:id`
- `POST /attestations`
- `GET /attestations/:id`
- `POST /attestations/:id/verify`
- `POST /agent-cards`
- `POST /agent-cards/:id/sign`
- `POST /agent-cards/:id/verify`
- `GET /agent-cards/:id`
- `POST /agents/register`
- `GET /agents`
- `GET /agents/:id`
- `POST /discover`
- `POST /discover/local`
- `POST /discover/well-known`
- `POST /discover/registry`
- `POST /discover/relay`
- `POST /discover/dht`
- `POST /discover/federation`
- `POST /trust/evaluate`
- `GET /trust/:agentId`
- `POST /reputation/update`
- `GET /reputation/:agentId`
- `POST /policy/evaluate`
- `POST /approvals`
- `GET /approvals`
- `POST /approvals/:id/approve`
- `POST /approvals/:id/deny`
- `POST /delegations`
- `POST /sessions`
- `GET /sessions/:id`
- `POST /sessions/:id/verify`
- `POST /invoke`
- `POST /evidence`
- `GET /evidence`
- `GET /evidence/:eventId`
- `POST /evidence/verify`
- `POST /evidence/export`
- `POST /revocations`
- `GET /revocations`
- `GET /revocations/:id`
- `POST /incidents`
- `GET /incidents`
- `GET /incidents/:id`
- `POST /incidents/:id/resolve`
- `POST /killswitch`
- `GET /killswitch`
- `DELETE /killswitch/:id`
- `POST /registry/start`
- `POST /registry/publish`
- `POST /registry/search`
- `GET /registry/index`
- `POST /relay/start`
- `POST /relay/register`
- `POST /relay/discover`
- `POST /dht/start`
- `POST /dht/publish`
- `GET /dht/find`
- `POST /dht/find`
- `GET /.well-known/fides.json`
- `GET /.well-known/agents.json`
- `GET /.well-known/agents/:id.json`
- `POST /demo/run`
- `POST /simulate/adversarial`

See `docs/api/agentd.yaml` and `docs/api-reference.md` for the complete API
surface.

## SDK Example

```typescript
import { FidesClient } from '@fides/sdk'

const client = new FidesClient({ daemonUrl: 'http://localhost:7345' })

const identity = await client.identity.createAgent({ name: 'Invoice Agent' })
const card = await client.cards.create({
  agentId: identity.did,
  name: 'Invoice Agent',
  capabilities: [{ id: 'invoice.reconcile', riskLevel: 'medium' }],
})

await client.cards.sign({ id: card.card.id })
await client.agents.register({ agentCardId: card.card.id })

const candidates = await client.discovery.local({ capability: 'invoice.reconcile' })
const trust = await client.trust.evaluate({ agentId: identity.did, capability: 'invoice.reconcile' })
const session = await client.sessions.request({
  agentId: identity.did,
  capability: 'invoice.reconcile',
  requestedScopes: ['invoice:read'],
})
const result = await client.invoke({
  sessionId: session.session.session_id,
  input: { invoiceId: 'inv_123' },
})

console.log({ authorityGrantedByDiscovery: candidates.authorityGranted, trust, result })
```

## Verification Run

Recently verified commands:

```bash
pnpm verify
pnpm examples:audit
pnpm examples:typecheck
pnpm --filter @fides/sdk build
pnpm --filter @fides/sdk test
pnpm --filter @fides/sdk test -- fides-client.test.ts
pnpm --filter @fides/sdk lint
pnpm --filter @fides/cli lint
pnpm --filter @fides/agentd test
pnpm --filter @fides/e2e-tests test -- agentd-openapi-contract.test.ts
pnpm --filter @fides/cli build
pnpm package:hygiene
pnpm api:audit
pnpm cli:audit
pnpm rust-adapter:audit
pnpm smoke:agentd
```

Manual DX smoke:

```bash
pnpm smoke:agentd

# Equivalent manual flow:
AGENTD_LOCAL_STATE=memory AGENTD_PORT=7486 pnpm agentd:dev
pnpm --silent agentd demo run --agentd-url http://localhost:7486 --json
pnpm --silent agentd session request <invoice-agent-did> --capability invoice.reconcile --requested-scopes invoice:read --principal-id <principal-did> --requester-agent-id <requester-did> --agentd-url http://localhost:7486 --json
pnpm --silent agentd invoke --session-id <session-id> --input-json '{"invoiceId":"inv_smoke_signed"}' --sign --requester-private-key-file requester.key --agentd-url http://localhost:7486 --json
pnpm --silent agentd session create --capability invoice.reconcile --token-file signed-delegation-token-v2.json --agentd-url http://localhost:7486 --json
pnpm --silent agentd discover --capability invoice.reconcile --all-providers --agentd-url http://localhost:7486 --json
pnpm --silent agentd simulate adversarial --agentd-url http://localhost:7486 --json
```

Observed manual smoke results:

- demo returned `status: "executed"`.
- demo returned `mode: "local-first"`.
- demo returned `evidenceHashChainValid: true`.
- demo returned `discoveryGrantsAuthority: false`.
- demo returned `payments: "dry_run_only"`.
- signed invocation returned `signedRequestVerified: true`.
- signed invocation returned `signedResultVerified: true`.
- canonical signed delegation-token session creation returned
  `signedDelegationVerified: true`.
- all-provider discovery queried local, well-known, registry, relay, DHT, and federation providers.
- all-provider discovery returned `authorityGranted: false`.
- registry publish, relay register, and DHT publish responses return top-level
  `authorityGranted: false`.
- root discovery responses return `evidenceRefs` and `evidence_refs` for the
  appended `discovery.performed` event.
- adversarial simulation returned `status: "detected"`.
- adversarial simulation detected 10 scenarios.
- adversarial simulation returned `rootChainValid: true`.
- adversarial simulation returned `brokenEvidenceChainValid: false`.

## Known Limitations

- The full pivot is not complete.
- Several target package boundaries are public facades over `packages/core`
  rather than independent implementations.
- DHT, relay, registry, and federation are local mock/simulator surfaces rather
  than production networks.
- Real TEE providers are adapter-ready but not implemented.
- Real payment execution is intentionally not implemented in FIDES; it belongs
  in Sardis.
- Some legacy standalone service docs remain for compatibility and deployment
  reference.
- Full verification has passed locally, but remote CI has not been checked in
  the current session.
- The branch has not been pushed in the current session.

## Future Hardening Steps

- Keep full `pnpm verify` green before release.
- Push `fides-v2-agent-trust-fabric` and open/update a PR.
- Move facade internals into separate packages only when the split removes real
  complexity or enables independent adapters.
- Add real DHT, relay, registry, and federation adapters.
- Add production TEE/build/container attestation providers.
- Harden local key storage beyond prototype snapshot material.

## Commit History Summary

Recent v2 status/DX commits:

- `ad606ec feat(delegation): add canonical delegation tokens`
- `061d14e test(adapters): audit rust adapter readiness`
- `cb14b16 test(examples): enforce target agent layout`
- `86c719e feat(packages): publish guard and adapters surfaces`
- `33a6de8 feat(packages): add daemon and runtime effect boundaries`
- `99d40b2 test(examples): enforce v2 capability names`
- `7b7511f test(examples): audit canonical agent catalog`
- `44bad51 docs: refresh fides v2 status gates`
- `d719687 test(cli): audit agentd command surface`
- `2e0bbdf ci: use full verify gate`
- `c2ca6b7 test(services): require existing test suites`
- `b9b6967 test(packages): cover protocol facade exports`
- `25bb2f6 feat(packages): add protocol domain facades`
- `18a52f0 docs: refresh fides v2 dx status commits`
- `292055d fix(cli): catch async entrypoint failures`
- `8b472a0 feat(cli): surface typed agentd errors`
- `2d4eb41 feat(delegation): bind session grants to protocol versions`
- `2ccaa52 test(agentd): cover provider discovery evidence refs`
- `7c60719 docs: document discovery evidence events`
- `22cd792 feat(agentd): emit discovery evidence events`
- `55653a8 docs: record non-authoritative discovery writes`
- `ffd0874 test(sdk): expose non-authoritative discovery writes`
- `fd17264 feat(agentd): mark discovery writes non-authoritative`
- `6c09690 test(api): lock demo response contracts`
- `1b2276c docs: document sqlite local state mirrors`
- `29df5d6 test(agentd): cover sqlite local state mirrors`
- `9c2cbb3 test(sdk): cover root agentd endpoint helpers`
- `2167309 test(api): audit documented endpoint summaries`
- `8199a2e docs: record all-provider discovery smoke`
- `e35d5ea test(agentd): smoke all-provider discovery`
- `0500032 test(api): audit agentd openapi routes`
- `416de6c docs(cli): note silent json mode for pnpm agentd`
- `57fd72c chore(cli): add root agentd scripts`
- `e0554eb docs(cli): fix workspace agentd invocation`
- `f054a69 docs: clarify agentd as fides v2 deployment surface`
- `1dae3db docs: refresh readme for fides v2 authority path`
- `f956dc2 docs: align top-level architecture with fides v2`
- `f99721d docs(cli): document agentd authority workflow`
- `1208ccd docs(sdk): lead with fides client quickstart`
- `49542c8 docs: refresh getting started for fides v2`
