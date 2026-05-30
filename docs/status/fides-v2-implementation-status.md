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
- Canonical signing model for signed protocol objects.
- Typed error envelopes on important session and invocation failure paths.
- Signed AgentCards and capability descriptors.
- Candidate-only discovery across local, well-known, registry, relay, DHT, and
  federation-ready surfaces.
- Signed registry index records, signed relay AgentCard references, and signed
  DHT pointer records.
- Capability-specific trust and reputation scoring with explainability.
- Policy-before-execution with approval, dry-run, revocation, incident, runtime
  attestation, and kill switch inputs.
- Scoped SessionGrants and invocation preflight.
- Hash-chained EvidenceEvents with verification and export.
- Runtime attestation schema and local MockTEE provider.
- Local SQLite daemon snapshot store for v2 local state.
- Full local demo and adversarial simulation endpoints.
- Public docs refreshed around `agentd`, `FidesClient`, candidate-only
  discovery, and authority-via-policy/session.

## Production-Like

- Canonical object signing and verification primitives.
- Typed error vocabulary and `ErrorEnvelope` response shape.
- `agentd` scoped API key enforcement on protected mutation routes.
- Postgres authority-store migration and health-check path for `agentd`.
- Revocation, incident, kill switch, session, and evidence policy hooks.
- SDK type coverage for the main root v2 API responses.
- OpenAPI schemas for root `agentd` demo and simulation responses.

## Working Prototype

- Local `agentd` v2 authority path.
- Identity creation and local key-backed signing for prototype flows.
- AgentCard create/sign/verify/register/discover.
- Capability-specific trust and reputation.
- Policy evaluation and session request.
- Invocation with dry-run and denial modes.
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
| Evidence ledger | `packages/evidence` |
| Policy evaluator | `packages/policy` |
| Guard decision pipeline | `packages/guard` |
| Runtime attestation and kill switch | `packages/runtime` |
| Discovery providers | `packages/discovery` |
| SDK | `packages/sdk` |
| CLI | `packages/cli` |
| Local daemon/API | `services/agentd` |
| Adapters | `packages/adapters` |

Some target package boundaries from the v2 architecture remain consolidated in
existing packages. See `docs/architecture/implementation-plan.md` for the target
package structure.

## CLI Command Overview

Primary local commands:

```bash
pnpm agentd identity create --type agent
pnpm agentd card create
pnpm agentd card sign <card-id>
pnpm agentd register <card-id>
pnpm agentd discover --capability invoice.reconcile
pnpm agentd trust <agent-id> --capability invoice.reconcile
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
- `POST /attestations`
- `POST /agent-cards`
- `POST /agents/register`
- `POST /discover`
- `POST /trust/evaluate`
- `POST /reputation/update`
- `POST /policy/evaluate`
- `POST /approvals`
- `POST /delegations`
- `POST /sessions`
- `POST /invoke`
- `GET /evidence`
- `POST /evidence/verify`
- `POST /revocations`
- `POST /incidents`
- `POST /killswitch`
- `POST /registry/publish`
- `POST /relay/register`
- `POST /dht/publish`
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
pnpm --filter @fides/sdk build
pnpm --filter @fides/sdk test
pnpm --filter @fides/cli lint
pnpm --filter @fides/agentd test
pnpm --filter @fides/cli build
pnpm package:hygiene
```

Manual DX smoke:

```bash
AGENTD_LOCAL_STATE=memory AGENTD_PORT=7486 pnpm agentd:dev
pnpm --silent agentd demo run --agentd-url http://localhost:7486 --json
pnpm --silent agentd simulate adversarial --agentd-url http://localhost:7486 --json
```

Observed manual smoke results:

- demo returned `status: "executed"`.
- demo returned `mode: "local-first"`.
- demo returned `evidenceHashChainValid: true`.
- demo returned `discoveryGrantsAuthority: false`.
- demo returned `payments: "dry_run_only"`.
- adversarial simulation returned `status: "detected"`.
- adversarial simulation detected 10 scenarios.
- adversarial simulation returned `rootChainValid: true`.
- adversarial simulation returned `brokenEvidenceChainValid: false`.

## Known Limitations

- The full pivot is not complete.
- The target package structure is not fully split into every final package.
- DHT, relay, registry, and federation are local mock/simulator surfaces rather
  than production networks.
- Real TEE providers are adapter-ready but not implemented.
- Real payment execution is intentionally not implemented in FIDES; it belongs
  in Sardis.
- Some legacy standalone service docs remain for compatibility and deployment
  reference.
- Full `pnpm verify` was not run in the latest local verification pass.
- The branch has not been pushed in the current session.

## Future Hardening Steps

- Run full `pnpm verify` before release.
- Push `fides-v2-agent-trust-fabric` and open/update a PR.
- Normalize target package boundaries where the current monorepo is still
  consolidated.
- Add real DHT, relay, registry, and federation adapters.
- Add production TEE/build/container attestation providers.
- Harden local key storage beyond prototype snapshot material.
- Expand CLI end-to-end tests around root `pnpm agentd` scripts.
- Add full release notes and contribution guidance for external OSS users.

## Commit History Summary

Recent v2 status/DX commits:

- `416de6c docs(cli): note silent json mode for pnpm agentd`
- `57fd72c chore(cli): add root agentd scripts`
- `e0554eb docs(cli): fix workspace agentd invocation`
- `f054a69 docs: clarify agentd as fides v2 deployment surface`
- `1dae3db docs: refresh readme for fides v2 authority path`
- `f956dc2 docs: align top-level architecture with fides v2`
- `f99721d docs(cli): document agentd authority workflow`
- `1208ccd docs(sdk): lead with fides client quickstart`
- `49542c8 docs: refresh getting started for fides v2`
