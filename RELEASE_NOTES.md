# FIDES v2 Release Notes

This document summarizes the current FIDES v2 Agent Trust Fabric state for
local evaluation and OSS review. It is not a production-readiness claim for the
entire protocol roadmap.

## Current Snapshot

FIDES v2 is a TS-first, Rust-adapter-ready trust fabric for autonomous agent
systems. The current implementation provides local-first identity, signed
AgentCards, candidate-only discovery, capability-specific trust and reputation,
policy-before-execution, delegation, scoped sessions, signed invocation,
runtime attestation primitives, evidence, revocation, incidents, kill switches,
CLI, local daemon HTTP API, SDK, examples, demo, and adversarial simulation.

The implementation keeps the core protocol constraints explicit:

- discovery does not grant authority
- identity does not equal trust
- trust score does not equal permission
- policy is evaluated before execution
- signed protocol objects use one canonical signing model
- evidence defaults toward privacy-aware hash-only or redacted records
- Rust is optional and adapter-ready rather than required

## Production-Like Surfaces

- Canonical JSON signing and Ed25519 verification primitives.
- Typed `ErrorEnvelope` vocabulary on root v2 API/SDK/CLI failure paths.
- Policy-before-execution hooks for revocation, incidents, runtime attestation,
  approval, kill switch, dry-run, and scope limits.
- Issuer-bound canonical `DelegationTokenV2` signatures and payload-hash
  validation.
- Scoped `SessionGrantV2` records with protocol version negotiation.
- Canonical signed `InvocationRequest` and signed invocation result support.
- Hash-chained evidence verification and export.
- Publishable package hygiene and dry-run pack gates for public packages.
- OpenAPI and CLI surface audits.

## Working Prototype Surfaces

- Local `agentd` root v2 API and local state store.
- Promise-based `FidesClient` SDK.
- `agentd` CLI for identity, AgentCards, discovery, trust, reputation, policy,
  sessions, invocation, evidence, revocation, incidents, kill switch, registry,
  relay, DHT, demo, and adversarial simulation.
- Full local demo and adversarial simulation endpoints.
- Example agents for calendar, invoice, payment dry-run, requester, and
  malicious simulation flows.

## Local Mock Surfaces

- Registry discovery.
- Relay presence and rendezvous hints.
- DHT pointer records.
- Federation discovery.
- MockTEE runtime attestation provider.
- Generic payment flow is dry-run only; payment execution remains Sardis-owned.

## Adapter-Ready Surfaces

- AGIT/Rust primitive bridge for hashing, canonicalization, hash chain, Merkle,
  and DAG-style evidence primitives.
- libp2p/Kademlia DHT provider boundary.
- Relay transport boundary.
- Real TEE/build/container attestation provider boundaries.
- MCP, A2A, OAPS, OSP, AP2, x402, and Sardis interop adapter contracts.
- Federation peering and propagation contracts.

## Recently Verified

Local verification has passed with:

```bash
pnpm verify
pnpm smoke:agentd
pnpm package:hygiene
pnpm package:packcheck
pnpm api:audit
pnpm cli:audit
pnpm examples:audit
pnpm rust-adapter:audit
```

`pnpm smoke:agentd` starts an isolated local daemon and exercises root
`pnpm agentd` CLI flows for demo, signed invocation, canonical signed
delegation-token session creation, all-provider discovery, and adversarial
simulation.

The CI workflow runs both `pnpm verify` and `pnpm smoke:agentd`, so the same
local gates are enforced on pull requests before the Docker smoke job runs.
`pnpm package:hygiene` also enforces non-placeholder README coverage for every
publishable package boundary.

## Known Limitations

- The full FIDES v2 pivot is not complete.
- Several target package boundaries are facades over `packages/core` rather
  than independent implementations.
- Registry, relay, DHT, and federation are local mock/simulator surfaces, not
  production networks.
- Real TEE providers are adapter-ready but not implemented.
- Local key material is prototype-grade and should be hardened before
  production use.
- Remote CI has not been checked in the current local session unless a PR or CI
  run explicitly says otherwise; the workflow is configured to run the full
  verify gate and the agentd DX smoke.
- The branch may need to be pushed before external review.

## Release Checklist

Before cutting an external release:

1. Run `pnpm verify`.
2. Run `pnpm smoke:agentd`.
3. Confirm `.github/workflows/ci.yml` passes remotely.
4. Confirm `scripts/print-public-package-dirs.mjs` matches intended packages.
5. Review `docs/status/fides-v2-implementation-status.md`.
6. Update this file with the final tag, date, commit range, and known limits.
7. Do not describe local mock or adapter-ready surfaces as production-ready.

## Suggested Tag Notes Template

```markdown
## vX.Y.Z - YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Verification
- `pnpm verify`
- `pnpm smoke:agentd`
- Remote CI: <link>

### Known Limits
- ...
```
