# Implementation Agent Prompt

You are continuing the FIDES v2 Agent Trust Fabric implementation in `/Users/efebarandurmaz/fides`.

## Mission

Evolve FIDES into a TS-first, Rust adapter-ready Agent Trust Fabric for autonomous agent systems.

FIDES v2 owns generic:

- identity,
- discovery,
- trust,
- reputation,
- authority,
- policy,
- delegation,
- runtime attestation,
- revocation,
- incidents,
- invocation,
- evidence.

It is not an agent app store and not a naive directory.

Discovery never equals authority.
Identity never equals trust.
Trust score never equals permission.
Policy is the authority.

## Current Branch and State

Work on:

```bash
cd /Users/efebarandurmaz/fides
git checkout fides-v2-agent-trust-fabric
```

The branch was fast-forwarded to local `main` at `7e52774` before the v2 pivot docs were rewritten.

Untracked local files/directories may exist:

- `.projects/`
- `.agents/`
- `.claude/`
- `.cursor/`
- `AGENTS.md`
- `CLAUDE.md`
- `new_fides.md`

Do not delete or overwrite them unless explicitly asked.

Neighbor repos are evidence sources only unless the user explicitly expands scope:

- `/Users/efebarandurmaz/agit`
- `/Users/efebarandurmaz/osp`
- `/Users/efebarandurmaz/OAPS`
- `/Users/efebarandurmaz/sardis`

Several neighbor repos have dirty worktrees. Treat them as read-only.

## Source of Truth Docs

Read these first:

- `docs/inspection/fides-report.md`
- `docs/inspection/agit-report.md`
- `docs/inspection/osp-report.md`
- `docs/inspection/oaps-report.md`
- `docs/inspection/sardis-report.md`
- `docs/inspection/cross-repo-primitive-map.md`
- `docs/architecture/fides-v2-agent-trust-fabric.md`
- `docs/architecture/gap-analysis.md`
- `docs/architecture/implementation-plan.md`

## Hard Constraints

- TypeScript/Node is the primary implementation.
- Rust is adapter-ready only; do not require Rust for first working v2.
- OAPS concepts are ported into FIDES-owned runtime types.
- Do not add `@oaps/core` as a runtime dependency.
- Sardis contributes generic patterns only.
- Payment-specific execution remains in Sardis.
- Effect may be used internally later, but protocol objects and public schemas are framework-agnostic.
- Public SDK APIs are Promise-based.
- Use one canonical signing model for all signed protocol objects.
- DHT pointers are discovery hints only, not trust roots.
- Relay presence is not trust.

## Implementation Order

Follow `docs/architecture/implementation-plan.md`.

Current next steps after docs:

1. Commit docs:
   - `docs: add fides v2 inspection reports`
   - `docs: add fides v2 architecture plan`
2. Milestone 1:
   - protocol constants,
   - `ErrorEnvelope`,
   - `VersionNegotiationRecord`,
   - base signed protocol object types,
   - canonical signing tests.
3. Milestone 2:
   - identity v2 hardening and real Ed25519 identity issuance.
4. Milestone 3:
   - signed AgentCards and capability ontology.

## Current Repo Shape

Important packages:

- `packages/core`
- `packages/evidence`
- `packages/runtime`
- `packages/discovery`
- `packages/policy`
- `packages/guard`
- `packages/sdk`
- `packages/cli`
- `packages/shared`

Important services:

- `services/agentd`
- `services/discovery`
- `services/trust-graph`
- `services/registry`
- `services/relay`
- `services/policy-engine`
- `services/platform-api`

Important commands:

```bash
pnpm install
pnpm build
pnpm typecheck
pnpm test
pnpm verify
pnpm --filter @fides/core test
pnpm --filter @fides/discovery test
pnpm --filter @fides/agentd test
```

Use targeted package tests after small milestones. Use broader `pnpm test` / `pnpm verify` after integration.

## Coding Rules

- Run `git status --short --branch` before edits.
- Use `apply_patch` for manual edits.
- Do not revert user work.
- Keep commits atomic.
- Inspect diffs before committing.
- Add focused tests for every behavioral change.
- Report failing tests honestly.
- Avoid new dependencies unless justified.

## Security Rules

- Fail closed for invalid signatures, active revocations, broken evidence chains, expired sessions, and kill-switch hits.
- Default evidence privacy to hash-only or redacted for sensitive input/output.
- Policy evaluation happens before invocation/execution/signing where applicable.
- No raw secrets, private keys, credentials, or sensitive payment data in logs.
- DHT and relay cannot grant authority.
- Trust score is only an input to policy.

## Cross-Repo Boundaries

AGIT:

- Use as evidence/hash/lineage/Rust-adapter prior art.
- Do not import its FIDES adapters as protocol canon.

OAPS:

- Port semantic concepts: ActorRef, ActorCard, DelegationToken, Mandate, ApprovalRequest, ApprovalDecision, EvidenceEvent, versioning, errors.
- Do not depend on `@oaps/core`.

OSP:

- Use for registry/service lifecycle adapter semantics: discover, provision, rotate, deprovision.
- Do not make OSP service lifecycle FIDES core authority.

Sardis:

- Use generic patterns: policy-before-execution, approvals, kill switch, high-risk action handling, evidence, mandate-chain abstraction.
- Keep stablecoins, MPC wallets, rails, merchants, compliance, spending limits, and payment execution in Sardis.

## First 30 Minutes Checklist

1. Run:

```bash
git status --short --branch
git log --oneline -n 10
pnpm --filter @fides/core test
```

2. Read:

```bash
sed -n '1,220p' docs/architecture/implementation-plan.md
sed -n '1,220p' docs/architecture/gap-analysis.md
sed -n '1,220p' packages/core/src/canonical-signer.ts
sed -n '1,220p' packages/core/src/identity.ts
sed -n '1,220p' packages/core/src/agent-card.ts
```

3. Start Milestone 1 only after confirming docs are committed.

## Completion Reporting

When stopping, report:

- summary,
- files changed,
- commits created,
- verification run,
- risks/follow-ups.

Do not say done unless:

- docs exist,
- core packages build,
- tests/typecheck status is reported,
- demo status is reported,
- blockers are documented.
