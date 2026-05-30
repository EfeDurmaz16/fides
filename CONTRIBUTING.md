# Contributing to FIDES

FIDES is a TS-first Agent Trust Fabric. Contributions should preserve the
protocol invariants that make discovery, trust, authority, policy, and evidence
separate layers.

## Before You Start

Use Node.js 22+ and pnpm 10.

```bash
pnpm install
pnpm verify
```

For local daemon and CLI smoke testing:

```bash
pnpm smoke:agentd
```

## Architecture Rules

- Discovery must never grant authority. Discovery results are candidates only.
- Identity must never imply trust. A valid DID can still be low trust.
- Trust scores must never imply permission. Policy decisions issue authority.
- Policy must run before execution, signing, or external side effects.
- Evidence must be privacy-aware. Prefer hash-only or redacted inputs/outputs.
- Signed protocol objects must use the shared canonical signing model.
- Public protocol objects and SDK APIs must stay framework-agnostic and
  Promise-based.
- FIDES is TS-first and Rust adapter-ready. Do not make Rust required for the
  first working path.
- OAPS concepts should be ported into FIDES-owned runtime types rather than
  added as a runtime dependency.
- Sardis-specific payment execution belongs in Sardis. FIDES owns generic
  authority, trust, policy, delegation, and evidence primitives.

## Code Changes

Keep changes scoped and atomic. Prefer the existing package boundaries and
helpers before introducing new abstractions.

Use focused tests for the changed package, then run the relevant repository
gate:

```bash
pnpm --filter @fides/core test
pnpm --filter @fides/cli test
pnpm api:audit
pnpm cli:audit
pnpm examples:audit
pnpm package:hygiene
pnpm package:packcheck
pnpm verify
```

For public package changes, keep package metadata, README, LICENSE, exports,
and dry-run package contents aligned with `scripts/public-packages.mjs`.

## Security-Sensitive Work

Treat identity, signatures, delegation, sessions, policy, evidence, revocation,
incidents, kill switches, API keys, and storage as security-sensitive.

Look for:

- signature or issuer-binding bypasses
- replay and nonce mistakes
- policy-after-execution ordering bugs
- authority granted by discovery, registry, relay, or DHT paths
- raw sensitive input/output leaking into evidence
- private key, token, or API key exposure
- revocation, incident, or kill switch bypasses

Do not log secrets or private keys. Use stable typed `ErrorEnvelope` responses
for public API/SDK/CLI failure surfaces.

## Documentation

Update docs when behavior changes. Prefer concrete flows and file paths over
abstract claims.

Common docs to update:

- `README.md`
- `docs/status/fides-v2-implementation-status.md`
- `docs/api-reference.md`
- `docs/cli-reference.md`
- `docs/sdk-reference.md`
- `docs/protocol/*`
- `docs/api/agentd.yaml`

If an implementation is local mock, adapter-ready, or spec-complete rather than
production-like, say so explicitly.

## Pull Requests

Before opening a PR:

1. Rebase or merge current `main`.
2. Run `pnpm verify`.
3. Run `pnpm smoke:agentd` for CLI/API/daemon changes.
4. Include what changed, what was verified, and any known limitations.
5. Keep commits atomic and descriptive.

Do not claim production readiness for local mock registry, relay, DHT,
federation, or TEE surfaces.
