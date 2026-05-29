# Policy Engine

FIDES enforces policy before execution.

Current implementation anchors:

- `packages/policy/src/index.ts`
- `packages/guard/src/index.ts`

## Decisions

- `allow`
- `deny`
- `require_approval`
- `dry_run_only`
- `scope_limit`
- `risk_limit`

## Inputs

Policy evaluates principal, requester agent, target agent, capability, trust result, reputation result, runtime attestation, revocation status, incidents, kill switch rules, scopes, and constraints.

Every decision returns machine-readable reasons, human-readable reasons, required controls, and evidence refs. No decision should be only a boolean.
