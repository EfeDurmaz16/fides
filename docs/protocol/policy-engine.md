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

## PolicyDecision object

`packages/policy/src/index.ts` emits `fides.policy.decision.v1` records as canonical-hashable protocol objects:

- `id`
- `issuer`
- `subject`
- `principal_id`
- `requester_agent_id`
- `target_agent_id`
- `capability`
- `decision`
- `reason_codes`
- `machine_reasons`
- `human_reasons`
- `required_controls`
- `evidence_refs`
- `issued_at`
- `evaluated_at`
- `payload_hash`

The `payload_hash` is computed with the shared FIDES canonical JSON digest. A policy engine, daemon, or registry can wrap the decision with the canonical object signing model; downstream session grants and evidence events can then reference the exact policy decision hash.
