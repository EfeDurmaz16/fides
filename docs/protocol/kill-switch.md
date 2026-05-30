# Kill Switch

Kill switch rules override normal trust and policy evaluation.

Current implementation anchors:

- `packages/core/src/approval.ts`
- `packages/runtime/src/index.ts`
- `services/agentd/src/index.ts`

## Targets

- global
- agent
- publisher
- capability
- session
- principal
- risk class

Kill switch checks should run before policy grants or invocation execution.

## Evidence

The local root daemon appends a hash-only `kill_switch.triggered` event when a
kill switch rule is created. The event records issuer, target type, target,
enabled state, and reason metadata so policy denials caused by kill switches
can be audited later.
