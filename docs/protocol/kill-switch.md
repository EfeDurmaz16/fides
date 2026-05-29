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
