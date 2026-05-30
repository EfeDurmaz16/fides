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

Signed kill switch verification has two levels. `verifySignedKillSwitchRule`
checks the canonical Ed25519 proof. `verifySignedKillSwitchRuleIssuer`
additionally requires `proof.verificationMethod` to equal the rule `issuer`.
Authority paths should use the issuer-bound verifier so a valid signature from
another DID cannot activate or disable emergency controls for the stated issuer.

## Evidence

The local root daemon appends a hash-only `kill_switch.triggered` event when a
kill switch rule is created. The event records issuer, target type, target,
enabled state, and reason metadata so policy denials caused by kill switches
can be audited later.
