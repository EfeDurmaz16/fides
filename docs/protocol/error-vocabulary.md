# Error Vocabulary

FIDES v2 exposes stable typed errors across CLI, API, SDK, and protocol flows.

Current implementation anchor:

- `packages/core/src/errors.ts`

## Error Envelope

Each error includes:

- `code`
- `category`
- `severity`
- `retryable`
- `message`
- `details`

## Required Codes

The core vocabulary includes identity, AgentCard, capability, trust, policy,
approval, session, attestation, DHT, evidence, revocation, incident, kill
switch, and version errors.

Examples:

- `IDENTITY_INVALID_SIGNATURE`
- `IDENTITY_KEY_UNBOUND`
- `AGENT_CARD_INVALID_SIGNATURE`
- `AGENT_CARD_EXPIRED`
- `CAPABILITY_NOT_FOUND`
- `TRUST_BELOW_THRESHOLD`
- `POLICY_DENIED`
- `APPROVAL_REQUIRED`
- `SESSION_EXPIRED`
- `SESSION_NOT_FOUND`
- `ATTESTATION_INVALID`
- `DHT_POINTER_TAMPERED`
- `EVIDENCE_CHAIN_BROKEN`
- `REVOCATION_ACTIVE`
- `INCIDENT_ACTIVE`
- `KILL_SWITCH_ACTIVE`
- `VERSION_INCOMPATIBLE`

Root `agentd` authority-critical failures return this envelope shape on the
`error` field for session issuance and invocation failures. Policy-blocked
session issuance maps kill switch, revocation, approval-required, and generic
policy denial states to stable machine codes while preserving the full
`policy.reason_codes` list in `error.details`.
