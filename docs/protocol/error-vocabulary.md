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

The core vocabulary includes identity, AgentCard, capability, trust, policy, approval, session, attestation, DHT, evidence, revocation, kill switch, and version errors.

Examples:

- `IDENTITY_INVALID_SIGNATURE`
- `AGENT_CARD_EXPIRED`
- `CAPABILITY_NOT_FOUND`
- `TRUST_BELOW_THRESHOLD`
- `POLICY_DENIED`
- `APPROVAL_REQUIRED`
- `SESSION_EXPIRED`
- `ATTESTATION_INVALID`
- `DHT_POINTER_TAMPERED`
- `EVIDENCE_CHAIN_BROKEN`
- `REVOCATION_ACTIVE`
- `KILL_SWITCH_ACTIVE`
- `VERSION_INCOMPATIBLE`
