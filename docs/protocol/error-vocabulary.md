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
- `IDENTITY_NOT_FOUND`
- `AGENT_CARD_INVALID_SIGNATURE`
- `AGENT_CARD_EXPIRED`
- `AGENT_CARD_NOT_FOUND`
- `AGENT_NOT_REGISTERED`
- `CAPABILITY_NOT_FOUND`
- `TRUST_BELOW_THRESHOLD`
- `POLICY_DENIED`
- `APPROVAL_REQUIRED`
- `APPROVAL_NOT_FOUND`
- `SESSION_EXPIRED`
- `SESSION_NOT_FOUND`
- `ATTESTATION_INVALID`
- `ATTESTATION_NOT_FOUND`
- `DHT_POINTER_TAMPERED`
- `EVIDENCE_CHAIN_BROKEN`
- `EVIDENCE_EVENT_NOT_FOUND`
- `EVIDENCE_PRIVACY_MODE_INVALID`
- `REVOCATION_ACTIVE`
- `REVOCATION_NOT_FOUND`
- `INCIDENT_ACTIVE`
- `INCIDENT_NOT_FOUND`
- `KILL_SWITCH_ACTIVE`
- `KILL_SWITCH_RULE_NOT_FOUND`
- `VERSION_INCOMPATIBLE`
- `REQUEST_INVALID`

Root `agentd` authority-critical failures return this envelope shape on the
`error` field for session issuance, invocation failures, approval lifecycle,
kill switch, revocation, incident, and evidence ledger failures. Policy-blocked
session issuance maps kill switch, revocation, approval-required, and generic
policy denial states to stable machine codes while preserving the full
`policy.reason_codes` list in `error.details`.

Root local API validation failures use `REQUEST_INVALID` unless the invalid
payload belongs to a more specific protocol family, such as `INCIDENT_INVALID`
or `EVIDENCE_PRIVACY_MODE_INVALID`. Missing root local resources use the
resource-specific `*_NOT_FOUND` codes so SDKs and CLI clients do not need to
parse human-readable strings.

The CLI preserves typed root `agentd` failures when an HTTP response includes
an `ErrorEnvelope`, printing the stable code with the message, for example
`[POLICY_DENIED] Policy denied the request`.
