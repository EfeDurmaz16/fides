# Incidents

Incidents record security, safety, and policy failures that affect trust and policy.

Current implementation anchor:

- `packages/core/src/revocation.ts`

## Categories

- `policy_violation`
- `data_exfiltration`
- `malicious_output`
- `sandbox_escape`
- `unauthorized_action`
- `prompt_injection_failure`
- `payment_error`
- `suspicious_behavior`

Incidents carry severity, evidence refs, resolution status, trust penalty, and reputation penalty.

`IncidentRecordV2` uses the shared protocol object envelope: `id`, `issuer`,
`subject`, timestamps, and `payload_hash`. `issuer` is the reporter and
`subject` is the affected agent id. Resolution changes recompute the payload
hash so trust and policy can cite the exact incident state they evaluated.

Signed incident verification has two levels. `verifySignedIncidentRecordV2`
checks the canonical Ed25519 proof. `verifySignedIncidentRecordV2Issuer`
additionally requires `proof.verificationMethod` to equal the reporter/issuer.
Trust and policy ingestion paths should use the issuer-bound verifier before an
incident can affect trust, reputation, or authorization decisions.

## Evidence

The local root daemon appends a hash-only `incident.reported` event when an
incident is reported. The event records reporter, target agent, severity,
category, and penalty metadata while preserving the evidence privacy default.
