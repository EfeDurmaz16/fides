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

## Evidence

The local root daemon appends a hash-only `incident.reported` event when an
incident is reported. The event records reporter, target agent, severity,
category, and penalty metadata while preserving the evidence privacy default.
