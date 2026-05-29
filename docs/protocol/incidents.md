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
