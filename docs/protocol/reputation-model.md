# Reputation Model

Reputation is capability-specific. Reputation for `calendar.schedule` must not imply reputation for `payments.execute`.

Current implementation anchor:

- `packages/core/src/reputation.ts`

## Signals

- canonical `ReputationRecord` id, issuer, subject, and payload hash
- capability-specific success rate
- observed volume confidence
- publisher weight
- incident penalty
- context boundary penalty

## Boundaries

Reputation may also be principal-specific where possible. Context laundering should be penalized when a reputation signal is reused outside the capability or principal context where it was earned.

`payload_hash` is computed over the machine-readable reputation record, including
capability and optional principal scope. This lets trust and policy cite an
exact reputation snapshot without allowing reputation to become permission.
