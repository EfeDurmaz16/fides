# ADR: Sardis Patterns Only

## Status

Accepted.

## Decision

Only generic Sardis patterns move into FIDES: policy-before-execution, guardrails, evidence, approval, kill switch, high-risk handling, and mandate-chain abstraction.

Payment-specific domain remains in Sardis.

## Consequences

- FIDES owns generic trust, authority, policy, delegation, attestation, and evidence.
- Sardis owns stablecoins, MPC wallets, payment rails, merchants, compliance, spending limits, and payment-specific mandates.
