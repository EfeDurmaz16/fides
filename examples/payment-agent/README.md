# Payment Agent

Runnable FIDES v2 example agent for `payments.prepare` and
`payments.execute`.

Generic FIDES only models payment preparation and dry-run authority flows.
Payment execution remains Sardis-specific. This example demonstrates critical
risk classification, approval/attestation-aware policy, kill-switch behavior,
and evidence generation without turning discovery into permission.

```bash
pnpm exec tsx examples/payment-agent/index.ts
```

The legacy wrapper remains available:

```bash
pnpm exec tsx examples/payment-agent.ts
```
