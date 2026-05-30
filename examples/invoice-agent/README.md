# Invoice Agent

Runnable FIDES v2 example agent for `invoice.reconcile`.

This example demonstrates medium-risk capability handling, delegation
constraints, policy decisions, evidence records, and guard evaluation for an
invoice workflow. It models discovery as a candidate source, not an authority
grant.

```bash
pnpm exec tsx examples/invoice-agent/index.ts
```

The legacy wrapper remains available:

```bash
pnpm exec tsx examples/invoice-agent.ts
```
