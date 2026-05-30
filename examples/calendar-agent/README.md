# Calendar Agent

Runnable FIDES v2 example agent for `calendar.schedule`.

This example demonstrates local agent identity, signed AgentCard creation, local
discovery registration, scoped delegation, policy evaluation, hash-chained
evidence, and pre-execution guard evaluation. Discovery remains candidate-only;
authority still requires policy and a scoped grant before invocation.

```bash
pnpm exec tsx examples/calendar-agent/index.ts
```

The legacy wrapper remains available:

```bash
pnpm exec tsx examples/calendar-agent.ts
```
