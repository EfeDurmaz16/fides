# Full Demo

This directory captures the target full-demo contract for FIDES v2.

Run the manifest:

```bash
pnpm exec tsx examples/full-demo/run.ts
```

Run the local daemon prototype endpoint:

```bash
agentd demo run
```

The current manifest is spec-complete. The daemon endpoint is a working local prototype. The remaining hardening step is to execute every manifest step against real local agentd state and evidence events.
