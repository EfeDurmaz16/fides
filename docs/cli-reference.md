# CLI Reference

The CLI package exposes both `fides` and `agentd` binary names.

Current implementation anchors:

- `packages/cli/src/index.ts`
- `packages/cli/src/commands/`

## Command Groups

- `init`
- `identity`
- `card`
- `discover`
- `trust`
- `policy`
- `session`
- `authorize`
- `runtime`
- `revoke`
- `incident`
- `killswitch`
- `relay`
- `dht`
- `evidence`
- `demo`
- `simulate`
- `daemon`

Example:

```bash
agentd demo run
agentd simulate adversarial
agentd dht find --capability invoice.reconcile
agentd evidence verify
```
