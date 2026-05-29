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
- `registry`
- `relay`
- `dht`
- `evidence`
- `demo`
- `simulate`
- `daemon`

Example:

```bash
agentd identity create --type agent --name "Invoice Agent"
agentd identity create --type publisher --name "Acme Agents"
agentd identity list
agentd identity show did:fides:...
agentd identity domain challenge example.com did:fides:...
agentd identity domain verify example.com did:fides:...
agentd demo run
agentd simulate adversarial
agentd registry start
agentd registry publish did:fides:...
agentd registry search --capability invoice.reconcile
agentd relay start
agentd relay register did:fides:...
agentd relay discover --capability invoice.reconcile
agentd dht find --capability invoice.reconcile
agentd evidence verify
```

Local identity files are stored under `~/.fides/identities` by default. Set
`FIDES_HOME=/path/to/workdir` to isolate local CLI state for demos or tests.
`identity show` and `identity list` do not print private keys; private keys stay
inside the local identity file.

`registry`, `relay`, and `dht` commands target local `agentd` discovery
surfaces by default. They return registry records, relay presence records, or
DHT pointers only; they do not grant invocation authority.
