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
agentd discover "reconcile invoices" --capability invoice.reconcile --provider local
agentd discover --capability invoice.reconcile --provider registry
agentd discover --capability invoice.reconcile --provider relay
agentd discover --capability invoice.reconcile --provider dht
agentd discover --capability invoice.reconcile --all-providers
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

`discover --capability` targets local `agentd` capability discovery. Use
`--provider local`, `well-known`, `registry`, `relay`, `dht`, or
`--all-providers` to choose the provider surface. These commands return
candidates, registry records, relay presence records, or DHT pointers only;
they do not grant invocation authority.

`registry`, `relay`, and `dht` commands target local `agentd` discovery
surfaces by default. They expose provider-specific publish/start/search
operations and keep authority separate from discovery.
