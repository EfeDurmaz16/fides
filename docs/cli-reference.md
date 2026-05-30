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
- `invoke`
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
agentd discover --capability invoice.reconcile --provider registry --supported-versions fides.v2.0 --required-versions fides.v2.0
agentd discover --capability invoice.reconcile --provider relay --supported-versions fides.v2.0
agentd discover --capability invoice.reconcile --provider dht
agentd discover --capability invoice.reconcile --all-providers
agentd demo run
agentd simulate adversarial
agentd registry start
agentd registry publish did:fides:...
agentd registry search --capability invoice.reconcile --supported-versions fides.v2.0
agentd relay start
agentd relay register did:fides:...
agentd relay discover --capability invoice.reconcile --supported-versions fides.v2.0
agentd dht publish --capability invoice.reconcile --agent-id did:fides:...
agentd dht find --capability invoice.reconcile
agentd invoke did:fides:... --capability invoice.reconcile --input invoice.json --requested-scopes invoice:read
agentd invoke --session-id sess_... --input invoice.json
agentd invoke --dry-run did:fides:... --capability payments.prepare --input payment.json
agentd evidence verify
agentd daemon status
```

Local identity files are stored under `~/.fides/identities` by default. Set
`FIDES_HOME=/path/to/workdir` to isolate local CLI state for demos or tests.
`identity show` and `identity list` do not print private keys; private keys stay
inside the local identity file.

`discover --capability` targets local `agentd` capability discovery. Use
`--provider local`, `well-known`, `registry`, `relay`, `dht`, or
`--all-providers` to choose the provider surface. These commands return
candidates, registry records, relay presence records, or DHT pointers only;
they do not grant invocation authority. Use `--supported-versions` and
`--required-versions` to send protocol compatibility constraints to provider
discovery endpoints.

`registry`, `relay`, and `dht` commands target local `agentd` discovery
surfaces by default. They expose provider-specific publish/start/search
operations and keep authority separate from discovery. `registry search` and
`relay discover` also accept protocol version constraints. `dht publish` can
publish an external pointer from an AgentCard path/URL, or publish a signed
local pointer without a URL by passing `--agent-id` or `--agent-card-id` with
`--capability`.

`invoke` always goes through the authority path. With `--session-id`, it calls
`POST /invoke` directly. With `<agent-id> --capability`, it first requests a
policy-checked `SessionGrant` from `POST /sessions`, then invokes that session.
Input defaults to `{}` and can be supplied with `--input` or `--input-json`.
Use `--dry-run` to request dry-run execution; discovery is never treated as
authority by this command.

`daemon status` calls `GET /health` and prints upstream checks, the authority
store, and the root v2 local state store. When SQLite local state is enabled,
the status output includes the SQLite path used for the daemon snapshot.
