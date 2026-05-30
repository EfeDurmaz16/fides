# CLI Reference

The CLI package exposes both `fides` and `agentd` binary names.

Current implementation anchors:

- `packages/cli/src/index.ts`
- `packages/cli/src/commands/`

## Command Groups

- `init`
- `identity`
- `card`
- `register`
- `agents`
- `discover`
- `trust`
- `policy`
- `session`
- `invoke`
- `authorize`
- `attest`
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
agentd register card_...
agentd agents list
agentd agents inspect did:fides:...
agentd discover "reconcile invoices" --capability invoice.reconcile --provider local
agentd discover --capability invoice.reconcile --provider registry --supported-versions fides.v2.0 --required-versions fides.v2.0
agentd discover --capability invoice.reconcile --provider relay --supported-versions fides.v2.0
agentd discover --capability invoice.reconcile --provider dht
agentd discover --capability invoice.reconcile --provider federation
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
agentd session request did:fides:... --capability invoice.reconcile --requested-scopes invoice:read
agentd session verify sess_...
agentd attest runtime --agent did:fides:... --code-hash sha256:... --runtime-hash sha256:... --policy-hash sha256:...
agentd attest show att_...
agentd attest verify att_...
agentd incident report did:fides:... --severity high --category unauthorized_action --description "policy bypass"
agentd incident list
agentd incident inspect inc_...
agentd incident resolve inc_...
agentd killswitch enable --capability payments.prepare --reason "incident response"
agentd killswitch list
agentd killswitch disable ks_...
agentd revoke agent did:fides:... --reason "disabled"
agentd revoke key key_... --reason "rotated"
agentd revoke card card_... --reason "expired"
agentd revoke session sess_... --reason "replay risk"
agentd revoke attestation att_... --reason "expired attestation"
agentd revoke list
agentd revoke inspect rev_...
agentd evidence verify
agentd evidence export --privacy-mode hash_only --no-metadata
agentd daemon status
```

Local identity files are stored under `~/.fides/identities` by default. Set
`FIDES_HOME=/path/to/workdir` to isolate local CLI state for demos or tests.
`identity show` and `identity list` do not print private keys; private keys stay
inside the local identity file.

`register` and `agents list/inspect` use the root v2 local agentd registration
endpoints. Registration records an AgentCard as a discovery candidate only; it
does not grant authority to invoke capabilities.

`discover --capability` targets local `agentd` capability discovery. Use
`--provider local`, `well-known`, `registry`, `relay`, `dht`, `federation`, or
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

`session request`, `session show`, and `session verify` use the root v2 local
agentd session endpoints. The older `session create` and `session revoke`
commands remain available for the legacy signed `DelegationToken` `/v1`
authority path.

`attest runtime/show/verify` use the root v2 local agentd runtime attestation
endpoints. Issuing or verifying an attestation emits evidence and does not
grant authority by itself. The older `runtime attest` command remains a local
MockTEE helper for standalone runtime package checks.

`incident report/list/inspect/resolve` use the root v2 incident endpoints by
default. Passing `--private-key-hex` keeps the legacy signed `/v1/incidents`
path available for compatibility with existing authority records.

`killswitch enable/list/disable` use root v2 kill switch rules. The older
`engage`, `disengage`, and `status` commands are local-file controls kept for
legacy demos; use the root v2 commands when testing policy-before-execution in
agentd.

`revoke agent/key/identity/card/capability/session/attestation/publisher`,
`revoke list`, and `revoke inspect` use root v2 revocation records. Passing
`--private-key-hex` to `revoke agent` keeps the legacy signed `/v1/revocations`
path available for compatibility.

`evidence export` defaults to the daemon's privacy-aware export behavior. Use
`--privacy-mode public`, `private`, `redacted`, or `hash_only` to request a
specific export view, and `--no-metadata` when exported evidence should omit
metadata fields. `hash-only` is accepted as a CLI alias for `hash_only`.

`daemon status` calls `GET /health` and prints upstream checks, the authority
store, and the root v2 local state store. When SQLite local state is enabled,
the status output includes the SQLite path used for the daemon snapshot.
