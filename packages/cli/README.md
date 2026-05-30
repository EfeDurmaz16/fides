# @fides/cli

Command-line tools for the FIDES v2 Agent Trust Fabric.

The CLI exposes local-first `agentd` workflows for identity, attestations,
AgentCards, discovery, trust, reputation, policy, approvals, kill switches,
delegation, sessions, invocation, evidence, revocation, incidents, registry,
relay, DHT, demos, and adversarial simulation.

Discovery commands return candidate records only. They do not grant invocation
authority. Capability execution must go through policy evaluation and a scoped
`SessionGrant`.

## Installation

```bash
npm install -g @fides/cli
```

From the monorepo checkout:

```bash
pnpm agentd <command>
```

Use `pnpm --silent agentd ... --json` when piping JSON output to another tool,
because pnpm prints script banners by default.

## Usage

```bash
agentd identity create --type principal --name "Demo Principal" --agentd-url http://localhost:7345
agentd identity create --type publisher --name "Demo Publisher" --agentd-url http://localhost:7345
agentd identity create --type agent --name "Invoice Agent" --agentd-url http://localhost:7345
agentd identity list --agentd-url http://localhost:7345

agentd attest github --identity did:fides:publisher --handle fides-dev --agentd-url http://localhost:7345

agentd card create --did did:fides:invoice-agent --name "Invoice Agent" --capabilities '[{"id":"invoice.reconcile","riskLevel":"medium","requiredScopes":["invoice:read"]}]' --agentd-url http://localhost:7345
agentd card sign did:fides:invoice-agent --agentd-url http://localhost:7345
agentd register did:fides:invoice-agent --agentd-url http://localhost:7345

agentd discover --capability invoice.reconcile --provider local --agentd-url http://localhost:7345
agentd dht publish --capability invoice.reconcile --agent-id did:fides:invoice-agent --agentd-url http://localhost:7345
agentd dht find --capability invoice.reconcile --agentd-url http://localhost:7345

agentd trust did:fides:invoice-agent --capability invoice.reconcile --agentd-url http://localhost:7345
agentd graph inspect did:fides:invoice-agent --agentd-url http://localhost:7345
agentd policy evaluate --agent did:fides:invoice-agent --capability invoice.reconcile --requested-scopes invoice:read --agentd-url http://localhost:7345
agentd session request did:fides:invoice-agent --capability invoice.reconcile --requested-scopes invoice:read --agentd-url http://localhost:7345
agentd invoke --session-id sess_... --input invoice.json --agentd-url http://localhost:7345

agentd evidence verify --agentd-url http://localhost:7345
agentd demo run --agentd-url http://localhost:7345
agentd simulate adversarial --agentd-url http://localhost:7345
agentd daemon status --agentd-url http://localhost:7345
```

Use `fides --help`, `agentd --help`, and command-specific `--help` output for
the full command surface. Both binaries point to the same CLI; `agentd` is the
preferred name for local authority, daemon, demo, and simulation workflows.

## License

MIT
