# @fides/cli

Command-line tools for the FIDES trust protocol.

The CLI wraps identity initialization, request signing and verification, discovery, AgentCard publishing, agentd authority operations, relay operations, and local daemon lifecycle commands.

## Installation

```bash
npm install -g @fides/cli
```

## Usage

```bash
fides init --name payment-agent
fides identity create --type agent --name invoice-agent
fides identity list
fides identity show did:fides:...
fides sign https://api.example.com/data --method GET
fides card publish agent-card.json --registry-url http://localhost:7346
agentd demo run --agentd-url http://localhost:7345
agentd simulate adversarial --agentd-url http://localhost:7345
agentd daemon status --agentd-url http://localhost:7345
```

Use `fides --help`, `agentd --help`, and command-specific `--help` output for the full command surface. Both binaries point to the same CLI; `agentd` is the preferred name for local authority, daemon, demo, and simulation workflows.

## License

MIT
