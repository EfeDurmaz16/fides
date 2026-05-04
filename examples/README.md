# FIDES v2 Examples

## Quick Start

```bash
# Initialize an agent identity
fides init

# Create an AgentCard
fides card create --did did:fides:myagent --name "My Agent"

# Evaluate a policy
fides policy evaluate --bundle ./policy.json --context '{"role":"admin"}'

# Start the local daemon
fides daemon start
```

## Demo Script

Run the full demo:

```bash
pnpm demo
```

## Example Agents

- `calendar-agent/` — Calendar management agent
- `invoice-agent/` — Invoice processing agent
- `payment-agent/` — Payment execution agent (high-risk)
- `requester-agent/` — Agent that discovers and invokes other agents

## End-to-End Flow

1. Agent A creates identity and AgentCard
2. Agent B discovers Agent A via well-known or registry
3. Agent B creates trust attestation for Agent A
4. Agent B delegates capability to Agent C
5. Agent C invokes capability with delegation token
6. Policy engine evaluates request
7. Evidence event is recorded
8. Runtime attestation verified (for high-risk)
