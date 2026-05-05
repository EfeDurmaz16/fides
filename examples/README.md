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
# or
npx tsx examples/demo.ts
```

## Example Agents

Each example is a self-contained script that demonstrates specific FIDES concepts.
Run any example with:

```bash
npx tsx examples/<name>.ts
```

### calendar-agent.ts

Calendar management agent demonstrating identity creation, policy evaluation, and evidence recording.

**Demonstrates:**
- Identity creation and AgentCard publishing
- Calendar capabilities (create, list, delete) with risk classification
- Local discovery registration and resolution
- Delegation from user to agent with constraints
- Policy evaluation (allow + deny scenarios)
- Evidence chain with Merkle root verification
- Guard decision engine (good agent + kill switch scenarios)

```bash
npx tsx examples/calendar-agent.ts
```

### invoice-agent.ts

Invoice processing agent demonstrating financial risk classification and delegation chains.

**Demonstrates:**
- Identity creation (agent + finance manager + CFO)
- Invoice capabilities (create, approve, list) with high-risk classification
- Delegation with financial constraints (max spend, allowed contexts)
- Chain of authority (CFO + Finance Manager delegating to same agent)
- Policy evaluation with all decision types (allow / approve-required / deny / dry-run)
- Evidence chain for financial audit trail
- Guard decision engine (good trust + low trust scenarios)

```bash
npx tsx examples/invoice-agent.ts
```

### payment-agent.ts

Payment processing agent demonstrating critical risk capabilities and kill switch operations.

**Demonstrates:**
- Identity creation (agent + merchant + customer)
- Payment capabilities (charge, refund, status) with critical risk classification
- Keyword-based risk detection (payment keywords → critical)
- Delegation with spending constraints
- Fraud detection policies (fraud score, transaction velocity)
- Kill switch engagement, global kill, and recovery
- Evidence chain for payment audit trail
- Guard decision engine (good / killed / bad trust scenarios)

```bash
npx tsx examples/payment-agent.ts
```

### requester-agent.ts

Agent that discovers and invokes other agents, demonstrating the full trust fabric flow.

**Demonstrates:**
- Identity creation for a requester/orchestrator agent
- Multiple service provider AgentCards (calendar, payment, invoice)
- Local discovery registration, resolution, and listing
- User delegation to requester with multi-capability scope
- Trust score checking against provider minimum thresholds
- Full flow: discover → check trust → evaluate guard → invoke
- Evidence chain for multi-agent interaction
- Capability risk classification across all providers

```bash
npx tsx examples/requester-agent.ts
```

## End-to-End Flow

1. Agent A creates identity and AgentCard
2. Agent B discovers Agent A via well-known or registry
3. Agent B creates trust attestation for Agent A
4. Agent B delegates capability to Agent C
5. Agent C invokes capability with delegation token
6. Policy engine evaluates request
7. Evidence event is recorded
8. Runtime attestation verified (for high-risk)

## Packages Used

| Package | Purpose |
|---------|---------|
| `@fides/core` | Identity, AgentCard, delegation, capability risk |
| `@fides/policy` | Policy evaluation, pre-execution pipeline |
| `@fides/evidence` | Hash chain, Merkle root, privacy levels |
| `@fides/runtime` | TEE attestation, kill switch |
| `@fides/guard` | Unified decision engine |
| `@fides/discovery` | Local discovery provider |
