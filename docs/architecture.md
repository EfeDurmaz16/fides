# FIDES Architecture

FIDES v2 is a local-first Agent Trust Fabric for autonomous agent systems. It
is not an agent app store, a naive directory, or a global popularity graph.

The current architecture is defined in
[`docs/architecture/fides-v2-agent-trust-fabric.md`](./architecture/fides-v2-agent-trust-fabric.md).

## Core Invariants

- Discovery never equals authority.
- Identity never equals trust.
- Trust score never equals permission.
- Domain ownership is optional and is only one trust anchor.
- Reputation is capability-specific.
- Policy is evaluated before execution.
- Authority is scoped through delegation tokens and session grants.
- Evidence is append-only, hash-chained, and privacy-aware.
- Signed protocol objects use one canonical signing model.
- Public SDK APIs are Promise-based.

## Layer Model

FIDES v2 is organized into these layers:

1. Identity
2. Attestation
3. Agent metadata
4. Discovery
5. Trust
6. Reputation
7. Policy
8. Delegation
9. Invocation
10. Evidence
11. Revocation
12. Incident
13. Registry
14. Transport
15. Runtime
16. Developer
17. Interop

## Local Authority Path

The main local authority path is:

1. Create agent, publisher, and principal identities.
2. Add optional trust anchors such as GitHub, email, package registry, domain,
   wallet, passkey, organization invitation, runtime attestation, build
   attestation, or peer attestation.
3. Create and sign an AgentCard with capability descriptors.
4. Register or publish the AgentCard through local, well-known, registry, relay,
   DHT, or federation-ready discovery providers.
5. Treat discovered agents as candidates only.
6. Verify signed records and AgentCards.
7. Negotiate protocol versions.
8. Evaluate capability-specific trust and reputation.
9. Evaluate policy with revocations, incidents, kill switches, runtime
   attestations, scopes, constraints, and requested capability.
10. Issue a scoped SessionGrant only when policy allows it.
11. Invoke through the session authority path.
12. Emit privacy-aware EvidenceEvents and verify the evidence hash chain.

## Primary Runtime Surface

`services/agentd` is the primary local HTTP API for the v2 prototype. It exposes
identity, attestations, AgentCards, agent registration, discovery, trust,
reputation, policy, approvals, delegation, sessions, invocation, evidence,
revocation, incidents, kill switch, registry, relay, DHT, demo, and adversarial
simulation endpoints.

The CLI and SDK should prefer the v2 `agentd` surface:

- CLI: `agentd ...`
- SDK: `FidesClient({ daemonUrl: "http://localhost:7345" })`

Older standalone discovery and trust graph services may remain as compatibility
or migration surfaces, but they are not the v2 authority model. Discovery
providers return candidates; policy and SessionGrants grant authority.

## Package Map

| Package | Role |
|---------|------|
| `@fides/core` | Protocol objects, canonical signing, identities, capabilities, sessions, errors, version negotiation |
| `@fides/crypto` | Ed25519, hashing, canonical JSON, signatures |
| `@fides/identity` | Identity v2 types and trust anchors |
| `@fides/attestations` | Attestation provider interfaces and local/mock attestations |
| `@fides/cards` | AgentCards, capability descriptors, ontology, risk taxonomy |
| `@fides/discovery` | Provider interfaces and discovery orchestration |
| `@fides/dht` | DHT pointer records, simulator, adapter boundary |
| `@fides/relay` | Relay client/server protocol and NAT-hidden discovery hints |
| `@fides/registry` | Registry records, public/private modes, federation-ready peering |
| `@fides/trust` | Trust graph, trust scoring, trust explanations |
| `@fides/reputation` | Capability-specific reputation |
| `@fides/policy` | Policy-before-execution evaluator, approvals, guardrails, kill switch rules |
| `@fides/delegation` | DelegationToken and SessionGrant authority primitives |
| `@fides/invocation` | Capability invocation, validation, dry-run and approval-gated execution |
| `@fides/evidence` | Hash-chained EvidenceEvents, verification, redaction, export |
| `@fides/runtime-effect` | Optional internal Effect orchestration; protocol objects remain framework-agnostic |
| `@fides/sdk` | Promise-based TypeScript SDK |
| `@fides/cli` | `agentd` CLI |

Some package boundaries are still being consolidated in the current monorepo.
The target structure is tracked in
[`docs/architecture/implementation-plan.md`](./architecture/implementation-plan.md).

## Further Reading

- [`docs/getting-started.md`](./getting-started.md)
- [`docs/architecture/fides-v2-agent-trust-fabric.md`](./architecture/fides-v2-agent-trust-fabric.md)
- [`docs/architecture/gap-analysis.md`](./architecture/gap-analysis.md)
- [`docs/protocol/canonical-object-signing.md`](./protocol/canonical-object-signing.md)
- [`docs/protocol/discovery.md`](./protocol/discovery.md)
- [`docs/protocol/policy-engine.md`](./protocol/policy-engine.md)
- [`docs/protocol/delegation-and-sessions.md`](./protocol/delegation-and-sessions.md)
- [`docs/protocol/evidence-ledger.md`](./protocol/evidence-ledger.md)
- [`docs/cli-reference.md`](./cli-reference.md)
- [`docs/sdk-reference.md`](./sdk-reference.md)
