# Implementation Agent Prompt

This prompt is designed for a future coding agent to implement FIDES v2 / Agent Trust Fabric with atomic commits.

## Mission

Implement FIDES v2 as a full Agent Trust Fabric. The implementation must:

1. Build on the existing FIDES v1 codebase in `~/fides`
2. Port and adapt concepts from AGIT, OSP, OAPS, and Sardis as documented
3. Follow the architecture in `~/fides/docs/architecture/fides-v2-agent-trust-fabric.md`
4. Follow the implementation plan in `~/fides/docs/architecture/implementation-plan.md`
5. Close the gaps identified in `~/fides/docs/architecture/gap-analysis.md`
6. Use atomic commits with meaningful messages
7. Run tests and type checks where practical
8. Do not overwrite uncommitted user work

## Architecture Decisions (Non-Negotiable)

- **TS-first, Rust adapter-ready.** All new code is TypeScript. AGIT Rust core may be bridged later via adapters.
- **OAPS concepts are ported into FIDES, not imported as runtime dependencies.** OAPS remains the spec/source of semantic compatibility.
- **Sardis contributes generic patterns only:** policy-before-execution, guardrails, evidence ledger, approvals, kill switch, high-risk action handling. Payment-specific models stay in Sardis.
- **FIDES owns the generic authority/trust/evidence layer. Sardis owns the payment-specific authority model.**
- **Protocol objects, crypto, canonical JSON, signing primitives, and public schemas must remain framework-agnostic.**
- **Public SDK exposes Promise-based APIs, with optional Effect-native APIs later.**

## Package Structure

```
packages/
  @fides/sdk/          # Existing: identity, signing, trust, discovery client
  @fides/shared/       # Extended: types, constants, errors
  @fides/cli/          # Extended: CLI commands
  @fides/core/         # NEW: identity v2, AgentCard, CapabilityDescriptor,
  #                      DelegationToken, SessionGrant, PolicyBundle,
  #                      ApprovalRequest, ApprovalDecision, MandateChain,
  #                      canonical object signing, version negotiation
  @fides/discovery/    # NEW: discovery providers (local, well-known, registry,
  #                      relay, DHT), provider orchestration
  @fides/runtime/      # NEW: runtime attestation, TEE adapters, session grants,
  #                      kill switch
  @fides/evidence/     # NEW: evidence ledger, hash chain, Merkle proofs,
  #                      event streaming, privacy model
  @fides/policy/       # NEW: policy engine, risk taxonomy, guardrails,
  #                      pre-execution pipeline
services/
  discovery/           # Extended: identity + agent registry, well-known,
  #                      federation peering
  trust-graph/         # Extended: reputation v2, incident penalties,
  #                      novelty penalties, runtime safety score
  policy-engine/       # Full implementation: evaluate policies, approvals,
  #                      kill switch enforcement
  registry/            # NEW: hosted registry (public/private mode)
  relay/               # NEW: mock relay server for discovery
  agentd/              # NEW: local daemon (HTTP API, SDK proxy)
```

## Required Components

### 1. Canonical Object Signing

Every signed protocol object must use:

```typescript
interface SignedObject<T> {
  payload: T;
  proof: {
    type: "Ed25519Signature2024";
    created: string;
    verificationMethod: string; // DID
    proofPurpose: "assertionMethod" | "authentication" | "delegation" | "capabilityInvocation";
    canonicalizationAlgorithm: "https://fides.dev/canonical-json/v1";
    proofValue: string; // base58 signature
  };
}
```

Implementation:
- `packages/@fides/core/src/canonical-signer.ts`
- Deterministic JSON (sorted keys, no whitespace, explicit nulls)
- SHA-256 digest → Ed25519 sign
- `@noble/ed25519` for crypto

### 2. Identity v2

```typescript
interface AgentIdentity { did: string; publicKey: Uint8Array; keyType: "Ed25519"; createdAt: string; publisher?: PublisherIdentity; principal?: PrincipalIdentity; }
interface PublisherIdentity { did: string; name: string; domain?: string; verified: boolean; verificationMethod: "dns" | "github" | "email" | "manual"; }
interface PrincipalIdentity { did: string; type: "individual" | "organization" | "platform"; displayName: string; }
interface TrustAnchor { did: string; name: string; publicKey: Uint8Array; attestation: SignedObject<TrustAttestation>; }
```

### 3. AgentCard and CapabilityDescriptor

```typescript
interface AgentCard {
  id: string;
  identity: AgentIdentity;
  publisher?: PublisherIdentity;
  capabilities: CapabilityDescriptor[];
  endpoints: EndpointDescriptor[];
  policies: PolicyRequirement[];
  createdAt: string;
  updatedAt: string;
}

interface CapabilityDescriptor {
  id: string;
  name: string;
  description: string;
  inputSchema: JSONSchema;
  outputSchema: JSONSchema;
  riskLevel: "low" | "medium" | "high" | "critical";
  requiresApproval: boolean;
  requiresRuntimeAttestation: boolean;
}
```

### 4. Discovery Providers

Implement 5 providers:
- `LocalDiscoveryProvider` — mDNS-ready interface (stub acceptable)
- `WellKnownDiscoveryProvider` — HTTP `.well-known/fides.json`
- `RegistryDiscoveryProvider` — Hosted registry
- `RelayDiscoveryProvider` — Relay server (stub acceptable)
- `DHTDiscoveryProvider` — DHT pointers (stub acceptable)

`DiscoveryOrchestrator` tries providers in priority order.

### 5. Policy Engine

Port from OAPS `@oaps/policy`:

```typescript
interface PolicyBundle {
  id: string;
  version: string;
  rules: PolicyRule[];
  defaultAction: "allow" | "deny" | "approve-required";
}

interface PolicyRule {
  id: string;
  condition: PolicyExpression;
  action: "allow" | "deny" | "approve-required" | "dry-run";
  explanation: string;
}

interface PolicyExpression {
  operator: "eq" | "neq" | "lt" | "lte" | "gt" | "gte" | "in" | "all" | "any";
  field: string;
  value: unknown;
}
```

Add Sardis-inspired pre-execution pipeline with Allow/Warn/Block guards.

### 6. Delegation and Sessions

Port from OAPS `@oaps/core`:

```typescript
interface DelegationToken {
  id: string;
  delegator: string;
  delegatee: string;
  capabilities: string[];
  constraints: DelegationConstraint;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  audience?: string[];
  signature: string;
}

interface SessionGrant {
  id: string;
  token: DelegationToken;
  sessionKey: string;
  expiresAt: string;
  boundTo?: string;
}
```

### 7. Evidence Ledger

Merge OAPS `@oaps/evidence` + AGIT hash-chain semantics:

```typescript
interface EvidenceEvent {
  id: string;
  type: string;
  timestamp: string;
  actor: string;
  action: string;
  target?: string;
  payload: unknown;
  privacy: EvidencePrivacy;
  prevHash: string;
  hash: string;
  signature: string;
}

interface EvidencePrivacy {
  level: "public" | "private" | "redacted" | "hash-only";
  redactionKey?: string;
}
```

### 8. Runtime Attestation

```typescript
interface RuntimeAttestation {
  id: string;
  agentDid: string;
  provider: string;
  measurement: string;
  timestamp: string;
  expiresAt: string;
  evidence: unknown;
  signature: string;
}

interface TEEAdapter {
  readonly provider: string;
  attest(agentDid: string): Promise<RuntimeAttestation>;
  verify(attestation: RuntimeAttestation): Promise<boolean>;
}
```

Implement `MockTEEProvider`. Add adapter stubs for Nitro, SGX, SEV.

### 9. Kill Switch

Port concept from Sardis:

```typescript
interface KillSwitch {
  engage(target: KillSwitchTarget): void;
  disengage(target: KillSwitchTarget): void;
  isEngaged(target: KillSwitchTarget): boolean;
}

type KillSwitchTarget = { type: "global" } | { type: "agent"; did: string } | { type: "capability"; id: string } | { type: "principal"; did: string };
```

### 10. Adapter Interfaces

Create base adapter:

```typescript
interface ProtocolAdapter {
  readonly protocol: string;
  handshake(): Promise<void>;
  invoke(capability: string, params: unknown): Promise<unknown>;
}
```

Add stubs for: MCP, A2A, OAPS, OSP, AP2, x402, Sardis.

## Required CLI Commands

```
fides init                          # Initialize FIDES identity
fides identity create               # Create identity (agent, publisher, principal)
fides identity show                 # Show current identity
fides card create                   # Create and sign AgentCard
fides card verify <did>             # Verify AgentCard
fides capability add <name>         # Add capability to card
fides discover <did>                # Discover agent
fides trust attest <did>            # Create trust attestation
fides trust score <did>             # Get reputation score
fides delegate --to <did>           # Create delegation token
fides session grant --token <id>    # Create session grant
fides session revoke <id>           # Revoke session
fides policy evaluate               # Evaluate policy
fides policy explain                # Explain policy decision
fides evidence append               # Append evidence event
fides evidence verify               # Verify evidence chain
fides evidence export               # Export evidence
fides revoke <did>                  # Revoke agent
fides incident report               # Report incident
fides incident list                 # List incidents
fides runtime attest                # Create runtime attestation
fides runtime verify                # Verify runtime attestation
fides registry register             # Register with registry
fides registry resolve <did>        # Resolve from registry
fides relay send                    # Send relay message
fides dht publish                   # Publish DHT pointer
fides dht resolve <did>             # Resolve DHT pointer
fides killswitch engage             # Engage kill switch
fides killswitch disengage          # Disengage kill switch
fides daemon start                  # Start agentd
fides daemon status                 # Check agentd status
fides daemon stop                   # Stop agentd
```

## Required API Endpoints (agentd)

```
POST   /v1/identities
GET    /v1/identities/:did
POST   /v1/cards
GET    /v1/cards/:did
POST   /v1/trust
GET    /v1/trust/:did/score
POST   /v1/delegate
POST   /v1/sessions
DELETE /v1/sessions/:id
POST   /v1/evidence
GET    /v1/evidence/:did
POST   /v1/policy/evaluate
POST   /v1/revoke
POST   /v1/incidents
GET    /v1/incidents
POST   /v1/runtime/attest
POST   /v1/runtime/verify
GET    /v1/killswitch/status
POST   /v1/killswitch/engage
POST   /v1/killswitch/disengage
GET    /v1/discovery/resolve/:did
POST   /v1/discovery/register
```

## Tests

- Every new package must have unit tests
- Every new service must have integration tests
- E2E tests in `tests/e2e/`
- Adversarial tests in `tests/adversarial/`
- Target coverage: > 80% for new packages

## Docs

- Update `README.md`
- Create `docs/protocol/*.md` for each layer
- Create `docs/api/README.md` for HTTP API
- Create `docs/cli/README.md` for CLI
- Create `examples/README.md`
- Update `docs/architecture.md`

## Commit Rules

1. **Atomic commits:** One logical change per commit
2. **Meaningful messages:** `feat: add DelegationToken signing`, `fix: trust decay formula`, `test: add adversarial sybil test`
3. **Run tests before commit:** `pnpm test` should pass
4. **Run typecheck before commit:** `pnpm typecheck` should pass
5. **No breaking changes without migration path**
6. **Document breaking changes in commit message**

## Completion Contract

The implementation is complete when:

1. All 15 milestones are implemented
2. All tests pass (`pnpm test`)
3. Typecheck passes (`pnpm typecheck`)
4. Build passes (`pnpm build`)
5. E2E demo runs successfully (`pnpm demo`)
6. All docs are written and cross-referenced
7. No uncommitted user work was overwritten
8. All changes are on branch `fides-v2-agent-trust-fabric`
9. A summary of what was implemented is provided

## Reference Docs

Read these before starting:
- `~/fides/docs/inspection/fides-report.md`
- `~/fides/docs/inspection/agit-report.md`
- `~/fides/docs/inspection/osp-report.md`
- `~/fides/docs/inspection/oaps-report.md`
- `~/fides/docs/inspection/sardis-report.md`
- `~/fides/docs/inspection/cross-repo-primitive-map.md`
- `~/fides/docs/architecture/fides-v2-agent-trust-fabric.md`
- `~/fides/docs/architecture/gap-analysis.md`
- `~/fides/docs/architecture/implementation-plan.md`

## Important Reminders

- **Do not ask the user what is in the repos.** The inspection reports already document everything.
- **Do not start implementation before reading all reference docs.**
- **Do not delete or rewrite large parts of any repo without explicit reason.**
- **Prefer evolving existing code over creating new files where possible.**
- **Every major claim must be backed by actual file paths from the repos.**
- **Do not hallucinate features.** If you cannot find something, say so.
- **Do not stop after a shallow README scan.** Inspect source code, package structure, docs, tests, examples, and config.
