# Implementation Plan

This document provides a detailed, milestone-based implementation plan for FIDES v2 / Agent Trust Fabric. Each milestone is designed to be executable by a coding agent with atomic commits.

## Architecture Decisions (Enforced)

- **TS-first, Rust adapter-ready.**
- **OAPS concepts ported into FIDES, not imported as runtime dependencies.**
- **Sardis contributes generic patterns only.**
- **Protocol objects, crypto, canonical JSON, and public schemas remain framework-agnostic.**
- **Public SDK exposes Promise-based APIs.**

---

## Milestone 1: Stabilize FIDES Core

**Goal:** Fix known issues in FIDES v1 before building v2.

**Files to modify:**
- `packages/shared/src/errors.ts` — Add OAPS error categories
- `packages/shared/src/constants.ts` — Add protocol version constant
- `packages/sdk/src/identity/did.ts` — Document W3C non-compliance
- `packages/sdk/src/identity/rotation.ts` — Document DID-changing rotation behavior
- `services/trust-graph/src/services/scoring.ts` — Fix trust decay formula or update spec
- `docs/protocol-spec.md` — Update to match implementation or vice versa
- `package.json` (discovery, trust-graph) — Normalize to `@fides/discovery`, `@fides/trust-graph`

**Packages to create:** None

**Types/schemas to add:**
- `ProtocolVersion = "fides-v2.0.0"`
- Extended `FidesError` categories: `capability`, `execution`, `economic`, `settlement`, `versioning`

**Tests to add:**
- Test that trust decay formula matches spec (or update spec test)
- Test nonce replay protection in server services

**Docs to update:**
- `docs/protocol-spec.md`
- `docs/architecture.md`

**Expected CLI/API behavior:** No breaking changes. `fides status` should report protocol version.

**Commit checklist:**
- [ ] Fix package names
- [ ] Fix trust decay formula or spec
- [ ] Extend error hierarchy
- [ ] Add protocol version constant
- [ ] Update docs

**Validation command:** `pnpm test` (all existing tests pass)

---

## Milestone 2: Identity v2

**Goal:** Introduce AgentIdentity, PublisherIdentity, PrincipalIdentity, and trust anchors.

**Files to modify:**
- `packages/sdk/src/identity/` — Refactor to support multi-level identity
- `packages/shared/src/types.ts` — Add new identity types

**Packages to create:**
- `packages/@fides/core/` — New package for core primitives

**Types/schemas to add:**
```typescript
interface AgentIdentity {
  did: string;
  publicKey: Uint8Array;
  keyType: "Ed25519";
  createdAt: string;
  publisher?: PublisherIdentity;
  principal?: PrincipalIdentity;
}

interface PublisherIdentity {
  did: string;
  name: string;
  domain?: string;
  verified: boolean;
  verificationMethod: "dns" | "github" | "email" | "manual";
}

interface PrincipalIdentity {
  did: string;
  type: "individual" | "organization" | "platform";
  displayName: string;
}

interface TrustAnchor {
  did: string;
  name: string;
  publicKey: Uint8Array;
  attestation: SignedObject<TrustAttestation>;
}
```

**Tests to add:**
- Identity creation and round-trip
- Publisher verification mock
- Principal identity resolution
- Trust anchor validation

**Docs to update:**
- `docs/protocol/identity-v2.md`

**Expected CLI/API behavior:**
- `fides identity create --type agent`
- `fides identity create --type publisher --name "Acme Corp" --domain acme.com`
- `fides identity create --type principal --name "Alice"`
- `fides trust anchor add <did>`

**Commit checklist:**
- [ ] Create `@fides/core` package
- [ ] Add identity v2 types
- [ ] Refactor existing identity code to use new types (backward compatible)
- [ ] Add trust anchor primitive
- [ ] Add CLI commands
- [ ] Write tests

**Validation command:** `pnpm test && pnpm typecheck`

---

## Milestone 3: AgentCards and Capabilities

**Goal:** Signed AgentCards with CapabilityDescriptors.

**Files to modify:**
- `packages/shared/src/types.ts` — Extend AgentCard
- `packages/sdk/src/discovery/agent-client.ts` — Use new AgentCard
- `services/discovery/src/routes/well-known.ts` — Serve signed AgentCards

**Packages to create:** None (use `@fides/core`)

**Types/schemas to add:**
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

interface SignedAgentCard extends SignedObject<AgentCard> {}
```

**Tests to add:**
- AgentCard creation and validation
- CapabilityDescriptor risk classification
- SignedAgentCard verification
- A2A compatibility conversion

**Docs to update:**
- `docs/protocol/agent-cards.md`
- `docs/protocol/capabilities.md`

**Expected CLI/API behavior:**
- `fides card create` — creates and signs AgentCard
- `fides card verify <did>` — verifies signed AgentCard
- `fides capability add <name> --risk high`

**Commit checklist:**
- [ ] Add AgentCard v2 types
- [ ] Add CapabilityDescriptor
- [ ] Implement canonical signing for AgentCard
- [ ] Update discovery service to serve signed cards
- [ ] Update CLI
- [ ] Write tests

**Validation command:** `pnpm test && pnpm typecheck`

---

## Milestone 4: Discovery Provider Architecture

**Goal:** Pluggable discovery with 5 providers.

**Files to modify:**
- `packages/sdk/src/discovery/` — Refactor to use provider pattern

**Packages to create:**
- `packages/@fides/discovery/` — Discovery provider framework

**Types/schemas to add:**
```typescript
interface DiscoveryProvider {
  readonly name: string;
  resolve(did: string): Promise<AgentCard | null>;
  register(card: SignedAgentCard): Promise<void>;
  deregister(did: string): Promise<void>;
}

class LocalDiscoveryProvider implements DiscoveryProvider { /* mDNS / local network */ }
class WellKnownDiscoveryProvider implements DiscoveryProvider { /* HTTP .well-known */ }
class RegistryDiscoveryProvider implements DiscoveryProvider { /* Hosted registry */ }
class RelayDiscoveryProvider implements DiscoveryProvider { /* Relay server */ }
class DHTDiscoveryProvider implements DiscoveryProvider { /* DHT pointers */ }

class DiscoveryOrchestrator {
  constructor(providers: DiscoveryProvider[]);
  resolve(did: string): Promise<AgentCard | null>;
}
```

**Tests to add:**
- Each provider unit test
- Orchestrator fallback test
- Provider priority test

**Docs to update:**
- `docs/protocol/discovery.md`

**Expected CLI/API behavior:**
- `fides discover --provider local`
- `fides discover --provider registry`
- `fides discover --provider all`

**Commit checklist:**
- [ ] Create `@fides/discovery` package
- [ ] Implement provider interface
- [ ] Implement WellKnown provider (port from existing)
- [ ] Implement Local provider (stub with mDNS-ready interface)
- [ ] Implement Registry provider (stub with HTTP interface)
- [ ] Implement Relay provider (stub)
- [ ] Implement DHT provider (stub)
- [ ] Write tests

**Validation command:** `pnpm test && pnpm typecheck`

---

## Milestone 5: Registry and Relay

**Goal:** Hosted registry (public/private) and mock relay server.

**Files to modify:**
- `services/discovery/src/` — Extend with registry routes

**Packages to create:**
- `services/registry/` — New registry service (or extend discovery)
- `services/relay/` — Mock relay server

**Types/schemas to add:**
```typescript
interface RegistryRecord {
  did: string;
  card: SignedAgentCard;
  registeredAt: string;
  updatedAt: string;
  registryMode: "public" | "private";
  federationPeers: string[];
}

interface RelayMessage {
  id: string;
  to: string;
  payload: unknown;
  ttl: number;
}
```

**Tests to add:**
- Registry CRUD
- Private registry access control
- Relay message routing
- Federation peering (stub)

**Docs to update:**
- `docs/protocol/registry.md`
- `docs/protocol/relay.md`

**Expected CLI/API behavior:**
- `fides registry register --card ./agent-card.json`
- `fides registry resolve <did>`
- `fides registry set-mode <did> private`
- `fides relay send --to <did> --message "..."`

**Commit checklist:**
- [ ] Create registry service
- [ ] Add public/private mode
- [ ] Create mock relay server
- [ ] Add federation peering stubs
- [ ] Update discovery service to use registry
- [ ] Write tests

**Validation command:** `pnpm test && docker-compose -f docker-compose.dev.yml up --build`

---

## Milestone 6: DHT Discovery

**Goal:** Signed DHT pointer records and in-memory DHT simulator.

**Files to modify:**
- `packages/@fides/discovery/src/dht-provider.ts`

**Packages to create:** None

**Types/schemas to add:**
```typescript
interface DHTPointerRecord {
  did: string;
  registryUrl: string;
  relayUrl?: string;
  signature: string;  // signed by DID
  ttl: number;
}
```

**Tests to add:**
- DHT record creation and validation
- In-memory DHT simulator lookup
- Record expiry

**Docs to update:**
- `docs/protocol/dht.md`

**Expected CLI/API behavior:**
- `fides dht publish --registry <url>`
- `fides dht resolve <did>`

**Commit checklist:**
- [ ] Implement DHT pointer record
- [ ] Implement in-memory DHT simulator
- [ ] Add libp2p adapter interface (stub)
- [ ] Write tests

**Validation command:** `pnpm test`

---

## Milestone 7: Trust and Reputation v2

**Goal:** Capability-specific reputation, context-specific trust, incident penalties.

**Files to modify:**
- `services/trust-graph/src/services/scoring.ts`
- `services/trust-graph/src/db/schema.ts`
- `packages/sdk/src/trust/`

**Packages to create:** None

**Types/schemas to add:**
```typescript
interface ReputationScore {
  did: string;
  globalScore: number;
  capabilityScores: Record<string, number>;
  contextScores: Record<string, number>;
  incidentPenalty: number;
  noveltyPenalty: number;
  runtimeSafetyScore: number;
  calculatedAt: string;
}

interface TrustEdge {
  from: string;
  to: string;
  level: TrustLevel;
  capability?: string;
  context?: string;
  createdAt: string;
  expiresAt?: string;
}
```

**Tests to add:**
- Capability-specific reputation calculation
- Context-specific trust path
- Incident penalty application
- Time-based decay

**Docs to update:**
- `docs/protocol/trust-v2.md`
- `docs/protocol/reputation.md`

**Expected CLI/API behavior:**
- `fides trust score <did> --capability <id>`
- `fides trust score <did> --context <context>`

**Commit checklist:**
- [ ] Update DB schema for capability/context trust edges
- [ ] Update scoring algorithm
- [ ] Add incident/novelty/runtime penalties
- [ ] Update trust attestation to support capability scope
- [ ] Write tests

**Validation command:** `pnpm test`

---

## Milestone 8: Policy Engine

**Goal:** Full policy engine with risk taxonomy, guardrails, and pre-execution pipeline.

**Files to modify:**
- `services/policy-engine/` — Replace stub with full implementation

**Packages to create:**
- `packages/@fides/policy/` — Policy engine package

**Types/schemas to add:**
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

interface PolicyResult {
  decision: "allow" | "deny" | "approve-required" | "dry-run";
  explanation: DecisionExplanation;
  matchedRules: string[];
}

interface DecisionExplanation {
  decision: string;
  factors: { factor: string; weight: number; description: string }[];
}
```

**Tests to add:**
- Policy evaluation (all expression operators)
- Guardrail Allow/Warn/Block
- High-risk capability handling
- Revoked agent denial
- Invalid runtime attestation denial

**Docs to update:**
- `docs/protocol/policy.md`
- `docs/protocol/guardrails.md`
- `docs/protocol/risk.md`

**Expected CLI/API behavior:**
- `fides policy evaluate --bundle ./policy.json --request ./request.json`
- `fides policy explain --did <did> --capability <id>`

**Commit checklist:**
- [ ] Create `@fides/policy` package
- [ ] Implement policy evaluator (ported from OAPS)
- [ ] Implement pre-execution pipeline (ported from Sardis pattern)
- [ ] Implement risk taxonomy
- [ ] Integrate with trust graph scores
- [ ] Integrate with runtime attestation
- [ ] Write tests

**Validation command:** `pnpm test && pnpm typecheck`

---

## Milestone 9: Delegation and Sessions

**Goal:** DelegationToken, SessionGrant, scoped authority.

**Files to modify:**
- `packages/@fides/core/` — Add delegation primitives

**Packages to create:** None

**Types/schemas to add:**
```typescript
interface DelegationToken {
  id: string;
  delegator: string;      // DID
  delegatee: string;      // DID
  capabilities: string[]; // capability IDs
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
  boundTo?: string;       // IP, device fingerprint, etc.
}

interface DelegationConstraint {
  maxActions?: number;
  maxSpend?: string;      // currency amount
  allowedContexts?: string[];
  forbiddenContexts?: string[];
}
```

**Tests to add:**
- DelegationToken creation and verification
- SessionGrant issuance and expiry
- Replay protection (nonce)
- Audience restriction
- Constraint enforcement

**Docs to update:**
- `docs/protocol/delegation.md`
- `docs/protocol/sessions.md`

**Expected CLI/API behavior:**
- `fides delegate --to <did> --capability <id> --expires 1h`
- `fides session grant --token <token-id>`
- `fides session revoke <session-id>`

**Commit checklist:**
- [ ] Add DelegationToken type and signing
- [ ] Add SessionGrant type
- [ ] Implement nonce/replay protection
- [ ] Implement audience restriction
- [ ] Implement constraint validation
- [ ] Write tests

**Validation command:** `pnpm test`

---

## Milestone 10: Evidence Ledger

**Goal:** Append-only evidence ledger with hash chain and Merkle proofs.

**Files to modify:** None

**Packages to create:**
- `packages/@fides/evidence/` — Evidence ledger package

**Types/schemas to add:**
```typescript
interface EvidenceEvent {
  id: string;
  type: string;
  timestamp: string;
  actor: string;          // DID
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

interface EvidenceChain {
  events: EvidenceEvent[];
  merkleRoot?: string;
}
```

**Tests to add:**
- EvidenceEvent creation and signing
- Hash chain integrity
- Merkle proof generation and verification
- Privacy level application
- Chain export

**Docs to update:**
- `docs/protocol/evidence.md`
- `docs/protocol/evidence-privacy.md`

**Expected CLI/API behavior:**
- `fides evidence append --type invocation --actor <did> --action <capability>`
- `fides evidence verify --chain ./evidence.json`
- `fides evidence export --did <did> --format json`

**Commit checklist:**
- [ ] Create `@fides/evidence` package
- [ ] Implement EvidenceEvent with canonical signing
- [ ] Implement hash chain (SHA-256 chaining)
- [ ] Implement Merkle tree builder
- [ ] Implement privacy levels
- [ ] Write tests

**Validation command:** `pnpm test && pnpm typecheck`

---

## Milestone 11: Revocation and Incidents

**Goal:** RevocationRecord, IncidentRecord, and automated response.

**Files to modify:**
- `packages/sdk/src/identity/rotation.ts` — Extend revocation

**Packages to create:** None

**Types/schemas to add:**
```typescript
interface RevocationRecord {
  id: string;
  did: string;
  reason: string;
  revokedAt: string;
  revokedBy: string;
  signature: string;
  propagatedTo: string[];
}

interface IncidentRecord {
  id: string;
  type: "compromise" | "misbehavior" | "policy_violation" | "runtime_failure" | "sybil";
  severity: "low" | "medium" | "high" | "critical";
  actor: string;
  description: string;
  evidenceRefs: string[];
  reportedAt: string;
  resolvedAt?: string;
  impact: {
    trustPenalty: number;
    reputationPenalty: number;
    capabilitiesRevoked: string[];
  };
}
```

**Tests to add:**
- RevocationRecord creation and propagation
- IncidentRecord creation and impact calculation
- Policy engine integration (revoked agent denial)
- Trust graph integration (incident penalties)

**Docs to update:**
- `docs/protocol/revocation.md`
- `docs/protocol/incidents.md`

**Expected CLI/API behavior:**
- `fides revoke <did> --reason "key compromise"`
- `fides incident report --actor <did> --type misbehavior`
- `fides incident list --severity critical`

**Commit checklist:**
- [ ] Add RevocationRecord type
- [ ] Add IncidentRecord type
- [ ] Implement revocation propagation interface
- [ ] Integrate with policy engine
- [ ] Integrate with trust graph
- [ ] Write tests

**Validation command:** `pnpm test`

---

## Milestone 12: Runtime Attestation

**Goal:** RuntimeAttestation, MockTEEProvider, adapter interfaces.

**Files to modify:** None

**Packages to create:**
- `packages/@fides/runtime/` — Runtime attestation package

**Types/schemas to add:**
```typescript
interface RuntimeAttestation {
  id: string;
  agentDid: string;
  provider: string;       // "mock-tee", "aws-nitro", "intel-sgx", "amd-sev"
  measurement: string;    // hash of runtime state
  timestamp: string;
  expiresAt: string;
  evidence: unknown;      // provider-specific attestation evidence
  signature: string;
}

interface TEEAdapter {
  readonly provider: string;
  attest(agentDid: string): Promise<RuntimeAttestation>;
  verify(attestation: RuntimeAttestation): Promise<boolean>;
}

interface BuildAttestationAdapter {
  attest(imageHash: string): Promise<RuntimeAttestation>;
}
```

**Tests to add:**
- MockTEEProvider attestation and verification
- RuntimeAttestation expiry
- Policy engine integration (invalid attestation denial)
- Adapter interface compliance

**Docs to update:**
- `docs/protocol/runtime-attestation.md`
- `docs/protocol/tee-adapters.md`

**Expected CLI/API behavior:**
- `fides runtime attest --provider mock-tee`
- `fides runtime verify --attestation ./attestation.json`

**Commit checklist:**
- [ ] Create `@fides/runtime` package
- [ ] Implement RuntimeAttestation type
- [ ] Implement MockTEEProvider
- [ ] Add adapter interfaces (Nitro, SGX, SEV stubs)
- [ ] Add container/build attestation interfaces
- [ ] Integrate with policy engine
- [ ] Write tests

**Validation command:** `pnpm test && pnpm typecheck`

---

## Milestone 13: CLI and API

**Goal:** Extended CLI and local HTTP API.

**Files to modify:**
- `packages/cli/src/` — Add new commands
- `services/` — Ensure all services expose stable APIs

**Packages to create:**
- `services/agentd/` — Local daemon

**Types/schemas to add:**
```typescript
// agentd HTTP API routes
POST /v1/identities
GET  /v1/identities/:did
POST /v1/cards
GET  /v1/cards/:did
POST /v1/trust
GET  /v1/trust/:did/score
POST /v1/delegate
POST /v1/sessions
POST /v1/evidence
GET  /v1/evidence/:did
POST /v1/policy/evaluate
POST /v1/revoke
POST /v1/incidents
GET  /v1/runtime/attest
```

**Tests to add:**
- CLI command tests for all new commands
- agentd HTTP API integration tests

**Docs to update:**
- `docs/api/README.md`
- `docs/cli/README.md`

**Expected CLI/API behavior:**
- All previous CLI commands work
- New commands: `fides card`, `fides delegate`, `fides session`, `fides evidence`, `fides policy`, `fides revoke`, `fides incident`, `fides runtime`, `fides registry`, `fides relay`, `fides dht`
- `agentd` runs local HTTP API on port 7345 (FIDES)

**Commit checklist:**
- [ ] Extend CLI with all new commands
- [ ] Create `agentd` service
- [ ] Add local HTTP API
- [ ] Write CLI tests
- [ ] Write agentd integration tests

**Validation command:** `pnpm test && pnpm build`

---

## Milestone 14: Examples and Full Demo

**Goal:** Runnable example agents and end-to-end demo.

**Files to modify:** None

**Packages to create:** None

**Files to add:**
- `examples/calendar-agent/` — Calendar agent with FIDES identity
- `examples/invoice-agent/` — Invoice agent with delegation
- `examples/payment-agent/` — Payment agent with policy + evidence
- `examples/requester-agent/` — Agent that discovers and invokes others
- `examples/demo/` — Full demo script

**Tests to add:**
- E2E demo test

**Docs to update:**
- `examples/README.md`
- `docs/getting-started.md`

**Expected behavior:**
- `pnpm demo` runs full multi-agent trust fabric demo
- Demo shows: identity creation, discovery, trust attestation, delegation, policy enforcement, evidence collection, revocation

**Commit checklist:**
- [ ] Create example agents
- [ ] Create demo script
- [ ] Write E2E test
- [ ] Update docs

**Validation command:** `pnpm demo` (manual verification)

---

## Milestone 15: Docs and Tests

**Goal:** Complete documentation, threat model, and test suite.

**Files to modify:** None

**Files to add:**
- `docs/threat-model.md`
- `docs/security-review-checklist.md`
- `docs/production-hardening.md`
- `tests/adversarial/` — Adversarial simulation harness

**Tests to add:**
- Adversarial tests: Sybil, replay, policy bypass, delegation abuse
- Load tests for trust graph
- Fuzz tests for policy evaluator

**Docs to update:**
- `README.md`
- `docs/README.md`
- All protocol docs reviewed and cross-linked

**Expected behavior:**
- All docs are consistent and cross-referenced
- Adversarial tests run in CI
- Test coverage > 80% for new packages

**Commit checklist:**
- [ ] Write threat model
- [ ] Write security review checklist
- [ ] Write production hardening notes
- [ ] Implement adversarial simulation harness
- [ ] Add adversarial tests to CI
- [ ] Review and update all docs

**Validation command:** `pnpm test && pnpm coverage`

---

## Summary Timeline

| Phase | Milestones | Estimated Duration |
|-------|-----------|-------------------|
| Phase 0: Foundation | 1-3 | 2 weeks |
| Phase 1: Discovery | 4-6 | 2 weeks |
| Phase 2: Trust & Policy | 7-9 | 2 weeks |
| Phase 3: Evidence & Runtime | 10-12 | 2 weeks |
| Phase 4: Developer Surface | 13-15 | 2 weeks |
| **Total** | **1-15** | **10 weeks** |

This is a rough estimate. Parallel work on independent milestones can shorten the timeline.
