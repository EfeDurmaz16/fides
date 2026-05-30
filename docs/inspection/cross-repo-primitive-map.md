# Cross-Repo Primitive Map

This map reflects the current local inspection of:

- FIDES: `/Users/efebarandurmaz/fides`
- AGIT: `/Users/efebarandurmaz/agit`
- OSP: `/Users/efebarandurmaz/osp`
- OAPS: `/Users/efebarandurmaz/OAPS`
- Sardis: `/Users/efebarandurmaz/sardis`

## Hard Architecture Decisions

- FIDES v2 is TS-first and Rust adapter-ready.
- OAPS concepts are ported into FIDES. FIDES must not depend on `@oaps/core` at runtime.
- Sardis contributes generic authority patterns only; payment-specific models stay in Sardis.
- Effect may be used internally later, but protocol objects, signing, schemas, AgentCards, evidence events, DHT records, session grants, attestations, revocations, and incidents stay framework-agnostic.
- Public SDK remains Promise-based.

## Primitive Map

| Primitive | FIDES | AGIT | OSP | OAPS | Sardis | Best source | Action |
|----------|-------|------|-----|------|--------|-------------|--------|
| Agent identity | `packages/core/src/identity.ts`, `packages/shared/src/types.ts` | Adapter only: `python/agit/integrations/fides.py` | `osp-manifest/src/types.rs` | `ActorRef`/`ActorCard` | `fides_did.py`, `identity.py` | FIDES | extend existing |
| Publisher identity | `packages/core/src/identity.ts` | not found | provider identity adjacent | ActorCard publisher semantics | publisher mixed with payment/API context | FIDES + OAPS | extend existing |
| Principal identity | `packages/core/src/identity.ts` | not found | service principal adjacent | `ActorRef`, mandate principal | payment mandates/principals | FIDES + OAPS | extend existing |
| DID/key format | `did:fides`, canonical signer | adapter-level FIDES DID | Ed25519 DID methods | DID as actor profile, no verifier | `fides_did.py` | FIDES | reuse existing |
| Signing | `canonical-signer.ts`, SDK signing | canonical hashing, adapter signatures | `osp-crypto` | generic proof/HMAC | attestation envelope | FIDES | extend existing |
| HTTP message signatures | SDK signing package | not core | not primary | documented gap | not generic | FIDES | reuse existing |
| Canonical object signing | `packages/core/src/canonical-signer.ts` | `crates/agit-core/src/hash.rs` | `osp-crypto/src/canonical.rs` | core canonical JSON/hash | attestation envelope | FIDES + AGIT/OAPS prior art | extend existing |
| Trust attestation | trust graph/service | adapter-only | trust tier/reputation metadata | profile draft | TrustFramework | FIDES | extend existing |
| Trust graph | `services/trust-graph` | causal graph only | not found | not found | FIDES adapter/trust infra | FIDES | extend existing |
| Reputation | capability scoring partial | not found | registry reputation metadata | not found | KYA/payment reputation | FIDES | extend existing |
| Capability descriptor | `packages/core/src/capability.ts` | not found | service/capability manifest | CapabilityCard | agent auth/A2A/payment capabilities | OAPS + FIDES | extend existing |
| Capability ontology | heuristic only | blast radius/risk | service taxonomy | capability schemas/constants | risk/action patterns | OAPS | create new |
| AgentCard / ActorCard | `packages/core/src/agent-card.ts`, shared AgentCard | not found | service manifest | ActorCard | A2A AgentCard | FIDES + OAPS | extend existing |
| Discovery | provider package/services | adapter only | service discovery | actor discovery | A2A/agent auth | FIDES | extend existing |
| Well-known discovery | discovery service/provider | not found | manifest fetch | `.well-known/oaps.json` | agent auth/A2A well-known | FIDES | extend existing |
| Registry | `services/registry` | not found | `osp-registry` | not broad runtime | not generic | FIDES + OSP | extend existing |
| Relay | `services/relay`, relay provider | not found | not found | not found | not found | FIDES | extend existing |
| DHT | signed pointer record + in-memory simulator | not found | not found | not found | not found | FIDES | extend existing |
| Federation | signed peer record + local mock provider | not found | registry concepts | profile notes only | not found | FIDES + OSP | extend existing |
| DelegationToken | `packages/core/src/delegation.ts` | not found | delegation chain structs | `DelegationToken` | mandates | FIDES + OAPS | extend existing |
| SessionGrant | `packages/core/src/delegation.ts`, session store | not found | not found | auth-web session adjacent | grant/session-like agent auth | FIDES | extend existing |
| PolicyBundle | `packages/policy` | guard chain | not core | policy package | policy DSL/pipeline | FIDES + OAPS | extend existing |
| Policy engine | `packages/policy`, `services/policy-engine`, guard | guards/blast radius | not core | fail-closed evaluator | pre-execution pipeline | FIDES + Sardis | extend existing |
| Intent | not first-class | not found | not found | foundation intent | AP2/payment intents | OAPS | create new |
| ApprovalRequest | missing first-class core | `approval.rs` | HITL spec | core approvals | approval flow | OAPS + Sardis | create new |
| ApprovalDecision | missing first-class core | `approval.rs` | HITL spec | core approvals | approval flow | OAPS + Sardis | create new |
| EvidenceEvent | `packages/evidence` | commits/events/audit | webhook events | hash-linked evidence | evidence export/hash-chain | FIDES + OAPS + AGIT | extend existing |
| Hash chain | `packages/evidence` | strong lineage/hash prior art | not generic | evidence package | policy hash-chain | FIDES + AGIT | extend existing |
| Merkle proof | Merkle root only | Merkle/state diff concepts | not found | not found | ledger anchor | AGIT + Sardis | create new |
| Revocation | `packages/core/src/revocation.ts`, services | not core | docs/spec | revoke flow | identity/payment revocation | FIDES | extend existing |
| Incident | `packages/core/src/revocation.ts`, services | not core | not found | not found | payment/trust context | FIDES | extend existing |
| Runtime attestation | `packages/runtime` | not found | not found | not found | not generic | FIDES | extend existing |
| TEE | Mock/HTTP adapter boundary | not found | not found | not found | not found | FIDES | adapter-ready |
| Privacy/redaction | evidence privacy modes | not found | credential encryption | profile/spec only | payment privacy primitives | FIDES + Sardis prior art | extend existing |
| Error vocabulary | broad error classes | `AgitError` | error responses | error taxonomy | exception/reason codes | FIDES + OAPS | extend existing |
| Version negotiation | missing/partial | not found | version fields | negotiateVersion | version fields | OAPS | create new |
| Kill switch | `packages/runtime`, CLI/agentd | not found | not found | revoke/fail-closed only | payment kill switch | FIDES + Sardis | extend existing |
| Guardrails | guard/policy | guard chain/blast radius | not core | policy/approval | pre-execution pipeline | FIDES + Sardis + AGIT | extend existing |
| Service lifecycle | agentd/services | not found | discover/provision/rotate/deprovision | not core | project provisioning payment-adjacent | OSP | adapter-ready |
| Provisioning | not generic | not found | core OSP primitive | not core | payment/project-specific | OSP | adapter-ready |
| Rotation | identity/session/revocation partial | not core | rotate credentials | not core | identity/payment rotation | FIDES + OSP | extend existing |
| Deprovisioning | deregister/revoke partial | not found | core OSP primitive | revoke flows | payment/project-specific | OSP | adapter-ready |
| CLI | `packages/cli`, binary `fides` | Python CLI | Rust/TS tools | CLI refs | several CLIs | FIDES | extend existing |
| SDK | `packages/sdk` | TS/Python SDKs | TS/Python/Go/Rust | TS reference packages | TS/Python SDKs | FIDES | extend existing |
| Examples | `examples/` | demos | examples | many fixtures/examples | many demos | FIDES | extend existing |
| Tests | package/service/e2e/adversarial | Rust/Python/TS tests | conformance | reference tests | large suite | FIDES | extend existing |
| Docs | docs present but stale | docs | spec/docs | spec/schemas | docs/site | FIDES | extend existing |
| MCP adapter | adapter contract + manifest | exists | MCP server | MCP adapter | MCP server | OAPS + Sardis/OSP | adapter-ready |
| A2A adapter | adapter contract + manifest | exists | A2A adjacent | A2A adapter | A2A resources/routes | FIDES + OAPS/Sardis | adapter-ready |
| OAPS adapter | adapter contract + mapping set | not found | not found | source spec | not found | FIDES | extend existing |
| OSP adapter | adapter contract + mapping set | not found | source spec | not found | not found | FIDES + OSP | adapter-ready |
| AP2 adapter | payment action-flow adapter contract | not found | not core | payment profile | AP2 verifier/mandates | Sardis | adapter-ready |
| x402 adapter | payment action-flow adapter contract | not found | not core | x402 adapter | x402 facilitator | Sardis/OAPS | adapter-ready |
| Sardis adapter | payment action-flow adapter contract | FIDES adapter to AGIT | Sardis integration | profile relation | source consumer | FIDES + Sardis | extend existing |

## Key Findings

- FIDES already contains the most complete local runtime for this pivot, but it is not yet coherent enough to call FIDES v2 complete.
- OAPS is the best semantic source for actor/delegation/mandate/approval/evidence/version/error concepts, but it is not a high-assurance trust runtime.
- AGIT is useful for evidence lineage, hashing, state history, Merkle/diff concepts, and causal graph ideas.
- OSP is useful for service lifecycle, registry, provisioning, rotation, deprovisioning, and provider/MCP integration semantics.
- Sardis is useful for generic authority patterns but must remain payment-specific for actual payment execution.

## Recommended Implementation Bias

1. Reuse and harden FIDES packages first.
2. Port OAPS semantics into FIDES-owned types.
3. Use AGIT as Rust adapter-ready prior art for evidence hashing/lineage.
4. Use OSP for adapter semantics and lifecycle mapping only.
5. Use Sardis for policy-before-execution, approvals, kill switch, evidence, high-risk action handling, and mandate-chain abstractions only.
6. Keep DHT/relay/registry as discovery signals, never authority.
