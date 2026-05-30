# Discovery

Discovery resolves capability intent into candidate AgentCards. Discovery never grants authority.

Current implementation anchors:

- `packages/core/src/discovery.ts`
- `packages/discovery/src/provider.ts`
- `packages/discovery/src/orchestrator.ts`
- `packages/discovery/src/local-provider.ts`
- `packages/discovery/src/well-known-provider.ts`
- `packages/discovery/src/registry-provider.ts`
- `packages/discovery/src/relay-provider.ts`
- `packages/discovery/src/dht-provider.ts`
- `packages/discovery/src/federation-provider.ts`
- `services/agentd/src/index.ts`

## Flow

1. Receive `DiscoveryQuery`.
2. Query enabled providers.
3. Verify signed records where available.
4. Verify AgentCards.
5. Check protocol version compatibility.
6. Check capability compatibility.
7. Compute trust.
8. Evaluate policy.
9. Return ranked candidates with explanations.
10. Emit evidence.

## URL-less Discovery

FIDES discovery does not require every candidate to already expose an HTTP URL.
An endpoint URL is transport metadata, not identity, trust, or authority.

All package-level discovery providers that accept `SignedAgentCard` registration
must require identity-bound AgentCard proofs. Local, registry, relay, and DHT
registration paths verify that the AgentCard proof verification method matches
the advertised `identity.did` before storing, publishing, or relaying the card.
Direct `registerCard` helpers remain local mock/test utilities and do not imply
the card is signed or trusted.

Current support:

- Local discovery can resolve from daemon-held AgentCards without endpoint URLs.
  `agentd` marks these candidates with `resolution.urlRequired: false` and the
  reason `url_not_required_for_local_discovery`.
- DHT discovery can resolve a signed capability pointer to a daemon-held
  AgentCard. The DHT pointer is only a hint; it is not a trust source and it
  does not grant authority.
- Relay discovery can advertise presence and endpoint hints for NAT-hidden
  agents. A relay hint is not an authority decision.
- Registry discovery can return AgentCards that have no callable endpoint yet,
  but invocation still requires a later transport/session path.

URL-dependent cases:

- Well-known discovery requires a domain or DID-to-domain mapping because the
  discovery mechanism itself is HTTP `.well-known`.
- Capability invocation eventually needs a transport path, relay route, local
  process binding, or adapter-specific execution channel. Discovery alone only
  returns candidates.

The package-level `DiscoveryOrchestrator` supports capability-query providers,
candidate explanations, provider scoping, ranking, and protocol version
negotiation. Incompatible provider or legacy DID-resolution candidates are
filtered before ranking and compatible candidates carry a
`versionNegotiation` record. Every returned `DiscoveryCandidate` is explicitly
marked `authority: candidate_only` and carries `evidence_refs` for audit links.
Trust/policy/evidence integration remains an incremental hardening area.

Root `agentd` local, well-known, registry, relay, locally resolvable DHT, and
local mock federation discovery now apply protocol version negotiation before
returning provider results. A query can send `supported_versions` and
`required_versions`; each matching local AgentCard contributes its
`protocolVersions`. Compatible candidates, records, and pointers include a
`versionNegotiation` record. Incompatible matches are filtered out of the
active result set and returned in `rejectedCandidates`, `rejectedRecords`, or
`rejectedPointers` with a `VERSION_INCOMPATIBLE` error envelope. This keeps
discovery useful for explainability without treating an incompatible candidate
as invokable.

Federation discovery is deliberately candidate-only. The local mock federation
provider verifies signed `RegistryPeerRecord` metadata and ignores expired or
non-search peers, but a federated candidate remains untrusted until the normal
AgentCard, trust, reputation, revocation, incident, policy, session, and
evidence pipeline completes.
