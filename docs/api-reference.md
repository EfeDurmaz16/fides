# API Reference

The local HTTP API is served by `agentd`.

Current implementation anchors:

- `services/agentd/src/index.ts`
- `docs/api/agentd.yaml`

## Stable Local Endpoints

- `GET /health`
- `POST /identities`
- `GET /identities`
- `GET /identities/:id`
- `POST /agent-cards`
- `POST /agent-cards/:id/sign`
- `POST /agent-cards/:id/verify`
- `GET /agent-cards/:id`
- `POST /agents/register`
- `GET /agents`
- `GET /agents/:id`
- `POST /discover`
- `POST /discover/local`
- `POST /discover/well-known`
- `POST /discover/registry`
- `POST /discover/relay`
- `POST /discover/dht`
- `POST /discover/federation`
- `POST /trust/evaluate`
- `GET /trust/:agentId`
- `POST /reputation/update`
- `GET /reputation/:agentId`
- `POST /policy/evaluate`
- `POST /delegations`
- `POST /sessions`
- `GET /sessions/:id`
- `POST /sessions/:id/verify`
- `POST /invoke`
- `POST /approvals`
- `GET /approvals`
- `POST /approvals/:id/approve`
- `POST /approvals/:id/deny`
- `POST /killswitch`
- `GET /killswitch`
- `DELETE /killswitch/:id`
- `POST /revocations`
- `GET /revocations`
- `GET /revocations/:id`
- `POST /incidents`
- `GET /incidents`
- `GET /incidents/:id`
- `POST /incidents/:id/resolve`
- `POST /attestations`
- `GET /attestations/:id`
- `POST /attestations/:id/verify`
- `GET /.well-known/fides.json`
- `GET /.well-known/agents.json`
- `GET /.well-known/agents/:id.json`
- `POST /registry/start`
- `POST /registry/publish`
- `POST /registry/search`
- `GET /registry/index`
- `POST /relay/start`
- `POST /relay/register`
- `POST /relay/discover`
- `POST /v1/policy/evaluate`
- `POST /v1/sessions`
- `GET /v1/sessions/:id`
- `POST /v1/authorize`
- `POST /v1/evidence`
- `GET /v1/evidence/:did`
- `GET /v1/evidence/:did/verify`
- `POST /v1/revocations`
- `GET /v1/revocations/:did`
- `POST /v1/incidents`
- `GET /v1/incidents/:did`
- `POST /v1/killswitch/engage`
- `POST /v1/killswitch/disengage`
- `POST /v1/attest`

## v2 Alias Endpoints

- `POST /dht/start`
- `POST /dht/publish`
- `GET /dht/find`
- `POST /dht/find`
- `POST /demo/run`
- `POST /simulate/adversarial`
- `POST /evidence`
- `GET /evidence`
- `GET /evidence/:eventId`
- `POST /evidence/verify`
- `POST /evidence/export`

The root v2 endpoints are local-first daemon surfaces. Registry and relay are
mock/local providers, and the root daemon persists its local v2 state through a
SQLite-backed snapshot store by default outside tests. The default path is
`~/.fides/fides.sqlite`; set `AGENTD_SQLITE_PATH` to override it or
`AGENTD_LOCAL_STATE=memory` to disable persistence for ephemeral local runs.
This store is a daemon snapshot, not the final normalized SQLite table model for
production hardening.

`POST /registry/start`, `POST /registry/publish`, `POST /registry/search`, and
`GET /registry/index` provide a local mock registry over registered AgentCards.
Registry records for locally signed AgentCards include `agentCardUrl`,
`agentCardHash`, `registryIndexRecord`, `registryIndexProof`, and
`registryIndexVerified`; search and discovery verify signed local registry index
records before returning them.
`POST /relay/start`, `POST /relay/register`, and `POST /relay/discover` provide
local mock relay presence and rendezvous. Relay records for locally signed
AgentCards include `agentCardUrl`, `agentCardHash`, `signedAgentCard`, and
`agentCardProof` so callers can resolve and verify the card after rendezvous.
Both surfaces return candidates or presence records only; they set
`authorityGranted: false` and do not replace policy evaluation or scoped session
grants. `GET /.well-known/fides.json`,
`GET /.well-known/agents.json`, and `GET /.well-known/agents/:id.json` expose
local well-known metadata for same-host discovery.

`POST /evidence`, `GET /evidence`, `GET /evidence/:eventId`,
`POST /evidence/verify`, and `POST /evidence/export` expose the root local
EvidenceEvent ledger. Sensitive inputs and outputs are not stored directly by
default; the daemon records `sha256:` hashes and metadata under `hash_only`
privacy unless another privacy mode is explicitly requested. Root evidence is
tamper-evident through the hash chain and is persisted in the local daemon
snapshot when SQLite state is enabled.

`POST /demo/run` executes the local FIDES v2 trust-fabric scenario in the
current daemon process. It creates demo identities and signed AgentCards,
publishes candidates through local registry, relay, and DHT surfaces, performs
provider discovery, verifies AgentCards, evaluates trust/reputation/policy,
issues scoped sessions, invokes invoice and payment dry-run flows, records an
incident and revocation, and verifies the local EvidenceEvent hash chain.

`POST /identities` creates local daemon identities and returns only public
identity data. Private keys are retained in local daemon state for prototype
signing and are not returned by `POST /identities`, `GET /identities`, or
`GET /identities/:id`. When SQLite state is enabled, that local signing material
is included in the daemon snapshot and must be protected by filesystem controls;
OS-backed encryption or hardware-backed key storage remains production
hardening work. This route is protected by the same production API-key
fail-closed behavior as other mutating `agentd` routes.

`POST /agent-cards` creates local AgentCards bound to local daemon identities.
`POST /agent-cards/:id/sign` signs the stored card with the local agent identity
key using the canonical AgentCard signing model, and
`POST /agent-cards/:id/verify` verifies the signed card when present. These
routes are durable across daemon restarts when SQLite local state is enabled,
but remain prototype-local until the daemon state is migrated from snapshot
storage to normalized identity/card tables.

`POST /agents/register` registers a locally stored AgentCard as a discovery
candidate. `GET /agents` and `GET /agents/:id` expose local registration state
and the associated AgentCard. `POST /discover` and `POST /discover/local`
search registered local agents by capability. `POST /discover/well-known`,
`POST /discover/registry`, `POST /discover/relay`, `POST /discover/dht`, and
`POST /discover/federation` expose provider-specific discovery aliases over
the daemon's local state.
`POST /dht/publish` creates a signed DHT pointer when the referenced agent is
registered locally; callers may omit `agentCardUrl`, in which case the daemon
uses a `local://agent-cards/<card-id>` pointer and signs it with the local
identity. Unresolved external DHT publishes remain local mock pointers and are
returned as unverified records.
Discovery responses always include `authorityGranted: false`; discovery is
candidate resolution only, and invocation authority still requires policy
evaluation and scoped session grants. Local discovery does not require an
endpoint URL; daemon-held AgentCards can resolve by capability with
`resolution.urlRequired: false`. Endpoint URLs remain optional transport
metadata, not authority. DHT discovery also does not require an HTTP URL when a
local AgentCard can be resolved, but DHT remains a pointer layer rather than a
trust source. Local, well-known, registry, relay, and locally resolvable DHT
discovery also negotiate protocol compatibility between query
`supported_versions` / `required_versions` and the candidate AgentCard
`protocolVersions`; incompatible candidates are omitted from provider results
and reported under `rejectedCandidates`, `rejectedRecords`, or
`rejectedPointers` with `VERSION_INCOMPATIBLE`.
Federation discovery wraps verified local registry records with a signed
`RegistryPeerRecord`, marks them as provider `federation`, and reports
incompatible records under `rejectedRecords`. Federation expands discovery
reach only; it is not a trust source and never grants authority.

`POST /trust/evaluate` computes a local capability-scoped trust result for a
registered candidate. `POST /reputation/update` stores capability-specific
reputation signals, and `GET /reputation/:agentId` returns those local records.
`POST /policy/evaluate` runs the FIDES v2 policy evaluator against the local
candidate, trust result, requested scopes, and runtime/revocation/incident
flags. Trust and reputation are signals only; policy decisions still do not
execute capabilities and allowed decisions require a scoped SessionGrant before
invocation.

`POST /delegations` creates a local unsigned `DelegationToken` intent and
returns `authorityGranted: false`; it must still be signed and converted into a
policy-checked SessionGrant before invocation. `POST /sessions` issues a local
`SessionGrant` only after policy allows or limits the action to dry-run.
`POST /invoke` verifies the session, verifies an optional caller-supplied
canonical `signedRequest`, runs the policy preflight path, validates the
capability context, validates input/output schemas for the advertised
capability, and returns an `InvocationResult` plus a canonical `signedResult`
proof from the target agent identity when the target is locally managed. A
supplied signed request must verify and match the session, input hash, and
dry-run mode before execution. Invocation state and result evidence are
persisted in the local daemon snapshot when SQLite state is enabled; normalized
durable invocation tables remain follow-up hardening work. Session issuance and
invocation failures return a stable `ErrorEnvelope` on the `error` field for
policy denial, approval required, active revocation, active kill switch, missing
capability, missing session, expired session, invalid session-scope cases,
invalid invocation request signatures, and capability schema violations.

`POST /approvals` creates an approval request and records approval decisions
through `/approvals/:id/approve` or `/approvals/:id/deny`. Approval records do
not grant authority by themselves; they are inputs to policy/session issuance.
Approval request, grant, and deny mutations append `approval.requested`,
`approval.granted`, or `approval.denied` evidence events and return
`evidenceRefs`.
`POST /killswitch` creates an active kill switch rule for an agent, publisher,
capability, session, principal, or risk class. Active kill switch rules override
normal trust and policy evaluation and block root session issuance until
disabled with `DELETE /killswitch/:id`. Kill switch creation appends a
`kill_switch.triggered` evidence event and returns `evidenceRefs`.

`POST /revocations` creates a local FIDES v2 revocation record for keys,
identities, agents, AgentCards, capabilities, sessions, attestations, or
publishers. Active matching revocations override normal policy and block root
session issuance. `POST /incidents` records an open incident against a target
agent; open incidents require policy review for matching session requests until
resolved with `POST /incidents/:id/resolve`. Revocation and incident creation
append `revocation.recorded` and `incident.reported` evidence events and return
`evidenceRefs`.

`POST /attestations` issues a local FIDES v2 runtime attestation through the
MockTEE provider. `POST /attestations/:id/verify` verifies provider, expiry,
and hash shape. Root `POST /sessions` can consume a valid `attestationId` as
runtime attestation evidence for high-risk capability policy. Attestation
issuance and verification append `attestation.issued`, `attestation.verified`,
or `attestation.failed` evidence events and return `evidenceRefs`.
