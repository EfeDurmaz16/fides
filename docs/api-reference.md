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
- `POST /trust/evaluate`
- `GET /trust/:agentId`
- `POST /reputation/update`
- `GET /reputation/:agentId`
- `POST /policy/evaluate`
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
- `POST /demo/run`
- `POST /simulate/adversarial`
- `POST /evidence/verify`
- `POST /evidence/export`

The alias endpoints currently provide local mock/demo behavior and should be hardened into durable API routes.

`POST /identities` creates local in-memory identities for the daemon prototype
and returns only public identity data. Private keys are retained inside the
daemon process and are not returned by `POST /identities`, `GET /identities`, or
`GET /identities/:id`. This route is protected by the same production API-key
fail-closed behavior as other mutating `agentd` routes.

`POST /agent-cards` creates local in-memory AgentCards bound to local daemon
identities. `POST /agent-cards/:id/sign` signs the stored card with the local
agent identity key using the canonical AgentCard signing model, and
`POST /agent-cards/:id/verify` verifies the signed card when present. These
routes are prototype-local until the daemon storage layer is migrated to
durable SQLite-backed identity/card storage.

`POST /agents/register` registers a locally stored AgentCard as a discovery
candidate. `GET /agents` and `GET /agents/:id` expose local registration state
and the associated AgentCard. `POST /discover` searches registered local agents
by capability. Discovery responses always include `authorityGranted: false`;
discovery is candidate resolution only, and invocation authority still requires
policy evaluation and scoped session grants. Local discovery does not require
an endpoint URL; daemon-held AgentCards can resolve by capability with
`resolution.urlRequired: false`. Endpoint URLs remain optional transport
metadata, not authority.

`POST /trust/evaluate` computes a local capability-scoped trust result for a
registered candidate. `POST /reputation/update` stores capability-specific
reputation signals, and `GET /reputation/:agentId` returns those local records.
`POST /policy/evaluate` runs the FIDES v2 policy evaluator against the local
candidate, trust result, requested scopes, and runtime/revocation/incident
flags. Trust and reputation are signals only; policy decisions still do not
execute capabilities and allowed decisions require a scoped SessionGrant before
invocation.

`POST /sessions` issues a local `SessionGrant` only after policy allows or
limits the action to dry-run. `POST /invoke` verifies the session, runs the
policy preflight path, validates the capability context, and returns an
`InvocationResult`. The current root implementation is in-memory and intended
for local daemon DX; durable storage and signed invocation results remain
follow-up hardening work.

`POST /approvals` creates an approval request and records approval decisions
through `/approvals/:id/approve` or `/approvals/:id/deny`. Approval records do
not grant authority by themselves; they are inputs to policy/session issuance.
`POST /killswitch` creates an active kill switch rule for an agent, publisher,
capability, session, principal, or risk class. Active kill switch rules override
normal trust and policy evaluation and block root session issuance until
disabled with `DELETE /killswitch/:id`.

`POST /revocations` creates a local FIDES v2 revocation record for keys,
identities, agents, AgentCards, capabilities, sessions, attestations, or
publishers. Active matching revocations override normal policy and block root
session issuance. `POST /incidents` records an open incident against a target
agent; open incidents require policy review for matching session requests until
resolved with `POST /incidents/:id/resolve`.

`POST /attestations` issues a local FIDES v2 runtime attestation through the
MockTEE provider. `POST /attestations/:id/verify` verifies provider, expiry,
and hash shape. Root `POST /sessions` can consume a valid `attestationId` as
runtime attestation evidence for high-risk capability policy.
