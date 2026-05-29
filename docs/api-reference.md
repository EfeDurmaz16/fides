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
policy evaluation and scoped session grants.
