# API Reference

The local HTTP API is served by `agentd`.

Current implementation anchors:

- `services/agentd/src/index.ts`
- `docs/api/agentd.yaml`

## Stable Local Endpoints

- `GET /health`
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
