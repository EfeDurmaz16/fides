# FIDES Platform API

Minimal API layer for FIDES developer platform metadata and service discovery.

The platform API is intentionally small today. It provides a stable place for dashboard and operator clients to discover FIDES service metadata without coupling directly to every internal service.

## Status

Implemented as a TypeScript Hono service.

Current scope:

- Health endpoint for readiness checks.
- Prometheus metrics endpoint for request counters and latency summaries.
- Version metadata for platform clients.
- Topology endpoint that exposes configured service URLs.
- File-backed passkey credential binding persistence for platform-hosted principals.

Not included yet:

- Authenticated agent management.
- Trust relationship CRUD APIs.
- Policy management APIs.
- Analytics and API key management.
- Live WebAuthn cryptographic verification. The platform API stores bindings
  after a verifier adapter has accepted registration or authentication.

Those higher-level workflows should be added only once their backing service contracts are stable.

## Development

```bash
pnpm --filter @fides/platform-api dev
pnpm --filter @fides/platform-api test
pnpm --filter @fides/platform-api lint
```

The service listens on `PLATFORM_API_PORT`, then `PORT`, then `3600`.
Passkey bindings persist to `PLATFORM_STORE_PATH` when set, otherwise
`~/.fides/platform-api/platform-store.json`. Tests use an in-memory store.

## API

### `GET /health`

Returns service readiness metadata.

### `GET /v1/version`

Returns the platform API version and protocol family.

### `GET /metrics`

Returns Prometheus text metrics for HTTP request counts, response latency summaries, and active connections.

### `GET /v1/topology`

Returns configured service URLs. Defaults are local development ports and can be overridden with:

- `DISCOVERY_URL`
- `TRUST_GRAPH_URL`
- `POLICY_ENGINE_URL`
- `REGISTRY_URL`
- `RELAY_URL`
- `AGENTD_URL`

When `SERVICE_API_KEY` is set, callers must include `X-API-Key`. In `NODE_ENV=production`, this endpoint fails closed with `503` if `SERVICE_API_KEY` is unset.

### `POST /v1/passkeys/bindings`

Stores or updates a verified passkey credential binding:

```json
{
  "principalDid": "did:fides:principal",
  "credentialId": "credential-id",
  "publicKey": "base64url-or-provider-public-key",
  "relyingPartyId": "example.com",
  "signCount": 1,
  "createdAt": "2026-01-01T00:00:00.000Z"
}
```

The endpoint rejects credential takeover across principals and sign-count
rollback.

### `GET /v1/passkeys/principals/:did/credentials`

Lists credential descriptors for a principal DID.

### `GET /v1/passkeys/credentials/:credentialId`

Returns a stored passkey credential binding.

### `DELETE /v1/passkeys/credentials/:credentialId`

Deletes a stored passkey credential binding.
