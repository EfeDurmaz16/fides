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
- File-backed governed trust-anchor registry and deterministic distribution bundle.

Not included yet:

- Authenticated agent management.
- General trust relationship CRUD APIs beyond governed trust anchors.
- Policy management APIs.
- Analytics and API key management.
- Live WebAuthn cryptographic verification. The platform API stores bindings
  after a verifier adapter has accepted registration or authentication.
- Network peering or external trust-anchor governance workflows.

Those higher-level workflows should be added only once their backing service contracts are stable.

## Development

```bash
pnpm --filter @fides/platform-api dev
pnpm --filter @fides/platform-api test
pnpm --filter @fides/platform-api lint
```

The service listens on `PLATFORM_API_PORT`, then `PORT`, then `3600`.
Passkey bindings persist to `PLATFORM_STORE_PATH` when set, otherwise
`~/.fides/platform-api/platform-store.json`. The file snapshot includes
`schemaVersion: 1`; legacy unversioned snapshots are migrated on read and
rewritten with the current schema on the next mutation. Tests use an in-memory
store.

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

### `POST /v1/trust-anchors`

Stores or updates a governed trust anchor:

```json
{
  "did": "did:fides:anchor",
  "name": "Example Root Anchor",
  "publicKey": "0000000000000000000000000000000000000000000000000000000000000000",
  "attestation": {
    "payload": { "did": "did:fides:anchor" },
    "proof": {
      "type": "Ed25519Signature2024",
      "created": "2026-01-01T00:00:00.000Z",
      "verificationMethod": "did:fides:issuer#key-1",
      "proofPurpose": "assertionMethod",
      "canonicalizationAlgorithm": "https://fides.dev/canonical-json/v1",
      "proofValue": "signature"
    }
  },
  "status": "active",
  "scopes": ["identity.organization"],
  "issuerDid": "did:fides:issuer",
  "createdAt": "2026-01-01T00:00:00.000Z"
}
```

The API stores public keys as 32-byte hex strings and emits the same shape back
to operator clients.

### `GET /v1/trust-anchors`

Lists governed trust anchors. Optional `status=active|suspended|revoked`
filters the response.

### `GET /v1/trust-anchors/distribution`

Returns a deterministic `fides.trust-anchors.v1` distribution bundle containing
active anchors that pass core trust-anchor policy validation. Optional query
parameters:

- `issuerDid`
- `requiredScope`
- `trustedIssuerDids` as a comma-separated DID list

### `GET /v1/trust-anchors/:did`

Returns one governed trust-anchor record.

### `PATCH /v1/trust-anchors/:did/status`

Updates anchor status:

```json
{
  "status": "revoked",
  "reason": "key compromise"
}
```

Revocations automatically receive `revokedAt` when the request omits it.

### `DELETE /v1/trust-anchors/:did`

Hard-deletes a trust-anchor record from local platform storage. Prefer status
revocation when downstream distribution clients need evidence of removal.
