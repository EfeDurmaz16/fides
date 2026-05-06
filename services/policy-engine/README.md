# FIDES Policy Engine

Standalone deterministic policy evaluation service for FIDES agents.

The service wraps `@fides/policy` behind a small Hono HTTP API. It validates incoming policy bundles, evaluates them against request context, and returns the same `allow`, `deny`, `approve-required`, or `dry-run` decisions used by agentd guard flows.

## Status

Implemented as a TypeScript service.

Current scope:

- Health endpoint for service readiness checks.
- Prometheus metrics endpoint for request counters and latency summaries.
- Policy bundle validation before evaluation.
- Deterministic rule evaluation through `@fides/policy`.
- Context-aware inputs for `agentDid`, `capabilityId`, and arbitrary JSON context.
- CORS and body-size middleware suitable for local service deployment.

Not included yet:

- Natural-language policy compilation.
- Policy persistence/version history.
- Audit trail storage.

## Development

```bash
pnpm --filter @fides/policy-engine dev
pnpm --filter @fides/policy-engine test
pnpm --filter @fides/policy-engine lint
```

The service listens on `POLICY_ENGINE_PORT`, then `PORT`, then `3300`.

Policy evaluation routes are protected with `X-API-Key` when `SERVICE_API_KEY`
is set. For least-privilege deployments, `POLICY_ENGINE_API_KEYS` can provide
JSON-scoped keys such as:

```bash
POLICY_ENGINE_API_KEYS='[{"key":"policy-operator-key","scopes":["policy:evaluate"]}]'
```

When `POLICY_ENGINE_API_KEYS` is set, it takes precedence over `SERVICE_API_KEY`.
In `NODE_ENV=production`, evaluation routes fail closed with `503` if neither
`SERVICE_API_KEY` nor valid `POLICY_ENGINE_API_KEYS` are configured. Malformed
`POLICY_ENGINE_API_KEYS` also fails closed with `503`.

## API

### `GET /health`

Returns service readiness metadata.

### `GET /metrics`

Returns Prometheus text metrics for HTTP request counts, response latency summaries, and active connections.

### `POST /v1/policies/evaluate`

Evaluates a policy bundle with optional agent/capability fields.

```json
{
  "agentDid": "did:fides:agent",
  "capabilityId": "payments.execute",
  "policy": {
    "id": "payments-policy",
    "version": "1.0.0",
    "rules": [
      {
        "id": "deny-large-transfer",
        "condition": { "field": "amount", "operator": "gt", "value": 1000 },
        "action": "deny",
        "explanation": "Large transfers are blocked"
      }
    ],
    "defaultAction": "allow"
  },
  "context": {
    "amount": 2500
  }
}
```

Example response:

```json
{
  "decision": "deny",
  "matchedRules": ["deny-large-transfer"],
  "explanation": {
    "decision": "Rule deny-large-transfer matched",
    "factors": []
  }
}
```

### `POST /v1/evaluate`

Compatibility endpoint that evaluates `{ "policy": ..., "context": ... }`.
