# FIDES Deployment Guide

## Prerequisites

- **Node.js** 22 or later
- **pnpm** 10 (enabled via `corepack enable`)
- **Docker** 24+ (for containerized deployment)
- **PostgreSQL** 16 (for discovery, trust-graph, production registry storage, and production `agentd` authority storage)

## Services Overview

| Service      | Port  | Database       | Description                              |
| ------------ | ----- | -------------- | ---------------------------------------- |
| `discovery`  | 3100  | PostgreSQL     | DID resolution, identity registry        |
| `trust-graph`| 3200  | PostgreSQL     | Web-of-trust scoring                     |
| `policy-engine` | 3300 | None          | Deterministic policy evaluation          |
| `registry`   | 7346  | PostgreSQL or file | AgentCard registry with durable hosted storage |
| `relay`      | 7347  | File or memory | Message relay for NAT/firewall traversal |
| `agentd`     | 7345  | PostgreSQL or file | Local daemon unifying all services and durable authority state |
| `platform-api` | 3600 | None          | Platform health, version, and topology metadata |

---

## Environment Variables Reference

All variables are defined in `.env.example`. Copy it to `.env` and adjust:

```bash
cp .env.example .env
```

### Database

| Variable          | Default                                  | Required | Description                |
| ----------------- | ---------------------------------------- | -------- | -------------------------- |
| `DATABASE_URL`    | `postgresql://fides:CHANGEME@localhost:5432/fides` | yes      | Connection string          |
| `POSTGRES_USER`   | `fides`                                  | yes      | PostgreSQL user            |
| `POSTGRES_PASSWORD` | `CHANGEME`                             | yes      | PostgreSQL password        |
| `POSTGRES_DB`     | `fides`                                  | yes      | PostgreSQL database name   |
| `DB_POOL_MAX`     | `10`                                     | no       | Connection pool size       |

### Discovery Store

| Variable                    | Default | Required | Description |
| --------------------------- | ------- | -------- | ----------- |
| `DISCOVERY_DB_AUTO_MIGRATE` | `true`  | no | Runs idempotent discovery migrations on startup and records applied ids plus checksums in `discovery_schema_migrations`. Set `false` when migrations are managed externally. |
| `DISCOVERY_DB_SCHEMA`       | _(empty)_ | no | Optional Postgres schema name for discovery tables when multiple services share one database. Must be a simple identifier. |

### Trust Graph Store

| Variable                      | Default | Required | Description |
| ----------------------------- | ------- | -------- | ----------- |
| `TRUST_GRAPH_DB_AUTO_MIGRATE` | `true`  | no | Runs idempotent trust graph migrations on startup and records applied ids plus checksums in `trust_graph_schema_migrations`. Set `false` when migrations are managed externally. |
| `TRUST_GRAPH_DB_SCHEMA`       | `trust_graph` in Docker Compose, otherwise _(empty)_ | no | Optional Postgres schema name for trust graph tables when multiple services share one database. Must be a simple identifier. |

### Agentd Authority Store

| Variable                  | Default | Required | Description |
| ------------------------- | ------- | -------- | ----------- |
| `AGENTD_AUTHORITY_STORE`  | `file`  | production | `file` for local JSON state, `postgres` for durable authority state |
| `AGENTD_DATABASE_URL`     | _(empty)_ | production when `AGENTD_AUTHORITY_STORE=postgres` | Dedicated agentd authority database URL. Falls back to `DATABASE_URL` when unset. |
| `AGENTD_DB_AUTO_MIGRATE`  | `true`  | no | Runs idempotent authority migrations on startup and records applied ids in `agentd_schema_migrations`. Set `false` when migrations are managed externally. |
| `AGENTD_DB_POOL_MAX`      | `10`    | no | Agentd authority store connection pool size. Falls back to `DB_POOL_MAX`. |
| `AGENTD_STATE_STORE_PATH` | _(empty)_ | no | File authority store path. Defaults to `~/.fides/agentd/authority-store.json`. |
| `AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION` | `true` in production, `false` otherwise | no | When `true`, agentd rejects delegation, revocation, and incident writes unless the request includes the corresponding signer public key for canonical signature verification. Set `false` only for transitional deployments that cannot yet send signer public keys. |

### Registry Store

| Variable                  | Default | Required | Description |
| ------------------------- | ------- | -------- | ----------- |
| `REGISTRY_STORE`          | `file`  | production | `file` for local JSON state, `postgres` for durable hosted registry state |
| `REGISTRY_DATABASE_URL`   | _(empty)_ | production when `REGISTRY_STORE=postgres` | Dedicated registry database URL. Falls back to `DATABASE_URL` when unset. |
| `REGISTRY_DB_AUTO_MIGRATE`| `true`  | no | Runs idempotent registry migrations on startup and records applied ids plus checksums in `registry_schema_migrations`. Set `false` when migrations are managed externally. |
| `REGISTRY_DB_POOL_MAX`    | `10`    | no | Registry store connection pool size. Falls back to `DB_POOL_MAX`. |
| `REGISTRY_STORE_PATH`     | _(empty)_ | no | File registry store path. Defaults to `~/.fides/registry/registry.json`. |

### Relay Store

| Variable           | Default | Required | Description |
| ------------------ | ------- | -------- | ----------- |
| `RELAY_STORE`      | `memory` in development, `file` in production and Docker Compose | production | `memory` for process-local queues, `file` for schema-versioned JSON snapshots. |
| `RELAY_STORE_PATH` | _(empty)_ | no | File relay store path. Defaults to `~/.fides/relay/relay-store.json`; Docker Compose uses `/data/fides/relay/relay-store.json`. |

### Service Ports

| Variable          | Default | Service       |
| ----------------- | ------- | ------------- |
| `DISCOVERY_PORT`  | `3100`  | discovery     |
| `TRUST_GRAPH_PORT`| `3200`  | trust-graph   |
| `POLICY_ENGINE_PORT` | `3300` | policy-engine |
| `REGISTRY_PORT`   | `7346`  | registry      |
| `RELAY_PORT`      | `7347`  | relay         |
| `AGENTD_PORT`     | `7345`  | agentd        |
| `PLATFORM_API_PORT` | `3600` | platform-api |

### Service URLs (inter-service communication)

| Variable          | Default                        | Used by            |
| ----------------- | ------------------------------ | ------------------ |
| `DISCOVERY_URL`   | `http://localhost:3100`        | agentd             |
| `TRUST_GRAPH_URL` | `http://localhost:3200`        | agentd             |
| `POLICY_ENGINE_URL` | `http://localhost:3300`      | platform-api       |
| `REGISTRY_URL`    | `http://localhost:7346`        | agentd, platform-api |
| `RELAY_URL`       | `http://localhost:7347`        | platform-api       |
| `AGENTD_URL`      | `http://localhost:7345`        | platform-api       |

### Authentication

| Variable          | Default | Required | Description                                   |
| ----------------- | ------- | -------- | --------------------------------------------- |
| `SERVICE_API_KEY` | _(empty)_ | production | Shared API key for protected service routes. In production, protected routes return `503` when this is unset. Outside production, leaving it unset disables local auth. |
| `DISCOVERY_API_KEYS` | _(empty)_ | no | Optional discovery scoped keys as JSON, for example `[{"key":"discovery-operator-key","scopes":["discovery:identities:register","discovery:identities:domain:verify","discovery:identities:organization-domain:verify","discovery:agents:register","discovery:agents:update","discovery:agents:heartbeat","discovery:agents:delete"]}]`. When set, it takes precedence over `SERVICE_API_KEY` for discovery write routes and malformed JSON fails closed with `503`. |
| `PLATFORM_API_KEYS` | _(empty)_ | no | Optional platform-api scoped keys as JSON, for example `[{"key":"operator-key","scopes":["platform:topology:read","platform:passkeys:read","platform:passkeys:write","platform:trust-anchors:read","platform:trust-anchors:write"]}]`. When set, it takes precedence over `SERVICE_API_KEY` for platform-api routes and malformed JSON fails closed with `503`. |
| `AGENTD_API_KEYS` | _(empty)_ | no | Optional agentd scoped keys as JSON, for example `[{"key":"agentd-operator-key","scopes":["agentd:policy:evaluate","agentd:sessions:write","agentd:authority:write","agentd:authorize:write","agentd:evidence:write","agentd:attest:write","agentd:killswitch:write"]}]`. When set, it takes precedence over `SERVICE_API_KEY` for agentd mutating `/v1/*` routes and malformed JSON fails closed with `503`. |
| `REGISTRY_API_KEYS` | _(empty)_ | no | Optional registry scoped keys as JSON, for example `[{"key":"registry-operator-key","scopes":["registry:cards:publish","registry:cards:delete","registry:cards:mode:write","registry:cards:metadata:write"]}]`. When set, it takes precedence over `SERVICE_API_KEY` for registry mutating `/v1/*` routes and malformed JSON fails closed with `503`. |
| `RELAY_API_KEYS` | _(empty)_ | no | Optional relay scoped keys as JSON, for example `[{"key":"relay-operator-key","scopes":["relay:messages:submit","relay:messages:delete"]}]`. When set, it takes precedence over `SERVICE_API_KEY` for relay mutating `/v1/*` routes and malformed JSON fails closed with `503`. |
| `POLICY_ENGINE_API_KEYS` | _(empty)_ | no | Optional policy-engine scoped keys as JSON, for example `[{"key":"policy-operator-key","scopes":["policy:evaluate"]}]`. When set, it takes precedence over `SERVICE_API_KEY` for policy evaluation routes and malformed JSON fails closed with `503`. |
| `TRUST_GRAPH_API_KEYS` | _(empty)_ | no | Optional trust-graph scoped keys as JSON, for example `[{"key":"trust-operator-key","scopes":["trust:edges:write","trust:capability:invoke","trust:incidents:write","trust:revocations:write"]}]`. When set, it takes precedence over `SERVICE_API_KEY` for trust-graph write routes and malformed JSON fails closed with `503`. |

### Logging

| Variable     | Default | Choices            | Description      |
| ------------ | ------- | ------------------ | ---------------- |
| `LOG_LEVEL`  | `info`  | debug,info,warn,error | Log verbosity |
| `LOG_FORMAT` | `json`  | json,text          | Log output format|

### Network

| Variable        | Default  | Required | Description                      |
| --------------- | -------- | -------- | -------------------------------- |
| `CORS_ORIGIN`   | `*`      | production | Allowed origin for browser clients. Set to your frontend URL in production. |
| `RATE_LIMIT_MAX`     | `100`    | no       | Max requests per window (POST)   |
| `RATE_LIMIT_WINDOW_MS` | `60000` | no       | Rate limit window in ms          |
| `NODE_ENV`      | `development` | yes | `production` or `development` |

---

## Docker Compose Quick Start

The fastest way to run all services:

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD.
# Docker Compose defaults agentd to AGENTD_AUTHORITY_STORE=postgres.

# Start all services
docker compose up -d

# Verify health
docker compose ps
curl http://localhost:3100/health
curl http://localhost:3200/health
curl http://localhost:3300/health
curl http://localhost:7346/health
curl http://localhost:7347/health
curl http://localhost:7345/health
curl http://localhost:3600/health

# View logs
docker compose logs -f
```

This starts PostgreSQL, discovery, trust-graph, policy-engine, registry, relay, agentd, and platform-api — all pre-configured for inter-service communication. In Docker Compose, `agentd` uses the same PostgreSQL container for durable authority state unless `AGENTD_DATABASE_URL` points at a dedicated database, and relay uses the `relay_data` volume for file-backed message state.

### Development Mode

For hot-reload in development:

```bash
docker compose -f docker-compose.dev.yml up
```

Source is mounted into containers; changes trigger automatic restarts via `tsx watch`.

---

## Manual Deployment

### 1. Install and Build

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm build
```

Run authority migrations before starting `agentd` when auto-migration is disabled:

```bash
export AGENTD_AUTHORITY_STORE=postgres
export AGENTD_DATABASE_URL="postgresql://fides:CHANGEME@localhost:5432/fides"
pnpm --filter @fides/agentd db:migrate
export AGENTD_DB_AUTO_MIGRATE=false
```

`pnpm --filter @fides/agentd db:migrate` creates the authority tables and records `001_authority_store` plus its statement checksum in `agentd_schema_migrations`. When `AGENTD_DB_AUTO_MIGRATE=false`, startup validates both the tables and the migration ledger instead of silently creating missing schema or accepting a drifted migration body.

### 2. Run Each Service

Start them in separate terminals or use a process manager (pm2, systemd):

```bash
# Terminal 1 — Discovery
export DATABASE_URL="postgresql://fides:CHANGEME@localhost:5432/fides"
export DISCOVERY_PORT=3100
export NODE_ENV=production
node services/discovery/dist/index.js

# Terminal 2 — Trust Graph
export DATABASE_URL="postgresql://fides:CHANGEME@localhost:5432/fides"
export TRUST_GRAPH_PORT=3200
export DISCOVERY_URL="http://localhost:3100"
export NODE_ENV=production
node services/trust-graph/dist/index.js

# Terminal 3 — Registry
export REGISTRY_PORT=7346
export REGISTRY_STORE=postgres
export REGISTRY_DATABASE_URL="postgresql://fides:CHANGEME@localhost:5432/fides"
export NODE_ENV=production
pnpm --filter @fides/registry-service db:migrate
node services/registry/dist/index.js

# Terminal 4 — Policy Engine (no database needed)
export POLICY_ENGINE_PORT=3300
export NODE_ENV=production
node services/policy-engine/dist/index.js

# Terminal 5 — Relay (file-backed by default in production)
export RELAY_PORT=7347
export RELAY_STORE=file
export RELAY_STORE_PATH="$HOME/.fides/relay/relay-store.json"
export NODE_ENV=production
node services/relay/dist/index.js

# Terminal 6 — Agent Daemon
export AGENTD_PORT=7345
export AGENTD_AUTHORITY_STORE=postgres
export AGENTD_DATABASE_URL="postgresql://fides:CHANGEME@localhost:5432/fides"
export AGENTD_DB_AUTO_MIGRATE=false
export DISCOVERY_URL="http://localhost:3100"
export TRUST_GRAPH_URL="http://localhost:3200"
export REGISTRY_URL="http://localhost:7346"
export NODE_ENV=production
node services/agentd/dist/index.js

# Terminal 7 — Platform API
export PLATFORM_API_PORT=3600
export DISCOVERY_URL="http://localhost:3100"
export TRUST_GRAPH_URL="http://localhost:3200"
export POLICY_ENGINE_URL="http://localhost:3300"
export REGISTRY_URL="http://localhost:7346"
export RELAY_URL="http://localhost:7347"
export AGENTD_URL="http://localhost:7345"
export NODE_ENV=production
node services/platform-api/dist/index.js
```

### 3. Systemd Unit Example

```
# /etc/systemd/system/fides-discovery.service
[Unit]
Description=FIDES Discovery Service
After=network.target postgresql.service

[Service]
Type=simple
User=fides
WorkingDirectory=/opt/fides
Environment=NODE_ENV=production
Environment=DISCOVERY_PORT=3100
Environment="DATABASE_URL=postgresql://fides:CHANGEME@localhost:5432/fides"
ExecStart=/usr/bin/node services/discovery/dist/index.js
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Health Check Verification

All services expose a `GET /health` endpoint returning JSON with a `status` field:

```bash
curl -s http://localhost:3100/health | jq .
curl -s http://localhost:3200/health | jq .
curl -s http://localhost:3300/health | jq .
curl -s http://localhost:7346/health | jq .
curl -s http://localhost:7347/health | jq .
curl -s http://localhost:7345/health | jq .
curl -s http://localhost:3600/health | jq .
```

Expected responses:

- `discovery`: `{"status":"healthy",...}` — depends on PostgreSQL connectivity
- `trust-graph`: `{"status":"healthy",...}` — depends on PostgreSQL connectivity
- `policy-engine`: `{"status":"healthy",...}` — deterministic evaluator is ready
- `registry`: `{"status":"healthy",...}` — depends on the configured registry store; inspect `checks.store.kind` for `postgres` or `file`
- `relay`: `{"status":"healthy",...}` — inspect `store` for `file` or `memory`
- `agentd`: `{"status":"healthy",...}` — depends on upstream services and authority store readiness
- `platform-api`: `{"status":"healthy",...}` — topology metadata endpoint is ready

If a dependency is unavailable, the service returns HTTP 503 with `"status":"degraded"` and `checks` detailing which component failed. For `agentd`, inspect `checks.authorityStore` and `authorityStore.kind` to confirm whether the file or Postgres authority store is active.

Docker containers include built-in `HEALTHCHECK` instructions; use `docker compose ps` to monitor container health.

---

## TLS / HTTPS Setup

FIDES services listen on plain HTTP internally. Terminate TLS at a reverse proxy.

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name fides.example.com;

    ssl_certificate     /etc/letsencrypt/live/fides.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/fides.example.com/privkey.pem;

    # Discovery
    location /discovery/ {
        proxy_pass http://127.0.0.1:3100/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Trust Graph
    location /trust-graph/ {
        proxy_pass http://127.0.0.1:3200/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Registry
    location /registry/ {
        proxy_pass http://127.0.0.1:7346/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Relay
    location /relay/ {
        proxy_pass http://127.0.0.1:7347/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Policy Engine
    location /policy-engine/ {
        proxy_pass http://127.0.0.1:3300/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Agent Daemon
    location /agentd/ {
        proxy_pass http://127.0.0.1:7345/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Platform API
    location /platform-api/ {
        proxy_pass http://127.0.0.1:3600/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy

```
fides.example.com {
    handle_path /discovery/* {
        reverse_proxy localhost:3100
    }
    handle_path /trust-graph/* {
        reverse_proxy localhost:3200
    }
    handle_path /registry/* {
        reverse_proxy localhost:7346
    }
    handle_path /relay/* {
        reverse_proxy localhost:7347
    }
    handle_path /policy-engine/* {
        reverse_proxy localhost:3300
    }
    handle_path /agentd/* {
        reverse_proxy localhost:7345
    }
    handle_path /platform-api/* {
        reverse_proxy localhost:3600
    }
}
```

### Production Checklist

1. Set `NODE_ENV=production` on all services
2. Set `SERVICE_API_KEY` to a strong random value (generated via `openssl rand -hex 32`); protected service routes fail closed with `503` in production when it is missing. For least privilege, prefer `DISCOVERY_API_KEYS`, `PLATFORM_API_KEYS`, `AGENTD_API_KEYS`, `REGISTRY_API_KEYS`, `RELAY_API_KEYS`, `POLICY_ENGINE_API_KEYS`, and `TRUST_GRAPH_API_KEYS` with route-specific scopes on their services.
3. Set `CORS_ORIGIN` to your frontend origin (not `*`)
4. Enable rate limiting via `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS`
5. Set `LOG_LEVEL=warn` to reduce noise, use `LOG_FORMAT=json` for log aggregation
6. Run PostgreSQL with TLS if accessed over untrusted networks
7. Run `pnpm --filter @fides/discovery-service db:migrate` before setting `DISCOVERY_DB_AUTO_MIGRATE=false`
8. Run `pnpm --filter @fides/trust-graph db:migrate` before setting `TRUST_GRAPH_DB_AUTO_MIGRATE=false`
9. Run `pnpm --filter @fides/agentd db:migrate` before setting `AGENTD_DB_AUTO_MIGRATE=false`
10. Keep `AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION=true` in production and send signer public keys with delegated session, revocation, and incident writes
11. Rotate `SERVICE_API_KEY` periodically

---

## Backup and Restore

### PostgreSQL (discovery + trust-graph)

Both services share the same database. Back up:

```bash
pg_dump -U fides -h localhost fides > fides-backup-$(date +%Y%m%d).sql
```

Restore:

```bash
psql -U fides -h localhost fides < fides-backup-YYYYMMDD.sql
```

With Docker Compose:

```bash
# Backup
docker compose exec postgres pg_dump -U fides fides > backup.sql

# Restore
cat backup.sql | docker compose exec -T postgres psql -U fides fides
```

### Registry

When `REGISTRY_STORE=postgres`, registry cards live in the `registry_cards` table and are covered by the normal Postgres backup flow above. Migrations are idempotent and can be applied with:

```bash
REGISTRY_DATABASE_URL="postgresql://fides:CHANGEME@localhost:5432/fides" pnpm --filter @fides/registry-service db:migrate
```

When `REGISTRY_STORE=file`, the registry stores data at `~/.fides/registry/registry.json`. Back up this file:

```bash
cp ~/.fides/registry/registry.json ~/fides-registry-backup-$(date +%Y%m%d).json
```

In Docker Compose, the volume `registry_data` persists this. Back it up:

```bash
docker compose run --rm registry cat /home/fides/.fides/registry/registry.json > registry-backup.json
```

Restore:

```bash
cat registry-backup.json | docker compose run --rm -T registry sh -c 'cat > /home/fides/.fides/registry/registry.json'
```

### Relay

When `RELAY_STORE=file`, the relay stores messages at `~/.fides/relay/relay-store.json` by default. The snapshot is schema-versioned JSON and is written through an atomic temp-file rename. Back up this file:

```bash
cp ~/.fides/relay/relay-store.json ~/fides-relay-backup-$(date +%Y%m%d).json
```

In Docker Compose, the volume `relay_data` persists this. Back it up:

```bash
docker compose run --rm relay cat /data/fides/relay/relay-store.json > relay-backup.json
```

Restore:

```bash
cat relay-backup.json | docker compose run --rm -T relay sh -c 'mkdir -p /data/fides/relay && cat > /data/fides/relay/relay-store.json'
```

When `RELAY_STORE=memory`, relay messages are process-local and disappear on restart. Messages still have a default TTL of 5 minutes.

---

## Monitoring

Services with the shared observability middleware expose Prometheus metrics at `GET /metrics`:

| Service      | Metrics URL                  |
| ------------ | ---------------------------- |
| discovery    | `http://localhost:3100/metrics` |
| trust-graph  | `http://localhost:3200/metrics` |
| policy-engine | `http://localhost:3300/metrics` |
| registry     | `http://localhost:7346/metrics` |
| relay        | `http://localhost:7347/metrics` |
| agentd       | `http://localhost:7345/metrics` |
| platform-api | `http://localhost:3600/metrics` |

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: fides-discovery
    static_configs:
      - targets: ['localhost:3100']
    metrics_path: /metrics

  - job_name: fides-trust-graph
    static_configs:
      - targets: ['localhost:3200']
    metrics_path: /metrics

  - job_name: fides-policy-engine
    static_configs:
      - targets: ['localhost:3300']
    metrics_path: /metrics

  - job_name: fides-registry
    static_configs:
      - targets: ['localhost:7346']
    metrics_path: /metrics

  - job_name: fides-relay
    static_configs:
      - targets: ['localhost:7347']
    metrics_path: /metrics

  - job_name: fides-agentd
    static_configs:
      - targets: ['localhost:7345']
    metrics_path: /metrics

  - job_name: fides-platform-api
    static_configs:
      - targets: ['localhost:3600']
    metrics_path: /metrics
```

### Key metrics

Each service reports:

- `http_requests_total` — total requests (labels: `method`, `path`, `status`)
- `http_response_duration_ms` — latency summary in milliseconds
- `http_active_connections` — current active requests

### Health check alerts

Every service also exposes structured health at `/health`. Combine metrics with health endpoints for alerting rules:

```yaml
# Example alerting rule
- alert: FidesDiscoveryDown
  expr: up{job="fides-discovery"} == 0
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "FIDES discovery service is down"
```

---

## Service Dependencies

```
discovery ─────────────────────┐
  (needs PostgreSQL)            │
                                │
trust-graph ────────────────────┤
  (needs PostgreSQL, discovery) │
                                ├── agentd
registry ───────────────────────┤   (proxies to all three)
  (PostgreSQL in production)    │
                                │
relay ──────────────────────────┘
  (standalone, file or memory)

policy-engine ──────────────── platform-api
  (standalone evaluator)        (metadata over service URLs)
```

- `discovery` and `trust-graph` require PostgreSQL
- `trust-graph` additionally requires `discovery` for identity resolution
- `policy-engine` is standalone — deterministic policy evaluation
- `registry` stores AgentCards in PostgreSQL by default in Docker Compose and can fall back to a local JSON file for development
- `relay` is standalone — file-backed by default in Docker/production, memory-backed for lightweight development
- `agentd` is a local proxy that depends on discovery, trust-graph, and registry
- `platform-api` is standalone metadata over configured service URLs

### Running a Minimal Setup

For development without PostgreSQL, you can run just registry, relay, and agentd:

```bash
node services/registry/dist/index.js &
SERVICE_API_KEY=dev-key node services/policy-engine/dist/index.js &
node services/relay/dist/index.js &
AGENTD_PORT=7345 DISCOVERY_URL=http://localhost:3100 TRUST_GRAPH_URL=http://localhost:3200 REGISTRY_URL=http://localhost:7346 node services/agentd/dist/index.js &
SERVICE_API_KEY=dev-key PLATFORM_API_PORT=3600 AGENTD_URL=http://localhost:7345 node services/platform-api/dist/index.js &
```

Note: agentd health will show `degraded` when discovery or trust-graph are unreachable — this is expected in minimal mode.
