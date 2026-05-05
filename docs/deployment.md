# FIDES Deployment Guide

## Prerequisites

- **Node.js** 22 or later
- **pnpm** 10 (enabled via `corepack enable`)
- **Docker** 24+ (for containerized deployment)
- **PostgreSQL** 16 (for discovery, trust-graph, and production `agentd` authority storage)

## Services Overview

| Service      | Port  | Database       | Description                              |
| ------------ | ----- | -------------- | ---------------------------------------- |
| `discovery`  | 3100  | PostgreSQL     | DID resolution, identity registry        |
| `trust-graph`| 3200  | PostgreSQL     | Web-of-trust scoring                     |
| `registry`   | 7346  | File-based     | AgentCard registry (filesystem)          |
| `relay`      | 7347  | In-memory      | Message relay for NAT/firewall traversal |
| `agentd`     | 7345  | PostgreSQL or file | Local daemon unifying all services and durable authority state |

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

### Agentd Authority Store

| Variable                  | Default | Required | Description |
| ------------------------- | ------- | -------- | ----------- |
| `AGENTD_AUTHORITY_STORE`  | `file`  | production | `file` for local JSON state, `postgres` for durable authority state |
| `AGENTD_DATABASE_URL`     | _(empty)_ | production when `AGENTD_AUTHORITY_STORE=postgres` | Dedicated agentd authority database URL. Falls back to `DATABASE_URL` when unset. |
| `AGENTD_DB_AUTO_MIGRATE`  | `true`  | no | Runs idempotent authority migrations on startup and records applied ids in `agentd_schema_migrations`. Set `false` when migrations are managed externally. |
| `AGENTD_DB_POOL_MAX`      | `10`    | no | Agentd authority store connection pool size. Falls back to `DB_POOL_MAX`. |
| `AGENTD_STATE_STORE_PATH` | _(empty)_ | no | File authority store path. Defaults to `~/.fides/agentd/authority-store.json`. |
| `AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION` | `false` | production recommended | When `true`, agentd rejects delegation, revocation, and incident writes unless the request includes the corresponding signer public key for canonical signature verification. |

### Service Ports

| Variable          | Default | Service       |
| ----------------- | ------- | ------------- |
| `DISCOVERY_PORT`  | `3100`  | discovery     |
| `TRUST_GRAPH_PORT`| `3200`  | trust-graph   |
| `REGISTRY_PORT`   | `7346`  | registry      |
| `RELAY_PORT`      | `7347`  | relay         |
| `AGENTD_PORT`     | `7345`  | agentd        |

### Service URLs (inter-service communication)

| Variable          | Default                        | Used by            |
| ----------------- | ------------------------------ | ------------------ |
| `DISCOVERY_URL`   | `http://localhost:3100`        | agentd             |
| `TRUST_GRAPH_URL` | `http://localhost:3200`        | agentd             |
| `REGISTRY_URL`    | `http://localhost:7346`        | agentd             |

### Authentication

| Variable          | Default | Required | Description                                   |
| ----------------- | ------- | -------- | --------------------------------------------- |
| `SERVICE_API_KEY` | _(empty)_ | production | Shared API key for mutating endpoints. In production, mutating endpoints return `503` when this is unset. Outside production, leaving it unset disables write auth for local development. |

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
curl http://localhost:7346/health
curl http://localhost:7347/health
curl http://localhost:7345/health

# View logs
docker compose logs -f
```

This starts PostgreSQL, discovery, trust-graph, registry, relay, and agentd — all pre-configured for inter-service communication. In Docker Compose, `agentd` uses the same PostgreSQL container for durable authority state unless `AGENTD_DATABASE_URL` points at a dedicated database.

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

`pnpm --filter @fides/agentd db:migrate` creates the authority tables and records `001_authority_store` in `agentd_schema_migrations`. When `AGENTD_DB_AUTO_MIGRATE=false`, startup validates both the tables and the migration ledger instead of silently creating missing schema.

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

# Terminal 3 — Registry (no database needed)
export REGISTRY_PORT=7346
export NODE_ENV=production
node services/registry/dist/index.js

# Terminal 4 — Relay (no database needed)
export RELAY_PORT=7347
export NODE_ENV=production
node services/relay/dist/index.js

# Terminal 5 — Agent Daemon
export AGENTD_PORT=7345
export AGENTD_AUTHORITY_STORE=postgres
export AGENTD_DATABASE_URL="postgresql://fides:CHANGEME@localhost:5432/fides"
export AGENTD_DB_AUTO_MIGRATE=false
export DISCOVERY_URL="http://localhost:3100"
export TRUST_GRAPH_URL="http://localhost:3200"
export REGISTRY_URL="http://localhost:7346"
export NODE_ENV=production
node services/agentd/dist/index.js
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
curl -s http://localhost:7346/health | jq .
curl -s http://localhost:7347/health | jq .
curl -s http://localhost:7345/health | jq .
```

Expected responses:

- `discovery`: `{"status":"healthy",...}` — depends on PostgreSQL connectivity
- `trust-graph`: `{"status":"healthy",...}` — depends on PostgreSQL connectivity
- `registry`: `{"status":"healthy",...}` — depends on filesystem write access
- `relay`: `{"status":"healthy",...}` — always healthy (in-memory)
- `agentd`: `{"status":"healthy",...}` — depends on upstream services and authority store readiness

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

    # Agent Daemon
    location /agentd/ {
        proxy_pass http://127.0.0.1:7345/;
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
    handle_path /agentd/* {
        reverse_proxy localhost:7345
    }
}
```

### Production Checklist

1. Set `NODE_ENV=production` on all services
2. Set `SERVICE_API_KEY` to a strong random value (generated via `openssl rand -hex 32`); mutating endpoints fail closed with `503` in production when it is missing
3. Set `CORS_ORIGIN` to your frontend origin (not `*`)
4. Enable rate limiting via `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS`
5. Set `LOG_LEVEL=warn` to reduce noise, use `LOG_FORMAT=json` for log aggregation
6. Run PostgreSQL with TLS if accessed over untrusted networks
7. Run `pnpm --filter @fides/agentd db:migrate` before setting `AGENTD_DB_AUTO_MIGRATE=false`
8. Set `AGENTD_REQUIRE_AUTHORITY_SIGNATURE_VERIFICATION=true` once clients send signer public keys with delegated session, revocation, and incident writes
9. Rotate `SERVICE_API_KEY` periodically

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

### Registry (file-based)

The registry stores data at `~/.fides/registry/registry.json`. Back up this file:

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

### Relay (in-memory only)

The relay stores messages in memory only — no backup needed. Messages have a default TTL of 5 minutes.

---

## Monitoring

All services expose Prometheus metrics at `GET /metrics`:

| Service      | Metrics URL                  |
| ------------ | ---------------------------- |
| discovery    | `http://localhost:3100/metrics` |
| trust-graph  | `http://localhost:3200/metrics` |
| registry     | `http://localhost:7346/metrics` |
| relay        | `http://localhost:7347/metrics` |
| agentd       | `http://localhost:7345/metrics` |

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
```

### Key metrics

Each service reports:

- `http_requests_total` — total requests (labels: `method`, `path`, `status`)
- `http_request_duration_seconds` — latency histogram
- `http_requests_in_flight` — current in-flight requests

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
  (standalone, file-based)      │
                                │
relay ──────────────────────────┘
  (standalone, in-memory)
```

- `discovery` and `trust-graph` require PostgreSQL
- `trust-graph` additionally requires `discovery` for identity resolution
- `registry` is standalone — stores AgentCards on the filesystem
- `relay` is standalone — pure in-memory message queue
- `agentd` is a local proxy that depends on discovery, trust-graph, and registry

### Running a Minimal Setup

For development without PostgreSQL, you can run just registry, relay, and agentd:

```bash
node services/registry/dist/index.js &
node services/relay/dist/index.js &
AGENTD_PORT=7345 DISCOVERY_URL=http://localhost:3100 TRUST_GRAPH_URL=http://localhost:3200 REGISTRY_URL=http://localhost:7346 node services/agentd/dist/index.js &
```

Note: agentd health will show `degraded` when discovery or trust-graph are unreachable — this is expected in minimal mode.
