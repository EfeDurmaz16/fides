# FIDES v2 Load Tests

Load tests using [k6](https://k6.io) (Grafana k6) that hit all 5 FIDES services
with realistic traffic patterns.

## Prerequisites

Install k6:

**macOS:**
```bash
brew install k6
```

**Linux (Debian/Ubuntu):**
```bash
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6
```

**Docker:**
```bash
docker run --rm -i grafana/k6 run - < load-tests/k6-script.js
```

**Other platforms:** See https://k6.io/docs/get-started/installation/

## Services Tested

| Service | Port | What's Tested |
|---------|------|---------------|
| Discovery | 3100 | Identity registration, resolution, well-known |
| Trust Graph | 3200 | Trust edge creation, score lookup, capability score |
| Registry | 7346 | AgentCard registration, search, stats |
| Relay | 7347 | Message submit, poll, stats |
| Agentd | 7345 | Evidence submit/retrieval, kill switch toggle, policy eval, proxy endpoints |

## Running

### All services (local)

Start all services first, then:

```bash
cd fides
k6 run load-tests/k6-script.js
```

### Custom configuration

```bash
# Run with 50 virtual users for 2 minutes
k6 run -e VUS=50 -e DURATION=2m load-tests/k6-script.js

# Run against staging
k6 run -e FIDES_BASE_URL=https://staging.fides.example.com load-tests/k6-script.js

# With API key auth
k6 run -e SERVICE_API_KEY=your-api-key load-tests/k6-script.js
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FIDES_BASE_URL` | `http://localhost` | Base URL (port is appended per service) |
| `VUS` | `10` | Number of virtual users |
| `DURATION` | `30s` | Test duration after ramp-up |
| `RAMP_UP` | `5s` | Ramp-up period |
| `SERVICE_API_KEY` | *(none)* | API key for write-endpoint auth |

## Thresholds

The test enforces these thresholds (build fails if breached):

- **p95 latency < 500ms** for each service
- **Error rate < 1%** overall

## Traffic Patterns

Each virtual user iteration makes ~20 requests across all services:
- 4 discovery (health, register, resolve, well-known)
- 3 trust-graph (health, create edge, score lookup)
- 4 registry (health, register, search, stats)
- 3 relay (health, submit, poll)
- 6 agentd (health, identity resolve, trust score, evidence submit, policy eval, kill switch toggle)

With 10 VUs over 30 seconds, expect ~600-2000 total requests depending on latency.
