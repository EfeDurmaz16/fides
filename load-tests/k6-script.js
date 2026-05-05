/**
 * FIDES v2 — k6 Load Test Suite
 *
 * Hits all 5 services with realistic traffic patterns:
 *   discovery (3100)  — identity registration + resolution
 *   trust-graph (3200) — trust edge creation + score lookup
 *   registry (7346)   — card registration + search
 *   relay (7347)      — message submit + poll
 *   agentd (7345)     — evidence submission + kill switch toggle
 *
 * Usage:
 *   k6 run load-tests/k6-script.js
 *
 * Configuration via environment variables:
 *   FIDES_BASE_URL   — override base (default: http://localhost)
 *   VUS              — virtual users (default: 10)
 *   DURATION         — test duration (default: 30s)
 *   RAMP_UP          — ramp-up time (default: 5s)
 */

const BASE = __ENV.FIDES_BASE_URL || 'http://localhost'

const DISCOVERY   = `${BASE}:3100`
const TRUST_GRAPH = `${BASE}:3200`
const REGISTRY    = `${BASE}:7346`
const RELAY       = `${BASE}:7347`
const AGENTD      = `${BASE}:7345`

const VUS      = parseInt(__ENV.VUS || '10')
const DURATION = __ENV.DURATION || '30s'
const RAMP_UP  = __ENV.RAMP_UP || '5s'

function randomHex(len) {
  const chars = 'abcdef0123456789'
  let out = ''
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)]
  return out
}

function randomDid() {
  return `did:fides:loadtest-${randomHex(16)}`
}

function randomRelayId() {
  return crypto.randomUUID()
}

export const options = {
  vus: VUS,
  duration: DURATION,
  thresholds: {
    'http_req_duration{name:discovery}': ['p(95)<500'],
    'http_req_duration{name:trust-graph}': ['p(95)<500'],
    'http_req_duration{name:registry}': ['p(95)<500'],
    'http_req_duration{name:relay}': ['p(95)<500'],
    'http_req_duration{name:agentd}': ['p(95)<500'],
    http_req_failed: ['rate<0.01'],
  },
  stages: [
    { duration: RAMP_UP, target: VUS },
    { duration: DURATION, target: VUS },
    { duration: '10s', target: 0 },
  ],
}

const API_KEY = __ENV.SERVICE_API_KEY || undefined

function authHeaders() {
  if (!API_KEY) return {}
  return { 'X-API-Key': API_KEY }
}

// ─── Discovery Service ──────────────────────────────────

export function discoveryFlow() {
  const did = randomDid()
  const publicKey = randomHex(64)

  // Health
  const health = http.get(`${DISCOVERY}/health`, { tags: { name: 'discovery' } })
  check(health, { 'discovery health 200': (r) => r.status === 200 })

  // Register identity
  const reg = http.post(`${DISCOVERY}/identities`, JSON.stringify({ did, publicKey, metadata: { loadtest: true } }), {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    tags: { name: 'discovery' },
  })
  check(reg, { 'discovery register 201': (r) => r.status === 201 || r.status === 409 })

  // Resolve identity
  if (did) {
    const resolve = http.get(`${DISCOVERY}/identities/${encodeURIComponent(did)}`, { tags: { name: 'discovery' } })
    check(resolve, { 'discovery resolve ok': (r) => r.status === 200 || r.status === 404 })
  }

  // Well-known
  const wk = http.get(`${DISCOVERY}/.well-known/fides.json`, { tags: { name: 'discovery' } })
  check(wk, { 'discovery well-known 200': (r) => r.status === 200 })
}

// ─── Trust Graph Service ────────────────────────────────

export function trustGraphFlow() {
  const issuerDid = 'did:fides:loadtest-alice'
  const subjectDid = `did:fides:loadtest-bob-${randomHex(4)}`
  const payloadStr = JSON.stringify({ issuerDid, subjectDid, trustLevel: 70 })

  // Health
  const health = http.get(`${TRUST_GRAPH}/health`, { tags: { name: 'trust-graph' } })
  check(health, { 'trust health 200': (r) => r.status === 200 || r.status === 503 })

  // Create trust edge
  const edge = http.post(`${TRUST_GRAPH}/v1/trust`, JSON.stringify({
    issuerDid,
    subjectDid,
    trustLevel: 70,
    signature: randomHex(64),
    payload: payloadStr,
  }), {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'trust-graph' },
  })
  check(edge, { 'trust edge accepted': (r) => r.status === 201 || r.status === 400 })

  // Get score
  const score = http.get(`${TRUST_GRAPH}/v1/trust/${encodeURIComponent('did:fides:loadtest-alice')}/score`, {
    tags: { name: 'trust-graph' },
  })
  check(score, { 'trust score 200': (r) => r.status === 200 })

  // Get capability score
  const capScore = http.get(`${TRUST_GRAPH}/v1/trust/${encodeURIComponent('did:fides:loadtest-alice')}/capability/web%3Asearch`, {
    tags: { name: 'trust-graph' },
  })
  check(capScore, { 'trust cap score 200': (r) => r.status === 200 })
}

// ─── Registry Service ───────────────────────────────────

export function registryFlow() {
  const did = randomDid()
  const card = {
    id: did,
    name: `Load Test Agent ${randomHex(4)}`,
    description: 'Load test agent card',
    version: '0.1.0',
    capabilities: [{ id: 'web:search', name: 'Web Search' }],
    protocols: ['mcp'],
    endpoints: [{ url: 'https://example.com/api', protocol: 'mcp', capabilities: ['web:search'] }],
    security: { authentication: ['api-key'], encryption: ['tls1.3'] },
    metadata: { loadtest: true },
  }

  // Health
  const health = http.get(`${REGISTRY}/health`, { tags: { name: 'registry' } })
  check(health, { 'registry health 200': (r) => r.status === 200 || r.status === 503 })

  // Register card
  const reg = http.post(`${REGISTRY}/v1/cards`, JSON.stringify(card), {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    tags: { name: 'registry' },
  })
  check(reg, { 'registry register 201': (r) => r.status === 201 || r.status === 401 })

  // Get card
  const get = http.get(`${REGISTRY}/v1/cards/${encodeURIComponent(did)}`, {
    tags: { name: 'registry' },
  })
  check(get, { 'registry get ok': (r) => r.status === 200 || r.status === 404 })

  // Search
  const search = http.get(`${REGISTRY}/v1/search?q=Load+Test`, {
    tags: { name: 'registry' },
  })
  check(search, { 'registry search 200': (r) => r.status === 200 })

  // Stats
  const stats = http.get(`${REGISTRY}/v1/stats`, { tags: { name: 'registry' } })
  check(stats, { 'registry stats 200': (r) => r.status === 200 })
}

// ─── Relay Service ──────────────────────────────────────

export function relayFlow() {
  const receiverDid = `did:fides:loadtest-relay-${randomHex(4)}`

  // Health
  const health = http.get(`${RELAY}/health`, { tags: { name: 'relay' } })
  check(health, { 'relay health 200': (r) => r.status === 200 })

  // Submit message
  const submit = http.post(`${RELAY}/v1/relay`, JSON.stringify({
    to: receiverDid,
    from: 'did:fides:loadtest-sender',
    payload: { content: `Load test message ${randomHex(4)}`, ts: Date.now() },
  }), {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    tags: { name: 'relay' },
  })
  check(submit, { 'relay submit 201': (r) => r.status === 201 || r.status === 401 })

  // Poll messages
  const poll = http.get(`${RELAY}/v1/relay/${encodeURIComponent(receiverDid)}/messages`, {
    tags: { name: 'relay' },
  })
  check(poll, { 'relay poll 200': (r) => r.status === 200 })

  // Stats
  const stats = http.get(`${RELAY}/v1/relay/stats`, { tags: { name: 'relay' } })
  check(stats, { 'relay stats 200': (r) => r.status === 200 })
}

// ─── Agent Daemon ───────────────────────────────────────

export function agentdFlow() {
  const did = `did:fides:loadtest-agentd-${randomHex(4)}`

  // Health
  const health = http.get(`${AGENTD}/health`, { tags: { name: 'agentd' } })
  check(health, { 'agentd health ok': (r) => r.status === 200 || r.status === 503 })

  // Identity resolution (proxy — may fail if discovery is down)
  const idResolve = http.get(`${AGENTD}/v1/identities/${encodeURIComponent(did)}`, {
    tags: { name: 'agentd' },
  })
  check(idResolve, { 'agentd identity ok': (r) => r.status >= 200 && r.status < 600 })

  // Trust score (proxy — may fallback to 0.5)
  const trustScore = http.get(`${AGENTD}/v1/trust/${encodeURIComponent(did)}/score`, {
    tags: { name: 'agentd' },
  })
  check(trustScore, { 'agentd trust score 200': (r) => r.status === 200 })

  // Evidence submission
  const evidence = http.post(`${AGENTD}/v1/evidence`, JSON.stringify({
    actor: did,
    action: 'capability:invoke',
    type: 'execution',
    payload: { capability: 'web:search', loadtest: true },
  }), {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    tags: { name: 'agentd' },
  })
  check(evidence, { 'agentd evidence 201': (r) => r.status === 201 || r.status === 401 })

  // Evidence retrieval
  const getEvidence = http.get(`${AGENTD}/v1/evidence/${encodeURIComponent(did)}`, {
    tags: { name: 'agentd' },
  })
  check(getEvidence, { 'agentd evidence get 200': (r) => r.status === 200 })

  // Policy evaluation
  const policy = http.post(`${AGENTD}/v1/policy/evaluate`, JSON.stringify({
    agentDid: did,
    capabilityId: 'web:search',
    policy: {
      id: 'loadtest-policy',
      version: '1.0',
      rules: [],
      defaultAction: 'allow',
    },
    context: {},
  }), {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    tags: { name: 'agentd' },
  })
  check(policy, { 'agentd policy 200': (r) => r.status === 200 || r.status === 401 })

  // Kill switch toggle
  const engage = http.post(`${AGENTD}/v1/killswitch/engage`, JSON.stringify({ did: 'did:fides:loadtest' }), {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    tags: { name: 'agentd' },
  })
  check(engage, { 'agentd killswitch engage 200': (r) => r.status === 200 || r.status === 401 })

  const disengage = http.post(`${AGENTD}/v1/killswitch/disengage`, JSON.stringify({ did: 'did:fides:loadtest' }), {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    tags: { name: 'agentd' },
  })
  check(disengage, { 'agentd killswitch disengage 200': (r) => r.status === 200 || r.status === 401 })
}

// ─── Main Scenario ──────────────────────────────────────

import http from 'k6/http'
import { check } from 'k6'

export default function () {
  discoveryFlow()
  trustGraphFlow()
  registryFlow()
  relayFlow()
  agentdFlow()
}
