import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createDelegationToken } from '@fides/core'

const execFileAsync = promisify(execFile)

const services = {
  discovery: 'http://127.0.0.1:3100',
  trustGraph: 'http://127.0.0.1:3200',
  registry: 'http://127.0.0.1:7346',
  relay: 'http://127.0.0.1:7347',
  agentd: 'http://127.0.0.1:7345',
} as const

const serviceApiKey = process.env.SERVICE_API_KEY

async function main() {
  console.log('FIDES docker compose smoke')

  for (const [name, url] of Object.entries(services)) {
    await waitForHealth(name, url)
  }

  await assertAgentdUsesPostgres()
  await runAuthorityFlow()

  console.log('docker compose smoke complete')
}

async function runAuthorityFlow() {
  const runId = crypto.randomUUID().slice(0, 8)
  const agentDid = `did:fides:docker-agent-${runId}`
  const principalDid = `did:fides:docker-principal-${runId}`
  const capabilityId = 'payments.execute'

  const token = {
    ...createDelegationToken({
      delegator: principalDid,
      delegatee: agentDid,
      capabilities: [capabilityId],
      constraints: { maxActions: 3, maxSpend: '100.00', allowedContexts: ['docker-smoke'] },
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      audience: ['agentd'],
    }),
    signature: '00'.repeat(64),
  }

  const sessionResponse = await postJson(`${services.agentd}/v1/sessions`, {
    token,
    capabilityId,
    audience: 'agentd',
    ttlMs: 300_000,
  })
  await expectStatus(sessionResponse, 201, 'created delegated session')
  const { session } = await sessionResponse.json() as { session: { id: string } }

  await expectStatus(await postJson(`${services.agentd}/v1/sessions`, {
    token,
    capabilityId,
    audience: 'agentd',
  }), 409, 'rejected replayed delegation nonce')

  await expectDecision(await postJson(`${services.agentd}/v1/authorize`, {
    agentDid,
    capabilityId,
    sessionId: session.id,
    audience: 'agentd',
    context: { amount: 25 },
  }), 'allow', 'authorized delegated execution')

  await expectStatus(await fetch(`${services.agentd}/v1/evidence/${encodeURIComponent(agentDid)}`), 200, 'read evidence chain')

  console.log('restarting agentd to verify Postgres authority persistence')
  await execFileAsync('docker', ['compose', 'restart', 'agentd'], {
    env: { ...process.env, POSTGRES_PASSWORD: process.env.POSTGRES_PASSWORD || 'fides' },
  })
  await waitForHealth('agentd', services.agentd)
  await assertAgentdUsesPostgres()

  const persistedSession = await fetch(`${services.agentd}/v1/sessions/${encodeURIComponent(session.id)}`)
  await expectStatus(persistedSession, 200, 'read session after agentd restart')

  await expectStatus(await postJson(`${services.agentd}/v1/sessions/${session.id}/revoke`, {
    reason: 'docker smoke session revoked',
  }), 200, 'revoked delegated session')

  await expectStatus(await postJson(`${services.agentd}/v1/authorize`, {
    agentDid,
    capabilityId,
    sessionId: session.id,
    audience: 'agentd',
  }), 403, 'denied revoked session invocation')

  const revocationResponse = await postJson(`${services.agentd}/v1/revocations`, {
    did: agentDid,
    reason: 'principal disabled docker smoke agent',
    revokedBy: principalDid,
  })
  await expectStatus(revocationResponse, 201, 'recorded agent revocation')

  const incidentResponse = await postJson(`${services.agentd}/v1/incidents`, {
    actor: agentDid,
    reporter: principalDid,
    type: 'policy_violation',
    severity: 'high',
    description: 'Docker smoke incident report',
  })
  await expectStatus(incidentResponse, 201, 'recorded incident')
}

async function assertAgentdUsesPostgres() {
  const response = await fetch(`${services.agentd}/health`)
  await expectStatus(response, 200, 'agentd health')
  const body = await response.json() as { authorityStore?: { kind?: string, ok?: boolean } }
  if (body.authorityStore?.kind !== 'postgres' || body.authorityStore.ok !== true) {
    throw new Error(`agentd authority store is not ready postgres: ${JSON.stringify(body)}`)
  }
  console.log('ok agentd authority store is postgres')
}

async function waitForHealth(name: string, url: string): Promise<void> {
  const deadline = Date.now() + 90_000
  let last = ''

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${url}/health`)
      if (response.ok) {
        console.log(`ok ${name} healthy`)
        return
      }
      last = `HTTP ${response.status}: ${await response.text()}`
    } catch (error) {
      last = error instanceof Error ? error.message : String(error)
    }
    await sleep(1000)
  }

  throw new Error(`${name} did not become healthy: ${last}`)
}

async function postJson(url: string, body: unknown): Promise<Response> {
  const headers = new Headers({ 'Content-Type': 'application/json' })
  if (serviceApiKey) {
    headers.set('X-API-Key', serviceApiKey)
  }

  return fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  })
}

async function expectStatus(response: Response, expected: number, label: string): Promise<void> {
  if (response.status !== expected) {
    throw new Error(`${label}: expected HTTP ${expected}, received ${response.status}: ${await response.text()}`)
  }
  console.log(`ok ${label}`)
}

async function expectDecision(response: Response, expected: string, label: string): Promise<void> {
  await expectStatus(response, 200, label)
  const body = await response.json() as { decision?: string }
  if (body.decision !== expected) {
    throw new Error(`${label}: expected decision ${expected}, received ${JSON.stringify(body)}`)
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

if (process.env.FIDES_SMOKE_SKIP_MAIN !== 'true') {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
