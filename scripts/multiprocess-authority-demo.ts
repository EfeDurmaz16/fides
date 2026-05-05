import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createDelegationToken,
  createIdentity,
  type AgentCard,
  type CapabilityDescriptor,
} from '@fides/core'

interface ServiceProcess {
  name: string
  url: string
  child: ChildProcessWithoutNullStreams
}

const ports = {
  discovery: 43100,
  trustGraph: 43200,
  policyEngine: 43300,
  agentd: 47345,
  registry: 47346,
  relay: 47347,
}

const services = [
  {
    name: 'discovery',
    script: 'services/discovery/src/index.ts',
    port: ports.discovery,
    env: { DISCOVERY_PORT: String(ports.discovery), PORT: String(ports.discovery) },
  },
  {
    name: 'trust-graph',
    script: 'services/trust-graph/src/index.ts',
    port: ports.trustGraph,
    env: {
      TRUST_GRAPH_PORT: String(ports.trustGraph),
      PORT: String(ports.trustGraph),
      DISCOVERY_URL: `http://127.0.0.1:${ports.discovery}`,
    },
  },
  {
    name: 'registry',
    script: 'services/registry/src/index.ts',
    port: ports.registry,
    env: { REGISTRY_PORT: String(ports.registry) },
  },
  {
    name: 'relay',
    script: 'services/relay/src/index.ts',
    port: ports.relay,
    env: { RELAY_PORT: String(ports.relay) },
  },
  {
    name: 'policy-engine',
    script: 'services/policy-engine/src/index.ts',
    port: ports.policyEngine,
    env: { POLICY_ENGINE_PORT: String(ports.policyEngine), PORT: String(ports.policyEngine) },
  },
  {
    name: 'agentd',
    script: 'services/agentd/src/index.ts',
    port: ports.agentd,
    env: {
      AGENTD_PORT: String(ports.agentd),
      DISCOVERY_URL: `http://127.0.0.1:${ports.discovery}`,
      TRUST_GRAPH_URL: `http://127.0.0.1:${ports.trustGraph}`,
      REGISTRY_URL: `http://127.0.0.1:${ports.registry}`,
    },
  },
] as const

async function main() {
  const stateDir = await mkdtemp(join(tmpdir(), 'fides-authority-demo-'))
  const processes: ServiceProcess[] = []

  try {
    console.log('FIDES multi-process authority demo')
    for (const service of services) {
      const serviceProcess = spawnService(service.name, service.script, service.port, {
        ...service.env,
        AGENTD_AUTHORITY_STORE: 'file',
        AGENTD_STATE_STORE_PATH: join(stateDir, 'agentd-authority.json'),
      })
      processes.push(serviceProcess)
    }

    for (const service of processes) {
      await waitForService(service)
    }

    await runAuthorityFlow()
    console.log('multi-process authority path complete')
  } finally {
    await Promise.allSettled(processes.map(stopService))
    await rm(stateDir, { recursive: true, force: true })
  }
}

function spawnService(
  name: string,
  script: string,
  port: number,
  env: Record<string, string>
): ServiceProcess {
  const child = spawn('pnpm', ['exec', 'tsx', script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ...env,
      NODE_ENV: 'development',
      SERVICE_API_KEY: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  child.stdout.on('data', (chunk) => {
    process.stdout.write(`[${name}] ${chunk}`)
  })
  child.stderr.on('data', (chunk) => {
    process.stderr.write(`[${name}] ${chunk}`)
  })

  return { name, url: `http://127.0.0.1:${port}`, child }
}

async function waitForService(service: ServiceProcess): Promise<void> {
  const deadline = Date.now() + 15_000
  let lastError = ''

  while (Date.now() < deadline) {
    if (service.child.exitCode !== null) {
      throw new Error(`${service.name} exited before readiness with code ${service.child.exitCode}`)
    }

    try {
      const response = await fetch(`${service.url}/health`)
      if (response.status < 600) {
        console.log(`ok ${service.name} reachable: HTTP ${response.status}`)
        return
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error)
    }

    await sleep(250)
  }

  throw new Error(`${service.name} did not become reachable: ${lastError}`)
}

async function runAuthorityFlow() {
  const runId = crypto.randomUUID().slice(0, 8)
  const agentDid = `did:fides:process-agent-${runId}`
  const principalDid = `did:fides:process-principal-${runId}`

  const capability: CapabilityDescriptor = {
    id: 'payments.execute',
    name: 'Execute Payment',
    description: 'Execute a bounded payment on behalf of a principal',
    inputSchema: { type: 'object', required: ['amount', 'merchant'] },
    outputSchema: { type: 'object' },
    riskLevel: 'critical',
    requiresApproval: true,
    requiresRuntimeAttestation: true,
  }

  const policy = {
    id: 'authority-path-policy',
    version: '1.0.0',
    rules: [
      {
        id: 'deny-large-payment',
        condition: { operator: 'gt' as const, field: 'amount', value: 1000 },
        action: 'deny' as const,
        explanation: 'Large payments require a separate mandate',
      },
    ],
    defaultAction: 'allow' as const,
  }

  const card: AgentCard = {
    id: agentDid,
    identity: createIdentity(agentDid, 'agent', { name: 'Process Demo Payment Agent' }),
    capabilities: [capability],
    endpoints: [
      {
        url: `http://127.0.0.1:${ports.agentd}/v1/authorize`,
        protocol: 'https',
        capabilities: [capability.id],
        auth: 'signature',
      },
    ],
    policies: [{ requiresRuntimeAttestation: true, requiresApproval: true, minTrustScore: 0.8 }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  await expectStatus(await postJson(`http://127.0.0.1:${ports.registry}/v1/cards`, card), 201, 'registered AgentCard')
  await expectDecision(await postJson(`http://127.0.0.1:${ports.policyEngine}/v1/policies/evaluate`, {
    policy,
    context: { amount: 25 },
    agentDid,
    capabilityId: capability.id,
  }), 'allow', 'policy-engine allowed bounded action')

  const token = {
    ...createDelegationToken({
      delegator: principalDid,
      delegatee: agentDid,
      capabilities: [capability.id],
      constraints: { maxActions: 3, maxSpend: '100.00', allowedContexts: ['demo'] },
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      audience: ['agentd'],
    }),
    signature: '00'.repeat(64),
  }

  const sessionResponse = await postJson(`http://127.0.0.1:${ports.agentd}/v1/sessions`, {
    token,
    capabilityId: capability.id,
    audience: 'agentd',
    ttlMs: 300_000,
  })
  await expectStatus(sessionResponse, 201, 'created delegated session')
  const { session } = await sessionResponse.json() as { session: { id: string } }

  await expectStatus(await postJson(`http://127.0.0.1:${ports.agentd}/v1/sessions`, {
    token,
    capabilityId: capability.id,
    audience: 'agentd',
  }), 409, 'rejected replayed delegation nonce')

  await expectDecision(await postJson(`http://127.0.0.1:${ports.agentd}/v1/authorize`, {
    agentDid,
    capabilityId: capability.id,
    sessionId: session.id,
    audience: 'agentd',
    policy,
    context: { amount: 25 },
    capabilityHighRisk: true,
    requiresRuntimeAttestation: true,
    attestationValid: true,
    requiresApproval: true,
    approvalGranted: true,
  }), 'allow', 'authorized delegated execution')

  await expectStatus(await fetch(`http://127.0.0.1:${ports.agentd}/v1/evidence/${encodeURIComponent(agentDid)}`), 200, 'read evidence chain')
  await expectStatus(await postJson(`http://127.0.0.1:${ports.agentd}/v1/sessions/${session.id}/revoke`, {
    reason: 'process demo session revoked',
  }), 200, 'revoked delegated session')
  await expectStatus(await postJson(`http://127.0.0.1:${ports.agentd}/v1/authorize`, {
    agentDid,
    capabilityId: capability.id,
    sessionId: session.id,
    audience: 'agentd',
  }), 403, 'denied revoked session invocation')
  await expectStatus(await postJson(`http://127.0.0.1:${ports.agentd}/v1/revocations`, {
    did: agentDid,
    reason: 'principal disabled process demo agent',
    revokedBy: principalDid,
  }), 201, 'recorded agent revocation')
  await expectStatus(await postJson(`http://127.0.0.1:${ports.agentd}/v1/incidents`, {
    actor: agentDid,
    reporter: principalDid,
    type: 'policy_violation',
    severity: 'high',
    description: 'Process demo incident report',
  }), 201, 'recorded incident')
}

async function postJson(url: string, body: unknown): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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

async function stopService(service: ServiceProcess): Promise<void> {
  if (service.child.exitCode !== null) return
  service.child.kill('SIGTERM')
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      if (service.child.exitCode === null) service.child.kill('SIGKILL')
      resolve()
    }, 3000)
    service.child.once('exit', () => {
      clearTimeout(timeout)
      resolve()
    })
  })
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
