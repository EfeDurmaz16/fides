import {
  createDelegationToken,
  createIdentity,
  createRevocationRecord,
  signRevocationRecord,
  type AgentCard,
  type CapabilityDescriptor,
} from '@fides/core'
import { generateDID, generateKeyPair } from '@fides/sdk'

process.env.NODE_ENV = 'test'

async function main() {
  const [{ app: agentd }, { app: policyEngine }, { app: registry }] = await Promise.all([
    import('../services/agentd/src/index.js'),
    import('../services/policy-engine/src/index.js'),
    import('../services/registry/src/index.js'),
  ])

  const agentKey = await generateKeyPair()
  const principalKey = await generateKeyPair()
  const agentDid = generateDID(agentKey.publicKey)
  const principalDid = generateDID(principalKey.publicKey)

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
      {
        id: 'approval-for-new-merchant',
        condition: { operator: 'eq' as const, field: 'merchantSeen', value: false },
        action: 'approve-required' as const,
        explanation: 'New merchants require principal approval',
      },
    ],
    defaultAction: 'allow' as const,
  }

  console.log('FIDES authority path demo')
  console.log(`agent=${agentDid}`)
  console.log(`principal=${principalDid}`)

  const agentIdentity = createIdentity(agentDid, 'agent', { name: 'Demo Payment Agent' })
  const card: AgentCard = {
    id: agentDid,
    identity: agentIdentity,
    capabilities: [capability],
    endpoints: [
      {
        url: 'http://localhost:7345/v1/authorize',
        protocol: 'https',
        capabilities: [capability.id],
        auth: 'signature',
      },
    ],
    policies: [{ requiresRuntimeAttestation: true, requiresApproval: true, minTrustScore: 0.8 }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  const registerCard = await registry.request('/v1/cards', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(card),
  })
  await expectStatus(registerCard, 201, 'registered AgentCard')

  const policyAllow = await policyEngine.request('/v1/policies/evaluate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      policy,
      context: { amount: 25, merchantSeen: true },
      agentDid,
      capabilityId: capability.id,
    }),
  })
  await expectDecision(policyAllow, 'allow', 'policy allows bounded known merchant payment')

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

  const sessionResponse = await agentd.request('/v1/sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, capabilityId: capability.id, audience: 'agentd', ttlMs: 300_000 }),
  })
  await expectStatus(sessionResponse, 201, 'created delegated session')
  const { session } = await sessionResponse.json()

  const replayResponse = await agentd.request('/v1/sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, capabilityId: capability.id, audience: 'agentd' }),
  })
  await expectStatus(replayResponse, 409, 'rejected replayed delegation nonce')

  const authorizeResponse = await agentd.request('/v1/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agentDid,
      capabilityId: capability.id,
      sessionId: session.id,
      audience: 'agentd',
      policy,
      context: { amount: 25, merchantSeen: true },
      capabilityHighRisk: true,
      requiresRuntimeAttestation: true,
      attestationValid: true,
      requiresApproval: true,
      approvalGranted: true,
    }),
  })
  await expectDecision(authorizeResponse, 'allow', 'authorized payment execution')

  const evidenceResponse = await agentd.request(`/v1/evidence/${encodeURIComponent(agentDid)}`)
  await expectStatus(evidenceResponse, 200, 'read authorization evidence')
  const evidence = await evidenceResponse.json()
  if (evidence.count !== 1 || evidence.events[0].action !== 'authorization.allow') {
    throw new Error(`expected one authorization.allow evidence event, received ${JSON.stringify(evidence)}`)
  }
  console.log('ok evidence appended for allow decision')

  const revokeSession = await agentd.request(`/v1/sessions/${session.id}/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: 'demo session revoked' }),
  })
  await expectStatus(revokeSession, 200, 'revoked delegated session')

  const revokedSessionAuth = await agentd.request('/v1/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agentDid,
      capabilityId: capability.id,
      sessionId: session.id,
      audience: 'agentd',
    }),
  })
  await expectStatus(revokedSessionAuth, 403, 'denied revoked session invocation')

  const revokeAgent = await agentd.request('/v1/revocations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ record: await signRevocationRecord(createRevocationRecord({
      did: agentDid,
      reason: 'principal disabled demo agent',
      revokedBy: principalDid,
    }), principalKey.privateKey) }),
  })
  await expectStatus(revokeAgent, 201, 'recorded agent revocation')

  const revokedAgentAuth = await agentd.request('/v1/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      agentDid,
      capabilityId: capability.id,
      policy,
      context: { amount: 25, merchantSeen: true },
    }),
  })
  await expectStatus(revokedAgentAuth, 403, 'denied revoked agent invocation')

  console.log('authority path complete')
}

async function expectStatus(response: Response, expected: number, label: string) {
  if (response.status !== expected) {
    throw new Error(`${label}: expected HTTP ${expected}, received ${response.status}: ${await response.text()}`)
  }
  console.log(`ok ${label}`)
}

async function expectDecision(response: Response, expected: string, label: string) {
  await expectStatus(response, 200, label)
  const body = await response.json()
  if (body.decision !== expected) {
    throw new Error(`${label}: expected decision ${expected}, received ${JSON.stringify(body)}`)
  }
  console.log(`ok ${label}: ${expected}`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
