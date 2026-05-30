import { spawn, execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import {
  createAgentIdentity,
  createDelegationTokenV2,
  createPrincipalIdentity,
  signDelegationTokenV2,
} from '@fides/core'

const execFileAsync = promisify(execFile)

const port = process.env.AGENTD_DX_SMOKE_PORT ?? '4819'
const baseUrl = `http://127.0.0.1:${port}`

async function main() {
  const workdir = await mkdtemp(join(tmpdir(), 'fides-agentd-dx-'))
  const sqlitePath = join(workdir, 'fides.sqlite')
  const authorityStorePath = join(workdir, 'authority-store.json')

  const agentd = spawn('pnpm', ['--filter', '@fides/agentd', 'dev'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      AGENTD_PORT: port,
      AGENTD_SQLITE_PATH: sqlitePath,
      AGENTD_STATE_STORE_PATH: authorityStorePath,
    },
  })

  const logs: string[] = []
  agentd.stdout.on('data', (chunk) => logs.push(String(chunk)))
  agentd.stderr.on('data', (chunk) => logs.push(String(chunk)))

  try {
    await waitForAgentd(sqlitePath, authorityStorePath)
    console.log(`ok agentd reachable at ${baseUrl}`)

    const demo = await runAgentdJson(['demo', 'run', '--json'])
    assert(demo.status === 'executed', `demo status was not executed: ${JSON.stringify(demo.status)}`)
    assert(demo.authority?.discoveryGrantsAuthority === false, 'demo must keep discovery non-authoritative')
    assert(demo.authority?.policyBeforeExecution === true, 'demo must enforce policy before execution')
    assert(demo.verification?.evidenceHashChainValid === true, 'demo evidence hash chain must verify')
    console.log('ok agentd demo run')

    const requester = await createAgentIdentity()
    const requesterPrivateKeyHex = Buffer.from(requester.privateKey).toString('hex')
    const requesterKeyPath = join(workdir, 'requester.key')
    await writeFile(requesterKeyPath, requesterPrivateKeyHex, { mode: 0o600 })

    const invoiceSession = await runAgentdJson([
      'session',
      'request',
      String(demo.identities?.invoice),
      '--capability',
      'invoice.reconcile',
      '--requested-scopes',
      'invoice:read',
      '--principal-id',
      String(demo.identities?.principal),
      '--requester-agent-id',
      requester.identity.did,
      '--agentd-url',
      baseUrl,
      '--json',
    ])
    const invoiceSessionId = assertString(invoiceSession.session?.session_id, 'signed invoke smoke session id')
    assert(invoiceSession.authorityGranted === true, 'signed invoke smoke session must grant execution authority')

    const signedInvocation = await runAgentdJson([
      'invoke',
      '--session-id',
      invoiceSessionId,
      '--input-json',
      '{"invoiceId":"inv_smoke_signed"}',
      '--sign',
      '--requester-private-key-file',
      requesterKeyPath,
      '--agentd-url',
      baseUrl,
      '--json',
    ])
    assert(signedInvocation.signedRequestVerified === true, 'signed invocation request must verify')
    assert(signedInvocation.signedResultVerified === true, 'signed invocation result must verify')
    assert(signedInvocation.authorityGranted === true, 'signed invocation must preserve execution authority')
    assert(signedInvocation.result?.status === 'completed', 'signed invocation must complete')
    assert(
      signedInvocation.signedRequest?.payload?.issuer === requester.identity.did,
      'signed invocation issuer must be the requester DID',
    )
    console.log('ok signed invocation CLI authority path')

    const delegator = await createPrincipalIdentity({
      type: 'individual',
      displayName: 'Smoke Delegator',
      verificationMethod: 'self_signed',
      verified: false,
    })
    const signedDelegationToken = await signDelegationTokenV2(
      createDelegationTokenV2({
        delegator: delegator.identity.did,
        delegatee: String(demo.identities?.invoice),
        capabilities: ['invoice.reconcile'],
        audience: ['agentd'],
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      }),
      delegator.privateKey,
      delegator.identity.did,
    )
    const signedTokenPath = join(workdir, 'signed-delegation-token-v2.json')
    await writeFile(signedTokenPath, JSON.stringify(signedDelegationToken, null, 2))
    const delegatedSession = await runAgentdJson([
      'session',
      'create',
      '--capability',
      'invoice.reconcile',
      '--token-file',
      signedTokenPath,
      '--agentd-url',
      baseUrl,
      '--json',
    ])
    assert(delegatedSession.authorized === true, 'canonical signed delegation token must authorize a session')
    assert(delegatedSession.signedDelegationVerified === true, 'canonical signed delegation token must verify')
    assert(delegatedSession.session?.id, 'canonical signed delegation session must include an id')
    console.log('ok signed delegation token CLI authority path')

    const discovery = await runAgentdJson(['discover', '--capability', 'invoice.reconcile', '--all-providers', '--json'])
    assert(discovery.authorityGranted === false, 'all-provider discovery must not grant authority')
    assertNoAuthorityGrantedTrue(discovery, 'all-provider discovery response')
    const discoveryResults = Array.isArray(discovery.results) ? discovery.results : []
    const providers = new Set(discoveryResults.map((entry: Record<string, any>) => entry.provider))
    for (const expected of ['local', 'well-known', 'registry', 'relay', 'dht', 'federation']) {
      assert(providers.has(expected), `all-provider discovery did not query ${expected}`)
    }
    assert(
      discoveryResults.some((entry: Record<string, any>) => entry.provider === 'local' && entry.ok === true),
      'all-provider discovery did not return a successful local provider result',
    )
    console.log('ok all-provider discovery')

    const simulation = await runAgentdJson(['simulate', 'adversarial', '--json'])
    assert(simulation.status === 'detected', `simulation status was not detected: ${JSON.stringify(simulation.status)}`)
    const detections = new Set(Array.isArray(simulation.detections) ? simulation.detections : [])
    for (const expected of [
      'fake_agent',
      'malicious_dht_pointer',
      'tampered_agent_card',
      'revoked_agent',
      'broken_evidence_chain',
    ]) {
      assert(detections.has(expected), `simulation did not detect ${expected}`)
    }
    assert(simulation.authority?.discoveryGrantsAuthority === false, 'simulation must keep discovery non-authoritative')
    assert(simulation.evidence?.rootChainValid === true, 'simulation root evidence chain must verify')
    assert(simulation.evidence?.brokenEvidenceChainValid === false, 'simulation must detect broken evidence chain')
    console.log('ok adversarial simulation')

    console.log('agentd dx smoke complete')
  } finally {
    agentd.kill('SIGTERM')
    await onceExit(agentd)
    await rm(workdir, { recursive: true, force: true })
  }

  function printAgentdLogs() {
    const output = logs.join('').trim()
    if (output) {
      console.error(output.split('\n').slice(-40).join('\n'))
    }
  }

  async function waitForAgentd(expectedSqlitePath: string, expectedAuthorityStorePath: string) {
    const startedAt = Date.now()
    let lastError = ''
    while (Date.now() - startedAt < 20_000) {
      try {
        const response = await fetch(`${baseUrl}/health`)
        const health = await response.json() as {
          service?: string
          authorityStore?: { ok?: boolean; detail?: string }
          localStateStore?: { ok?: boolean; path?: string }
        }
        if (
          health.service === 'agentd' &&
          health.authorityStore?.ok === true &&
          health.authorityStore.detail === expectedAuthorityStorePath &&
          health.localStateStore?.path === expectedSqlitePath
        ) {
          return
        }
        lastError = JSON.stringify(health)
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error)
      }
      await sleep(250)
    }
    printAgentdLogs()
    throw new Error(`agentd did not become ready with isolated state: ${lastError}`)
  }
}

async function runAgentdJson(args: string[]): Promise<Record<string, any>> {
  const { stdout } = await execFileAsync('pnpm', ['--silent', 'agentd', ...args], {
    env: {
      ...process.env,
      FIDES_AGENTD_URL: baseUrl,
    },
    maxBuffer: 20 * 1024 * 1024,
  })
  return JSON.parse(stdout) as Record<string, any>
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message)
}

function assertString(value: unknown, label: string): string {
  assert(typeof value === 'string' && value.length > 0, `${label} must be a non-empty string`)
  return value
}

function assertNoAuthorityGrantedTrue(value: unknown, label: string): void {
  if (!value || typeof value !== 'object') return
  if (Array.isArray(value)) {
    for (const item of value) {
      assertNoAuthorityGrantedTrue(item, label)
    }
    return
  }
  for (const [key, nested] of Object.entries(value)) {
    assert(!(key === 'authorityGranted' && nested === true), `${label} included authorityGranted: true`)
    assertNoAuthorityGrantedTrue(nested, label)
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function onceExit(child: ReturnType<typeof spawn>): Promise<void> {
  if (child.exitCode !== null) return Promise.resolve()
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      child.kill('SIGKILL')
      resolve()
    }, 2_000)
    child.once('exit', () => {
      clearTimeout(timeout)
      resolve()
    })
  })
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
