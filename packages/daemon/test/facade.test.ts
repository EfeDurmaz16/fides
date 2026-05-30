import { describe, expect, it } from 'vitest'
import { createDaemonClient, defaultDaemonConfig, wellKnownDaemonEndpoints } from '../src/index.js'

describe('@fides/daemon boundary', () => {
  it('exposes local daemon defaults and well-known endpoints', () => {
    const config = defaultDaemonConfig('/tmp/fides-home')

    expect(config.daemonUrl).toBe('http://localhost:7345')
    expect(config.databasePath).toBe('/tmp/fides-home/.fides/fides.sqlite')
    expect(config.evidenceDir).toBe('/tmp/fides-home/.fides/evidence')
    expect(wellKnownDaemonEndpoints('http://agentd.test/')).toEqual([
      'http://agentd.test/.well-known/fides.json',
      'http://agentd.test/.well-known/agents.json',
    ])
  })

  it('creates a Promise-based SDK client for the daemon surface', () => {
    const client = createDaemonClient({ daemonUrl: 'http://agentd.test' })

    expect(client).toMatchObject({
      identity: expect.any(Object),
      discovery: expect.any(Object),
      sessions: expect.any(Object),
    })
  })
})
