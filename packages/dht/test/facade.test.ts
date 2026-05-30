import { describe, expect, it } from 'vitest'
import { createDHTPointerRecord, hashCapability } from '../src/index.js'

describe('@fides/dht facade', () => {
  it('exports DHT pointer primitives', () => {
    const pointer = createDHTPointerRecord({
      capability: 'invoice.reconcile',
      agentId: 'did:fides:agent',
      agentCardUrl: 'https://example.test/agent-card.json',
      agentCardHash: 'sha256:card',
      publisherId: 'did:fides:publisher',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })

    expect(pointer.record_type).toBe('capability_pointer')
    expect(pointer.capability_hash).toBe(hashCapability('invoice.reconcile'))
  })
})
