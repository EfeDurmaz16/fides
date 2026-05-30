import { describe, expect, it } from 'vitest'
import { createRegistryIndexRecord } from '../src/index.js'

describe('@fides/registry facade', () => {
  it('exports registry index record primitives', () => {
    const record = createRegistryIndexRecord({
      issuer: 'did:fides:registry',
      mode: 'public',
      agentCardId: 'card_1',
      agentId: 'did:fides:agent',
      capabilityIds: ['invoice.reconcile'],
      agentCardHash: 'sha256:card',
      registryUrl: 'https://registry.example.test',
      supportedVersions: ['fides.v2.0'],
    })

    expect(record.schema_version).toBe('fides.registry.index.v1')
    expect(record.capability_ids).toEqual(['invoice.reconcile'])
  })
})
