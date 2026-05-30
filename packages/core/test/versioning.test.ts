import { describe, expect, it } from 'vitest'
import {
  defaultVersionNegotiationRecord,
  isSupportedProtocolVersion,
  negotiateProtocolVersion,
} from '../src/versioning.js'
import { FIDES_PROTOCOL_VERSION } from '../src/protocol.js'
import { createDiscoveryQuery, negotiateDiscoveryCandidateVersion } from '../src/discovery.js'
import type { AgentCard } from '../src/agent-card.js'

describe('version negotiation', () => {
  it('negotiates the first common supported version', () => {
    const record = negotiateProtocolVersion({
      localSupported: ['fides.v2.0', 'fides.v2'],
      peerSupported: ['fides.v2', 'fides.v1'],
    })

    expect(record.compatible).toBe(true)
    expect(record.negotiated_version).toBe('fides.v2')
    expect(record.errors).toEqual([])
  })

  it('returns a typed compatibility error when no version matches', () => {
    const record = negotiateProtocolVersion({
      localSupported: ['fides.v2.0'],
      peerSupported: ['fides.v1'],
    })

    expect(record.compatible).toBe(false)
    expect(record.negotiated_version).toBeUndefined()
    expect(record.errors[0]).toMatchObject({
      code: 'VERSION_INCOMPATIBLE',
      category: 'version',
    })
  })

  it('honors required versions from both sides', () => {
    const record = negotiateProtocolVersion({
      localSupported: ['fides.v2.0'],
      peerSupported: ['fides.v2.0'],
      peerRequired: ['fides.v2.1'],
    })

    expect(record.compatible).toBe(false)
    expect(record.errors[0].code).toBe('VERSION_INCOMPATIBLE')
  })

  it('provides a default FIDES negotiation record', () => {
    const record = defaultVersionNegotiationRecord([FIDES_PROTOCOL_VERSION])

    expect(record.compatible).toBe(true)
    expect(record.required_versions).toEqual([FIDES_PROTOCOL_VERSION])
    expect(isSupportedProtocolVersion(record.negotiated_version!)).toBe(true)
  })

  it('negotiates discovery query versions against AgentCard protocol versions', () => {
    const card = {
      id: 'did:fides:agent',
      identity: {
        did: 'did:fides:agent',
        publicKey: new Uint8Array(32),
        keyType: 'Ed25519',
        createdAt: '2026-01-01T00:00:00.000Z',
      },
      capabilities: [],
      endpoints: [],
      policies: [],
      protocolVersions: ['fides.v2.0'],
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    } satisfies AgentCard

    const record = negotiateDiscoveryCandidateVersion(createDiscoveryQuery({
      supported_versions: ['fides.v2.0'],
      required_versions: ['fides.v2.0'],
    }), card)

    expect(record.compatible).toBe(true)
    expect(record.negotiated_version).toBe('fides.v2.0')
  })
})
