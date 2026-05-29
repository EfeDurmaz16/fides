import { describe, expect, it } from 'vitest'
import {
  defaultVersionNegotiationRecord,
  isSupportedProtocolVersion,
  negotiateProtocolVersion,
} from '../src/versioning.js'
import { FIDES_PROTOCOL_VERSION } from '../src/protocol.js'

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
})
