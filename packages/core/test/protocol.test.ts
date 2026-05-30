import { describe, expect, it } from 'vitest'
import {
  assertProtocolObjectBase,
  createProtocolSignatureInput,
  FIDES_PROTOCOL_VERSION,
  hashProtocolPayload,
  isProtocolObjectExpired,
} from '../src/protocol.js'

describe('protocol object foundation', () => {
  it('hashes protocol payloads with stable sha256 prefixes', () => {
    const first = hashProtocolPayload({ b: 2, a: 1 })
    const second = hashProtocolPayload({ a: 1, b: 2 })

    expect(first).toBe(second)
    expect(first).toMatch(/^sha256:[0-9a-f]{64}$/)
  })

  it('creates signature input from required protocol fields', () => {
    const payload = {
      schema_version: 'fides.test.v1',
      id: 'obj_123',
      issuer: 'did:fides:issuer',
      subject: 'did:fides:subject',
      issued_at: '2026-05-29T00:00:00.000Z',
      expires_at: '2026-05-30T00:00:00.000Z',
      value: 'ignored by signature input except hash',
    }

    const input = createProtocolSignatureInput(payload)

    expect(input).toMatchObject({
      schema_version: 'fides.test.v1',
      id: 'obj_123',
      issuer: 'did:fides:issuer',
      subject: 'did:fides:subject',
      issued_at: '2026-05-29T00:00:00.000Z',
      expires_at: '2026-05-30T00:00:00.000Z',
    })
    expect(input.payload_hash).toMatch(/^sha256:[0-9a-f]{64}$/)
  })

  it('treats invalid or elapsed expiration as expired', () => {
    expect(isProtocolObjectExpired({ expires_at: 'not-a-date' })).toBe(true)
    expect(isProtocolObjectExpired(
      { expires_at: '2026-05-28T00:00:00.000Z' },
      new Date('2026-05-29T00:00:00.000Z')
    )).toBe(true)
    expect(isProtocolObjectExpired(
      { expires_at: '2026-05-30T00:00:00.000Z' },
      new Date('2026-05-29T00:00:00.000Z')
    )).toBe(false)
  })

  it('requires schema version, id, issuer, and time field', () => {
    expect(() => assertProtocolObjectBase({
      schema_version: FIDES_PROTOCOL_VERSION,
      id: 'obj_123',
      issuer: 'did:fides:issuer',
      issued_at: '2026-05-29T00:00:00.000Z',
    })).not.toThrow()

    expect(() => assertProtocolObjectBase({
      schema_version: FIDES_PROTOCOL_VERSION,
      id: 'obj_123',
      issuer: 'did:fides:issuer',
    })).toThrow('created_at or issued_at')
  })
})
