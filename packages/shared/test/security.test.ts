import { describe, expect, it } from 'vitest'
import { timingSafeStringEqual } from '../src/security.js'

describe('timingSafeStringEqual', () => {
  it('accepts identical strings', () => {
    expect(timingSafeStringEqual('service-key', 'service-key')).toBe(true)
  })

  it('rejects strings with equal length but different contents', () => {
    expect(timingSafeStringEqual('service-key', 'service-zzz')).toBe(false)
  })

  it('rejects strings with different lengths', () => {
    expect(timingSafeStringEqual('service-key', 'service-key-with-suffix')).toBe(false)
  })
})
