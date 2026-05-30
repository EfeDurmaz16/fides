import { describe, expect, it } from 'vitest'
import { canonicalDigest, canonicalJson } from '../src/index.js'

describe('@fides/crypto facade', () => {
  it('exports canonical JSON and digest primitives', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}')
    expect(canonicalDigest({ ok: true })).toBeInstanceOf(Uint8Array)
  })
})
