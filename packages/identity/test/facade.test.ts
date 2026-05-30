import { describe, expect, it } from 'vitest'
import { createAgentIdentity, isValidFidesDid } from '../src/index.js'

describe('@fides/identity facade', () => {
  it('exports identity creation and DID validation primitives', async () => {
    const createdAt = '2026-05-30T00:00:00.000Z'
    const { identity } = await createAgentIdentity({ createdAt })

    expect(isValidFidesDid(identity.did)).toBe(true)
    expect(identity.createdAt).toBe(createdAt)
  })
})
