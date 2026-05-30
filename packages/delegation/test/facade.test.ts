import { describe, expect, it } from 'vitest'
import { createDelegationToken, validateDelegationToken } from '../src/index.js'

describe('@fides/delegation facade', () => {
  it('exports delegation token primitives', () => {
    const token = createDelegationToken({
      delegator: 'did:fides:principal',
      delegatee: 'did:fides:agent',
      capabilities: ['invoice.reconcile'],
      constraints: { maxInvocations: 1 },
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    })

    expect(token.capabilities).toEqual(['invoice.reconcile'])
    expect(validateDelegationToken({ ...token, signature: 'local-test-signature' }).valid).toBe(true)
  })
})
