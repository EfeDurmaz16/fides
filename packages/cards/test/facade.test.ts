import { describe, expect, it } from 'vitest'
import { classifyCapabilityRisk, createCapabilityDescriptor } from '../src/index.js'

describe('@fides/cards facade', () => {
  it('exports capability descriptor and risk taxonomy primitives', () => {
    const descriptor = createCapabilityDescriptor({ id: 'payments.execute' })

    expect(descriptor.id).toBe('payments.execute')
    expect(classifyCapabilityRisk('payments.execute')).toBe('critical')
  })
})
