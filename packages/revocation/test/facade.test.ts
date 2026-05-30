import { describe, expect, it } from 'vitest'
import { createRevocationRecordV2 } from '../src/index.js'

describe('@fides/revocation facade', () => {
  it('exports revocation record primitives', () => {
    const record = createRevocationRecordV2({
      issuer: 'did:fides:issuer',
      targetType: 'agent',
      targetId: 'did:fides:agent',
      reason: 'manual revoke',
    })

    expect(record.schema_version).toBe('fides.revocation.record.v1')
    expect(record.target_type).toBe('agent')
  })
})
