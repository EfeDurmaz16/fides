import { describe, expect, it } from 'vitest'
import { createIncidentRecordV2 } from '../src/index.js'

describe('@fides/incidents facade', () => {
  it('exports incident record primitives', () => {
    const incident = createIncidentRecordV2({
      reporter: 'did:fides:reporter',
      targetAgentId: 'did:fides:agent',
      severity: 'high',
      category: 'policy_violation',
      description: 'Policy violation in facade contract test',
      evidenceRefs: ['evidence_1'],
    })

    expect(incident.schema_version).toBe('fides.incident.record.v1')
    expect(incident.category).toBe('policy_violation')
  })
})
