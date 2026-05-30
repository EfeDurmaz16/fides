import { describe, expect, it } from 'vitest'
import { createIdentityKeyPair } from '../src/identity.js'
import {
  createIncidentRecordV2,
  createRevocationRecordV2,
  resolveIncidentRecordV2,
  signIncidentRecordV2,
  signRevocationRecordV2,
  verifySignedIncidentRecordV2,
  verifySignedIncidentRecordV2Issuer,
  verifySignedRevocationRecordV2,
  verifySignedRevocationRecordV2Issuer,
} from '../src/revocation.js'

describe('revocation and incident v2 records', () => {
  it('creates and verifies signed revocation records for sessions and attestations', async () => {
    const issuer = await createIdentityKeyPair()
    const record = createRevocationRecordV2({
      issuer: issuer.did,
      targetType: 'session',
      targetId: 'sess_123',
      reason: 'Session nonce replay detected',
      evidenceRefs: ['evt_1'],
    })

    expect(record).toMatchObject({
      schema_version: 'fides.revocation.record.v1',
      issuer: issuer.did,
      subject: 'sess_123',
      target_type: 'session',
      target_id: 'sess_123',
      status: 'active',
      evidence_refs: ['evt_1'],
    })
    expect(record.payload_hash).toMatch(/^sha256:/)

    const signed = await signRevocationRecordV2(record, issuer.privateKey, issuer.did)
    expect(await verifySignedRevocationRecordV2(signed)).toBe(true)
    expect(await verifySignedRevocationRecordV2Issuer(signed)).toBe(true)
  })

  it('creates and resolves signed incident records with trust impact metadata', async () => {
    const reporter = await createIdentityKeyPair()
    const incident = createIncidentRecordV2({
      reporter: reporter.did,
      targetAgentId: 'did:fides:agent',
      severity: 'high',
      category: 'prompt_injection_failure',
      description: 'Agent ignored policy context and leaked tool output.',
      evidenceRefs: ['evt_2'],
    })

    expect(incident).toMatchObject({
      schema_version: 'fides.incident.record.v1',
      issuer: reporter.did,
      subject: 'did:fides:agent',
      reporter: reporter.did,
      target_agent_id: 'did:fides:agent',
      severity: 'high',
      category: 'prompt_injection_failure',
      resolution_status: 'open',
      evidence_refs: ['evt_2'],
    })
    expect(incident.trust_penalty).toBeGreaterThan(0)
    expect(incident.payload_hash).toMatch(/^sha256:/)

    const signed = await signIncidentRecordV2(incident, reporter.privateKey, reporter.did)
    expect(await verifySignedIncidentRecordV2(signed)).toBe(true)
    expect(await verifySignedIncidentRecordV2Issuer(signed)).toBe(true)

    const resolved = resolveIncidentRecordV2(incident, 'false_positive')
    expect(resolved.resolution_status).toBe('false_positive')
    expect(resolved.resolved_at).toBeDefined()
    expect(resolved.payload_hash).not.toBe(incident.payload_hash)
  })

  it('rejects revocation and incident proofs whose verification method is not the issuer', async () => {
    const issuer = await createIdentityKeyPair()
    const attacker = await createIdentityKeyPair()
    const revocation = createRevocationRecordV2({
      issuer: issuer.did,
      targetType: 'agent',
      targetId: 'did:fides:agent',
      reason: 'Compromised agent identity',
    })
    const incident = createIncidentRecordV2({
      reporter: issuer.did,
      targetAgentId: 'did:fides:agent',
      severity: 'critical',
      category: 'unauthorized_action',
      description: 'Agent attempted an unauthorized action.',
    })

    const signedRevocation = await signRevocationRecordV2(revocation, attacker.privateKey, attacker.did)
    const signedIncident = await signIncidentRecordV2(incident, attacker.privateKey, attacker.did)

    expect(await verifySignedRevocationRecordV2(signedRevocation)).toBe(true)
    expect(await verifySignedRevocationRecordV2Issuer(signedRevocation)).toBe(false)
    expect(await verifySignedIncidentRecordV2(signedIncident)).toBe(true)
    expect(await verifySignedIncidentRecordV2Issuer(signedIncident)).toBe(false)
  })
})
