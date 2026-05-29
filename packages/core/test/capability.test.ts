import { describe, it, expect } from 'vitest'
import {
  DEFAULT_CAPABILITY_ONTOLOGY,
  classifyCapabilityRisk,
  createCapabilityDescriptor,
  parseCapabilityId,
} from '../src/capability.js'

describe('CapabilityDescriptor', () => {
  describe('classifyCapabilityRisk', () => {
    it('should classify payment as critical', () => {
      expect(classifyCapabilityRisk('processPayment')).toBe('critical')
      expect(classifyCapabilityRisk('transferFunds')).toBe('critical')
    })

    it('should classify write as high', () => {
      expect(classifyCapabilityRisk('updateRecord')).toBe('high')
      expect(classifyCapabilityRisk('deployService')).toBe('high')
    })

    it('should classify read as medium', () => {
      expect(classifyCapabilityRisk('getUser')).toBe('medium')
      expect(classifyCapabilityRisk('listItems')).toBe('medium')
    })

    it('should classify unknown as low', () => {
      expect(classifyCapabilityRisk('ping')).toBe('low')
      expect(classifyCapabilityRisk('healthCheck')).toBe('low')
    })
  })

  describe('capability ontology', () => {
    it('parses namespace and action from capability ids', () => {
      expect(parseCapabilityId('invoice.reconcile')).toEqual({
        namespace: 'invoice',
        action: 'reconcile',
      })
      expect(parseCapabilityId('deploy.production.web')).toEqual({
        namespace: 'deploy',
        action: 'production',
        resource: 'web',
      })
    })

    it('creates v2 capability descriptors with controls and scopes', () => {
      const capability = createCapabilityDescriptor({
        id: 'payments.prepare',
        requiredScopes: ['payments:prepare'],
        supportedControls: ['dry_run', 'human_approval', 'policy_proof', 'runtime_attestation'],
      })

      expect(capability).toMatchObject({
        id: 'payments.prepare',
        namespace: 'payments',
        action: 'prepare',
        riskLevel: 'critical',
        requiredScopes: ['payments:prepare'],
        requiresApproval: true,
        requiresRuntimeAttestation: true,
        supportsDryRun: true,
        supportsHumanApproval: true,
        supportsPolicyProof: true,
      })
    })

    it('ships the requested seed ontology entries', () => {
      const ids = DEFAULT_CAPABILITY_ONTOLOGY.map(entry => entry.id)

      expect(ids).toEqual(expect.arrayContaining([
        'calendar.schedule',
        'invoice.reconcile',
        'payments.prepare',
        'payments.execute',
        'code.review',
        'code.merge',
        'file.read',
        'file.write',
        'file.delete',
        'deploy.preview',
        'deploy.production',
      ]))
      expect(DEFAULT_CAPABILITY_ONTOLOGY.find(entry => entry.id === 'payments.execute')).toMatchObject({
        riskClass: 'critical',
        supportedControls: expect.arrayContaining(['human_approval', 'runtime_attestation']),
      })
    })
  })
})
