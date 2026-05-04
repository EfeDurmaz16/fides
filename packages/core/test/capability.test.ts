import { describe, it, expect } from 'vitest'
import { classifyCapabilityRisk } from '../src/capability.js'

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
})
