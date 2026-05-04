import { describe, it, expect } from 'vitest'
import { evaluatePolicy, runPreExecutionPipeline } from '../src/index.js'
import type { PolicyBundle, PolicyContext } from '../src/index.js'

describe('Policy Engine', () => {
  const bundle: PolicyBundle = {
    id: 'test-bundle',
    version: '1.0.0',
    defaultAction: 'deny',
    rules: [
      {
        id: 'allow-admin',
        condition: { operator: 'eq', field: 'role', value: 'admin' },
        action: 'allow',
        explanation: 'Admins are allowed',
      },
      {
        id: 'high-risk-approval',
        condition: { operator: 'eq', field: 'risk', value: 'high' },
        action: 'approve-required',
        explanation: 'High risk actions need approval',
      },
      {
        id: 'block-guest',
        condition: { operator: 'eq', field: 'role', value: 'guest' },
        action: 'deny',
        explanation: 'Guests are blocked',
      },
    ],
  }

  it('should allow admin', () => {
    const ctx: PolicyContext = { role: 'admin', risk: 'low' }
    const result = evaluatePolicy(bundle, ctx)
    expect(result.decision).toBe('allow')
    expect(result.matchedRules).toContain('allow-admin')
  })

  it('should require approval for high risk', () => {
    const ctx: PolicyContext = { role: 'user', risk: 'high' }
    const result = evaluatePolicy(bundle, ctx)
    expect(result.decision).toBe('approve-required')
    expect(result.matchedRules).toContain('high-risk-approval')
  })

  it('should deny guest', () => {
    const ctx: PolicyContext = { role: 'guest', risk: 'low' }
    const result = evaluatePolicy(bundle, ctx)
    expect(result.decision).toBe('deny')
    expect(result.matchedRules).toContain('block-guest')
  })

  it('should use default action when no rules match', () => {
    const ctx: PolicyContext = { role: 'user', risk: 'low' }
    const result = evaluatePolicy(bundle, ctx)
    expect(result.decision).toBe('deny')
    expect(result.matchedRules).toHaveLength(0)
  })

  it('should support lt operator', () => {
    const b: PolicyBundle = {
      id: 'num',
      version: '1',
      defaultAction: 'deny',
      rules: [{ id: 'r1', condition: { operator: 'lt', field: 'score', value: 50 }, action: 'allow', explanation: '' }],
    }
    expect(evaluatePolicy(b, { score: 30 }).decision).toBe('allow')
    expect(evaluatePolicy(b, { score: 60 }).decision).toBe('deny')
  })
})

describe('Pre-execution Pipeline', () => {
  it('should allow when all guards pass', async () => {
    const result = await runPreExecutionPipeline([
      { name: 'g1', evaluate: () => 'allow' },
      { name: 'g2', evaluate: () => 'allow' },
    ], {})
    expect(result.decision).toBe('allow')
  })

  it('should block on first block guard', async () => {
    const result = await runPreExecutionPipeline([
      { name: 'g1', evaluate: () => 'allow' },
      { name: 'g2', evaluate: () => 'block' },
    ], {})
    expect(result.decision).toBe('block')
    expect(result.blockingGuard).toBe('g2')
  })
})
