import { describe, expect, it } from 'vitest'
import {
  ADAPTER_KINDS,
  createAdapterMapping,
  isPaymentAdapterKind,
} from '../src/index.js'

describe('FIDES interop adapter interfaces', () => {
  it('declares the required adapter kinds without external runtime dependencies', () => {
    expect(ADAPTER_KINDS).toEqual([
      'mcp',
      'a2a',
      'oaps',
      'osp',
      'ap2',
      'x402',
      'sardis',
    ])
  })

  it('creates mapping records for identity, capabilities, policy, evidence, and invocation', () => {
    const mapping = createAdapterMapping({
      kind: 'oaps',
      externalId: 'oaps:actor:invoice-agent',
      fidesAgentId: 'did:fides:agent',
      capabilityIds: ['invoice.reconcile'],
      supportsDelegation: true,
      supportsPolicy: true,
      supportsEvidence: true,
      supportsInvocation: true,
    })

    expect(mapping).toMatchObject({
      schema_version: 'fides.adapter.mapping.v1',
      kind: 'oaps',
      external_id: 'oaps:actor:invoice-agent',
      fides_agent_id: 'did:fides:agent',
      capability_ids: ['invoice.reconcile'],
      supports_delegation: true,
      supports_policy: true,
      supports_evidence: true,
      supports_invocation: true,
    })
  })

  it('marks AP2, x402, and Sardis as payment/action-flow adapters', () => {
    expect(isPaymentAdapterKind('ap2')).toBe(true)
    expect(isPaymentAdapterKind('x402')).toBe(true)
    expect(isPaymentAdapterKind('sardis')).toBe(true)
    expect(isPaymentAdapterKind('mcp')).toBe(false)
  })
})
