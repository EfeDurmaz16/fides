import { describe, expect, it } from 'vitest'
import {
  ADAPTER_KINDS,
  ADAPTER_PROTOCOL_SURFACES,
  createAdapterManifest,
  createAdapterMapping,
  createInteropMappingSet,
  defaultSurfacesForAdapter,
  isAdapterProtocolSurface,
  isPaymentAdapterKind,
  validateAdapterCoverage,
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

  it('declares protocol surfaces that adapters can map without protocol SDK dependencies', () => {
    expect(ADAPTER_PROTOCOL_SURFACES).toEqual([
      'identity',
      'agent_card',
      'capability',
      'discovery',
      'trust',
      'policy',
      'delegation',
      'session',
      'approval',
      'invocation',
      'evidence',
      'attestation',
      'revocation',
      'incident',
      'payment_action_flow',
    ])
    expect(isAdapterProtocolSurface('evidence')).toBe(true)
    expect(isAdapterProtocolSurface('unknown')).toBe(false)
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

  it('creates manifests with default generic surfaces', () => {
    const manifest = createAdapterManifest({
      kind: 'mcp',
      name: 'MCP adapter',
      version: '0.1.0',
    })

    expect(manifest).toMatchObject({
      schema_version: 'fides.adapter.manifest.v1',
      kind: 'mcp',
      name: 'MCP adapter',
      version: '0.1.0',
      payment_specific: false,
      runtime_dependency_required: false,
    })
    expect(manifest.surfaces).toEqual(expect.arrayContaining([
      'identity',
      'agent_card',
      'capability',
      'trust',
      'delegation',
      'policy',
      'evidence',
      'invocation',
    ]))
  })

  it('keeps payment action-flow surfaces scoped to payment adapters', () => {
    expect(defaultSurfacesForAdapter('sardis')).toContain('payment_action_flow')
    expect(defaultSurfacesForAdapter('x402')).toContain('payment_action_flow')
    expect(defaultSurfacesForAdapter('ap2')).toContain('payment_action_flow')
    expect(defaultSurfacesForAdapter('oaps')).toContain('trust')
    expect(defaultSurfacesForAdapter('oaps')).not.toContain('payment_action_flow')

    const manifest = createAdapterManifest({ kind: 'sardis', name: 'Sardis adapter' })
    expect(manifest.payment_specific).toBe(true)
    expect(manifest.surfaces).toContain('approval')
    expect(manifest.surfaces).toContain('attestation')
    expect(manifest.surfaces).toContain('revocation')
  })

  it('builds mapping sets across FIDES protocol surfaces', () => {
    const mapping = createInteropMappingSet({
      kind: 'oaps',
      externalId: 'oaps:flow:invoice-reconcile',
      identities: {
        agent: {
          did: 'did:fides:agent',
          publicKey: new Uint8Array(32),
          keyType: 'Ed25519',
          createdAt: '2026-01-01T00:00:00.000Z',
        },
      },
      capabilities: [{
        id: 'invoice.reconcile',
        namespace: 'invoice',
        action: 'reconcile',
        resource: 'invoice',
        name: 'invoice.reconcile',
        description: 'Reconcile invoices',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' },
        riskLevel: 'medium',
        requiresApproval: false,
        requiresRuntimeAttestation: false,
      }],
      policyDecisions: [{ decision: 'allow', reason_codes: ['POLICY_ALLOWED'] }],
      evidenceEvents: [{ type: 'policy.evaluated', actor: 'did:fides:agent' }],
    })

    expect(mapping).toMatchObject({
      schema_version: 'fides.adapter.mapping_set.v1',
      kind: 'oaps',
      external_id: 'oaps:flow:invoice-reconcile',
    })
    expect(mapping.identities.agent?.did).toBe('did:fides:agent')
    expect(mapping.capabilities[0]?.id).toBe('invoice.reconcile')
    expect(mapping.policy_decisions[0]?.decision).toBe('allow')
    expect(mapping.evidence_events[0]?.type).toBe('policy.evaluated')
    expect(mapping.approvals).toEqual({ requests: [], decisions: [] })
    expect(mapping.invocations).toEqual({ requests: [], results: [] })
  })

  it('reports missing required surfaces for adapter readiness checks', () => {
    const manifest = createAdapterManifest({
      kind: 'osp',
      name: 'OSP adapter',
      surfaces: ['identity', 'discovery'],
    })

    const report = validateAdapterCoverage(manifest, ['identity', 'discovery', 'revocation'])
    expect(report).toEqual({
      valid: false,
      missing: ['revocation'],
    })
  })
})
