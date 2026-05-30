import type { CapabilityDescriptor } from '@fides/core'

export interface ExampleCapability {
  id: string
  riskLevel: CapabilityDescriptor['riskLevel']
  requiredScopes: string[]
  dryRunSupported: boolean
  humanApprovalSupported: boolean
  policyProofSupported: boolean
}

export interface ExampleAgentManifest {
  id: string
  name: string
  role: 'calendar' | 'invoice' | 'payment' | 'requester' | 'malicious'
  capabilities: ExampleCapability[]
  authorityNotes: string[]
}

export const exampleAgentCatalog: ExampleAgentManifest[] = [
  {
    id: 'calendar-agent',
    name: 'Calendar Agent',
    role: 'calendar',
    capabilities: [
      {
        id: 'calendar.schedule',
        riskLevel: 'low',
        requiredScopes: ['calendar:write'],
        dryRunSupported: true,
        humanApprovalSupported: false,
        policyProofSupported: true,
      },
    ],
    authorityNotes: [
      'Local discovery returns this agent as a candidate only.',
      'A scoped SessionGrant is still required before invocation.',
    ],
  },
  {
    id: 'invoice-agent',
    name: 'Invoice Agent',
    role: 'invoice',
    capabilities: [
      {
        id: 'invoice.reconcile',
        riskLevel: 'medium',
        requiredScopes: ['invoice:read'],
        dryRunSupported: true,
        humanApprovalSupported: true,
        policyProofSupported: true,
      },
    ],
    authorityNotes: [
      'Registry discovery is non-authoritative.',
      'Policy evaluation must run before invoice reconciliation.',
    ],
  },
  {
    id: 'payment-agent',
    name: 'Payment Agent',
    role: 'payment',
    capabilities: [
      {
        id: 'payments.prepare',
        riskLevel: 'high',
        requiredScopes: ['payments:prepare'],
        dryRunSupported: true,
        humanApprovalSupported: true,
        policyProofSupported: true,
      },
      {
        id: 'payments.execute',
        riskLevel: 'critical',
        requiredScopes: ['payments:execute'],
        dryRunSupported: false,
        humanApprovalSupported: true,
        policyProofSupported: true,
      },
    ],
    authorityNotes: [
      'Generic FIDES demos use payment preparation in dry-run mode.',
      'Payment execution remains Sardis-specific and must not execute in FIDES.',
    ],
  },
  {
    id: 'requester-agent',
    name: 'Requester Agent',
    role: 'requester',
    capabilities: [
      {
        id: 'agent.request',
        riskLevel: 'medium',
        requiredScopes: ['agents:invoke'],
        dryRunSupported: true,
        humanApprovalSupported: true,
        policyProofSupported: true,
      },
    ],
    authorityNotes: [
      'Discovers candidates and requests scoped sessions.',
      'Does not treat discovery, identity, or trust score as authority.',
    ],
  },
  {
    id: 'malicious-agent',
    name: 'Malicious Agent',
    role: 'malicious',
    capabilities: [
      {
        id: 'payments.execute',
        riskLevel: 'critical',
        requiredScopes: ['payments:execute'],
        dryRunSupported: false,
        humanApprovalSupported: false,
        policyProofSupported: false,
      },
    ],
    authorityNotes: [
      'Used by adversarial simulation for tampering, context laundering, revocation, and broken evidence-chain checks.',
      'Expected outcome is detection, trust penalty, policy denial, and evidence.',
    ],
  },
] as const

export function findExampleAgent(id: string): ExampleAgentManifest | undefined {
  return exampleAgentCatalog.find(agent => agent.id === id)
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify({ agents: exampleAgentCatalog }, null, 2))
}
