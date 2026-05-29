/**
 * FIDES v2 Capability Descriptor
 *
 * A CapabilityDescriptor defines a single capability that an agent claims
 * it can perform. It includes input/output schemas, risk classification,
 * and authorization requirements.
 */

export interface JSONSchema {
  type: string
  properties?: Record<string, unknown>
  required?: string[]
  [key: string]: unknown
}

export interface CapabilityDescriptor {
  /** Unique capability ID (URL-friendly) */
  id: string
  /** Namespace such as calendar, invoice, payments, code, file, deploy. */
  namespace?: string
  /** Action verb such as schedule, reconcile, prepare, execute, read, write. */
  action?: string
  /** Resource class this capability acts on. */
  resource?: string
  /** Human-readable name */
  name: string
  /** Human-readable description */
  description: string
  /** JSON Schema for input validation */
  inputSchema: JSONSchema
  /** JSON Schema for output validation */
  outputSchema: JSONSchema
  /** Risk level of this capability */
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  /** Whether invocation requires explicit approval */
  requiresApproval: boolean
  /** Whether invocation requires runtime attestation (e.g., TEE) */
  requiresRuntimeAttestation: boolean
  /** Required scopes for delegated sessions. */
  requiredScopes?: string[]
  /** Controls supported by this capability. */
  supportedControls?: CapabilityControl[]
  /** Whether this capability supports dry-run. */
  supportsDryRun?: boolean
  /** Whether this capability supports explicit human approval. */
  supportsHumanApproval?: boolean
  /** Whether this capability can produce policy proof/evidence. */
  supportsPolicyProof?: boolean
}

export type CapabilityControl =
  | 'dry_run'
  | 'human_approval'
  | 'policy_proof'
  | 'runtime_attestation'
  | 'scope_limit'
  | 'rate_limit'

export interface CapabilityOntologyEntry {
  schema_version: 'fides.capability_ontology_entry.v1'
  id: string
  namespace: string
  action: string
  resource: string
  riskClass: CapabilityDescriptor['riskLevel']
  description: string
  defaultRequiredScopes: string[]
  supportedControls: CapabilityControl[]
}

/**
 * Determine the risk level of a capability based on its ID/name heuristics.
 * This is a simple default classifier; production systems should use
 * a more sophisticated ontology.
 */
export function classifyCapabilityRisk(name: string): CapabilityDescriptor['riskLevel'] {
  const lower = name.toLowerCase()
  const criticalKeywords = ['pay', 'payment', 'transfer', 'withdraw', 'delete', 'destroy', 'purge']
  const highKeywords = ['write', 'update', 'modify', 'deploy', 'provision', 'purchase']
  const mediumKeywords = ['read', 'get', 'list', 'search', 'query']

  if (criticalKeywords.some(k => lower.includes(k))) return 'critical'
  if (highKeywords.some(k => lower.includes(k))) return 'high'
  if (mediumKeywords.some(k => lower.includes(k))) return 'medium'
  return 'low'
}

export function parseCapabilityId(id: string): Pick<CapabilityDescriptor, 'namespace' | 'action' | 'resource'> {
  const [namespace, action, ...resourceParts] = id.split('.')
  return {
    ...(namespace && { namespace }),
    ...(action && { action }),
    ...(resourceParts.length > 0 && { resource: resourceParts.join('.') }),
  }
}

export function createCapabilityDescriptor(input: {
  id: string
  name?: string
  description?: string
  inputSchema?: JSONSchema
  outputSchema?: JSONSchema
  riskLevel?: CapabilityDescriptor['riskLevel']
  requiredScopes?: string[]
  supportedControls?: CapabilityControl[]
  supportsDryRun?: boolean
  supportsHumanApproval?: boolean
  supportsPolicyProof?: boolean
}): CapabilityDescriptor {
  const parsed = parseCapabilityId(input.id)
  const supportedControls = input.supportedControls ?? [
    ...(input.supportsDryRun ? ['dry_run' as const] : []),
    ...(input.supportsHumanApproval ? ['human_approval' as const] : []),
    ...(input.supportsPolicyProof ? ['policy_proof' as const] : []),
  ]

  return {
    id: input.id,
    ...parsed,
    name: input.name ?? input.id,
    description: input.description ?? input.id,
    inputSchema: input.inputSchema ?? { type: 'object' },
    outputSchema: input.outputSchema ?? { type: 'object' },
    riskLevel: input.riskLevel ?? classifyCapabilityRisk(input.id),
    requiresApproval: input.supportsHumanApproval ?? supportedControls.includes('human_approval'),
    requiresRuntimeAttestation: supportedControls.includes('runtime_attestation'),
    requiredScopes: input.requiredScopes ?? [],
    supportedControls,
    supportsDryRun: input.supportsDryRun ?? supportedControls.includes('dry_run'),
    supportsHumanApproval: input.supportsHumanApproval ?? supportedControls.includes('human_approval'),
    supportsPolicyProof: input.supportsPolicyProof ?? supportedControls.includes('policy_proof'),
  }
}

export const DEFAULT_CAPABILITY_ONTOLOGY: CapabilityOntologyEntry[] = [
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'calendar.schedule',
    namespace: 'calendar',
    action: 'schedule',
    resource: 'event',
    riskClass: 'low',
    description: 'Schedule or update calendar events.',
    defaultRequiredScopes: ['calendar:write'],
    supportedControls: ['dry_run', 'human_approval'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'invoice.reconcile',
    namespace: 'invoice',
    action: 'reconcile',
    resource: 'invoice',
    riskClass: 'medium',
    description: 'Reconcile invoice records against supporting data.',
    defaultRequiredScopes: ['invoice:read', 'invoice:write'],
    supportedControls: ['dry_run', 'policy_proof'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'payments.prepare',
    namespace: 'payments',
    action: 'prepare',
    resource: 'payment',
    riskClass: 'high',
    description: 'Prepare a payment plan without executing funds movement.',
    defaultRequiredScopes: ['payments:prepare'],
    supportedControls: ['dry_run', 'human_approval', 'policy_proof', 'runtime_attestation'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'payments.execute',
    namespace: 'payments',
    action: 'execute',
    resource: 'payment',
    riskClass: 'critical',
    description: 'Execute payment movement. Generic FIDES should route this to Sardis-specific authority.',
    defaultRequiredScopes: ['payments:execute'],
    supportedControls: ['human_approval', 'policy_proof', 'runtime_attestation'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'code.review',
    namespace: 'code',
    action: 'review',
    resource: 'change',
    riskClass: 'medium',
    description: 'Review code changes and produce findings.',
    defaultRequiredScopes: ['code:read'],
    supportedControls: ['policy_proof'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'code.merge',
    namespace: 'code',
    action: 'merge',
    resource: 'change',
    riskClass: 'high',
    description: 'Merge code changes into a protected branch.',
    defaultRequiredScopes: ['code:write'],
    supportedControls: ['human_approval', 'policy_proof'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'file.read',
    namespace: 'file',
    action: 'read',
    resource: 'file',
    riskClass: 'medium',
    description: 'Read local or remote file contents.',
    defaultRequiredScopes: ['file:read'],
    supportedControls: ['scope_limit'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'file.write',
    namespace: 'file',
    action: 'write',
    resource: 'file',
    riskClass: 'high',
    description: 'Write or update file contents.',
    defaultRequiredScopes: ['file:write'],
    supportedControls: ['dry_run', 'human_approval', 'scope_limit'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'file.delete',
    namespace: 'file',
    action: 'delete',
    resource: 'file',
    riskClass: 'critical',
    description: 'Delete file contents.',
    defaultRequiredScopes: ['file:delete'],
    supportedControls: ['human_approval', 'scope_limit'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'deploy.preview',
    namespace: 'deploy',
    action: 'preview',
    resource: 'deployment',
    riskClass: 'medium',
    description: 'Create a preview deployment.',
    defaultRequiredScopes: ['deploy:preview'],
    supportedControls: ['policy_proof'],
  },
  {
    schema_version: 'fides.capability_ontology_entry.v1',
    id: 'deploy.production',
    namespace: 'deploy',
    action: 'production',
    resource: 'deployment',
    riskClass: 'critical',
    description: 'Deploy to production.',
    defaultRequiredScopes: ['deploy:production'],
    supportedControls: ['human_approval', 'policy_proof', 'runtime_attestation'],
  },
]
