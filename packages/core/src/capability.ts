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
