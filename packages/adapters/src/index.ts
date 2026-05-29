export const ADAPTER_KINDS = [
  'mcp',
  'a2a',
  'oaps',
  'osp',
  'ap2',
  'x402',
  'sardis',
] as const

export type AdapterKind = typeof ADAPTER_KINDS[number]

export interface AdapterMapping {
  schema_version: 'fides.adapter.mapping.v1'
  id: string
  kind: AdapterKind
  external_id: string
  fides_agent_id?: string
  fides_publisher_id?: string
  fides_principal_id?: string
  capability_ids: string[]
  supports_delegation: boolean
  supports_policy: boolean
  supports_evidence: boolean
  supports_invocation: boolean
  created_at: string
}

export interface AdapterMappingInput {
  kind: AdapterKind
  externalId: string
  fidesAgentId?: string
  fidesPublisherId?: string
  fidesPrincipalId?: string
  capabilityIds?: string[]
  supportsDelegation?: boolean
  supportsPolicy?: boolean
  supportsEvidence?: boolean
  supportsInvocation?: boolean
  createdAt?: string
}

export interface FidesInteropAdapter<TExternal = unknown> {
  readonly kind: AdapterKind
  toFidesMapping(external: TExternal): Promise<AdapterMapping> | AdapterMapping
}

export function createAdapterMapping(input: AdapterMappingInput): AdapterMapping {
  return {
    schema_version: 'fides.adapter.mapping.v1',
    id: crypto.randomUUID(),
    kind: input.kind,
    external_id: input.externalId,
    fides_agent_id: input.fidesAgentId,
    fides_publisher_id: input.fidesPublisherId,
    fides_principal_id: input.fidesPrincipalId,
    capability_ids: input.capabilityIds ?? [],
    supports_delegation: input.supportsDelegation ?? false,
    supports_policy: input.supportsPolicy ?? false,
    supports_evidence: input.supportsEvidence ?? false,
    supports_invocation: input.supportsInvocation ?? false,
    created_at: input.createdAt ?? new Date().toISOString(),
  }
}

export function isAdapterKind(value: string): value is AdapterKind {
  return (ADAPTER_KINDS as readonly string[]).includes(value)
}

export function isPaymentAdapterKind(kind: AdapterKind): boolean {
  return kind === 'ap2' || kind === 'x402' || kind === 'sardis'
}
