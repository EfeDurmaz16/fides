import type {
  AgentCard,
  ApprovalDecision,
  ApprovalRequest,
  CapabilityDescriptor,
  DelegationToken,
  DiscoveryCandidate,
  IncidentRecordV2,
  InvocationRequest,
  InvocationResult,
  PrincipalIdentity,
  PublisherIdentity,
  RevocationRecordV2,
  RuntimeAttestation,
  SessionGrantV2,
  TrustResult,
  AgentIdentity,
} from '@fides/core'

export interface AdapterPolicyDecision {
  schema_version?: string
  decision: string
  reason_codes?: string[]
  evidence_refs?: string[]
  [key: string]: unknown
}

export interface AdapterEvidenceEvent {
  schema_version?: string
  event_id?: string
  type: string
  actor: string
  subject?: string
  evidence_refs?: string[]
  [key: string]: unknown
}

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

export const ADAPTER_PROTOCOL_SURFACES = [
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
] as const

export type AdapterProtocolSurface = typeof ADAPTER_PROTOCOL_SURFACES[number]

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

export interface AdapterManifest {
  schema_version: 'fides.adapter.manifest.v1'
  id: string
  kind: AdapterKind
  name: string
  version: string
  surfaces: AdapterProtocolSurface[]
  payment_specific: boolean
  runtime_dependency_required: boolean
  created_at: string
}

export interface InteropMappingSet {
  schema_version: 'fides.adapter.mapping_set.v1'
  id: string
  kind: AdapterKind
  external_id: string
  identities: {
    agent?: AgentIdentity
    publisher?: PublisherIdentity
    principal?: PrincipalIdentity
  }
  agent_card?: AgentCard
  capabilities: CapabilityDescriptor[]
  discovery_candidates: DiscoveryCandidate[]
  trust_results: TrustResult[]
  policy_decisions: AdapterPolicyDecision[]
  delegation_tokens: DelegationToken[]
  session_grants: SessionGrantV2[]
  approvals: {
    requests: ApprovalRequest[]
    decisions: ApprovalDecision[]
  }
  invocations: {
    requests: InvocationRequest[]
    results: InvocationResult[]
  }
  evidence_events: AdapterEvidenceEvent[]
  runtime_attestations: RuntimeAttestation[]
  revocations: RevocationRecordV2[]
  incidents: IncidentRecordV2[]
  payment_action_flows: unknown[]
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

export interface AdapterManifestInput {
  kind: AdapterKind
  name: string
  version?: string
  surfaces?: AdapterProtocolSurface[]
  runtimeDependencyRequired?: boolean
  createdAt?: string
}

export interface InteropMappingSetInput {
  kind: AdapterKind
  externalId: string
  identities?: InteropMappingSet['identities']
  agentCard?: AgentCard
  capabilities?: CapabilityDescriptor[]
  discoveryCandidates?: DiscoveryCandidate[]
  trustResults?: TrustResult[]
  policyDecisions?: AdapterPolicyDecision[]
  delegationTokens?: DelegationToken[]
  sessionGrants?: SessionGrantV2[]
  approvals?: Partial<InteropMappingSet['approvals']>
  invocations?: Partial<InteropMappingSet['invocations']>
  evidenceEvents?: AdapterEvidenceEvent[]
  runtimeAttestations?: RuntimeAttestation[]
  revocations?: RevocationRecordV2[]
  incidents?: IncidentRecordV2[]
  paymentActionFlows?: unknown[]
  createdAt?: string
}

export interface AdapterCoverageReport {
  valid: boolean
  missing: AdapterProtocolSurface[]
}

export interface FidesInteropAdapter<TExternal = unknown> {
  readonly kind: AdapterKind
  readonly manifest: AdapterManifest
  toFidesMapping(external: TExternal): Promise<AdapterMapping> | AdapterMapping
  toFidesMappingSet?(external: TExternal): Promise<InteropMappingSet> | InteropMappingSet
  fromFidesMappingSet?(mapping: InteropMappingSet): Promise<TExternal> | TExternal
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

export function createAdapterManifest(input: AdapterManifestInput): AdapterManifest {
  return {
    schema_version: 'fides.adapter.manifest.v1',
    id: crypto.randomUUID(),
    kind: input.kind,
    name: input.name,
    version: input.version ?? '0.1.0',
    surfaces: input.surfaces ?? defaultSurfacesForAdapter(input.kind),
    payment_specific: isPaymentAdapterKind(input.kind),
    runtime_dependency_required: input.runtimeDependencyRequired ?? false,
    created_at: input.createdAt ?? new Date().toISOString(),
  }
}

export function createInteropMappingSet(input: InteropMappingSetInput): InteropMappingSet {
  return {
    schema_version: 'fides.adapter.mapping_set.v1',
    id: crypto.randomUUID(),
    kind: input.kind,
    external_id: input.externalId,
    identities: input.identities ?? {},
    agent_card: input.agentCard,
    capabilities: input.capabilities ?? [],
    discovery_candidates: input.discoveryCandidates ?? [],
    trust_results: input.trustResults ?? [],
    policy_decisions: input.policyDecisions ?? [],
    delegation_tokens: input.delegationTokens ?? [],
    session_grants: input.sessionGrants ?? [],
    approvals: {
      requests: input.approvals?.requests ?? [],
      decisions: input.approvals?.decisions ?? [],
    },
    invocations: {
      requests: input.invocations?.requests ?? [],
      results: input.invocations?.results ?? [],
    },
    evidence_events: input.evidenceEvents ?? [],
    runtime_attestations: input.runtimeAttestations ?? [],
    revocations: input.revocations ?? [],
    incidents: input.incidents ?? [],
    payment_action_flows: input.paymentActionFlows ?? [],
    created_at: input.createdAt ?? new Date().toISOString(),
  }
}

export function isAdapterKind(value: string): value is AdapterKind {
  return (ADAPTER_KINDS as readonly string[]).includes(value)
}

export function isAdapterProtocolSurface(value: string): value is AdapterProtocolSurface {
  return (ADAPTER_PROTOCOL_SURFACES as readonly string[]).includes(value)
}

export function isPaymentAdapterKind(kind: AdapterKind): boolean {
  return kind === 'ap2' || kind === 'x402' || kind === 'sardis'
}

export function defaultSurfacesForAdapter(kind: AdapterKind): AdapterProtocolSurface[] {
  const generic: AdapterProtocolSurface[] = [
    'identity',
    'agent_card',
    'capability',
    'delegation',
    'policy',
    'evidence',
    'invocation',
  ]

  if (kind === 'osp') {
    return ['identity', 'agent_card', 'capability', 'discovery', 'revocation']
  }

  if (isPaymentAdapterKind(kind)) {
    return [...generic, 'session', 'approval', 'attestation', 'revocation', 'incident', 'payment_action_flow']
  }

  return generic
}

export function validateAdapterCoverage(
  manifest: AdapterManifest,
  requiredSurfaces: AdapterProtocolSurface[]
): AdapterCoverageReport {
  const provided = new Set(manifest.surfaces)
  const missing = requiredSurfaces.filter(surface => !provided.has(surface))
  return {
    valid: missing.length === 0,
    missing,
  }
}
