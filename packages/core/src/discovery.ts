import type { AgentCard } from './agent-card.js'
import type { ErrorEnvelope } from './errors.js'
import { FIDES_PROTOCOL_VERSION } from './protocol.js'
import { negotiateProtocolVersion, type VersionNegotiationRecord } from './versioning.js'

export interface DiscoveryQuery {
  schema_version: 'fides.discovery_query.v1'
  id: string
  capability?: string
  constraints?: Record<string, unknown>
  principal_id?: string
  requester_agent_id?: string
  supported_versions?: string[]
  required_versions?: string[]
  providers?: string[]
  limit?: number
}

export interface DiscoveryCandidate {
  schema_version: 'fides.discovery_candidate.v1'
  provider: string
  agentId: string
  card: AgentCard
  capability?: string
  verified: boolean
  rank: number
  explanations: string[]
  errors: ErrorEnvelope[]
  versionNegotiation?: VersionNegotiationRecord
}

export function createDiscoveryQuery(input: Omit<DiscoveryQuery, 'schema_version' | 'id'> & { id?: string }): DiscoveryQuery {
  return {
    schema_version: 'fides.discovery_query.v1',
    id: input.id ?? crypto.randomUUID(),
    ...(input.capability !== undefined && { capability: input.capability }),
    ...(input.constraints !== undefined && { constraints: input.constraints }),
    ...(input.principal_id !== undefined && { principal_id: input.principal_id }),
    ...(input.requester_agent_id !== undefined && { requester_agent_id: input.requester_agent_id }),
    ...(input.supported_versions !== undefined && { supported_versions: input.supported_versions }),
    ...(input.required_versions !== undefined && { required_versions: input.required_versions }),
    ...(input.providers !== undefined && { providers: input.providers }),
    ...(input.limit !== undefined && { limit: input.limit }),
  }
}

export function cardSupportsCapability(card: AgentCard, capability?: string): boolean {
  if (!capability) return true
  return card.capabilities.some(candidate => candidate.id === capability)
}

export function createDiscoveryCandidate(input: {
  provider: string
  card: AgentCard
  capability?: string
  verified?: boolean
  rank?: number
  explanations?: string[]
  errors?: ErrorEnvelope[]
  versionNegotiation?: VersionNegotiationRecord
}): DiscoveryCandidate {
  return {
    schema_version: 'fides.discovery_candidate.v1',
    provider: input.provider,
    agentId: input.card.agent_id ?? input.card.identity.did,
    card: input.card,
    ...(input.capability !== undefined && { capability: input.capability }),
    verified: input.verified ?? false,
    rank: input.rank ?? 0,
    explanations: input.explanations ?? [],
    errors: input.errors ?? [],
    ...(input.versionNegotiation !== undefined && { versionNegotiation: input.versionNegotiation }),
  }
}

export function negotiateDiscoveryCandidateVersion(
  query: Pick<DiscoveryQuery, 'supported_versions' | 'required_versions'>,
  card: AgentCard
): VersionNegotiationRecord {
  return negotiateProtocolVersion({
    localSupported: query.supported_versions,
    localRequired: query.required_versions,
    peerSupported: card.protocolVersions?.length ? card.protocolVersions : [FIDES_PROTOCOL_VERSION],
    peerRequired: getCardRequiredVersions(card),
  })
}

function getCardRequiredVersions(card: AgentCard): string[] | undefined {
  const value = (card as unknown as { required_versions?: unknown }).required_versions
  return Array.isArray(value) ? value.map(String) : undefined
}
