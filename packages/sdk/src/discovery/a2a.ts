import type { AgentCard, A2AAgentCard } from '@fides/shared'

/**
 * Convert a FIDES AgentCard to an A2A-compatible Agent Card.
 * The A2A card includes x-fides-* extension fields for interop.
 */
export function toA2AAgentCard(
  card: AgentCard,
  options?: { trustEndpoint?: string }
): A2AAgentCard {
  const a2aCard: A2AAgentCard = {
    id: card.did,
    name: card.name,
    url: card.url,
    version: card.version,
    securitySchemes: {
      'fides-signature': {
        type: 'http',
        scheme: 'signature',
        description: 'FIDES Ed25519 HTTP Message Signatures (RFC 9421)',
      },
    },
    security: ['fides-signature'],
    // FIDES extensions
    'x-fides-did': card.did,
    'x-fides-publicKey': card.publicKey,
    'x-fides-algorithm': card.algorithm,
  }

  if (card.description) a2aCard.description = card.description
  if (card.provider) a2aCard.provider = card.provider
  if (card.capabilities) a2aCard.capabilities = card.capabilities
  if (card.skills && card.skills.length > 0) a2aCard.skills = card.skills
  if (card.defaultInputModes) a2aCard.defaultInputModes = card.defaultInputModes
  if (card.defaultOutputModes) a2aCard.defaultOutputModes = card.defaultOutputModes
  if (options?.trustEndpoint) a2aCard['x-fides-trust-endpoint'] = options.trustEndpoint

  return a2aCard
}

/**
 * Convert an A2A Agent Card to a FIDES AgentCard (best effort).
 * Extracts x-fides-* extensions if present, otherwise generates placeholders.
 */
export function fromA2AAgentCard(a2aCard: A2AAgentCard): Partial<AgentCard> {
  return {
    did: a2aCard['x-fides-did'] || a2aCard.id,
    name: a2aCard.name,
    description: a2aCard.description,
    url: a2aCard.url,
    version: a2aCard.version,
    publicKey: a2aCard['x-fides-publicKey'] || '',
    algorithm: a2aCard['x-fides-algorithm'] || 'ed25519',
    provider: a2aCard.provider,
    capabilities: {
      ...a2aCard.capabilities,
      a2aCompatible: true,
    },
    skills: a2aCard.skills,
    defaultInputModes: a2aCard.defaultInputModes,
    defaultOutputModes: a2aCard.defaultOutputModes,
  }
}
