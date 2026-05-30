import type { AgentCard } from './agent-card.js'
import { hashProtocolPayload } from './protocol.js'
import { signObject, verifyObject } from './canonical-signer.js'

export interface DHTPointerRecord {
  schema_version: 'fides.dht.pointer.v1'
  record_type: 'capability_pointer'
  capability: string
  capability_hash: string
  agent_id: string
  agent_card_url: string
  agent_card_hash: string
  publisher_id: string
  expires_at: string
  sequence: number
  signature: string
}

export function hashCapability(capability: string): string {
  return hashProtocolPayload({ capability })
}

export function hashAgentCard(card: AgentCard): string {
  return hashProtocolPayload(card)
}

export function createDHTPointerRecord(input: {
  capability: string
  agentId: string
  agentCardUrl: string
  agentCardHash: string
  publisherId: string
  expiresAt: string
  sequence?: number
}): DHTPointerRecord {
  return {
    schema_version: 'fides.dht.pointer.v1',
    record_type: 'capability_pointer',
    capability: input.capability,
    capability_hash: hashCapability(input.capability),
    agent_id: input.agentId,
    agent_card_url: input.agentCardUrl,
    agent_card_hash: input.agentCardHash,
    publisher_id: input.publisherId,
    expires_at: input.expiresAt,
    sequence: input.sequence ?? 1,
    signature: '',
  }
}

export async function signDHTPointerRecord(
  record: DHTPointerRecord,
  privateKey: Uint8Array,
  verificationMethod = record.publisher_id
): Promise<DHTPointerRecord> {
  const unsigned = { ...record, signature: '' }
  const signed = await signObject(unsigned, privateKey, {
    verificationMethod,
    proofPurpose: 'assertionMethod',
  })
  return {
    ...record,
    signature: signed.proof.proofValue,
  }
}

export async function verifyDHTPointerRecord(
  record: DHTPointerRecord,
  options: {
    card?: AgentCard
    now?: Date
    verificationMethod?: string
  } = {}
): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = []
  if (record.schema_version !== 'fides.dht.pointer.v1') {
    errors.push('DHT pointer schema_version is invalid')
  }
  if (record.record_type !== 'capability_pointer') {
    errors.push('DHT pointer record_type is invalid')
  }
  if (record.capability_hash !== hashCapability(record.capability)) {
    errors.push('DHT pointer capability_hash mismatch')
  }
  if (new Date(record.expires_at).getTime() <= (options.now ?? new Date()).getTime()) {
    errors.push('DHT pointer is expired')
  }
  if (options.card) {
    if (hashAgentCard(options.card) !== record.agent_card_hash) {
      errors.push('DHT pointer agent_card_hash mismatch')
    }
    if ((options.card.agent_id ?? options.card.identity.did) !== record.agent_id) {
      errors.push('DHT pointer agent_id does not match AgentCard')
    }
    if (!options.card.capabilities.some(capability => capability.id === record.capability)) {
      errors.push('DHT pointer capability is not advertised by AgentCard')
    }
  }

  if (!record.signature) {
    errors.push('DHT pointer signature is required')
  } else {
    const signatureValid = await verifyObject({
      payload: { ...record, signature: '' },
      proof: {
        type: 'Ed25519Signature2024',
        created: record.expires_at,
        verificationMethod: options.verificationMethod ?? record.publisher_id,
        proofPurpose: 'assertionMethod',
        canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1',
        proofValue: record.signature,
      },
    })
    if (!signatureValid) {
      errors.push('DHT pointer signature is invalid')
    }
  }

  return { valid: errors.length === 0, errors }
}
