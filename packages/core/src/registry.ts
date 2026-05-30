import { signObject, verifyObject, type SignedObject } from './canonical-signer.js'
import { hashProtocolPayload } from './protocol.js'

export type RegistryMode = 'hosted' | 'public' | 'private'
export type RegistryPeeringMode = 'public' | 'private' | 'federated'

export interface RegistryIndexRecord {
  schema_version: 'fides.registry.index.v1'
  id: string
  issuer: string
  mode: RegistryMode
  agent_card_id: string
  agent_id: string
  capability_ids: string[]
  agent_card_hash: string
  registry_url: string
  supported_versions: string[]
  created_at: string
  expires_at?: string
  payload_hash: string
}

export interface RegistryPeerRecord {
  schema_version: 'fides.registry.peer.v1'
  id: string
  issuer: string
  peer_id: string
  registry_url: string
  trust_domain?: string
  peering_mode: RegistryPeeringMode
  supported_versions: string[]
  capabilities: Array<'registry_search' | 'revocation_propagation' | 'incident_propagation' | 'agent_card_replication'>
  created_at: string
  expires_at?: string
  payload_hash: string
}

export type SignedRegistryIndexRecord = SignedObject<RegistryIndexRecord>
export type SignedRegistryPeerRecord = SignedObject<RegistryPeerRecord>

export interface RegistryIndexRecordInput {
  issuer: string
  mode: RegistryMode
  agentCardId: string
  agentId: string
  capabilityIds: string[]
  agentCardHash: string
  registryUrl: string
  supportedVersions: string[]
  createdAt?: string
  expiresAt?: string
}

export interface RegistryPeerRecordInput {
  issuer: string
  peerId: string
  registryUrl: string
  trustDomain?: string
  peeringMode: RegistryPeeringMode
  supportedVersions: string[]
  capabilities: RegistryPeerRecord['capabilities']
  createdAt?: string
  expiresAt?: string
}

export function createRegistryIndexRecord(input: RegistryIndexRecordInput): RegistryIndexRecord {
  const payload = {
    schema_version: 'fides.registry.index.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.issuer,
    mode: input.mode,
    agent_card_id: input.agentCardId,
    agent_id: input.agentId,
    capability_ids: input.capabilityIds,
    agent_card_hash: input.agentCardHash,
    registry_url: input.registryUrl,
    supported_versions: input.supportedVersions,
    created_at: input.createdAt ?? new Date().toISOString(),
    expires_at: input.expiresAt,
  }

  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
  }
}

export function createRegistryPeerRecord(input: RegistryPeerRecordInput): RegistryPeerRecord {
  const payload = {
    schema_version: 'fides.registry.peer.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.issuer,
    peer_id: input.peerId,
    registry_url: input.registryUrl,
    trust_domain: input.trustDomain,
    peering_mode: input.peeringMode,
    supported_versions: input.supportedVersions,
    capabilities: input.capabilities,
    created_at: input.createdAt ?? new Date().toISOString(),
    expires_at: input.expiresAt,
  }

  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
  }
}

export function isRegistryIndexRecordExpired(record: RegistryIndexRecord, now: Date = new Date()): boolean {
  return record.expires_at ? new Date(record.expires_at) <= now : false
}

export function isRegistryPeerRecordExpired(record: RegistryPeerRecord, now: Date = new Date()): boolean {
  return record.expires_at ? new Date(record.expires_at) <= now : false
}

export function signRegistryIndexRecord(
  record: RegistryIndexRecord,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedRegistryIndexRecord> {
  return signObject(record, privateKey, { verificationMethod, proofPurpose: 'assertionMethod' })
}

export function verifySignedRegistryIndexRecord(signed: SignedRegistryIndexRecord): Promise<boolean> {
  return verifyObject(signed)
}

export async function verifySignedRegistryIndexRecordIssuer(signed: SignedRegistryIndexRecord): Promise<boolean> {
  return signed.proof.verificationMethod === signed.payload.issuer && await verifySignedRegistryIndexRecord(signed)
}

export function signRegistryPeerRecord(
  record: RegistryPeerRecord,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedRegistryPeerRecord> {
  return signObject(record, privateKey, { verificationMethod, proofPurpose: 'assertionMethod' })
}

export function verifySignedRegistryPeerRecord(signed: SignedRegistryPeerRecord): Promise<boolean> {
  return verifyObject(signed)
}

export async function verifySignedRegistryPeerRecordIssuer(signed: SignedRegistryPeerRecord): Promise<boolean> {
  return signed.proof.verificationMethod === signed.payload.issuer && await verifySignedRegistryPeerRecord(signed)
}
