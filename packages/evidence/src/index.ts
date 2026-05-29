/**
 * FIDES v2 Evidence Ledger
 *
 * Merge of OAPS EvidenceEvent + AGIT hash-chain semantics.
 */

import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import { canonicalJson, signObject, verifyObject } from '@fides/core'

export interface EvidencePrivacy {
  level: 'public' | 'private' | 'redacted' | 'hash-only'
  redactionKey?: string
}

export interface EvidenceEvent {
  id: string
  type: string
  timestamp: string
  actor: string
  action: string
  target?: string
  payload: unknown
  privacy: EvidencePrivacy
  prevHash: string
  hash: string
  signature: string
}

export interface EvidenceChain {
  events: EvidenceEvent[]
  merkleRoot?: string
}

export type EvidenceEventType =
  | 'agent.registered'
  | 'agent.updated'
  | 'agent.revoked'
  | 'discovery.performed'
  | 'trust.computed'
  | 'policy.evaluated'
  | 'approval.requested'
  | 'approval.granted'
  | 'approval.denied'
  | 'session.requested'
  | 'session.granted'
  | 'session.denied'
  | 'capability.invoked'
  | 'capability.completed'
  | 'capability.failed'
  | 'attestation.issued'
  | 'attestation.verified'
  | 'attestation.failed'
  | 'revocation.recorded'
  | 'incident.reported'
  | 'kill_switch.triggered'

export type EvidencePrivacyMode = 'public' | 'private' | 'redacted' | 'hash_only'

export interface EvidenceEventV2 {
  schema_version: 'fides.evidence_event.v1'
  event_id: string
  type: EvidenceEventType
  actor: string
  subject?: string
  principal?: string
  capability?: string
  input_hash?: string
  output_hash?: string
  policy_hash?: string
  decision?: string
  risk_level?: 'low' | 'medium' | 'high' | 'critical'
  privacy_mode: EvidencePrivacyMode
  timestamp: string
  prev_event_hash: string
  event_hash: string
  signature: string
  metadata?: Record<string, unknown>
}

export interface EvidenceEventV2Input {
  event_id?: string
  type: EvidenceEventType
  actor: string
  subject?: string
  principal?: string
  capability?: string
  input?: unknown
  output?: unknown
  input_hash?: string
  output_hash?: string
  policy?: unknown
  policy_hash?: string
  decision?: string
  risk_level?: EvidenceEventV2['risk_level']
  privacy_mode?: EvidencePrivacyMode
  timestamp?: string
  metadata?: Record<string, unknown>
}

function hashEvent(event: Omit<EvidenceEvent, 'hash'>): string {
  const canonical = canonicalJson(event)
  return bytesToHex(sha256(new TextEncoder().encode(canonical)))
}

export function hashEvidenceValue(value: unknown): string {
  return `sha256:${bytesToHex(sha256(new TextEncoder().encode(canonicalJson(value))))}`
}

export function createEvidenceEventV2(
  input: EvidenceEventV2Input,
  previousEventHash = '0'
): EvidenceEventV2 {
  const eventWithoutHash: Omit<EvidenceEventV2, 'event_hash' | 'signature'> = {
    schema_version: 'fides.evidence_event.v1',
    event_id: input.event_id ?? crypto.randomUUID(),
    type: input.type,
    actor: input.actor,
    privacy_mode: input.privacy_mode ?? defaultPrivacyMode(input),
    timestamp: input.timestamp ?? new Date().toISOString(),
    prev_event_hash: previousEventHash,
    ...(input.subject !== undefined && { subject: input.subject }),
    ...(input.principal !== undefined && { principal: input.principal }),
    ...(input.capability !== undefined && { capability: input.capability }),
    ...(input.input_hash !== undefined || input.input !== undefined
      ? { input_hash: input.input_hash ?? hashEvidenceValue(input.input) }
      : {}),
    ...(input.output_hash !== undefined || input.output !== undefined
      ? { output_hash: input.output_hash ?? hashEvidenceValue(input.output) }
      : {}),
    ...(input.policy_hash !== undefined || input.policy !== undefined
      ? { policy_hash: input.policy_hash ?? hashEvidenceValue(input.policy) }
      : {}),
    ...(input.decision !== undefined && { decision: input.decision }),
    ...(input.risk_level !== undefined && { risk_level: input.risk_level }),
    ...(input.metadata !== undefined && { metadata: input.metadata }),
  }
  const event_hash = hashEvidenceValue(eventWithoutHash)
  return {
    ...eventWithoutHash,
    event_hash,
    signature: '',
  }
}

export async function signEvidenceEventV2(
  event: EvidenceEventV2,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<EvidenceEventV2> {
  const unsigned = { ...event, signature: '' }
  const signed = await signObject(unsigned, privateKey, {
    verificationMethod,
    proofPurpose: 'assertionMethod',
  })
  return {
    ...event,
    signature: signed.proof.proofValue,
  }
}

export async function verifyEvidenceEventV2(
  event: EvidenceEventV2,
  verificationMethod = event.actor
): Promise<boolean> {
  if (!event.signature) return false
  const { event_hash, signature, ...withoutHashAndSignature } = event
  if (hashEvidenceValue(withoutHashAndSignature) !== event_hash) return false
  return verifyObject({
    payload: { ...event, signature: '' },
    proof: {
      type: 'Ed25519Signature2024',
      created: event.timestamp,
      verificationMethod,
      proofPurpose: 'assertionMethod',
      canonicalizationAlgorithm: 'https://fides.dev/canonical-json/v1',
      proofValue: signature,
    },
  })
}

export function appendEvidenceEventV2(
  events: EvidenceEventV2[],
  event: EvidenceEventV2
): EvidenceEventV2[] {
  const expectedPrevious = events.length > 0 ? events[events.length - 1].event_hash : '0'
  if (event.prev_event_hash !== expectedPrevious) {
    throw new Error('EvidenceEvent.prev_event_hash does not match chain head')
  }
  return [...events, event]
}

export function verifyEvidenceEventsV2(events: EvidenceEventV2[]): boolean {
  for (let index = 0; index < events.length; index++) {
    const event = events[index]
    const expectedPrevious = index === 0 ? '0' : events[index - 1].event_hash
    if (event.prev_event_hash !== expectedPrevious) return false
    const { event_hash, signature: _signature, ...withoutHashAndSignature } = event
    if (hashEvidenceValue(withoutHashAndSignature) !== event_hash) return false
  }
  return true
}

/**
 * Build a Merkle tree from event hashes and return the root.
 */
export function buildMerkleRoot(eventHashes: string[]): string {
  if (eventHashes.length === 0) return '0'
  if (eventHashes.length === 1) return eventHashes[0]

  let level = [...eventHashes]
  while (level.length > 1) {
    const nextLevel: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        const combined = level[i] + level[i + 1]
        nextLevel.push(bytesToHex(sha256(new TextEncoder().encode(combined))))
      } else {
        nextLevel.push(level[i])
      }
    }
    level = nextLevel
  }
  return level[0]
}

/**
 * Compute the Merkle root of an evidence chain.
 */
export function computeMerkleRoot(chain: EvidenceChain): string {
  const hashes = chain.events.map(e => e.hash)
  return buildMerkleRoot(hashes)
}

export function createEvidenceChain(): EvidenceChain {
  return { events: [] }
}

export function appendEvidenceEvent(
  chain: EvidenceChain,
  eventData: Omit<EvidenceEvent, 'prevHash' | 'hash' | 'signature'>,
  signature: string
): EvidenceChain {
  const prevHash = chain.events.length > 0 ? chain.events[chain.events.length - 1].hash : '0'
  const eventWithoutHash: Omit<EvidenceEvent, 'hash'> = {
    ...eventData,
    prevHash,
    signature,
  }
  const hash = hashEvent(eventWithoutHash)
  const event: EvidenceEvent = { ...eventWithoutHash, hash }
  const newChain: EvidenceChain = { events: [...chain.events, event] }
  newChain.merkleRoot = computeMerkleRoot(newChain)
  return newChain
}

export function verifyEvidenceChain(chain: EvidenceChain): boolean {
  for (let i = 0; i < chain.events.length; i++) {
    const event = chain.events[i]
    const expectedPrev = i === 0 ? '0' : chain.events[i - 1].hash
    if (event.prevHash !== expectedPrev) return false
    const { hash, ...withoutHash } = event
    if (hashEvent(withoutHash) !== hash) return false
  }
  // Verify Merkle root
  const expectedRoot = computeMerkleRoot(chain)
  if (chain.merkleRoot && chain.merkleRoot !== expectedRoot) return false
  return true
}

/**
 * Apply privacy level to an event before export.
 */
export function redactEvent(event: EvidenceEvent, level?: EvidencePrivacy['level']): EvidenceEvent {
  const privacyLevel = level ?? event.privacy.level
  switch (privacyLevel) {
    case 'public':
      return event
    case 'private':
      return { ...event, payload: null }
    case 'redacted':
      return { ...event, payload: '[REDACTED]' }
    case 'hash-only':
      return { ...event, payload: null, hash: event.hash }
    default:
      return event
  }
}

function defaultPrivacyMode(input: EvidenceEventV2Input): EvidencePrivacyMode {
  if (input.privacy_mode) return input.privacy_mode
  if (input.input !== undefined || input.output !== undefined) return 'hash_only'
  return 'redacted'
}
