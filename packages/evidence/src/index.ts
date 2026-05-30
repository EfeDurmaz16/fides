/**
 * FIDES v2 Evidence Ledger
 *
 * Merge of OAPS EvidenceEvent + AGIT hash-chain semantics.
 */

import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import { canonicalJson, signObject, verifyObject } from '@fides/core'

export interface EvidencePrivacy {
  level: 'public' | 'private' | 'redacted' | 'hash_only' | 'hash-only'
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

export interface MerkleProofStep {
  position: 'left' | 'right'
  hash: string
}

export interface MerkleProof {
  leafHash: string
  leafIndex: number
  root: string
  steps: MerkleProofStep[]
}

export const EVIDENCE_EVENT_TYPES = [
  'agent.registered',
  'agent.updated',
  'agent.revoked',
  'discovery.performed',
  'trust.computed',
  'policy.evaluated',
  'approval.requested',
  'approval.granted',
  'approval.denied',
  'session.requested',
  'session.granted',
  'session.denied',
  'capability.invoked',
  'capability.completed',
  'capability.failed',
  'attestation.issued',
  'attestation.verified',
  'attestation.failed',
  'revocation.recorded',
  'incident.reported',
  'kill_switch.triggered',
] as const

export type EvidenceEventType = typeof EVIDENCE_EVENT_TYPES[number]

export type EvidencePrivacyMode = 'public' | 'private' | 'redacted' | 'hash_only'

export interface EvidenceEventV2 {
  schema_version: 'fides.evidence_event.v1'
  id: string
  event_id: string
  issuer: string
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
  issued_at: string
  timestamp: string
  prev_event_hash: string
  payload_hash: string
  event_hash: string
  signature: string
  metadata?: Record<string, unknown>
}

export interface EvidenceEventV2ExportOptions {
  privacy_mode?: EvidencePrivacyMode
  include_metadata?: boolean
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

function isEvidenceEventType(value: unknown): value is EvidenceEventType {
  return typeof value === 'string' && EVIDENCE_EVENT_TYPES.includes(value as EvidenceEventType)
}

function isEvidencePrivacyMode(value: unknown): value is EvidencePrivacyMode {
  return value === 'public' || value === 'private' || value === 'redacted' || value === 'hash_only'
}

function isRiskLevel(value: unknown): value is EvidenceEventV2['risk_level'] {
  return value === 'low' || value === 'medium' || value === 'high' || value === 'critical'
}

function optionalString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key]
  return typeof value === 'string' ? value : undefined
}

function optionalMetadata(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

export function createEvidenceEventV2(
  input: EvidenceEventV2Input,
  previousEventHash = '0'
): EvidenceEventV2 {
  const eventId = input.event_id ?? crypto.randomUUID()
  const timestamp = input.timestamp ?? new Date().toISOString()
  const eventPayload: Omit<EvidenceEventV2, 'payload_hash' | 'event_hash' | 'signature'> = {
    schema_version: 'fides.evidence_event.v1',
    id: eventId,
    event_id: eventId,
    issuer: input.actor,
    type: input.type,
    actor: input.actor,
    privacy_mode: input.privacy_mode ?? defaultPrivacyMode(input),
    issued_at: timestamp,
    timestamp,
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
  const eventWithoutHash: Omit<EvidenceEventV2, 'event_hash' | 'signature'> = {
    ...eventPayload,
    payload_hash: hashEvidenceValue(eventPayload),
  }
  const event_hash = hashEvidenceValue(eventWithoutHash)
  return {
    ...eventWithoutHash,
    event_hash,
    signature: '',
  }
}

export function normalizeEvidenceEventV2(
  input: EvidenceEventV2 | Record<string, unknown>,
  previousEventHash?: string
): EvidenceEventV2 {
  const event = input as Record<string, unknown>
  const eventId = optionalString(event, 'event_id') ?? optionalString(event, 'id') ?? crypto.randomUUID()
  const actor = optionalString(event, 'actor') ?? optionalString(event, 'issuer') ?? 'did:fides:unknown'
  const timestamp = optionalString(event, 'timestamp') ?? optionalString(event, 'issued_at') ?? new Date().toISOString()
  const legacyEventHash = optionalString(event, 'event_hash')
  const legacyPrevEventHash = optionalString(event, 'prev_event_hash')
  const hasEnvelope =
    typeof event.id === 'string' &&
    typeof event.issuer === 'string' &&
    typeof event.issued_at === 'string' &&
    typeof event.payload_hash === 'string'
  const existingMetadata = optionalMetadata(event.metadata)
  const metadata = hasEnvelope
    ? existingMetadata
    : {
      ...(existingMetadata ?? {}),
      migrated_from_legacy_evidence_event: true,
      ...(legacyEventHash !== undefined && { legacy_event_hash: legacyEventHash }),
      ...(legacyPrevEventHash !== undefined && { legacy_prev_event_hash: legacyPrevEventHash }),
    }

  const eventPayload: Omit<EvidenceEventV2, 'payload_hash' | 'event_hash' | 'signature'> = {
    schema_version: 'fides.evidence_event.v1',
    id: eventId,
    event_id: eventId,
    issuer: actor,
    type: isEvidenceEventType(event.type) ? event.type : 'capability.failed',
    actor,
    privacy_mode: isEvidencePrivacyMode(event.privacy_mode) ? event.privacy_mode : 'hash_only',
    issued_at: timestamp,
    timestamp,
    prev_event_hash: previousEventHash ?? legacyPrevEventHash ?? '0',
    ...(optionalString(event, 'subject') !== undefined && { subject: optionalString(event, 'subject') }),
    ...(optionalString(event, 'principal') !== undefined && { principal: optionalString(event, 'principal') }),
    ...(optionalString(event, 'capability') !== undefined && { capability: optionalString(event, 'capability') }),
    ...(optionalString(event, 'input_hash') !== undefined && { input_hash: optionalString(event, 'input_hash') }),
    ...(optionalString(event, 'output_hash') !== undefined && { output_hash: optionalString(event, 'output_hash') }),
    ...(optionalString(event, 'policy_hash') !== undefined && { policy_hash: optionalString(event, 'policy_hash') }),
    ...(optionalString(event, 'decision') !== undefined && { decision: optionalString(event, 'decision') }),
    ...(isRiskLevel(event.risk_level) && { risk_level: event.risk_level }),
    ...(metadata !== undefined && { metadata }),
  }
  const eventWithoutHash: Omit<EvidenceEventV2, 'event_hash' | 'signature'> = {
    ...eventPayload,
    payload_hash: hashEvidenceValue(eventPayload),
  }
  return {
    ...eventWithoutHash,
    event_hash: hashEvidenceValue(eventWithoutHash),
    signature: optionalString(event, 'signature') ?? '',
  }
}

export function normalizeEvidenceEventsV2(
  events: Array<EvidenceEventV2 | Record<string, unknown>>
): EvidenceEventV2[] {
  const normalized: EvidenceEventV2[] = []
  for (const event of events) {
    normalized.push(normalizeEvidenceEventV2(event, normalized.at(-1)?.event_hash ?? '0'))
  }
  return normalized
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
  if (event.id !== event.event_id) return false
  if (event.issuer !== event.actor) return false
  if (event.issued_at !== event.timestamp) return false
  const { event_hash, signature, payload_hash, ...withoutHashAndSignature } = event
  if (hashEvidenceValue(withoutHashAndSignature) !== payload_hash) return false
  const withPayloadHash = { ...withoutHashAndSignature, payload_hash }
  if (hashEvidenceValue(withPayloadHash) !== event_hash) return false
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

export function verifyUnsignedEvidenceEventV2(event: EvidenceEventV2): boolean {
  if (event.id !== event.event_id) return false
  if (event.issuer !== event.actor) return false
  if (event.issued_at !== event.timestamp) return false
  const { event_hash, signature: _signature, payload_hash, ...withoutHashAndSignature } = event
  if (hashEvidenceValue(withoutHashAndSignature) !== payload_hash) return false
  const withPayloadHash = { ...withoutHashAndSignature, payload_hash }
  if (hashEvidenceValue(withPayloadHash) !== event_hash) return false
  return true
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
    if (!verifyUnsignedEvidenceEventV2(event)) return false
  }
  return true
}

export function redactEvidenceEventV2(
  event: EvidenceEventV2,
  options: EvidenceEventV2ExportOptions = {}
): EvidenceEventV2 {
  const privacyMode = options.privacy_mode ?? event.privacy_mode
  const includeMetadata = options.include_metadata ?? privacyMode === 'public'
  const exported: EvidenceEventV2 = {
    ...event,
    privacy_mode: privacyMode,
    ...(includeMetadata ? {} : { metadata: undefined }),
  }

  if (privacyMode === 'public') return exported

  if (privacyMode === 'private') {
    return {
      ...exported,
      input_hash: undefined,
      output_hash: undefined,
      policy_hash: undefined,
      decision: undefined,
      risk_level: undefined,
      metadata: undefined,
    }
  }

  if (privacyMode === 'redacted') {
    return {
      ...exported,
      metadata: includeMetadata ? exported.metadata : undefined,
    }
  }

  return {
    ...exported,
    metadata: undefined,
  }
}

export function exportEvidenceEventsV2(
  events: EvidenceEventV2[],
  options: EvidenceEventV2ExportOptions = {}
): EvidenceEventV2[] {
  return events.map(event => redactEvidenceEventV2(event, options))
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
        nextLevel.push(hashMerklePair(level[i], level[i + 1]))
      } else {
        nextLevel.push(level[i])
      }
    }
    level = nextLevel
  }
  return level[0]
}

export function buildMerkleProof(eventHashes: string[], leafIndex: number): MerkleProof {
  if (eventHashes.length === 0) {
    throw new Error('Cannot build a Merkle proof for an empty tree')
  }
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= eventHashes.length) {
    throw new Error('Merkle proof leafIndex is out of range')
  }

  let index = leafIndex
  let level = [...eventHashes]
  const steps: MerkleProofStep[] = []

  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1
    if (siblingIndex < level.length) {
      steps.push({
        position: siblingIndex < index ? 'left' : 'right',
        hash: level[siblingIndex],
      })
    }

    const nextLevel: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        nextLevel.push(hashMerklePair(level[i], level[i + 1]))
      } else {
        nextLevel.push(level[i])
      }
    }
    index = Math.floor(index / 2)
    level = nextLevel
  }

  return {
    leafHash: eventHashes[leafIndex],
    leafIndex,
    root: level[0],
    steps,
  }
}

export function buildEvidenceMerkleProof(chain: EvidenceChain, eventId: string): MerkleProof {
  const leafIndex = chain.events.findIndex(event => event.id === eventId)
  if (leafIndex === -1) {
    throw new Error(`Evidence event not found in chain: ${eventId}`)
  }
  return buildMerkleProof(chain.events.map(event => event.hash), leafIndex)
}

export function verifyMerkleProof(proof: MerkleProof): boolean {
  if (!proof.leafHash || !proof.root || proof.leafIndex < 0 || !Number.isInteger(proof.leafIndex)) {
    return false
  }
  let computed = proof.leafHash
  for (const step of proof.steps) {
    computed = step.position === 'left'
      ? hashMerklePair(step.hash, computed)
      : hashMerklePair(computed, step.hash)
  }
  return computed === proof.root
}

function hashMerklePair(left: string, right: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(left + right)))
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
    case 'hash_only':
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
