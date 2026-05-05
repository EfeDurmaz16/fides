/**
 * FIDES v2 Evidence Ledger
 *
 * Merge of OAPS EvidenceEvent + AGIT hash-chain semantics.
 */

import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import { canonicalJson } from '@fides/core'

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

function hashEvent(event: Omit<EvidenceEvent, 'hash'>): string {
  const canonical = canonicalJson(event)
  return bytesToHex(sha256(new TextEncoder().encode(canonical)))
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
