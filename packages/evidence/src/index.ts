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

export function createEvidenceChain(): EvidenceChain {
  return { events: [] }
}

export function appendEvidenceEvent(
  chain: EvidenceChain,
  eventData: Omit<EvidenceEvent, 'prevHash' | 'hash'>,
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
  return { events: [...chain.events, event] }
}

export function verifyEvidenceChain(chain: EvidenceChain): boolean {
  for (let i = 0; i < chain.events.length; i++) {
    const event = chain.events[i]
    const expectedPrev = i === 0 ? '0' : chain.events[i - 1].hash
    if (event.prevHash !== expectedPrev) return false
    const { hash, ...withoutHash } = event
    if (hashEvent(withoutHash) !== hash) return false
  }
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
