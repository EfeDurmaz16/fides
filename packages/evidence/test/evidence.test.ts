import { describe, it, expect } from 'vitest'
import {
  appendEvidenceEvent,
  appendEvidenceEventV2,
  buildEvidenceMerkleProof,
  buildMerkleProof,
  createEvidenceChain,
  createEvidenceEventV2,
  exportEvidenceEventsV2,
  hashEvidenceValue,
  redactEvidenceEventV2,
  redactEvent,
  signEvidenceEventV2,
  verifyEvidenceChain,
  verifyEvidenceEventV2,
  verifyEvidenceEventsV2,
  verifyMerkleProof,
} from '../src/index.js'
import type { EvidenceEvent } from '../src/index.js'
import { createAgentIdentity } from '@fides/core'

describe('Evidence Ledger', () => {
  it('should create an empty chain', () => {
    const chain = createEvidenceChain()
    expect(chain.events).toHaveLength(0)
  })

  it('should append events with hash chain', () => {
    let chain = createEvidenceChain()
    chain = appendEvidenceEvent(chain, {
      id: '1',
      type: 'invocation',
      timestamp: new Date().toISOString(),
      actor: 'did:fides:alice',
      action: 'read',
      payload: { file: 'doc1' },
      privacy: { level: 'public' },
    }, 'sig1')

    chain = appendEvidenceEvent(chain, {
      id: '2',
      type: 'invocation',
      timestamp: new Date().toISOString(),
      actor: 'did:fides:bob',
      action: 'write',
      payload: { file: 'doc2' },
      privacy: { level: 'public' },
    }, 'sig2')

    expect(chain.events).toHaveLength(2)
    expect(chain.events[0].prevHash).toBe('0')
    expect(chain.events[1].prevHash).toBe(chain.events[0].hash)
    expect(verifyEvidenceChain(chain)).toBe(true)
  })

  it('builds and verifies Merkle inclusion proofs for evidence chains', () => {
    let chain = createEvidenceChain()
    chain = appendEvidenceEvent(chain, {
      id: 'evt_1',
      type: 'invocation',
      timestamp: '2026-05-29T00:00:00.000Z',
      actor: 'did:fides:alice',
      action: 'read',
      payload: { file: 'doc1' },
      privacy: { level: 'hash-only' },
    }, 'sig1')
    chain = appendEvidenceEvent(chain, {
      id: 'evt_2',
      type: 'policy',
      timestamp: '2026-05-29T00:00:01.000Z',
      actor: 'did:fides:policy',
      action: 'evaluate',
      payload: { decision: 'allow' },
      privacy: { level: 'hash-only' },
    }, 'sig2')
    chain = appendEvidenceEvent(chain, {
      id: 'evt_3',
      type: 'invocation',
      timestamp: '2026-05-29T00:00:02.000Z',
      actor: 'did:fides:bob',
      action: 'write',
      payload: { file: 'doc2' },
      privacy: { level: 'hash-only' },
    }, 'sig3')

    const proof = buildEvidenceMerkleProof(chain, 'evt_2')

    expect(proof.leafHash).toBe(chain.events[1].hash)
    expect(proof.root).toBe(chain.merkleRoot)
    expect(verifyMerkleProof(proof)).toBe(true)
    expect(verifyMerkleProof({ ...proof, leafHash: 'tampered' })).toBe(false)
  })

  it('builds Merkle proofs from raw event hashes', () => {
    const hashes = ['h1', 'h2', 'h3', 'h4']
    const proof = buildMerkleProof(hashes, 3)

    expect(proof.leafHash).toBe('h4')
    expect(proof.leafIndex).toBe(3)
    expect(verifyMerkleProof(proof)).toBe(true)
    expect(verifyMerkleProof({ ...proof, steps: proof.steps.slice(1) })).toBe(false)
  })

  it('should detect tampered chain', () => {
    let chain = createEvidenceChain()
    chain = appendEvidenceEvent(chain, {
      id: '1',
      type: 'invocation',
      timestamp: new Date().toISOString(),
      actor: 'did:fides:alice',
      action: 'read',
      payload: {},
      privacy: { level: 'public' },
    }, 'sig1')

    chain.events[0].payload = { tampered: true } as any
    expect(verifyEvidenceChain(chain)).toBe(false)
  })

  it('should redact events by privacy level', () => {
    const event: EvidenceEvent = {
      id: '1',
      type: 'invocation',
      timestamp: '',
      actor: 'did:fides:alice',
      action: 'read',
      payload: { secret: 'data' },
      privacy: { level: 'private' },
      prevHash: '0',
      hash: 'abc',
      signature: 'sig',
    }

    expect(redactEvent(event, 'public').payload).toEqual({ secret: 'data' })
    expect(redactEvent(event, 'private').payload).toBeNull()
    expect(redactEvent(event, 'redacted').payload).toBe('[REDACTED]')
    expect(redactEvent(event, 'hash-only').payload).toBeNull()
  })

  it('creates privacy-aware v2 events with hashes instead of raw payloads', () => {
    const event = createEvidenceEventV2({
      type: 'capability.invoked',
      actor: 'did:fides:agent',
      principal: 'did:fides:principal',
      capability: 'invoice.reconcile',
      input: { invoiceId: 'inv_123', secret: 'hidden' },
      policy: { id: 'default' },
      decision: 'allow',
      risk_level: 'medium',
    })

    expect(event.schema_version).toBe('fides.evidence_event.v1')
    expect(event.privacy_mode).toBe('hash_only')
    expect(event.input_hash).toBe(hashEvidenceValue({ invoiceId: 'inv_123', secret: 'hidden' }))
    expect(event.policy_hash).toMatch(/^sha256:/)
    expect(JSON.stringify(event)).not.toContain('hidden')
  })

  it('signs and verifies v2 events', async () => {
    const issued = await createAgentIdentity()
    const event = createEvidenceEventV2({
      type: 'trust.computed',
      actor: issued.identity.did,
      subject: 'did:fides:target',
      metadata: { score: 0.8 },
      timestamp: '2026-05-29T00:00:00.000Z',
    })

    const signed = await signEvidenceEventV2(event, issued.privateKey, issued.identity.did)

    expect(signed.signature).not.toBe('')
    expect(await verifyEvidenceEventV2(signed)).toBe(true)

    expect(await verifyEvidenceEventV2({ ...signed, metadata: { score: 0.1 } })).toBe(false)
  })

  it('verifies v2 hash chains and detects broken links', () => {
    const first = createEvidenceEventV2({
      type: 'session.requested',
      actor: 'did:fides:requester',
      timestamp: '2026-05-29T00:00:00.000Z',
    })
    const second = createEvidenceEventV2({
      type: 'session.granted',
      actor: 'did:fides:target',
      timestamp: '2026-05-29T00:00:01.000Z',
    }, first.event_hash)

    const events = appendEvidenceEventV2(appendEvidenceEventV2([], first), second)

    expect(verifyEvidenceEventsV2(events)).toBe(true)
    expect(verifyEvidenceEventsV2([{ ...second, prev_event_hash: 'wrong' }])).toBe(false)
  })

  it('exports v2 events according to privacy mode without exposing metadata by default', () => {
    const event = createEvidenceEventV2({
      type: 'capability.completed',
      actor: 'did:fides:agent',
      subject: 'did:fides:target',
      input: { invoiceId: 'inv_123', secret: 'hidden-input' },
      output: { status: 'ok', secret: 'hidden-output' },
      policy: { decision: 'allow' },
      decision: 'allow',
      risk_level: 'medium',
      metadata: { rawPrompt: 'do not export this' },
      timestamp: '2026-05-29T00:00:00.000Z',
    })

    const hashOnly = redactEvidenceEventV2(event)
    expect(hashOnly.input_hash).toMatch(/^sha256:/)
    expect(hashOnly.output_hash).toMatch(/^sha256:/)
    expect(hashOnly.metadata).toBeUndefined()
    expect(JSON.stringify(hashOnly)).not.toContain('hidden-input')
    expect(JSON.stringify(hashOnly)).not.toContain('rawPrompt')

    const privateExport = redactEvidenceEventV2(event, { privacy_mode: 'private' })
    expect(privateExport.input_hash).toBeUndefined()
    expect(privateExport.output_hash).toBeUndefined()
    expect(privateExport.policy_hash).toBeUndefined()
    expect(privateExport.decision).toBeUndefined()

    const publicExport = exportEvidenceEventsV2([event], { privacy_mode: 'public' })
    expect(publicExport[0].metadata).toEqual({ rawPrompt: 'do not export this' })
  })
})
