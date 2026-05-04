import { describe, it, expect } from 'vitest'
import { createEvidenceChain, appendEvidenceEvent, verifyEvidenceChain, redactEvent } from '../src/index.js'
import type { EvidenceEvent } from '../src/index.js'

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
})
