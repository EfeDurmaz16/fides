import { describe, expect, it } from 'vitest'
import { AgitPrimitiveBridge } from '../src/integrations/agit.js'
import type { AgitRustPrimitiveAdapter } from '../src/integrations/agit.js'

describe('AGIT primitive bridge', () => {
  it('uses TypeScript canonical JSON and hashing when no Rust adapter is installed', async () => {
    const bridge = new AgitPrimitiveBridge()

    await expect(bridge.canonicalizeJson({ b: 2, a: 1 })).resolves.toBe('{"a":1,"b":2}')
    await expect(bridge.hashObject({ b: 2, a: 1 })).resolves.toMatch(/^sha256:/)

    const first = await bridge.appendEvidenceHash({
      eventPayload: { event_id: 'evt_1', type: 'policy.evaluated' },
    })
    const second = await bridge.appendEvidenceHash({
      previousEventHash: first.eventHash,
      eventPayload: { event_id: 'evt_2', type: 'capability.invoked' },
    })

    expect(first.eventHash).toMatch(/^sha256:/)
    expect(second.previousEventHash).toBe(first.eventHash)
    expect(second.eventHash).not.toBe(first.eventHash)
  })

  it('delegates primitive work to a supplied Rust adapter', async () => {
    const adapter: AgitRustPrimitiveAdapter = {
      canonicalizeJson: () => 'rust-canonical-json',
      hashBytes: () => 'sha256:rust-hash',
      appendEvidenceHash: input => ({
        previousEventHash: input.previousEventHash,
        eventHash: 'sha256:rust-event-hash',
      }),
      createMerkleProof: input => ({
        root: 'sha256:rust-root',
        leaf: input.leaf,
        proof: ['sha256:rust-proof'],
      }),
    }
    const bridge = new AgitPrimitiveBridge({ rustAdapter: adapter })

    await expect(bridge.canonicalizeJson({ a: 1 })).resolves.toBe('rust-canonical-json')
    await expect(bridge.hashBytes(new Uint8Array([1, 2, 3]))).resolves.toBe('sha256:rust-hash')
    await expect(bridge.appendEvidenceHash({
      previousEventHash: 'sha256:previous',
      eventPayload: { event_id: 'evt' },
    })).resolves.toEqual({
      previousEventHash: 'sha256:previous',
      eventHash: 'sha256:rust-event-hash',
    })
    await expect(bridge.createMerkleProof({
      leaves: ['sha256:a', 'sha256:b'],
      leaf: 'sha256:b',
    })).resolves.toEqual({
      root: 'sha256:rust-root',
      leaf: 'sha256:b',
      proof: ['sha256:rust-proof'],
    })
  })

  it('creates local Merkle proofs without Rust', async () => {
    const bridge = new AgitPrimitiveBridge()
    const leaves = [
      'sha256:leaf-a',
      'sha256:leaf-b',
      'sha256:leaf-c',
    ]

    const proof = await bridge.createMerkleProof({ leaves, leaf: 'sha256:leaf-b' })

    expect(proof).toMatchObject({
      leaf: 'sha256:leaf-b',
      proof: expect.arrayContaining(['sha256:leaf-a']),
    })
    expect(proof.root).toMatch(/^sha256:/)

    await expect(bridge.createMerkleProof({ leaves, leaf: 'sha256:missing' }))
      .rejects.toThrow('Merkle proof leaf is not present in leaves')
  })
})
