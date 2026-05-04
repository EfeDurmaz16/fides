/**
 * FIDES v2 Runtime Attestation and Kill Switch
 *
 * Provides runtime attestation primitives and emergency kill switch.
 */

export interface RuntimeAttestation {
  id: string
  agentDid: string
  provider: string
  measurement: string
  timestamp: string
  expiresAt: string
  evidence: unknown
  signature: string
}

export interface TEEAdapter {
  readonly provider: string
  attest(agentDid: string): Promise<RuntimeAttestation>
  verify(attestation: RuntimeAttestation): Promise<boolean>
}

/** Mock TEE provider for development and testing */
export class MockTEEProvider implements TEEAdapter {
  readonly provider = 'mock-tee'

  async attest(agentDid: string): Promise<RuntimeAttestation> {
    const now = new Date()
    const expires = new Date(now.getTime() + 3600000) // 1 hour
    const measurement = `mock-measurement-${agentDid}-${now.toISOString()}`
    return {
      id: crypto.randomUUID(),
      agentDid,
      provider: this.provider,
      measurement,
      timestamp: now.toISOString(),
      expiresAt: expires.toISOString(),
      evidence: { mock: true },
      signature: 'mock-signature',
    }
  }

  async verify(attestation: RuntimeAttestation): Promise<boolean> {
    if (attestation.provider !== this.provider) return false
    if (new Date(attestation.expiresAt) < new Date()) return false
    return attestation.signature === 'mock-signature'
  }
}

export interface KillSwitchTarget {
  type: 'global' | 'agent' | 'capability' | 'principal'
  did?: string
  id?: string
}

export interface KillSwitch {
  engage(target: KillSwitchTarget): void
  disengage(target: KillSwitchTarget): void
  isEngaged(target: KillSwitchTarget): boolean
}

export class InMemoryKillSwitch implements KillSwitch {
  private state = new Map<string, boolean>()

  private key(target: KillSwitchTarget): string {
    if (target.type === 'global') return 'global'
    if (target.type === 'agent' || target.type === 'principal') return `${target.type}:${target.did}`
    if (target.type === 'capability') return `capability:${target.id}`
    return 'unknown'
  }

  engage(target: KillSwitchTarget): void {
    this.state.set(this.key(target), true)
  }

  disengage(target: KillSwitchTarget): void {
    this.state.set(this.key(target), false)
  }

  isEngaged(target: KillSwitchTarget): boolean {
    // Global kill switch overrides everything
    if (this.state.get('global')) return true
    return this.state.get(this.key(target)) ?? false
  }
}
