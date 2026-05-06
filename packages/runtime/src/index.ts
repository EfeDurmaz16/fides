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

export interface BuildAttestationInput {
  agentDid: string
  imageDigest: string
  sourceCommit: string
  builderId: string
  expiresInMs?: number
}

export interface ContainerImageAttestationInput {
  agentDid: string
  registry: string
  repository: string
  digest: string
  tag?: string
  sourceCommit?: string
  expiresInMs?: number
}

export interface PackageAttestationInput {
  agentDid: string
  registry: 'npm' | 'pypi' | 'crates' | string
  packageName: string
  version: string
  integrity: string
  expiresInMs?: number
}

export interface GitHubAttestationInput {
  agentDid: string
  repository: string
  workflowRef: string
  sha: string
  runId: string
  expiresInMs?: number
}

export interface BuildAttestationAdapter {
  readonly provider: string
  attest(input: BuildAttestationInput): Promise<RuntimeAttestation>
  verify(attestation: RuntimeAttestation): Promise<boolean>
}

export interface ContainerImageAttestationAdapter {
  readonly provider: string
  attest(input: ContainerImageAttestationInput): Promise<RuntimeAttestation>
  verify(attestation: RuntimeAttestation): Promise<boolean>
}

export interface PackageAttestationAdapter {
  readonly provider: string
  attest(input: PackageAttestationInput): Promise<RuntimeAttestation>
  verify(attestation: RuntimeAttestation): Promise<boolean>
}

export interface GitHubAttestationAdapter {
  readonly provider: string
  attest(input: GitHubAttestationInput): Promise<RuntimeAttestation>
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

export class HttpTEEAdapter implements TEEAdapter {
  constructor(
    readonly provider: 'aws-nitro' | 'intel-sgx' | 'amd-sev' | string,
    private readonly endpoint: string
  ) {}

  async attest(agentDid: string): Promise<RuntimeAttestation> {
    const response = await fetch(`${this.endpoint.replace(/\/$/, '')}/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentDid, provider: this.provider }),
    })
    if (!response.ok) {
      throw new Error(`${this.provider} attestation failed with HTTP ${response.status}`)
    }
    return response.json() as Promise<RuntimeAttestation>
  }

  async verify(attestation: RuntimeAttestation): Promise<boolean> {
    if (attestation.provider !== this.provider) return false
    if (new Date(attestation.expiresAt) < new Date()) return false
    const response = await fetch(`${this.endpoint.replace(/\/$/, '')}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attestation }),
    })
    if (!response.ok) return false
    const body = await response.json() as { valid?: boolean }
    return body.valid === true
  }
}

export class AwsNitroTEEAdapter extends HttpTEEAdapter {
  constructor(endpoint: string) {
    super('aws-nitro', endpoint)
  }
}

export class IntelSGXTEEAdapter extends HttpTEEAdapter {
  constructor(endpoint: string) {
    super('intel-sgx', endpoint)
  }
}

export class AmdSEVTEEAdapter extends HttpTEEAdapter {
  constructor(endpoint: string) {
    super('amd-sev', endpoint)
  }
}

export class BuildProvenanceAttestationProvider implements BuildAttestationAdapter {
  readonly provider = 'build-provenance'

  async attest(input: BuildAttestationInput): Promise<RuntimeAttestation> {
    const expiresAt = new Date(Date.now() + (input.expiresInMs ?? 24 * 3600_000)).toISOString()
    return createStructuredAttestation({
      provider: this.provider,
      agentDid: input.agentDid,
      measurement: input.imageDigest,
      expiresAt,
      evidence: {
        type: 'build-provenance',
        imageDigest: input.imageDigest,
        sourceCommit: input.sourceCommit,
        builderId: input.builderId,
      },
    })
  }

  async verify(attestation: RuntimeAttestation): Promise<boolean> {
    if (!isFreshProvider(attestation, this.provider)) return false
    const evidence = attestation.evidence as Partial<BuildAttestationInput> & { type?: string }
    return evidence.type === 'build-provenance' &&
      typeof evidence.imageDigest === 'string' &&
      evidence.imageDigest === attestation.measurement &&
      typeof evidence.sourceCommit === 'string' &&
      typeof evidence.builderId === 'string'
  }
}

export class ContainerImageAttestationProvider implements ContainerImageAttestationAdapter {
  readonly provider = 'container-image'

  constructor(private readonly allowedImages?: Array<{ registry: string; repository: string }>) {}

  async attest(input: ContainerImageAttestationInput): Promise<RuntimeAttestation> {
    const expiresAt = new Date(Date.now() + (input.expiresInMs ?? 24 * 3600_000)).toISOString()
    return createStructuredAttestation({
      provider: this.provider,
      agentDid: input.agentDid,
      measurement: input.digest,
      expiresAt,
      evidence: {
        type: 'container-image',
        registry: input.registry,
        repository: input.repository,
        digest: input.digest,
        tag: input.tag,
        sourceCommit: input.sourceCommit,
      },
    })
  }

  async verify(attestation: RuntimeAttestation): Promise<boolean> {
    if (!isFreshProvider(attestation, this.provider)) return false
    const evidence = attestation.evidence as Partial<ContainerImageAttestationInput> & { type?: string }
    if (evidence.type !== 'container-image') return false
    if (typeof evidence.registry !== 'string' || !evidence.registry) return false
    if (typeof evidence.repository !== 'string' || !evidence.repository) return false
    if (typeof evidence.digest !== 'string' || !isSha256Digest(evidence.digest)) return false
    if (evidence.digest !== attestation.measurement) return false
    if (this.allowedImages && !this.allowedImages.some(image =>
      image.registry === evidence.registry && image.repository === evidence.repository
    )) {
      return false
    }
    return true
  }
}

export class GitHubActionsAttestationProvider implements GitHubAttestationAdapter {
  readonly provider = 'github-actions'

  constructor(private readonly allowedRepositories?: string[]) {}

  async attest(input: GitHubAttestationInput): Promise<RuntimeAttestation> {
    const expiresAt = new Date(Date.now() + (input.expiresInMs ?? 6 * 3600_000)).toISOString()
    return createStructuredAttestation({
      provider: this.provider,
      agentDid: input.agentDid,
      measurement: input.sha,
      expiresAt,
      evidence: { type: 'github-actions', ...input },
    })
  }

  async verify(attestation: RuntimeAttestation): Promise<boolean> {
    if (!isFreshProvider(attestation, this.provider)) return false
    const evidence = attestation.evidence as Partial<GitHubAttestationInput> & { type?: string }
    if (evidence.type !== 'github-actions') return false
    if (!evidence.repository || !evidence.workflowRef || !evidence.sha || !evidence.runId) return false
    if (evidence.sha !== attestation.measurement) return false
    if (this.allowedRepositories && !this.allowedRepositories.includes(evidence.repository)) return false
    return true
  }
}

export class PackageRegistryAttestationProvider implements PackageAttestationAdapter {
  readonly provider = 'package-registry'

  async attest(input: PackageAttestationInput): Promise<RuntimeAttestation> {
    const expiresAt = new Date(Date.now() + (input.expiresInMs ?? 24 * 3600_000)).toISOString()
    return createStructuredAttestation({
      provider: this.provider,
      agentDid: input.agentDid,
      measurement: input.integrity,
      expiresAt,
      evidence: { type: 'package-registry', ...input },
    })
  }

  async verify(attestation: RuntimeAttestation): Promise<boolean> {
    if (!isFreshProvider(attestation, this.provider)) return false
    const evidence = attestation.evidence as Partial<PackageAttestationInput> & { type?: string }
    return evidence.type === 'package-registry' &&
      typeof evidence.registry === 'string' &&
      typeof evidence.packageName === 'string' &&
      typeof evidence.version === 'string' &&
      typeof evidence.integrity === 'string' &&
      evidence.integrity === attestation.measurement
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
  disengageAll(): void
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

  disengageAll(): void {
    this.state.clear()
  }

  isEngaged(target: KillSwitchTarget): boolean {
    // Global kill switch overrides everything
    if (this.state.get('global')) return true
    return this.state.get(this.key(target)) ?? false
  }
}

function createStructuredAttestation(input: {
  provider: string
  agentDid: string
  measurement: string
  expiresAt: string
  evidence: unknown
}): RuntimeAttestation {
  return {
    id: crypto.randomUUID(),
    agentDid: input.agentDid,
    provider: input.provider,
    measurement: input.measurement,
    timestamp: new Date().toISOString(),
    expiresAt: input.expiresAt,
    evidence: input.evidence,
    signature: 'structured-local-attestation',
  }
}

function isFreshProvider(attestation: RuntimeAttestation, provider: string): boolean {
  return attestation.provider === provider && new Date(attestation.expiresAt) >= new Date()
}

function isSha256Digest(value: string): boolean {
  return /^sha256:[a-f0-9]{64}$/i.test(value)
}
