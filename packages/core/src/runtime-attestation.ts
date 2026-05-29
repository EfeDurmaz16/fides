import { hashProtocolPayload } from './protocol.js'

export interface RuntimeAttestation {
  schema_version: 'fides.runtime_attestation.v1'
  attestation_id: string
  agent_id: string
  provider: 'mock-tee' | 'null' | 'aws-nitro' | 'intel-sgx' | 'amd-sev' | 'container-image' | 'reproducible-build' | string
  code_hash: string
  runtime_hash: string
  policy_hash: string
  enclave_measurement?: string
  issued_at: string
  expires_at: string
  signature: string
}

export interface RuntimeAttestationIssueInput {
  agentId: string
  codeHash: string
  runtimeHash: string
  policyHash: string
  enclaveMeasurement?: string
  issuedAt?: string
  expiresAt?: string
}

export interface AttestationProvider {
  readonly provider: RuntimeAttestation['provider']
  issue(input: RuntimeAttestationIssueInput): Promise<RuntimeAttestation>
  verify(attestation: RuntimeAttestation): Promise<boolean>
}

export interface TeeAttestationProvider extends AttestationProvider {}
export interface ContainerBuildAttestationProvider extends AttestationProvider {}

const DEFAULT_ATTESTATION_TTL_MS = 3600_000

export function isRuntimeAttestationExpired(attestation: RuntimeAttestation, now: Date = new Date()): boolean {
  return new Date(attestation.expires_at) <= now
}

export function createRuntimeAttestation(input: RuntimeAttestationIssueInput & {
  provider: RuntimeAttestation['provider']
  signature: string
}): RuntimeAttestation {
  const issuedAt = input.issuedAt ?? new Date().toISOString()
  return {
    schema_version: 'fides.runtime_attestation.v1',
    attestation_id: crypto.randomUUID(),
    agent_id: input.agentId,
    provider: input.provider,
    code_hash: input.codeHash,
    runtime_hash: input.runtimeHash,
    policy_hash: input.policyHash,
    enclave_measurement: input.enclaveMeasurement ?? hashProtocolPayload({
      agent_id: input.agentId,
      code_hash: input.codeHash,
      runtime_hash: input.runtimeHash,
      policy_hash: input.policyHash,
      issued_at: issuedAt,
      provider: input.provider,
    }),
    issued_at: issuedAt,
    expires_at: input.expiresAt ?? new Date(Date.now() + DEFAULT_ATTESTATION_TTL_MS).toISOString(),
    signature: input.signature,
  }
}

export async function verifyRuntimeAttestation(
  attestation: RuntimeAttestation,
  provider: Pick<AttestationProvider, 'provider' | 'verify'>
): Promise<boolean> {
  if (attestation.provider !== provider.provider) return false
  if (isRuntimeAttestationExpired(attestation)) return false
  return provider.verify(attestation)
}

export class MockTEEProvider implements TeeAttestationProvider {
  readonly provider = 'mock-tee'

  async issue(input: RuntimeAttestationIssueInput): Promise<RuntimeAttestation> {
    return createRuntimeAttestation({
      ...input,
      provider: this.provider,
      signature: 'mock-tee-signature',
    })
  }

  async verify(attestation: RuntimeAttestation): Promise<boolean> {
    if (attestation.provider !== this.provider) return false
    if (isRuntimeAttestationExpired(attestation)) return false
    return attestation.signature === 'mock-tee-signature' &&
      isSha256(attestation.code_hash) &&
      isSha256(attestation.runtime_hash) &&
      isSha256(attestation.policy_hash) &&
      Boolean(attestation.enclave_measurement)
  }
}

export class NullAttestationProvider implements AttestationProvider {
  readonly provider = 'null'

  async issue(input: RuntimeAttestationIssueInput): Promise<RuntimeAttestation> {
    return createRuntimeAttestation({
      ...input,
      provider: this.provider,
      signature: 'null-attestation',
    })
  }

  async verify(_attestation: RuntimeAttestation): Promise<boolean> {
    return false
  }
}

function isSha256(value: string): boolean {
  return /^sha256:[a-f0-9]{64}$/i.test(value)
}
