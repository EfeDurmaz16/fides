import { hashProtocolPayload } from './protocol.js'

export interface RuntimeAttestation {
  schema_version: 'fides.runtime_attestation.v1'
  id: string
  issuer: string
  subject: string
  attestation_id: string
  agent_id: string
  provider: 'mock-tee' | 'null' | 'aws-nitro' | 'intel-sgx' | 'amd-sev' | 'container-image' | 'reproducible-build' | string
  code_hash: string
  runtime_hash: string
  policy_hash: string
  enclave_measurement?: string
  issued_at: string
  expires_at: string
  payload_hash: string
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
  issuer?: string
  signature?: string
}): RuntimeAttestation {
  const issuedAt = input.issuedAt ?? new Date().toISOString()
  const id = crypto.randomUUID()
  const payload = {
    schema_version: 'fides.runtime_attestation.v1',
    id,
    issuer: input.issuer ?? input.provider,
    subject: input.agentId,
    attestation_id: id,
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
  } satisfies Omit<RuntimeAttestation, 'payload_hash' | 'signature'>

  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
    signature: input.signature ?? localRuntimeAttestationSignature(payload),
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
    })
  }

  async verify(attestation: RuntimeAttestation): Promise<boolean> {
    if (attestation.provider !== this.provider) return false
    if (isRuntimeAttestationExpired(attestation)) return false
    const payload = runtimeAttestationPayload(attestation)
    return attestation.payload_hash === hashProtocolPayload(payload) &&
      attestation.signature === localRuntimeAttestationSignature(payload) &&
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

function runtimeAttestationPayload(attestation: RuntimeAttestation): Omit<RuntimeAttestation, 'payload_hash' | 'signature'> {
  return {
    schema_version: attestation.schema_version,
    id: attestation.id,
    issuer: attestation.issuer,
    subject: attestation.subject,
    attestation_id: attestation.attestation_id,
    agent_id: attestation.agent_id,
    provider: attestation.provider,
    code_hash: attestation.code_hash,
    runtime_hash: attestation.runtime_hash,
    policy_hash: attestation.policy_hash,
    enclave_measurement: attestation.enclave_measurement,
    issued_at: attestation.issued_at,
    expires_at: attestation.expires_at,
  }
}

function localRuntimeAttestationSignature(payload: Omit<RuntimeAttestation, 'payload_hash' | 'signature'>): string {
  return `local-attestation:${hashProtocolPayload(payload).slice('sha256:'.length)}`
}
