import { signObject, verifyObject, type SignedObject } from './canonical-signer.js'
import { hashProtocolPayload } from './protocol.js'

export type AttestationSubjectType =
  | 'agent'
  | 'publisher'
  | 'principal'
  | 'domain'
  | 'package'
  | 'wallet'
  | 'passkey'
  | 'runtime'
  | 'build'
  | 'peer'

export interface Attestation {
  schema_version: 'fides.attestation.v1'
  id: string
  issuer: string
  subject: string
  subject_type: AttestationSubjectType
  provider: string
  claims: Record<string, unknown>
  evidence_refs: string[]
  issued_at: string
  expires_at?: string
  payload_hash: string
  signature: string
}

export type SignedAttestation = SignedObject<Attestation>

export interface AttestationInput {
  issuer: string
  subject: string
  subjectType: AttestationSubjectType
  provider: string
  claims?: Record<string, unknown>
  evidenceRefs?: string[]
  issuedAt?: string
  expiresAt?: string
  signature?: string
}

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

export function createAttestation(input: AttestationInput): Attestation {
  const issuedAt = input.issuedAt ?? new Date().toISOString()
  const payload = {
    schema_version: 'fides.attestation.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.issuer,
    subject: input.subject,
    subject_type: input.subjectType,
    provider: input.provider,
    claims: input.claims ?? {},
    evidence_refs: input.evidenceRefs ?? [],
    issued_at: issuedAt,
    expires_at: input.expiresAt,
  }

  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
    signature: input.signature ?? '',
  }
}

export function isAttestationExpired(attestation: Attestation, now: Date = new Date()): boolean {
  return attestation.expires_at ? new Date(attestation.expires_at) <= now : false
}

export function signAttestation(
  attestation: Attestation,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedAttestation> {
  return signObject(attestation, privateKey, { verificationMethod, proofPurpose: 'assertionMethod' })
}

export function verifySignedAttestation(signed: SignedAttestation): Promise<boolean> {
  return verifyObject(signed)
}

export async function verifySignedAttestationIssuer(signed: SignedAttestation): Promise<boolean> {
  return signed.proof.verificationMethod === signed.payload.issuer && await verifySignedAttestation(signed)
}

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
