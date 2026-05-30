import { signObject, verifyObject, type SignedObject } from './canonical-signer.js'
import { hashProtocolPayload } from './protocol.js'
import type { JSONSchema } from './capability.js'
import { isSessionGrantV2Expired, type SessionGrantV2 } from './delegation.js'

export type InvocationStatus =
  | 'dry_run'
  | 'approval_required'
  | 'denied'
  | 'allowed'
  | 'completed'
  | 'failed'

export interface InvocationRequest {
  schema_version: 'fides.invocation.request.v1'
  id: string
  issuer: string
  subject: string
  session_id: string
  requester_agent_id: string
  target_agent_id: string
  principal_id: string
  capability: string
  scopes: string[]
  dry_run: boolean
  input_hash: string
  input_schema_hash?: string
  output_schema_hash?: string
  issued_at: string
  payload_hash: string
}

export interface InvocationResult {
  schema_version: 'fides.invocation.result.v1'
  id: string
  issuer: string
  subject: string
  invocation_request_id: string
  status: InvocationStatus
  output_hash?: string
  error_code?: string
  evidence_refs: string[]
  created_at: string
  payload_hash: string
}

export type SignedInvocationRequest = SignedObject<InvocationRequest>
export type SignedInvocationResult = SignedObject<InvocationResult>

export interface InvocationRequestInput {
  issuer: string
  sessionGrant: SessionGrantV2
  input: unknown
  dryRun?: boolean
  inputSchema?: unknown
  outputSchema?: unknown
  issuedAt?: string
}

export interface InvocationResultInput {
  issuer: string
  invocationRequestId: string
  status: InvocationStatus
  output?: unknown
  errorCode?: string
  evidenceRefs?: string[]
  createdAt?: string
}

export interface InvocationPolicyDecisionLike {
  decision: 'allow' | 'deny' | 'require_approval' | 'dry_run_only' | 'scope_limit' | 'risk_limit'
  reason_codes: string[]
}

export interface InvocationPreflightInput {
  request: InvocationRequest
  policyDecision: InvocationPolicyDecisionLike
}

export interface InvocationPreflightResult {
  status: InvocationStatus
  can_execute: boolean
  dry_run_only: boolean
  reason_codes: string[]
}

export interface SchemaValidationResult {
  valid: boolean
  errors: string[]
}

export interface InvocationGrantValidationInput {
  request: InvocationRequest
  sessionGrant: SessionGrantV2
  now?: Date
}

export function createInvocationRequest(input: InvocationRequestInput): InvocationRequest {
  const payload = {
    schema_version: 'fides.invocation.request.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.issuer,
    subject: input.sessionGrant.target_agent_id,
    session_id: input.sessionGrant.session_id,
    requester_agent_id: input.sessionGrant.requester_agent_id,
    target_agent_id: input.sessionGrant.target_agent_id,
    principal_id: input.sessionGrant.principal_id,
    capability: input.sessionGrant.capability,
    scopes: input.sessionGrant.scopes,
    dry_run: input.dryRun ?? false,
    input_hash: hashProtocolPayload(input.input),
    input_schema_hash: input.inputSchema ? hashProtocolPayload(input.inputSchema) : undefined,
    output_schema_hash: input.outputSchema ? hashProtocolPayload(input.outputSchema) : undefined,
    issued_at: input.issuedAt ?? new Date().toISOString(),
  }

  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
  }
}

export function createInvocationResult(input: InvocationResultInput): InvocationResult {
  const payload = {
    schema_version: 'fides.invocation.result.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.issuer,
    subject: input.invocationRequestId,
    invocation_request_id: input.invocationRequestId,
    status: input.status,
    output_hash: input.output === undefined ? undefined : hashProtocolPayload(input.output),
    error_code: input.errorCode,
    evidence_refs: input.evidenceRefs ?? [],
    created_at: input.createdAt ?? new Date().toISOString(),
  }

  return {
    ...payload,
    payload_hash: hashProtocolPayload(payload),
  }
}

export function evaluateInvocationPreflight(input: InvocationPreflightInput): InvocationPreflightResult {
  switch (input.policyDecision.decision) {
    case 'allow':
      return {
        status: input.request.dry_run ? 'dry_run' : 'allowed',
        can_execute: !input.request.dry_run,
        dry_run_only: input.request.dry_run,
        reason_codes: input.policyDecision.reason_codes,
      }
    case 'dry_run_only':
      return {
        status: 'dry_run',
        can_execute: false,
        dry_run_only: true,
        reason_codes: input.policyDecision.reason_codes,
      }
    case 'require_approval':
      return {
        status: 'approval_required',
        can_execute: false,
        dry_run_only: false,
        reason_codes: input.policyDecision.reason_codes,
      }
    default:
      return {
        status: 'denied',
        can_execute: false,
        dry_run_only: false,
        reason_codes: input.policyDecision.reason_codes,
      }
  }
}

export function validateInvocationRequestAgainstSessionGrant(
  input: InvocationGrantValidationInput
): SchemaValidationResult {
  const { request, sessionGrant } = input
  const errors: string[] = []
  const { payload_hash: _, ...requestPayload } = request

  if (request.schema_version !== 'fides.invocation.request.v1') {
    errors.push('InvocationRequest.schema_version is invalid')
  }
  if (request.payload_hash !== hashProtocolPayload(requestPayload)) {
    errors.push('InvocationRequest.payload_hash mismatch')
  }
  if (isSessionGrantV2Expired(sessionGrant, input.now)) {
    errors.push('SessionGrant is expired')
  }
  if (request.session_id !== sessionGrant.session_id) {
    errors.push('InvocationRequest.session_id does not match SessionGrant')
  }
  if (request.issuer !== sessionGrant.requester_agent_id) {
    errors.push('InvocationRequest.issuer must match SessionGrant.requester_agent_id')
  }
  if (request.requester_agent_id !== sessionGrant.requester_agent_id) {
    errors.push('InvocationRequest.requester_agent_id does not match SessionGrant')
  }
  if (request.target_agent_id !== sessionGrant.target_agent_id) {
    errors.push('InvocationRequest.target_agent_id does not match SessionGrant')
  }
  if (request.subject !== sessionGrant.target_agent_id) {
    errors.push('InvocationRequest.subject must match SessionGrant.target_agent_id')
  }
  if (request.principal_id !== sessionGrant.principal_id) {
    errors.push('InvocationRequest.principal_id does not match SessionGrant')
  }
  if (request.capability !== sessionGrant.capability) {
    errors.push('InvocationRequest.capability does not match SessionGrant')
  }
  if (!sessionGrant.audience.includes(request.target_agent_id)) {
    errors.push('SessionGrant audience does not include InvocationRequest.target_agent_id')
  }

  const grantedScopes = new Set(sessionGrant.scopes)
  for (const scope of request.scopes) {
    if (!grantedScopes.has(scope)) {
      errors.push(`InvocationRequest.scope ${scope} is not granted by SessionGrant`)
    }
  }

  return { valid: errors.length === 0, errors }
}

export function validateJsonSchemaValue(schema: JSONSchema | undefined, value: unknown): SchemaValidationResult {
  if (!schema) return { valid: true, errors: [] }
  const errors: string[] = []
  validateAgainstSchema(schema, value, '$', errors)
  return { valid: errors.length === 0, errors }
}

function validateAgainstSchema(schema: JSONSchema, value: unknown, path: string, errors: string[]): void {
  if (schema.const !== undefined && !Object.is(value, schema.const)) {
    errors.push(`${path} must equal ${JSON.stringify(schema.const)}`)
  }

  if (Array.isArray(schema.enum) && !schema.enum.some(item => Object.is(item, value))) {
    errors.push(`${path} must be one of ${schema.enum.map(item => JSON.stringify(item)).join(', ')}`)
  }

  if (schema.type && !matchesJsonSchemaType(value, schema.type)) {
    errors.push(`${path} must be ${schema.type}`)
    return
  }

  if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return
    const objectValue = value as Record<string, unknown>
    for (const key of schema.required ?? []) {
      if (!(key in objectValue)) {
        errors.push(`${path}.${key} is required`)
      }
    }

    const properties = schema.properties ?? {}
    for (const [key, propertySchema] of Object.entries(properties)) {
      if (key in objectValue && isJsonSchema(propertySchema)) {
        validateAgainstSchema(propertySchema, objectValue[key], `${path}.${key}`, errors)
      }
    }

    if (schema.additionalProperties === false) {
      for (const key of Object.keys(objectValue)) {
        if (!(key in properties)) {
          errors.push(`${path}.${key} is not allowed`)
        }
      }
    }
  }

  if (schema.type === 'array' && Array.isArray(value) && isJsonSchema(schema.items)) {
    value.forEach((item, index) => validateAgainstSchema(schema.items as JSONSchema, item, `${path}[${index}]`, errors))
  }
}

function matchesJsonSchemaType(value: unknown, type: string): boolean {
  switch (type) {
    case 'object':
      return Boolean(value && typeof value === 'object' && !Array.isArray(value))
    case 'array':
      return Array.isArray(value)
    case 'string':
      return typeof value === 'string'
    case 'number':
      return typeof value === 'number' && Number.isFinite(value)
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value)
    case 'boolean':
      return typeof value === 'boolean'
    case 'null':
      return value === null
    default:
      return true
  }
}

function isJsonSchema(value: unknown): value is JSONSchema {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) && typeof (value as { type?: unknown }).type === 'string')
}

export function signInvocationRequest(
  request: InvocationRequest,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedInvocationRequest> {
  return signObject(request, privateKey, { verificationMethod, proofPurpose: 'capabilityInvocation' })
}

export function verifySignedInvocationRequest(signed: SignedInvocationRequest): Promise<boolean> {
  return verifyObject(signed)
}

export async function verifySignedInvocationRequestIssuer(signed: SignedInvocationRequest): Promise<boolean> {
  return signed.proof.verificationMethod === signed.payload.issuer && await verifySignedInvocationRequest(signed)
}

export function signInvocationResult(
  result: InvocationResult,
  privateKey: Uint8Array,
  verificationMethod: string
): Promise<SignedInvocationResult> {
  return signObject(result, privateKey, { verificationMethod, proofPurpose: 'capabilityInvocation' })
}

export function verifySignedInvocationResult(signed: SignedInvocationResult): Promise<boolean> {
  return verifyObject(signed)
}

export async function verifySignedInvocationResultIssuer(signed: SignedInvocationResult): Promise<boolean> {
  return signed.proof.verificationMethod === signed.payload.issuer && await verifySignedInvocationResult(signed)
}
