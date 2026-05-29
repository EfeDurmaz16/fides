import { signObject, verifyObject, type SignedObject } from './canonical-signer.js'
import { hashProtocolPayload } from './protocol.js'
import type { SessionGrantV2 } from './delegation.js'

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

export function createInvocationRequest(input: InvocationRequestInput): InvocationRequest {
  const payload = {
    schema_version: 'fides.invocation.request.v1' as const,
    id: crypto.randomUUID(),
    issuer: input.issuer,
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
