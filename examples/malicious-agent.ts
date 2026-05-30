/**
 * Malicious Agent example.
 *
 * Demonstrates adversarial metadata that FIDES should discover only as a
 * candidate, then penalize or deny through verification, trust, revocation,
 * incident, and policy checks.
 *
 * Run: pnpm exec tsx examples/malicious-agent.ts
 */

import {
  createCapabilityDescriptor,
  createIncidentRecordV2,
  computeCapabilityReputation,
  computeTrustResult,
  evaluateInvocationPreflight,
} from '@fides/core'

function main() {
  const capability = createCapabilityDescriptor({
    id: 'payments.execute',
    requiredScopes: ['payments:execute'],
    supportedControls: ['human_approval', 'runtime_attestation', 'policy_proof'],
  })

  const incident = createIncidentRecordV2({
    reporter: 'did:fides:principal',
    targetAgentId: 'did:fides:malicious-agent',
    severity: 'critical',
    category: 'unauthorized_action',
    description: 'Agent attempted to launder a payment execution as a low-risk calendar action.',
    evidenceRefs: ['evt_malicious_1'],
  })

  const reputation = computeCapabilityReputation({
    agentId: 'did:fides:malicious-agent',
    publisherId: 'did:fides:fake-publisher',
    capability: capability.id,
    successfulInvocations: 0,
    failedInvocations: 4,
    incidentCount: 1,
    publisherWeight: 0.1,
    contextBoundaryMismatch: true,
  })

  const trust = computeTrustResult({
    agentId: 'did:fides:malicious-agent',
    capability,
    evidenceRefs: incident.evidence_refs,
    components: {
      identity: 0.2,
      publisher: 0.1,
      trustAnchors: 0,
      capabilityFit: 0.4,
      evidence: 0.1,
      policyCompliance: 0,
      runtimeSafety: 0,
      peerAttestation: 0.1,
      incidentPenalty: incident.trust_penalty,
      noveltyPenalty: 0.4,
      contextBoundaryPenalty: reputation.context_boundary_penalty,
    },
  })

  const preflight = evaluateInvocationPreflight({
    request: {
      schema_version: 'fides.invocation.request.v1',
      id: 'inv_req_malicious',
      issuer: 'did:fides:requester',
      subject: 'did:fides:malicious-agent',
      session_id: 'missing-session',
      requester_agent_id: 'did:fides:requester',
      target_agent_id: 'did:fides:malicious-agent',
      principal_id: 'did:fides:principal',
      capability: capability.id,
      scopes: ['payments:execute'],
      dry_run: false,
      input_hash: 'sha256:input',
      issued_at: new Date().toISOString(),
      payload_hash: 'sha256:payload',
    },
    policyDecision: {
      decision: 'deny',
      reason_codes: ['REVOCATION_ACTIVE', 'TRUST_BELOW_THRESHOLD'],
    },
  })

  console.log(JSON.stringify({
    agent: 'did:fides:malicious-agent',
    capability: capability.id,
    incident,
    reputation,
    trust,
    preflight,
  }, null, 2))
}

main()
