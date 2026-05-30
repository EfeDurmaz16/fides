import type {
  DiscoveryCandidate,
  DiscoveryQuery,
  InvocationPolicyDecisionLike,
  SessionGrantV2,
  TrustResult,
} from '@fides/core'

export type RuntimeWorkflowStep =
  | 'discover'
  | 'verify_agent_card'
  | 'evaluate_trust'
  | 'evaluate_policy'
  | 'issue_session'
  | 'append_evidence'

export interface RuntimeWorkflowContext {
  query?: DiscoveryQuery
  candidates?: DiscoveryCandidate[]
  trustResult?: TrustResult
  policyDecision?: InvocationPolicyDecisionLike
  sessionGrant?: SessionGrantV2
  evidenceEvents?: unknown[]
}

export interface RuntimeWorkflow {
  id: string
  name: string
  steps: RuntimeWorkflowStep[]
  context: RuntimeWorkflowContext
}

export interface RuntimeWorkflowRunner {
  run(workflow: RuntimeWorkflow): Promise<RuntimeWorkflowContext>
}

export function createRuntimeWorkflow(input: {
  id?: string
  name?: string
  steps?: RuntimeWorkflowStep[]
  context?: RuntimeWorkflowContext
}): RuntimeWorkflow {
  return {
    id: input.id ?? crypto.randomUUID(),
    name: input.name ?? 'fides-runtime-workflow',
    steps: input.steps ?? [
      'discover',
      'verify_agent_card',
      'evaluate_trust',
      'evaluate_policy',
      'issue_session',
      'append_evidence',
    ],
    context: input.context ?? {},
  }
}

export async function runRuntimeWorkflow(
  workflow: RuntimeWorkflow,
  runner: RuntimeWorkflowRunner
): Promise<RuntimeWorkflowContext> {
  return runner.run(workflow)
}
