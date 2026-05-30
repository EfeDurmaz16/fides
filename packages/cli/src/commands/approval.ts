import { Command } from 'commander'
import { getJson, parseJsonObject, parseList, postJson, printResult } from './authority-utils.js'

export function createApprovalCommand(): Command {
  const cmd = new Command('approval')
    .description('Approval requests and decisions')

  cmd.command('request')
    .description('Create a root v2 approval request')
    .requiredOption('--agent <id>', 'Target agent DID')
    .requiredOption('--capability <capability>', 'Capability ID')
    .option('--requester-agent <id>', 'Requester agent DID')
    .option('--principal <id>', 'Principal DID')
    .option('--requested-scopes <csv>', 'Comma-separated requested scopes')
    .option('--risk-level <level>', 'Risk level: low, medium, high, critical')
    .option('--policy-decision-hash <hash>', 'Policy decision hash')
    .option('--evidence-refs <csv>', 'Comma-separated evidence event IDs')
    .option('--expires-at <iso>', 'Expiration timestamp')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      const result = await postJson(`${baseUrl(options.agentdUrl)}/approvals`, {
        targetAgentId: options.agent,
        capability: options.capability,
        ...(options.requesterAgent && { requesterAgentId: options.requesterAgent }),
        ...(options.principal && { principalId: options.principal }),
        requestedScopes: parseList(options.requestedScopes),
        ...(options.riskLevel && { riskLevel: options.riskLevel }),
        ...(options.policyDecisionHash && { policyDecisionHash: options.policyDecisionHash }),
        evidenceRefs: parseList(options.evidenceRefs),
        ...(options.expiresAt && { expiresAt: options.expiresAt }),
      })
      printResult('Approval requested:', result, options)
    })

  cmd.command('list')
    .description('List root v2 approval requests')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      const result = await getJson(`${baseUrl(options.agentdUrl)}/approvals`)
      printResult('Approvals:', result, options)
    })

  cmd.command('approve')
    .description('Approve a root v2 approval request')
    .argument('<approval-id>', 'Approval request ID')
    .option('--approver <id>', 'Approver DID')
    .option('--reason <reason>', 'Approval reason')
    .option('--constraints <json>', 'Decision constraints JSON object')
    .option('--evidence-refs <csv>', 'Comma-separated evidence event IDs')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (approvalId, options) => {
      const result = await postJson(`${baseUrl(options.agentdUrl)}/approvals/${encodeURIComponent(approvalId)}/approve`, decisionBody(options))
      printResult('Approval approved:', result, options)
    })

  cmd.command('deny')
    .description('Deny a root v2 approval request')
    .argument('<approval-id>', 'Approval request ID')
    .option('--approver <id>', 'Approver DID')
    .option('--reason <reason>', 'Denial reason')
    .option('--constraints <json>', 'Decision constraints JSON object')
    .option('--evidence-refs <csv>', 'Comma-separated evidence event IDs')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (approvalId, options) => {
      const result = await postJson(`${baseUrl(options.agentdUrl)}/approvals/${encodeURIComponent(approvalId)}/deny`, decisionBody(options))
      printResult('Approval denied:', result, options)
    })

  return cmd
}

function decisionBody(options: {
  approver?: string
  reason?: string
  constraints?: string
  evidenceRefs?: string
}): Record<string, unknown> {
  return {
    ...(options.approver && { approverId: options.approver }),
    ...(options.reason && { reason: options.reason }),
    constraints: parseJsonObject(options.constraints),
    evidenceRefs: parseList(options.evidenceRefs),
  }
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}
