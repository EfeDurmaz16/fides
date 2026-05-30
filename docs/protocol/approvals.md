# Approvals

Approvals convert pending high-risk actions into explicit authority decisions.

Current implementation anchor:

- `packages/core/src/approval.ts`

## Objects

- `ApprovalRequest`
- `ApprovalDecision`

Approval requests include `id`, `issuer`, `subject`, requester, target,
principal, capability, scopes, risk level, policy decision hash, evidence refs,
timestamps, and canonical `payload_hash`. The request issuer is the requester
agent and the subject is the target agent.

Approval decisions include `id`, `issuer`, `subject`, approver, decision,
constraints, evidence refs, timestamps, and canonical `payload_hash`. The
decision issuer is the approver and the subject is the approval request id.
Approval decisions are signed by the approver and may include constraints.

## Evidence

The local root daemon appends hash-only evidence for approval lifecycle
mutations:

- `approval.requested`
- `approval.granted`
- `approval.denied`

These events record authorization intent and decision provenance. They do not
grant authority without a subsequent policy evaluation and scoped
`SessionGrant`.
