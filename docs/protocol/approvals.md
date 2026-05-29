# Approvals

Approvals convert pending high-risk actions into explicit authority decisions.

Current implementation anchor:

- `packages/core/src/approval.ts`

## Objects

- `ApprovalRequest`
- `ApprovalDecision`

Approval requests include requester, target, principal, capability, scopes, risk level, policy decision hash, and evidence refs.

Approval decisions are signed by the approver and may include constraints.
