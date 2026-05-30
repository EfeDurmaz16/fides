# Approvals

Approvals convert pending high-risk actions into explicit authority decisions.

Current implementation anchor:

- `packages/core/src/approval.ts`

## Objects

- `ApprovalRequest`
- `ApprovalDecision`

Approval requests include requester, target, principal, capability, scopes, risk level, policy decision hash, and evidence refs.

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
