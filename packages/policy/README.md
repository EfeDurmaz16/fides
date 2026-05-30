# @fides/policy

Deterministic policy evaluation for FIDES.

This package evaluates policy bundles against request and trust context before an agent action executes. Decisions are explicit: `allow`, `deny`, `require_approval`, `dry_run_only`, `scope_limit`, or `risk_limit`.

FIDES v2 policy decisions are protocol objects. The v2 evaluator returns `id`, `issuer`, `subject`, `issued_at`, machine-readable reasons, human-readable reasons, required controls, evidence refs, and a canonical `payload_hash` so the decision can be signed by the shared FIDES canonical object signing model.

## Installation

```bash
npm install @fides/policy
```

## Usage

```typescript
import { evaluateFidesPolicy } from '@fides/policy'

const decision = evaluateFidesPolicy({
  issuerId: 'did:fides:policy-engine',
  principalId: 'did:fides:principal',
  requesterAgentId: 'did:fides:requester',
  targetAgentId: 'did:fides:invoice-agent',
  capability: {
    id: 'invoice.reconcile',
    namespace: 'invoice',
    action: 'reconcile',
    name: 'Invoice reconciliation',
    description: 'Match invoice data against records',
    inputSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    riskLevel: 'medium',
    requiresApproval: false,
    requiresRuntimeAttestation: false,
    requiredScopes: ['invoice:read'],
    supportedControls: ['dry_run', 'human_approval', 'scope_limit'],
  },
  trustResult: {
    schema_version: 'fides.trust.result.v1',
    id: 'trust_result_1',
    issuer: 'did:fides:trust-engine',
    subject: 'did:fides:invoice-agent',
    agent_id: 'did:fides:invoice-agent',
    capability: 'invoice.reconcile',
    score: 0.82,
    band: 'high',
    reasons: [],
    risk_flags: [],
    evidence_refs: ['evt_1'],
    required_controls: [],
    computed_at: new Date().toISOString(),
    payload_hash: 'sha256:...',
  },
  requestedScopes: ['invoice:read'],
})

console.log(decision.decision, decision.payload_hash)
```

## License

MIT
