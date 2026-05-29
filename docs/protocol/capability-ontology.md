# Capability Ontology

Capabilities are scoped by namespace, action, and resource. Reputation and trust must be capability-specific.

Current implementation anchor:

- `packages/core/src/capability.ts`

## Descriptor Fields

- `id`
- `namespace`
- `action`
- `resource`
- `inputSchema`
- `outputSchema`
- `riskLevel`
- `requiredScopes`
- `supportedControls`
- dry-run support
- human approval support
- policy proof support

## Seed Capabilities

The seed ontology includes calendar, invoice, payments, code, file, and deploy capabilities.

Payment execution remains Sardis-specific. Generic FIDES may model `payments.prepare` and dry-run flows, but payment execution authority stays in Sardis.
