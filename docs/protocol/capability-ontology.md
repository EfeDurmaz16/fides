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

Invocation treats `inputSchema` and `outputSchema` as enforceable authority
checks, not just descriptive metadata. The local daemon rejects inputs that do
not satisfy the advertised `inputSchema`, and fails the invocation if generated
output does not satisfy `outputSchema`.

`createCapabilityDescriptor()` applies seed ontology defaults before falling
back to heuristic risk classification. This matters for capabilities like
`payments.prepare`: the generic FIDES ontology classifies preparation as
`high`, while `payments.execute` remains `critical` and Sardis-specific for real
payment execution authority.

## Seed Capabilities

The seed ontology includes calendar, invoice, payments, code, file, and deploy capabilities.

Payment execution remains Sardis-specific. Generic FIDES may model `payments.prepare` and dry-run flows, but payment execution authority stays in Sardis.
