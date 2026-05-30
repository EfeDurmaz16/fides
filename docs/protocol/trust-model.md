# Trust Model

Trust is a signal, not permission.

Current implementation anchors:

- `packages/core/src/trust.ts`
- `services/trust-graph/src/`

## Trust Result

A `TrustResult` includes:

- id
- issuer
- subject
- agent id
- capability
- score
- band
- reasons
- risk flags
- evidence refs
- required controls
- computed timestamp
- payload hash

`payload_hash` is computed with the shared canonical JSON digest over the
machine-readable trust result. Session grants and policy decisions can bind to
that hash without treating trust as authority.

## Components

- IdentityScore
- PublisherScore
- TrustAnchorScore
- CapabilityFitScore
- EvidenceScore
- PolicyComplianceScore
- RuntimeSafetyScore
- PeerAttestationScore
- IncidentPenalty
- NoveltyPenalty
- ContextBoundaryPenalty

Policy remains the authority. A high trust score can still be denied by policy.
