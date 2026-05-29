# Trust Model

Trust is a signal, not permission.

Current implementation anchors:

- `packages/core/src/trust.ts`
- `services/trust-graph/src/`

## Trust Result

A `TrustResult` includes:

- score
- band
- reasons
- risk flags
- evidence refs
- required controls
- computed timestamp

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
