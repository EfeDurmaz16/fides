# Protocol Version Negotiation

FIDES v2 protocol objects declare compatible versions so discovery, registry, DHT, and session flows can fail closed when peers cannot speak the same protocol.

Current implementation anchors:

- `packages/core/src/versioning.ts`
- `packages/core/src/protocol.ts`

## Required Fields

- `supported_versions`: versions a peer can speak.
- `required_versions`: versions the requester requires.
- `negotiated_version`: selected version.
- `compatible`: whether a safe version exists.
- `error`: stable compatibility error when negotiation fails.

## Flow

1. Read requester required/supported versions.
2. Read candidate supported versions from AgentCard or registry/DHT record.
3. Select the highest mutually supported version.
4. Reject with `VERSION_INCOMPATIBLE` when no overlap exists.

Version compatibility is a discovery filter. It does not grant authority.
