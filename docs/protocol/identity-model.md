# Identity Model

FIDES separates agent identity, publisher identity, and principal identity.

Current implementation anchors:

- `packages/core/src/identity.ts`
- `packages/core/src/trust-anchor.ts`
- `packages/core/src/domain-verifier.ts`
- `packages/core/src/passkey.ts`

## Identity Types

- `AgentIdentity`: stable cryptographic identity for an agent.
- `PublisherIdentity`: human, developer, organization, project, company, or platform publisher.
- `PrincipalIdentity`: human, organization, or service on whose behalf an action is authorized.

## Publisher Types

- `anonymous`
- `self_signed`
- `verified_individual`
- `platform_hosted`
- `domain_verified`
- `organization_verified`

## Trust Anchors

Domains are optional and are only one trust anchor. Other anchors include GitHub, email, npm, PyPI, wallet, passkey, organization invitation, runtime attestation, build attestation, peer attestation, and evidence history.

Identity never equals trust. A valid identity can still be low trust.
