# @fides/attestations

Generic attestations, runtime attestations, and TEE-ready provider entrypoints
for FIDES v2.

Generic `Attestation` records express signed claims from a provider or trust
anchor about an agent, publisher, principal, domain, package, wallet, passkey,
runtime, build, or peer signal. Runtime attestations bind an agent to code,
runtime, policy, and enclave or build measurements. FIDES uses both as trust and
policy inputs while keeping protocol objects framework-agnostic.

## Installation

```bash
npm install @fides/attestations
```

## Usage

```typescript
import {
  MockTEEProvider,
  NullAttestationProvider,
  createAttestation,
  createRuntimeAttestation,
  signAttestation,
  verifySignedAttestationIssuer,
  verifyRuntimeAttestation,
} from '@fides/attestations'

const attestation = createAttestation({
  issuer: 'did:fides:publisher',
  subject: 'did:fides:agent',
  subjectType: 'agent',
  provider: 'github',
  claims: { handle: 'fides-dev' },
  evidenceRefs: ['evt_github_1'],
})

const signed = await signAttestation(attestation, privateKey, 'did:fides:publisher')
await verifySignedAttestationIssuer(signed)
```

## Status

Generic attestations and MockTEE runtime attestations are TypeScript-first local
protocol surfaces. `MockTEEProvider` and `NullAttestationProvider` are local
development surfaces. AWS Nitro, SGX, SEV, container image, reproducible build,
package registry, wallet, passkey, and peer attestation providers are
adapter-ready interfaces, not production integrations in this package snapshot.

## License

MIT
