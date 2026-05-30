# @fides/attestations

Runtime attestation and TEE-ready provider entrypoints for FIDES v2.

Runtime attestations bind an agent to code, runtime, policy, and enclave or
build measurements. FIDES uses them as trust and policy inputs, especially for
high-risk capabilities, while keeping protocol objects framework-agnostic.

## Installation

```bash
npm install @fides/attestations
```

## Usage

```typescript
import {
  MockTEEProvider,
  NullAttestationProvider,
  createRuntimeAttestation,
  verifyRuntimeAttestation,
} from '@fides/attestations'
```

## Status

`MockTEEProvider` and `NullAttestationProvider` are local development surfaces.
AWS Nitro, SGX, SEV, container image, and reproducible build providers are
adapter-ready interfaces, not production integrations in this package snapshot.

## License

MIT
