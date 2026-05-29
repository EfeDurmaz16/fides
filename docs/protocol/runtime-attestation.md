# Runtime Attestation

Runtime attestation provides evidence about where and how an agent is running. It does not grant authority by itself.

Current implementation anchors:

- `packages/core/src/runtime-attestation.ts`
- `packages/runtime/src/index.ts`

## Providers

- `MockTEEProvider`
- `NullAttestationProvider`
- AWS Nitro adapter-ready
- Intel SGX adapter-ready
- AMD SEV adapter-ready
- container image attestation adapter-ready
- reproducible build attestation adapter-ready

## Policy Rule

High-risk capabilities require valid runtime attestation or explicit approval. Missing attestation should not deny low-risk actions by default.
