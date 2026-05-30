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

## RuntimeAttestation Object

`packages/core/src/runtime-attestation.ts` emits
`fides.runtime_attestation.v1` records with shared signed-object fields:

- `id`
- `issuer`
- `subject`
- `attestation_id`
- `agent_id`
- `provider`
- `code_hash`
- `runtime_hash`
- `policy_hash`
- `enclave_measurement`
- `issued_at`
- `expires_at`
- `payload_hash`
- `signature`

`id` and `attestation_id` are the same identifier for compatibility with older
call sites. `subject` is the attested agent id. `payload_hash` is computed with
the shared canonical JSON digest before the provider-specific signature is
attached.

## Policy Rule

High-risk capabilities require valid runtime attestation or explicit approval. Missing attestation should not deny low-risk actions by default.

## Evidence

Runtime attestation lifecycle actions are evidence-producing. Local `agentd`
appends hash-only events for:

- `attestation.issued` when `POST /attestations` creates a MockTEE attestation.
- `attestation.verified` when `POST /attestations/:id/verify` succeeds.
- `attestation.failed` when verification fails or the attestation is missing.

These evidence events do not grant authority. They provide audit references
that policy and trust decisions can cite later.
