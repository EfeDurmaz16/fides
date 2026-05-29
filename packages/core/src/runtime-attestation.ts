export interface RuntimeAttestation {
  schema_version?: 'fides.runtime_attestation.v1'
  attestation_id: string
  agent_id: string
  provider: 'mock-tee' | 'null' | 'aws-nitro' | 'intel-sgx' | 'amd-sev' | 'container-image' | 'reproducible-build' | string
  code_hash: string
  runtime_hash: string
  policy_hash: string
  enclave_measurement?: string
  issued_at: string
  expires_at: string
  signature: string
}
