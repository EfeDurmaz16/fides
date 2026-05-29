/**
 * Full FIDES v2 demo contract.
 *
 * This is a deterministic, local-first scenario description that mirrors the
 * executing `agentd demo run` flow. It is intentionally side-effect-light so
 * docs, tests, and future scripts can share the same ordered contract.
 *
 * Run: pnpm exec tsx examples/full-demo/run.ts
 */

export const fullDemoSteps = [
  'initialize_daemon',
  'create_principal_identity',
  'create_publisher_identity',
  'add_github_attestation',
  'add_email_attestation',
  'add_domain_attestation',
  'create_calendar_agent',
  'create_invoice_agent',
  'create_payment_agent',
  'create_payment_runtime_attestation',
  'sign_agent_cards',
  'register_agents_locally',
  'publish_invoice_agent_to_registry',
  'publish_calendar_agent_to_relay',
  'publish_payment_pointer_to_dht',
  'verify_signed_registry_index_record',
  'verify_signed_relay_agent_card_reference',
  'verify_signed_dht_pointer_record',
  'discover_calendar_locally',
  'discover_invoice_through_registry',
  'discover_payment_through_dht',
  'verify_agent_cards',
  'evaluate_trust',
  'show_capability_reputation',
  'request_invoice_session',
  'invoke_invoice_agent',
  'emit_invocation_evidence',
  'deny_high_risk_payment_without_attestation',
  'add_runtime_attestation',
  'request_payment_dry_run_session',
  'invoke_payment_dry_run',
  'report_malicious_agent_incident',
  'apply_trust_penalty',
  'revoke_malicious_agent',
  'verify_revoked_agent_not_trusted',
  'verify_evidence_hash_chain',
  'export_evidence_log',
  'print_final_trust_graph',
] as const

export function describeFullDemo(): { status: 'manifest'; execution: string; steps: readonly string[] } {
  return {
    status: 'manifest',
    execution: 'agentd demo run executes this contract against local daemon state and verifies signed provider records without granting discovery authority',
    steps: fullDemoSteps,
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify(describeFullDemo(), null, 2))
}
