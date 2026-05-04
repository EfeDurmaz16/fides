# FIDES v2 Threat Model

## Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Malicious Agent | Compromised key, forged attestations | Financial gain, data theft |
| Sybil Cluster | Many low-trust identities | Reputation manipulation |
| Relay Operator | Controls relay infrastructure | Censorship, surveillance |
| Registry Operator | Controls hosted registry | Censorship, data mining |

## Attack Vectors

### 1. Identity Compromise
- **Risk**: Private key theft leads to full identity takeover
- **Mitigation**: Key rotation, revocation registry, multi-factor attestation

### 2. Trust Graph Manipulation
- **Risk**: Sybil clusters inflate reputation scores
- **Mitigation**: Novelty penalties, trust anchor requirement, capability-specific reputation

### 3. Replay Attacks
- **Risk**: Signed messages reused out of context
- **Mitigation**: Nonces, expiry, audience restriction

### 4. Policy Bypass
- **Risk**: Attacker crafts requests that evade policy rules
- **Mitigation**: Default-deny, exhaustive rule matching, adversarial testing

### 5. Evidence Tampering
- **Risk**: Evidence chain modified post-hoc
- **Mitigation**: Hash chaining, Merkle proofs, distributed anchoring

### 6. Runtime Spoofing
- **Risk**: Fake TEE attestations
- **Mitigation**: Adapter verification, attestation expiry, multi-provider checks

## Security Review Checklist

- [ ] All signed objects use canonical JSON
- [ ] Nonce replay protection enabled
- [ ] Trust decay formula matches spec
- [ ] Policy engine defaults to deny
- [ ] Kill switch tested and documented
- [ ] Evidence chain integrity verified
- [ ] Runtime attestation adapters validate signatures
- [ ] Registry private mode enforces access control
- [ ] DHT pointer records signed by DID owner
- [ ] Adversarial tests run in CI

## Production Hardening Notes

1. **Key Storage**: Use HSM or secure enclave for private keys
2. **Database**: Encrypt trust edges and evidence at rest
3. **Network**: mTLS between services, rate limiting on all endpoints
4. **Observability**: Audit logs for all policy decisions and delegations
5. **Incident Response**: Automated kill switch triggers on anomaly detection
6. **Compliance**: GDPR/CCPA privacy levels for evidence export
