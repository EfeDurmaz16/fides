# Security Policy

## Supported Versions

FIDES is currently in active development. Security updates will be provided for the latest version.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

We take the security of FIDES seriously. If you believe you have found a security vulnerability in FIDES, please report it to us responsibly.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to the project maintainers. You can find contact information in the project repository.

Please include the following information in your report:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### What to Expect

- You will receive an acknowledgment of your report within 48 hours
- We will investigate the issue and determine its impact
- We will work on a fix and release timeline
- We will keep you informed of our progress
- Once the vulnerability is fixed, we will publicly disclose it (with credit to you if desired)

## Security Measures

FIDES implements several security measures to protect against common vulnerabilities:

### Cryptographic Security

- **Ed25519 Signatures**: All signatures use the Ed25519 algorithm via the audited @noble/ed25519 library
- **Timing-Safe Comparisons**: Sensitive string comparisons (DIDs, signatures, tokens) use `crypto.timingSafeEqual()` to prevent timing attacks
- **Secure Random**: All random values use `crypto.randomUUID()` or `crypto.getRandomValues()`

### Input Validation

- **DID Format Validation**: All DIDs are validated to match the `did:fides:` prefix with valid base58 encoding
- **Trust Level Bounds**: Trust levels are validated as integers between 0-100
- **Key Length Validation**: Ed25519 keys are validated for correct length (32 bytes for public keys, 32 or 64 bytes for private keys)
- **Signature Expiry**: HTTP signatures include and enforce expiry timestamps per RFC 9421

### Request Security

- **Payload Size Limits**: Request bodies are limited to 1 MB to prevent denial-of-service attacks
- **Signature Verification**: All requests can be signed and verified using RFC 9421 HTTP Message Signatures
- **Header Validation**: Required headers are validated before processing

### Error Handling

- Error messages are sanitized to avoid leaking sensitive information
- Private keys and full signatures are never included in error messages
- Stack traces are not exposed in production environments

## Security Best Practices

When using FIDES, follow these best practices:

1. **Key Management**
   - Never commit private keys to version control
   - Use environment variables or secure key management systems
   - Rotate keys periodically

2. **Trust Attestations**
   - Verify all attestations before accepting them
   - Implement appropriate trust thresholds for your use case
   - Monitor for unexpected trust relationships

3. **Network Security**
   - Use HTTPS/TLS for all network communication
   - Validate TLS certificates
   - Implement rate limiting and request throttling

4. **Database Security**
   - Use strong database credentials
   - Enable database encryption at rest
   - Regularly backup data

## Known Security Considerations

- FIDES is in active development and has not yet undergone a formal security audit
- The trust graph algorithm assumes honest participation; Byzantine fault tolerance is not yet implemented
- Sybil resistance mechanisms are not yet implemented

## Security Updates

Security updates will be announced through:
- GitHub Security Advisories
- Release notes
- Project documentation

We recommend watching the repository for security announcements.
