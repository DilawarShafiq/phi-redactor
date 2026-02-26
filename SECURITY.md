# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in phi-redactor, please report it responsibly:

1. **Do NOT** create a public GitHub issue
2. Email: security@phi-redactor.dev
3. Include: description, reproduction steps, and impact assessment
4. Expected response time: 48 hours

## Security Architecture

### Data Protection

- **PHI at rest**: All original PHI is Fernet-encrypted (AES-128-CBC) in the SQLite vault
- **PHI in transit**: Never logged, never cached in plaintext, always redacted before forwarding
- **Key management**: Encryption keys stored in separate `.key` files with restricted permissions
- **Hash-based deduplication**: Original values identified by SHA-256 hash, never by plaintext

### HIPAA Compliance

phi-redactor implements the HIPAA Safe Harbor method (45 CFR 164.514(b)(2)), detecting and redacting all 18 PHI identifier categories:

1. Names
2. Geographic data (smaller than state)
3. Dates (except year) related to an individual
4. Phone numbers
5. Fax numbers
6. Email addresses
7. Social Security numbers
8. Medical record numbers
9. Health plan beneficiary numbers
10. Account numbers
11. Certificate/license numbers
12. Vehicle identifiers and serial numbers
13. Device identifiers and serial numbers
14. Web URLs
15. IP addresses
16. Biometric identifiers
17. Full-face photographs
18. Any other unique identifying number

### Audit Trail

- Tamper-evident hash chain (SHA-256 linked entries)
- Every redaction event logged with category, confidence, method, and action
- Chain integrity verification available via compliance reports

### Session Security

- Sessions expire after configurable idle/max lifetime
- Session data isolated by unique session ID
- Vault entries cascade-deleted when sessions expire
- No cross-session data leakage

### Network Security

- Proxy operates locally by default (127.0.0.1)
- TLS termination expected at reverse proxy layer for production
- API keys passed through to upstream providers, never stored
- CORS configurable for production deployment

## Best Practices for Deployment

1. Run behind a TLS-terminating reverse proxy (nginx, Caddy)
2. Restrict vault file permissions (`chmod 600`)
3. Use dedicated encryption key paths, not defaults
4. Enable audit trail and monitor compliance reports
5. Set appropriate session lifetimes for your use case
6. Review and rotate encryption keys periodically
7. Back up vault database with encrypted backups only
