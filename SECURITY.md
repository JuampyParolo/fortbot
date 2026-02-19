# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in FortBot, **do not open a public issue**.

Instead, please email: **security@fortbot.dev** (or open a private advisory on GitHub)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a patch within 7 days for critical issues.

## Security Architecture

FortBot implements 7 layers of security. See [docs/FINAL_AUDIT.md](docs/FINAL_AUDIT.md) for the complete audit.

### Trust Model
- Messages are classified by trust level: OWNER > SYSTEM > KNOWN_CONTACT > UNKNOWN > UNTRUSTED
- Only OWNER can trigger task execution
- External data is always processed by the Quarantined LLM (no tools, schema-enforced output)

### What We Protect Against
- Indirect prompt injection (Privileged/Quarantined LLM separation)
- Data exfiltration (taint tracking, SSRF protection, recipient validation)
- Command injection (shell allowlist, Docker sandbox, dangerous pattern detection)
- Credential theft (AES-256-GCM encryption at rest, file path sandboxing)
- Supply chain attacks (no plugin/skill system — capabilities are hardcoded)

### Known Limitations
- WhatsApp session token (`auth_store/`) grants full account access if stolen
- Docker sandbox requires Docker to be installed and running
- Rate limiter resets on restart (in-memory, not persisted)
- Local LLM quarantine quality depends heavily on model choice

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | ✅ Current |
| < 0.4   | ❌ No      |
