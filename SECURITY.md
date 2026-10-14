# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

The `latch-proxy` maintainers take security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

**Please report security issues via [GitHub Private Vulnerability Reporting](https://github.com/WiseHax/latch-proxy/security/advisories/new).**

When submitting a report, please include:

- A clear description of the vulnerability and its potential impact.
- Detailed steps to reproduce the issue, including any relevant configuration, payloads, or proof-of-concept code.
- The affected version(s) and component(s) (e.g., `app/guard.py`, `app/ratelimit.py`).
- Any suggested mitigations or fixes, if available.

### What to Expect

- **Acknowledgement:** We will acknowledge receipt of your report within **48 hours**.
- **Triage:** We will investigate and provide an initial assessment within **5 business days**.
- **Resolution:** Critical vulnerabilities will be patched in a timely manner, and you will be notified when a fix is released.
- **Credit:** With your permission, we will credit you in the release notes and security advisory.

### Scope

The following are in scope for security reports:

- Authentication and authorization bypasses (HMAC spoofing, BOLA, RBAC).
- Prompt injection vectors that circumvent delimiter spotlighting or taint tracking.
- Data exfiltration through tainted sinks.
- Rate limiter or quota guard bypasses.
- Sensitive information disclosure in egress responses.
- Container escape or privilege escalation in the Docker image.

### Out of Scope

- Vulnerabilities in upstream dependencies — please report these to the respective maintainers.
- Denial-of-service attacks against the in-memory rate limiter in non-production deployments.
- Issues that require physical access to the host machine.

---

**Please do not open public GitHub issues for security vulnerabilities.**
