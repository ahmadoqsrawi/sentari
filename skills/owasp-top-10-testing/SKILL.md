---
name: owasp-top-10-testing
description: Map an authorized security assessment to the OWASP Top 10 with Sentari and pick the right flags for each category (broken access control, cryptographic/transport issues, injection, insecure design/business logic, security misconfiguration, vulnerable components, auth/session, integrity/deserialization, logging, SSRF). Findings are evidence-backed and tagged with OWASP/CWE/NIST references. Use when the user asks to test against the OWASP Top 10 or a specific OWASP category.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# OWASP Top 10 testing with Sentari

Always pass `--scope` and `--authorized`. Sentari tags findings with OWASP/CWE/NIST references automatically (disable with `--no-compliance`).

| OWASP 2021 | Sentari coverage | Flags |
|---|---|---|
| A01 Broken Access Control | IDOR / missing-auth by identity comparison; SSH privesc enumeration | `--access-control --identity ...`; `--privesc` (gated) |
| A02 Cryptographic Failures | TLS inspection, cleartext credentials/secrets in captured traffic, insecure cookies | scanning phase; `--proxy-ingest` |
| A03 Injection | SQLi, NoSQLi, OS command (OOB-confirmed), SSTI, plus nuclei templates | `--injection`; `--no-safe-mode --sqlmap-url ...` |
| A04 Insecure Design / business logic | operator-defined workflow replay; race conditions | `--workflow spec.json`; `--race-url ...` |
| A05 Security Misconfiguration | security headers, exposed sensitive paths, cloud misconfig | scanning phase; `--cloud-audit ...` |
| A06 Vulnerable Components | nuclei templates + CISA KEV correlation | vuln phase (on by default) |
| A07 Auth & Session | JWT audit, session fixation | `--api-tests`/`--jwt`; `--session-fixation ...` |
| A08 Integrity / deserialization | serialized-object detection in params/cookies | `--injection` |
| A09 Logging & Monitoring | not a scan target; report findings for the team via `--siem-url` | reporting |
| A10 SSRF | out-of-band confirmed SSRF | `--injection` |

## A broad, safe first pass

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --api-tests --html owasp-report.html --json owasp-report.json
```

## Adding the active categories (authorized, non-production)

```bash
sentari https://app.example.com --scope app.example.com --authorized --no-safe-mode \
  --injection --oob-host <reachable-ip> --browser \
  --access-control --identity alice:Cookie:session=aaa --identity bob:Cookie:session=bbb
```

Every finding carries its evidence and its OWASP/CWE/NIST tags, so the report maps straight onto the Top 10.
