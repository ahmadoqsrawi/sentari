---
name: owasp-top-10-testing
description: Test an application against the OWASP Top 10 with Sentari and pick the right flags for each category (broken access control, cryptographic failures, injection, insecure design and business logic, security misconfiguration, vulnerable components, auth and session, integrity and deserialization, logging, SSRF). Findings are evidence-backed and tagged with OWASP/CWE/NIST references, and Sentari states honestly which categories it can prove and which need source or human review. Use when the user asks to test against the OWASP Top 10, do OWASP compliance testing, or map a review to OWASP categories.
license: AGPL-3.0-or-later
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Test against the OWASP Top 10 with Sentari

The OWASP Top 10 is a taxonomy of risk, not a test suite. "OWASP Top 10 testing" means exercising each category against the real app and reporting what is actually provable. Sentari tags findings with OWASP/CWE/NIST references automatically (disable with `--no-compliance`); its tags use the **OWASP Top 10:2021** ids. If the user needs a different edition, say which one the report reflects.

Install, verification, and flags are in the **penetration-testing-with-sentari** skill.

## What Sentari can and cannot prove

Be straight with the user: claiming a clean sweep of all ten is misleading. Sentari only reports what it has evidence for.

| Category (2021) | Coverage with Sentari |
|---|---|
| A01 Broken Access Control | **Strong** with two identities: IDOR and missing-auth via `--access-control`, plus SSH privilege-escalation enumeration (`--privesc`). Needs credentials for two users to prove the authorization half. |
| A02 Cryptographic Failures | **Partial**: TLS inspection, cleartext credentials/secrets and insecure cookies in captured traffic (`--proxy-ingest`). At-rest crypto and key management need source or infra review. |
| A03 Injection | **Strong**: SQLi (sqlmap), NoSQLi (differential), OS command injection (out-of-band confirmed), SSTI (evaluation-confirmed), plus nuclei templates. |
| A04 Insecure Design / business logic | **Partial**: operator-defined workflow replay (`--workflow`) and race conditions (`--race-url`). Design intent still needs human threat modelling. |
| A05 Security Misconfiguration | **Strong**: security headers, exposed sensitive paths, and cloud misconfiguration (`--cloud-audit`). |
| A06 Vulnerable & Outdated Components | **Partial**: nuclei version/CVE templates and CISA-KEV correlation; full dependency SCA needs source (pair with `--sast`). |
| A07 Identification & Auth Failures | **Strong on tokens/sessions**: JWT audit (`--jwt`/`--api-tests`) and session fixation (`--session-fixation`). Credential stuffing is refused by design. |
| A08 Software & Data Integrity Failures | **Partial**: insecure-deserialization detection (serialized blobs in params/cookies). CI/CD trust boundaries are not runtime-testable. |
| A09 Security Logging & Monitoring Failures | **Not testable from outside**. Say so rather than reporting it passed. Sentari can ship findings to a SIEM (`--siem-url`) but cannot assess the app's own logging. |
| A10 Server-Side Request Forgery | **Strong**: out-of-band confirmed SSRF (`--injection`). |

## Run it (broad, then active)

A safe first pass:

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --api-tests --html owasp-report.html --json owasp-report.json
```

Full coverage of the active categories (authorized, non-production only), with two accounts so A01 is real:

```bash
sentari https://app.example.com --scope app.example.com --authorized --no-safe-mode \
  --injection --oob-host <reachable-ip> --browser \
  --access-control --identity alice:Cookie:session=aaa --identity bob:Cookie:session=bbb \
  --workflow ./business-logic.json --session-fixation https://app.example.com/login --login-data "user=a&pass=b"
```

Without a second identity, A01 results are structurally incomplete; state that in the report rather than implying coverage.

## Report honestly

Group findings by their OWASP tag and, per category, say what was attempted, what was proven (with evidence ids), and what could not be assessed (A09 always; A02/A04/A06/A08 partially). Confirmed exploits (A03/A10, XSS in A03) carry a real observed effect; verify each one from its evidence before it reaches the user.

## Then fix and re-test

Remediate with **fix-security-vulnerabilities-with-sentari**, then re-run and diff with **retest-and-monitor** to prove each issue is closed. Gate future changes with **ci-security-scanning-with-sentari**.
