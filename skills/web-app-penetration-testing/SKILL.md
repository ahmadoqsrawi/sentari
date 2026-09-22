---
name: web-app-penetration-testing
description: Pentest a web application end to end with Sentari. Tests a live URL, staging site, or local dev server for injection (SQL/NoSQL/OS command/SSTI), SSRF, XXE, client-side attacks (reflected/DOM/stored XSS, prototype pollution, clickjacking, CSRF), and broken access control (IDOR). High-impact issues are confirmed by real effect (payload execution or an out-of-band callback), not guessed. Use when the user wants a dynamic web-app pentest, DAST, or to test a specific web vulnerability class on an authorized target.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Pentest a web application with Sentari

Dynamic testing of a running web app. Every high-impact finding is confirmed by a real effect, so there are no signature-only false positives to triage. Install, verification, and the full flag set are in the **penetration-testing-with-sentari** skill.

## 1. Confirm authorization and scope

- The target is the user's or explicitly authorized. Never test a third-party site on a hunch.
- Prefer **staging over production**. Active tests send real payloads and, outside safe mode, submit data (stored XSS, mass assignment).
- Note out-of-scope paths (payments, mass-email, destructive admin).
- Get **credentials**. Most web-app bugs live behind login. For access-control/IDOR you need **two accounts** (and a privileged one helps). That is the only way Sentari can prove cross-user access.

Ask for anything missing. Always pass `--scope` and `--authorized`.

## 2. Client-side DAST (headless browser)

```bash
sentari https://app.example.com --scope app.example.com --authorized --browser
```

Confirms reflected and DOM XSS and prototype pollution by actual browser execution, and flags clickjacking, token-less CSRF forms, password-over-HTTP, and mixed content. Needs `pip install ".[browser]"` and `playwright install chromium`.

Stored XSS also runs, but only outside safe mode (it submits through forms, which writes data):

```bash
sentari https://app.example.com --scope app.example.com --authorized --no-safe-mode --browser
```

## 3. Injection and server-side (out-of-band confirmed)

```bash
sentari https://app.example.com --scope app.example.com --authorized --injection --oob-host <reachable-ip>
```

- **SSRF, XXE, OS command injection** are confirmed only when the target calls back to Sentari's listener. Set `--oob-host` to an address the target can reach (default 127.0.0.1 for local targets). XXE POSTs XML, so it runs only outside safe mode.
- **SSTI** is confirmed when a template expression (7*7) is evaluated in the response.
- **NoSQLi** (differential), **insecure deserialization** (serialized blobs in params/cookies), and **mass assignment** (gated) are reported as candidates.

SQL injection with sqlmap is gated:

```bash
sentari https://app.example.com --scope app.example.com --authorized --no-safe-mode --sqlmap-url "https://app.example.com/item?id=1"
```

## 4. Broken access control / IDOR (two identities)

```bash
sentari https://app.example.com --scope app.example.com --authorized --access-control \
  --identity alice:Cookie:session=aaa --identity bob:Cookie:session=bbb \
  --ac-url https://app.example.com/account --ac-url https://app.example.com/orders/42
```

Flags a resource served without authentication, or served identically to two different users while anonymous access is refused (an IDOR candidate). With one identity this class cannot be proven; say so.

## 5. Localhost and dev servers

Point at the real bound address, for example `http://127.0.0.1:3000`, and pass the port explicitly. To test only that port without probing anything else on the box, use `--phases scanning,vuln,browser http://127.0.0.1:3000` (no recon).

## 6. Manual traffic, tampering, and fuzzing

```bash
sentari --proxy 8080 --proxy-out flows.jsonl                     # capture (route the app through it)
sentari x --scope <host> --authorized --proxy-ingest flows.jsonl # analyze the capture
sentari --proxy-web 8080                                         # live interactive editing (mitmweb)
sentari x --scope <host> --authorized --tamper flows.jsonl --set-param id=99 --fuzz-param id --fuzz-values vals.txt
```

## 7. Review, verify, and fix

Read the console report, then `--json` for detail. A finding whose title says "confirmed" carries a real observed effect; a `metadata.candidate` finding is a lead for manual review. Verify each finding from its `evidence_ids` before reporting. Write reports with `--html`/`--json`/`--xml`/`--pdf`.

Remediate with **fix-security-vulnerabilities-with-sentari**, then re-run and diff with **retest-and-monitor** to prove the fix landed. Keep the app covered on every change with **ci-security-scanning-with-sentari**.
