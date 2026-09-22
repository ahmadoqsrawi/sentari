---
name: web-app-penetration-testing
description: Test a web application with Sentari for injection (SQL/NoSQL/OS command/SSTI), SSRF, XXE, client-side attacks (reflected/DOM/stored XSS, prototype pollution, clickjacking, CSRF), and broken access control (IDOR). High-impact issues are confirmed by real effect (payload execution or an out-of-band callback), not guessed. Use when the user wants a dynamic web-app pentest, DAST, or to test a specific web vulnerability class on an authorized target.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Web-app pentesting with Sentari

Always pass `--scope <host>` and `--authorized`. Do not run active/gated tests against production.

## Client-side DAST (headless browser)

```bash
sentari https://app.example.com --scope app.example.com --authorized --browser
```

Finds reflected and DOM XSS and prototype pollution (each confirmed by actual browser execution), plus clickjacking, token-less CSRF forms, password-over-HTTP, and mixed content. Needs `pip install ".[browser]"` and `playwright install chromium`.

Stored XSS also runs, but only outside safe mode (it submits through forms, which writes data):

```bash
sentari https://app.example.com --scope app.example.com --authorized --no-safe-mode --browser
```

## Injection and server-side (out-of-band confirmed)

```bash
sentari https://app.example.com --scope app.example.com --authorized --injection --oob-host <reachable-ip>
```

- **SSRF, XXE, OS command injection**: Sentari injects a URL pointing at its own listener; a finding is raised only when the target actually calls back. Set `--oob-host` to an address the target can reach (default 127.0.0.1 for local targets). XXE POSTs XML, so it runs only outside safe mode.
- **SSTI**: confirmed when a template expression (7*7) is evaluated in the response.
- **NoSQLi**: differential operator injection (candidate).
- **Insecure deserialization**: detects serialized blobs in params/cookies (candidate).
- **Mass assignment**: posts privileged fields, gated to outside safe mode.

## Broken access control / IDOR

Compare identities:

```bash
sentari https://app.example.com --scope app.example.com --authorized --access-control \
  --identity alice:Cookie:session=aaa --identity bob:Cookie:session=bbb \
  --ac-url https://app.example.com/account --ac-url https://app.example.com/orders/42
```

Flags resources served without authentication, or served identically to two different users while anonymous access is refused (an IDOR candidate).

## SQL injection (gated sqlmap)

```bash
sentari https://app.example.com --scope app.example.com --authorized --no-safe-mode --sqlmap-url "https://app.example.com/item?id=1"
```

## Proxy, tamper, and fuzz

```bash
sentari --proxy 8080 --proxy-out flows.jsonl        # capture (route the app through it)
sentari x --scope <host> --authorized --proxy-ingest flows.jsonl   # analyze the capture
sentari --proxy-web 8080                              # live interactive tampering (mitmweb)
sentari x --scope <host> --authorized --tamper flows.jsonl --set-param id=99 --fuzz-param id --fuzz-values vals.txt
```

Report with `--html report.html` (or `--json`/`--xml`/`--pdf`).
