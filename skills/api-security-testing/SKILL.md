---
name: api-security-testing
description: Test a REST/HTTP API with Sentari using its OpenAPI, Swagger, or Postman spec. Covers JWT weaknesses (alg=none, weak secret, missing expiry, sensitive payload), broken authentication and object-level access (IDOR), missing rate limiting, mass assignment, and injection against the ingested endpoints, with high-impact issues confirmed by real effect. Read-only by default. Use when the user wants to security-test an API, an API spec, or API endpoints they are authorized to test.
license: AGPL-3.0-or-later
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# API security testing with Sentari

Maps to the OWASP API Security Top 10 (broken object-level auth / BOLA, broken authentication, mass assignment, unrestricted resource consumption). Install and flags are in the **penetration-testing-with-sentari** skill.

## 1. Confirm authorization and get the spec and tokens

- The API is the user's or authorized. Prefer staging.
- Get the **API spec** (OpenAPI v3, Swagger v2, or a Postman collection) so endpoints become real scan targets instead of guesses.
- Get **bearer tokens or cookies for two users**. Object-level authorization (BOLA/IDOR) can only be proven by comparing identities. A privileged token helps for function-level auth.

Always pass `--scope` and `--authorized`.

## 2. Ingest the API surface

```bash
sentari https://api.example.com --scope api.example.com --authorized \
  --openapi ./openapi.json --api-tests --html api-report.html
```

`--openapi` accepts a file or URL. Use `--openapi-base-url` to override the base URL. YAML specs need `pip install ".[api]"`. Recon records the ingested endpoints; the vuln, api, injection, and access-control phases then test them.

## 3. What `--api-tests` checks (read-only: GET/OPTIONS only)

- **JWT audit**: every JWT seen in responses/cookies is decoded and checked for `alg=none`, a weak HMAC secret (cracked from a wordlist), missing/expired `exp`, and sensitive claims. Audit a single token with `--jwt <token>`.
- **Unauthenticated access**: endpoints returning data with no credentials (candidate).
- **Missing rate limiting**: a bounded burst that draws no throttling (candidate).
- **State-changing methods**: PUT/DELETE/PATCH advertised via OPTIONS.

## 4. Object-level and function-level authorization (two tokens)

```bash
sentari https://api.example.com --scope api.example.com --authorized --openapi ./openapi.json \
  --access-control \
  --identity alice:Authorization:"Bearer AAA" --identity bob:Authorization:"Bearer BBB" \
  --ac-url https://api.example.com/v1/orders/1001 --ac-url https://api.example.com/v1/users/42
```

Flags an endpoint that returns the same private object to two different users while anonymous access is refused (BOLA/IDOR candidate), or one reachable with no credentials.

## 5. Injection and mass assignment (authorized, non-production)

```bash
sentari https://api.example.com --scope api.example.com --authorized --openapi ./openapi.json \
  --no-safe-mode --injection --oob-host <reachable-ip>
```

SSRF/XXE/command injection are confirmed out-of-band; SSTI by evaluation; NoSQLi differentially; mass assignment by posting privileged fields (gated to outside safe mode, since it writes).

## 6. Review, verify, and fix

Read `--json` for detail; each finding cites `evidence_ids`. "Confirmed" findings carry a real observed effect; `metadata.candidate` findings (unauth access, rate limiting, mass assignment) are leads to verify manually against the evidence. Then remediate with **fix-security-vulnerabilities-with-sentari** and re-run with **retest-and-monitor** to confirm the fix. See **owasp-top-10-testing** for the full category map.
