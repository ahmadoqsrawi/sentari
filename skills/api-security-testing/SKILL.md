---
name: api-security-testing
description: Test a REST/HTTP API with Sentari using its OpenAPI, Swagger, or Postman spec. Covers JWT weaknesses (alg=none, weak secret, missing expiry, sensitive payload), broken authentication and object-level access (IDOR), missing rate limiting, mass assignment, and injection against the ingested endpoints. Read-only by default. Use when the user wants to security-test an API, an API spec, or API endpoints they are authorized to test.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# API security testing with Sentari

Always pass `--scope` and `--authorized`.

## Ingest the API surface

Point Sentari at the spec so its endpoints become scan targets:

```bash
sentari https://api.example.com --scope api.example.com --authorized \
  --openapi ./openapi.json --api-tests --html api-report.html
```

`--openapi` accepts OpenAPI v3, Swagger v2, or a Postman collection (file or URL). Use `--openapi-base-url` to override the base URL. YAML specs need `pip install ".[api]"`.

## What `--api-tests` checks (read-only: GET/OPTIONS only)

- **JWT audit**: any JWT seen in responses/cookies is decoded and checked for `alg=none`, a weak HMAC secret (cracked from a wordlist), missing/expired `exp`, and sensitive claims. Audit a single token directly with `--jwt <token>`.
- **Unauthenticated access**: endpoints returning data with no credentials (candidate).
- **Missing rate limiting**: a bounded burst that draws no throttling (candidate).
- **State-changing methods**: PUT/DELETE/PATCH advertised via OPTIONS.

## Object-level access (IDOR / broken auth)

```bash
sentari https://api.example.com --scope api.example.com --authorized --openapi ./openapi.json \
  --access-control --identity alice:Authorization:"Bearer AAA" --identity bob:Authorization:"Bearer BBB"
```

Flags an endpoint that returns the same private object to two different users while anonymous access is refused.

## Injection against API endpoints (authorized, non-production)

```bash
sentari https://api.example.com --scope api.example.com --authorized --openapi ./openapi.json \
  --no-safe-mode --injection --oob-host <reachable-ip>
```

SSRF/XXE/command injection are confirmed out-of-band; SSTI by evaluation; NoSQLi differentially; mass assignment by posting privileged fields (gated).
