---
name: ci-security-scanning-with-sentari
description: Add Sentari to a CI/CD pipeline as a security gate. A composite GitHub Action runs an authorized assessment on push or on a schedule, uploads the reports as artifacts, and can fail the build. Use when the user wants continuous security scanning, a CI security gate, scheduled scans, or a GitHub Action for security testing.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# CI security scanning with Sentari

Sentari ships a composite GitHub Action (`action.yml`) with an authorization gate. Only set `authorized: "true"` for a target you have written permission to test.

## Minimal workflow

Copy into `.github/workflows/security.yml` in the repo you want to assess:

```yaml
name: Security assessment
on:
  workflow_dispatch:
  schedule:
    - cron: "0 3 * * 1"   # weekly
jobs:
  sentari:
    runs-on: ubuntu-latest
    steps:
      - uses: ahmadoqsrawi/sentari@main
        with:
          target: "https://staging.example.com"
          scope: "staging.example.com"
          authorized: "true"
          args: "--openapi openapi.json --json sentari-report.json --html sentari-report.html"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sentari-reports
          path: |
            sentari-report.json
            sentari-report.html
```

A full example is in `examples/github-action-usage.yml`.

## Inputs

- `target` (required), `scope` (defaults to target), `authorized` ("true"/"false", required), `args` (extra Sentari flags), `python-version`.

## Notes

- The Action installs Sentari from the action path and runs it as your user, read-only by default.
- Keep gated/offensive flags out of CI unless the runner targets an authorized non-production lab.
- Scheduled runs plus `--db`/artifacts give you trend and delta over time; pair with the retest flags (`--retest`, `--retest-latest`).
