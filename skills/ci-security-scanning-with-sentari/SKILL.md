---
name: ci-security-scanning-with-sentari
description: Add Sentari to a CI/CD pipeline as a security gate. A composite GitHub Action runs an authorized assessment on push or on a schedule, uploads the reports as artifacts, and can fail the build. Use when the user wants continuous security scanning, a CI security gate, scheduled scans, or a GitHub Action for security testing.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# CI security scanning with Sentari

Run an authorized assessment automatically on every change or on a schedule. Sentari ships a composite GitHub Action (`action.yml`) with an authorization gate. Install and the full flag set are in the **penetration-testing-with-sentari** skill.

## 1. Confirm authorization

Only set `authorized: "true"` for a target the user has written permission to test. Keep gated/offensive flags out of CI unless the runner targets an authorized non-production lab.

## 2. Add the workflow

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

## 3. Inputs

- `target` (required), `scope` (defaults to target), `authorized` ("true"/"false", required), `args` (extra Sentari flags), `python-version`.

## 4. Gate and artifacts

The Action installs Sentari from the action path and runs it as your user, read-only by default. Upload the JSON/HTML as artifacts (as above) so every run is reviewable. Use `args` to add phases or reports.

## 5. Scheduled scans and delta

Scheduled runs plus `--db` and artifacts give you trend and delta over time. Pair with the retest flags (`--retest`, `--retest-latest`) so a run reports what changed since the last one; see **retest-and-monitor**.

## 6. Act on results

Pull the artifacts, rank with **risk-prioritization**, and open remediation PRs with **fix-security-vulnerabilities-with-sentari**.
