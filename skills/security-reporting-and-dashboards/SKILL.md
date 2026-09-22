---
name: security-reporting-and-dashboards
description: Produce reports and dashboards from a Sentari assessment. Writes HTML, JSON, XML, and PDF reports, serves a read-only executive dashboard with KPI cards, severity and trend charts, a risk matrix and compliance coverage, exports findings to a SIEM (Splunk, Elasticsearch, syslog, webhook), and exposes Prometheus metrics. Use when the user wants a security report, an executive dashboard, or to send findings to a SIEM or monitoring stack.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Reporting and dashboards with Sentari

Always pass `--scope` and `--authorized` for a scan. Reporting reads the results a scan produced.

## Report files

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --html report.html --json report.json --xml report.xml --pdf report.pdf
```

- HTML is self-contained. JSON carries every finding with its evidence. XML suits importers. PDF needs `pip install ".[pdf]"`.

## Executive dashboard (read-only)

```bash
sentari https://app.example.com --scope app.example.com --authorized --save-run runs/
sentari --serve --runs-dir runs/            # or: --serve --db sentari.db
```

The dashboard leads with KPI cards (runs, findings, critical/high, known-exploited, targets), a severity distribution, a findings-over-time trend, a risk prioritization matrix, and OWASP compliance coverage. It binds to localhost by default; use `--host 0.0.0.0` only inside a container you control.

## SIEM export

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --siem-url https://splunk.example.com:8088 --siem-type splunk --siem-token "$TOKEN"
```

`--siem-type` is one of webhook, splunk, elasticsearch, syslog. The token can also come from `SENTARI_SIEM_TOKEN`.

## Prometheus metrics

The dashboard exposes `/metrics` for Prometheus; a Grafana dashboard ships under `deploy/grafana/`.

## Turn a report into fixes

Use the fix-security-vulnerabilities-with-sentari skill to generate a remediation guide or a draft PR from the same findings.
