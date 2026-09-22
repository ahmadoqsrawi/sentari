---
name: security-reporting-and-dashboards
description: Produce reports and dashboards from a Sentari assessment. Writes HTML, JSON, XML, and PDF reports, serves a read-only executive dashboard with KPI cards, severity and trend charts, a risk matrix and compliance coverage, exports findings to a SIEM (Splunk, Elasticsearch, syslog, webhook), and exposes Prometheus metrics. Use when the user wants a security report, an executive dashboard, or to send findings to a SIEM or monitoring stack.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Reporting and dashboards with Sentari

Turn an assessment into reports, a dashboard, and monitoring exports. Reporting reads the results a scan produced; the scan itself still needs `--scope` and `--authorized`. Install and the full flag set are in the **penetration-testing-with-sentari** skill.

## 1. Write report files

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --html report.html --json report.json --xml report.xml --pdf report.pdf
```

HTML is self-contained. JSON carries every finding with its evidence (use it for scripting). XML suits importers. PDF needs `pip install ".[pdf]"`.

## 2. Serve the executive dashboard (read-only)

```bash
sentari https://app.example.com --scope app.example.com --authorized --save-run runs/
sentari --serve --runs-dir runs/            # or: --serve --db sentari.db
```

The dashboard leads with KPI cards (runs, findings, critical/high, known-exploited, targets), a severity distribution, a findings-over-time trend, a risk prioritization matrix, and OWASP compliance coverage. It binds to localhost by default; use `--host 0.0.0.0` only inside a container you control.

## 3. Export to a SIEM

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --siem-url https://splunk.example.com:8088 --siem-type splunk --siem-token "$TOKEN"
```

`--siem-type` is one of webhook, splunk, elasticsearch, syslog. The token can also come from `SENTARI_SIEM_TOKEN`.

## 4. Prometheus and Grafana

The dashboard exposes `/metrics` for Prometheus; a Grafana dashboard ships under `deploy/grafana/`.

## 5. Present honestly, then act

Group findings by severity and separate confirmed findings from candidates when you summarize. Turn the same findings into a remediation guide or draft PR with **fix-security-vulnerabilities-with-sentari**, rank them with **risk-prioritization**, and track them over time with **retest-and-monitor**.
