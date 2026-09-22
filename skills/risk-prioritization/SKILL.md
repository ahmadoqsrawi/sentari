---
name: risk-prioritization
description: Prioritize what to fix first from a Sentari assessment. Combines CVSS v3.1 base scores, CISA Known Exploited Vulnerabilities correlation, business-impact weighting by asset criticality, and a likelihood-by-impact risk matrix, plus honest prioritization aids (anomaly and error-pattern candidates) that never assert a vulnerability. Use when the user wants to triage findings, rank by risk, or decide remediation order.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Risk prioritization with Sentari

Every input here is derived from real findings; none of it invents or predicts a vulnerability. Always pass `--scope` and `--authorized`.

## Weight by how critical the asset is

```bash
sentari https://payments.example.com --scope payments.example.com --authorized \
  --asset-value critical --html report.html
```

`--asset-value` is low, medium (default), high, or critical. It weights each finding's CVSS (or severity) so issues on a critical asset rank higher. The console report and dashboard show a likelihood-by-impact risk matrix.

## Signals that feed prioritization

- **CVSS v3.1**: base scores on nuclei findings that carry a vector.
- **CISA KEV**: finding CVEs are correlated against the Known Exploited Vulnerabilities catalog; a match is tagged known-exploited (real exploit-in-the-wild signal). Disable with `--no-threatintel`.
- **Business impact and risk matrix**: from `--asset-value`, per the rules above.

## Honest prioritization aids (never vulnerability claims)

- **Anomaly flagging**: marks findings whose evidence is unusual for the target as worth manual review. Disable with `--no-anomaly`.
- **Heuristic candidates**: flags error and stack-trace patterns in evidence as candidates for manual review. It never asserts a vulnerability and creates no findings. Disable with `--no-heuristics`.

## Compliance mapping for context

Findings are tagged with OWASP, CWE, and NIST references (disable with `--no-compliance`), so you can prioritize by framework as well as by risk.

## Suggested order

Fix known-exploited (KEV) and critical-CVSS issues on high-value assets first, then the rest of the risk matrix from the top-right (high likelihood, high impact) down. Confirm candidates manually before acting.
