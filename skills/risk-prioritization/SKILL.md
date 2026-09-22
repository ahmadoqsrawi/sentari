---
name: risk-prioritization
description: Prioritize what to fix first from a Sentari assessment. Combines CVSS v3.1 base scores, CISA Known Exploited Vulnerabilities correlation, business-impact weighting by asset criticality, and a likelihood-by-impact risk matrix, plus honest prioritization aids (anomaly and error-pattern candidates) that never assert a vulnerability. Use when the user wants to triage findings, rank by risk, or decide remediation order.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Risk prioritization with Sentari

Rank real findings by risk. Every input here is derived from evidence; none of it invents or predicts a vulnerability. Install and the full flag set are in the **penetration-testing-with-sentari** skill.

## 1. Set the asset criticality

```bash
sentari https://payments.example.com --scope payments.example.com --authorized \
  --asset-value critical --html report.html
```

`--asset-value` is low, medium (default), high, or critical. It weights each finding's CVSS (or severity) so issues on a critical asset rank higher. The console report and dashboard show a likelihood-by-impact risk matrix.

## 2. Read the signals that feed prioritization

- **CVSS v3.1**: base scores on nuclei findings that carry a vector.
- **CISA KEV**: finding CVEs correlated against the Known Exploited Vulnerabilities catalog; a match is tagged known-exploited (real exploit-in-the-wild signal). Disable with `--no-threatintel`.
- **Business impact and risk matrix**: from `--asset-value`, per step 1.

## 3. Treat the aids as leads, not findings

- **Anomaly flagging** marks findings whose evidence is unusual for the target as worth manual review. Disable with `--no-anomaly`.
- **Heuristic candidates** flag error and stack-trace patterns in evidence as candidates. They never assert a vulnerability and create no findings. Disable with `--no-heuristics`.

## 4. Use compliance tags for framework views

Findings are tagged with OWASP, CWE, and NIST references (disable with `--no-compliance`), so you can prioritize by framework as well as by raw risk.

## 5. Suggested remediation order

1. Known-exploited (KEV) issues, then critical-CVSS issues, on the highest-value assets.
2. The rest of the risk matrix from the top (high likelihood, high impact) down.
3. Candidates last, and only after confirming them manually from their evidence.

Then remediate with **fix-security-vulnerabilities-with-sentari** and confirm closure with **retest-and-monitor**.
