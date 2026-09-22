---
name: find-security-vulnerabilities-in-code
description: Run static analysis (SAST) over a source tree with Sentari, using semgrep, and map results to evidence-backed findings with CWE/OWASP references. Use when the user wants to scan a repository or codebase for security issues, do a code security review, or add SAST to their workflow.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Static analysis with Sentari

SAST reads code; it does not touch a running target. It still goes through the same engine, so results land in the same report and carry evidence (semgrep's own output).

## Install and run

```bash
pip install ".[dev]" && pip install semgrep   # semgrep is the SAST engine
sentari localhost --scope localhost --authorized --phases sast --sast ./path/to/code
```

`--sast PATH` scans that tree. `--sast-config <ruleset>` picks a semgrep config (default `auto`). Without semgrep installed, the phase reports that and adds nothing (it never fabricates).

## Combine with a dynamic scan

Run SAST alongside the dynamic phases when you have both code and a running instance:

```bash
sentari https://staging.example.com --scope staging.example.com --authorized \
  --sast ./repo --browser --html report.html
```

## Output

Each semgrep result becomes a finding with the rule id, file:line location, severity (semgrep ERROR/WARNING/INFO mapped to high/medium/low), and CWE/OWASP references when the rule provides them. Turn the findings into a remediation guide or draft PR with the **fix-security-vulnerabilities-with-sentari** skill.
