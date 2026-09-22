---
name: find-security-vulnerabilities-in-code
description: Run static analysis (SAST) over a source tree with Sentari, using semgrep, and map results to evidence-backed findings with CWE/OWASP references. Use when the user wants to scan a repository or codebase for security issues, do a code security review, or add SAST to their workflow.
license: AGPL-3.0-or-later
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Static analysis with Sentari

SAST reads code; it does not touch a running target. It runs through the same engine, so results land in the same report and carry evidence (semgrep's own output). Install and the full flag set are in the **penetration-testing-with-sentari** skill.

## 0. Guided setup (optional)

For a one-command review, use the Code Review wizard: it asks for the source (a git repo URL or a local path) and the context (threats/areas to focus on), then launches.

```bash
sentari wizard code-review    # Source, Context, Review & Launch; saves code-review.json
```

Or go straight to the preset, which accepts a local path or a git URL (cloned, scanned, removed) and adds AI fix suggestions:

```bash
sentari --code-review ./src
sentari --code-review https://github.com/me/app
```

Both are authorized by default (they only read source you can already access) and map onto the flags below.

## 1. Confirm scope

- The code is the user's or they are authorized to review it.
- SAST is read-only and safe to run on any checkout; still pass `--scope` and `--authorized` because the engine requires them.

## 2. Prerequisites

```bash
pip install semgrep       # the SAST engine
```

Without semgrep on PATH the phase reports that and adds nothing (it never fabricates).

## 3. Run over a source tree

```bash
sentari localhost --scope localhost --authorized --phases sast --sast ./path/to/code
```

`--sast PATH` scans that tree. `--sast-config <ruleset>` picks a semgrep config (default `auto`). Large trees take a few minutes.

## 4. Combine with a dynamic scan

When you have both the code and a running instance, run SAST alongside the dynamic phases for white-box depth:

```bash
sentari https://staging.example.com --scope staging.example.com --authorized \
  --sast ./repo --browser --html report.html
```

## 5. Review and verify

Each semgrep result becomes a finding with the rule id, `file:line` location, severity (semgrep ERROR/WARNING/INFO mapped to high/medium/low), and CWE/OWASP references when the rule provides them. SAST findings are static matches; open the cited file and line to confirm exploitability before reporting.

## 6. Fix

Turn the findings into a remediation guide or a draft PR with the **fix-security-vulnerabilities-with-sentari** skill, then re-run with **retest-and-monitor** to confirm the rule no longer matches.
