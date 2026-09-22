---
name: fix-security-vulnerabilities-with-sentari
description: Turn Sentari's findings into a remediation guide and, optionally, a draft pull request. Sentari is suggest-only, so it writes a Markdown fix guide from the real findings (and grounded AI remediation when enabled) and can open it as a draft PR via the GitHub CLI, but it never edits application code or merges. Use when the user wants remediation guidance, a fix write-up, or a PR from a security scan.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Remediation and fix PRs with Sentari

Suggest-only by design: Sentari produces a guide and can open a draft PR that contains that guide, but it does not change application code or merge. Install and the full flag set are in the **penetration-testing-with-sentari** skill.

## 1. Get findings to fix

Run any assessment that produces findings first (see **penetration-testing-with-sentari** or the class-specific skills). The remediation output is built from those real findings, so run the fix flags on the same command or a re-run.

## 2. Write a remediation guide

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --ai --autofix SECURITY_FIXES.md
```

`--autofix FILE` writes a Markdown guide grouped by severity, one section per real finding, with the recommended fix, the location, and the evidence ids. Adding `--ai` includes the grounded AI remediation text.

## 3. Open a draft pull request

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --autofix-pr --autofix-repo /path/to/the/repo
```

Requirements: the repo is a git repository with a GitHub remote, and the GitHub CLI (`gh`) is installed and authenticated (`gh auth login`). Sentari creates a branch, writes `SECURITY_FIXES.md`, commits, pushes, and opens a **draft** PR. It touches only that file.

## 4. Review and apply the fix

A human reads the guide and makes the actual code change. Fix the root cause, not just the symptom the finding points at.

## 5. Verify the fix landed

Re-run against the same target and diff (see **retest-and-monitor**):

```bash
sentari https://app.example.com --scope app.example.com --authorized --retest baseline.json
```

The finding must move to "fixed". Re-testing is the only reliable confirmation.

## Why suggest-only

Auto-editing application code from a scanner is unreliable and risky. The honest workflow is: Sentari proves and explains the issue with evidence, a human makes the change, and a re-test confirms it. Keep it that way.
