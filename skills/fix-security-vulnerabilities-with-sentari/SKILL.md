---
name: fix-security-vulnerabilities-with-sentari
description: Turn Sentari's findings into a remediation guide and, optionally, a draft pull request. Sentari is suggest-only, so it writes a Markdown fix guide from the real findings (and grounded AI remediation when enabled) and can open it as a draft PR via the GitHub CLI, but it never edits application code or merges. Use when the user wants remediation guidance, a fix write-up, or a PR from a security scan.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Remediation and fix PRs with Sentari

This is suggest-only. Sentari does not change application code; it produces a guide and can open a draft PR that contains that guide for a human to review.

## Write a remediation guide

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --ai --autofix SECURITY_FIXES.md
```

`--autofix FILE` writes a Markdown guide grouped by severity, one section per real finding, with the recommended fix, the location, and the evidence ids. Adding `--ai` includes the grounded AI remediation text.

## Open a draft pull request

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --autofix-pr --autofix-repo /path/to/the/repo
```

Requirements: the repo is a git repository with a GitHub remote, and the GitHub CLI (`gh`) is installed and authenticated (`gh auth login`). Sentari creates a branch, writes `SECURITY_FIXES.md`, commits, pushes, and opens a **draft** PR. It touches only that file; it never edits code and never merges. A human reviews and applies the actual fixes.

## Why suggest-only

Auto-editing application code from a scanner is unreliable and risky. The honest workflow is: Sentari proves and explains the issue with evidence, and a human makes the code change. Keep it that way.
