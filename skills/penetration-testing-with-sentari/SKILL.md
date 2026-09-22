---
name: penetration-testing-with-sentari
description: Pentest a web app, API, URL, domain, or host with Sentari, an evidence-grounded, authorized security assessment tool that reports only findings backed by real tool output (no fabricated or guessed results). Runs a phased methodology (OSINT, recon, scanning, SAST, vuln, API, access-control, injection, browser DAST, verification) with optional AI triage and a multi-target graph, and confirms high-impact issues by actual effect (XSS/SSTI execution, SSRF/XXE/command-injection out-of-band callback). Use when the user asks to pentest, security-scan, security-audit, or find vulnerabilities in an app, API, website, or host they are authorized to test.
license: AGPL-3.0-or-later
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Run a Sentari assessment

Sentari is an authorized-use security assessment tool. Its one hard rule: a finding cannot exist without evidence (the real output of a real command that ran). It never invents results, and anything labelled "confirmed" required an actual observed effect (payload execution, or an out-of-band callback). This skill is the end-to-end workflow; the other Sentari skills go deeper per area and are linked at the end.

## 1. Confirm authorization and scope

Before running anything, establish:

- **The target is the user's**, or they have written permission to test it. Never scan third-party infrastructure on a hunch.
- **Which environment.** Prefer staging over production. Gated/active features send real payloads and can change data; keep them off production.
- **Credentials**, if the app has a login. Most real issues live behind auth; without a test account Sentari only sees the public surface. Two accounts are needed to prove access-control/IDOR bugs (see the web-app and access-control skills).
- **Out-of-scope paths** (payments, mass-email, destructive admin actions).

Ask for anything missing rather than guessing. Sentari refuses to run unless you pass `--scope <host-or-CIDR>` (repeatable) and `--authorized`, and it records every run in an append-only audit log.

## 2. Prerequisites

Python 3.9+. The core is standard-library only:

```bash
pip install .                      # core
sentari --version                  # verify
sentari --list-phases              # see the phases available
```

Optional extras add coverage and degrade gracefully when absent:

```bash
pip install ".[ai,browser,api,cloud,openvas,privesc,pdf,distributed,postgres]"
playwright install chromium        # only if using --browser
```

External scanners (`nmap`, `nuclei`, `sqlmap`, `gobuster`/`ffuf`, `subfinder`, `semgrep`, `prowler`, `mitmproxy`, Docker) are used when present and reported as missing otherwise. Sentari never fabricates a result to fill a gap.

## 3. Run the assessment

Safe mode is on by default (intrusive and gated checks stay off).

```bash
# Read-only first pass with reports
sentari https://staging.example.com --scope staging.example.com --authorized \
  --html report.html --json report.json

# Only some phases
sentari https://staging.example.com --scope staging.example.com --authorized --phases recon,scanning,vuln

# With the API surface and client-side DAST
sentari https://staging.example.com --scope staging.example.com --authorized \
  --openapi ./openapi.json --api-tests --browser

# Access control needs two identities (the only way to prove IDOR)
sentari https://staging.example.com --scope staging.example.com --authorized \
  --access-control --identity alice:Cookie:session=aaa --identity bob:Cookie:session=bbb

# AI triage over the real findings
sentari https://staging.example.com --scope staging.example.com --authorized --ai --ai-provider openai

# Multi-target, red-team style: shared blackboard, parallel, correlated (+ AI chaining)
sentari t1.example.com --graph --graph-target t2.example.com --scope example.com --authorized --ai
```

Some phases (nuclei, injection with out-of-band waits, browser) take minutes. For a large or `--graph` run, launch it in the background and poll rather than blocking.

Localhost: point at the actual bound address (for example `http://127.0.0.1:3000`) and pass that port explicitly; to test only a throwaway port, use `--phases scanning,vuln http://host:PORT` without recon so nothing else on the box is probed.

## 4. Phases

| Phase | Flag to enable (if not default) | What it does |
|---|---|---|
| osint | default | passive subdomain enumeration + Shodan (needs tools/keys) |
| recon | default | DNS, ports/services, web fingerprint; ingests `--openapi` |
| scanning | default | security headers, TLS, content discovery |
| sast | `--sast PATH` | semgrep over a source tree |
| cloud-audit | `--cloud-audit aws\|azure\|gcp` | Prowler misconfiguration audit |
| vuln | default | nuclei, gated sqlmap, optional OpenVAS/Nexpose |
| api | `--api-tests` | JWT audit, rate-limit, auth exposure |
| access-control | `--access-control` | IDOR / missing-auth by comparing identities |
| injection | `--injection` | SSRF/XXE/cmdi (OOB-confirmed), SSTI, NoSQLi, deserialization |
| workflow | `--workflow FILE` | operator-defined business-logic replay |
| browser | `--browser` | reflected/DOM/stored XSS, proto pollution, clickjacking, CSRF |
| verification | `--no-safe-mode` | read-only confirmation of findings, secrets redacted |

## 5. Read the results

Read the console report first, then `report.json` for detail. Structure:

```
{"results": [{"phase": "...", "findings": [{
    "title", "severity", "description", "location", "evidence_ids": ["..."],
    "metadata": {"cvss", "compliance", "known_exploited", "risk", "business_impact", "candidate"}}],
  "evidence": [{"id", "command", "returncode", "stdout", "stderr", ...}]}]}
```

- **Confirmed vs candidate.** A finding whose title says "confirmed" (XSS, SSRF, XXE, command injection, SSTI, PoC) required a real observed effect. A finding with `metadata.candidate` set is a lead for manual review, not an assertion. Report the difference honestly.
- **Verify before reporting.** Every finding cites `evidence_ids`; cross-check them against the `evidence` entries (the exact command and its output). For a confirmed exploit, re-run the evidence to see it for yourself.
- **Prioritize** with CVSS, the CISA-KEV `known_exploited` tag, and the `business_impact`/`risk` fields (see the risk-prioritization skill).

Reports: `--html`, `--json`, `--xml`, `--pdf`. Persist and browse runs with `--db <dsn>` and `--serve` (see the reporting skill).

## 6. Coverage honesty

A clean run means nothing was proven **in what was tested**, not that the app is secure. State what was and was not exercised: gated/active phases run only when enabled and outside safe mode, tool-backed phases skip when the tool is missing, and access-control/business-logic need credentials to be meaningful. Do not imply full coverage from a default run.

## 7. Fix, re-test, and automate

- Remediate and open a draft PR: **fix-security-vulnerabilities-with-sentari**.
- Confirm the fix landed by diffing a fresh run: **retest-and-monitor** (`--retest`, `--retest-latest`).
- Gate every change in CI: **ci-security-scanning-with-sentari**.

## What Sentari will not do

No fabricated findings, no credential stuffing, and no fully-autonomous exploitation of production. These are structural; do not try to work around them.
