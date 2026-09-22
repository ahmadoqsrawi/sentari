---
name: penetration-testing-with-sentari
description: Pentest a web app, API, URL, domain, or host with Sentari, an evidence-grounded, authorized security assessment tool that reports only findings backed by real tool output (no fabricated or guessed results). Runs a 6-phase methodology (OSINT, recon, scanning, vuln assessment, verification, reporting) with optional AI triage, and confirms high-impact issues by actual effect (XSS/SSTI execution, SSRF/XXE out-of-band callback). Use when the user asks to pentest, security-scan, security-audit, or find vulnerabilities in an app, API, website, or host they are authorized to test.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Run a Sentari assessment

Sentari is an authorized-use security assessment tool. Its core rule: a finding cannot exist without evidence (the real output of a real command that ran). It never invents results, and every result marked "confirmed" required an actual observed effect.

## Before you run anything

Sentari refuses to run unless the operator attests authorization and gives a scope. Always pass both:

- `--scope <host-or-CIDR>` (repeatable): the authorized target(s).
- `--authorized`: attests written permission to test.

Never run it against a target the user does not own or have written permission to test. Do not use offensive/gated features against production.

## Install

Python 3.9+. Core is standard-library only:

```bash
pip install .
# optional extras as needed:
pip install ".[ai,browser,api,cloud,openvas,privesc,pdf,distributed,postgres]"
```

## A first, safe assessment (read-only by default)

```bash
sentari https://staging.example.com --scope staging.example.com --authorized \
  --html report.html --json report.json
```

Safe mode is on by default: intrusive and gated checks stay off until explicitly enabled.

## Phases

Run all (default) or select with `--phases a,b,c`:

| Phase | What it does |
|---|---|
| osint | passive subdomain enumeration + Shodan (needs the tools/keys) |
| recon | DNS, ports/services, web fingerprint; ingests an `--openapi` spec |
| scanning | security headers, TLS, content discovery |
| sast | semgrep over a source tree (`--sast PATH`) |
| cloud-audit | Prowler misconfiguration audit (`--cloud-audit aws|azure|gcp`) |
| vuln | nuclei templates, gated sqlmap, optional OpenVAS/Nexpose |
| api | JWT audit, rate-limit, auth exposure (`--api-tests`) |
| access-control | IDOR / missing-auth by comparing identities (`--access-control`) |
| injection | SSRF/XXE/cmdi (out-of-band confirmed), SSTI, NoSQLi, deserialization (`--injection`) |
| browser | client-side DAST: reflected/DOM/stored XSS, proto pollution, clickjacking, CSRF (`--browser`) |
| verification | read-only confirmation of findings (only with `--no-safe-mode`) |

## Add AI triage (optional, grounded)

```bash
sentari <target> --scope <target> --authorized --ai --ai-provider openai
```

The AI prioritizes and chains the real findings; a grounding guard drops any AI reference to a finding that does not exist. `--autopilot` lets the AI choose phases; `--agent` lets it call tools directly. Findings stay evidence-anchored.

## Multi-target / red-team style

```bash
sentari t1.example.com --graph --graph-target t2.example.com --graph-target t3.example.com \
  --scope example.com --authorized --ai
```

`--graph` runs specialized nodes on a shared blackboard, several targets in parallel, then correlates findings across assets and (with `--ai`) chains them.

## Reporting and retest

`--html`, `--json`, `--xml`, `--pdf` write reports. `--db <dsn>` persists runs; `--serve` opens a read-only dashboard. `--retest <baseline.json>` or `--retest-latest` diffs a fresh run (fixed / still present / new).

## Gated offensive features (authorized, non-production only)

These run real attack tooling and need `--no-safe-mode`, their own flag, and an exact confirmation string. See the **web-app-penetration-testing** skill for details. Never point them at production.

## What Sentari will not do

It will not fabricate findings, will not perform credential stuffing, and will not run fully autonomous exploitation of production. Respect these; do not try to work around them.
