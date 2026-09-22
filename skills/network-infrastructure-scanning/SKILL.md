---
name: network-infrastructure-scanning
description: Map a host or network with Sentari. Resolves DNS, discovers open ports and services, classifies them, checks TLS and security headers, finds exposed sensitive paths, and correlates any CVEs against the CISA Known Exploited Vulnerabilities catalog. Uses nmap, masscan, or naabu when installed and a built-in TCP scan otherwise. Use when the user wants to scan a host, IP, or network they are authorized to test for open services and infrastructure exposure.
license: AGPL-3.0-or-later
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Network and infrastructure scanning with Sentari

Discover what a host or network actually exposes, with every result backed by a real probe. Install and the full flag set are in the **penetration-testing-with-sentari** skill.

## 1. Confirm authorization and scope

- The host or range is the user's or explicitly authorized. Scope can be a host or a CIDR.
- Wide port ranges and masscan are noisy; confirm the network owner is fine with active scanning.
- Always pass `--scope <host-or-CIDR>` and `--authorized`.

## 2. Prerequisites

Sentari scans with a built-in TCP-connect scanner out of the box. Install any of `nmap`, `naabu`, `masscan`, `httpx` on PATH for faster, richer discovery; Sentari picks them up automatically and reports which it used.

## 3. Recon and scanning

```bash
sentari 203.0.113.10 --scope 203.0.113.0/24 --authorized --phases recon,scanning --json infra.json
```

- **recon**: DNS resolution, port and service discovery, web fingerprint. Scanner preference is nmap, then naabu, then masscan (only outside safe mode, it needs root), then the built-in scan. Each open port is classified (web, database, mail, remote-access, and so on).
- **scanning**: security headers, TLS inspection (including handshakes against TLS 1.0/1.1 to spot legacy protocols), version disclosure, and content discovery for exposed sensitive paths.

Faster discovery with masscan (needs `--no-safe-mode` and root):

```bash
sentari 203.0.113.10 --scope 203.0.113.10 --authorized --no-safe-mode --phases recon
```

## 4. External attack surface (OSINT)

```bash
sentari example.com --scope example.com --authorized --phases osint
```

Passive subdomain enumeration (subfinder, amass, theHarvester) and Shodan lookups when the tools and `SHODAN_API_KEY` are present. Discovered assets are recorded for review, never scanned automatically; bring the ones in scope into a later run.

## 5. Threat intel on discovered services

Finding CVEs are correlated against the CISA KEV catalog automatically (disable with `--no-threatintel`); a match is tagged known-exploited in the report. See the **risk-prioritization** skill for ranking.

## 6. Review and verify

Read the console report, then `infra.json`. Each open-port and service finding cites the probe in `evidence_ids`; cross-check before reporting. An open port is not a vulnerability by itself, so describe exposure honestly.

## 7. Next steps

Feed web services found here into the **web-app-penetration-testing** skill, and persist runs for trend and delta tracking with **retest-and-monitor**.
