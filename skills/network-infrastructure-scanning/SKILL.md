---
name: network-infrastructure-scanning
description: Map a host or network with Sentari. Resolves DNS, discovers open ports and services, classifies them, checks TLS and security headers, finds exposed sensitive paths, and correlates any CVEs against the CISA Known Exploited Vulnerabilities catalog. Uses nmap, masscan, or naabu when installed and a built-in TCP scan otherwise. Use when the user wants to scan a host, IP, or network they are authorized to test for open services and infrastructure exposure.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Network and infrastructure scanning with Sentari

Always pass `--scope` and `--authorized`. Scope can be a host or a CIDR.

## Recon and scanning

```bash
sentari 203.0.113.10 --scope 203.0.113.0/24 --authorized --phases recon,scanning --json infra.json
```

- **recon**: DNS resolution, port and service discovery, web fingerprint. Scanner preference is nmap, then naabu, then masscan (only outside safe mode, it needs root), then a built-in TCP-connect scan. Each open port is classified (web, database, mail, remote-access, and so on).
- **scanning**: security headers, TLS inspection (including handshakes against TLS 1.0/1.1 to spot legacy protocols), version disclosure, and content discovery for exposed sensitive paths.

## Faster discovery with real tools

Install any of `nmap`, `naabu`, `masscan`, `httpx` on PATH and Sentari uses them automatically. masscan runs only with `--no-safe-mode` (it needs root):

```bash
sentari 203.0.113.10 --scope 203.0.113.10 --authorized --no-safe-mode --phases recon
```

## Threat intel on discovered services

Finding CVEs are correlated against the CISA KEV catalog automatically (disable with `--no-threatintel`); a match is tagged as known-exploited in the report.

## OSINT for external attack surface

```bash
sentari example.com --scope example.com --authorized --phases osint
```

Passive subdomain enumeration (subfinder, amass, theHarvester) and Shodan lookups when the tools and `SHODAN_API_KEY` are present. Discovered assets are recorded for review, never scanned automatically.
