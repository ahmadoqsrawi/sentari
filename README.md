# Sentari

**Evidence-grounded, authorized security assessment.**

Sentari orchestrates real security tools and reports **only what they actually
found**. Its one non-negotiable rule:

> A finding may exist only if it is backed by **evidence**: the real output of a
> real command that actually ran. No hardcoded results. No LLM-invented
> vulnerabilities.

Every finding in a Sentari report cites the exact command, its output, exit code
and timing. If a tool didn't observe it, Sentari won't claim it.

## Status

Early. Implemented phase-by-phase:

- [x] **Phase 1: Reconnaissance**: DNS resolution, port/service discovery
  (built-in TCP connect scan, enriched by `nmap -sV` when installed), and basic
  web fingerprint. Runs with zero external tools installed.
- [ ] Phase 2: Scanning & enumeration (`nmap` scripts, `gobuster`/`ffuf`)
- [ ] Phase 3: Vulnerability assessment (`nuclei`, `testssl.sh`)
- [ ] Phase 4: Exploitation (approval-gated, safe-mode aware)
- [ ] Phase 5: Reporting (HTML/JSON, evidence-linked)
- [ ] Phase 6: Retest

## Authorization (required)

Sentari runs real offensive tooling. It refuses to act unless:

1. you declare a **scope** (`--scope`) that the target falls within, **and**
2. you **attest authorization** (`--authorized`).

Every run is written to an append-only audit log. Use Sentari only against
systems you own or have explicit written permission to test.

## Usage

```bash
# list phases
python -m sentari --list-phases

# run against an authorized target
python -m sentari example.com --scope example.com --authorized

# scope by CIDR, save full evidence to JSON
python -m sentari 10.0.0.5 --scope 10.0.0.0/24 --authorized --json report.json

# preview without executing anything
python -m sentari example.com --scope example.com --authorized --dry-run
```

## License

Proprietary, no-derivatives: see [LICENSE](LICENSE). You may use and share
verbatim copies; you may not modify, create derivatives, or redistribute
modified versions.
