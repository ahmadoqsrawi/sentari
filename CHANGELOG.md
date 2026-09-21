# Changelog

All notable changes to Sentari are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/); versioning follows
[SemVer](https://semver.org/).

## [0.1.0]: 2026-09-22

First release. A complete, evidence-grounded assessment pipeline built around one
rule: **a finding may only exist if backed by real command output.**

### Added
- **Core**: evidence-first data model (`Evidence` / `Finding` / `PhaseResult`);
  a `Finding` cannot be constructed without evidence. `ToolRunner` captures every
  external tool *and* built-in probe as evidence (command, output, exit, timing).
- **Authorization**: real scope allowlist (host + CIDR with DNS resolution),
  explicit `--authorized` attestation, and an append-only audit log. Refuses to
  run out-of-scope or unattested.
- **Phase 1: Reconnaissance**: DNS resolution, port/service discovery (built-in
  TCP connect scan, enriched by `nmap -sV` when present), web fingerprint.
- **Phase 2: Scanning & Enumeration**: HTTP security-header analysis, TLS
  inspection (incl. real legacy TLS 1.0/1.1 handshake tests), technology/version
  disclosure, content discovery (`gobuster`/`ffuf` or a built-in sensitive-path
  probe).
- **Phase 3: Vulnerability Assessment**: `nuclei` template integration; gated
  `sqlmap` (runs only with `--sqlmap-url` or `--no-safe-mode`).
- **Phase 4: Verification**: read-only, non-destructive confirmation of
  findings; gated behind `--no-safe-mode`; retrieved secrets are redacted.
- **Phase 5: Reporting**: self-contained, offline HTML report (evidence linked
  per finding) plus JSON output.
- **Phase 6: Retest**: diff a fresh scan against a prior `--json` baseline into
  fixed / still-present / new.
- **CLI**: `sentari` / `python -m sentari` with `--scope`, `--authorized`,
  `--phases`, `--safe-mode`, `--html`, `--json`, `--retest`, `--dry-run`.

### Notes
- Core runs on the Python standard library alone; external tools are optional
  enrichment.
- Missing tools are reported honestly and never fabricated around.
