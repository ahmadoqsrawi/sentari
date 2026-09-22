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
  explicit `--authorized` attestation, and an append-only audit log.
- **Phases**: 1 Reconnaissance, 2 Scanning & Enumeration, 3 Vulnerability
  Assessment (`nuclei` + gated `sqlmap`), 4 Verification (read-only, gated,
  secrets redacted), 5 Reporting, 6 Retest.
- **Grounded AI triage**: multi-provider (`sentari/ai/`: OpenAI, OpenRouter,
  Anthropic, Google, Ollama); prioritizes / correlates / remediates over real
  findings only, with a guard that drops any invented references.
- **Compliance mapping**: OWASP Top 10 (2021), CWE, NIST 800-53 tags on
  findings (console / HTML / JSON).
- **Reporting**: self-contained evidence-linked HTML plus JSON.
- **Retest**: diff against a prior run: `--retest FILE` or `--retest-latest`
  (from `--db`).
- **Persistence**: `sentari/db/`: SQLite by default, optional Postgres.
- **Web dashboard + REST API**: `sentari/web/`: read-only, localhost by default,
  standard-library `http.server`; `--serve`, `/api/runs`, `/run/<id>`.
- **Parallelism**: stdlib thread pool for I/O-bound probes (port scan, content
  discovery).
- **Distributed**: optional Celery task queue (`sentari/tasks/`, `--enqueue`);
  `Dockerfile`, `docker-compose.yml`, and `deploy/k8s/` manifests.
- **Engine**: one shared `run_assessment` code path for CLI and workers.
- **CLI**: `--scope`, `--authorized`, `--phases`, `--no-safe-mode`, `--html`,
  `--json`, `--save-run`, `--db`, `--retest`, `--retest-latest`, `--ai`
  (`--ai-provider`/`--ai-model`/`--ai-base-url`), `--no-compliance`, `--enqueue`,
  `--serve`/`--host`/`--port`/`--runs-dir`, `--dry-run`, `--list-phases`.
- **Tests**: `tests/` (stdlib `unittest`): evidence contract, authorization,
  nmap parser, retest diff, compliance mapping, AI grounding guard, redaction.

### Notes
- Core runs on the Python standard library alone; external tools and
  celery/redis/psycopg2 are optional enrichment.
- Missing tools are reported honestly and never fabricated around.
