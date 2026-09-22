# Changelog

All notable changes to Sentari are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and versioning follows
[SemVer](https://semver.org/).

## [0.1.0] - 2026-09-22

First release. An evidence-grounded assessment pipeline built around one rule: a finding may exist only if a real command produced output for it.

### Added
- **Core**: an evidence-first data model (`Evidence` / `Finding` / `PhaseResult`). A `Finding` cannot be constructed without evidence. `ToolRunner` records every external tool and built-in probe as evidence (command, output, exit code, timing).
- **Authorization**: a scope allowlist (host and CIDR, with DNS resolution), an explicit `--authorized` attestation, and an append-only audit log.
- **Phases**: 1 Reconnaissance, 2 Scanning and Enumeration, 3 Vulnerability Assessment (`nuclei` plus gated `sqlmap`), 4 Verification (read-only, gated, secrets redacted), 5 Reporting, 6 Retest.
- **AI triage**: multi-provider (`sentari/ai/`: OpenAI, OpenRouter, Anthropic, Google, Ollama). It prioritizes, correlates, and suggests fixes, working only from the real findings, and it drops any reference to a finding that does not exist.
- **Compliance mapping**: OWASP Top 10 (2021), CWE, and NIST 800-53 tags on findings (console, HTML, JSON).
- **Reporting**: self-contained HTML with per-finding evidence, plus JSON.
- **Retest**: diff against a prior run, either `--retest FILE` or `--retest-latest` (from `--db`).
- **Persistence**: `sentari/db/`, SQLite by default and Postgres optionally.
- **Web dashboard and REST API**: `sentari/web/`, read-only, localhost by default, built on the standard library's `http.server`; `--serve`, `/api/runs`, `/run/<id>`.
- **Parallelism**: a standard-library thread pool for I/O-bound probes (port scan, content discovery).
- **Distributed execution**: an optional Celery task queue (`sentari/tasks/`, `--enqueue`), plus `Dockerfile`, `docker-compose.yml`, and `deploy/k8s/` manifests.
- **Engine**: one shared `run_assessment` code path for the CLI and the workers.
- **CLI**: `--scope`, `--authorized`, `--phases`, `--no-safe-mode`, `--html`, `--json`, `--save-run`, `--db`, `--retest`, `--retest-latest`, `--ai` (`--ai-provider`/`--ai-model`/`--ai-base-url`), `--no-compliance`, `--enqueue`, `--serve`/`--host`/`--port`/`--runs-dir`, `--dry-run`, `--list-phases`.
- **Tests**: `tests/` (standard-library `unittest`) covering the evidence contract, authorization, the nmap parser, the retest diff, compliance mapping, the AI grounding guard, and redaction.

### Notes
- The core runs on the Python standard library. External tools and celery/redis/psycopg2 are optional.
- Missing tools are reported as missing, never worked around with invented results.
