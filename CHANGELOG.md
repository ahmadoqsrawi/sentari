# Changelog

All notable changes to Sentari are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and versioning follows
[SemVer](https://semver.org/).

## [0.2.0] - 2026-09-22

### Added
- **SIEM export** (`sentari/siem/`): ship findings and a run summary to Splunk HEC, Elasticsearch, syslog, or a generic webhook, via `--siem-url`/`--siem-type` (token from `--siem-token` or `SENTARI_SIEM_TOKEN`).
- **Prometheus metrics** (`sentari/metrics.py`): a `/metrics` endpoint on the dashboard, plus a Grafana dashboard and scrape config under `deploy/`.
- **Model catalog** (`sentari/ai/catalog.py`): `--list-models` lists known models per provider; any provider-specific id still works.
- **Anomaly flagging** (`sentari/anomaly.py`): tags findings whose evidence is unusual for the target as worth manual review. It is a prioritization aid, never a vulnerability claim, and it creates no findings. Disable with `--no-anomaly`.
- **AI autopilot** (`sentari/autopilot.py`, `--autopilot`): the model picks which phase to run next and when to stop. It controls only the flow; the target is fixed, findings still come from the tools with evidence, scope and safe mode are enforced on every step, and an invalid or missing model choice falls back to the normal phase order.
- **AI agent** (`sentari/agent/`, `--agent`, `--goal`): a function-calling loop where the model calls tools directly (dns, port scan, http, nuclei, gated sqlmap) and can author findings. A finding is accepted only with a real `evidence_id`, and a verifier pass drops model-authored findings the evidence does not support. The host is fixed and arguments are validated, so a prompt injection in a target response cannot redirect the host or run an arbitrary command. With no model it runs a fixed recon sequence.

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
