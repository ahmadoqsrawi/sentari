# Changelog

All notable changes to Sentari are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and versioning follows
[SemVer](https://semver.org/).

## [0.5.0] - 2026-09-22

### Added
- **Threat-intel correlation** (`threatintel.py`, on by default, `--no-threatintel`): correlates finding CVEs against the CISA Known Exploited Vulnerabilities catalog, fetched over HTTPS and cached daily. A match tags the finding as known-exploited; when the catalog cannot be fetched, correlation is skipped with a note. Reports what CISA lists; predicts nothing.
- **Service classification** (`classify.py`): deterministic port/service to category lookup (web, database, mail, remote-access, and so on) attached to open-port findings. A lookup, not machine learning.
- **Business-impact scoring and risk matrix** (`prioritize.py`, `--asset-value low|medium|high|critical`): weights a finding's CVSS or severity by asset criticality and places each finding on a likelihood by impact grid, shown in the console report. Rates the real findings; adds none.
- **Cross-asset correlation** (`correlation.py`, `--correlate`): reports a finding seen across more than one target in `--db` or `--runs-dir`, so a systemic issue stands out.
- **Trend analysis** (`trends.py`, `--trends`): severity counts per stored run, oldest to newest, from `--db` or `--runs-dir`.
- **OpenVAS / Greenbone connector** (`openvas.py`, `--openvas`): pulls results from a configured GVM instance (python-gvm + `GVM_*` env) into the vuln phase as evidence-backed findings; graceful when unconfigured.
- **Azure and GCP asset discovery** (`cloud_assets.py`): real implementations for `--cloud azure` (azure SDK, `AZURE_SUBSCRIPTION_ID`) and `--cloud gcp` (google-cloud-compute, `GOOGLE_CLOUD_PROJECT`), alongside the existing AWS path; enumerate only.
- **masscan** port discovery in recon when installed and safe mode is off.
- **Gated post-exploitation** (`phases/postexploit.py`, `--postexploit`): CrackMapExec SMB enumeration and bloodhound-python AD collection with operator-supplied credentials. Off by default; requires `--no-safe-mode`, `--postexploit`, credentials, and an exact confirmation string; scope enforced; findings evidence-backed. Authorized, non-production targets only.

## [0.4.0] - 2026-09-22

### Added
- **OSINT phase** (`phases/osint.py`, phase 0): passive subdomain enumeration (subfinder, amass passive, theHarvester) and Shodan host lookup; all optional and graceful; assets recorded as info findings, never auto-scanned.
- **httpx / naabu**: recon uses naabu for port discovery and httpx for web fingerprint when installed, with the built-in probes as fallback.
- **CVSS v3.1 scoring** (`cvss.py`): base scores from a vector, attached to nuclei findings with a vector.
- **XML and PDF export** (`reporting/xml.py`, `reporting/pdf.py`): `--xml`, `--pdf` (PDF via optional reportlab).
- **Cloud asset discovery** (`cloud_assets.py`, `--cloud aws|azure|gcp`): list internet-facing assets from your own account; boto3 for AWS, Azure/GCP graceful; enumerate only.
- **Scheduled retests**: Celery beat schedule from `SENTARI_SCHEDULE_*` plus a `scheduled_retest` task reporting the delta vs the previous run.
- **Heuristic candidate flagging** (`heuristics.py`): tags error/stack-trace patterns in evidence as candidates for manual review. Never a vulnerability or zero-day claim; creates no findings. `--no-heuristics` to disable.
- **Gated exploitation** (`phases/exploit.py`, `--exploit`): runs operator-named Metasploit modules and a bounded, redacted exfil-simulation. Off by default; requires `--no-safe-mode`, `--exploit`, and an exact confirmation string; scope enforced; findings evidence-backed. Authorized, non-production targets only.

### Fixed
- CLI report options now cover HTML/JSON/XML/PDF uniformly.

## [0.3.1] - 2026-09-22

### Fixed
- **Explicit target port is now always scanned.** `recon` and `scanning` honor the port in a `host:port` or URL target (`recon.target_port`), instead of only scanning the ports recon happened to discover. Found while testing a real app on a non-default port.
- **Verifier no longer confirms `/.svn/entries` from a catch-all page.** The signature required any content; it now requires the bare format-number line a real entries file starts with, so an app's fallback 200 is not escalated.

## [0.3.0] - 2026-09-22

### Added
- **More AI providers** (`sentari/ai/providers.py`): 14 in total. OpenAI-compatible entries are data-driven (OpenAI, OpenRouter, DeepSeek, Mistral, Groq, xAI, Together, Fireworks, Perplexity, GLM, NVIDIA), plus Anthropic, Google, and Ollama. An unknown name is treated as an OpenAI-compatible endpoint. The catalog and `--list-models` are expanded to match.
- **Native function-calling** for the agent: the OpenAI and Anthropic providers implement `tool_turn`, and the agent uses it when available, falling back to the JSON protocol otherwise. Tool schemas live in `sentari/agent/schema.py`. The same safety rules hold: fixed host, validated arguments, and evidence-anchored findings.

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
