# Changelog

All notable changes to Sentari are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and versioning follows
[SemVer](https://semver.org/).

## [0.25.0] - 2026-09-23

### Added
- Confidence tagging: every finding is marked confirmed (a real effect was observed) or reported/unverified (a scanner flagged it), the report leads with confirmed and counts them separately, so an unverified template match no longer shows as a proven critical.
- Coverage map + gaps: the run reports every surface reviewed with its outcome and the gaps (phase not enabled, tool missing, no credentials for authenticated flows); included in the console output and JSON.
- Catch-all / soft-404 detection: sensitive-path hits are suppressed on servers that return the same status for random nonexistent paths (kills a common false-positive class).
- Framework/SPA phase (--framework): open redirect (Location-confirmed), Next.js image-optimizer SSRF (/_next/image, OOB-confirmed), and host-header reflection.
- Threat model (--threat-model): plans the run as skill-scoped assessors (recon, auth/API, authorization/IDOR, injection, framework, client-side, verification) and attributes results to each, with per-assessor gaps.
- Executive Markdown report (--report): summary, methodology, confirmed findings, recommendations, coverage gaps and retest guidance, grounded in the real run.
- SARIF 2.1.0 export (--sarif) for GitHub code scanning / CI / IDEs, carrying severity, confidence, and references.

## [0.24.0] - 2026-09-23

### Added
- Environment-independent tool discovery: the runner now resolves scanners via PATH and a set of known install dirs (and `SENTARI_TOOLS_PATH`), so a worker/systemd/detached process finds the same tools an interactive shell would. Previously a minimal PATH made a scanner look missing and a phase silently reported 0.
- `--preflight`: report which external tools are installed/found and what each powers; a one-line environment summary now prints at the start of every scan and is embedded in the JSON report, so "0 findings" is never confused with "tool not installed".
- Auto-save: when no output flag is given, a run now writes a timestamped HTML+JSON report instead of only printing to stdout, so results can't be lost.

### Changed
- Dockerfile now bakes in the full scanner set (nmap, sqlmap, nuclei, httpx, subfinder, ffuf, gobuster, git, dig, semgrep, Playwright/Chromium) so a containerized run has the tools with no host setup; docker-compose publishes the OOB port and adds restart policies.

## [0.23.0] - 2026-09-23

### Added
- Public out-of-band callbacks for external targets: `--oob-host auto` detects this host's public IP, `--oob-port` fixes the listener port so it can be opened in the firewall, and the listener now binds all interfaces while advertising the public host. This makes SSRF/XXE/command-injection confirmable against real external sites (the model for a hosted deployment), not just a target on the same box. The wizard offers public OOB for any external target and prints the firewall command; specs carry an `oob` block.

### Changed
- The injection phase warns when the OOB host is localhost outside safe mode, since callbacks can then only be confirmed for a target that can reach this host.

## [0.22.0] - 2026-09-23

### Added
- Code Review wizard: `sentari wizard` now asks whether to set up a Web App Pentest or a Code Review, or jump straight in with `sentari wizard code-review` / `sentari wizard web-pentest`. The Code Review flow is two steps (Source, then Context) and needs no live environment: point it at a git repo or a local path, add the threats/areas to focus on, review, and launch. It saves a reusable `code-review.json` and is authorized by default (it only reads source you can already access).

## [0.21.0] - 2026-09-23

### Added
- Browser login recording (`--login-record URL` with `--login-user`/`--login-pass`): drives a real headless browser through a login form, verifies the sign-in (a caller-supplied success string, or the password field disappearing as the URL leaves the login page), captures the session cookies as a ready-to-use `--identity`/`--header` value, and saves a screenshot and the post-login response as evidence. Optional field selectors (`--login-user-field`/`--login-pass-field`/`--login-submit`). The wizard's Access step can record a login inline. Needs Playwright; degrades honestly without it.

## [0.20.0] - 2026-09-23

### Added
- Guided pentest setup: `sentari wizard` walks the five intake steps (Target & APIs, Scope, Repositories, Access, Context) with a Review & Launch summary, saves a reusable `pentest.json`, and launches. `--spec FILE` loads a spec directly.
- `--exclude HOST|CIDR`: an off-limits deny-list enforced in the authorization gate; an excluded target is refused even when it also matches `--scope`.
- `--header 'NAME: VALUE'`: custom headers sent with every request (API keys, JWTs, session cookies, WAF-bypass tokens), applied globally via urllib and to the browser phase.
- `--code-review` now accepts a git URL (GitHub/GitLab/Bitbucket): the repo is shallow-cloned into a temp dir, scanned, and removed. A repo in a web pentest spec adds source review alongside the live phases.
- `--verify-domain DOMAIN`: prove control of a domain via a `sentari-verify=<token>` DNS TXT record (Cloudflare-style) before an external scan; tokens are issued and checked per domain.

These are intake/orchestration features that map onto existing capabilities; they add no new engine behavior, so the evidence-first and authorization rules are unchanged.

## [0.19.0] - 2026-09-23

### Added
- Two workflow presets that bundle existing capabilities into one command: `--code-review PATH` (static source review over PATH, no live environment, with AI fix suggestions; authorized by default since it only reads local files) and `--web-pentest URL` (authenticated live-app pentest: full pipeline plus injection/OOB, browser execution, and API checks; still requires `--authorized`). Presets add no new engine behavior, so the evidence-first and authorization rules are unchanged.

## [0.18.0] - 2026-09-23

### Added
- Local terminal viewer (`--tui`): an interactive curses browser over a run's findings (from `--json`, `--runs-dir`, or `--db`) with severity colors, an evidence pane, and severity filtering; falls back to a plain colored dump without a TTY. Standard library only.

## [0.17.1] - 2026-09-22

### Fixed
- OOB listener now binds IPv6 addresses (AF_INET6) and brackets IPv6 URLs, so out-of-band SSRF/XXE/command-injection checks work on IPv6 hosts instead of hanging.
- AI provider clients (OpenAI, Anthropic) now use a bounded timeout and limited retries, so a stalled model call cannot hang an autonomous run.
- Injection phase caps endpoints (default 8, override with injection_max_urls) so it does not flood a live target.

## [0.17.0] - 2026-09-22

### Added
- Agent-driven --autonomous: the LLM agent now conducts the whole assessment via a new run_phase tool (recon, scanning, vuln, api, access-control, injection, browser, verification), findings stay evidence-anchored. Previously --autonomous ran the fixed pipeline plus AI triage.

## [0.16.0] - 2026-09-22

### Changed
- **License changed to AGPL-3.0-or-later** (was proprietary, no-derivatives). Sentari is now free software: you can use, study, modify, and share it, and a modified version distributed or run as a network service must offer its corresponding source under the same license. Updated `LICENSE`, `NOTICE`, `pyproject.toml`, the README, and every skill's license field, and added `CONTRIBUTING.md` (DCO sign-off).

## [0.15.0] - 2026-09-22

### Changed
- Offensive gates now allow authorized testing of production. The exploitation and post-exploitation confirmation string is now `I AM AUTHORIZED TO TEST THIS TARGET` (was the non-production wording), matching standard authorized pentest tooling. Scope, --authorized, the audit log, the per-run confirmation, and the evidence-first invariant are kept.

### Added
- `--autonomous`: one command runs the full pipeline including gated exploitation, AI-driven, authorized once at launch (needs --authorized, --no-safe-mode, and the confirmation string). Added an authorized-use disclaimer to the README.

## [0.14.0] - 2026-09-22

### Added
- **AI code-fix patches, applied only by explicit user action** (`patch.py`, `--suggest-patches`, `--patch-out`, `--apply-fixes`, `--apply-confirm`): for findings that map to a source location (for example from `--sast`), Sentari asks the AI for a minimal unified diff, validates it applies with `git apply --check`, and writes it to a patch file for the user to review and apply. `--apply-fixes` (with the exact `--apply-confirm` string) writes the validated patches into the working tree uncommitted, for review with `git diff`. It never commits or merges, and it never edits code without the confirmation. A path-traversal guard keeps proposed edits inside the repo.

## [0.13.0] - 2026-09-22

### Added
- **Interactive proxy tampering** (`--proxy-web`): launches mitmweb so requests and responses can be intercepted and edited live in a browser UI, while also capturing to the JSONL file.
- **Scriptable request tamper and replay** (`tamper.py`, `--tamper FILE`, `--set-header`, `--set-param`, `--set-body`): replays a captured request with overrides and shows a unified diff of the response against the original.
- **Parameter fuzzing** (`--fuzz-param`, `--fuzz-values`): sends one captured request through a list of values and reports the status/length of each response so a behavior change stands out.
- **Agent skills** (`skills/`): fourteen `SKILL.md` files in the open Agent Skills format (agentskills.io), one per capability area, so a coding agent can drive Sentari for pentesting, web and API testing, OWASP Top 10, network scanning, SAST, cloud audits, gated exploitation, AI-driven modes, retest and monitoring, reporting and dashboards, risk prioritization, CI gating, and remediation PRs.

## [0.12.0] - 2026-09-22

### Added
- **OS command injection (OOB-confirmed) and SSTI (math-confirmed)** in the injection phase: command injection is proven by a real callback to the listener; SSTI is proven when a template expression (7*7) is evaluated in the response.
- **Insecure-deserialization detection** (`deserial.py`): flags serialized objects (Java, PHP, Python pickle, Ruby Marshal) carried in URL parameters or cookies. Detection only; it builds no gadget.
- **Session fixation** (`sessionfix.py`, `--session-fixation`, `--login-data`, `--session-cookie`): checks whether the session id is reissued on login, using the supplied credentials.
- **Business-logic workflow testing** (`workflow.py`, `phases/workflow_phase.py`, `--workflow FILE`): replays an operator-defined request sequence with variable capture and flags steps that succeed when they should fail (workflow/authorization bypass, price/quantity tampering) or return an unexpected status.
- **Interactive sandbox shell** (`--shell`, `--shell-image`): opens a shell inside a disposable Docker container for exploit development.
- **Graph AI coordination**: with `--graph --ai`, the coordinator adds a grounded synthesis (prioritization and attack chains) over all findings across targets.

## [0.11.0] - 2026-09-22

### Added
- **SSRF and XXE, confirmed out-of-band** (`oob.py`, `injection.py`, `phases/injection.py`, `--injection`, `--oob-host`): Sentari runs its own listener and injects a unique URL that points back to it; a finding is raised only when the target actually calls back, so it is a real proof, not an inference. XXE (which POSTs XML) runs only outside safe mode.
- **NoSQL injection (differential)**: injects Mongo-style operators into existing parameters and flags a meaningful response change as a candidate.
- **Mass assignment (gated)**: POSTs privileged fields and flags acceptance/echo as a candidate; runs only outside safe mode.
- **Race-condition harness** (`--race-url`, `--race-count`, `--race-post`): fires concurrent requests and flags multiple successes on a should-be-once action.
- **Stored XSS** (`browser.py`): outside safe mode, the browser submits a payload through a form, reloads, and confirms execution, alongside the existing reflected/DOM XSS.
- **Fixed CI**: quoted the workflow step names containing a colon, which had made the YAML fail to parse.

## [0.10.0] - 2026-09-22

### Added
- **Broken access control / IDOR testing** (`accesscontrol.py`, `phases/accesscontrol.py`, `--access-control`, `--identity`, `--ac-url`): requests the protected URLs as several supplied identities and anonymously, then reports resources served without authentication or served identically to different users while anonymous access is refused (a horizontal-access/IDOR candidate). It only reports when responses actually match and the resource is non-trivial, and it sends ordinary GETs, so it changes nothing.

## [0.9.0] - 2026-09-22

### Added
- **Cloud misconfiguration audit** (`cloudaudit.py`, `phases/cloudaudit.py`, `--cloud-audit aws|azure|gcp|kubernetes`): runs Prowler against your own account and maps its failed checks (with severity, resource, region) to findings. Graceful without Prowler.
- **Custom PoC runtime** (`pocrunner.py`, `--poc SCRIPT`, `--poc-image`): runs operator-supplied Python proof-of-concepts against the target inside a disposable Docker container. A finding is recorded only when the PoC prints its own success marker (`SENTARI_POC_SUCCESS`); Sentari never decides on its own that an exploit worked. Gated with the other offensive features.
- **Graph of agents** (`graph.py`, `--graph`, `--graph-target`): specialized nodes (recon, assess, verify) run on one shared blackboard so later nodes see earlier discoveries, and several targets run in parallel with a cross-asset correlation pass. Every node runs the real phases; findings stay evidence-backed.
- `ToolRunner.run` gained `sandbox_wrap` so a command that already brings its own container (the PoC runner) is not double-wrapped.

## [0.8.0] - 2026-09-22

Strix-inspired coverage, built original and evidence-first.

### Added
- **JWT / API security** (`jwt_audit.py`, `phases/apitest.py`, `--api-tests`, `--jwt`): offline JWT auditing (alg=none, weak HMAC secret cracked from a wordlist, missing/expired exp, sensitive payload) plus read-only API checks (JWT seen in responses, unauthenticated access, no rate limiting, state-changing methods). Sends only GET/OPTIONS; no mutation.
- **Richer browser attacks** (`browser.py`): added DOM-based XSS and client-side prototype pollution, both confirmed by actual execution, plus clickjacking (missing X-Frame-Options / CSP frame-ancestors) and a token-less POST-form CSRF candidate, alongside the existing reflected-XSS check.
- **SAST** (`sast.py`, `phases/sast.py`, `--sast PATH`, `--sast-config`): runs semgrep over a source tree and maps results (with CWE/OWASP) to findings. Graceful without semgrep.
- **HTTP proxy capture** (`proxy.py`, `phases/proxy_ingest.py`, `--proxy PORT`, `--proxy-ingest FILE`): a mitmproxy addon records real traffic as JSONL; the analyzer (JSONL or HAR) reports JWT weaknesses, credentials/secrets sent in cleartext, and insecure cookies from the captured flows.

## [0.7.0] - 2026-09-22

### Added
- **API spec ingestion** (`openapi.py`, `--openapi SRC`, `--openapi-base-url`): reads an OpenAPI v3, Swagger v2, or Postman collection (file or URL) and turns the endpoints it describes into scan targets for nuclei and the browser phase. JSON via the standard library; YAML via the optional `api` extra. It reads the spec; it invents no endpoints.
- **Client-side DAST** (`browser.py`, `phases/browser.py`, `--browser`): drives a headless browser (Playwright) against the discovered URLs to find reflected XSS confirmed by actual execution (a unique payload must set a JS marker, a working proof rather than a reflection guess), password fields served over HTTP, and mixed content. Off by default; every finding carries the browser observation as evidence.
- **Docker exploit sandbox** (`sandbox.py`, `--sandbox`, `--sandbox-image`): the gated exploitation and post-exploitation tools can run inside a disposable `docker run --rm` container instead of on the host. It isolates where already-gated commands run; it does not change reporting or loosen any gate. The recorded evidence shows the actual `docker run ...` command.
- **Remediation guide and draft PR** (`autofix.py`, `--autofix FILE`, `--autofix-pr`, `--autofix-repo`): builds a Markdown fix guide from the real findings (and the grounded AI remediation when present) and can open it as a *draft* pull request via the GitHub CLI. Suggest-only: it never edits application code and never merges.
- **GitHub Action** (`action.yml`, `examples/github-action-usage.yml`): a composite action so a repository can run a Sentari assessment in CI, with an authorization gate and report artifacts.

## [0.6.0] - 2026-09-22

### Added
- **Nexpose / InsightVM connector** (`nexpose.py`, `--nexpose`): pulls a host's vulnerabilities from a Rapid7 console over the REST API (v3, `NEXPOSE_*` env) into the vuln phase as evidence-backed findings. Stdlib only, graceful when unconfigured. The OpenVAS and Nexpose paths now share one external-source handler.
- **Privilege-escalation enumeration** (`privesc.py`, `--privesc`): read-only SSH enumeration of a Linux host (NOPASSWD sudo, dangerous SUID binaries, writable `/etc/passwd`, readable `/etc/shadow`, dangerous capabilities, writable cron). Each command's output is the evidence; a vector is reported only when the output shows it. Runs inside the gated post-exploitation phase (needs paramiko). Changes nothing on the host.
- **AI-powered OSINT** (`ai/osint.py`, `--ai-osint`): the model proposes likely subdomain labels, then DNS confirms each one, so a subdomain is recorded only when it actually resolves. The model also writes a short analyst summary over the real discovered assets. Grounded: the model never asserts a host exists.
- **Executive dashboard**: the web dashboard now leads with KPI cards (runs, findings, critical/high, known-exploited, targets), a severity distribution chart, a findings-over-time trend, a risk prioritization matrix, and OWASP compliance coverage, all as inline SVG with no external scripts. The single-run view gains CVSS, known-exploited, and business-impact chips.

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
