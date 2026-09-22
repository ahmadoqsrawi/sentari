# Sentari

Evidence-grounded, authorized security assessment from the command line.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-proprietary-lightgrey.svg)](LICENSE)
[![CI](https://github.com/ahmadoqsrawi/sentari/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)

Sentari runs real security tools and reports only what they actually found. A finding exists only when a real command produced evidence for it. There are no hardcoded results and nothing invented by a language model. Every finding cites the command that produced it, its output, exit code, and timing.

The guarantee is enforced in the code: a `Finding` cannot be created without evidence, and the AI triage step discards any reference to a finding that does not exist.

## Why use it

- You get an assessment you can audit. Each result points back to the exact command and output behind it.
- The core needs only the Python standard library, so it runs anywhere Python does. External scanners and services are optional add-ons.
- It refuses to run outside an authorized scope, and it logs every run.

## Requirements

- Python 3.9 or newer (the core has no other dependencies).
- Optional scanners for deeper coverage: `nmap`, `nuclei`, `nikto`, `gobuster`/`ffuf`, `sqlmap`. Sentari uses each when present and reports it as missing otherwise.
- Optional Python extras: `ai` (OpenAI/Anthropic), `distributed` (Celery + Redis), `postgres`.

## Installation

Sentari is not on PyPI yet. Install it from source:

```bash
git clone https://github.com/ahmadoqsrawi/sentari.git
cd sentari
pip install .
```

Verify it:

```bash
sentari --version
# or, without installing:
python -m sentari --version
```

Optional extras:

```bash
pip install ".[ai]"           # OpenAI / Anthropic providers
pip install ".[distributed]"  # Celery workers + Redis
pip install ".[postgres]"     # Postgres run store
```

## Usage

```bash
sentari <target> --scope <target> --authorized [options]
```

Sentari will not act unless the target is inside a declared `--scope` and you pass `--authorized`. Use it only against systems you own or have written permission to test.

## Phases

Sentari follows a six-phase methodology. Phases 1 to 4 run tools; reporting and retest are output steps.

| # | Phase | What it does |
|---|-------|--------------|
| 1 | Reconnaissance | DNS resolution, port and service discovery (built-in TCP scan plus `nmap`), web fingerprint |
| 2 | Scanning | HTTP security headers, TLS checks (including legacy-TLS handshakes), version disclosure, content discovery |
| 3 | Vulnerability assessment | `nuclei` templates, and `sqlmap` behind a gate |
| 4 | Verification | Read-only confirmation of findings; retrieved secrets are redacted |
| 5 | Reporting | Evidence-linked HTML and JSON |
| 6 | Retest | Diff a fresh scan against a prior run |

List them at any time:

```bash
sentari --list-phases
```

## Options

| Option | Description |
|--------|-------------|
| `--scope HOST` (or CIDR) | Authorized target(s). Repeatable. Required. |
| `--authorized` | Attest you have permission to test the target. Required. |
| `--phases NAMES` | Comma-separated phase names, or `all` (default). |
| `--no-safe-mode` | Allow the gated, read-only verification checks. |
| `--html FILE` / `--json FILE` | Write the report to a file. |
| `--db DSN` | Persist runs to SQLite (a path) or Postgres (a `postgres://` URL). |
| `--retest FILE` / `--retest-latest` | Diff against a prior run (a file, or the last run in `--db`). |
| `--ai` | Grounded AI triage of the findings. |
| `--ai-provider` / `--ai-model` / `--ai-base-url` | Choose the provider and model. |
| `--serve` | Start the read-only web dashboard instead of scanning. |
| `--enqueue` | Send the scan to a Celery worker. |
| `--dry-run` | Show what would run without executing anything. |

## Examples

Full assessment with both report formats:

```bash
sentari example.com --scope example.com --authorized \
    --html report.html --json report.json
```

Add grounded AI triage (needs a provider key, e.g. `OPENAI_API_KEY`):

```bash
sentari example.com --scope example.com --authorized --ai
```

Scope by CIDR, save to a database, then retest against the last stored run:

```bash
sentari 10.0.0.5 --scope 10.0.0.0/24 --authorized --db runs.db
sentari 10.0.0.5 --scope 10.0.0.0/24 --authorized --db runs.db --retest-latest
```

Browse saved runs in the read-only dashboard:

```bash
sentari --serve --db runs.db     # http://127.0.0.1:8600
```

## Configuration

AI triage reads its key from the environment (or the matching `--ai-*` flags):

```bash
export OPENAI_API_KEY=...        # or ANTHROPIC_API_KEY, etc.
export SENTARI_PROVIDER=openai   # optional; default provider
export SENTARI_MODEL=gpt-4o      # optional; default model
```

## Web dashboard and distributed runs

The dashboard is read-only and binds to `127.0.0.1` by default. It shows completed runs and never starts a scan. For a Celery worker pool plus the dashboard behind Redis and Postgres, see [`deploy/README.md`](deploy/README.md), which covers Docker Compose and Kubernetes.

## Documentation

Architecture documentation (C4 model, with diagrams) is in [`docs/`](docs/): an overview, the architecture and workflow, per-domain deep dives, boundary interfaces, and a database overview.

## Testing

```bash
python -m unittest discover -s tests -v      # no dependencies
# or, with pytest:
pip install ".[dev]" && pytest -q
```

## Authorization

Sentari runs real offensive tooling. It enforces authorization at runtime: it refuses to run unless the target is within a declared `--scope` and you attest with `--authorized`, and it records every run in an append-only audit log. See [SECURITY.md](SECURITY.md).

## License

Proprietary, no-derivatives. See [LICENSE](LICENSE) and [NOTICE](NOTICE). You may use and share verbatim copies. You may not modify it, create derivatives, or redistribute modified versions.
