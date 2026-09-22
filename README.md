# Sentari

**Evidence-grounded, authorized security assessment.**

Sentari orchestrates real security tools and reports **only what they actually
found**. Its one non-negotiable rule:

> A finding may exist only if it is backed by **evidence**: the real output of a
> real command that actually ran. No hardcoded results. No LLM-invented
> vulnerabilities.

Every finding cites the exact command, its output, exit code and timing. If a
tool didn't observe it, Sentari won't claim it: and that guarantee is enforced
in code (a `Finding` cannot be constructed without evidence) and even extends to
the AI layer (invented references are dropped).

## Features

- **6-phase methodology**: recon, scanning/enumeration, vulnerability
  assessment, safe verification, reporting, retest. All real.
- **Reconnaissance**: DNS, port/service discovery (built-in TCP scan + `nmap`),
  web fingerprint.
- **Scanning**: HTTP security headers, TLS (incl. legacy-TLS handshake tests),
  version disclosure, content discovery (`gobuster`/`ffuf` or built-in probe).
- **Vulnerability assessment**: `nuclei` templates; gated `sqlmap`.
- **Verification**: read-only, non-destructive confirmation of findings
  (gated behind `--no-safe-mode`); retrieved secrets are redacted.
- **Grounded AI triage**: multi-provider (OpenAI, Anthropic, Google, OpenRouter,
  Ollama); prioritizes / correlates / remediates over *real* findings only.
- **Compliance mapping**: tags findings to OWASP Top 10, CWE, and NIST 800-53.
- **Reporting**: self-contained, evidence-linked HTML + JSON.
- **Retest**: diff a fresh scan against a prior run (file or DB baseline).
- **Persistence**: SQLite by default; optional Postgres.
- **Web dashboard + REST API**: read-only, localhost by default (stdlib).
- **Distributed**: optional Celery workers; Docker image, Compose stack, and
  Kubernetes manifests.
- **Authorization + audit**: enforced scope allowlist, explicit attestation,
  append-only audit log.

The **core runs on the Python standard library alone**: external tools and
`celery`/`redis`/`psycopg2` are optional enrichment.

## Authorization (required)

Sentari runs real offensive tooling. It refuses to act unless (1) the target
falls within a declared `--scope`, **and** (2) you attest with `--authorized`.
Use it only against systems you own or have explicit written permission to test.

## Usage

```bash
# full assessment + reports
python -m sentari example.com --scope example.com --authorized \
    --html report.html --json report.json

# with grounded AI triage (needs a provider key, e.g. OPENAI_API_KEY)
python -m sentari example.com --scope example.com --authorized --ai

# scope by CIDR, persist to a DB, then retest against the last stored run
python -m sentari 10.0.0.5 --scope 10.0.0.0/24 --authorized --db runs.db
python -m sentari 10.0.0.5 --scope 10.0.0.0/24 --authorized --db runs.db --retest-latest

# read-only web dashboard over saved runs
python -m sentari --serve --db runs.db            # http://127.0.0.1:8600

# read-only verification (gated) + list phases
python -m sentari example.com --scope example.com --authorized --no-safe-mode
python -m sentari --list-phases
```

Distributed execution (Celery workers + dashboard) is covered in
[`deploy/README.md`](deploy/README.md) (Docker Compose and Kubernetes).

## Tests

```bash
python -m unittest discover -s tests -v      # zero dependencies
# or, if you have pytest:  pytest -q
```

## License

Proprietary, no-derivatives: see [LICENSE](LICENSE) and [NOTICE](NOTICE). You
may use and share verbatim copies; you may not modify, create derivatives, or
redistribute modified versions.
