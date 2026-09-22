# Sentari

Evidence-grounded, authorized security assessment.

Sentari runs real security tools and reports only what they actually found. Its core rule: a finding may exist only if a real command produced evidence for it. It does not use hardcoded results or vulnerabilities invented by an LLM.

Every finding cites the command that produced it, its output, exit code, and timing. If no tool observed something, Sentari does not report it. This is enforced in the code: a `Finding` cannot be constructed without evidence, and the AI layer discards any reference to a finding that does not exist.

## Features

- **6-phase methodology**: recon, scanning/enumeration, vulnerability assessment, safe verification, reporting, and retest.
- **Reconnaissance**: DNS, port and service discovery (built-in TCP scan plus `nmap`), web fingerprint.
- **Scanning**: HTTP security headers, TLS (including legacy-TLS handshake tests), version disclosure, content discovery (`gobuster`/`ffuf`, or a built-in probe).
- **Vulnerability assessment**: `nuclei` templates, and `sqlmap` behind a gate.
- **Verification**: read-only, non-destructive confirmation of findings (behind `--no-safe-mode`); retrieved secrets are redacted.
- **AI triage**: multi-provider (OpenAI, Anthropic, Google, OpenRouter, Ollama). It prioritizes and correlates the real findings and suggests fixes, and it works only from those findings.
- **Compliance mapping**: tags findings with OWASP Top 10, CWE, and NIST 800-53 references.
- **Reporting**: self-contained HTML plus JSON, with each finding linked to its evidence.
- **Retest**: diff a fresh scan against a prior run (a file or a DB baseline).
- **Persistence**: SQLite by default, Postgres optionally.
- **Web dashboard and REST API**: read-only, bound to localhost by default, standard library only.
- **Distributed execution**: optional Celery workers, plus a Docker image, Compose stack, and Kubernetes manifests.
- **Authorization and audit**: an enforced scope allowlist, explicit attestation, and an append-only audit log.

The core runs on the Python standard library. The external tools and `celery`/`redis`/`psycopg2` are optional.

## Authorization (required)

Sentari runs real offensive tooling. It will not act unless the target falls within a declared `--scope` and you attest with `--authorized`. Use it only against systems you own or have written permission to test.

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

Distributed execution (Celery workers plus the dashboard) is described in [`deploy/README.md`](deploy/README.md), covering Docker Compose and Kubernetes.

## Tests

```bash
python -m unittest discover -s tests -v      # zero dependencies
# or, if you have pytest:  pytest -q
```

## License

Proprietary, no-derivatives. See [LICENSE](LICENSE) and [NOTICE](NOTICE). You may use and share verbatim copies. You may not modify it, create derivatives, or redistribute modified versions.
