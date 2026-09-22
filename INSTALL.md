# Installing Sentari

This guide is written for a first-time user. Follow it top to bottom and you will
have a working install and your first scan.

## TL;DR (the minimum)

Sentari's core needs only **Python 3.9 or newer**. Nothing else is required to
run a real scan.

```bash
git clone https://github.com/ahmadoqsrawi/sentari.git
cd sentari
python3 -m venv .venv && source .venv/bin/activate   # recommended
pip install .
sentari --version
```

First scan against a host you own or are allowed to test:

```bash
sentari 127.0.0.1 --scope 127.0.0.1 --authorized
```

That is it. Everything below is optional and only needed for specific features.

---

## What is required vs optional

| Thing | Required? | You need it for |
|---|---|---|
| Python 3.9+ | **Required** | everything |
| `git` | Recommended | cloning the repo (or download the zip) |
| A virtual environment (`venv`) | Recommended | keeping the install clean |
| Optional Python extras (below) | Optional | AI, browser testing, cloud, PDF, and so on |
| Optional external tools (below) | Optional | deeper scanning (nmap, nuclei, ...) |
| Docker | Optional | the sandbox, PoC runtime, and interactive shell |
| GitHub CLI (`gh`) | Optional | opening remediation pull requests |

The rule of thumb: **install the core, then add only the extra for the feature
you actually want.** If a tool is missing, Sentari says so and skips that part.
It never invents results to fill the gap.

---

## Step by step (Ubuntu / Debian)

1. **Check Python:**
   ```bash
   python3 --version        # need 3.9 or newer
   ```

2. **Make sure pip and venv are available** (some minimal systems lack them):
   ```bash
   sudo apt update && sudo apt install -y python3-pip python3-venv git
   ```

3. **Get the code and install the core:**
   ```bash
   git clone https://github.com/ahmadoqsrawi/sentari.git
   cd sentari
   python3 -m venv .venv && source .venv/bin/activate
   pip install .
   ```

4. **Verify:**
   ```bash
   sentari --version
   sentari --list-phases
   ```

5. **Run your first scan** (a target you own or are authorized to test):
   ```bash
   sentari https://staging.example.com --scope staging.example.com --authorized --html report.html
   ```

Open `report.html` in a browser to see the findings, each linked to its evidence.

> Note: after opening a new terminal, run `source .venv/bin/activate` again, or
> call Sentari by its full path `./.venv/bin/sentari`.

---

## Optional Python extras (install only what you need)

Install one or more like this:

```bash
pip install ".[ai]"                 # one extra
pip install ".[ai,browser,api]"     # several at once
```

| Extra | Command | Enables |
|---|---|---|
| `ai` | `pip install ".[ai]"` | AI triage, autopilot, agent, and OpenAI/Anthropic providers (`--ai`, `--autopilot`, `--agent`) |
| `browser` | `pip install ".[browser]"` then `playwright install chromium` | client-side DAST: reflected/DOM/stored XSS, clickjacking, CSRF (`--browser`) |
| `api` | `pip install ".[api]"` | reading **YAML** OpenAPI/Swagger specs (`--openapi file.yaml`); JSON specs work without it |
| `pdf` | `pip install ".[pdf]"` | PDF reports (`--pdf report.pdf`) |
| `cloud` | `pip install ".[cloud]"` | cloud asset discovery (`--cloud aws|azure|gcp`); needs credentials, see [Cloud setup](#cloud-setup-aws--azure--gcp) |
| `cloud-audit` | `pip install ".[cloud-audit]"` | Prowler misconfiguration audit (`--cloud-audit aws|azure|gcp|kubernetes`); see [Cloud setup](#cloud-setup-aws--azure--gcp) |
| `openvas` | `pip install ".[openvas]"` | pulling results from a Greenbone/OpenVAS console (`--openvas`) |
| `privesc` | `pip install ".[privesc]"` | SSH privilege-escalation enumeration (`--privesc`) |
| `proxy` | `pip install ".[proxy]"` | HTTP capture and live tampering (`--proxy`, `--proxy-web`) |
| `distributed` | `pip install ".[distributed]"` | Celery workers and scheduled retests (`--enqueue`) |
| `postgres` | `pip install ".[postgres]"` | storing runs in Postgres instead of SQLite (`--db postgres://...`) |
| `dev` | `pip install ".[dev]"` | running the test suite with pytest |

Want everything at once:

```bash
pip install ".[ai,browser,api,pdf,cloud,cloud-audit,openvas,privesc,proxy,distributed,postgres]"
playwright install chromium
```

---

## Optional external tools (system packages)

Sentari uses these when they are on your PATH and reports them as missing
otherwise. Install the ones matching what you want to test.

| Tool | Install (Ubuntu) | Enables |
|---|---|---|
| `nmap` | `sudo apt install -y nmap` | richer port/service discovery in recon |
| `nuclei` | from ProjectDiscovery | the main vulnerability template scan (vuln phase) |
| `subfinder`, `amass`, `theHarvester` | package or ProjectDiscovery | OSINT subdomain enumeration |
| `httpx`, `naabu` | ProjectDiscovery | faster web fingerprint and port discovery |
| `sqlmap` | `sudo apt install -y sqlmap` | gated SQL injection testing (`--sqlmap-url`) |
| `gobuster` or `ffuf` | `sudo apt install -y gobuster ffuf` | content discovery |
| `semgrep` | `pip install semgrep` | static code analysis (`--sast`) |
| `mitmproxy` | comes with the `proxy` extra | HTTP capture / live tamper |
| `prowler` | `pip install prowler` | cloud misconfiguration audit |
| `msfconsole` (Metasploit) | Metasploit installer | gated exploitation modules (`--exploit`) |
| CrackMapExec, bloodhound-python | pip / package | gated post-exploitation (`--postexploit`) |

### Docker (for the sandbox, PoC runtime, and shell)

Only needed for `--sandbox`, `--poc`, and `--shell`:

```bash
sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"     # then log out and back in
docker run --rm hello-world         # verify
```

### GitHub CLI (for remediation PRs)

Only needed for `--autofix-pr`:

```bash
sudo apt install -y gh
gh auth login
```

---

## Cloud setup (AWS / Azure / GCP)

Sentari has two cloud features, and both use **your own cloud credentials against
your own account**. They enumerate and audit; they do not attack anything.

- `--cloud aws|azure|gcp` lists internet-facing assets so you can bring the ones
  you own into scope. Install `pip install ".[cloud]"`.
- `--cloud-audit aws|azure|gcp|kubernetes` runs a Prowler misconfiguration audit.
  Install `pip install prowler`.

Each provider needs its normal credentials in the environment:

**AWS** uses the standard boto3 credential chain:

```bash
pip install ".[cloud]"
aws configure                # or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_PROFILE
sentari --cloud aws
```

**Azure** needs a subscription id plus a login (via `az login`, a managed
identity, or the `AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_CLIENT_SECRET`
service-principal variables):

```bash
pip install ".[cloud]"
az login                                       # or set the service-principal vars
export AZURE_SUBSCRIPTION_ID="<your-subscription-id>"
sentari --cloud azure
```

**GCP** needs a project id and application-default credentials (a service-account
key file, or `gcloud auth application-default login`):

```bash
pip install ".[cloud]"
export GOOGLE_CLOUD_PROJECT="<your-project-id>"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"   # or: gcloud auth application-default login
sentari --cloud gcp
```

If a credential or env var is missing, Sentari prints exactly what to set (for
example `set AZURE_SUBSCRIPTION_ID`) rather than failing silently.

---

## Integrations and configuration

Each integration below is optional and configured through environment variables
or flags. If something is not set up, Sentari reports it and skips that part.

### AI providers (`--ai`, `--autopilot`, `--agent`, `--graph --ai`, `--ai-osint`)

Install the extra and set the provider's API key, then select it with
`--ai-provider` / `--ai-model` (or the `SENTARI_PROVIDER` / `SENTARI_MODEL`
defaults). See known ids with `sentari --list-models`.

```bash
pip install ".[ai]"
export OPENAI_API_KEY="sk-..."
sentari https://app.example.com --scope app.example.com --authorized --ai --ai-provider openai
```

| Provider (`--ai-provider`) | API key env var |
|---|---|
| openai | `OPENAI_API_KEY` |
| anthropic | `ANTHROPIC_API_KEY` |
| google | `GOOGLE_API_KEY` |
| openrouter | `OPENROUTER_API_KEY` |
| deepseek | `DEEPSEEK_API_KEY` |
| groq | `GROQ_API_KEY` |
| mistral | `MISTRAL_API_KEY` |
| xai | `XAI_API_KEY` |
| together | `TOGETHER_API_KEY` |
| fireworks | `FIREWORKS_API_KEY` |
| perplexity | `PERPLEXITY_API_KEY` |
| glm | `GLM_API_KEY` |
| nvidia | `NVIDIA_API_KEY` |
| ollama (local) | none; runs at `http://localhost:11434` |

For a self-hosted or OpenAI-compatible gateway, point at it with `--ai-base-url`.

### OSINT and Shodan (`--phases osint`, `--ai-osint`)

Put `subfinder`, `amass`, or `theHarvester` on PATH for subdomain enumeration.
Shodan host lookups need an API key:

```bash
export SHODAN_API_KEY="..."
sentari example.com --scope example.com --authorized --phases osint
```

### External vulnerability scanners

**OpenVAS / Greenbone** (`--openvas`):

```bash
pip install ".[openvas]"
export GVM_HOST=greenbone.example.com GVM_PORT=9390 GVM_USER=admin GVM_PASS=secret
sentari https://app.example.com --scope app.example.com --authorized --openvas
```

**Nexpose / InsightVM** (`--nexpose`, uses the REST API, no extra needed):

```bash
export NEXPOSE_HOST=insightvm.example.com NEXPOSE_PORT=3780 NEXPOSE_USER=admin NEXPOSE_PASS=secret
# self-signed console certs are accepted by default; set NEXPOSE_VERIFY_TLS=1 to require a valid cert
sentari https://app.example.com --scope app.example.com --authorized --nexpose
```

### SIEM export (`--siem-url`, `--siem-type`)

Ship findings to a SIEM. The token can be passed with `--siem-token` or the
`SENTARI_SIEM_TOKEN` env var.

```bash
# Splunk HTTP Event Collector
sentari URL --scope HOST --authorized --siem-type splunk --siem-url https://splunk.example.com:8088 --siem-token "$HEC_TOKEN"
# Elasticsearch
sentari URL --scope HOST --authorized --siem-type elasticsearch --siem-url https://es.example.com:9200/sentari/_doc
# syslog (host:port)
sentari URL --scope HOST --authorized --siem-type syslog --siem-url syslog.example.com:514
# generic webhook
sentari URL --scope HOST --authorized --siem-type webhook --siem-url https://hooks.example.com/ingest
```

### Distributed runs and scheduled retests (Celery)

```bash
pip install ".[distributed]"
export SENTARI_BROKER_URL="redis://localhost:6379/0"     # or REDIS_URL
export SENTARI_RESULT_BACKEND="redis://localhost:6379/1" # optional
celery -A sentari.tasks worker            # start a worker
sentari URL --scope HOST --authorized --enqueue --db sentari.db   # dispatch a scan
```

Scheduled retests run through Celery beat, configured with environment variables:

```bash
export SENTARI_SCHEDULE_TARGET="https://app.example.com"
export SENTARI_SCHEDULE_SCOPE="app.example.com"
export SENTARI_SCHEDULE_DB="postgres://user:pass@localhost/sentari"
export SENTARI_SCHEDULE_CRON="0 3 * * *"   # daily at 03:00
celery -A sentari.tasks beat
```

Or bring up the whole stack (app, worker, beat, Redis, Postgres, Prometheus,
Grafana) with `docker-compose up -d` (needs `POSTGRES_PASSWORD` and
`REDIS_PASSWORD` in a `.env` file).

### Database (SQLite or Postgres)

```bash
sentari URL --scope HOST --authorized --db sentari.db                 # SQLite (default, no extra)
pip install ".[postgres]"
sentari URL --scope HOST --authorized --db "postgres://user:pass@localhost/sentari"
```

### Dashboard and metrics

```bash
sentari --serve --db sentari.db          # read-only dashboard on http://127.0.0.1:8600
# Prometheus metrics are exposed at /metrics on the dashboard; a Grafana
# dashboard ships under deploy/grafana/.
```

---

## "I just want to do X" quick picks

| Goal | Install | Run |
|---|---|---|
| A basic scan | core only | `sentari URL --scope HOST --authorized --html report.html` |
| Real web-app testing | `nuclei` + `pip install ".[browser]"` + `playwright install chromium` | add `--browser` |
| API testing from a spec | core (+ `".[api]"` for YAML) | add `--openapi spec.json --api-tests` |
| AI triage of findings | `pip install ".[ai]"` + a provider key | add `--ai --ai-provider openai` |
| Static code scan | `pip install semgrep` | `--sast ./code` |
| Cloud posture check | `pip install ".[cloud]"` + creds ([Cloud setup](#cloud-setup-aws--azure--gcp)) | `--cloud azure` or `--cloud-audit aws` |
| Full autonomous run | the above + `--no-safe-mode` | `--autonomous --exploit-confirm "I AM AUTHORIZED TO TEST THIS TARGET"` |

---

## Troubleshooting

- **`sentari: command not found`** after opening a new terminal: activate the
  venv again (`source .venv/bin/activate`) or use `./.venv/bin/sentari`.
- **`No module named pip`**: install it with `sudo apt install -y python3-pip`,
  or bootstrap it with `python3 -m ensurepip --upgrade`.
- **`error: a target is required`**: pass a target plus `--scope` and
  `--authorized`.
- **A phase says a tool is "not installed"**: that is expected. Install the tool
  from the tables above to enable that phase, or ignore it.
- **Docker "permission denied"**: you were added to the `docker` group but have
  not started a fresh login yet. Log out and back in, then retry.

## Authorization

Only run Sentari against systems you own or have explicit, written permission to
test, and stay within the agreed scope. You are responsible for authorization
and for complying with the law. See the README's authorization section.
