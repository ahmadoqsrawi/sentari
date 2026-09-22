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
