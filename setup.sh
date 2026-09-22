#!/usr/bin/env bash
#
# Sentari full setup: installs and verifies the three optional capabilities that
# need system packages, plus a Python environment for Sentari itself.
#
#   1. Docker            -> the --sandbox exploit isolation
#   2. Playwright        -> the --browser client-side DAST
#   3. GitHub CLI (gh)   -> the --autofix-pr draft pull requests
#
# Run it as your normal user (NOT root); it uses sudo only where needed and will
# ask for your password once. Debian/Ubuntu only.
#
#   cd ~/Downloads/sentari && ./setup.sh
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$REPO_DIR/.venv"
USER_NAME="${SUDO_USER:-$USER}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m  ok\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  !!\033[0m %s\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

if [ "$(id -u)" = "0" ]; then
  echo "Run this as your normal user, not root (it calls sudo itself)." >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "This script targets Debian/Ubuntu (apt). Install the pieces manually elsewhere." >&2
  exit 1
fi

bold "Sentari setup starting (user: $USER_NAME, repo: $REPO_DIR)"
sudo -v   # prime sudo once

# ----------------------------------------------------------------------------
step "Base packages (python venv, curl, group tools)"
sudo apt-get update -qq
sudo apt-get install -y python3-venv python3-full ca-certificates curl gnupg util-linux-extra
ok "base packages installed"

# ----------------------------------------------------------------------------
step "1/3  Docker (for --sandbox)"
if command -v docker >/dev/null 2>&1; then
  ok "docker already installed: $(docker --version)"
else
  # docker.io is the reliable choice on current Ubuntu releases.
  sudo apt-get install -y docker.io
  ok "installed docker.io"
fi
sudo systemctl enable --now docker
if id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx docker; then
  ok "$USER_NAME already in the docker group"
else
  sudo usermod -aG docker "$USER_NAME"
  warn "added $USER_NAME to the docker group: a REBOOT (or full logout) is required for it to take effect"
fi
# pre-pull a tiny image so the sandbox has something to run immediately
sudo docker pull alpine:latest >/dev/null 2>&1 && ok "pulled alpine:latest" || warn "could not pre-pull alpine"

# ----------------------------------------------------------------------------
step "2/3  GitHub CLI (for --autofix-pr)"
if command -v gh >/dev/null 2>&1; then
  ok "gh already installed: $(gh --version | head -1)"
else
  sudo mkdir -p -m 755 /etc/apt/keyrings
  wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
  sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y gh
  ok "installed gh"
fi
if gh auth status >/dev/null 2>&1; then
  ok "gh is already authenticated"
else
  warn "gh is not authenticated yet: run 'gh auth login' (or export GH_TOKEN) before using --autofix-pr"
fi

# ----------------------------------------------------------------------------
step "3/3  Python env + Sentari + Playwright (for --browser)"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
  ok "created venv at $VENV"
else
  ok "venv already exists at $VENV"
fi
"$VENV/bin/python" -m pip install -q --upgrade pip
# Sentari core is stdlib-only; install it editable with the browser + API extras.
"$VENV/bin/pip" install -q -e "$REPO_DIR[browser,api]"
ok "installed sentari (with browser, api extras)"
# Chromium browser binary + its system libraries.
sudo "$VENV/bin/playwright" install-deps chromium
"$VENV/bin/playwright" install chromium
ok "installed Chromium for Playwright"

# ----------------------------------------------------------------------------
step "Verification"
FAIL=0

# Docker: use sg to borrow the docker group so we can verify without a reboot.
if sg docker -c "docker run --rm alpine:latest echo sandbox-ok" 2>/dev/null | grep -q sandbox-ok; then
  ok "docker runs containers as $USER_NAME"
  if sg docker -c "PYTHONPATH='$REPO_DIR' '$VENV/bin/python' - <<'PY'
from sentari.runner import ToolRunner
from sentari.sandbox import Sandbox
ev = ToolRunner(sandbox=Sandbox(image='alpine:latest')).run(['sh','-c','echo inside-container-\$(hostname)'], tool='echo')
print(ev.stdout.strip())
PY" 2>/dev/null | grep -q inside-container; then
    ok "Sentari sandbox executes inside a real container"
  else
    warn "Sentari sandbox check did not confirm (see errors above)"; FAIL=1
  fi
else
  warn "docker not usable yet as your user: REBOOT, then re-run this script's verification"; FAIL=1
fi

# gh
command -v gh >/dev/null 2>&1 && ok "gh present ($(gh --version | head -1))" || { warn "gh missing"; FAIL=1; }

# Playwright / browser module
if PYTHONPATH="$REPO_DIR" "$VENV/bin/python" -c "from sentari import browser; import sys; sys.exit(0 if browser.available() else 1)"; then
  ok "Playwright available to Sentari"
else
  warn "Playwright not importable"; FAIL=1
fi

# ----------------------------------------------------------------------------
step "Done"
bold "Use the venv for Sentari, e.g.:"
echo "  $VENV/bin/sentari <target> --scope <target> --authorized --browser"
echo "  $VENV/bin/sentari <lab-target> --scope <lab> --authorized --no-safe-mode --exploit --sandbox \\"
echo "      --exploit-module <msf/module> --exploit-confirm \"I AM AUTHORIZED AND THIS IS NOT PRODUCTION\""
echo "  $VENV/bin/sentari <target> --scope <target> --authorized --autofix-pr --autofix-repo /path/to/repo"
echo
if id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx docker && ! id -nG | tr ' ' '\n' | grep -qx docker; then
  warn "You are in the docker group but this shell is not: REBOOT (or full logout) so every process picks it up."
fi
[ "$FAIL" = "0" ] && bold "All three capabilities verified." || warn "Some checks did not pass; see the notes above (a reboot fixes the docker-group one)."
