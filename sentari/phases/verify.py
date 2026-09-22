"""Phase 4: Verification (safe exploitation).

Confirms selected findings with READ-ONLY, non-destructive proof: nothing is
written, modified, brute-forced, or weaponized. It upgrades confidence by
fetching the resource a prior phase flagged and checking it really is what we
think it is (e.g. an exposed /.git/config that actually contains git config).

Hard rules:
  * Gated: does nothing unless safe mode is OFF (--no-safe-mode).
  * Read-only: HTTP GET only, and only against locations already discovered.
  * Redacts secrets it retrieves (e.g. masks .env values) before storing them.
  * Every verification is recorded as evidence and to the audit log via the runner.
"""
from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.request

from ..models import Finding, PhaseResult, Severity
from .base import Phase, PhaseContext

# path signature -> (regex the body must match to confirm, is it a secret to redact)
_SIGNATURES = [
    ("/.git/config", re.compile(r"\[core\]", re.I), False),
    ("/.git/HEAD", re.compile(r"^ref:\s", re.I | re.M), False),
    ("/.env", re.compile(r"^\s*[A-Z0-9_]+\s*=", re.M), True),
    # .svn/entries starts with a bare format-number line; a catch-all HTML page
    # will not, so this avoids confirming an app's fallback page as an exposure.
    ("/.svn/entries", re.compile(r"^\d+\s*$", re.M), False),
    ("/.DS_Store", re.compile(r"Bud1|\x00\x00\x00", re.S), False),
]


def _fetch_body(url: str, limit: int = 2048) -> tuple[int, str, str]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Sentari/0.1"})
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=8, context=sslctx) as resp:
            return resp.status, resp.read(limit).decode("utf-8", "replace"), ""
    except urllib.error.HTTPError as e:
        return e.code, "", ""
    except Exception as e:
        return -1, "", str(e)


def _redact(body: str) -> str:
    # mask the value side of KEY=VALUE lines so secrets never land in a report
    return re.sub(r"(?m)^(\s*[A-Za-z0-9_]+\s*=).*$", r"\1***REDACTED***", body)


class VerifyPhase(Phase):
    name = "verification"
    number = 4
    description = "Safe verification: read-only confirmation of findings (gated)"

    def execute(self, ctx: PhaseContext, result: PhaseResult) -> None:
        if ctx.safe_mode:
            result.notes.append(
                "Verification skipped: safe mode is on. Re-run with --no-safe-mode "
                "to enable READ-ONLY confirmation of findings.")
            return

        prior = ctx.shared.get("prior_findings", [])
        # only verify findings that point at a concrete, fetchable location
        candidates = [
            f for f in prior
            if f.title.startswith("Sensitive path reachable") and f.location
        ]
        if not candidates:
            result.notes.append("No findings eligible for read-only verification.")
            return

        for f in candidates:
            url = f.location
            sig = next((s for s in _SIGNATURES if s[0] in url), None)
            t0 = time.monotonic()
            status, body, err = _fetch_body(url)
            dur = round(time.monotonic() - t0, 3)
            if status != 200 or not body:
                ctx.runner.record_internal(["verify-get", url], 1,
                                           f"HTTP {status}", err, dur)
                result.notes.append(f"Could not confirm {url} (HTTP {status}).")
                continue

            confirmed = bool(sig and sig[1].search(body))
            is_secret = bool(sig and sig[2])
            proof = _redact(body) if is_secret else body
            proof = proof[:1200]
            ev = ctx.runner.record_internal(["verify-get", url], 0, proof, duration_sec=dur)

            if confirmed:
                # exposed VCS/secret material confirmed by content -> escalate
                sev = Severity.CRITICAL if is_secret else Severity.HIGH
                result.findings.append(Finding(
                    title=f"CONFIRMED exposure: {url}", severity=sev,
                    description=(f"Read-only fetch of {url} returned content matching a known "
                                 f"sensitive-file signature: the exposure is real, not a false positive."
                                 + (" Secret values redacted in evidence." if is_secret else "")),
                    evidence_ids=[ev.id], target=ctx.target, phase=self.name, location=url,
                    recommendation="Remove the exposed resource and block access to the path.",
                    metadata={"verified": True, "verifies_finding": f.id},
                ))
            else:
                result.notes.append(
                    f"{url} returned 200 but content did not match a sensitive-file "
                    f"signature: left as reported, not escalated.")
