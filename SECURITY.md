# Security Policy

## Authorized use only

Sentari executes **real** offensive security tools. Use it **only** against
systems that you own or for which you hold **explicit, written authorization**.
The tool enforces this at runtime: it refuses to run unless the target is within
a declared `--scope` and you attest authorization with `--authorized`, and it
writes every run to an append-only audit log.

You are solely responsible for:

- obtaining proper authorization before any assessment,
- complying with all applicable laws and regulations, and
- respecting privacy and data-protection obligations for any data encountered.

Unauthorized use is prohibited (see `LICENSE`).

## Safe defaults

- **Safe mode is on by default.** Intrusive/verification actions require
  `--no-safe-mode`, and the verification phase performs only read-only checks.
- The web dashboard is **read-only** and binds to `127.0.0.1` by default; it
  never triggers scans. Do not expose it publicly without an authenticated proxy.
- Secrets retrieved during verification (e.g. `.env` values) are **redacted**
  before they are stored in evidence or reports.

## Reporting a vulnerability in Sentari itself

If you find a security issue in Sentari's own code, please report it privately:

- Email: **contact@ahmadoqsrawi.com**
- Do **not** open a public issue for undisclosed vulnerabilities.

Please include a description, affected version/commit, and reproduction steps.
You can expect an acknowledgement within a reasonable time, and coordinated
disclosure once a fix is available.

## Supported versions

The latest release on `main` receives security fixes.
