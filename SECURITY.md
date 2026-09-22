# Security Policy

## Authorized use only

Sentari runs real offensive security tools. Use it only against systems you own or hold explicit, written authorization to test. The tool enforces this at runtime: it will not run unless the target is within a declared `--scope` and you attest authorization with `--authorized`, and it records every run in an append-only audit log.

You are responsible for:

- obtaining authorization before any assessment,
- complying with all applicable laws and regulations, and
- respecting privacy and data-protection obligations for any data you encounter.

Unauthorized use is prohibited (see `LICENSE`).

## Safe defaults

- Safe mode is on by default. Intrusive and verification actions require `--no-safe-mode`, and the verification phase does only read-only checks.
- The web dashboard is read-only and binds to `127.0.0.1` by default. It never triggers scans. Do not expose it publicly without an authenticated proxy.
- Secrets retrieved during verification, such as `.env` values, are redacted before they reach any evidence or report.

## Reporting a vulnerability in Sentari itself

If you find a security issue in Sentari's own code, please report it privately:

- Email: contact@ahmadoqsrawi.com
- Please do not open a public issue for an undisclosed vulnerability.

Include a description, the affected version or commit, and steps to reproduce. You can expect an acknowledgement within a reasonable time, and coordinated disclosure once a fix is ready.

## Supported versions

The latest release on `main` receives security fixes.
