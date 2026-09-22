# Contributing to Sentari

Contributions are welcome. Sentari is licensed under **AGPL-3.0-or-later**, and
contributions are accepted under the same license.

## Ground rules

- **Keep the core invariant.** A `Finding` cannot exist without `Evidence` (the
  real output of a real command). Do not add code that fabricates, guesses, or
  hardcodes findings, and keep the AI grounding guard intact.
- **Keep the authorization model.** `--scope`, `--authorized`, the audit log,
  and the confirmation strings on gated offensive features stay in place.
- **Optional dependencies degrade gracefully.** Guard any new optional import so
  the core still runs on the standard library alone.
- **Authorized use only.** This is offensive-security tooling; contributions must
  not weaken the safety and authorization gates.

## Developer workflow

```bash
git clone https://github.com/ahmadoqsrawi/sentari.git
cd sentari
python3 -m venv .venv && source .venv/bin/activate
pip install ".[dev]"
python -m unittest discover -s tests        # all tests must pass
python -m compileall -q sentari tests       # must byte-compile
```

Before opening a pull request:

- Add or update tests for your change; the suite must stay green.
- Match the surrounding style; keep line length reasonable (CI checks
  `flake8 --select=E9,F63,F7,F82`).
- Update the README, CHANGELOG, and any affected `skills/*/SKILL.md`.

## Sign your commits (DCO)

By contributing, you certify the [Developer Certificate of Origin](https://developercertificate.org/):
you wrote the change or have the right to submit it under the project license.
Add a sign-off line to each commit:

```bash
git commit -s -m "Your message"
```

which appends `Signed-off-by: Your Name <you@example.com>`.

## Reporting security issues

Do not open a public issue for a vulnerability in Sentari itself. See
[SECURITY.md](SECURITY.md) for how to report privately.
