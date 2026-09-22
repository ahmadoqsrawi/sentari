# Sentari skills

These are **Agent Skills**: one folder per skill, each with a `SKILL.md` that has
YAML frontmatter (`name`, `description`) plus Markdown instructions. A coding
agent (Claude Code, Cursor, and similar) discovers them by `description` and
loads the instructions when the task matches, so the agent drives Sentari
correctly instead of guessing flags.

The skills are original content authored for Sentari and licensed under the
Sentari license (see `../LICENSE`). They follow the open Agent Skills format
catalogued at [agentskills.io](https://agentskills.io/); credit for the format
and registry goes there.

## Available skills

| Skill | Use it when the user wants to |
|---|---|
| [penetration-testing-with-sentari](penetration-testing-with-sentari/SKILL.md) | pentest / security-scan / audit a web app, API, or host |
| [web-app-penetration-testing](web-app-penetration-testing/SKILL.md) | test a web app for injection, SSRF/XXE, XSS, IDOR |
| [api-security-testing](api-security-testing/SKILL.md) | test an API from its OpenAPI/Swagger/Postman spec |
| [owasp-top-10-testing](owasp-top-10-testing/SKILL.md) | map an assessment to the OWASP Top 10 |
| [find-security-vulnerabilities-in-code](find-security-vulnerabilities-in-code/SKILL.md) | run SAST over a repository |
| [cloud-security-testing](cloud-security-testing/SKILL.md) | discover cloud assets and audit account config |
| [ci-security-scanning-with-sentari](ci-security-scanning-with-sentari/SKILL.md) | add a security gate to CI/CD |
| [fix-security-vulnerabilities-with-sentari](fix-security-vulnerabilities-with-sentari/SKILL.md) | turn findings into a remediation guide or draft PR |

## Using them

- **Claude Code / Cursor / agent frameworks**: copy a skill folder into the tool's
  skills directory (for Claude Code: `~/.claude/skills/`), or point the tool at
  this `skills/` directory.
- **Anywhere**: read the `SKILL.md`; it holds the exact commands and the
  authorization and safe-mode rules.

## Ground rules baked into every skill

- Sentari runs only with `--scope` and `--authorized`; never test a target
  without written permission.
- Findings are evidence-backed; "confirmed" always means a real observed effect.
- Gated/offensive features are for authorized, non-production targets only.
