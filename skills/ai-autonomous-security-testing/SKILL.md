---
name: ai-autonomous-security-testing
description: Drive Sentari with an LLM while keeping findings evidence-backed. Grounded AI triage prioritizes and chains real findings, autopilot lets the model choose which phases to run, the agent mode lets the model call tools directly, AI-assisted OSINT proposes subdomains that DNS then confirms, and the graph coordinator synthesizes across targets. Works with many providers (OpenAI, Anthropic, Google, OpenRouter, Ollama, and more). Use when the user wants AI-driven or autonomous security testing.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# AI-driven security testing with Sentari

The AI never invents findings. A grounding guard drops any AI reference to a finding that does not exist, and AI-proposed leads (like subdomains) are confirmed by a real probe before they become findings. Always pass `--scope` and `--authorized`.

Install the AI extra and set a provider key: `pip install ".[ai]"`.

## Grounded triage of real findings

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --ai --ai-provider openai --ai-model gpt-4o
```

The model prioritizes findings, proposes attack chains, and suggests remediation, all over the real evidence. See known models with `--list-models`.

## Autopilot (the model chooses phases)

```bash
sentari https://app.example.com --scope app.example.com --authorized --autopilot
```

The model picks which phases to run; the phases still run real tools, so findings stay tool-backed. `--autopilot-steps` bounds it.

## Agent (the model calls tools directly)

```bash
sentari https://app.example.com --scope app.example.com --authorized --agent --goal "focus on the API"
```

The model calls a fixed toolbox; `record_finding` is evidence-anchored, so a finding is refused unless it cites real evidence. `--agent-steps` bounds it.

## AI-assisted OSINT (proposals confirmed by DNS)

```bash
sentari example.com --scope example.com --authorized --ai-osint
```

The model proposes likely subdomain labels; each is DNS-resolved, and only names that actually resolve are recorded.

## Graph coordination across targets

```bash
sentari t1.example.com --graph --graph-target t2.example.com --scope example.com --authorized --ai
```

`--graph --ai` runs specialized nodes on a shared blackboard across targets, then the coordinator synthesizes prioritization and chains over all real findings.

## Providers

Use `--ai-provider` (openai, anthropic, google, openrouter, deepseek, mistral, groq, ollama, and others), `--ai-model`, and `--ai-base-url` for OpenAI-compatible or local endpoints (Ollama).
