"""Known AI models per provider.

A convenience list for `--list-models`. It is not exhaustive and not a limit:
you can pass any provider-specific model id with `--ai-model`. The entries are
current, real model ids, not a marketing count.
"""
from __future__ import annotations

MODELS: dict[str, list[str]] = {
    "openai": ["gpt-5", "gpt-4.1", "gpt-4.1-mini", "gpt-4o", "gpt-4o-mini", "o4-mini", "o3"],
    "anthropic": ["claude-3-5-sonnet-latest", "claude-3-5-haiku-latest",
                  "claude-3-opus-20240229"],
    "google": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
    "deepseek": ["deepseek-chat", "deepseek-reasoner"],
    "mistral": ["mistral-large-latest", "mistral-small-latest", "codestral-latest"],
    "groq": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
    "xai": ["grok-2-latest", "grok-2-mini"],
    "together": ["meta-llama/Llama-3.3-70B-Instruct-Turbo",
                 "Qwen/Qwen2.5-72B-Instruct-Turbo",
                 "mistralai/Mixtral-8x7B-Instruct-v0.1"],
    "fireworks": ["accounts/fireworks/models/llama-v3p3-70b-instruct",
                  "accounts/fireworks/models/qwen2p5-72b-instruct"],
    "perplexity": ["sonar", "sonar-pro", "sonar-reasoning"],
    "glm": ["glm-4-plus", "glm-4-flash"],
    "nvidia": ["meta/llama-3.3-70b-instruct", "nvidia/llama-3.1-nemotron-70b-instruct"],
    "openrouter": ["openrouter/auto"],   # routes to any model OpenRouter supports
    "ollama": ["llama3.1", "llama3.3", "qwen2.5", "mistral"],  # whatever you pull locally
}


def list_models() -> dict[str, list[str]]:
    return MODELS
