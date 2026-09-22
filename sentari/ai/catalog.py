"""Known AI models per provider.

A convenience list for `--list-models`. It is not exhaustive and not a limit:
you can pass any provider-specific model id with `--ai-model`. The entries here
are current, real model ids, not a marketing count.
"""
from __future__ import annotations

MODELS: dict[str, list[str]] = {
    "openai": ["gpt-5", "gpt-4.1", "gpt-4.1-mini", "gpt-4o", "gpt-4o-mini", "o4-mini", "o3"],
    "anthropic": ["claude-3-5-sonnet-latest", "claude-3-5-haiku-latest",
                  "claude-3-opus-20240229"],
    "google": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
    "openrouter": ["openrouter/auto"],   # plus any model id OpenRouter routes
    "ollama": ["llama3.1", "llama3.3", "qwen2.5", "mistral"],  # whatever you pull locally
}


def list_models() -> dict[str, list[str]]:
    return MODELS
