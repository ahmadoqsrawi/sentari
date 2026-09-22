"""Multi-provider LLM abstraction.

Mirrors the breadth of a multi-provider AI layer (OpenAI, Anthropic, Google,
Ollama, OpenRouter, and any OpenAI-compatible endpoint) behind one interface.
Original implementation. SDKs are imported lazily so the tool runs with none of
them installed: a provider simply reports itself unavailable rather than
crashing the program.
"""
from __future__ import annotations

import importlib
import os
from abc import ABC, abstractmethod
from typing import Optional


def _try_import(mod: str):
    try:
        return importlib.import_module(mod)
    except Exception:
        return None


class LLMProvider(ABC):
    name = "base"

    def __init__(self, model: str, api_key: Optional[str] = None,
                 base_url: Optional[str] = None) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = base_url

    @abstractmethod
    def available(self) -> tuple[bool, str]:
        """(usable?, reason-if-not)."""

    @abstractmethod
    def complete(self, system: str, user: str, max_tokens: int = 1500) -> str:
        ...


class OpenAICompatProvider(LLMProvider):
    """OpenAI and any OpenAI-compatible API (OpenRouter, local gateways)."""
    name = "openai"

    def available(self) -> tuple[bool, str]:
        if _try_import("openai") is None:
            return False, "openai SDK not installed (pip install openai)"
        if not self.api_key:
            return False, "no API key set"
        return True, ""

    def complete(self, system: str, user: str, max_tokens: int = 1500) -> str:
        openai = importlib.import_module("openai")
        client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url or None)
        r = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            max_completion_tokens=max_tokens,
        )
        return r.choices[0].message.content or ""


class OpenRouterProvider(OpenAICompatProvider):
    name = "openrouter"

    def __init__(self, model, api_key=None, base_url=None):
        super().__init__(model, api_key, base_url or "https://openrouter.ai/api/v1")


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def available(self) -> tuple[bool, str]:
        if _try_import("anthropic") is None:
            return False, "anthropic SDK not installed (pip install anthropic)"
        if not self.api_key:
            return False, "no API key set"
        return True, ""

    def complete(self, system: str, user: str, max_tokens: int = 1500) -> str:
        anthropic = importlib.import_module("anthropic")
        client = anthropic.Anthropic(api_key=self.api_key)
        r = client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(getattr(b, "text", "") for b in r.content)


class GoogleProvider(LLMProvider):
    name = "google"

    def available(self) -> tuple[bool, str]:
        if _try_import("google.generativeai") is None:
            return False, "google-generativeai not installed"
        if not self.api_key:
            return False, "no API key set"
        return True, ""

    def complete(self, system: str, user: str, max_tokens: int = 1500) -> str:
        genai = importlib.import_module("google.generativeai")
        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(self.model, system_instruction=system)
        return (model.generate_content(user).text) or ""


class OllamaProvider(LLMProvider):
    """Local models via Ollama: no API key, no external calls."""
    name = "ollama"

    def __init__(self, model, api_key=None, base_url=None):
        super().__init__(model, api_key, base_url or "http://localhost:11434")

    def available(self) -> tuple[bool, str]:
        if _try_import("requests") is None:
            return False, "requests not installed"
        return True, ""

    def complete(self, system: str, user: str, max_tokens: int = 1500) -> str:
        requests = importlib.import_module("requests")
        r = requests.post(f"{self.base_url}/api/chat", timeout=120, json={
            "model": self.model, "stream": False,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        })
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")


_REGISTRY = {
    "openai": OpenAICompatProvider, "openrouter": OpenRouterProvider,
    "anthropic": AnthropicProvider, "google": GoogleProvider, "ollama": OllamaProvider,
}
# env var holding each provider's key
_ENV_KEY = {
    "openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY", "google": "GOOGLE_API_KEY", "ollama": "",
}
_DEFAULT_MODEL = {
    "openai": "gpt-4o-mini", "openrouter": "openrouter/auto",
    "anthropic": "claude-3-5-haiku-latest", "google": "gemini-1.5-flash",
    "ollama": "llama3.1",
}


def get_provider(name: Optional[str] = None, model: Optional[str] = None,
                 api_key: Optional[str] = None, base_url: Optional[str] = None) -> LLMProvider:
    """Build a provider. Falls back to env (HACKGPT-style precedence: explicit >
    HACKGPT_PROVIDER/MODEL are NOT used here: Sentari uses SENTARI_* / provider keys)."""
    name = (name or os.getenv("SENTARI_PROVIDER") or "openai").lower()
    cls = _REGISTRY.get(name, OpenAICompatProvider)
    model = model or os.getenv("SENTARI_MODEL") or _DEFAULT_MODEL.get(name, "gpt-4o-mini")
    if api_key is None and _ENV_KEY.get(name):
        api_key = os.getenv(_ENV_KEY[name])
    return cls(model=model, api_key=api_key, base_url=base_url)


def list_providers() -> list[str]:
    return list(_REGISTRY)
