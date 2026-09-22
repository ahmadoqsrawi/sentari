# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
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

    def supports_tools(self) -> bool:
        """True if the provider implements native function-calling (tool_turn)."""
        return False


class OpenAICompatProvider(LLMProvider):
    """OpenAI and any OpenAI-compatible API (OpenRouter, DeepSeek, Groq, xAI,
    Mistral, Together, Fireworks, Perplexity, GLM, local gateways)."""
    name = "openai"

    def __init__(self, model, api_key=None, base_url=None, name=None):
        super().__init__(model, api_key, base_url)
        if name:
            self.name = name

    def available(self) -> tuple[bool, str]:
        if _try_import("openai") is None:
            return False, "openai SDK not installed (pip install openai)"
        if not self.api_key:
            return False, "no API key set"
        return True, ""

    def _client(self):
        openai = importlib.import_module("openai")
        return openai.OpenAI(api_key=self.api_key, base_url=self.base_url or None)

    def complete(self, system: str, user: str, max_tokens: int = 1500) -> str:
        r = self._client().chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            max_completion_tokens=max_tokens,
        )
        return r.choices[0].message.content or ""

    def supports_tools(self) -> bool:
        return True

    def tool_turn(self, system, messages, tools, max_tokens=800) -> dict:
        """One tool-calling turn. `messages` is the normalized transcript; `tools`
        is OpenAI-format tool specs. Returns {text, tool_calls:[{id,name,args}]}."""
        import json as _json
        convo = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "assistant" and m.get("tool_calls"):
                convo.append({"role": "assistant", "content": m.get("content"),
                              "tool_calls": [{"id": c["id"], "type": "function",
                                              "function": {"name": c["name"],
                                                           "arguments": _json.dumps(c["args"])}}
                                             for c in m["tool_calls"]]})
            elif m["role"] == "tool":
                convo.append({"role": "tool", "tool_call_id": m["tool_call_id"],
                              "content": m["content"]})
            else:
                convo.append({"role": m["role"], "content": m.get("content", "")})
        r = self._client().chat.completions.create(
            model=self.model, messages=convo, tools=tools, tool_choice="auto",
            max_completion_tokens=max_tokens)
        msg = r.choices[0].message
        calls = []
        for tc in (msg.tool_calls or []):
            try:
                args = _json.loads(tc.function.arguments or "{}")
            except _json.JSONDecodeError:
                args = {}
            calls.append({"id": tc.id, "name": tc.function.name, "args": args})
        return {"text": msg.content, "tool_calls": calls}


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

    def supports_tools(self) -> bool:
        return True

    def tool_turn(self, system, messages, tools, max_tokens=800) -> dict:
        """Anthropic tool turn. Converts the OpenAI-format `tools` and the
        normalized transcript into Anthropic's tool_use / tool_result blocks."""
        anthropic = importlib.import_module("anthropic")
        client = anthropic.Anthropic(api_key=self.api_key)
        a_tools = [{"name": t["function"]["name"],
                    "description": t["function"].get("description", ""),
                    "input_schema": t["function"].get("parameters", {"type": "object"})}
                   for t in tools]
        conv = []
        for m in messages:
            if m["role"] == "assistant" and m.get("tool_calls"):
                blocks = ([{"type": "text", "text": m["content"]}] if m.get("content") else [])
                blocks += [{"type": "tool_use", "id": c["id"], "name": c["name"],
                            "input": c["args"]} for c in m["tool_calls"]]
                conv.append({"role": "assistant", "content": blocks})
            elif m["role"] == "tool":
                conv.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": m["tool_call_id"],
                     "content": m["content"]}]})
            else:
                conv.append({"role": m["role"], "content": m.get("content", "")})
        r = client.messages.create(model=self.model, max_tokens=max_tokens,
                                   system=system, tools=a_tools, messages=conv)
        text, calls = None, []
        for block in r.content:
            if getattr(block, "type", "") == "text":
                text = (text or "") + block.text
            elif getattr(block, "type", "") == "tool_use":
                calls.append({"id": block.id, "name": block.name, "args": block.input or {}})
        return {"text": text, "tool_calls": calls}


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


# OpenAI-compatible providers: name -> (base_url, key_env, default_model).
# Adding a company is one line here.
_COMPAT: dict[str, tuple[Optional[str], str, str]] = {
    "openai": (None, "OPENAI_API_KEY", "gpt-4o-mini"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", "openrouter/auto"),
    "deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY", "deepseek-chat"),
    "mistral": ("https://api.mistral.ai/v1", "MISTRAL_API_KEY", "mistral-large-latest"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "llama-3.3-70b-versatile"),
    "xai": ("https://api.x.ai/v1", "XAI_API_KEY", "grok-2-latest"),
    "together": ("https://api.together.xyz/v1", "TOGETHER_API_KEY",
                 "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
    "fireworks": ("https://api.fireworks.ai/inference/v1", "FIREWORKS_API_KEY",
                  "accounts/fireworks/models/llama-v3p3-70b-instruct"),
    "perplexity": ("https://api.perplexity.ai", "PERPLEXITY_API_KEY", "sonar"),
    "glm": ("https://open.bigmodel.cn/api/paas/v4", "GLM_API_KEY", "glm-4-plus"),
    "nvidia": ("https://integrate.api.nvidia.com/v1", "NVIDIA_API_KEY",
               "meta/llama-3.3-70b-instruct"),
}
# Providers with their own SDK / protocol.
_NATIVE = {
    "anthropic": (AnthropicProvider, "ANTHROPIC_API_KEY", "claude-3-5-haiku-latest"),
    "google": (GoogleProvider, "GOOGLE_API_KEY", "gemini-1.5-flash"),
    "ollama": (OllamaProvider, "", "llama3.1"),
}


def get_provider(name: Optional[str] = None, model: Optional[str] = None,
                 api_key: Optional[str] = None, base_url: Optional[str] = None) -> LLMProvider:
    """Build a provider. Precedence: explicit arg > SENTARI_PROVIDER/SENTARI_MODEL env
    > per-provider key env. Any provider-specific model id is allowed."""
    name = (name or os.getenv("SENTARI_PROVIDER") or "openai").lower()
    if name in _COMPAT:
        base, key_env, default = _COMPAT[name]
        model = model or os.getenv("SENTARI_MODEL") or default
        if api_key is None:
            api_key = os.getenv(key_env)
        return OpenAICompatProvider(model=model, api_key=api_key,
                                    base_url=base_url or base, name=name)
    if name in _NATIVE:
        cls, key_env, default = _NATIVE[name]
        model = model or os.getenv("SENTARI_MODEL") or default
        if api_key is None and key_env:
            api_key = os.getenv(key_env)
        return cls(model=model, api_key=api_key, base_url=base_url)
    # unknown name: treat as an OpenAI-compatible endpoint
    return OpenAICompatProvider(model=model or "gpt-4o-mini", api_key=api_key,
                                base_url=base_url, name=name)


def list_providers() -> list[str]:
    return list(_COMPAT) + list(_NATIVE)
