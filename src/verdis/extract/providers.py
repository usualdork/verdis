"""LLM provider abstraction and guardrails (PRD section 12).

Guardrails enforced here:

* schema-constrained outputs only, temperature 0;
* no agent tool use — providers may not call back into the tool;
* the report text is delimited and never placed in a system prompt;
* per-report token and cost budgets;
* optional redaction of emails and secrets before any external call.

Providers only ever *propose*. Nothing here decides a verdict, matches an
oracle to a claim, or executes anything.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx

from ..schemas.common import BudgetExceeded, sha256_text

__all__ = [
    "AnthropicProvider",
    "BudgetExceeded",
    "LLMProvider",
    "NullProvider",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "ProviderConfig",
    "ProviderUnavailable",
    "Redactor",
    "build_provider",
]

REPORT_DELIMITER_OPEN = "<<<REPORT_TEXT"
REPORT_DELIMITER_CLOSE = "REPORT_TEXT>>>"


class ProviderUnavailable(RuntimeError):
    """Raised when no provider is configured or the provider cannot be used."""


#: Indicative prices, in US dollars per million tokens.
#:
#: These are the published list prices at the time of writing; a provider
#: changes them, and the operator can override them. The cost the tool
#: reports is *modelled* from these numbers and the tokens the provider
#: reported, not an invoice.
MODEL_PRICES: dict[str, tuple[float, float]] = {
    # model -> (input per million, output per million)
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-opus-4": (15.00, 75.00),
    "claude-3-5-haiku": (0.80, 4.00),
}

#: What a local model costs: nothing, because nothing is billed.
LOCAL_PRICE = (0.0, 0.0)


@dataclass
class ProviderConfig:
    """Connection and behaviour settings for a provider."""

    provider: str = "none"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    timeout: float = 120.0
    budget_tokens: int = 20_000
    temperature: float = 0.0
    redaction: bool = True
    input_price_per_million: float = 0.0
    output_price_per_million: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProviderConfig:
        allowed = set(cls.__dataclass_fields__)
        kwargs = {k: v for k, v in data.items() if k in allowed}
        extra = {k: v for k, v in data.items() if k not in allowed}
        config = cls(**kwargs)
        config.extra.update(extra)
        return config


class Redactor:
    """Removes emails, tokens and secret-looking strings before external calls."""

    _PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
        (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"), "<token>"),
        (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "<token>"),
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<aws-key>"),
        (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
         "<private-key>"),
        (re.compile(r"(?i)\b(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[^\s'\"]{6,}"),
         r"\1=<redacted>"),
    )

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.count = 0

    def apply(self, text: str) -> str:
        if not self.enabled:
            return text
        result = text
        for pattern, replacement in self._PATTERNS:
            result, n = pattern.subn(replacement, result)
            self.count += n
        return result


@runtime_checkable
class LLMProvider(Protocol):
    """The interface every provider implements."""

    name: str
    model: str

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        purpose: str = "",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return ``(parsed_json, metadata)`` for a schema-constrained call."""
        ...

    @property
    def tokens_used(self) -> int:
        ...


class _BaseProvider:
    """Shared budget accounting and request shaping."""

    name = "base"

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.model = config.model
        self.redactor = Redactor(config.redaction)
        self._tokens_used = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._client: httpx.Client | None = None

    @property
    def tokens_used(self) -> int:
        return self._tokens_used

    @property
    def cost_usd(self) -> float:
        """What the calls so far cost, in US dollars.

        The number is modelled from the tokens the provider reported and
        the published price of the model. A local model costs nothing.
        """
        input_price, output_price = self._prices()
        cost = (
            self._input_tokens * input_price + self._output_tokens * output_price
        ) / 1_000_000
        return round(cost, 6)

    def _prices(self) -> tuple[float, float]:
        """The prices to use: the configured ones, or the table's."""
        if (
            self.config.input_price_per_million
            or self.config.output_price_per_million
        ):
            return (
                self.config.input_price_per_million,
                self.config.output_price_per_million,
            )
        if self.name in {"ollama", "local"}:
            return LOCAL_PRICE
        return MODEL_PRICES.get(self.model, (0.0, 0.0))

    def _budget_check(self, estimated: int) -> None:
        if self._tokens_used + estimated > self.config.budget_tokens:
            raise BudgetExceeded(
                f"token budget of {self.config.budget_tokens} exhausted "
                f"({self._tokens_used} used)"
            )

    def _account(self, usage: dict[str, Any] | None) -> None:
        if not usage:
            return
        prompt = int(
            usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0
        )
        completion = int(
            usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0
        )
        total = usage.get("total_tokens")
        if total is None:
            total = prompt + completion
        self._input_tokens += prompt
        self._output_tokens += completion
        self._tokens_used += int(total or 0)
        self._budget_check(0)

    def _prepare(self, user: str) -> str:
        """Redact and delimit the report text before it leaves the host.

        Redaction removes emails and secret-looking strings, so an
        accidental external call cannot leak a reporter's address or a
        token. The delimiters mark the text as data, not instructions.
        """
        return f"{REPORT_DELIMITER_OPEN}\n{self.redactor.apply(user)}\n{REPORT_DELIMITER_CLOSE}"

    def _postprocess(self, payload: dict[str, Any], purpose: str) -> tuple[dict[str, Any], dict[str, Any]]:
        raw = json.dumps(payload, sort_keys=True)
        metadata = {
            "provider": self.name,
            "model": self.model,
            "purpose": purpose,
            "prompt_hash": sha256_text(payload.get("_prompt", "")),
            "response_hash": sha256_text(raw),
            "tokens_used": self._tokens_used,
            "cost_usd": self.cost_usd,
            "redactions": self.redactor.count,
        }
        payload.pop("_prompt", None)
        return payload, metadata

    def client(self) -> httpx.Client:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"
            self._client = httpx.Client(timeout=self.config.timeout, headers=headers)
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        purpose: str = "",
    ) -> tuple[dict[str, Any], dict[str, Any]]:  # pragma: no cover - abstract
        raise NotImplementedError


class NullProvider(_BaseProvider):
    """The no-LLM mode. Refuses to answer rather than guessing."""

    name = "none"

    def __init__(self, config: ProviderConfig | None = None) -> None:
        super().__init__(config or ProviderConfig(provider="none"))

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        purpose: str = "",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        raise ProviderUnavailable(
            "no model provider is configured; run in no-LLM mode or set a provider"
        )


class OpenAICompatibleProvider(_BaseProvider):
    """OpenAI-compatible chat completions (works with vLLM, TGI, Ollama's compat API)."""

    name = "openai"

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        self.base_url = (config.base_url or "https://api.openai.com/v1").rstrip("/")

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        purpose: str = "",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._budget_check(len(user) // 4 + 512)
        payload = {
            "model": self.model,
            "temperature": self.config.temperature,
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": self._prepare(user),
                },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "response", "schema": schema, "strict": True},
            },
        }
        response = self.client().post(f"{self.base_url}/chat/completions", json=payload)
        response.raise_for_status()
        body = response.json()
        self._account(body.get("usage"))
        content = body["choices"][0]["message"]["content"]
        parsed = _loads(content)
        parsed["_prompt"] = user
        return self._postprocess(parsed, purpose)


class AnthropicProvider(_BaseProvider):
    """Anthropic messages API with a forced structured-output tool.

    The tool is only a JSON-schema channel; the model has no other tools and
    no ability to execute anything.
    """

    name = "anthropic"

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        self.base_url = (config.base_url or "https://api.anthropic.com/v1").rstrip("/")
        if self.config.api_key:
            self.client().headers["x-api-key"] = self.config.api_key
        self.client().headers["anthropic-version"] = "2023-06-01"

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        purpose: str = "",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._budget_check(len(user) // 4 + 512)
        tool = {
            "name": "emit",
            "description": "Return the structured result.",
            "input_schema": schema,
        }
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "temperature": self.config.temperature,
            "system": system,
            "messages": [
                {
                    "role": "user",
                    "content": self._prepare(user),
                }
            ],
            "tools": [tool],
            "tool_choice": {"type": "tool", "name": "emit"},
        }
        response = self.client().post(f"{self.base_url}/messages", json=payload)
        response.raise_for_status()
        body = response.json()
        usage = body.get("usage") or {}
        self._account(
            {
                "total_tokens": int(usage.get("input_tokens", 0))
                + int(usage.get("output_tokens", 0))
            }
        )
        content = body["content"][0]
        parsed = content.get("input", {})
        parsed = dict(parsed)
        parsed["_prompt"] = user
        return self._postprocess(parsed, purpose)


class OllamaProvider(_BaseProvider):
    """Local models through Ollama's HTTP API."""

    name = "ollama"

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        self.base_url = (config.base_url or "http://127.0.0.1:11434").rstrip("/")

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        purpose: str = "",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._budget_check(len(user) // 4 + 512)
        payload = {
            "model": self.model,
            "stream": False,
            "format": schema,
            "options": {"temperature": self.config.temperature},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": self._prepare(user)},
            ],
        }
        response = self.client().post(f"{self.base_url}/api/chat", json=payload)
        response.raise_for_status()
        body = response.json()
        self._account({"total_tokens": body.get("eval_count", 0)})
        content = body.get("message", {}).get("content", "{}")
        parsed = _loads(content)
        parsed["_prompt"] = user
        return self._postprocess(parsed, purpose)


def _loads(content: str) -> dict[str, Any]:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z]*\n?", "", content)
        content = re.sub(r"\n?```$", "", content)
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ProviderUnavailable(f"provider returned invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProviderUnavailable("provider returned a non-object JSON payload")
    return parsed


_PROVIDERS: dict[str, type[_BaseProvider]] = {
    "none": NullProvider,
    "null": NullProvider,
    "openai": OpenAICompatibleProvider,
    "openai-compatible": OpenAICompatibleProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
    "local": OllamaProvider,
}


def build_provider(config: ProviderConfig) -> LLMProvider:
    """Instantiate the provider named in ``config``."""
    key = config.provider.strip().lower()
    if key in {"", "none", "null"}:
        return NullProvider(config)
    factory = _PROVIDERS.get(key)
    if factory is None:
        raise ProviderUnavailable(f"unknown model provider: {config.provider!r}")
    return factory(config)
