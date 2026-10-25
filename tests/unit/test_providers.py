"""Tests for the LLM provider guardrails (PRD section 12)."""

from __future__ import annotations

import json

import httpx
import pytest

from verdis.extract.providers import (
    AnthropicProvider,
    NullProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    ProviderConfig,
    ProviderUnavailable,
    Redactor,
    build_provider,
)
from verdis.schemas.common import BudgetExceeded

SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
}


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


class TestNullProvider:
    def test_refuses_to_answer(self) -> None:
        provider = NullProvider(ProviderConfig(provider="none"))
        with pytest.raises(ProviderUnavailable):
            provider.complete_json(system="s", user="u", schema=SCHEMA)

    def test_is_chosen_by_default(self) -> None:
        assert isinstance(build_provider(ProviderConfig()), NullProvider)

    def test_zero_tokens_are_used(self) -> None:
        provider = NullProvider()
        assert provider.tokens_used == 0


class TestRedactor:
    def test_removes_emails(self) -> None:
        redactor = Redactor()
        assert "alice@example.org" not in redactor.apply("mail alice@example.org now")

    def test_removes_github_tokens(self) -> None:
        redactor = Redactor()
        token = "ghp_" + "a" * 36
        assert token not in redactor.apply(f"token {token}")

    def test_removes_private_keys(self) -> None:
        redactor = Redactor()
        blob = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
        assert "BEGIN RSA PRIVATE KEY" not in redactor.apply(blob)

    def test_can_be_disabled(self) -> None:
        redactor = Redactor(enabled=False)
        assert redactor.apply("a@b.org") == "a@b.org"

    def test_counts_redactions(self) -> None:
        redactor = Redactor()
        redactor.apply("a@b.org and c@d.org")
        assert redactor.count == 2


class TestOpenAICompatible:
    def test_sends_a_schema_constrained_request(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["payload"] = json.loads(request.content)
            captured["headers"] = dict(request.headers)
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": '{"answer": "yes"}'}}],
                    "usage": {"total_tokens": 12},
                },
            )

        provider = OpenAICompatibleProvider(
            ProviderConfig(provider="openai", model="gpt-x", api_key="secret", base_url="http://x/v1")
        )
        provider._client = httpx.Client(
            transport=_transport(handler), base_url="http://x/v1", timeout=10
        )
        payload, metadata = provider.complete_json(
            system="sys", user="REPORT TEXT", schema=SCHEMA, purpose="claim-extraction"
        )
        assert payload["answer"] == "yes"
        body = captured["payload"]
        assert body["temperature"] == 0
        assert body["response_format"]["json_schema"]["schema"] == SCHEMA
        assert body["messages"][0]["role"] == "system"
        assert body["messages"][0]["content"] == "sys"
        assert "REPORT TEXT" not in body["messages"][0]["content"]
        assert "REPORT TEXT" in body["messages"][1]["content"]
        assert metadata["tokens_used"] == 12

    def test_reports_invalid_json(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]})

        provider = OpenAICompatibleProvider(ProviderConfig(provider="openai", model="m"))
        provider._client = httpx.Client(transport=_transport(handler), base_url="http://x")
        with pytest.raises(ProviderUnavailable):
            provider.complete_json(system="s", user="u", schema=SCHEMA)

    def test_enforces_the_token_budget(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": "{}"}}],
                    "usage": {"total_tokens": 100},
                },
            )

        provider = OpenAICompatibleProvider(
            ProviderConfig(provider="openai", model="m", budget_tokens=50)
        )
        provider._client = httpx.Client(transport=_transport(handler), base_url="http://x")
        with pytest.raises(BudgetExceeded):
            provider.complete_json(system="s", user="u", schema=SCHEMA)


class TestAnthropic:
    def test_uses_a_forced_structured_output_tool(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["payload"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "content": [{"type": "tool_use", "input": {"answer": "ok"}}],
                    "usage": {"input_tokens": 5, "output_tokens": 5},
                },
            )

        provider = AnthropicProvider(
            ProviderConfig(provider="anthropic", model="claude", api_key="k")
        )
        provider._client = httpx.Client(transport=_transport(handler), base_url="http://x")
        payload, metadata = provider.complete_json(
            system="sys", user="REPORT", schema=SCHEMA
        )
        assert payload["answer"] == "ok"
        body = captured["payload"]
        assert body["tool_choice"]["name"] == "emit"
        assert body["tools"][0]["input_schema"] == SCHEMA
        assert metadata["tokens_used"] == 10

    def test_marks_down_streams_are_not_available(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"content": [{"type": "tool_use", "input": {}}], "usage": {}},
            )

        provider = AnthropicProvider(ProviderConfig(provider="anthropic", model="c"))
        provider._client = httpx.Client(transport=_transport(handler), base_url="http://x")
        _payload, _meta = provider.complete_json(system="s", user="u", schema=SCHEMA)


class TestOllama:
    def test_sends_a_json_format(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["payload"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={"message": {"content": '{"answer": "local"}'}, "eval_count": 4},
            )

        provider = OllamaProvider(ProviderConfig(provider="ollama", model="llama3"))
        provider._client = httpx.Client(transport=_transport(handler), base_url="http://x")
        payload, _meta = provider.complete_json(system="s", user="u", schema=SCHEMA)
        assert payload["answer"] == "local"
        assert captured["payload"]["format"] == SCHEMA
        assert captured["payload"]["options"]["temperature"] == 0

    def test_strips_code_fences(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"message": {"content": '```json\n{"answer": "fenced"}\n```'}},
            )

        provider = OllamaProvider(ProviderConfig(provider="ollama", model="m"))
        provider._client = httpx.Client(transport=_transport(handler), base_url="http://x")
        payload, _meta = provider.complete_json(system="s", user="u", schema=SCHEMA)
        assert payload["answer"] == "fenced"


class TestTheCost:
    """The cost of a report is modelled from the tokens (PRD 13.1)."""

    def test_a_local_model_costs_nothing(self) -> None:
        provider = OllamaProvider(ProviderConfig(provider="ollama", model="llama3"))
        provider._account({"prompt_tokens": 1000, "completion_tokens": 1000})
        assert provider.tokens_used == 2000
        assert provider.cost_usd == 0.0

    def test_a_hosted_model_is_costed_from_its_price(self) -> None:
        provider = OpenAICompatibleProvider(
            ProviderConfig(
                provider="openai", model="gpt-4o", budget_tokens=10_000_000
            )
        )
        provider._account({"prompt_tokens": 1_000_000, "completion_tokens": 0})
        assert provider.cost_usd == 2.50

    def test_the_configured_price_wins(self) -> None:
        provider = OpenAICompatibleProvider(
            ProviderConfig(
                provider="openai",
                model="gpt-4o",
                input_price_per_million=1.0,
                output_price_per_million=2.0,
                budget_tokens=10_000_000,
            )
        )
        provider._account({"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000})
        assert provider.cost_usd == 3.0

    def test_an_unknown_model_costs_nothing_and_says_so(self) -> None:
        provider = OpenAICompatibleProvider(
            ProviderConfig(provider="openai", model="something-new")
        )
        provider._account({"prompt_tokens": 100, "completion_tokens": 100})
        assert provider.cost_usd == 0.0

    def test_the_cost_is_in_the_metadata(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": "{\"answer\": \"yes\"}"}}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 50},
                },
            )

        provider = OpenAICompatibleProvider(
            ProviderConfig(
                provider="openai",
                model="gpt-4o",
                input_price_per_million=1.0,
                output_price_per_million=2.0,
            )
        )
        provider._client = httpx.Client(
            transport=_transport(handler), base_url="http://x/v1", timeout=10
        )
        _payload, metadata = provider.complete_json(
            system="sys", user="text", schema=SCHEMA, purpose="claim-extraction"
        )
        assert metadata["cost_usd"] == 0.0002
        assert metadata["tokens_used"] == 150


class TestBuildProvider:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("none", NullProvider),
            ("null", NullProvider),
            ("openai", OpenAICompatibleProvider),
            ("openai-compatible", OpenAICompatibleProvider),
            ("anthropic", AnthropicProvider),
            ("ollama", OllamaProvider),
            ("local", OllamaProvider),
        ],
    )
    def test_known_providers(self, name: str, expected: type) -> None:
        assert isinstance(build_provider(ProviderConfig(provider=name)), expected)

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(ProviderUnavailable):
            build_provider(ProviderConfig(provider="psychic"))

    def test_config_from_dict_keeps_extras(self) -> None:
        config = ProviderConfig.from_dict({"provider": "openai", "custom": 1})
        assert config.provider == "openai"
        assert config.extra["custom"] == 1
