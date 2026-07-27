"""Tests for opendevops.models.registry: alias resolution + chat-model construction.

No network calls: `build_chat_model` only constructs a `ChatAnthropic` instance, it never
invokes it. `ANTHROPIC_API_KEY` is stubbed via an autouse fixture because the constructor
reads it eagerly (langchain-anthropic's `secret_from_env` default factory).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool

from opendevops.config import load_config
from opendevops.models.registry import (
    UnknownAgentError,
    assert_all_agents_priced,
    build_chat_model,
    resolve,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _anthropic_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")


def test_resolve_happy_path_from_shipped_config() -> None:
    cfg = load_config(REPO_ROOT)
    assert resolve(cfg, "main") == "anthropic:claude-opus-4-8"
    assert resolve(cfg, "summarizer") == "anthropic:claude-haiku-4-5"


def test_resolve_unknown_agent_raises_clear_error() -> None:
    cfg = load_config(REPO_ROOT)
    with pytest.raises(UnknownAgentError) as exc:
        resolve(cfg, "does-not-exist")
    message = str(exc.value)
    assert "does-not-exist" in message
    assert "main" in message  # names a known agent so the error is actionable


def test_build_chat_model_returns_chat_anthropic_with_right_model_id() -> None:
    cfg = load_config(REPO_ROOT)
    model = build_chat_model(cfg, "main")
    assert isinstance(model, ChatAnthropic)
    assert model.model == "claude-opus-4-8"


def test_build_chat_model_summarizer_resolves_haiku() -> None:
    cfg = load_config(REPO_ROOT)
    model = build_chat_model(cfg, "summarizer")
    assert isinstance(model, ChatAnthropic)
    assert model.model == "claude-haiku-4-5"


def test_build_chat_model_unknown_agent_raises() -> None:
    cfg = load_config(REPO_ROOT)
    with pytest.raises(UnknownAgentError):
        build_chat_model(cfg, "does-not-exist")


def test_build_chat_model_openai_provider(
    write_config, base_models, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OpenAI provider constructs ChatOpenAI when the API key env is set."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai")
    base_models["aliases"]["opus"] = "openai:gpt-4"
    base_models["pricing"] = {
        "openai:gpt-4": {"input": 1.0, "output": 2.0, "cache_read": 0.0, "cache_write": 0.0},
        "anthropic:claude-haiku-4-5": {
            "input": 1.00,
            "output": 5.00,
            "cache_read": 0.10,
            "cache_write": 1.25,
        },
    }
    root = write_config(models=base_models)
    cfg = load_config(root)
    model = build_chat_model(cfg, "main")
    assert model.__class__.__name__ == "ChatOpenAI"


def test_build_chat_model_unknown_provider_raises(write_config, base_models) -> None:
    """Unconfigured provider ids fail loud with ProviderConfigError."""
    from opendevops.models.registry import ProviderConfigError

    base_models["aliases"]["opus"] = "acme:widget-1"
    base_models["pricing"] = {
        "acme:widget-1": {"input": 1.0, "output": 2.0, "cache_read": 0.0, "cache_write": 0.0},
        "anthropic:claude-haiku-4-5": {
            "input": 1.00,
            "output": 5.00,
            "cache_read": 0.10,
            "cache_write": 1.25,
        },
    }
    root = write_config(models=base_models)
    cfg = load_config(root)
    with pytest.raises(ProviderConfigError, match="acme"):
        build_chat_model(cfg, "main")


def test_assert_all_agents_priced_passes_for_shipped_config() -> None:
    cfg = load_config(REPO_ROOT)
    assert assert_all_agents_priced(cfg) is None  # does not raise


def test_parallel_tool_use_disabled_survives_deepagents_style_bind_tools() -> None:
    """The construction-time tool_choice default must survive deepagents' bind_tools call.

    deepagents/langchain's `create_agent` factory calls `request.model.bind_tools(final_tools,
    tool_choice=request.tool_choice, **request.model_settings)` with `tool_choice=None` and
    empty `model_settings` by default (verified against the installed langchain==1.3.14
    `langchain/agents/factory.py`). `ChatAnthropic.bind_tools` no-ops on a falsy
    `tool_choice`, so it never adds a `tool_choice` key to the bound kwargs;
    `_get_request_payload` merges `**self.model_kwargs` before `**kwargs`, so our
    constructor-time `model_kwargs["tool_choice"]` survives untouched into the request
    payload. This test exercises that exact path (via the public `bound`/`kwargs` fields of
    `RunnableBinding` and the private `_get_request_payload` helper) without any network
    call, to prove `build_chat_model`'s parallel-tool-use-disable actually reaches the wire
    format. See registry.py's module docstring for the caveat: this is
    verified-but-undocumented behavior of the pinned library, not a guaranteed public
    contract — this binding is the wire-level parallel-tool-call control, backstopped
    in-graph by the ``SingleToolCallMiddleware`` guard (see ``test_guard.py``).
    """

    @tool
    def noop(x: int) -> int:
        """Return x unchanged."""
        return x

    cfg = load_config(REPO_ROOT)
    model = build_chat_model(cfg, "main")
    bound = model.bind_tools([noop], tool_choice=None)  # mirrors deepagents' default call
    payload = bound.bound._get_request_payload([("user", "hi")], **bound.kwargs)
    assert payload["tool_choice"] == {"type": "auto", "disable_parallel_tool_use": True}
