"""Alias -> provider:model resolution; multi-provider chat model construction.

`resolve(cfg, agent_name)` walks `agents: -> aliases: -> provider:model`.

`build_chat_model(cfg, agent_name)` resolves the model key and constructs the chat model
instance for deepagents' `model=` param. Provider construction is driven by optional
`models.providers` entries (`kind`: anthropic | openai | openai_compatible | azure_openai |
google | bedrock). When `providers` is omitted, `anthropic:` and `openai:` use built-in
defaults (API keys from the usual env vars).

## Parallel tool use

Anthropic receives `disable_parallel_tool_use` via `model_kwargs`. Other providers rely on
`SingleToolCallMiddleware` (see `policy/guard.py`) as the load-bearing guard.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from opendevops.config import AppConfig, ProviderConfig
from opendevops.models.pricing import UnpricedModelError

_DISABLE_PARALLEL_TOOL_USE_KWARGS: dict[str, object] = {
    "tool_choice": {"type": "auto", "disable_parallel_tool_use": True},
}


class UnknownAgentError(KeyError):
    """Raised when `agent_name` is not a known `agents:` entry in `models.yaml`."""

    def __init__(self, agent_name: str, known_agents: list[str]) -> None:
        self.agent_name = agent_name
        self.known_agents = known_agents
        super().__init__(f"unknown agent {agent_name!r}; known agents: {known_agents}")

    def __str__(self) -> str:
        return str(self.args[0])


class ProviderConfigError(RuntimeError):
    """Misconfigured or unavailable LLM provider."""


def resolve(cfg: AppConfig, agent_name: str) -> str:
    """Resolve an `agents:` role (e.g. `"main"`) to its `provider:model` string."""
    if agent_name not in cfg.models.agents:
        raise UnknownAgentError(agent_name, sorted(cfg.models.agents))
    return cfg.models.resolve(agent_name)


def _provider_config(cfg: AppConfig, provider_id: str) -> ProviderConfig:
    explicit = cfg.models.providers.get(provider_id)
    if explicit is not None:
        return explicit
    # Built-in defaults when operators omit models.providers entirely.
    if provider_id == "anthropic":
        return ProviderConfig(kind="anthropic", api_key_env="ANTHROPIC_API_KEY")
    if provider_id == "openai":
        return ProviderConfig(kind="openai", api_key_env="OPENAI_API_KEY")
    raise ProviderConfigError(
        f"provider {provider_id!r} is not configured in models.providers; "
        f"add a providers.{provider_id} entry with kind and credentials"
    )


def _require_env(var_name: str | None, *, what: str) -> str:
    if not var_name:
        raise ProviderConfigError(f"{what} requires an api_key_env / endpoint env name")
    value = os.environ.get(var_name)
    if not value:
        raise ProviderConfigError(f"{what} env var {var_name!r} is unset or empty")
    return value


def _build_anthropic(model_id: str, provider: ProviderConfig) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic

    kwargs: dict[str, Any] = {
        "model": model_id,
        "model_kwargs": dict(_DISABLE_PARALLEL_TOOL_USE_KWARGS),
    }
    if provider.api_key_env:
        kwargs["api_key"] = _require_env(provider.api_key_env, what="anthropic")
    if provider.base_url:
        kwargs["base_url"] = provider.base_url
    return ChatAnthropic.model_validate(kwargs)


def _build_openai(model_id: str, provider: ProviderConfig, *, compatible: bool) -> BaseChatModel:
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:  # pragma: no cover
        raise ProviderConfigError(
            "openai / openai_compatible providers require the 'models-openai' extra "
            "(install 'opendevops[models-openai]')"
        ) from exc
    kwargs: dict[str, Any] = {"model": model_id}
    if provider.api_key_env:
        kwargs["api_key"] = _require_env(provider.api_key_env, what="openai")
    if provider.base_url:
        kwargs["base_url"] = provider.base_url
    elif compatible and not provider.base_url:
        raise ProviderConfigError(
            "openai_compatible providers require providers.*.base_url"
        )
    return ChatOpenAI.model_validate(kwargs)


def _build_azure(model_id: str, provider: ProviderConfig) -> BaseChatModel:
    try:
        from langchain_openai import AzureChatOpenAI
    except ImportError as exc:  # pragma: no cover
        raise ProviderConfigError(
            "azure_openai requires the 'models-openai' extra"
        ) from exc
    endpoint = _require_env(provider.azure_endpoint_env, what="azure_openai endpoint")
    api_key = _require_env(provider.api_key_env, what="azure_openai")
    if not provider.api_version:
        raise ProviderConfigError("azure_openai requires providers.*.api_version")
    return AzureChatOpenAI.model_validate(
        {
            "azure_deployment": model_id,
            "azure_endpoint": endpoint,
            "api_key": api_key,
            "api_version": provider.api_version,
        }
    )


def _build_google(model_id: str, provider: ProviderConfig) -> BaseChatModel:
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ImportError as exc:  # pragma: no cover
        raise ProviderConfigError(
            "google provider requires the 'models-google' extra"
        ) from exc
    kwargs: dict[str, Any] = {"model": model_id}
    if provider.api_key_env:
        kwargs["google_api_key"] = _require_env(provider.api_key_env, what="google")
    return ChatGoogleGenerativeAI.model_validate(kwargs)


def _build_bedrock(model_id: str, provider: ProviderConfig) -> BaseChatModel:
    try:
        from langchain_aws import ChatBedrock
    except ImportError as exc:  # pragma: no cover
        raise ProviderConfigError(
            "bedrock provider requires the 'models-bedrock' extra"
        ) from exc
    kwargs: dict[str, Any] = {"model_id": model_id}
    if provider.region_name:
        kwargs["region_name"] = provider.region_name
    if provider.credentials_profile_name:
        kwargs["credentials_profile_name"] = provider.credentials_profile_name
    return ChatBedrock.model_validate(kwargs)


def build_chat_model(cfg: AppConfig, agent_name: str) -> BaseChatModel:
    """Construct the chat model instance for `agent_name`, for deepagents' `model=` param."""
    model_key = resolve(cfg, agent_name)
    provider_id, _, model_id = model_key.partition(":")
    if not provider_id or not model_id:
        raise ProviderConfigError(
            f"model key {model_key!r} must be shaped as provider:model"
        )
    provider = _provider_config(cfg, provider_id)
    if provider.kind == "anthropic":
        return _build_anthropic(model_id, provider)
    if provider.kind == "openai":
        return _build_openai(model_id, provider, compatible=False)
    if provider.kind == "openai_compatible":
        return _build_openai(model_id, provider, compatible=True)
    if provider.kind == "azure_openai":
        return _build_azure(model_id, provider)
    if provider.kind == "google":
        return _build_google(model_id, provider)
    if provider.kind == "bedrock":
        return _build_bedrock(model_id, provider)
    raise ProviderConfigError(f"unsupported provider kind {provider.kind!r}")


def assert_all_agents_priced(cfg: AppConfig) -> None:
    """Defensively re-assert that every `agents:` entry resolves to a priced model."""
    for agent_name in cfg.models.agents:
        model_key = resolve(cfg, agent_name)
        if model_key not in cfg.models.pricing:
            raise UnpricedModelError(model_key)
