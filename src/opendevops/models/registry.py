"""Alias -> provider:model resolution; parallel-tool-use off; boot check every model priced.

`resolve(cfg, agent_name)` walks `agents: -> aliases: -> provider:model` (delegating to
`AppConfig.models.resolve`, which config.py's boot-time validator already guarantees is safe
for any `agent_name` present in `agents:`) and raises `UnknownAgentError` with the known-agent
list for anything else.

`build_chat_model(cfg, agent_name)` resolves the model key and constructs the chat model
**instance** for deepagents' `model=` param. Only the `anthropic:` provider is implemented;
other providers raise `NotImplementedError` naming the extension point (add a branch here
+ a pricing.yaml row).

## Parallel tool use

deepagents (via `langchain.agents.factory`) calls `request.model.bind_tools(final_tools,
tool_choice=request.tool_choice, **request.model_settings)` on the instance we hand it — a
`.bind_tools(...)` *return value* from this module would never be seen by deepagents, so it is
not a usable mechanism here (see the task brief). Only instance-/constructor-level
configuration on the `ChatAnthropic` we return survives.

Verified against the pinned, installed `langchain==1.3.14` / `langchain-anthropic==1.4.8`
source (not merely assumed):

- `request.tool_choice` defaults to `None` and deepagents never sets it or `model_settings`
  (`grep -rn "tool_choice\\|model_settings" deepagents/` — no hits).
- `ChatAnthropic.bind_tools` no-ops on a falsy `tool_choice` (`if not tool_choice: pass`), so
  a `None` tool_choice never adds a `"tool_choice"` key to the kwargs it binds.
- `ChatAnthropic._get_request_payload` builds the wire payload as
  `{..., **self.model_kwargs, **kwargs}` — bind-time `kwargs` only override keys they
  actually set, so a constructor-time `model_kwargs={"tool_choice": {...}}` is *not*
  clobbered when deepagents' internal `bind_tools(tool_choice=None)` call contributes no
  `"tool_choice"` key of its own.

So `build_chat_model` sets `model_kwargs={"tool_choice": {"type": "auto",
"disable_parallel_tool_use": True}}` at construction, and it demonstrably reaches the request
payload after deepagents' internal `bind_tools` call (see
`tests/unit/test_registry.py::test_parallel_tool_use_disabled_survives_deepagents_style_bind_tools`,
which exercises the exact `bind_tools` -> `_get_request_payload` path with no network call).

**Caveat:** this is verified-but-undocumented emergent behavior of dict-merge precedence in
the pinned library versions, not a publicly guaranteed contract — a future
langchain/langchain-anthropic release could start passing an explicit `tool_choice` through
`model_settings`/`bind_tools` and silently override it. This construction-time default
is **belt-and-braces, not load-bearing**: the escalate path now suspends the run via
`interrupt()` inside `policy/middleware.py`, which opens a node-replay window across the
suspend, so a dedicated `SingleToolCallMiddleware` (an `awrap_model_call` guard in
`policy/guard.py`, wired ahead of `PolicyMiddleware` in `agent.py`) collapses any parallel-tool
turn to a single call *by construction* — correctness holds regardless of what the model emits
or whether this `model_kwargs` precedence ever regresses. The `tool_results_cache` in
`PolicyMiddleware` is the third, independent layer, serving any replayed sibling from cache
rather than re-running it. See `policy/guard.py` for the full three-layer rationale.

`assert_all_agents_priced(cfg)` re-asserts (defensively, at the registry — the consumer of
`cfg.models`) the invariant `config.py`'s `ModelsConfig` validator already enforces at load
time: every `agents:` entry resolves to a model with a pricing row.
"""

from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel

from opendevops.config import AppConfig
from opendevops.models.pricing import UnpricedModelError

# See the "Parallel tool use" section of this module's docstring for exactly why this
# survives deepagents' internal `model.bind_tools(...)` call (verified, not assumed) and why
# it is belt-and-braces rather than load-bearing.
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
        # KeyError.__str__ reprs a single-arg message (double-quoting it); return the plain
        # message instead so this reads cleanly wherever it's logged/printed.
        return str(self.args[0])


def resolve(cfg: AppConfig, agent_name: str) -> str:
    """Resolve an `agents:` role (e.g. `"main"`) to its `provider:model` string.

    Raises `UnknownAgentError` if `agent_name` is not present in `cfg.models.agents`. (Every
    `agent_name` that *is* present is guaranteed resolvable — config.py's boot-time validator
    already checked its alias exists and is priced.)
    """
    if agent_name not in cfg.models.agents:
        raise UnknownAgentError(agent_name, sorted(cfg.models.agents))
    return cfg.models.resolve(agent_name)


def build_chat_model(cfg: AppConfig, agent_name: str) -> BaseChatModel:
    """Construct the chat model instance for `agent_name`, for deepagents' `model=` param.

    Raises `UnknownAgentError` for an unknown `agent_name`, and `NotImplementedError` for any
    provider other than `anthropic:` (only Anthropic is supported; adding a provider means
    adding a branch here plus matching `pricing:` rows in `models.yaml`).
    """
    model_key = resolve(cfg, agent_name)
    provider, _, model_id = model_key.partition(":")

    if provider == "anthropic":
        # `model_validate(...)` rather than `ChatAnthropic(model=...)`: mypy's PEP-681
        # (dataclass_transform) support synthesizes ChatAnthropic's keyword-arg __init__
        # signature from only the pydantic *alias* names (e.g. `model_name`, not the
        # `populate_by_name=True`-permitted `model`), and additionally mis-treats several
        # `Field(None, alias=...)` fields as required — both verified in isolation against
        # the installed langchain-anthropic 1.4.8 (`ChatAnthropic(model_name="x")` alone
        # still errors "Missing named argument timeout/stop"). `model_validate` is the same
        # public, documented pydantic v2 construction path (identical validation/aliasing at
        # runtime) and is typed as `(obj: Any) -> Self`, sidestepping the false positive.
        return ChatAnthropic.model_validate(
            {"model": model_id, "model_kwargs": dict(_DISABLE_PARALLEL_TOOL_USE_KWARGS)}
        )

    raise NotImplementedError(
        f"provider {provider!r} (from model key {model_key!r}) is not implemented; "
        f"multi-provider support arrives by adding a branch to "
        f"opendevops.models.registry.build_chat_model for {provider!r} plus matching "
        f"pricing: rows in models.yaml"
    )


def assert_all_agents_priced(cfg: AppConfig) -> None:
    """Defensively re-assert that every `agents:` entry resolves to a priced model.

    `config.py`'s `ModelsConfig` validator already enforces this at load time (an unpriced
    model can't even parse into a valid `AppConfig`); this is a belt-and-braces boot check at
    the point of consumption. Raises `UnknownAgentError` (shouldn't happen for a valid
    `cfg.models.agents` key) or `UnpricedModelError`.
    """
    for agent_name in cfg.models.agents:
        model_key = resolve(cfg, agent_name)
        if model_key not in cfg.models.pricing:
            raise UnpricedModelError(model_key)
