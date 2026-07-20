"""Scenario 6 (unpriced model refuses to boot) + the other fail-closed boot assertions.

Also pins the BOOT CHECK: the compiled graph's ``run_cost_usd`` channel must be a
``BinaryOperatorAggregate`` (the accumulating reducer), else the per-run cap silently degrades to
last-write-only.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from langgraph.channels.binop import BinaryOperatorAggregate
from pydantic import ValidationError

import opendevops.agent as agent_mod
from opendevops.agent import _REDUCER_CHANNELS, build_agent
from opendevops.audit.logger import AuditLogger
from opendevops.budget.daily import InMemoryDailyCounter

from .helpers import MODELS, ai_text, make_fake_model


def test_unpriced_agent_model_refuses_to_boot(make_cfg: Any) -> None:
    """An agent model with no pricing row fails config validation (an unmetered model)."""
    bad_models = copy.deepcopy(MODELS)
    bad_models["agents"]["main"] = "ghost"
    bad_models["aliases"]["ghost"] = "anthropic:claude-ghost-9"
    # deliberately no pricing entry for anthropic:claude-ghost-9

    with pytest.raises(ValidationError) as excinfo:
        make_cfg(models=bad_models)
    assert "unpriced model is an unmetered model" in str(excinfo.value)


def test_compiled_graph_keeps_accumulating_reducers(cfg: Any, monkeypatch: Any) -> None:
    """The real compiled graph wires BinaryOperatorAggregate reducers for the budget channels."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used-at-construction")
    graph = build_agent(cfg, audit=AuditLogger(cfg.audit.dir), counter=InMemoryDailyCounter())
    for key in _REDUCER_CHANNELS:
        assert isinstance(graph.channels[key], BinaryOperatorAggregate), key


def test_credential_coverage_gap_refuses_boot(built_agent: Any, monkeypatch: Any) -> None:
    """If an allow pack's tool_family has no configured credential, boot fails closed."""
    monkeypatch.setattr(agent_mod, "_configured_credential_families", lambda _cfg: set())
    with pytest.raises(RuntimeError, match="credential family is not configured"):
        built_agent(make_fake_model([ai_text("x")]))


def test_boot_refuses_when_cloud_family_unconfigured(built_agent: Any, cfg: Any) -> None:
    """A shipped cloud pack whose target has no credential_env refuses boot (coverage gate).

    The default ``cfg`` fixture configures aws/gcloud/az; blanking aws's ``credential_env`` (leaving
    gcloud/az set) must surface as a coverage gap naming ``aws``, while every other graph test — all
    of which boot with the cloud families configured — proves the configured path boots.
    """
    unconfigured = cfg.model_copy(deep=True)
    unconfigured.targets.aws.credential_env = []
    with pytest.raises(RuntimeError) as excinfo:
        built_agent(make_fake_model([ai_text("x")]), cfg_override=unconfigured)
    assert "credential family is not configured" in str(excinfo.value)
    assert "aws" in str(excinfo.value)


def test_boot_refuses_when_ssh_family_unconfigured(built_agent: Any, cfg: Any) -> None:
    """The shipped ssh pack refuses boot when targets.ssh.key_env is unset (coverage gate).

    The default ``cfg`` fixture configures ssh; clearing ``key_env`` (the ssh credential) must
    surface as a coverage gap naming ``ssh``. Every other graph test boots with ssh configured,
    proving the configured path boots.
    """
    unconfigured = cfg.model_copy(deep=True)
    unconfigured.targets.ssh.key_env = None
    with pytest.raises(RuntimeError) as excinfo:
        built_agent(make_fake_model([ai_text("x")]), cfg_override=unconfigured)
    assert "credential family is not configured" in str(excinfo.value)
    assert "ssh" in str(excinfo.value)


def test_boot_refuses_when_gh_rw_token_unconfigured(built_agent: Any, cfg: Any) -> None:
    """The shipped gh-write pack refuses boot when github.token_env_rw is unset (coverage gate).

    The default ``cfg`` fixture configures both the ro gh token AND the rw write PAT, so the normal
    path boots. Clearing ``token_env_rw`` (leaving the ro ``token_env`` set, so gh-read still boots)
    must surface as a coverage gap for the ``gh-rw`` write pseudo-family — the gh-write pack's rw
    allows have no write credential — while gh-read stays covered.
    """
    unconfigured = cfg.model_copy(deep=True)
    unconfigured.targets.github.token_env_rw = None
    with pytest.raises(RuntimeError) as excinfo:
        built_agent(make_fake_model([ai_text("x")]), cfg_override=unconfigured)
    assert "credential family is not configured" in str(excinfo.value)
    assert "gh-rw" in str(excinfo.value)


def test_summarizer_is_haiku_backed_marker_subclass(cfg: Any) -> None:
    """The summarizer replacement is a distinct marker subclass built on the ``summarizer`` alias.

    Proves the in-place replacement mechanism: ``_build_summarizer`` returns an instance
    whose ``.name`` is the subclass name (NOT the ``"SummarizationMiddleware"`` alias the harness
    profile excludes), built on the haiku model — so the default (main-model) summarizer is
    dropped and this one takes its place without a duplicate-name collision.
    """
    from deepagents.backends import StateBackend

    from opendevops.agent import _build_summarizer, _HaikuSummarizationMiddleware

    mw = _build_summarizer(cfg, StateBackend())
    assert isinstance(mw, _HaikuSummarizationMiddleware)
    assert mw.name == "_HaikuSummarizationMiddleware"
    # Built on the summarizer alias -> haiku (distinct from the main/opus model).
    assert "haiku" in getattr(mw.model, "model", "")
