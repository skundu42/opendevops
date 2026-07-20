"""T19 Slack adapter: thread mapping, principal resolve (fail-closed), Block Kit, resume, seam.

slack-bolt Socket Mode needs a live websocket, so nothing here starts a real handler. Every test
drives the pure functions / :class:`SlackAdapter` methods directly with an ``AsyncMock`` gateway and
a stub Slack client (an ``AsyncMock`` exposing ``chat_postMessage`` / ``views_open``), and the
run-complete seam is driven through :func:`create_app` over an in-process ASGI transport with a stub
notifier. No aiohttp / websocket involved.
"""

from __future__ import annotations

import copy
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from graph.helpers import MODELS, budgets
from opendevops.config import AppConfig
from opendevops.gateway import Escalation, EscalationEvent, RunEnd, RunResult
from opendevops.interfaces.slack_app import (
    ACTION_APPROVE,
    ACTION_EDIT,
    ACTION_REJECT,
    EDIT_INPUT_ACTION,
    EDIT_INPUT_BLOCK,
    INTERFACE_SLACK,
    NS_SLACK,
    SlackAdapter,
    SlackThreadNotifier,
    SlackThreadRegistry,
    _require_env,
    build_bolt_app,
    decision_from_action,
    edited_argv_from_view,
    encode_action_value,
    render_denied,
    render_escalation_blocks,
    render_final_blocks,
    resolve_principal,
    slack_thread_id,
)
from opendevops.interfaces.webapp import create_app

_SLACK_USER = "U_ALICE"
_SLACK_PRINCIPAL = "alice@gnosis.io"
_SLACK_PROFILE = "incident"


# -- config / stubs ------------------------------------------------------------------------


def _make_cfg(*, principals: dict[str, Any] | None = None, slack_env: str = "staging") -> AppConfig:
    return AppConfig.model_validate(
        {
            "targets": {"kubernetes": {"kubeconfig_ro": "/tmp/k.yaml"}},
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH"],
            },
            "audit": {"dir": "/tmp/audit"},
            "policy": {"dir": "/tmp/policy"},
            "slack": {"default_channel_environment": slack_env},
            "principals": principals
            if principals is not None
            else {_SLACK_USER: {"principal": _SLACK_PRINCIPAL, "profile": _SLACK_PROFILE}},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


def _stub_client() -> AsyncMock:
    client = AsyncMock()
    client.chat_postMessage = AsyncMock()
    client.views_open = AsyncMock()
    return client


def _result(final_text: str = "", *, interrupted: Escalation | None = None) -> RunResult:
    return RunResult(
        final_text=final_text,
        run_id="r",
        cost_usd_state=0.0,
        cost_usd_authoritative=0.0,
        interrupted=interrupted,
    )


async def _aiter(events: list[Any]) -> Any:
    for event in events:
        yield event


def _stream_gateway(events: list[Any]) -> MagicMock:
    """A gateway whose ``stream`` returns an async iterator over ``events`` (called, not await)."""
    gw = MagicMock()
    gw.stream = MagicMock(return_value=_aiter(events))
    gw.resume_interrupt = AsyncMock()
    return gw


def _escalation(thread_id: str, *, run_id: str = "run-xyz") -> Escalation:
    return Escalation(
        payload={
            "action_requests": [
                {"action": "run_command", "args": {"argv": ["kubectl", "delete", "pod", "api-0"]}}
            ],
            "review_configs": [
                {
                    "rule_id": "kubectl-write-verbs",
                    "reason": "destructive verb requires approval",
                    "allowed_decisions": ["approve", "edit", "reject"],
                    "timeout_s": 300,
                }
            ],
        },
        run_id=run_id,
        thread_id=thread_id,
    )


def _posted_blocks(client: AsyncMock) -> list[list[dict[str, Any]]]:
    return [call.kwargs["blocks"] for call in client.chat_postMessage.await_args_list]


def _actions_block(blocks: list[dict[str, Any]]) -> dict[str, Any] | None:
    for block in blocks:
        if block.get("type") == "actions":
            return block
    return None


# -- thread-id determinism -----------------------------------------------------------------


def test_slack_thread_id_is_deterministic() -> None:
    a = slack_thread_id("C123", "1700000000.000100")
    b = slack_thread_id("C123", "1700000000.000100")
    assert a == b == "".join(a)  # stable
    # It is exactly uuid5(NS_SLACK, "channel:thread_ts").
    import uuid

    assert a == str(uuid.uuid5(NS_SLACK, "C123:1700000000.000100"))


def test_slack_thread_id_differs_per_thread() -> None:
    assert slack_thread_id("C123", "1.1") != slack_thread_id("C123", "2.2")
    assert slack_thread_id("C1", "1.1") != slack_thread_id("C2", "1.1")


# -- principal resolve (fail-closed) -------------------------------------------------------


def test_resolve_principal_mapped() -> None:
    cfg = _make_cfg()
    principal = resolve_principal(_SLACK_USER, cfg)
    assert principal is not None
    assert principal.principal == _SLACK_PRINCIPAL
    assert principal.profile == _SLACK_PROFILE


def test_resolve_principal_unknown_is_none() -> None:
    cfg = _make_cfg()
    assert resolve_principal("U_STRANGER", cfg) is None


# -- Block Kit shapes ----------------------------------------------------------------------


def test_escalation_blocks_carry_thread_id_and_tool_call_id() -> None:
    esc = _escalation("thread-abc", run_id="run-42")
    blocks = render_escalation_blocks(esc)
    actions = _actions_block(blocks)
    assert actions is not None
    action_ids = {el["action_id"] for el in actions["elements"]}
    assert action_ids == {ACTION_APPROVE, ACTION_EDIT, ACTION_REJECT}
    # Every button value carries the agent thread_id + a tool_call_id correlation (run_id fallback).
    for element in actions["elements"]:
        decoded = json.loads(element["value"])
        assert decoded["thread_id"] == "thread-abc"
        assert decoded["tool_call_id"] == "run-42"
    # The escalated command + rule are rendered.
    rendered = json.dumps(blocks)
    assert "kubectl delete pod api-0" in rendered
    assert "kubectl-write-verbs" in rendered


def test_escalation_blocks_honor_explicit_tool_call_id() -> None:
    esc = _escalation("thread-abc")
    esc.payload["action_requests"][0]["tool_call_id"] = "call_777"
    blocks = render_escalation_blocks(esc)
    value = _actions_block(blocks)["elements"][0]["value"]  # type: ignore[index]
    assert json.loads(value)["tool_call_id"] == "call_777"


def test_final_and_denied_block_shapes() -> None:
    final = render_final_blocks("all clear")
    assert final[0]["type"] == "section"
    assert "all clear" in final[0]["text"]["text"]
    denied = render_denied("not authorized")
    assert "not authorized" in denied[0]["text"]["text"]


# -- action -> decision mapping ------------------------------------------------------------


def test_decision_from_action_approve() -> None:
    assert decision_from_action(ACTION_APPROVE, "{}") == {"type": "approve"}


def test_decision_from_action_reject() -> None:
    dec = decision_from_action(ACTION_REJECT, "{}")
    assert dec["type"] == "reject"
    assert dec["message"]


def test_decision_from_action_edit_uses_edited_argv() -> None:
    dec = decision_from_action(ACTION_EDIT, "{}", edited_argv=["kubectl", "get", "pods"])
    assert dec == {"type": "edit", "args": {"argv": ["kubectl", "get", "pods"]}}


def test_decision_from_action_unknown_fails_closed_to_reject() -> None:
    assert decision_from_action("some:garbage", "{}")["type"] == "reject"


def test_encode_decode_round_trip_and_edited_argv_from_view() -> None:
    value = encode_action_value("thread-1", "call-1")
    assert json.loads(value) == {"thread_id": "thread-1", "tool_call_id": "call-1"}
    view = {
        "state": {"values": {EDIT_INPUT_BLOCK: {EDIT_INPUT_ACTION: {"value": "kubectl get pods"}}}}
    }
    assert edited_argv_from_view(view) == ["kubectl", "get", "pods"]


# -- message handler: fail-closed unknown user, mapped user runs slack --------------------


async def test_message_unknown_user_refused_no_stream() -> None:
    cfg = _make_cfg()
    gw = _stream_gateway([])
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    await adapter.handle_message(channel="C1", thread_ts="1.1", user="U_STRANGER", text="hi")

    gw.stream.assert_not_called()
    # A single "not authorized" post, no placeholder / run output.
    assert client.chat_postMessage.await_count == 1
    assert "not authorized" in json.dumps(_posted_blocks(client)[0])


async def test_message_mapped_user_streams_with_slack_interface_and_profile() -> None:
    cfg = _make_cfg(slack_env="prod")
    gw = _stream_gateway([RunEnd(result=_result("done"))])
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    await adapter.handle_message(channel="C9", thread_ts="9.9", user=_SLACK_USER, text="check pods")

    expected_thread = slack_thread_id("C9", "9.9")
    gw.stream.assert_called_once_with(
        expected_thread,
        "check pods",
        profile=_SLACK_PROFILE,
        principal=_SLACK_PRINCIPAL,
        interface=INTERFACE_SLACK,
        environment="prod",
    )
    # The thread was registered so a later run-complete can find it.
    assert adapter.registry.destination_for(expected_thread) is not None


async def test_message_renders_assistant_text_to_thread() -> None:
    from opendevops.gateway import AssistantText

    cfg = _make_cfg()
    gw = _stream_gateway(
        [
            AssistantText(text="Looking at the pods…"),
            RunEnd(result=_result("Looking at the pods…")),
        ]
    )
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    await adapter.handle_message(channel="C1", thread_ts="1.1", user=_SLACK_USER, text="go")

    posted = json.dumps(_posted_blocks(client))
    assert "Looking at the pods" in posted


# -- escalation render -> approve resumes (with resolved approver) --------------------------


async def test_escalation_streamed_then_approve_resumes_with_resolved_approver() -> None:
    cfg = _make_cfg()
    thread_id = slack_thread_id("C1", "1.1")
    esc = _escalation(thread_id, run_id="run-99")
    gw = _stream_gateway(
        [
            EscalationEvent(escalation=esc),
            RunEnd(result=_result(interrupted=esc)),
        ]
    )
    gw.resume_interrupt = AsyncMock(return_value=_result("pod deleted"))
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    # 1) message -> escalation buttons posted.
    await adapter.handle_message(channel="C1", thread_ts="1.1", user=_SLACK_USER, text="delete pod")
    esc_blocks = next(b for b in _posted_blocks(client) if _actions_block(b) is not None)
    value = _actions_block(esc_blocks)["elements"][0]["value"]  # type: ignore[index]
    assert json.loads(value)["thread_id"] == thread_id

    # 2) approve button -> resume_interrupt with the RESOLVED approver principal.
    await adapter.handle_action(
        action_id=ACTION_APPROVE, value=value, user=_SLACK_USER, channel="C1", thread_ts="1.1"
    )
    gw.resume_interrupt.assert_awaited_once_with(
        thread_id, [{"type": "approve"}], approver=_SLACK_PRINCIPAL
    )
    # 3) the final answer is rendered.
    assert "pod deleted" in json.dumps(_posted_blocks(client))


async def test_action_unknown_user_refused_no_resume() -> None:
    cfg = _make_cfg()
    gw = _stream_gateway([])
    gw.resume_interrupt = AsyncMock()
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    value = encode_action_value("thread-abc", "call-1")
    await adapter.handle_action(
        action_id=ACTION_APPROVE, value=value, user="U_STRANGER", channel="C1", thread_ts="1.1"
    )
    gw.resume_interrupt.assert_not_awaited()
    assert "not authorized" in json.dumps(_posted_blocks(client))


async def test_action_reject_resumes_with_reject_decision() -> None:
    cfg = _make_cfg()
    gw = _stream_gateway([])
    gw.resume_interrupt = AsyncMock(return_value=_result("ok, skipping"))
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    thread_id = slack_thread_id("C1", "1.1")  # M-1: the value must be bound to the click's thread.
    value = encode_action_value(thread_id, "call-1")
    await adapter.handle_action(
        action_id=ACTION_REJECT, value=value, user=_SLACK_USER, channel="C1", thread_ts="1.1"
    )
    args, kwargs = gw.resume_interrupt.await_args
    assert args[0] == thread_id
    assert args[1][0]["type"] == "reject"
    assert kwargs["approver"] == _SLACK_PRINCIPAL


# -- M-1: approve/reject click is bound to the thread the card was rendered in -------------


async def test_action_in_thread_click_resumes() -> None:
    """A legitimate in-thread click (value.thread_id matches the click's own thread) resumes."""
    cfg = _make_cfg()
    gw = _stream_gateway([])
    gw.resume_interrupt = AsyncMock(return_value=_result("approved"))
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    thread_id = slack_thread_id("C1", "1.1")
    value = encode_action_value(thread_id, "call-1")
    await adapter.handle_action(
        action_id=ACTION_APPROVE, value=value, user=_SLACK_USER, channel="C1", thread_ts="1.1"
    )
    gw.resume_interrupt.assert_awaited_once_with(
        thread_id, [{"type": "approve"}], approver=_SLACK_PRINCIPAL
    )


async def test_action_foreign_thread_id_refused_no_resume() -> None:
    """A forged value.thread_id for a thread OTHER than the click's is refused, never resumed."""
    cfg = _make_cfg()
    gw = _stream_gateway([])
    gw.resume_interrupt = AsyncMock()
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    # The clicker is a mapped/authorized user, but the button value points at a DIFFERENT thread
    # (one they may not even be able to see) — the thread-binding gate must refuse it.
    foreign = slack_thread_id("C_SECRET", "9.9")
    assert foreign != slack_thread_id("C1", "1.1")
    value = encode_action_value(foreign, "call-1")
    await adapter.handle_action(
        action_id=ACTION_APPROVE, value=value, user=_SLACK_USER, channel="C1", thread_ts="1.1"
    )
    gw.resume_interrupt.assert_not_awaited()
    assert "not valid for this thread" in json.dumps(_posted_blocks(client))


async def test_action_foreign_thread_id_refused_for_edit_too() -> None:
    """The thread-binding gate also blocks a forged edit click before any modal opens."""
    cfg = _make_cfg()
    gw = _stream_gateway([])
    gw.resume_interrupt = AsyncMock()
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    value = encode_action_value(slack_thread_id("C_SECRET", "9.9"), "call-1")
    await adapter.handle_action(
        action_id=ACTION_EDIT,
        value=value,
        user=_SLACK_USER,
        channel="C1",
        thread_ts="1.1",
        trigger_id="trig-1",
    )
    client.views_open.assert_not_awaited()
    gw.resume_interrupt.assert_not_awaited()


# -- M-2: malformed/undecodable button value fails closed (no gateway call, no unhandled exc) --


async def test_action_malformed_value_refused_no_resume() -> None:
    """An undecodable button value yields no thread_id -> denial, no resume_interrupt, no raise."""
    cfg = _make_cfg()
    gw = _stream_gateway([])
    gw.resume_interrupt = AsyncMock(side_effect=AssertionError("resume must not be called"))
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)

    # A garbage value (not JSON) decodes to {} -> thread_id == "" -> fail closed.
    await adapter.handle_action(
        action_id=ACTION_APPROVE, value="not-json", user=_SLACK_USER, channel="C1", thread_ts="1.1"
    )
    gw.resume_interrupt.assert_not_awaited()
    assert "could not identify the escalation" in json.dumps(_posted_blocks(client))


async def test_view_submission_unregistered_thread_fails_closed() -> None:
    """A modal submission whose thread_id is not registered is refused (no resume, no raise)."""
    cfg = _make_cfg()
    gw = _stream_gateway([])
    gw.resume_interrupt = AsyncMock(side_effect=AssertionError("resume must not be called"))
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)  # empty registry

    submitted_view = {
        "private_metadata": encode_action_value(slack_thread_id("C1", "1.1"), "call-1"),
        "state": {"values": {EDIT_INPUT_BLOCK: {EDIT_INPUT_ACTION: {"value": "kubectl get pods"}}}},
    }
    await adapter.handle_view_submission(view=submitted_view, user=_SLACK_USER)
    gw.resume_interrupt.assert_not_awaited()


async def test_action_edit_opens_modal_and_submission_resumes_with_edited_argv() -> None:
    cfg = _make_cfg()
    thread_id = slack_thread_id("C1", "1.1")
    gw = _stream_gateway([])
    gw.resume_interrupt = AsyncMock(return_value=_result("edited run done"))
    client = _stub_client()
    adapter = SlackAdapter(cfg, gw, client)
    adapter.registry.register(thread_id, "C1", "1.1")  # message handler would have registered it

    value = encode_action_value(thread_id, "call-1")
    # Edit button opens a modal carrying `value` in private_metadata; no resume yet.
    await adapter.handle_action(
        action_id=ACTION_EDIT,
        value=value,
        user=_SLACK_USER,
        channel="C1",
        thread_ts="1.1",
        trigger_id="trig-1",
    )
    client.views_open.assert_awaited_once()
    view_arg = client.views_open.await_args.kwargs["view"]
    assert view_arg["private_metadata"] == value
    gw.resume_interrupt.assert_not_awaited()

    # Modal submission -> resume with an edit decision carrying the edited argv.
    submitted_view = {
        "private_metadata": value,
        "state": {
            "values": {EDIT_INPUT_BLOCK: {EDIT_INPUT_ACTION: {"value": "kubectl get pods -n web"}}}
        },
    }
    await adapter.handle_view_submission(view=submitted_view, user=_SLACK_USER)
    args, kwargs = gw.resume_interrupt.await_args
    assert args[0] == thread_id
    assert args[1][0] == {"type": "edit", "args": {"argv": ["kubectl", "get", "pods", "-n", "web"]}}
    assert kwargs["approver"] == _SLACK_PRINCIPAL
    assert "edited run done" in json.dumps(_posted_blocks(client))


# -- SlackThreadNotifier (concrete run-complete notifier) ----------------------------------


async def test_notifier_posts_only_for_registered_thread() -> None:
    registry = SlackThreadRegistry()
    registry.register("T-known", "C1", "1.1")
    client = _stub_client()
    notifier = SlackThreadNotifier(client, registry)

    assert notifier.destination_for("T-known") is not None
    assert notifier.destination_for("T-unknown") is None

    await notifier.post_final("T-known", "final answer")
    client.chat_postMessage.assert_awaited_once()
    assert notifier.destination_for("T-known").channel == "C1"  # type: ignore[union-attr]

    client.chat_postMessage.reset_mock()
    await notifier.post_final("T-unknown", "ignored")
    client.chat_postMessage.assert_not_awaited()


# -- webapp run-complete -> Slack seam (through the route) ----------------------------------


_TOKEN = "s3cr3t-bearer-token"
_TOKEN_ENV = "TEST_AM_TOKEN_SLACK"


def _webapp_cfg() -> AppConfig:
    return AppConfig.model_validate(
        {
            "targets": {"kubernetes": {"kubeconfig_ro": "/tmp/k.yaml"}},
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH"],
            },
            "audit": {"dir": "/tmp/audit"},
            "policy": {"dir": "/tmp/policy"},
            "server": {"url": "http://localhost:8123", "alertmanager_token_env": _TOKEN_ENV},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


class _StubNotifier:
    """A run-complete notifier: destination_for gates on a registered set; post_final recorded."""

    def __init__(self, registered: set[str]) -> None:
        self._registered = registered
        self.post_final = AsyncMock()

    def destination_for(self, thread_id: str) -> object | None:
        return object() if thread_id in self._registered else None


def _client(app: Any) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 40000))
    return httpx.AsyncClient(transport=transport, base_url="http://webhooks")


async def test_run_complete_posts_for_registered_slack_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    notifier = _StubNotifier({"T-slack"})
    gw = AsyncMock()
    app = create_app(_webapp_cfg(), gw, notifier)
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/run-complete",
            headers={"Authorization": f"Bearer {_TOKEN}"},
            json={"thread_id": "T-slack", "status": "success", "final_text": "all clear"},
        )
    assert resp.status_code == 204
    notifier.post_final.assert_awaited_once_with("T-slack", "all clear")


async def test_run_complete_skips_unregistered_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    notifier = _StubNotifier(set())  # nothing registered
    gw = AsyncMock()
    app = create_app(_webapp_cfg(), gw, notifier)
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/run-complete",
            headers={"Authorization": f"Bearer {_TOKEN}"},
            json={"thread_id": "T-webhook", "status": "success", "final_text": "x"},
        )
    assert resp.status_code == 204
    notifier.post_final.assert_not_awaited()


async def test_run_complete_no_notifier_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default (notifier=None) path is unchanged — still 204, no Slack interaction."""
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_webapp_cfg(), AsyncMock())  # no notifier arg
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/run-complete",
            headers={"Authorization": f"Bearer {_TOKEN}"},
            json={"thread_id": "T-slack", "status": "success"},
        )
    assert resp.status_code == 204


# -- startup config errors (opt-in, fail-closed) -------------------------------------------


def test_require_env_unset_name_raises() -> None:
    with pytest.raises(RuntimeError, match="bot_token_env"):
        _require_env(None, "bot_token_env")


def test_require_env_unset_value_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOME_SLACK_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="unset"):
        _require_env("SOME_SLACK_TOKEN", "app_token_env")


def test_require_env_returns_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOME_SLACK_TOKEN", "xapp-123")
    assert _require_env("SOME_SLACK_TOKEN", "app_token_env") == "xapp-123"


# -- I-1: the `slack` extra is sufficient to import the live async wiring -------------------


def test_slack_extra_can_build_async_app() -> None:
    """The `slack` extra pulls the aiohttp that slack-bolt's async surface needs to start.

    slack-bolt 1.30.0's `AsyncApp` (and the default `AsyncSocketModeHandler`) require `aiohttp` — a
    transitive dep of the already-listed async surface that the extra now pulls. This RUNS in the
    synced dev env (proving the gap is closed) and skips cleanly if aiohttp is somehow absent.
    """
    pytest.importorskip("aiohttp")  # part of the `slack` extra's async surface
    app = build_bolt_app(MagicMock(), bot_token="xoxb-test")
    # A live AsyncApp exposes the decorator registries the shims use — construction alone would have
    # raised ModuleNotFoundError: aiohttp before the extra was fixed.
    assert hasattr(app, "event")
    assert hasattr(app, "action")
    assert hasattr(app, "view")
