"""Identity isolation and state-machine tests for durable dashboard chat."""

from __future__ import annotations

from pathlib import Path

import pytest

from opendevops.control_plane import ActionIdentity
from opendevops.interfaces.dashboard_chat import DashboardChatError, DashboardChatStore


def _actor(subject: str) -> ActionIdentity:
    return ActionIdentity(
        issuer="https://identity.example.test",
        subject=subject,
        display_name=subject,
    )


def test_chat_threads_and_messages_are_scoped_to_exact_identity(tmp_path: Path) -> None:
    database = tmp_path / "control-plane.sqlite3"
    store = DashboardChatStore(database)
    owner = _actor("operator-a")
    other = _actor("operator-b")

    thread = store.create("thread-private", owner, "prod")
    store.begin_turn(thread.thread_id, owner, "What is failing in production?")
    store.append(
        thread.thread_id,
        role="assistant",
        kind="message",
        content="The API deployment is degraded.",
        run_id="run-1",
    )
    store.finish_turn(thread.thread_id, awaiting_approval=False, run_id="run-1")

    assert [item.thread_id for item in store.list_threads(owner)] == ["thread-private"]
    assert store.list_threads(other) == []
    assert [item.role for item in store.messages(thread.thread_id, owner)] == [
        "user",
        "assistant",
    ]
    with pytest.raises(DashboardChatError, match="not found"):
        store.get(thread.thread_id, other)
    with pytest.raises(DashboardChatError, match="not found"):
        store.messages(thread.thread_id, other)
    assert database.stat().st_mode & 0o777 == 0o600


def test_chat_turn_state_blocks_overlap_and_waits_for_approval(tmp_path: Path) -> None:
    store = DashboardChatStore(tmp_path / "control-plane.sqlite3")
    actor = _actor("operator")
    store.create("thread-state", actor, "staging")

    running = store.begin_turn("thread-state", actor, "Inspect the cluster")
    assert running.status == "running"
    assert running.title == "Inspect the cluster"
    with pytest.raises(DashboardChatError, match="already active"):
        store.begin_turn("thread-state", actor, "Overlap this run")

    store.finish_turn("thread-state", awaiting_approval=True, run_id="run-approval")
    with pytest.raises(DashboardChatError, match="waiting for an approval"):
        store.begin_turn("thread-state", actor, "Skip the approval")

    store.cancel("thread-state", actor)
    restarted = store.begin_turn("thread-state", actor, "Continue safely")
    assert restarted.status == "running"
    assert restarted.title == "Inspect the cluster"


def test_idle_chat_threads_expire_after_configured_retention(tmp_path: Path) -> None:
    clock = [1_000_000.0]
    store = DashboardChatStore(
        tmp_path / "control-plane.sqlite3",
        retention_days=1,
        now=lambda: clock[0],
    )
    actor = _actor("operator")
    store.create("thread-expiring", actor, "staging")

    clock[0] += 86_401

    assert store.list_threads(actor) == []
    with pytest.raises(DashboardChatError, match="not found"):
        store.get("thread-expiring", actor)
