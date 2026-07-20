"""``ReplayToolMiddleware`` — a test-tier ``AgentMiddleware`` that replays canned executions (T15).

The P2 eval harness runs the **real** policy/audit/budget stack (via ``build_agent``) but swaps the
one dangerous, non-deterministic surface — the ``run_command`` subprocess — for hand-written canned
output. That lets a golden trajectory + mechanical audit gates assert end-to-end behaviour with
``$0`` LLM/cluster cost, and it is the regression net that makes the pinned trio upgradable.

Placement — INNERMOST (verified empirically, see ``tests/replay/conftest.py``)
------------------------------------------------------------------------------
Middleware ``awrap_tool_call`` handlers nest in list order: the **last** middleware is the
innermost wrap, closest to the real tool. ``build_agent`` already puts ``PolicyMiddleware`` last so
its authorization sits closest to execution. This middleware is appended *after* it (a test-only
seam that monkeypatches ``opendevops.agent.create_deep_agent`` to extend the list),
so it is even more innermost:

    ... -> PolicyMiddleware.awrap_tool_call (decide + audit + gate)
            -> handler -> ReplayToolMiddleware.awrap_tool_call (canned result, no execution)

The consequences we rely on (and assert in the harness):

* Policy still **decides and audits** every call — that is exactly what the harness tests. Replay
  only replaces the *execution*.
* A **denied** call is short-circuited by ``PolicyMiddleware`` *before* it calls ``handler`` — so a
  deny never reaches replay and never consumes a fixture step. (This is why a denied call cannot
  smuggle an execution: there is nothing to replay.)
* A **rewrite** (e.g. ``force-server-dry-run-first`` appending ``--dry-run=server``) is applied by
  ``PolicyMiddleware`` *before* it calls ``handler``, so the ``argv`` this middleware sees — and
  matches a fixture step against — is the **executed** (rewritten) argv, not what the model asked
  for. Fixture steps therefore carry the executed argv (the golden *trajectory* keeps the
  model-requested argv; the two differ only for a rewrite).

Faithful exec-meta
------------------
A canned ``run_command`` result is built to look **byte-for-byte** like a real one so
``PolicyMiddleware`` writes execution events + ``dry_run_ok`` recordings exactly as live:

* the content is ``f"exit_code: {code}\\n{scrubbed_output}"`` (the run_command wire format);
* the per-exec meta rides on ``additional_kwargs[EXEC_META_KEY]`` with the same keys run_command
  emits (``stdout_sha256``/``duration_ms``/``exit_code``/``truncated``/``scrub_count``/
  ``staged_files``), so ``PolicyMiddleware`` pops it, writes the execution event, and strips it;
* ``staged_files`` is derived from the **real** virtual-FS state via the shared
  :func:`resolve_file_refs`, so a replayed ``kubectl apply -f`` records the *same* content sha256
  the staging bridge would — which is what makes the run-scoped ``dry_run_ok`` gate permit the later
  real apply of the same manifest.

Only ``run_command`` is replayed (``replayed_tools``); the built-in virtual-FS tools
(``write_file`` etc.) run for real — they are pure, in-memory, deterministic, and scenario 2 needs
the manifest actually present in state for the staging bridge / dry-run hook to resolve it.

record mode
-----------
``ReplayToolMiddleware(mode="record", record_path=...)`` wraps the real handler and appends
``{tool, args, content, exec_meta}`` (one JSON object per line) to ``record_path`` — the tool for
capturing real kind-cluster sessions into a fixture. It never strips the meta (``PolicyMiddleware``
still needs it). Not exercised in CI yet; documented so a P3 capture run can use it.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
from langchain_core.messages import ToolMessage
from langgraph.types import Command

from opendevops.tools.run_command import EXEC_META_KEY, RUN_COMMAND_NAME
from opendevops.tools.scrub import scrub, sha256_hex, strip_ansi
from opendevops.tools.staging import resolve_file_refs


@dataclass
class ReplayStep:
    """One expected, canned ``run_command`` execution.

    * ``argv`` — the **executed** argv to match exactly (post-rewrite; see the module docstring).
    * ``output`` — the canned combined stdout+stderr (a realistic kubectl/gh snippet).
    * ``exit_code`` — the process exit code (non-zero for a failing command, e.g. a failed rollout).
    * ``tool`` — the tool name (always ``run_command`` in P2; carried for record/replay symmetry).
    * ``duration_ms`` — a fixed fake duration for the exec meta.
    """

    argv: list[str]
    output: str
    exit_code: int = 0
    tool: str = RUN_COMMAND_NAME
    duration_ms: int = 1

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReplayStep:
        """Build a step from a fixture dict (argv/output/exit_code/tool/duration_ms)."""
        return cls(
            argv=list(data["argv"]),
            output=str(data.get("output", "")),
            exit_code=int(data.get("exit_code", 0)),
            tool=str(data.get("tool", RUN_COMMAND_NAME)),
            duration_ms=int(data.get("duration_ms", 1)),
        )


class ReplayMismatch(BaseException):
    """A tool call did not match the next expected replay step (order-strict); precise diff.

    Deliberately a ``BaseException``, NOT ``Exception``: ``PolicyMiddleware.awrap_tool_call`` wraps
    its whole pipeline in ``except Exception`` and fails closed (a ``policy_error`` deny). An
    ``Exception``-derived mismatch would therefore be *swallowed* into a silent deny — a fixture bug
    would masquerade as a policy denial instead of failing the test. As a ``BaseException`` it slips
    past that catch (like ``asyncio.CancelledError``) and propagates out of ``graph.ainvoke`` to the
    test, which is exactly the "test failure with a precise diff" the eval harness requires. The
    first mismatch is also recorded on the middleware (:attr:`mismatch`) as belt-and-suspenders."""


class ReplayToolMiddleware(AgentMiddleware[Any, Any, Any]):
    """Replay canned ``run_command`` executions (or record real ones) as the innermost wrap.

    Args:
        steps: the ordered fixture steps (replay mode). Each intercepted ``run_command`` call is
            matched against the next unconsumed step (order-strict).
        replayed_tools: the tool names replay intercepts; all others pass through to the real
            handler. Defaults to ``{"run_command"}`` (the one subprocess surface).
        mode: ``"replay"`` (default) or ``"record"``.
        record_path: JSONL sink for record mode (one ``{tool, args, content, exec_meta}`` per line).
    """

    def __init__(
        self,
        steps: list[ReplayStep] | None = None,
        *,
        replayed_tools: set[str] | None = None,
        mode: str = "replay",
        record_path: str | Path | None = None,
    ) -> None:
        super().__init__()
        self._steps = list(steps or [])
        self._cursor = 0
        self._mismatch: ReplayMismatch | None = None
        self._replayed = replayed_tools if replayed_tools is not None else {RUN_COMMAND_NAME}
        self._mode = mode
        self._record_path = Path(record_path) if record_path is not None else None
        if mode == "record" and self._record_path is None:
            raise ValueError("record mode requires a record_path")

    # -- introspection (tests assert the fixture was fully consumed) -----------------------

    @property
    def consumed(self) -> int:
        """How many replay steps have been matched so far."""
        return self._cursor

    @property
    def remaining(self) -> list[ReplayStep]:
        """The replay steps not yet matched (should be empty at the end of a scenario)."""
        return self._steps[self._cursor :]

    @property
    def mismatch(self) -> ReplayMismatch | None:
        """The first replay mismatch seen, or ``None``. Recorded even though it also propagates."""
        return self._mismatch

    # -- entrypoint -----------------------------------------------------------------------

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        tool_name = str(request.tool_call.get("name") or "")

        if self._mode == "record":
            return await self._record(request, handler, tool_name)

        # Pass built-in virtual-FS tools straight through to the real handler; only the
        # subprocess surface is replayed. (Their execution is pure/deterministic and scenario 2
        # needs the written manifest actually present in state.)
        if tool_name not in self._replayed:
            return await handler(request)

        return self._replay(request, tool_name)

    # -- replay ---------------------------------------------------------------------------

    def _replay(self, request: ToolCallRequest, tool_name: str) -> ToolMessage:
        args = dict(request.tool_call.get("args") or {})
        argv = args.get("argv")
        tool_call_id = str(request.tool_call.get("id") or "")

        step = self._next_step(tool_name, argv)
        self._cursor += 1

        return self._canned_message(request, step, tool_call_id)

    def _next_step(self, tool_name: str, argv: Any) -> ReplayStep:
        if self._cursor >= len(self._steps):
            raise self._record_mismatch(
                f"unexpected extra tool call after the fixture was exhausted: "
                f"tool={tool_name!r} argv={argv!r} (fixture had {len(self._steps)} step(s))"
            )
        step = self._steps[self._cursor]
        if tool_name != step.tool or argv != step.argv:
            raise self._record_mismatch(
                "replay step mismatch at index "
                f"{self._cursor}:\n  expected tool={step.tool!r} argv={step.argv!r}"
                f"\n  actual   tool={tool_name!r} argv={argv!r}"
            )
        return step

    def _record_mismatch(self, message: str) -> ReplayMismatch:
        mismatch = ReplayMismatch(message)
        if self._mismatch is None:
            self._mismatch = mismatch
        return mismatch

    def _canned_message(
        self, request: ToolCallRequest, step: ReplayStep, tool_call_id: str
    ) -> ToolMessage:
        """Build the ToolMessage a real ``run_command`` would return for ``step``'s output.

        Mirrors ``run_command._format_result``: ANSI-strip -> scrub -> sha256(scrubbed), the
        ``exit_code:`` wire prefix, and ``staged_files`` resolved from the live virtual FS so the
        recorded manifest sha matches what the staging bridge (and the dry-run hook) computes.
        """
        argv = list(step.argv)
        scrubbed, scrub_count = scrub(strip_ansi(step.output))
        staged_files = self._staged_files(request, argv)
        meta: dict[str, Any] = {
            "stdout_sha256": sha256_hex(scrubbed),
            "duration_ms": step.duration_ms,
            "exit_code": step.exit_code,
            "truncated": False,
            "scrub_count": scrub_count,
            "staged_files": staged_files,
        }
        content = f"exit_code: {step.exit_code}\n{scrubbed}"
        return ToolMessage(
            content=content,
            tool_call_id=tool_call_id,
            name=step.tool,
            additional_kwargs={EXEC_META_KEY: meta},
        )

    @staticmethod
    def _staged_files(request: ToolCallRequest, argv: list[str]) -> list[dict[str, str]]:
        """The ``[{path, sha256}]`` for any file-consuming flag, resolved from live ``files`` state.

        Uses the same pure resolver the tool layer uses, so a replayed ``apply -f`` records the
        identical content sha256 the run-scoped ``dry_run_ok`` gate later looks up. A manifest that
        is not in state (a fixture bug) surfaces as the resolver's ``StagingError`` — a loud
        failure, exactly as a real staged apply would refuse.
        """
        files = _read_files(request.state)
        refs = resolve_file_refs(list(argv), files)
        return [{"path": r.virtual_path, "sha256": r.sha256} for r in refs]

    # -- record ---------------------------------------------------------------------------

    async def _record(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
        tool_name: str,
    ) -> ToolMessage | Command[Any]:
        """Run the real handler and append ``{tool, args, content, exec_meta}`` to the JSONL sink.

        The exec meta is *read* (not popped) so ``PolicyMiddleware`` still consumes it downstream.
        """
        result = await handler(request)
        if tool_name in self._replayed:
            message = _terminal_message(result)
            content = message.content if message is not None else None
            meta = (
                message.additional_kwargs.get(EXEC_META_KEY)
                if message is not None
                else None
            )
            record = {
                "tool": tool_name,
                "args": dict(request.tool_call.get("args") or {}),
                "content": content,
                "exec_meta": meta,
            }
            assert self._record_path is not None  # guarded in __init__
            self._record_path.parent.mkdir(parents=True, exist_ok=True)
            with self._record_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        return result


# --------------------------------------------------------------------------------------
# module-level helpers
# --------------------------------------------------------------------------------------


def _read_files(state: Any) -> Mapping[str, Any]:
    """The virtual-FS ``files`` mapping off the agent state (dict or object), else ``{}``."""
    files = _read_state_key(state, "files")
    return files if isinstance(files, Mapping) else {}


def _read_state_key(state: Any, key: str) -> Any:
    """Read ``key`` off the agent state (mapping or object), or ``None``."""
    if isinstance(state, Mapping):
        return state.get(key)
    return getattr(state, key, None)


def _terminal_message(result: ToolMessage | Command[Any]) -> ToolMessage | None:
    """The terminating ToolMessage — returned directly or inside a Command's ``messages`` update."""
    if isinstance(result, ToolMessage):
        return result
    if isinstance(result, Command) and isinstance(result.update, dict):
        for message in result.update.get("messages", []) or []:
            if isinstance(message, ToolMessage):
                return message
    return None
