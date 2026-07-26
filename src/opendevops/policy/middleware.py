"""``PolicyMiddleware`` — authorize, audit, gate, and cache every tool call.

This is the integration heart of the safety core: the ``awrap_tool_call`` hook every tool call
passes through. The pipeline is::

    read context -> run-scoped cache-check -> engine.decide -> audit(decision) -> gate+execute
                -> audit(execution) -> cache the result

Fail-closed invariant: *any* exception raised inside this middleware's own code becomes a
``__fail_closed__`` deny ``ToolMessage`` plus a best-effort ``policy_error`` audit event. The
middleware never raises into the graph — a bug in authorization must stop a tool, never crash
the run.

Interfaces consumed (their real APIs are ground truth):
* engine — ``await engine.decide(ToolCallCtx) -> Decision``; an escalate ``Decision`` carries
  only effect+rule_id+reason (the ``Escalation`` payload is resolved via
  ``loaded.rules_by_id[rule_id]``), a rewrite carries ``rewritten_argv`` + the winning allow's
  ``channel``.
* run_command tool — the ``current_decision`` ``ExecDecision`` gate (set/reset around the
  run_command handler) and the exec-meta return channel: run_command tags its returned
  ToolMessage's ``additional_kwargs[EXEC_META_KEY]`` with the per-exec audit facts (set only
  when the tool actually ran), which :func:`_pop_exec_meta` reads and strips here.
* audit — ``AuditLogger.append(run_id, EventType, ...)``; the run chain is seeded by the
  gateway's ``start_run`` (unit tests seed it themselves).
* loader — ``LoadedPolicy.tool_family_by_rule`` (winning rule -> credential family) and
  ``rules_by_id`` (escalation payload), plus ``policy_version``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Literal, cast

from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
from langchain_core.messages import ToolCall, ToolMessage
from langgraph.errors import GraphBubbleUp
from langgraph.types import Command, interrupt

from opendevops.audit.logger import AuditLogger
from opendevops.audit.schema import EventType, canonical_dumps
from opendevops.control_plane import ChangeControlError, ChangeControlService
from opendevops.observability.otel import observe_operation, span
from opendevops.policy.engine import RUN_COMMAND, PolicyEngine
from opendevops.policy.loader import LoadedPolicy
from opendevops.policy.parsing import ParseError, parse_argv
from opendevops.policy.schema import RULE_FAIL_CLOSED, Decision, ToolCallCtx
from opendevops.state import DevOpsState
from opendevops.tools.run_command import EXEC_META_KEY, ExecDecision, current_decision
from opendevops.tools.ssh_run import SSH_RUN_NAME as SSH_RUN

logger = logging.getLogger(__name__)

# Fallbacks when the runtime context is missing (a misconfigured boot). ``run_id`` and
# ``environment`` have NO safe DECISION fallback — a missing run_id breaks audit correlation and a
# missing environment would silently apply the staging allow set — so ``_read_context`` fails
# closed on either. ``_DEFAULT_ENVIRONMENT`` survives only to LABEL the best-effort ``policy_error``
# audit event on the fail-closed path (recording an error, never gating a tool).
_DEFAULT_ENVIRONMENT = "staging"
_UNKNOWN_PRINCIPAL = "unknown"
_UNKNOWN_INTERFACE = "unknown"

# Max chars of the (already scrubbed) tool output copied into the audit execution excerpt.
_STDOUT_EXCERPT_MAX = 2000


class PolicyMiddleware(AgentMiddleware[DevOpsState, Any, Any]):
    """Wrap every tool call with policy authorization, audit, the exec gate, and a result cache.

    Constructor (expanded from the ``(engine, audit)`` sketch to carry the interfaces the
    integration actually needs — the LoadedPolicy for tool_family/escalation/policy_version and
    the model id for audit provenance):

    * ``engine`` — the ``PolicyEngine`` (``YamlRuleEngine`` today; OPA later).
    * ``audit`` — the ``AuditLogger``. The run chain must already be started (the gateway
      calls ``start_run``); if it is not, an ``append`` raises and the fail-closed wrapper turns
      it into a deny with no crash.
    * ``loaded`` — the ``LoadedPolicy`` (``tool_family_by_rule``, ``rules_by_id``,
      ``policy_version``).
    * ``model`` — the ``provider:model`` string recorded on every audit event.
    * ``policy_version`` — overrides ``loaded.policy_version`` if given (else derived from it).
    """

    state_schema = DevOpsState

    def __init__(
        self,
        engine: PolicyEngine,
        audit: AuditLogger,
        loaded: LoadedPolicy,
        model: str,
        *,
        policy_version: str | None = None,
        change_control: ChangeControlService | None = None,
    ) -> None:
        super().__init__()
        self._engine = engine
        self._audit = audit
        self._loaded = loaded
        self._model = model
        self._policy_version = policy_version or loaded.policy_version
        self._change_control = change_control

    # -- entrypoint -------------------------------------------------------------------------

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        tool_call = request.tool_call
        tool_call_id = str(tool_call.get("id") or "")
        tool_name = str(tool_call.get("name") or "")
        args = dict(tool_call.get("args") or {})
        try:
            return await self._pipeline(request, handler, tool_call_id, tool_name, args)
        except GraphBubbleUp:
            # LangGraph control flow (GraphInterrupt from interrupt()/HITL, ParentCommand)
            # subclasses Exception but is NOT an error: it must propagate for suspend/resume
            # to work. Converting it into a fail-closed deny would break every interrupt
            # flow — including the escalate path that calls interrupt() inside this very
            # pipeline. (asyncio.CancelledError is a BaseException and propagates anyway.)
            raise
        except Exception as exc:  # noqa: BLE001 - fail-closed: nothing escapes into the graph
            logger.exception("PolicyMiddleware failed closed for tool_call %r", tool_call_id)
            return self._fail_closed(request, tool_call_id, tool_name, exc)

    # -- pipeline ---------------------------------------------------------------------------

    async def _pipeline(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
        tool_call_id: str,
        tool_name: str,
        args: dict[str, Any],
    ) -> ToolMessage | Command[Any]:
        # 1. Runtime context (environment / principal / interface / run_id). A run_id is required
        #    before reading the replay cache because checkpointer state survives across turns.
        env, principal, interface, run_id = self._read_context(request.runtime)

        # 2. Execution-cache check. The key binds run + call id + canonical tool payload, so a
        #    provider reusing an id on a later run (or for divergent args) cannot replay stale
        #    output without authorization. It still absorbs exact LangGraph interrupt/resume
        #    re-execution within the same run.
        cache_key = _cache_key(run_id, tool_call_id, tool_name, args)
        cache = _read_cache(request.state)
        if tool_call_id and cache_key in cache:
            return ToolMessage(
                content=cache[cache_key], tool_call_id=tool_call_id, name=tool_name
            )

        # 3. Authorize. For run_command, surface the virtual-FS ``files`` and the recorded
        #    ``dry_run_ok`` shas from state so the dry_run_before_apply hook can verify a real
        #    apply against a prior successful server dry-run (None-safe; other tools get neither).
        is_run_command = tool_name == RUN_COMMAND
        ctx = ToolCallCtx(
            tool_name=tool_name,
            args=args,
            environment=env,
            principal=principal,
            run_id=run_id,
            files=_read_files(request.state) if is_run_command else None,
            dry_run_ok=_read_dry_run_ok(request.state) if is_run_command else None,
        )
        trace_id = str(
            _ctx_attr(getattr(request.runtime, "context", None), "trace_id") or ""
        )
        policy_attributes = {
            "run.id": run_id,
            "tool.call.id": tool_call_id,
            "opendevops.trace_id": trace_id,
            "opendevops.tool": tool_name,
            "opendevops.environment": env,
        }
        policy_started = time.perf_counter()
        try:
            with span("opendevops.policy.decide", policy_attributes):
                decision = await self._engine.decide(ctx)
        except Exception:
            observe_operation(
                "policy",
                (time.perf_counter() - policy_started) * 1000,
                "error",
                {"opendevops.environment": env},
            )
            raise
        policy_duration_ms = max(
            0, int((time.perf_counter() - policy_started) * 1000)
        )
        observe_operation(
            "policy",
            policy_duration_ms,
            decision.effect,
            {"opendevops.environment": env},
        )

        # Production rw actions are available only inside an active, expiring capability grant.
        # A plain allow is upgraded to an interrupt so a different approver must authorize it.
        # Server-side dry-runs still consume the grant but do not need a human decision.
        rule = self._loaded.rules_by_id.get(decision.rule_id)
        rule_channel = rule.channel if rule is not None else decision.channel
        if (
            env == "prod"
            and rule_channel == "rw"
            and decision.effect in {"allow", "rewrite", "escalate"}
            and self._change_control is not None
        ):
            family = self._loaded.tool_family_by_rule.get(decision.rule_id)
            try:
                self._change_control.require_active_grant(
                    environment=env, tool_family=family
                )
            except ChangeControlError as exc:
                decision = Decision.deny("__capability_grant__", str(exc))
            else:
                effective_argv = decision.rewritten_argv or args.get("argv")
                is_server_dry_run = (
                    isinstance(effective_argv, list)
                    and "--dry-run=server" in effective_argv
                )
                if decision.effect in {"allow", "rewrite"} and not is_server_dry_run:
                    decision = Decision.escalate(
                        decision.rule_id,
                        "production rw action requires independent human approval",
                    )

        # 4. Audit the decision (every effect, including deny/escalate — a complete record).
        self._audit_decision(
            run_id,
            principal,
            interface,
            env,
            tool_name,
            tool_call_id,
            args,
            decision,
            policy_duration_ms,
        )

        # 5. Act on the effect.
        if decision.effect == "deny":
            return self._deny_message(decision, tool_call_id, tool_name)
        if decision.effect == "escalate":
            return await self._escalate(
                request, handler, decision, tool_call_id, tool_name, args,
                run_id, principal, interface, env,
            )

        # rewrite / allow: execute (rewrite is treated as allow using the rewritten argv).
        return await self._execute(
            request, handler, decision, tool_call_id, tool_name, args,
            run_id, principal, interface, env,
        )

    async def _execute(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
        decision: Decision,
        tool_call_id: str,
        tool_name: str,
        args: dict[str, Any],
        run_id: str,
        principal: str,
        interface: str,
        env: str,
    ) -> ToolMessage | Command[Any]:
        exec_request = request
        exec_argv = args.get("argv")

        # A rewrite executes the rewritten argv: copy the tool_call onto a new request (the
        # documented immutable ``override`` pattern) so the ToolMessage the model sees matches
        # what actually ran.
        if decision.rewritten_argv is not None:
            exec_argv = list(decision.rewritten_argv)
            new_tool_call = cast(
                ToolCall, {**request.tool_call, "args": {**args, "argv": exec_argv}}
            )
            exec_request = request.override(tool_call=new_tool_call)

        # Both run_command AND ssh_run read the ``current_decision`` ExecDecision as an in-tool
        # fail-closed backstop (argv + tool_call_id must match), so the token is set for both.
        # ``exec_argv`` already resolves to the ssh remote argv for ssh_run — ssh has no rewrite
        # path, so ``decision.rewritten_argv is None`` and it is the original remote argv.
        is_decision_gated = tool_name in (RUN_COMMAND, SSH_RUN)

        channel: Literal["ro", "rw"] | None = None
        token = None
        exec_decision: ExecDecision | None = None
        if is_decision_gated:
            channel = decision.channel if decision.channel is not None else "ro"
            exec_decision = ExecDecision(
                tool_call_id=tool_call_id,
                channel=channel,
                tool_family=self._loaded.tool_family_by_rule.get(decision.rule_id),
                argv=tuple(exec_argv) if isinstance(exec_argv, list) else (),
                environment=env,
            )

        fingerprint = hashlib.sha256(
            canonical_dumps(
                {
                    "tool": tool_name,
                    "family": self._loaded.tool_family_by_rule.get(decision.rule_id),
                    "argv": exec_argv,
                }
            ).encode()
        ).hexdigest()
        if channel == "rw" and self._change_control is not None:
            try:
                self._change_control.authorize_rw(
                    run_id=run_id,
                    environment=env,
                    principal=principal,
                    tool_family=self._loaded.tool_family_by_rule.get(decision.rule_id),
                    fingerprint=fingerprint,
                )
            except ChangeControlError as exc:
                self._audit.append(
                    run_id,
                    EventType.policy_error,
                    tool_call_id=tool_call_id or None,
                    principal={"interface": interface, "user": principal},
                    environment=env,
                    model=self._model,
                    policy_version=self._policy_version,
                    tool=tool_name,
                    summary={"kind": "dangerous_action_guard", "reason": str(exc)},
                )
                return ToolMessage(
                    content=f"Denied by change control: {exc}.",
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )
        if exec_decision is not None:
            token = current_decision.set(exec_decision)
        execution_started = time.perf_counter()
        execution_status = "error"
        try:
            with span(
                "opendevops.executor.tool",
                {
                    "run.id": run_id,
                    "tool.call.id": tool_call_id,
                    "opendevops.trace_id": str(
                        _ctx_attr(getattr(request.runtime, "context", None), "trace_id")
                        or ""
                    ),
                    "opendevops.tool": tool_name,
                    "opendevops.channel": channel or "none",
                },
            ):
                result = await handler(exec_request)
                execution_status = "ok"
        finally:
            if token is not None:
                current_decision.reset(token)
            observe_operation(
                "executor",
                (time.perf_counter() - execution_started) * 1000,
                execution_status,
                {
                    "opendevops.tool": tool_name,
                    "opendevops.channel": channel or "none",
                },
            )

        # 6. Execution audit — ONLY when the tool actually ran. run_command tags its ToolMessage
        #    with EXEC_META_KEY; built-in FS tools and any refusal do not, so they get a decision
        #    event but no execution event. _pop_exec_meta also strips the key, so it never reaches
        #    the model or the result cache. The EXECUTED argv + channel are recorded (I1) so the
        #    command that actually ran is recoverable from the chain on every path — including an
        #    approved escalation or an edited argv, where the execution differs from the request.
        meta = _pop_exec_meta(result)
        if channel == "rw" and self._change_control is not None:
            try:
                self._change_control.record_rw_result(
                    run_id=run_id,
                    fingerprint=fingerprint,
                    succeeded=meta is not None and int(meta.get("exit_code") or 0) == 0,
                )
            except Exception:  # noqa: BLE001 - post-exec telemetry must not invite a retry
                logger.exception(
                    "failed to record dangerous-action result for run %s", run_id
                )
        if meta is not None:
            self._audit_execution(
                run_id, principal, interface, env, tool_name, tool_call_id, meta, result,
                exec_argv, channel,
            )

        # 6b. Dry-run recording — a successful (exit 0) server-side dry-run of a staged manifest
        #     records each applied manifest's RUN-SCOPED sha (``{run_id}:{sha256}``) in the
        #     ``dry_run_ok`` state channel, which the dry_run_before_apply hook consults to permit a
        #     later real apply of the same manifest *in the same run*. Run-scoping is required
        #     because the checkpointer persists this channel across turns on a thread: a bare-sha
        #     key would let a turn-N server dry-run silently approve a turn-N+1 real apply with no
        #     fresh (current-cluster) validation. See the builtin_hooks lookup.
        dry_run_ok = _dry_run_ok_update(exec_argv, meta, run_id) if meta is not None else None

        # 7. Cache the result into state (via a Command) so a resume re-execution is absorbed;
        #    the dry-run recording (if any) rides on the same Command update.
        content = _result_content(result)
        if content is not None and tool_call_id:
            return _with_cache(
                result,
                _cache_key(run_id, tool_call_id, tool_name, args),
                content,
                dry_run_ok,
            )
        return result

    # -- context ----------------------------------------------------------------------------

    def _read_context(self, runtime: Any) -> tuple[str, str, str, str]:
        context = getattr(runtime, "context", None)
        env = _ctx_attr(context, "environment")
        principal = _ctx_attr(context, "principal") or _UNKNOWN_PRINCIPAL
        interface = _ctx_attr(context, "interface") or _UNKNOWN_INTERFACE
        run_id = _ctx_attr(context, "run_id")
        if not run_id:
            # No safe fallback: without a run_id the audit chain cannot be correlated. Fail
            # closed (the outer wrapper turns this into a deny + best-effort policy_error).
            raise ValueError("no run_id in runtime context; cannot correlate audit")
        if not env:
            # No safe fallback either: defaulting a missing environment to "staging" would
            # silently apply the staging allow set to a run whose environment is unknown (a
            # privilege escalation). Fail closed instead — same posture as the missing run_id.
            raise ValueError("no environment in runtime context; refusing to guess an overlay")
        return str(env), str(principal), str(interface), str(run_id)

    # -- effect -> ToolMessage --------------------------------------------------------------

    @staticmethod
    def _deny_message(decision: Decision, tool_call_id: str, tool_name: str) -> ToolMessage:
        content = f"Denied by policy [{decision.rule_id}]: {decision.reason}."
        if decision.hint:
            content += f" {decision.hint}"
        return ToolMessage(
            content=content, tool_call_id=tool_call_id, name=tool_name, status="error"
        )

    async def _escalate(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
        decision: Decision,
        tool_call_id: str,
        tool_name: str,
        args: dict[str, Any],
        run_id: str,
        principal: str,
        interface: str,
        env: str,
    ) -> ToolMessage | Command[Any]:
        """Suspend the run for human review, then act on the approver's decision (HITL).

        The flow (verified against langgraph 1.2.9):

        1. Audit an ``escalation`` event. The content-bearing audit dedupe collapses the resume
           re-execution's identical re-emit, but an escalation of a DIFFERENT (edited) argv is a
           distinct event and IS recorded — so a double interrupt (edit → still-escalating →
           approve) leaves both escalations in the chain.
        2. ``interrupt(payload)`` — raises ``GraphInterrupt`` on the first pass (propagated by the
           :class:`GraphBubbleUp` carve-out in :meth:`awrap_tool_call`, suspending the run under
           the checkpointer) and, on resume via ``Command(resume={"decisions": [...]})``, RETURNS
           the resume value right here. Everything above ``interrupt`` re-runs on resume; the audit
           dedupe absorbs the identical repeats.
        3. Audit a ``resolution`` event — carries the ``approver`` the gateway injected plus the
           authorized argv (edit) / credential channel (approve), so the chain records WHAT was
           authorized. Then:
           * ``approve`` — execute via the SAME :meth:`_execute` path an allow uses, with the
             escalate rule's ``channel``. The tool runs exactly once (it never ran pre-interrupt),
             and the ``tool_call_id`` execution cache absorbs any further node re-execution.
           * ``edit``   — rebuild the argv from ``decision.args`` and RE-ENTER the full pipeline so
             the edited command is authorized from scratch (a denied edit comes back denied; a
             still-escalating edit suspends again for a second approver).
           * ``reject`` — a deny ``ToolMessage``; the model self-corrects.
        """
        argv = args.get("argv")
        rule = self._loaded.rules_by_id.get(decision.rule_id)
        esc = rule.escalation if rule is not None else None
        self._audit.append(
            run_id,
            EventType.escalation,
            tool_call_id=tool_call_id or None,
            principal={"interface": interface, "user": principal},
            environment=env,
            model=self._model,
            policy_version=self._policy_version,
            tool=tool_name,
            args={"argv": argv},
            summary={
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                "timeout_s": esc.timeout_s if esc is not None else None,
                "on_timeout": esc.on_timeout if esc is not None else "deny",
            },
        )

        payload = {
            "action_requests": [{"action": tool_name, "args": {"argv": argv}}],
            "review_configs": [
                {
                    "rule_id": decision.rule_id,
                    "reason": decision.reason,
                    "allowed_decisions": ["approve", "edit", "reject"],
                    "timeout_s": esc.timeout_s if esc is not None else None,
                }
            ],
        }
        resume = interrupt(payload)

        dec = _first_decision(resume)
        dtype = str(dec.get("type") or "reject")
        approver = str(dec.get("approver") or _UNKNOWN_PRINCIPAL)
        message = dec.get("message")

        # Resolve the argv the approver actually authorized (edit) and the credential channel an
        # approved execution will use, so the ``resolution`` event is ATTRIBUTABLE — it records
        # WHAT was authorized, not merely that someone acted (I1/M3). Without this an edited
        # command was unrecoverable from the chain and the executing approver went unrecorded.
        new_args = dec.get("args")
        new_argv = new_args.get("argv") if isinstance(new_args, dict) else None
        edited_argv = list(new_argv) if isinstance(new_argv, list) else None
        resolved_channel = rule.channel if rule is not None else decision.channel

        summary: dict[str, Any] = {
            "rule_id": decision.rule_id,
            "type": dtype,
            "message": message,
        }
        resolution_args: dict[str, Any] | None = None
        if dtype == "approve":
            # M3: record the credential channel the approved execution runs under.
            summary["channel"] = resolved_channel
        elif dtype == "edit":
            # I1: record the edited argv, so the executed command is recoverable from the chain
            # even though it differs from the originally-escalated argv.
            resolution_args = {"argv": edited_argv if edited_argv is not None else argv}

        self._audit.append(
            run_id,
            EventType.resolution,
            tool_call_id=tool_call_id or None,
            principal={"interface": interface, "user": principal},
            environment=env,
            model=self._model,
            policy_version=self._policy_version,
            tool=tool_name,
            approver=approver,
            args=resolution_args,
            summary=summary,
        )

        if dtype == "approve":
            # Execute using the escalate rule's channel (an approved escalation runs the tool,
            # so it needs the rule's credential channel — carried on the rule, resolved here from
            # ``loaded.rules_by_id`` rather than the escalate Decision, which has none).
            exec_decision = decision
            if rule is not None and rule.channel is not None:
                exec_decision = decision.model_copy(update={"channel": rule.channel})
            return await self._execute(
                request, handler, exec_decision, tool_call_id, tool_name, args,
                run_id, principal, interface, env,
            )

        if dtype == "edit":
            edited_args = dict(args)
            if edited_argv is not None:
                edited_args["argv"] = edited_argv
            edited_tool_call = cast(
                ToolCall, {**request.tool_call, "args": edited_args}
            )
            edited_request = request.override(tool_call=edited_tool_call)
            return await self._pipeline(
                edited_request, handler, tool_call_id, tool_name, edited_args
            )

        # reject (default for any non-approve/edit type, or a missing/empty decision).
        reason = str(message) if message else "escalation rejected by approver"
        return ToolMessage(
            content=f"Denied by policy [{decision.rule_id}]: {reason}.",
            tool_call_id=tool_call_id,
            name=tool_name,
            status="error",
        )

    # -- audit ------------------------------------------------------------------------------

    def _audit_decision(
        self,
        run_id: str,
        principal: str,
        interface: str,
        env: str,
        tool_name: str,
        tool_call_id: str,
        args: dict[str, Any],
        decision: Decision,
        duration_ms: int,
    ) -> None:
        self._audit.append(
            run_id,
            EventType.decision,
            tool_call_id=tool_call_id or None,
            principal={"interface": interface, "user": principal},
            environment=env,
            model=self._model,
            policy_version=self._policy_version,
            tool=tool_name,
            args=args,
            decision={
                "effect": decision.effect,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                # The audit Decision section requires a channel string; deny/escalate carry
                # none, recorded explicitly as "none".
                "channel": decision.channel or "none",
                "rewritten_argv": decision.rewritten_argv,
            },
            summary={"duration_ms": duration_ms},
        )

    def _audit_execution(
        self,
        run_id: str,
        principal: str,
        interface: str,
        env: str,
        tool_name: str,
        tool_call_id: str,
        meta: dict[str, Any],
        result: ToolMessage | Command[Any],
        exec_argv: Any = None,
        channel: str | None = None,
    ) -> None:
        self._audit.append(
            run_id,
            EventType.execution,
            tool_call_id=tool_call_id,
            principal={"interface": interface, "user": principal},
            environment=env,
            model=self._model,
            policy_version=self._policy_version,
            tool=tool_name,
            # The frozen audit Execution section has no scrub_count / argv / channel field; surface
            # the secret-scrub count AND the EXECUTED argv + credential channel on the generic
            # event ``args`` so the metric is kept and the executed command is attributable (I1).
            args={
                "scrub_count": meta.get("scrub_count"),
                "argv": list(exec_argv) if isinstance(exec_argv, list) else None,
                "channel": channel,
            },
            execution={
                "exit_code": meta["exit_code"],
                "duration_ms": meta["duration_ms"],
                "stdout_sha256": meta["stdout_sha256"],
                "stdout_excerpt": _excerpt(result),
                "truncated": meta["truncated"],
                "staged_files": _staged_files(result, meta),
            },
        )

    def _fail_closed(
        self,
        request: ToolCallRequest,
        tool_call_id: str,
        tool_name: str,
        exc: Exception,
    ) -> ToolMessage:
        # Best-effort policy_error audit; if we cannot even resolve a run_id or the append
        # itself raises (e.g. the run was never started), swallow it — never raise into the graph.
        try:
            context = getattr(request.runtime, "context", None)
            run_id = _ctx_attr(context, "run_id")
            if run_id:
                self._audit.append(
                    str(run_id),
                    EventType.policy_error,
                    tool_call_id=tool_call_id or None,
                    principal={
                        "interface": _ctx_attr(context, "interface") or _UNKNOWN_INTERFACE,
                        "user": _ctx_attr(context, "principal") or _UNKNOWN_PRINCIPAL,
                    },
                    environment=_ctx_attr(context, "environment") or _DEFAULT_ENVIRONMENT,
                    model=self._model,
                    policy_version=self._policy_version,
                    tool=tool_name,
                    args={"error": str(exc)},
                )
        except Exception:  # noqa: BLE001 - audit is best-effort; the deny below still returns
            logger.exception("failed to write policy_error audit event")
        content = (
            f"Denied by policy [{RULE_FAIL_CLOSED}]: policy middleware internal error; "
            "failing closed."
        )
        return ToolMessage(
            content=content, tool_call_id=tool_call_id, name=tool_name, status="error"
        )


# --------------------------------------------------------------------------------------
# module-level helpers (pure; no self)
# --------------------------------------------------------------------------------------


def _ctx_attr(context: Any, name: str) -> Any:
    """Read ``name`` from the runtime context (attribute for a dataclass/model, key for a dict)."""
    if context is None:
        return None
    value = getattr(context, name, None)
    if value is None and isinstance(context, dict):
        value = context.get(name)
    return value


def _first_decision(resume: Any) -> dict[str, Any]:
    """The first decision dict from an ``interrupt()`` resume value, or ``{}`` (→ reject).

    Resume shape is ``{"decisions": [{"type": ..., "args"?, "message"?, "approver"?}]}`` (the
    deepagents-compatible envelope the gateway builds). A malformed or empty resume yields ``{}``,
    which the caller treats as a reject — fail-safe (never execute on an unreadable approval).
    """
    if isinstance(resume, Mapping):
        decisions = resume.get("decisions")
        if isinstance(decisions, list) and decisions and isinstance(decisions[0], Mapping):
            return dict(decisions[0])
    return {}


def _read_cache(state: Any) -> dict[str, str]:
    """The ``tool_results_cache`` from the agent state (dict or BaseModel), or an empty map."""
    if isinstance(state, dict):
        cache = state.get("tool_results_cache")
    else:
        cache = getattr(state, "tool_results_cache", None)
    return cache if isinstance(cache, dict) else {}


def _cache_key(
    run_id: str, tool_call_id: str, tool_name: str, args: Mapping[str, Any]
) -> str:
    """Bind a replay-cache entry to the run and exact canonical tool request."""
    payload = canonical_dumps({"tool": tool_name, "args": dict(args)})
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{run_id}:{tool_call_id}:{digest}"


def _read_state_key(state: Any, key: str) -> Any:
    """Read ``key`` off the agent state (mapping or object), or ``None``."""
    if isinstance(state, Mapping):
        return state.get(key)
    return getattr(state, key, None)


def _read_files(state: Any) -> Mapping[str, Any] | None:
    """The deepagents virtual-FS ``files`` mapping from state, or ``None`` when absent."""
    files = _read_state_key(state, "files")
    return files if isinstance(files, Mapping) else None


def _read_dry_run_ok(state: Any) -> Mapping[str, bool] | None:
    """The recorded ``dry_run_ok`` sha->True map from state, or ``None`` when absent."""
    recorded = _read_state_key(state, "dry_run_ok")
    return recorded if isinstance(recorded, Mapping) else None


def _executed_server_dry_run(exec_argv: Any) -> bool:
    """True iff the EXECUTED argv carried ``--dry-run=server`` (parsed, so ``=`` and space forms).

    Best-effort: the argv already parsed cleanly at decide time, but a parse surprise here simply
    means "do not record" (a missed recording only costs a later re-dry-run, never safety).
    """
    if not isinstance(exec_argv, list):
        return False
    try:
        parsed = parse_argv(exec_argv)
    except ParseError:
        return False
    return parsed.flags.get("--dry-run") == "server"


def _dry_run_ok_update(
    exec_argv: Any, meta: dict[str, Any], run_id: str
) -> dict[str, bool] | None:
    """``{run_id:sha: True}`` per staged manifest iff a server dry-run just succeeded, else None.

    Recording requires ALL of: exit 0, an executed argv carrying ``--dry-run=server``, and at
    least one ``staged_files`` entry (the applied manifest). Anything else records nothing. Keys
    are RUN-SCOPED (``{run_id}:{sha256}``) so a dry-run recorded on one turn cannot validate a real
    apply on a later turn of the same checkpointed thread — the ``dry_run_before_apply`` hook looks
    up the identically-scoped key ``f"{ctx.run_id}:{sha}"``.
    """
    if meta.get("exit_code") != 0:
        return None
    if not _executed_server_dry_run(exec_argv):
        return None
    shas = {
        f"{run_id}:{f.get('sha256')}": True
        for f in meta.get("staged_files") or []
        if f.get("sha256")
    }
    return shas or None


def _terminal_message(result: ToolMessage | Command[Any]) -> ToolMessage | None:
    """The tool's terminating ToolMessage — returned directly, or inside a Command's messages."""
    if isinstance(result, ToolMessage):
        return result
    if isinstance(result, Command) and isinstance(result.update, dict):
        for message in result.update.get("messages", []) or []:
            if isinstance(message, ToolMessage):
                return message
    return None


def _pop_exec_meta(result: ToolMessage | Command[Any]) -> dict[str, Any] | None:
    """Extract and remove run_command's per-exec audit meta from the returned ToolMessage.

    run_command carries the meta on ``additional_kwargs[EXEC_META_KEY]`` because the ContextVar it
    once used does not survive langchain's ``tool.ainvoke`` context-copy boundary. Reading it here
    — and stripping it, so the model and the result cache never carry it — is what lets the
    execution audit event fire in the real graph. Absence of the key means the tool did not run
    (built-in FS tools / refusals), so no execution event is emitted.
    """
    message = _terminal_message(result)
    if message is None:
        return None
    meta = message.additional_kwargs.pop(EXEC_META_KEY, None)
    return meta if isinstance(meta, dict) else None


def _result_content(result: ToolMessage | Command[Any]) -> str | None:
    """The string content of the tool's ToolMessage (unwrapping a Command), or None."""
    message = _terminal_message(result)
    return None if message is None else _as_text(message.content)


def _as_text(content: Any) -> str:
    return content if isinstance(content, str) else str(content)


def _with_cache(
    result: ToolMessage | Command[Any],
    cache_key: str,
    content: str,
    dry_run_ok: dict[str, bool] | None = None,
) -> Command[Any]:
    """Return a Command that delivers ``result`` AND persists the cache entry into state.

    * A tool that returned a ``Command`` (e.g. run_command's truncation spill) is passed through
      with its ``files`` / ``messages`` updates intact — only an additive ``tool_results_cache``
      key (and, when a server dry-run just succeeded, ``dry_run_ok``) is merged in, so the model
      still sees exactly what ran.
    * A plain ``ToolMessage`` is wrapped in a Command whose ``messages`` update delivers it and
      whose ``tool_results_cache`` update records it.

    Both state updates go through the ``DevOpsState`` dict-merge reducers, so they accumulate
    across tool calls rather than clobbering earlier entries.
    """
    extra: dict[str, Any] = {"tool_results_cache": {cache_key: content}}
    if dry_run_ok:
        extra["dry_run_ok"] = dry_run_ok
    if isinstance(result, Command):
        if isinstance(result.update, dict):
            return dataclasses.replace(result, update={**result.update, **extra})
        return result  # unusual Command shape (non-dict update): pass through, do not cache
    return Command(update={"messages": [result], **extra})


def _excerpt(result: ToolMessage | Command[Any]) -> str:
    content = _result_content(result)
    return "" if content is None else content[:_STDOUT_EXCERPT_MAX]


def _staged_files(
    result: ToolMessage | Command[Any], meta: dict[str, Any]
) -> list[dict[str, str]]:
    """Record the files this execution touched, by virtual path + content sha256.

    Two sources, concatenated:
    * ``meta["staged_files"]`` — the staging bridge's record of virtual-FS manifests it
      materialized for file-consuming flags (``kubectl apply -f`` etc.). The applied manifest
      is exactly what audit must capture, and the dry-run hook keys on these shas.
    * the truncation-spill Command's ``files`` update — the spilled full-output file,
      hashed by ``stdout_sha256`` (the spill content IS the scrubbed output).
    """
    staged: list[dict[str, str]] = [
        {"path": str(f.get("path", "")), "sha256": str(f.get("sha256", ""))}
        for f in meta.get("staged_files") or []
    ]
    if isinstance(result, Command) and isinstance(result.update, dict):
        files = result.update.get("files") or {}
        sha = str(meta.get("stdout_sha256", ""))
        staged.extend({"path": path, "sha256": sha} for path in files)
    return staged
