"""Typer CLI: project initialization, config/audit commands, and the ``chat`` REPL.

``chat`` is the human entry point: it builds a :class:`LocalGateway` over the on-disk config
and drives a streaming REPL against it — assistant text as it arrives, tool calls as
``→ run_command …`` lines, policy denials in red with the rule id, and a per-turn cost line.
``audit verify`` wires the audit chain walker as a CI-able integrity check. The gateway build and
config load are indirected through module-level seams (:func:`_build_gateway`, ``load_config``)
so the REPL can be smoke-tested with a stub gateway.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import sys
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from opendevops import __version__
from opendevops.audit import main as audit_verify_main
from opendevops.config import load_config, validate_runtime_config
from opendevops.control_plane import (
    ActionIdentity,
    Capability,
    CapabilityGrantRequest,
    ChangeControlError,
    ChangeControlService,
)
from opendevops.gateway import (
    AssistantText,
    EscalationEvent,
    LocalGateway,
    RunEnd,
    RunResult,
    ToolCall,
    ToolResult,
)
from opendevops.observability.tracing import configure_tracing

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from opendevops.config import AppConfig
    from opendevops.gateway import AgentGateway, Escalation, RunEvent

app = typer.Typer(
    name="opendevops",
    help="Autonomous DevOps agent.",
    no_args_is_help=True,
    add_completion=False,
)
config_app = typer.Typer(help="Configuration commands.", no_args_is_help=True)
app.add_typer(config_app, name="config")
audit_app = typer.Typer(help="Audit-trail commands.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")

console = Console()
err_console = Console(stderr=True)

_PROMPT = "[bold green]you[/bold green] › "


@app.command()
def version() -> None:
    """Print the opendevops version."""
    console.print(f"opendevops {__version__}")


def _workspace_templates() -> Traversable:
    """Return wheel-embedded templates, falling back to the source checkout for contributors."""
    packaged = resources.files("opendevops").joinpath("templates")
    if packaged.joinpath("config").is_dir():
        return packaged
    return Path(__file__).resolve().parents[2]


def _resource_at(root: Traversable, relative: Path) -> Traversable:
    current = root
    for part in relative.parts:
        current = current.joinpath(part)
    return current


def _copy_resource_tree(source: Traversable, destination: Path) -> None:
    if source.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        for child in source.iterdir():
            _copy_resource_tree(child, destination / child.name)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source.read_bytes())
    if destination.suffix == ".sh":
        destination.chmod(0o755)


@app.command("init")
def init_workspace(
    directory: Path = typer.Argument(  # noqa: B008
        Path("."), help="Directory in which to create the opendevops workspace."
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace existing generated files. Extra user files are preserved.",
    ),
) -> None:
    """Create starter config, environment template, and Kubernetes bootstrap files."""
    destination = directory.expanduser().resolve()
    templates = _workspace_templates()
    paths = (Path("config"), Path("ops/k8s"), Path(".env.example"))
    conflicts = [relative for relative in paths if (destination / relative).exists()]
    if conflicts and not force:
        rendered = ", ".join(str(path) for path in conflicts)
        err_console.print(
            f"[red]init refused:[/red] {rendered} already exists under {destination}. "
            "Choose an empty directory or pass --force."
        )
        raise typer.Exit(code=1)

    destination.mkdir(parents=True, exist_ok=True)
    for relative in paths:
        _copy_resource_tree(
            _resource_at(templates, relative),
            destination / relative,
        )
    console.print(f"[green]workspace initialized[/green] at {destination}")
    console.print(
        "Next: copy .env.example to .env, set ANTHROPIC_API_KEY, scope your credentials, "
        "then run `opendevops config check`."
    )


@config_app.command("check")
def config_check() -> None:
    """Load and validate config; print a one-line OK with counts, or the validation error."""
    try:
        cfg = load_config()
        validate_runtime_config(cfg)
    except Exception as exc:  # noqa: BLE001 - surface any load/validation failure to the user
        err_console.print(f"[red]config INVALID:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    contexts = len(cfg.targets.kubernetes.allowed_contexts)
    profiles = len(cfg.budgets.per_run.profiles)
    priced = len(cfg.models.pricing)
    console.print(
        f"[green]config OK[/green]: {contexts} contexts allowed, "
        f"{profiles} budget profiles, {priced} priced models"
    )


def _control_actor(cfg: AppConfig, actor: str | None, required_role: str) -> ActionIdentity:
    subject = actor or _default_principal()
    mapped = cfg.principals.get(subject)
    roles = set(mapped.roles) if mapped is not None else set()
    # Static auth is explicitly the local-development mode; mirror its local admin session for the
    # OS user. OIDC deployments must map CLI identities explicitly under principals.
    if cfg.server.dashboard_auth_mode == "static" and mapped is None:
        roles = {"viewer", "operator", "approver", "admin"}
    allowed = {
        "viewer": {"viewer", "operator", "approver", "admin"},
        "operator": {"operator", "admin"},
        "approver": {"approver", "admin"},
        "admin": {"admin"},
    }[required_role]
    if not roles & allowed:
        raise ChangeControlError(
            f"CLI identity {subject!r} lacks the required {required_role} role"
        )
    return ActionIdentity(issuer="cli-local", subject=subject)


def _change_service() -> tuple[AppConfig, ChangeControlService]:
    cfg = load_config()
    return cfg, ChangeControlService(cfg.control_plane)


@config_app.command("grants")
def config_grants() -> None:
    """List versioned dangerous-capability proposals and active grants."""
    cfg, service = _change_service()
    _control_actor(cfg, None, "viewer")
    console.print(f"[dim]revision {service.revision()}[/dim]")
    proposals = service.list()
    if not proposals:
        console.print("No capability proposals.")
        return
    for proposal in proposals:
        console.print(
            f"[bold]{proposal.proposal_id}[/bold] "
            f"{proposal.status.value} {proposal.request.environment}/"
            f"{proposal.request.capability.value} "
            f"targets={','.join(proposal.request.targets)} "
            f"used={proposal.executions_used}/{proposal.request.max_executions}"
        )


@config_app.command("propose-grant")
def config_propose_grant(
    capability: Capability = typer.Option(..., "--capability"),  # noqa: B008
    target: list[str] = typer.Option(  # noqa: B008
        ..., "--target", help="Repeat for each explicit target."
    ),
    reason: str = typer.Option(..., "--reason"),
    environment: str = typer.Option("staging", "--environment"),
    ttl_s: int = typer.Option(3600, "--ttl"),
    max_executions: int = typer.Option(10, "--max-executions"),
    actor: str | None = typer.Option(None, "--actor"),
) -> None:
    """Propose an expiring, bounded capability grant through the shared control ledger."""
    try:
        cfg, service = _change_service()
        identity = _control_actor(cfg, actor, "operator")
        proposal = service.propose(
            CapabilityGrantRequest(
                capability=capability,
                targets=target,
                reason=reason,
                environment=environment,
                ttl_s=ttl_s,
                max_executions=max_executions,
            ),
            identity,
        )
    except Exception as exc:  # noqa: BLE001 - CLI surfaces validation/refusal without traceback
        err_console.print(f"[red]proposal refused:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(
        f"[green]proposal created[/green] {proposal.proposal_id} "
        f"revision={proposal.revision} status={proposal.status.value}"
    )


@config_app.command("approve-grant")
def config_approve_grant(
    proposal_id: str,
    actor: str | None = typer.Option(None, "--actor"),
) -> None:
    """Approve a pending grant; production rejects requester self-approval."""
    try:
        cfg, service = _change_service()
        proposal = service.approve(
            proposal_id, _control_actor(cfg, actor, "approver")
        )
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]approval refused:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]approved[/green] {proposal.proposal_id} revision={proposal.revision}")


@config_app.command("activate-grant")
def config_activate_grant(
    proposal_id: str,
    actor: str | None = typer.Option(None, "--actor"),
) -> None:
    """Activate an approved grant as an admin (a distinct lifecycle step)."""
    try:
        cfg, service = _change_service()
        proposal = service.activate(proposal_id, _control_actor(cfg, actor, "admin"))
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]activation refused:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]active[/green] {proposal.proposal_id} revision={proposal.revision}")


@config_app.command("revoke-grant")
def config_revoke_grant(
    proposal_id: str,
    actor: str | None = typer.Option(None, "--actor"),
) -> None:
    """Immediately revoke a proposed, approved, or active grant."""
    try:
        cfg, service = _change_service()
        proposal = service.revoke(proposal_id, _control_actor(cfg, actor, "admin"))
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]revocation refused:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[yellow]revoked[/yellow] {proposal.proposal_id} revision={proposal.revision}")


@audit_app.command("verify")
def audit_verify(
    dir: Path = typer.Option(  # noqa: B008 - typer.Option belongs in the signature default
        Path("./audit"), "--dir", help="Directory of per-run <run_id>.jsonl chain files."
    ),
    allow_incomplete: bool = typer.Option(
        False,
        "--allow-incomplete",
        help="Accept structurally valid runs without a terminal run_completed event.",
    ),
) -> None:
    """Strictly verify every audit chain under --dir; exit 1 on corruption or truncation."""
    code = audit_verify_main(dir, allow_incomplete=allow_incomplete)
    raise typer.Exit(code=code)


@app.command()
def chat(
    environment: str = typer.Option("staging", "--environment", help="Policy environment overlay."),
    profile: str = typer.Option("interactive", "--profile", help="Per-run budget profile."),
    principal: str = typer.Option(
        None, "--principal", help="Agent principal (defaults to the OS user)."
    ),
) -> None:
    """Interactive streaming REPL over the local agent gateway."""
    principal = principal or _default_principal()

    try:
        cfg = load_config()
    except Exception as exc:  # noqa: BLE001 - surface any load/validation failure to the user
        err_console.print(f"[red]config INVALID:[/red] {exc}")
        err_console.print("Fix the config and re-run `opendevops config check` to validate.")
        raise typer.Exit(code=1) from exc

    if not cfg.targets.kubernetes.allowed_contexts:
        _print_empty_contexts_help()
        raise typer.Exit(code=1)

    configure_tracing(cfg)

    try:
        gateway = _build_gateway(cfg)
    except Exception as exc:  # noqa: BLE001 - a build failure should not dump a traceback at users
        err_console.print(f"[red]could not start agent:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _run_repl(gateway, environment=environment, profile=profile, principal=principal)


# --------------------------------------------------------------------------------------
# REPL internals (seams the tests drive)
# --------------------------------------------------------------------------------------


def _build_gateway(cfg: AppConfig) -> AgentGateway:
    """Construct the production gateway (a seam tests monkeypatch with a stub)."""
    return LocalGateway(cfg)


def _default_principal() -> str:
    """The default agent principal: ``$USER`` or the OS login name."""
    return os.environ.get("USER") or getpass.getuser()


def _print_empty_contexts_help() -> None:
    """Explain the empty ``allowed_contexts`` gate and how to resolve it."""
    err_console.print(
        "[red]no kubernetes contexts are allow-listed[/red] "
        "(targets.kubernetes.allowed_contexts is empty)."
    )
    err_console.print(
        "This is a deliberate fail-closed gate — it must be filled before the first live run. "
        "Generate a read-only kubeconfig scoped to the contexts the agent may touch with "
        "[bold]ops/k8s/gen-kubeconfig.sh[/bold], then list those contexts under "
        "targets.kubernetes.allowed_contexts in config/config.yaml."
    )


def _run_repl(
    gateway: AgentGateway, *, environment: str, profile: str, principal: str
) -> None:
    """Drive the streaming REPL on a single persistent event loop (one loop for the session)."""
    loop = asyncio.new_event_loop()
    try:
        thread_id = loop.run_until_complete(gateway.create_thread())
        console.print(
            Panel.fit(
                f"opendevops chat — env=[bold]{environment}[/bold] "
                f"profile=[bold]{profile}[/bold] principal=[bold]{principal}[/bold]\n"
                "type a request, or /cost, /quit",
                title="opendevops",
                border_style="green",
            )
        )
        session_cost = 0.0
        while True:
            try:
                line = console.input(_PROMPT).strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break

            if not line:
                continue
            if line in {"/quit", "/exit", "/q"}:
                break
            if line == "/cost":
                daily = loop.run_until_complete(_safe_daily(gateway))
                console.print(
                    f"[dim]session ${session_cost:.4f} / today ${daily:.2f} (global)[/dim]"
                )
                continue

            result = _drive_turn(
                loop,
                gateway,
                thread_id,
                line,
                environment=environment,
                profile=profile,
                principal=principal,
            )
            if result is None:
                continue
            session_cost += result.cost_usd_authoritative
            if result.error:
                err_console.print(f"[red]{result.error}[/red]")
            daily = loop.run_until_complete(_safe_daily(gateway))
            console.print(
                f"[dim]spent ${result.cost_usd_authoritative:.4f} (run) "
                f"/ ${daily:.2f} (today)[/dim]"
            )
    finally:
        loop.close()


def _drive_turn(
    loop: asyncio.AbstractEventLoop,
    gateway: AgentGateway,
    thread_id: str,
    text: str,
    *,
    environment: str,
    profile: str,
    principal: str,
) -> RunResult | None:
    """Run one streamed turn; Ctrl-C cancels the run (via the gateway) without killing the REPL.

    A turn that suspends on a policy escalation yields an :class:`EscalationEvent`; the REPL renders
    it, prompts the operator (approve / edit / reject — or auto-rejects a non-interactive session),
    and resumes the SAME thread via ``stream_resume``, looping until the run reaches a final
    (non-interrupted) :class:`RunEnd`.
    """

    async def _go() -> RunResult | None:
        stream: AsyncIterator[RunEvent] | None = gateway.stream(
            thread_id,
            text,
            profile=profile,
            principal=principal,
            interface="cli",
            environment=environment,
        )
        result: RunResult | None = None
        while stream is not None:
            result = await _consume_stream(stream)
            stream = None
            if result is not None and result.interrupted is not None:
                decisions = _resolve_escalation(result.interrupted)
                stream = gateway.stream_resume(thread_id, decisions, approver=principal)
        return result

    task = loop.create_task(_go())
    try:
        return loop.run_until_complete(task)
    except KeyboardInterrupt:
        loop.run_until_complete(gateway.cancel(thread_id))
        try:
            result = loop.run_until_complete(task)
        except Exception:  # noqa: BLE001 - the run was interrupted; keep the REPL alive
            result = None
        console.print("[yellow]run cancelled[/yellow]")
        return result


async def _consume_stream(stream: AsyncIterator[RunEvent]) -> RunResult | None:
    """Render every event of one (initial or resumed) stream; return its terminal RunResult."""
    result: RunResult | None = None
    async for event in stream:
        if isinstance(event, RunEnd):
            result = event.result
        elif isinstance(event, EscalationEvent):
            _render_escalation_panel(event.escalation)
        else:
            _render_event(event)
    return result


def _stdin_is_interactive() -> bool:
    """True iff stdin is a tty (a seam tests patch; a non-tty run auto-rejects escalations)."""
    return sys.stdin.isatty()


def _render_escalation_panel(escalation: Escalation) -> None:
    """Render the red human-approval panel for a suspended escalation (argv, rule, reason)."""
    payload = escalation.payload
    request = (payload.get("action_requests") or [{}])[0]
    argv = request.get("args", {}).get("argv") or []
    review = (payload.get("review_configs") or [{}])[0]
    rule = review.get("rule_id", "?")
    reason = review.get("reason", "")
    console.print(
        Panel.fit(
            f"[bold]{escape(' '.join(str(a) for a in argv))}[/bold]\n"
            f"rule: [bold]{escape(str(rule))}[/bold]\n{escape(str(reason))}",
            title="escalation — human approval required",
            border_style="red",
        )
    )


def _resolve_escalation(escalation: Escalation) -> list[dict[str, Any]]:
    """Prompt the operator for approve / edit / reject (auto-reject when non-interactive)."""
    if not _stdin_is_interactive():
        err_console.print("[yellow]non-interactive session — auto-rejecting escalation[/yellow]")
        return [{"type": "reject", "message": "non-interactive session"}]

    choice = console.input("[bold]approve / edit / reject[/bold] › ").strip().lower()
    if choice.startswith("a"):
        return [{"type": "approve"}]
    if choice.startswith("e"):
        edited = console.input("edited argv › ").strip()
        return [{"type": "edit", "args": {"argv": edited.split()}}]
    message = console.input("reject reason (optional) › ").strip()
    return [{"type": "reject", "message": message or "rejected by operator"}]


def _render_event(event: RunEvent) -> None:
    """Render one non-terminal stream event (dynamic text escaped so it is never read as markup)."""
    if isinstance(event, AssistantText):
        console.print(escape(event.text))
    elif isinstance(event, ToolCall):
        argv = escape(" ".join(event.argv)) if event.argv else ""
        console.print(f"[cyan]→ {escape(event.name)}[/cyan] {argv}".rstrip())
    elif isinstance(event, ToolResult):
        excerpt = escape(_first_line(event.excerpt))
        if event.denied:
            rule = f" [{escape(event.rule_id)}]" if event.rule_id else ""
            console.print(f"[red]✗ denied{rule}[/red]: {excerpt}")
        else:
            console.print(f"[dim]{excerpt}[/dim]")


def _first_line(text: str) -> str:
    """The first non-empty line of ``text`` (tool output can be long/multi-line)."""
    for line in text.splitlines():
        if line.strip():
            return line
    return text.strip()


async def _safe_daily(gateway: AgentGateway) -> float:
    """The gateway's daily ``global`` spend, or ``0.0`` if the gateway does not expose it."""
    getter = getattr(gateway, "daily_total", None)
    if getter is None:
        return 0.0
    try:
        return await getter()
    except Exception:  # noqa: BLE001 - a counter outage must not break the REPL
        return 0.0


if __name__ == "__main__":  # pragma: no cover
    app()
