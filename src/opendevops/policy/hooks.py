"""``@policy_hook`` registry: named async policy hooks (T4).

A *hook* is a small async escape hatch a ``effect: hook`` rule can name. The engine looks it
up here, runs it under a hard timeout, and treats it fail-closed: a hook that raises, times
out, or is not registered becomes ``deny(__fail_closed__)``. A hook returns a
:class:`~opendevops.policy.schema.Decision` to voice an opinion, or ``None`` to abstain (the
engine then drops the hook rule and re-applies precedence to the rest of the matched set).

No hooks ship in P1 — the dry-run-before-apply hook lands in P2. This module is only the
registry; the sole P1 consumer is the engine, and tests register a trivial example hook.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from opendevops.policy.schema import Decision, ToolCallCtx

# A policy hook: async, receives the tool-call context, returns a Decision or None (abstain).
PolicyHook = Callable[[ToolCallCtx], Awaitable[Decision | None]]

_REGISTRY: dict[str, PolicyHook] = {}


def policy_hook(name: str) -> Callable[[PolicyHook], PolicyHook]:
    """Decorator registering an async ``fn(ctx) -> Decision | None`` under ``name``.

    Raises :class:`ValueError` on a duplicate name so two hooks can never silently shadow one
    another (a wired-up hook name must be unambiguous).
    """

    def decorator(fn: PolicyHook) -> PolicyHook:
        if name in _REGISTRY:
            raise ValueError(f"policy hook {name!r} is already registered")
        _REGISTRY[name] = fn
        return fn

    return decorator


def get_hook(name: str) -> PolicyHook | None:
    """Return the hook registered under ``name``, or ``None`` if there is none."""
    return _REGISTRY.get(name)


def registered_hooks() -> dict[str, PolicyHook]:
    """Return a copy of the ``name -> hook`` registry (callers must not mutate the registry)."""
    return dict(_REGISTRY)
