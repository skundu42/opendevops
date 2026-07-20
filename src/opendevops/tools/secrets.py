"""``{{secret:NAME}}`` resolver — secrets into the subprocess ENV, never argv/logs (P5d).

The model may reference a named secret in a command with a ``{{secret:NAME}}`` token (e.g.
``["curl", "-H", "Authorization: Bearer {{secret:API_TOKEN}}", url]``). Resolving it does **two**
things and never a third:

1. inject ``NAME=<value>`` into the subprocess environment; and
2. replace the ``{{secret:NAME}}`` occurrence in the argv token with a literal ``$NAME``
   *reference* (a marker only — there is no shell, so ``$NAME`` is passed verbatim; the actual
   value is available to a tool that reads the environment variable ``NAME``).

The secret **value** therefore never appears in argv, in the audit ``args``, in the ToolMessage, or
in any log — only the ``$NAME`` marker does. This is the specified design (value-in-env, not
value-in-argv).

Fail-closed: an unknown / unset ``NAME`` raises :class:`SecretResolutionError` (deny, no exec) —
never an empty-string substitution. The secret **source** is config-named and env-var-backed to
start (:class:`EnvSecretSource`); the :class:`SecretSource` protocol is the seam a future vault
backend plugs into.

On the **remote** executor path this resolution runs inside the executor **service** (the only
holder of secret values); on the **local** (single-process) path it runs in-process. The exact set
of resolved values is handed to the full-scrub (:func:`opendevops.tools.scrub.scrub_full`) so any
literal occurrence in the command output is redacted as a backstop.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# ``{{secret:NAME}}`` where NAME is a conventional env-var identifier. Anchored to that grammar so a
# stray ``{{secret:...}}`` with an illegal name is simply not matched (and thus not treated as a
# resolvable secret) rather than silently mangled.
_SECRET_RE = re.compile(r"\{\{secret:([A-Za-z_][A-Za-z0-9_]*)\}\}")


class SecretResolutionError(Exception):
    """A ``{{secret:NAME}}`` token names a secret the source does not provide (fail-closed deny)."""


@runtime_checkable
class SecretSource(Protocol):
    """Resolves a secret NAME to its value, or ``None`` if it is unknown/unset (fail-closed)."""

    def get(self, name: str) -> str | None:  # pragma: no cover - protocol
        ...


@dataclass(frozen=True)
class EnvSecretSource:
    """The default secret backend: read ``{{secret:NAME}}`` from the process environment.

    ``prefix`` (default empty) is prepended to NAME for the lookup, so an operator can namespace the
    executor's secrets (e.g. ``prefix="DEVOPS_SECRET_"`` maps ``{{secret:PGPASSWORD}}`` to the env
    var ``DEVOPS_SECRET_PGPASSWORD``). Only the process env is read here; values are never logged.
    """

    prefix: str = ""

    def get(self, name: str) -> str | None:
        value = os.environ.get(f"{self.prefix}{name}")
        return value if value else None


@dataclass(frozen=True)
class ResolvedSecrets:
    """The outcome of resolving ``{{secret:NAME}}`` tokens across an argv.

    * ``argv`` — a copy of the input argv with every ``{{secret:NAME}}`` replaced by ``$NAME``.
    * ``env`` — ``{NAME: value}`` to merge into the subprocess environment.
    * ``values`` — the raw resolved values, handed to the output full-scrub (never logged).
    * ``names`` — the resolved names, in first-seen order (for documentation / debugging only).
    """

    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)
    values: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)


def has_secret_tokens(argv: Sequence[str]) -> bool:
    """True iff any argv token contains a ``{{secret:NAME}}`` reference (cheap pre-check)."""
    return any(_SECRET_RE.search(token) for token in argv)


def resolve_secrets(argv: Sequence[str], source: SecretSource) -> ResolvedSecrets:
    """Resolve every ``{{secret:NAME}}`` in *argv* into env vars, rewriting the tokens to ``$NAME``.

    Returns a :class:`ResolvedSecrets`. Raises :class:`SecretResolutionError` if any referenced
    NAME is unknown/unset in *source* (fail-closed — never substitutes an empty string). An argv
    with no secret tokens yields a byte-identical argv copy, an empty env, and no values (so callers
    can treat "no secrets" as a transparent no-op).
    """
    env: dict[str, str] = {}
    values: list[str] = []
    names: list[str] = []

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = source.get(name)
        if value is None:
            # Fail closed: an unknown/unset secret is a hard deny, not an empty substitution.
            raise SecretResolutionError(
                f"unknown or unset secret {name!r} referenced as {{{{secret:{name}}}}}"
            )
        if name not in env:
            env[name] = value
            values.append(value)
            names.append(name)
        return f"${name}"

    new_argv = [_SECRET_RE.sub(_replace, token) for token in argv]
    return ResolvedSecrets(argv=new_argv, env=env, values=values, names=names)
