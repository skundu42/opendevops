"""``{{secret:NAME}}`` resolver — declare subprocess environment secrets without argv leakage.

A standalone ``{{secret:NAME}}`` argument is an environment declaration: the resolver injects
``NAME=<value>`` into the child and removes the declaration from the executed argv. This supports
programs with native environment-variable credentials (for example ``PGPASSWORD``) while ensuring
the secret value never appears in argv, audit arguments, tool output, or logs.

Embedded references such as ``"Authorization: Bearer {{secret:API_TOKEN}}"`` are rejected.
Because execution is deliberately ``shell=False``, replacing them with ``$API_TOKEN`` would pass
that text literally and silently send a broken credential. Expanding the value would work but leak
it through the OS process table, so the secure contract is intentionally env-aware programs only.

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

    * ``argv`` — a copy of the input argv with standalone secret declarations removed.
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
    """Resolve standalone ``{{secret:NAME}}`` declarations into child environment variables.

    Returns a :class:`ResolvedSecrets`. Raises :class:`SecretResolutionError` if any referenced
    NAME is unknown/unset or if a reference is embedded in another argument. An argv with no secret
    tokens yields a byte-identical argv copy, an empty env, and no values.
    """
    env: dict[str, str] = {}
    values: list[str] = []
    names: list[str] = []
    new_argv: list[str] = []

    for index, token in enumerate(argv):
        references = list(_SECRET_RE.finditer(token))
        if not references:
            new_argv.append(token)
            continue
        match = _SECRET_RE.fullmatch(token)
        if match is None:
            raise SecretResolutionError(
                "secret references must be standalone argv entries; embedded expansion is "
                "unsupported because commands run without a shell"
            )
        if index == 0:
            raise SecretResolutionError("the executable argv entry cannot be a secret declaration")
        name = match.group(1)
        value = source.get(name)
        if value is None:
            raise SecretResolutionError(
                f"unknown or unset secret {name!r} referenced as {{{{secret:{name}}}}}"
            )
        if name not in env:
            env[name] = value
            values.append(value)
            names.append(name)

    return ResolvedSecrets(argv=new_argv, env=env, values=values, names=names)
