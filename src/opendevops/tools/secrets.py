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
never an empty-string substitution. Backends: :class:`EnvSecretSource` (default),
:class:`FileSecretSource` (CSI/volume files), :class:`VaultSecretSource` (HashiCorp KV v2 with
``token`` / AppRole / Kubernetes auth). Use :func:`build_secret_source` to construct from
``executor`` config.

On the **remote** executor path this resolution runs inside the executor **service** (the only
holder of secret values); on the **local** (single-process) path it runs in-process. The exact set
of resolved values is handed to the full-scrub (:func:`opendevops.tools.scrub.scrub_full`) so any
literal occurrence in the command output is redacted as a backstop.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

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
class FileSecretSource:
    """CSI / volume-mounted secrets: one file per NAME under ``directory``.

    Reads ``{directory}/{NAME}`` as UTF-8 text and strips a single trailing newline. Missing or
    empty files return ``None`` (fail-closed at resolve time).
    """

    directory: Path

    def get(self, name: str) -> str | None:
        path = self.directory / name
        if not path.is_file():
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        if text.endswith("\n"):
            text = text[:-1]
        return text if text else None


def _vault_http_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout_s: float = 5.0,
) -> dict[str, Any] | None:
    """POST/GET JSON against Vault; return parsed object or ``None`` on any failure."""
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if body is not None else {}),
            **(headers or {}),
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            return json.loads(response.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        TimeoutError,
        json.JSONDecodeError,
        OSError,
    ):
        return None


def vault_login_approle(
    addr: str,
    *,
    role_id: str,
    secret_id: str,
    auth_mount: str = "approle",
    timeout_s: float = 5.0,
) -> str | None:
    """AppRole login → client token, or ``None`` on failure."""
    base = addr.rstrip("/")
    mount = auth_mount.strip("/")
    payload = _vault_http_json(
        f"{base}/v1/auth/{mount}/login",
        method="POST",
        body={"role_id": role_id, "secret_id": secret_id},
        timeout_s=timeout_s,
    )
    if not isinstance(payload, dict):
        return None
    auth = payload.get("auth")
    if not isinstance(auth, dict):
        return None
    token = auth.get("client_token")
    return token if isinstance(token, str) and token else None


def vault_login_kubernetes(
    addr: str,
    *,
    role: str,
    jwt: str,
    auth_mount: str = "kubernetes",
    timeout_s: float = 5.0,
) -> str | None:
    """Kubernetes auth login → client token, or ``None`` on failure."""
    base = addr.rstrip("/")
    mount = auth_mount.strip("/")
    payload = _vault_http_json(
        f"{base}/v1/auth/{mount}/login",
        method="POST",
        body={"role": role, "jwt": jwt},
        timeout_s=timeout_s,
    )
    if not isinstance(payload, dict):
        return None
    auth = payload.get("auth")
    if not isinstance(auth, dict):
        return None
    token = auth.get("client_token")
    return token if isinstance(token, str) and token else None


@dataclass
class VaultSecretSource:
    """HashiCorp Vault KV v2: GET ``{addr}/v1/{mount}/data/{path_prefix}/{NAME}``.

    ``token`` may be a static token, or a callable that returns a fresh token (AppRole /
    Kubernetes login). The secret payload field named by ``value_field`` (default ``value``)
    is returned; if absent and ``data`` has exactly one string field, that value is used.
    Network/auth failures return ``None`` (fail-closed).
    """

    addr: str
    token: str | Any  # str or zero-arg callable → str | None
    mount: str = "secret"
    path_prefix: str = "opendevops"
    value_field: str = "value"
    timeout_s: float = 5.0
    _cached_token: str | None = None

    def _resolve_token(self) -> str | None:
        if callable(self.token):
            if self._cached_token:
                return self._cached_token
            got = self.token()
            if isinstance(got, str) and got:
                self._cached_token = got
                return got
            return None
        return self.token if isinstance(self.token, str) and self.token else None

    def _kv_get(self, name: str, vault_token: str) -> dict[str, Any] | None:
        base = self.addr.rstrip("/")
        prefix = self.path_prefix.strip("/")
        path = f"{prefix}/{name}" if prefix else name
        url = f"{base}/v1/{self.mount.strip('/')}/data/{path}"
        return _vault_http_json(
            url,
            headers={"X-Vault-Token": vault_token},
            timeout_s=self.timeout_s,
        )

    def get(self, name: str) -> str | None:
        vault_token = self._resolve_token()
        if not vault_token:
            return None
        payload = self._kv_get(name, vault_token)
        if not isinstance(payload, dict):
            # Drop cached token and re-login once (AppRole / K8s JWT may have rotated).
            self._cached_token = None
            vault_token = self._resolve_token()
            if not vault_token:
                return None
            payload = self._kv_get(name, vault_token)
            if not isinstance(payload, dict):
                return None
        data = payload.get("data", {})
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data["data"]
        if not isinstance(data, dict):
            return None
        raw = data.get(self.value_field)
        if isinstance(raw, str) and raw:
            return raw
        strings = [v for v in data.values() if isinstance(v, str) and v]
        if len(strings) == 1:
            return strings[0]
        return None


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


def build_secret_source(cfg: Any) -> SecretSource:
    """Construct the configured ``{{secret:NAME}}`` backend (env / file / vault)."""
    from opendevops.config import AppConfig, ExecutorConfig

    if isinstance(cfg, AppConfig):
        executor = cfg.executor
    elif isinstance(cfg, ExecutorConfig):
        executor = cfg
    else:
        raise TypeError("build_secret_source expects AppConfig or ExecutorConfig")

    if executor.secret_source == "env":
        return EnvSecretSource(prefix=executor.secret_env_prefix)
    if executor.secret_source == "file":
        if executor.secret_file_dir is None:
            raise SecretResolutionError("executor.secret_file_dir is required for file secrets")
        return FileSecretSource(directory=executor.secret_file_dir)
    if executor.secret_source == "vault":
        if executor.vault is None:
            raise SecretResolutionError("executor.vault is required for vault secrets")
        vault = executor.vault
        addr = os.environ.get(vault.addr_env)
        if not addr:
            raise SecretResolutionError(
                f"vault secret source requires {vault.addr_env} to be set"
            )
        token: str | Any
        if vault.auth == "token":
            static = os.environ.get(vault.token_env)
            if not static:
                raise SecretResolutionError(
                    f"vault auth=token requires {vault.token_env} to be set"
                )
            token = static
        elif vault.auth == "approle":
            role_id = os.environ.get(vault.role_id_env or "")
            secret_id = os.environ.get(vault.secret_id_env or "")
            if not role_id or not secret_id:
                raise SecretResolutionError(
                    "vault auth=approle requires "
                    f"{vault.role_id_env} and {vault.secret_id_env} to be set"
                )
            mount = vault.resolved_auth_mount()

            def _approle_token(
                _addr: str = addr,
                _role_id: str = role_id,
                _secret_id: str = secret_id,
                _mount: str = mount,
            ) -> str | None:
                return vault_login_approle(
                    _addr, role_id=_role_id, secret_id=_secret_id, auth_mount=_mount
                )

            token = _approle_token
        elif vault.auth == "kubernetes":
            role = vault.kubernetes_role or ""
            jwt_path = vault.jwt_path
            # Boot-time readability check only — the login callable re-reads on every request
            # so a rotated ServiceAccount JWT is picked up after the cached Vault token expires.
            try:
                initial_jwt = jwt_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise SecretResolutionError(
                    f"vault auth=kubernetes could not read jwt_path {jwt_path}"
                ) from exc
            if not role or not initial_jwt:
                raise SecretResolutionError(
                    "vault auth=kubernetes requires kubernetes_role and a non-empty jwt"
                )
            mount = vault.resolved_auth_mount()

            def _k8s_token(
                _addr: str = addr,
                _role: str = role,
                _jwt_path: Path = jwt_path,
                _mount: str = mount,
            ) -> str | None:
                try:
                    jwt = _jwt_path.read_text(encoding="utf-8").strip()
                except OSError:
                    return None
                if not jwt:
                    return None
                return vault_login_kubernetes(
                    _addr, role=_role, jwt=jwt, auth_mount=_mount
                )

            token = _k8s_token
        else:  # pragma: no cover - pydantic Literal narrows this
            raise SecretResolutionError(f"unknown vault auth {vault.auth!r}")
        return VaultSecretSource(
            addr=addr,
            token=token,
            mount=vault.mount,
            path_prefix=vault.path_prefix,
            value_field=vault.value_field,
        )
    raise SecretResolutionError(f"unknown secret_source {executor.secret_source!r}")
