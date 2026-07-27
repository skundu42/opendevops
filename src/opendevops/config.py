"""Typed configuration loaders for the three YAML files (config/models/budgets) + .env.

`load_config(root)` reads ``<root>/config/{config,models,budgets}.yaml``, expands ``~`` in
paths, layers ``<root>/.env`` via pydantic-settings for future secrets, and returns a
strict (``extra="forbid"``) :class:`AppConfig` aggregate. All validation is fail-closed:
a malformed file, an unknown key, or an unpriced agent model raises rather than booting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# --------------------------------------------------------------------------------------
# config.yaml
# --------------------------------------------------------------------------------------

DashboardRole = Literal["viewer", "operator", "approver", "admin"]


class OIDCConfig(BaseModel):
    """Generic OpenID Connect relying-party configuration.

    Provider-specific behavior is expressed through discovery and claim mapping, so the same
    implementation works with Entra ID, Google Workspace, Okta, Keycloak, and standards-compliant
    providers. Secret *values* remain in the environment.
    """

    model_config = ConfigDict(extra="forbid")

    issuer: str | None = None
    client_id_env: str | None = None
    client_secret_env: str | None = None
    redirect_uri: str | None = None
    scopes: list[str] = ["openid", "profile", "email"]
    roles_claim: str = "groups"
    role_mappings: dict[DashboardRole, list[str]] = {}
    default_roles: list[DashboardRole] = []

    @model_validator(mode="after")
    def _validate_oidc(self) -> OIDCConfig:
        if "openid" not in self.scopes:
            raise ValueError("server.oidc.scopes must include 'openid'")
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("server.oidc.scopes must not contain duplicates")
        if self.issuer is not None:
            issuer = self.issuer.rstrip("/")
            if not issuer.startswith(("https://", "http://localhost", "http://127.0.0.1")):
                raise ValueError("server.oidc.issuer must use HTTPS (except localhost development)")
            self.issuer = issuer
        if self.redirect_uri is not None and not self.redirect_uri.startswith(
            ("https://", "http://localhost", "http://127.0.0.1")
        ):
            raise ValueError(
                "server.oidc.redirect_uri must use HTTPS (except localhost development)"
            )
        return self


class ControlPlaneConfig(BaseModel):
    """Approval separation and guarded runtime-capability configuration.

    Durable state (capability proposals + dashboard chat) lives in one store:

    * ``backend: sqlite`` (default) — file at ``database``; fine for single-replica / local.
    * ``backend: postgres`` — URL from the env var named by ``database_url_env``; required for
      multi-replica service mode so workers share the ledger and chat transcripts.
    """

    model_config = ConfigDict(extra="forbid")

    backend: Literal["sqlite", "postgres"] = "sqlite"
    database: Path = Path("./state/control-plane.sqlite3")
    database_url_env: str | None = None
    production_requires_independent_approval: bool = True
    enforce_runtime_grants: bool = False
    grant_required_environments: list[Literal["staging", "prod"]] = ["prod"]
    max_rw_actions_per_run: int = Field(default=12, ge=1, le=100)
    max_identical_rw_actions_per_run: int = Field(default=2, ge=1, le=10)
    max_consecutive_failures: int = Field(default=3, ge=1, le=10)
    default_grant_ttl_s: int = Field(default=3600, ge=60, le=86400)
    max_grant_ttl_s: int = Field(default=86400, ge=300, le=604800)
    minimum_cooldown_s: int = Field(default=5, ge=0, le=3600)

    @field_validator("database", mode="after")
    @classmethod
    def _expand_database(cls, value: Path) -> Path:
        return value.expanduser()

    @model_validator(mode="after")
    def _validate_limits(self) -> ControlPlaneConfig:
        if self.default_grant_ttl_s > self.max_grant_ttl_s:
            raise ValueError("default_grant_ttl_s must not exceed max_grant_ttl_s")
        if len(set(self.grant_required_environments)) != len(
            self.grant_required_environments
        ):
            raise ValueError("grant_required_environments must not contain duplicates")
        if self.backend == "postgres" and not self.database_url_env:
            raise ValueError(
                "control_plane.backend='postgres' requires control_plane.database_url_env"
            )
        return self


class KubernetesTarget(BaseModel):
    """Kubernetes target with a read identity and environment-scoped write identities."""

    model_config = ConfigDict(extra="forbid")

    kubeconfig_ro: Path
    kubeconfig_rw: Path | None = None
    kubeconfig_rw_by_environment: dict[Literal["staging", "prod"], Path] = {}
    allowed_contexts: list[str] = []

    @field_validator("kubeconfig_ro", "kubeconfig_rw", mode="after")
    @classmethod
    def _expand_user(cls, v: Path | None) -> Path | None:
        return v.expanduser() if v is not None else None

    @field_validator("kubeconfig_rw_by_environment", mode="after")
    @classmethod
    def _expand_environment_paths(
        cls, values: dict[Literal["staging", "prod"], Path]
    ) -> dict[Literal["staging", "prod"], Path]:
        return {environment: path.expanduser() for environment, path in values.items()}


class GithubTarget(BaseModel):
    """GitHub execution target: the ``gh`` credential family (read plus the rw write channel).

    ``token_env`` names the *agent-process* environment variable holding a read-only
    fine-grained PAT; the executor reads that variable's value into the child's ``GH_TOKEN``
    for ``gh``-family ``ro`` calls. Left as ``None`` (the default), the ``gh`` family always
    reports ``CredentialUnavailable`` and refuses — correct until the operator exports the
    variable. The token value itself is never stored in config, logs, or error messages.

    ``token_env_rw`` names the env var holding a **fine-grained PAT for writes** — the
    credential the executor injects as ``GH_TOKEN`` for a ``gh``-family ``rw`` call (the
    gh-write pack: ``gh run rerun`` / ``gh pr create`` / the ``gh api`` write allowlist). It is
    a *distinct* credential from the read PAT and is never injected on the ``ro`` channel (and
    the ro PAT is never injected on ``rw``); missing when a rw gh rule fires ⇒
    ``CredentialUnavailable``. Left ``None`` (the default), any gh-write allow refuses to boot
    (the rw coverage gate) — staging-only writes stay off until the operator exports the PAT.

    ``write_repos`` is the allowlist of ``owner/repo`` slugs the gh-write ``gh api``
    method+path predicate permits writes under (``POST``/``PATCH``/``PUT`` to
    ``/repos/{owner/repo}/...``). Empty (the default) means no repo is a write target — every
    ``gh api`` write default-denies. The policy pack references THIS list via
    ``${targets.github.write_repos}``, so config is the single source of truth for the write
    target set. Only slugs live here; the PAT's own repo scoping is the compensating control.
    """

    model_config = ConfigDict(extra="forbid")

    token_env: str | None = None
    token_env_rw: str | None = None
    write_repos: list[str] = []


class CloudTarget(BaseModel):
    """A read-only cloud-CLI execution target (the ``aws`` / ``gcloud`` / ``az`` families).

    ``credential_env`` names the *agent-process* environment variables whose VALUES the executor
    copies into the child env for this family's calls — the direct analogue of
    ``GithubTarget.token_env``, except a cloud credential is usually a *set* of variables rather
    than one token:

      * aws — ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` (/ ``AWS_SESSION_TOKEN``); the
        role behind them is the read-only role whose IAM policy Denies
        ``secretsmanager:GetSecretValue`` / ``ssm:GetParameter*`` decrypt / ``kms:Decrypt``.
        ``AWS_REGION`` may also be listed (region is not identity).
      * gcloud — ``GOOGLE_APPLICATION_CREDENTIALS`` (the service-account key file path) and/or
        ``CLOUDSDK_*`` vars.
      * az — ``AZURE_CLIENT_ID`` / ``AZURE_TENANT_ID`` / ``AZURE_CLIENT_SECRET`` (service-principal
        env auth) or ``AZURE_FEDERATED_TOKEN_FILE``.

    Empty (the default) means the family is *unconfigured*: the boot credential-coverage gate
    (:func:`~opendevops.policy.loader.check_credential_coverage`) treats an empty list as "no
    credential", so a shipped cloud pack with allow rules refuses to boot until the operator lists
    the variable names here — and the executor raises ``CredentialUnavailable`` for any call in the
    family meanwhile. Only NAMES live in config; the executor reads each variable's VALUE at exec
    time (never logged, never stored).
    """

    model_config = ConfigDict(extra="forbid")

    credential_env: list[str] = []


class SshTarget(BaseModel):
    """Read-only remote-exec target (the ``ssh`` credential family / ``ssh_run`` tool).

    ``ssh_run(host, argv)`` is a STRUCTURED remote-exec tool (``ssh`` as a run_command argv0 is
    hard-denied by base.yaml). The model supplies ONLY an allowlisted ``host`` name and the remote
    ``argv``; every identity/endpoint detail is pinned HERE by config (never by the model):

    * ``hosts`` — the explicit host allowlist. ``ssh_run`` is permitted (by policy) only for a host
      in this list, and the tool re-validates the host against it before connecting (defense in
      depth). Empty (the default) means no host is reachable — every ssh_run denies. The policy pack
      references THIS list (``ssh_host_in: "${targets.ssh.hosts}"``), so it is the single source of
      truth for which hosts are reachable.
    * ``user`` — the pinned remote login user (a username is not a secret, so it is a plain value).
    * ``key_env`` — the NAME of the agent-process env var holding the filesystem PATH to the private
      key file (the analogue of ``GithubTarget.token_env``: only the NAME lives in config; the
      executor reads the variable's value — a path — at exec time and never logs it). ``None`` (the
      default) => the ``ssh`` family is *unconfigured*: the boot coverage gate refuses to start an
      ssh allow pack, and the executor raises ``CredentialUnavailable`` for any ssh_run call.
    * ``key_passphrase_env`` — optional NAME of the env var holding the private key's passphrase
      (``None`` => the key is expected to be passphrase-less).
    * ``known_hosts_path`` — the pinned ``known_hosts`` file. Host-key verification is ALWAYS ON
      (asyncssh verifies the server key against this file); an unknown/mismatched host key fails
      closed (refusal, no exec). ``None`` => the executor raises ``CredentialUnavailable`` — there
      is no "disable host-key checking" path, fail-closed by construction.
    * ``port`` — the SSH port (default 22).
    """

    model_config = ConfigDict(extra="forbid")

    hosts: list[str] = []
    user: str | None = None
    key_env: str | None = None
    key_passphrase_env: str | None = None
    known_hosts_path: Path | None = None
    port: int = 22

    @field_validator("known_hosts_path", mode="after")
    @classmethod
    def _expand_user(cls, v: Path | None) -> Path | None:
        return v.expanduser() if v is not None else None


class Targets(BaseModel):
    """Infrastructure targets the agent may operate against.

    ``kubernetes`` is required; ``github``, the three read-only cloud families ``aws`` /
    ``gcloud`` / ``azure``, and ``ssh`` (remote-exec) are optional and default to
    *unconfigured* — their allow packs only become bootable once a credential is named (the boot
    coverage gate). The ``azure`` target backs the ``az`` credential family / ``az`` argv0 (the
    Azure CLI binary is ``az``); ``ssh`` backs the ``ssh`` family / the ``ssh_run`` tool.
    """

    model_config = ConfigDict(extra="forbid")

    kubernetes: KubernetesTarget
    github: GithubTarget = Field(default_factory=GithubTarget)
    aws: CloudTarget = Field(default_factory=CloudTarget)
    gcloud: CloudTarget = Field(default_factory=CloudTarget)
    azure: CloudTarget = Field(default_factory=CloudTarget)
    ssh: SshTarget = Field(default_factory=SshTarget)


class Execution(BaseModel):
    """Subprocess execution limits and the constructed-env allowlist."""

    model_config = ConfigDict(extra="forbid")

    cmd_timeout_seconds: int = Field(gt=0)
    output_max_chars: int = Field(gt=0)
    env_allowlist: list[Literal["PATH", "HOME"]]
    trusted_path: str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    @field_validator("env_allowlist")
    @classmethod
    def _require_safe_execution_env(cls, value: list[str]) -> list[str]:
        """The executor needs both safe base keys and must never accept arbitrary parent keys."""
        if len(value) != 2 or set(value) != {"PATH", "HOME"}:
            raise ValueError("execution.env_allowlist must contain exactly PATH and HOME")
        return value

    @field_validator("trusted_path")
    @classmethod
    def _trusted_path_is_absolute(cls, value: str) -> str:
        """Reject empty, relative, and current-directory PATH entries."""
        entries = value.split(":")
        if not entries or any(not entry or not Path(entry).is_absolute() for entry in entries):
            raise ValueError(
                "execution.trusted_path must be a colon-separated list of absolute directories"
            )
        return value


class ExecutorChannelUrls(BaseModel):
    """Base URLs for the ``ro`` and ``rw`` executor service pods of one environment."""

    model_config = ConfigDict(extra="forbid")

    ro: str
    rw: str


class VaultSecretConfig(BaseModel):
    """HashiCorp Vault KV v2 settings for ``executor.secret_source=vault``."""

    model_config = ConfigDict(extra="forbid")

    addr_env: str = "VAULT_ADDR"
    token_env: str = "VAULT_TOKEN"
    mount: str = "secret"
    path_prefix: str = "opendevops"
    # Optional KV field name; when null, uses key ``value`` then falls back to a single-field map.
    value_field: str = "value"


class ExecutorConfig(BaseModel):
    """Executor deployment selection (the executor split; defaults to in-process ``local``).

    ``mode`` picks how ``run_command`` / ``ssh_run`` reach execution:

    * ``local`` (the DEFAULT, so a config without an ``executor:`` block still validates and every
      existing deploy is unchanged) — the in-process ``LocalExecutor`` / ``SshExecutor``.
      This is the single-process deployment: it holds the infra credentials AND resolves
      ``{{secret:NAME}}`` values in-process (and holds the SSH key when ``targets.ssh`` is set).
    * ``remote`` — the agent holds no ``run_command`` credentials (kube/gh/cloud), no secret
      values, and no SSH key; each exec is signed with an ed25519 decision token and POSTed to the
      matching standalone executor **service** pod, which holds the credentials + the secret source
      (and the SSH key for ``ssh_run``) and does credential env + secret resolution + subprocess /
      SSH run + full-scrub. Opt-in. Production-ready once ``urls`` is fully populated: the token
      binds ``environment`` + ``channel`` (+ ``host`` for ssh), each pod asserts its own identity,
      and the client routes per ``(environment, channel)``.

    * ``urls`` — required when ``mode=remote``: a map of ``staging`` / ``prod`` → ``{ro, rw}``
      service base URLs. Boot fails closed if either environment or either channel is missing.
    * ``signing_key_env`` — NAME of the env var holding the agent's ed25519 PRIVATE signing key
      (base64 of the raw 32 bytes); only the NAME lives in config. Required for remote.
    * ``verify_key_env`` — NAME of the env var holding the executor service's ed25519 PUBLIC verify
      key (base64 raw 32 bytes). Read by the SERVICE, which holds the public key only.
    * ``secret_source`` — ``env`` | ``file`` (CSI/volume) | ``vault`` (HashiCorp KV v2).
    * ``secret_env_prefix`` — optional prefix for ``env`` lookups (namespacing).
    * ``secret_file_dir`` — directory of secret files when ``secret_source=file`` (CSI mount).
    * ``vault`` — HashiCorp Vault settings when ``secret_source=vault``.
    """

    model_config = ConfigDict(extra="forbid")

    mode: Literal["local", "remote"] = "local"
    urls: dict[Literal["staging", "prod"], ExecutorChannelUrls] | None = None
    signing_key_env: str | None = None
    verify_key_env: str | None = None
    secret_source: Literal["env", "file", "vault"] = "env"
    secret_env_prefix: str = ""
    secret_file_dir: Path | None = None
    vault: VaultSecretConfig | None = None

    @field_validator("secret_file_dir", mode="after")
    @classmethod
    def _expand_secret_dir(cls, value: Path | None) -> Path | None:
        return value.expanduser() if value is not None else None

    @model_validator(mode="after")
    def _remote_requires_urls_and_signing_key(self) -> ExecutorConfig:
        """``mode: remote`` needs the full URL map + signing-key env — fail-closed."""
        if self.mode == "remote":
            if self.urls is None or set(self.urls) != {"staging", "prod"}:
                raise ValueError(
                    "executor.mode='remote' requires executor.urls with both "
                    "'staging' and 'prod' entries (each providing ro and rw base URLs)"
                )
            if not self.signing_key_env:
                raise ValueError(
                    "executor.mode='remote' requires executor.signing_key_env "
                    "(the env var naming the agent's ed25519 private signing key)"
                )
        if self.secret_source == "file" and self.secret_file_dir is None:
            raise ValueError(
                "executor.secret_source='file' requires executor.secret_file_dir "
                "(CSI/volume mount path)"
            )
        if self.secret_source == "vault" and self.vault is None:
            raise ValueError(
                "executor.secret_source='vault' requires executor.vault "
                "(addr_env, token_env, mount, path_prefix)"
            )
        return self


class AuditConfig(BaseModel):
    """Audit trail location (per-run hash-chained JSONL under ``dir``)."""

    model_config = ConfigDict(extra="forbid")

    dir: Path

    @field_validator("dir", mode="after")
    @classmethod
    def _expand_user(cls, v: Path) -> Path:
        return v.expanduser()


class PolicyConfig(BaseModel):
    """Policy pack location."""

    model_config = ConfigDict(extra="forbid")

    dir: Path

    @field_validator("dir", mode="after")
    @classmethod
    def _expand_user(cls, v: Path) -> Path:
        return v.expanduser()


class StateConfig(BaseModel):
    """Durable local agent state. ``dir`` holds the LocalGateway checkpointer's sqlite db.

    The ``AsyncSqliteSaver`` writes ``<dir>/checkpoints.sqlite3`` (created
    ``0o700``) so an escalation can suspend and later resume on the same thread. Defaults to
    ``./state`` so a config without a ``state:`` block still validates.
    """

    model_config = ConfigDict(extra="forbid")

    dir: Path = Path("./state")

    @field_validator("dir", mode="after")
    @classmethod
    def _expand_user(cls, v: Path) -> Path:
        return v.expanduser()


class ServerConfig(BaseModel):
    """Self-hosted LangGraph Server connection details for :class:`ServerGateway` (service mode).

    ``ServerGateway`` (the only module importing ``langgraph_sdk``) drives a
    graph running *inside* a LangGraph Server over HTTP via ``get_client(url=..., api_key=...)``.

    * ``url`` — the server base URL (e.g. ``http://localhost:8123``). Left ``None`` (the default,
      so a config without a ``server:`` block still validates), constructing a ``ServerGateway``
      raises ``GatewayConfigError`` — service mode is opt-in.
    * ``api_key_env`` — the *name* of the process env var holding the server API key (never the key
      itself), read at client-construction time. ``None`` (the default) means no auth header is
      sent AND the SDK's ambient ``LANGGRAPH_API_KEY`` / ``LANGSMITH_API_KEY`` auto-load is
      suppressed — auth is explicit-by-config, never accidental-by-environment.

    Webhook-app fields (consumed by
    :mod:`opendevops.interfaces.webapp`, the FastAPI app mounted via ``langgraph.json``'s
    ``http.app``). Every secret is named, never valued — the app reads the *value* from
    ``os.environ`` at request time and fails **closed** (503) if a named env var is unset, never
    "auth disabled":

    * ``alertmanager_token_env`` — name of the env var holding the static bearer token
      Alertmanager sends in ``webhook_config.authorization`` (also authenticates the
      ``run-complete`` callback — same token). ``None`` → the ``/webhooks/alertmanager`` and
      ``/webhooks/run-complete`` routes fail closed (503).
    * ``github_webhook_secret_env`` — name of the env var holding the GitHub webhook HMAC secret
      (``X-Hub-Signature-256`` is verified over the raw body). ``None`` → ``/webhooks/github``
      fails closed (503).
    * ``dashboard_token_env`` — name of the env var holding the local-development dashboard login
      token. The token is exchanged for an opaque, short-lived server-side session in an HttpOnly
      cookie and is never stored in browser storage or returned by an API. ``None`` or an unset
      variable makes dashboard login fail closed (503).
    * ``dashboard_session_ttl_s`` — dashboard session lifetime in seconds (default one hour,
      bounded to one day).
    * ``dashboard_cookie_secure`` — emit the dashboard cookie with ``Secure``. Keep ``false`` only
      for the shipped local HTTP listener; set ``true`` when production TLS termination is active.
    * ``source_allowlist`` — client IPs permitted to reach ``/webhooks/alertmanager`` (empty =
      allow all). Compared against the *direct* peer IP (``request.client.host``); proxy headers
      are deliberately ignored because Caddy fronts this app on a trusted network.
    * ``webhook_environment`` — the policy-environment overlay (``staging`` | ``prod``) stamped
      onto webhook-initiated runs. Defaults to ``staging`` to match the CLI default; set to
      ``prod`` when the webhooks front production monitoring.
    """

    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    api_key_env: str | None = None
    alertmanager_token_env: str | None = None
    github_webhook_secret_env: str | None = None
    dashboard_auth_mode: Literal["static", "oidc"] = "static"
    dashboard_token_env: str | None = None
    dashboard_session_backend: Literal["memory", "redis"] = "memory"
    dashboard_session_redis_url: str | None = None
    dashboard_session_ttl_s: int = Field(default=3600, gt=0, le=86400)
    dashboard_cookie_secure: bool = False
    dashboard_chat_enabled: bool = True
    dashboard_chat_retention_days: int = Field(default=30, ge=1, le=365)
    dashboard_chat_max_message_chars: int = Field(default=8000, ge=256, le=24000)
    oidc: OIDCConfig = Field(default_factory=OIDCConfig)
    source_allowlist: list[str] = []
    webhook_environment: Literal["staging", "prod"] = "staging"

    @model_validator(mode="after")
    def _validate_dashboard_auth(self) -> ServerConfig:
        if self.dashboard_auth_mode == "oidc":
            missing = [
                field
                for field, value in {
                    "issuer": self.oidc.issuer,
                    "client_id_env": self.oidc.client_id_env,
                    "redirect_uri": self.oidc.redirect_uri,
                }.items()
                if not value
            ]
            if missing:
                raise ValueError(
                    "OIDC dashboard authentication requires server.oidc "
                    + ", ".join(missing)
                )
            if not self.oidc.role_mappings and not self.oidc.default_roles:
                raise ValueError("OIDC authentication requires at least one mapped/default role")
        if self.dashboard_session_backend == "redis" and not self.dashboard_session_redis_url:
            raise ValueError("Redis dashboard sessions require dashboard_session_redis_url")
        if self.dashboard_session_ttl_s > 8 * 60 * 60:
            raise ValueError("dashboard sessions may not exceed eight hours")
        return self


class Principal(BaseModel):
    """A mapped principal (e.g. Slack user -> agent principal + budget profile)."""

    model_config = ConfigDict(extra="forbid")

    principal: str
    profile: str = "interactive"
    roles: list[DashboardRole] = ["operator"]


class SlackConfig(BaseModel):
    """Slack Socket-Mode adapter connection details (opt-in like ``ServerConfig``).

    The adapter (:mod:`opendevops.interfaces.slack_app`) drives slack-bolt 1.30.0 in Socket Mode
    (``AsyncSocketModeHandler`` — no public URL). Like every other secret in this config the two
    tokens are named, never valued: config holds the *name* of the process env var, and the adapter
    reads the *value* at startup. A missing name / unset var is a **clear startup error** (the
    adapter refuses to boot) rather than a silent no-op — starting the Slack adapter is opt-in.

    * ``bot_token_env`` — name of the env var holding the bot token (``xoxb-...``) the adapter uses
      as the :class:`AsyncWebClient` token to post into Slack threads. ``None`` (the default) →
      starting the adapter raises.
    * ``app_token_env`` — name of the env var holding the app-level token (``xapp-...``, scope
      ``connections:write``) the Socket-Mode handler opens its websocket with. ``None`` → raises.
    * ``default_channel_environment`` — the policy-environment overlay (``staging`` | ``prod``)
      stamped onto Slack-initiated runs (mirrors ``server.webhook_environment``). Defaults to
      ``staging`` to match the CLI default.
    """

    model_config = ConfigDict(extra="forbid")

    bot_token_env: str | None = None
    app_token_env: str | None = None
    default_channel_environment: Literal["staging", "prod"] = "staging"


class SchedulerConfig(BaseModel):
    """Our own APScheduler service (:mod:`opendevops.interfaces.scheduler`).

    Opt-in like ``ServerConfig`` / ``SlackConfig`` — a config without a ``scheduler:`` block still
    validates (the default ``jobs_file`` is the shipped ``scheduler/jobs.yaml``). The service reads
    the job set from ``jobs_file`` and attributes every scheduled run to ``principal`` (the audit
    ``principal.user`` + the per-principal daily budget scope — the scheduler acts on its own
    behalf, not a human). The FIXED per-job knobs (``misfire_grace_time=300`` / ``coalesce`` /
    ``max_instances=1`` / 60s jitter) are NOT configurable here — the loader applies them to every
    job by design.

    * ``jobs_file`` — path to the jobs YAML (relative to the process CWD, or absolute). Defaults to
      ``scheduler/jobs.yaml``.
    * ``principal`` — the principal scheduled runs are attributed to (default ``"scheduler"``).
    """

    model_config = ConfigDict(extra="forbid")

    jobs_file: Path = Path("scheduler/jobs.yaml")
    principal: str = "scheduler"

    @field_validator("jobs_file", mode="after")
    @classmethod
    def _expand_user(cls, v: Path) -> Path:
        return v.expanduser()


# --------------------------------------------------------------------------------------
# models.yaml
# --------------------------------------------------------------------------------------


class ModelPricing(BaseModel):
    """USD-per-MTok pricing for a single model, split by cache tier."""

    model_config = ConfigDict(extra="forbid")

    input: float
    output: float
    cache_read: float
    cache_write: float


class ProviderConfig(BaseModel):
    """How to construct chat models for one provider id used in ``provider:model`` keys."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "anthropic",
        "openai",
        "openai_compatible",
        "azure_openai",
        "google",
        "bedrock",
    ]
    api_key_env: str | None = None
    base_url: str | None = None
    # Azure OpenAI
    azure_endpoint_env: str | None = None
    api_version: str | None = None
    # Bedrock
    region_name: str | None = None
    credentials_profile_name: str | None = None


class ModelsConfig(BaseModel):
    """Model aliases + price table with the boot invariant: every agent model is priced."""

    model_config = ConfigDict(extra="forbid")

    agents: dict[str, str]
    aliases: dict[str, str]
    pricing: dict[str, ModelPricing]
    fallback_pricing: Literal["error"]
    providers: dict[str, ProviderConfig] = {}

    @model_validator(mode="after")
    def _every_agent_model_is_priced(self) -> ModelsConfig:
        """An unpriced model is an unmetered model: refuse to boot if any agent lacks pricing."""
        for role, alias in self.agents.items():
            if alias not in self.aliases:
                raise ValueError(
                    f"agent {role!r} references alias {alias!r} not present in aliases:"
                )
            model_id = self.aliases[alias]
            if model_id not in self.pricing:
                raise ValueError(
                    f"agent {role!r} -> alias {alias!r} -> {model_id!r} has no pricing entry "
                    f"(an unpriced model is an unmetered model)"
                )
            provider_id, _, _ = model_id.partition(":")
            if not provider_id:
                raise ValueError(
                    f"model key {model_id!r} must be shaped as provider:model"
                )
            if self.providers and provider_id not in self.providers:
                raise ValueError(
                    f"model key {model_id!r} references provider {provider_id!r} "
                    f"not present in models.providers"
                )
        return self

    def resolve(self, role: str) -> str:
        """Resolve an agent role (e.g. 'main') to its provider:model string."""
        return self.aliases[self.agents[role]]


# --------------------------------------------------------------------------------------
# budgets.yaml
# --------------------------------------------------------------------------------------


class ResolvedProfile(BaseModel):
    """A fully-resolved budget profile (all limits present). Also the shape of `default`."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    usd: float = Field(gt=0)
    model_calls: int = Field(gt=0)
    tool_calls: int = Field(gt=0)
    shell_calls: int = Field(gt=0)
    recursion_limit: int = Field(gt=0)
    wall_clock_s: int = Field(gt=0)


class PartialProfile(BaseModel):
    """A named profile's overrides; unset fields inherit from `default`."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    usd: float | None = Field(default=None, gt=0)
    model_calls: int | None = Field(default=None, gt=0)
    tool_calls: int | None = Field(default=None, gt=0)
    shell_calls: int | None = Field(default=None, gt=0)
    recursion_limit: int | None = Field(default=None, gt=0)
    wall_clock_s: int | None = Field(default=None, gt=0)


class PerRun(BaseModel):
    """Per-run budget ceilings: a full `default` plus partial named `profiles`."""

    model_config = ConfigDict(extra="forbid")

    default: ResolvedProfile
    profiles: dict[str, PartialProfile] = {}


class Daily(BaseModel):
    """Daily USD envelopes (global and per-principal) + the counter backend.

    ``backend`` selects the :class:`~opendevops.budget.daily.DailyCounter` implementation the
    :func:`~opendevops.budget.daily.build_daily_counter` factory constructs:

    * ``"sqlite"`` (the default, so a config without a ``backend:`` still validates) — the durable
      local :class:`~opendevops.budget.daily.SqliteDailyCounter` on ``audit.dir``, correct for the
      single-process CLI / ``langgraph dev`` tier;
    * ``"redis"`` — the shared, restart-surviving
      :class:`~opendevops.budget.daily.RedisDailyCounter`, required in service mode where several
      LangGraph Server workers must accumulate one daily envelope. It needs ``redis_url`` (the
      compose stack's ``redis`` service, e.g. ``redis://redis:6379/0``); the validator below refuses
      to boot ``backend: redis`` without it — fail-closed, matching the rest of the config.
    """

    model_config = ConfigDict(extra="forbid")

    global_usd: float = Field(gt=0)
    per_principal_usd: float = Field(gt=0)
    backend: Literal["sqlite", "redis"] = "sqlite"
    redis_url: str | None = None

    @model_validator(mode="after")
    def _redis_backend_requires_url(self) -> Daily:
        """``backend: redis`` without ``redis_url`` is a mis-wired shared counter — refuse boot."""
        if self.backend == "redis" and not self.redis_url:
            raise ValueError(
                "budgets.daily.backend='redis' requires budgets.daily.redis_url "
                "(the shared cross-process counter needs a Redis endpoint, e.g. redis://redis:6379/0)"
            )
        return self


class BudgetsConfig(BaseModel):
    """Budget caps + profiles; `profile(name)` overlays a named profile onto `default`."""

    model_config = ConfigDict(extra="forbid")

    trip_ratio: float = Field(gt=0, le=1)
    fail_mode_on_counter_outage: Literal["closed", "open"]
    per_run: PerRun
    daily: Daily

    def profile(self, name: str = "default") -> ResolvedProfile:
        """Resolve a budget profile by overlaying its overrides onto `per_run.default`."""
        base = self.per_run.default
        if name == "default":
            return base
        if name not in self.per_run.profiles:
            known = sorted(["default", *self.per_run.profiles])
            raise KeyError(f"unknown budget profile {name!r}; known profiles: {known}")
        overrides = self.per_run.profiles[name].model_dump(exclude_none=True)
        return base.model_copy(update=overrides)


# --------------------------------------------------------------------------------------
# .env secrets (layered via pydantic-settings; optional, for future use)
# --------------------------------------------------------------------------------------


class Secrets(BaseSettings):
    """Secrets sourced from the process environment and ``.env`` (all optional for now)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    anthropic_api_key: str | None = None
    langsmith_tracing: str | None = None
    langsmith_api_key: str | None = None


# --------------------------------------------------------------------------------------
# aggregate
# --------------------------------------------------------------------------------------


class AppConfig(BaseModel):
    """The aggregate config: the three YAML files plus layered .env secrets."""

    model_config = ConfigDict(extra="forbid")

    targets: Targets
    execution: Execution
    executor: ExecutorConfig = Field(default_factory=ExecutorConfig)
    audit: AuditConfig
    policy: PolicyConfig
    state: StateConfig = Field(default_factory=StateConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    control_plane: ControlPlaneConfig = Field(default_factory=ControlPlaneConfig)
    slack: SlackConfig = Field(default_factory=SlackConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    principals: dict[str, Principal] = {}
    models: ModelsConfig
    budgets: BudgetsConfig
    secrets: Secrets = Field(default_factory=Secrets)


def validate_runtime_config(cfg: AppConfig) -> None:
    """Validate safety invariants required to execute, not merely parse, the template config.

    The repository intentionally ships with an empty Kubernetes context allowlist so operators
    must make an explicit deployment choice. Loading remains useful for tooling and editing, but
    every execution entry point calls this gate and refuses to build until at least one context is
    named.
    """
    if not cfg.targets.kubernetes.allowed_contexts:
        raise ValueError(
            "targets.kubernetes.allowed_contexts is empty; configure at least one explicitly "
            "allowed context before starting the agent"
        )


def _read_yaml(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"config file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping, got {type(data).__name__}")
    return data


def load_config(root: Path | None = None) -> AppConfig:
    """Load and validate the three YAML files under ``<root>/config/`` plus ``<root>/.env``.

    ``root`` defaults to the current working directory. Paths containing ``~`` are expanded.
    Raises ``FileNotFoundError`` if a config file is missing and ``pydantic.ValidationError``
    on any schema violation (unknown key, wrong type, or an unpriced agent model).
    """
    root = Path.cwd() if root is None else Path(root)
    config_dir = root / "config"

    raw_config = _read_yaml(config_dir / "config.yaml")
    raw_models = _read_yaml(config_dir / "models.yaml")
    raw_budgets = _read_yaml(config_dir / "budgets.yaml")

    secrets = Secrets(_env_file=root / ".env")  # type: ignore[call-arg]

    return AppConfig.model_validate(
        {
            **raw_config,
            "models": raw_models,
            "budgets": raw_budgets,
            "secrets": secrets,
        }
    )
