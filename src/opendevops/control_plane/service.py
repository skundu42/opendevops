"""Versioned capability grants shared by the CLI, dashboard, and runtime policy gate.

The database is deliberately narrow: operators do not submit arbitrary YAML or command strings.
They request a typed, expiring capability for an environment and explicit targets. Production
requests need a different approver, and activation is a separate admin action. Runtime
consumption is transactional, so concurrent workers share the same execution, retry, cooldown,
and failure limits.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from opendevops.audit.schema import canonical_dumps
from opendevops.config import ControlPlaneConfig


class Capability(StrEnum):
    kubernetes_deploy = "kubernetes_deploy"
    github_write = "github_write"
    aws_deploy = "aws_deploy"
    gcp_deploy = "gcp_deploy"
    azure_deploy = "azure_deploy"
    ssh_mutation = "ssh_mutation"


class ProposalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    active = "active"
    rejected = "rejected"
    revoked = "revoked"
    expired = "expired"


class ActionIdentity(BaseModel):
    """Stable actor identity; OIDC identities are always issuer + subject."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str
    subject: str
    display_name: str | None = None

    @property
    def principal(self) -> str:
        return f"oidc:{self.issuer}#{self.subject}"


class CapabilityGrantRequest(BaseModel):
    """The only configuration mutation accepted by the control plane."""

    model_config = ConfigDict(extra="forbid")

    environment: str
    capability: Capability
    targets: list[str] = Field(min_length=1, max_length=50)
    reason: str = Field(min_length=8, max_length=500)
    ttl_s: int | None = Field(default=None, ge=60, le=604800)
    max_executions: int = Field(default=10, ge=1, le=100)
    max_executions_per_run: int = Field(default=4, ge=1, le=25)
    max_identical_per_run: int = Field(default=1, ge=1, le=5)
    max_consecutive_failures: int = Field(default=2, ge=1, le=5)
    cooldown_s: int = Field(default=10, ge=0, le=3600)
    require_dry_run: bool = True

    @field_validator("environment")
    @classmethod
    def _environment(cls, value: str) -> str:
        if value not in {"staging", "prod"}:
            raise ValueError("environment must be staging or prod")
        return value

    @field_validator("targets")
    @classmethod
    def _targets(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            target = value.strip()
            if not target or target in {"*", "all"} or "*" in target:
                raise ValueError("targets must be explicit; wildcards are forbidden")
            if len(target) > 200:
                raise ValueError("a target may not exceed 200 characters")
            normalized.append(target)
        if len(set(normalized)) != len(normalized):
            raise ValueError("targets must not contain duplicates")
        return normalized


class CapabilityProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    revision: int
    status: ProposalStatus
    request: CapabilityGrantRequest
    requester: ActionIdentity
    created_at: str
    expires_at: str
    approver: ActionIdentity | None = None
    approved_at: str | None = None
    activated_by: ActionIdentity | None = None
    activated_at: str | None = None
    revoked_by: ActionIdentity | None = None
    revoked_at: str | None = None
    rejection_reason: str | None = None
    executions_used: int = 0


class ChangeControlError(RuntimeError):
    """A safe user-facing refusal from the control-plane state machine."""


def _utc_iso(epoch: float | None = None) -> str:
    value = datetime.fromtimestamp(epoch if epoch is not None else time.time(), UTC)
    return value.isoformat().replace("+00:00", "Z")


def capability_for_family(tool_family: str | None) -> Capability | None:
    return {
        "k8s": Capability.kubernetes_deploy,
        "kubectl": Capability.kubernetes_deploy,
        "gh": Capability.github_write,
        "github": Capability.github_write,
        "aws": Capability.aws_deploy,
        "gcloud": Capability.gcp_deploy,
        "az": Capability.azure_deploy,
        "ssh": Capability.ssh_mutation,
    }.get(str(tool_family or "").lower())


class ChangeControlService:
    """Transactional proposal ledger and runtime dangerous-action guard."""

    def __init__(self, config: ControlPlaneConfig, *, now: Any = time.time) -> None:
        self._config = config
        self._path = Path(config.database)
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._now = now
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS proposals (
                    proposal_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    executions_used INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_usage (
                    run_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    action_count INTEGER NOT NULL DEFAULT 0,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    last_action_at REAL,
                    PRIMARY KEY (run_id, fingerprint)
                );
                CREATE TABLE IF NOT EXISTS control_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                );
                """
            )

    def _write_proposal(self, connection: sqlite3.Connection, proposal: CapabilityProposal) -> None:
        payload = proposal.model_dump_json()
        connection.execute(
            """
            INSERT INTO proposals (
                proposal_id, revision, status, environment, capability, expires_at,
                executions_used, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(proposal_id) DO UPDATE SET
                revision=excluded.revision,
                status=excluded.status,
                expires_at=excluded.expires_at,
                executions_used=excluded.executions_used,
                payload=excluded.payload
            """,
            (
                proposal.proposal_id,
                proposal.revision,
                proposal.status.value,
                proposal.request.environment,
                proposal.request.capability.value,
                datetime.fromisoformat(proposal.expires_at.replace("Z", "+00:00")).timestamp(),
                proposal.executions_used,
                payload,
            ),
        )

    @staticmethod
    def _row_proposal(row: sqlite3.Row) -> CapabilityProposal:
        return CapabilityProposal.model_validate_json(str(row["payload"]))

    def _event(
        self,
        connection: sqlite3.Connection,
        action: str,
        actor: ActionIdentity,
        payload: dict[str, Any],
    ) -> None:
        last = connection.execute(
            "SELECT hash FROM control_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = str(last["hash"]) if last else "sha256:genesis"
        occurred_at = _utc_iso(self._now())
        content = {
            "occurred_at": occurred_at,
            "action": action,
            "issuer": actor.issuer,
            "subject": actor.subject,
            "payload": payload,
        }
        digest = "sha256:" + hashlib.sha256(
            (previous + canonical_dumps(content)).encode()
        ).hexdigest()
        connection.execute(
            """
            INSERT INTO control_events
                (occurred_at, action, issuer, subject, payload, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                occurred_at,
                action,
                actor.issuer,
                actor.subject,
                canonical_dumps(payload),
                previous,
                digest,
            ),
        )

    def record_action(
        self, action: str, actor: ActionIdentity, payload: dict[str, Any] | None = None
    ) -> None:
        with self._lock, self._connect() as connection:
            self._event(connection, action, actor, payload or {})

    def propose(
        self, request: CapabilityGrantRequest, requester: ActionIdentity
    ) -> CapabilityProposal:
        ttl = request.ttl_s or self._config.default_grant_ttl_s
        if ttl > self._config.max_grant_ttl_s:
            raise ChangeControlError("requested grant lifetime exceeds the configured maximum")
        if request.cooldown_s < self._config.minimum_cooldown_s:
            raise ChangeControlError("requested cooldown is below the configured minimum")
        if request.capability in {
            Capability.kubernetes_deploy,
            Capability.aws_deploy,
            Capability.gcp_deploy,
            Capability.azure_deploy,
        } and not request.require_dry_run:
            raise ChangeControlError("deployment capabilities always require a dry run")

        now = float(self._now())
        proposal = CapabilityProposal(
            proposal_id=str(uuid.uuid4()),
            revision=1,
            status=ProposalStatus.pending,
            request=request.model_copy(update={"ttl_s": ttl}),
            requester=requester,
            created_at=_utc_iso(now),
            expires_at=_utc_iso(now + ttl),
        )
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._write_proposal(connection, proposal)
            self._event(
                connection,
                "config.proposed",
                requester,
                {
                    "proposal_id": proposal.proposal_id,
                    "revision": proposal.revision,
                    "environment": request.environment,
                    "capability": request.capability.value,
                },
            )
            connection.commit()
        return proposal

    def get(self, proposal_id: str) -> CapabilityProposal:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
        if row is None:
            raise ChangeControlError("capability proposal not found")
        return self._expire_if_needed(self._row_proposal(row))

    def list(self, *, limit: int = 100) -> list[CapabilityProposal]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM proposals ORDER BY rowid DESC LIMIT ?", (min(limit, 200),)
            ).fetchall()
        return [self._expire_if_needed(self._row_proposal(row)) for row in rows]

    def _expire_if_needed(self, proposal: CapabilityProposal) -> CapabilityProposal:
        expiry = datetime.fromisoformat(proposal.expires_at.replace("Z", "+00:00")).timestamp()
        if proposal.status in {
            ProposalStatus.pending,
            ProposalStatus.approved,
            ProposalStatus.active,
        } and expiry <= float(self._now()):
            proposal = proposal.model_copy(
                update={"status": ProposalStatus.expired, "revision": proposal.revision + 1}
            )
            with self._lock, self._connect() as connection:
                self._write_proposal(connection, proposal)
        return proposal

    def approve(self, proposal_id: str, approver: ActionIdentity) -> CapabilityProposal:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
            if row is None:
                raise ChangeControlError("capability proposal not found")
            proposal = self._row_proposal(row)
            if proposal.status is not ProposalStatus.pending:
                raise ChangeControlError("only pending proposals can be approved")
            if (
                proposal.request.environment == "prod"
                and self._config.production_requires_independent_approval
                and approver.issuer == proposal.requester.issuer
                and approver.subject == proposal.requester.subject
            ):
                raise ChangeControlError(
                    "production changes require an approver different from the requester"
                )
            proposal = proposal.model_copy(
                update={
                    "status": ProposalStatus.approved,
                    "revision": proposal.revision + 1,
                    "approver": approver,
                    "approved_at": _utc_iso(self._now()),
                }
            )
            self._write_proposal(connection, proposal)
            self._event(
                connection,
                "config.approved",
                approver,
                {"proposal_id": proposal_id, "revision": proposal.revision},
            )
            connection.commit()
        return proposal

    def activate(self, proposal_id: str, admin: ActionIdentity) -> CapabilityProposal:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
            if row is None:
                raise ChangeControlError("capability proposal not found")
            proposal = self._row_proposal(row)
            if proposal.status is not ProposalStatus.approved:
                raise ChangeControlError("only approved proposals can be activated")
            proposal = proposal.model_copy(
                update={
                    "status": ProposalStatus.active,
                    "revision": proposal.revision + 1,
                    "activated_by": admin,
                    "activated_at": _utc_iso(self._now()),
                }
            )
            self._write_proposal(connection, proposal)
            self._event(
                connection,
                "config.activated",
                admin,
                {"proposal_id": proposal_id, "revision": proposal.revision},
            )
            connection.commit()
        return proposal

    def reject(
        self, proposal_id: str, approver: ActionIdentity, reason: str
    ) -> CapabilityProposal:
        if not reason.strip():
            raise ChangeControlError("a rejection reason is required")
        return self._terminal_transition(
            proposal_id,
            ProposalStatus.rejected,
            approver,
            "config.rejected",
            {"rejection_reason": reason[:500]},
        )

    def revoke(self, proposal_id: str, admin: ActionIdentity) -> CapabilityProposal:
        return self._terminal_transition(
            proposal_id, ProposalStatus.revoked, admin, "config.revoked", {}
        )

    def _terminal_transition(
        self,
        proposal_id: str,
        status: ProposalStatus,
        actor: ActionIdentity,
        action: str,
        updates: dict[str, Any],
    ) -> CapabilityProposal:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
            if row is None:
                raise ChangeControlError("capability proposal not found")
            proposal = self._row_proposal(row)
            if proposal.status in {
                ProposalStatus.rejected,
                ProposalStatus.revoked,
                ProposalStatus.expired,
            }:
                raise ChangeControlError("proposal is already terminal")
            if status is ProposalStatus.revoked:
                updates.update({"revoked_by": actor, "revoked_at": _utc_iso(self._now())})
            proposal = proposal.model_copy(
                update={
                    **updates,
                    "status": status,
                    "revision": proposal.revision + 1,
                }
            )
            self._write_proposal(connection, proposal)
            self._event(
                connection,
                action,
                actor,
                {"proposal_id": proposal_id, "revision": proposal.revision},
            )
            connection.commit()
        return proposal

    def authorize_rw(
        self,
        *,
        run_id: str,
        environment: str,
        principal: str,
        tool_family: str | None,
        fingerprint: str,
    ) -> str | None:
        """Consume one guarded rw operation, returning its grant id when grants are enforced."""
        if not self._config.enforce_runtime_grants:
            return None
        capability = capability_for_family(tool_family)
        now = float(self._now())
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            usage_rows = connection.execute(
                "SELECT * FROM run_usage WHERE run_id = ?", (run_id,)
            ).fetchall()
            total = sum(int(row["action_count"]) for row in usage_rows)
            if total >= self._config.max_rw_actions_per_run:
                raise ChangeControlError("dangerous-action run limit reached")
            failures = max(
                (int(row["consecutive_failures"]) for row in usage_rows), default=0
            )
            if failures >= self._config.max_consecutive_failures:
                raise ChangeControlError("dangerous actions stopped after repeated failures")

            row = connection.execute(
                "SELECT * FROM run_usage WHERE run_id = ? AND fingerprint = ?",
                (run_id, fingerprint),
            ).fetchone()
            if row is not None:
                if int(row["action_count"]) >= self._config.max_identical_rw_actions_per_run:
                    raise ChangeControlError("identical dangerous-action loop detected")
                last = row["last_action_at"]
                if last is not None and now - float(last) < self._config.minimum_cooldown_s:
                    raise ChangeControlError("dangerous action is inside its cooldown window")

            proposal: CapabilityProposal | None = None
            if self._grants_required(environment):
                if capability is None:
                    raise ChangeControlError("rw tool family has no controlled capability mapping")
                candidates = connection.execute(
                    """
                    SELECT * FROM proposals
                    WHERE status = 'active' AND environment = ? AND capability = ?
                      AND expires_at > ? AND executions_used < 100
                    ORDER BY rowid DESC
                    """,
                    (environment, capability.value, now),
                ).fetchall()
                for candidate in candidates:
                    parsed = self._row_proposal(candidate)
                    if parsed.executions_used < parsed.request.max_executions:
                        proposal = parsed
                        break
                if proposal is None:
                    raise ChangeControlError(
                        f"no active {capability.value} grant for {environment}"
                    )
                per_run = connection.execute(
                    """
                    SELECT COALESCE(SUM(action_count), 0) AS count
                    FROM run_usage WHERE run_id = ?
                    """,
                    (run_id,),
                ).fetchone()
                if int(per_run["count"]) >= proposal.request.max_executions_per_run:
                    raise ChangeControlError("capability grant per-run limit reached")
                if (
                    row is not None
                    and int(row["action_count"])
                    >= proposal.request.max_identical_per_run
                ):
                    raise ChangeControlError("capability grant repeat limit reached")
                if (
                    row is not None
                    and row["last_action_at"] is not None
                    and now - float(row["last_action_at"]) < proposal.request.cooldown_s
                ):
                    raise ChangeControlError("capability grant cooldown is active")

            connection.execute(
                """
                INSERT INTO run_usage
                    (run_id, fingerprint, action_count, consecutive_failures, last_action_at)
                VALUES (?, ?, 1, 0, ?)
                ON CONFLICT(run_id, fingerprint) DO UPDATE SET
                    action_count = action_count + 1,
                    last_action_at = excluded.last_action_at
                """,
                (run_id, fingerprint, now),
            )
            if proposal is not None:
                proposal = proposal.model_copy(
                    update={"executions_used": proposal.executions_used + 1}
                )
                self._write_proposal(connection, proposal)
                self._event(
                    connection,
                    "grant.consumed",
                    ActionIdentity(issuer="agent", subject=principal),
                    {
                        "proposal_id": proposal.proposal_id,
                        "run_id": run_id,
                        "capability": proposal.request.capability.value,
                    },
                )
            connection.commit()
        return proposal.proposal_id if proposal is not None else None

    def require_active_grant(
        self, *, environment: str, tool_family: str | None
    ) -> str | None:
        """Fail before an approval prompt when the environment requires a missing grant."""
        if not self._grants_required(environment):
            return None
        capability = capability_for_family(tool_family)
        if capability is None:
            raise ChangeControlError("rw tool family has no controlled capability mapping")
        now = float(self._now())
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM proposals
                WHERE status = 'active' AND environment = ? AND capability = ?
                  AND expires_at > ?
                ORDER BY rowid DESC
                """,
                (environment, capability.value, now),
            ).fetchall()
        for row in rows:
            proposal = self._row_proposal(row)
            if proposal.executions_used < proposal.request.max_executions:
                return proposal.proposal_id
        raise ChangeControlError(f"no active {capability.value} grant for {environment}")

    def _grants_required(self, environment: str) -> bool:
        return (
            self._config.enforce_runtime_grants
            and environment in self._config.grant_required_environments
        )

    def record_rw_result(self, *, run_id: str, fingerprint: str, succeeded: bool) -> None:
        with self._lock, self._connect() as connection:
            if succeeded:
                connection.execute(
                    """
                    UPDATE run_usage SET consecutive_failures = 0
                    WHERE run_id = ? AND fingerprint = ?
                    """,
                    (run_id, fingerprint),
                )
            else:
                connection.execute(
                    """
                    UPDATE run_usage
                    SET consecutive_failures = consecutive_failures + 1
                    WHERE run_id = ? AND fingerprint = ?
                    """,
                    (run_id, fingerprint),
                )

    def revision(self) -> str:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT proposal_id, revision, status, payload FROM proposals ORDER BY proposal_id"
            ).fetchall()
        payload = [dict(row) for row in rows]
        return "sha256:" + hashlib.sha256(canonical_dumps(payload).encode()).hexdigest()

    def events(self, *, limit: int = 100) -> builtins.list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, occurred_at, action, issuer, subject, payload, prev_hash, hash
                FROM control_events ORDER BY sequence DESC LIMIT ?
                """,
                (min(limit, 200),),
            ).fetchall()
        return [
            {
                **dict(row),
                "payload": json.loads(str(row["payload"])),
            }
            for row in rows
        ]
