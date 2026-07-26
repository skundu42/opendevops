"""OIDC login, opaque server-side sessions, CSRF, and dashboard RBAC."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, ConfigDict

from opendevops.config import AppConfig, DashboardRole
from opendevops.control_plane import ActionIdentity


class DashboardSession(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: str
    subject: str
    display_name: str | None = None
    email: str | None = None
    roles: list[DashboardRole]
    csrf_token: str
    created_at: float
    expires_at: float
    auth_mode: str

    @property
    def identity(self) -> ActionIdentity:
        return ActionIdentity(
            issuer=self.issuer,
            subject=self.subject,
            display_name=self.display_name,
        )

    @property
    def principal(self) -> str:
        return self.identity.principal


class OIDCTransaction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: str
    nonce: str
    code_verifier: str
    created_at: float


class SessionStore(Protocol):
    async def create(self, session: DashboardSession, ttl_s: int) -> str: ...

    async def get(self, token: str) -> DashboardSession | None: ...

    async def delete(self, token: str) -> None: ...

    async def revoke_identity(self, issuer: str, subject: str) -> int: ...

    async def put_transaction(self, transaction: OIDCTransaction, ttl_s: int) -> None: ...

    async def pop_transaction(self, state: str) -> OIDCTransaction | None: ...


def _store_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class MemorySessionStore:
    """Server-side local-development store; process restart revokes every session."""

    def __init__(self, *, now: Any = time.time) -> None:
        self._now = now
        self._sessions: dict[str, DashboardSession] = {}
        self._transactions: dict[str, tuple[float, OIDCTransaction]] = {}
        self._lock = asyncio.Lock()

    async def create(self, session: DashboardSession, ttl_s: int) -> str:
        token = secrets.token_urlsafe(32)
        async with self._lock:
            self._sessions[_store_key(token)] = session
        return token

    async def get(self, token: str) -> DashboardSession | None:
        async with self._lock:
            session = self._sessions.get(_store_key(token))
            if session is not None and session.expires_at <= float(self._now()):
                self._sessions.pop(_store_key(token), None)
                return None
            return session

    async def delete(self, token: str) -> None:
        async with self._lock:
            self._sessions.pop(_store_key(token), None)

    async def revoke_identity(self, issuer: str, subject: str) -> int:
        async with self._lock:
            matches = [
                key
                for key, session in self._sessions.items()
                if session.issuer == issuer and session.subject == subject
            ]
            for key in matches:
                self._sessions.pop(key, None)
            return len(matches)

    async def put_transaction(self, transaction: OIDCTransaction, ttl_s: int) -> None:
        async with self._lock:
            self._transactions[_store_key(transaction.state)] = (
                float(self._now()) + ttl_s,
                transaction,
            )

    async def pop_transaction(self, state: str) -> OIDCTransaction | None:
        async with self._lock:
            item = self._transactions.pop(_store_key(state), None)
        if item is None or item[0] <= float(self._now()):
            return None
        return item[1]


class RedisSessionStore:
    """Shared server-side store for restart-safe, multi-replica session revocation."""

    def __init__(self, url: str) -> None:
        from redis.asyncio import from_url

        self._redis = from_url(url, decode_responses=True)

    @staticmethod
    def _session_key(token: str) -> str:
        return f"opendevops:dashboard:session:{_store_key(token)}"

    @staticmethod
    def _transaction_key(state: str) -> str:
        return f"opendevops:dashboard:oidc:{_store_key(state)}"

    async def create(self, session: DashboardSession, ttl_s: int) -> str:
        token = secrets.token_urlsafe(32)
        key = self._session_key(token)
        await self._redis.set(key, session.model_dump_json(), ex=ttl_s)
        identity_key = f"opendevops:dashboard:identity:{_store_key(session.principal)}"
        async with self._redis.pipeline(transaction=True) as pipeline:
            pipeline.sadd(identity_key, key)
            pipeline.expire(identity_key, ttl_s)
            await pipeline.execute()
        return token

    async def get(self, token: str) -> DashboardSession | None:
        payload = await self._redis.get(self._session_key(token))
        if not payload:
            return None
        session = DashboardSession.model_validate_json(payload)
        if session.expires_at <= time.time():
            await self.delete(token)
            return None
        return session

    async def delete(self, token: str) -> None:
        await self._redis.delete(self._session_key(token))

    async def revoke_identity(self, issuer: str, subject: str) -> int:
        principal = ActionIdentity(issuer=issuer, subject=subject).principal
        identity_key = f"opendevops:dashboard:identity:{_store_key(principal)}"
        keys = await self._redis.smembers(identity_key)
        if keys:
            await self._redis.delete(*keys)
        await self._redis.delete(identity_key)
        return len(keys)

    async def put_transaction(self, transaction: OIDCTransaction, ttl_s: int) -> None:
        await self._redis.set(
            self._transaction_key(transaction.state),
            transaction.model_dump_json(),
            ex=ttl_s,
        )

    async def pop_transaction(self, state: str) -> OIDCTransaction | None:
        key = self._transaction_key(state)
        async with self._redis.pipeline(transaction=True) as pipeline:
            pipeline.get(key)
            pipeline.delete(key)
            result = await pipeline.execute()
        return OIDCTransaction.model_validate_json(result[0]) if result[0] else None


def build_session_store(cfg: AppConfig) -> SessionStore:
    if cfg.server.dashboard_session_backend == "redis":
        assert cfg.server.dashboard_session_redis_url is not None
        return RedisSessionStore(cfg.server.dashboard_session_redis_url)
    return MemorySessionStore()


class DashboardAuthError(RuntimeError):
    pass


_PERMISSIONS: dict[str, set[DashboardRole]] = {
    "dashboard.read": {"viewer", "operator", "approver", "admin"},
    "run.cancel": {"operator", "admin"},
    "approval.resolve": {"approver", "admin"},
    "config.propose": {"operator", "admin"},
    "config.approve": {"approver", "admin"},
    "config.activate": {"admin"},
    "config.revoke": {"admin"},
    "session.revoke": {"admin"},
}


def permitted(session: DashboardSession, permission: str) -> bool:
    allowed = _PERMISSIONS.get(permission, set())
    return bool(set(session.roles) & allowed)


def require_permission(session: DashboardSession, permission: str) -> None:
    if not permitted(session, permission):
        raise DashboardAuthError(f"role does not permit {permission}")


def validate_csrf(session: DashboardSession, provided: str | None) -> None:
    if not provided or not hmac.compare_digest(session.csrf_token, provided):
        raise DashboardAuthError("invalid CSRF token")


@dataclass
class DashboardAuth:
    cfg: AppConfig
    store: SessionStore
    _metadata: dict[str, Any] | None = None
    _metadata_loaded_at: float = 0.0
    _metadata_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def current(self, token: str | None) -> DashboardSession | None:
        return await self.store.get(token) if token else None

    async def static_login(self, provided: str) -> tuple[str, DashboardSession]:
        if self.cfg.server.dashboard_auth_mode != "static":
            raise DashboardAuthError("static-token login is disabled")
        name = self.cfg.server.dashboard_token_env
        expected = os.environ.get(name) if name else None
        if not expected:
            raise DashboardAuthError("dashboard authentication is not configured")
        try:
            valid = hmac.compare_digest(provided.encode(), expected.encode())
        except (TypeError, UnicodeError):
            valid = False
        if not valid:
            raise DashboardAuthError("the submitted credential is invalid")
        now = time.time()
        session = DashboardSession(
            issuer="local-development",
            subject="static-token",
            display_name="Local developer",
            roles=["viewer", "operator", "approver", "admin"],
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + self.cfg.server.dashboard_session_ttl_s,
            auth_mode="static",
        )
        token = await self.store.create(session, self.cfg.server.dashboard_session_ttl_s)
        return token, session

    async def begin_oidc(self) -> str:
        if self.cfg.server.dashboard_auth_mode != "oidc":
            raise DashboardAuthError("OIDC login is disabled")
        metadata = await self._load_metadata()
        client_id = self._client_id()
        oidc = self.cfg.server.oidc
        assert oidc.redirect_uri is not None
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode()
        challenge = challenge.rstrip("=")
        transaction = OIDCTransaction(
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            created_at=time.time(),
        )
        await self.store.put_transaction(transaction, 600)
        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": oidc.redirect_uri,
            "scope": " ".join(oidc.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{metadata['authorization_endpoint']}?{urlencode(params)}"

    async def complete_oidc(
        self, *, state: str | None, code: str | None
    ) -> tuple[str, DashboardSession]:
        if not state or not code:
            raise DashboardAuthError("OIDC callback is missing code or state")
        transaction = await self.store.pop_transaction(state)
        if transaction is None:
            raise DashboardAuthError("OIDC state is invalid or expired")
        metadata = await self._load_metadata()
        oidc = self.cfg.server.oidc
        assert oidc.redirect_uri is not None
        client_id = self._client_id()
        client_secret = (
            os.environ.get(oidc.client_secret_env) if oidc.client_secret_env else None
        )
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        client = AsyncOAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            scope=oidc.scopes,
            code_challenge_method="S256",
        )
        try:
            token = await client.fetch_token(
                str(metadata["token_endpoint"]),
                code=code,
                grant_type="authorization_code",
                redirect_uri=oidc.redirect_uri,
                code_verifier=transaction.code_verifier,
            )
        finally:
            await client.aclose()
        claims = await self._validate_id_token(
            str(token.get("id_token") or ""), metadata, transaction.nonce
        )
        roles = self._roles(claims)
        if not roles:
            raise DashboardAuthError("OIDC identity has no mapped dashboard role")
        now = time.time()
        session = DashboardSession(
            issuer=str(claims["iss"]),
            subject=str(claims["sub"]),
            display_name=str(claims.get("name") or "") or None,
            email=str(claims.get("email") or "") or None,
            roles=roles,
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + self.cfg.server.dashboard_session_ttl_s,
            auth_mode="oidc",
        )
        session_token = await self.store.create(
            session, self.cfg.server.dashboard_session_ttl_s
        )
        return session_token, session

    def _client_id(self) -> str:
        name = self.cfg.server.oidc.client_id_env
        client_id = os.environ.get(name) if name else None
        if not client_id:
            raise DashboardAuthError("OIDC client id is not configured")
        return client_id

    async def _load_metadata(self) -> dict[str, Any]:
        now = time.time()
        if self._metadata is not None and now - self._metadata_loaded_at < 3600:
            return self._metadata
        async with self._metadata_lock:
            issuer = self.cfg.server.oidc.issuer
            if not issuer:
                raise DashboardAuthError("OIDC issuer is not configured")
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                response = await client.get(f"{issuer}/.well-known/openid-configuration")
                response.raise_for_status()
                metadata = response.json()
            if metadata.get("issuer") != issuer:
                raise DashboardAuthError("OIDC discovery issuer does not match configuration")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                endpoint = str(metadata.get(key) or "")
                if not endpoint.startswith(
                    ("https://", "http://localhost", "http://127.0.0.1")
                ):
                    raise DashboardAuthError(f"OIDC discovery returned an unsafe {key}")
            self._metadata = metadata
            self._metadata_loaded_at = now
            return metadata

    async def _validate_id_token(
        self, id_token: str, metadata: dict[str, Any], nonce: str
    ) -> dict[str, Any]:
        if not id_token:
            raise DashboardAuthError("OIDC provider did not return an ID token")
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(str(metadata["jwks_uri"]))
            response.raise_for_status()
            jwks = response.json()
        from authlib.jose import JsonWebToken
        from authlib.oidc.core import CodeIDToken

        algorithms = metadata.get("id_token_signing_alg_values_supported") or ["RS256"]
        algorithms = [str(value) for value in algorithms if str(value).lower() != "none"]
        jwt = JsonWebToken(algorithms)
        claims = jwt.decode(
            id_token,
            jwks,
            claims_cls=CodeIDToken,
            claims_options={
                "iss": {"essential": True, "values": [self.cfg.server.oidc.issuer]},
                "sub": {"essential": True},
                "aud": {"essential": True, "values": [self._client_id()]},
                "exp": {"essential": True},
                "iat": {"essential": True},
                "nonce": {"essential": True, "values": [nonce]},
            },
            claims_params={"client_id": self._client_id(), "nonce": nonce},
        )
        claims.validate(leeway=60)
        if not hmac.compare_digest(str(claims.get("nonce") or ""), nonce):
            raise DashboardAuthError("OIDC nonce validation failed")
        return dict(claims)

    def _roles(self, claims: dict[str, Any]) -> list[DashboardRole]:
        value: Any = claims
        for part in self.cfg.server.oidc.roles_claim.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        claim_values = (
            {str(item) for item in value}
            if isinstance(value, list)
            else {str(value)}
            if value is not None
            else set()
        )
        roles: list[DashboardRole] = list(self.cfg.server.oidc.default_roles)
        for role, accepted in self.cfg.server.oidc.role_mappings.items():
            if claim_values & set(accepted):
                roles.append(role)
        return list(dict.fromkeys(roles))
