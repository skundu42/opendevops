"""ed25519-signed decision tokens for the executor split.

On the remote executor path the agent process holds **no** infra credential and **no** secret
value; the only thing it holds is an ed25519 *private* signing key. Every exec request carries a
:class:`DecisionToken` — an ed25519 signature over the exact command the policy engine authorized
plus the run-correlation fields — so the standalone executor **service** (which holds the *public*
key only) can prove the request passed the policy engine without re-running it, and reject anything
that did not.

Token contract::

    signature = ed25519_sign(private_key, canonical_payload)
    canonical_payload = canonical_dumps({
        "argv_sha256":    sha256(canonical_dumps(argv)),   # the authorized argv, single-sourced
        "staging_sha256": sha256(canonical_dumps(plan)),   # staged-file PLAN (content + rewrite)
        "run_id":         run_id,                          # binds the audit-chain correlation id
        "tool_call_id":   tool_call_id,                    # binds the exact tool call
        "channel":        channel,                         # ro | rw credential channel
        "tool_family":    tool_family,                     # binds the credential family (or null)
        "environment":    environment,                     # staging | prod — pod isolation binding
        "host":           host,                            # ssh_run host; null for run_command
        "exp":            now + 120,                       # unix seconds; short-lived
    })

Binding ``staging_sha256`` + ``tool_family`` + ``environment`` + ``host`` is what makes "the signed
decision is EXACTLY what runs" hold on the remote path. Without them the executor service would
materialize + rewrite argv + select a credential from the UNSIGNED request body, letting a
MITM/replay substitute manifest CONTENT, inject a flag via a rewritten ``argv_index``/
``inline_prefix``, swap ``tool_family`` to pull a different credential, route a ``staging``
decision onto a ``prod`` pod, or swap the ssh target host. The staging plan
(:func:`staging_sha256`) binds each file's
``{flag, virtual_path, content_sha256, argv_index, inline, inline_prefix}`` — the content sha
**recomputed from the actual bytes**, so substituted content fails verification.

The argv + staging hashes use :func:`opendevops.audit.schema.canonical_dumps` — the **same**
serializer the audit hash chain uses — so the signer (agent) and the verifier (service) can never
disagree on the bytes being signed (single-sourced, no second canonicalizer).

Fail-closed verification (:func:`verify_decision`): any mismatch — bad signature, expired,
argv-hash mismatch, staging-plan mismatch, or a bound field (``run_id`` / ``tool_call_id`` /
``channel`` / ``tool_family`` / ``environment`` / ``host``) that differs from the request — is a
hard reject that raises :class:`TokenError`. There is **no** signature-stripping /
algorithm-confusion path: the service verifies an ed25519 signature with the public key, full
stop. The expiry clock is injectable (``now``) so tests are deterministic; product code passes the
real :func:`time.time`.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from opendevops.audit.schema import canonical_dumps

# The token lifetime: short by design (a signed decision runs promptly or is re-authorized).
TOKEN_TTL_S = 120


class TokenError(Exception):
    """A decision token failed verification (bad sig / expired / argv-hash or bound-field mismatch).

    Raised by :func:`verify_decision`; the executor service maps it to a 4xx and never executes.
    """


def argv_sha256(argv: Sequence[str]) -> str:
    """``sha256`` (hex) of the canonical serialization of *argv* — the single-sourced argv hash.

    Uses :func:`opendevops.audit.schema.canonical_dumps`, the same serializer the audit chain
    uses, so the signer and verifier derive identical bytes for identical argv.
    """
    return hashlib.sha256(canonical_dumps(list(argv)).encode("utf-8")).hexdigest()


@runtime_checkable
class StagedFileLike(Protocol):
    """The staged-file fields :func:`staging_sha256` needs — satisfied by both sides.

    The agent's ``FileRef`` (from ``tools.staging``) and the service's ``_StagedFileWire`` (the
    request-body model) both expose these attributes structurally, so ONE implementation of the
    plan digest serves signer and verifier. ``content`` is the file bytes-as-str; the digest
    RECOMPUTES its sha here rather than trusting any wire ``sha256`` field.
    """

    flag: str
    virtual_path: str
    content: str
    argv_index: int
    inline: bool
    inline_prefix: str | None


def staging_sha256(staged_files: Sequence[StagedFileLike]) -> str:
    """``sha256`` (hex) of the canonical staging PLAN — content + rewrite metadata, in order.

    One ordered entry per staged file:
    ``{flag, virtual_path, content_sha256: sha256(content), argv_index, inline, inline_prefix}``.
    The ``content_sha256`` is **recomputed from the actual content bytes** — never a passed-in /
    wire ``sha256`` field (``content.encode(utf-8)``, matching how ``staging.stage`` writes them) —
    so a substituted body cannot pass verification. Empty plan → sha of ``[]`` (a stable constant),
    so a no-staging token verifies against a no-staging request and an INJECTED staged file fails.
    """
    plan = [
        {
            "flag": f.flag,
            "virtual_path": f.virtual_path,
            "content_sha256": hashlib.sha256(f.content.encode("utf-8")).hexdigest(),
            "argv_index": f.argv_index,
            "inline": f.inline,
            "inline_prefix": f.inline_prefix,
        }
        for f in staged_files
    ]
    return hashlib.sha256(canonical_dumps(plan).encode("utf-8")).hexdigest()


def _canonical_payload(
    argv_hash: str,
    staging_hash: str,
    run_id: str,
    tool_call_id: str,
    channel: str,
    tool_family: str | None,
    environment: str,
    host: str | None,
    exp: float,
) -> bytes:
    """The exact bytes signed / verified: a canonical JSON object over the bound fields."""
    return canonical_dumps(
        {
            "argv_sha256": argv_hash,
            "staging_sha256": staging_hash,
            "run_id": run_id,
            "tool_call_id": tool_call_id,
            "channel": channel,
            "tool_family": tool_family,
            "environment": environment,
            "host": host,
            "exp": exp,
        }
    ).encode("utf-8")


@dataclass(frozen=True)
class DecisionToken:
    """A signed authorization for exactly one execution.

    Carries the bound field VALUES plus the ed25519 signature (hex). The verifier re-derives the
    argv hash from the request's argv and checks every bound value against the request, then
    verifies the signature over the token's own canonical payload — so a token minted for a
    different argv / run / call / channel / environment / host, or a forged one, is rejected.
    """

    argv_sha256: str
    staging_sha256: str
    run_id: str
    tool_call_id: str
    channel: str
    tool_family: str | None
    environment: str
    host: str | None
    exp: float
    sig: str  # hex-encoded ed25519 signature over :func:`_canonical_payload`

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable form for the request body."""
        return {
            "argv_sha256": self.argv_sha256,
            "staging_sha256": self.staging_sha256,
            "run_id": self.run_id,
            "tool_call_id": self.tool_call_id,
            "channel": self.channel,
            "tool_family": self.tool_family,
            "environment": self.environment,
            "host": self.host,
            "exp": self.exp,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, data: Any) -> DecisionToken:
        """Rebuild a token from a request body; fail-closed on a malformed shape."""
        if not isinstance(data, dict):
            raise TokenError("decision token is missing or not an object")
        try:
            raw_family = data.get("tool_family")
            raw_host = data.get("host")
            return cls(
                argv_sha256=str(data["argv_sha256"]),
                staging_sha256=str(data["staging_sha256"]),
                run_id=str(data["run_id"]),
                tool_call_id=str(data["tool_call_id"]),
                channel=str(data["channel"]),
                # tool_family / host are str | None — preserve None (do NOT str(None) -> "None").
                tool_family=None if raw_family is None else str(raw_family),
                environment=str(data["environment"]),
                host=None if raw_host is None else str(raw_host),
                exp=float(data["exp"]),
                sig=str(data["sig"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TokenError(f"decision token is malformed: {exc}") from exc


def sign_decision(
    argv: Sequence[str],
    staged_files: Sequence[StagedFileLike],
    run_id: str,
    tool_call_id: str,
    channel: str,
    tool_family: str | None,
    private_key: Ed25519PrivateKey,
    *,
    environment: str,
    host: str | None = None,
    now: Callable[[], float] = time.time,
    ttl_s: int = TOKEN_TTL_S,
) -> DecisionToken:
    """Sign the authorized argv + staging plan + correlation fields into a :class:`DecisionToken`.

    ``staged_files`` is the exact staging plan the agent's ``resolve_file_refs`` produced (its
    content + rewrite metadata is bound via :func:`staging_sha256`); ``tool_family`` is the
    credential family the decision authorized; ``environment`` binds the policy overlay /
    executor-pod identity; ``host`` binds an ``ssh_run`` target (``None`` for ``run_command``).
    ``now`` is injectable so ``exp`` is deterministic in tests; product code uses ``time.time``.
    """
    argv_hash = argv_sha256(argv)
    staging_hash = staging_sha256(staged_files)
    exp = now() + ttl_s
    payload = _canonical_payload(
        argv_hash,
        staging_hash,
        run_id,
        tool_call_id,
        channel,
        tool_family,
        environment,
        host,
        exp,
    )
    sig = private_key.sign(payload).hex()
    return DecisionToken(
        argv_sha256=argv_hash,
        staging_sha256=staging_hash,
        run_id=run_id,
        tool_call_id=tool_call_id,
        channel=channel,
        tool_family=tool_family,
        environment=environment,
        host=host,
        exp=exp,
        sig=sig,
    )


def verify_decision(
    token: DecisionToken,
    argv: Sequence[str],
    staged_files: Sequence[StagedFileLike],
    run_id: str,
    tool_call_id: str,
    channel: str,
    tool_family: str | None,
    public_key: Ed25519PublicKey,
    *,
    environment: str,
    host: str | None = None,
    now: Callable[[], float] = time.time,
) -> None:
    """Fail-closed verification; raises :class:`TokenError` on ANY mismatch, else returns ``None``.

    Checks, in order: (1) the ed25519 signature over the token's own bound fields is valid under
    the public key — proving the token is authentic and untampered; (2) it has not expired;
    (3) the request's argv hashes to the signed ``argv_sha256``; (4) the request's staging PLAN
    (content recomputed from the RECEIVED bytes + rewrite metadata) hashes to the signed
    ``staging_sha256`` — so substituted content or a rewritten ``argv_index``/``inline_prefix``
    fails; (5) every bound field (``run_id`` / ``tool_call_id`` / ``channel`` / ``tool_family`` /
    ``environment`` / ``host``) matches the request. There is no path that skips the signature or
    trusts an unsigned request.
    """
    # 1. Signature over the token's OWN fields — authenticity before anything else.
    payload = _canonical_payload(
        token.argv_sha256,
        token.staging_sha256,
        token.run_id,
        token.tool_call_id,
        token.channel,
        token.tool_family,
        token.environment,
        token.host,
        token.exp,
    )
    try:
        raw_sig = bytes.fromhex(token.sig)
    except ValueError as exc:
        raise TokenError("decision token signature is not valid hex") from exc
    try:
        public_key.verify(raw_sig, payload)
    except InvalidSignature as exc:
        raise TokenError("decision token signature is invalid") from exc

    # 2. Expiry (injectable clock).
    if now() >= token.exp:
        raise TokenError("decision token has expired")

    # 3. The request's argv must hash to the signed value (blocks argv tampering post-signing).
    if argv_sha256(argv) != token.argv_sha256:
        raise TokenError("decision token argv hash does not match the request argv")

    # 4. The staging plan (content recomputed from the received bytes) must hash to the signed
    #    value — blocks content substitution + argv_index/inline_prefix/flag/virtual_path rewrites.
    if staging_sha256(staged_files) != token.staging_sha256:
        raise TokenError("decision token staging plan does not match the request")

    # 5. Every bound correlation/credential field must match the request.
    if token.run_id != run_id:
        raise TokenError("decision token run_id does not match the request")
    if token.tool_call_id != tool_call_id:
        raise TokenError("decision token tool_call_id does not match the request")
    if token.channel != channel:
        raise TokenError("decision token channel does not match the request")
    if token.tool_family != tool_family:
        raise TokenError("decision token tool_family does not match the request")
    if token.environment != environment:
        raise TokenError("decision token environment does not match the request")
    if token.host != host:
        raise TokenError("decision token host does not match the request")


def verify_ok(
    token: DecisionToken,
    argv: Sequence[str],
    staged_files: Sequence[StagedFileLike],
    run_id: str,
    tool_call_id: str,
    channel: str,
    tool_family: str | None,
    public_key: Ed25519PublicKey,
    *,
    environment: str,
    host: str | None = None,
    now: Callable[[], float] = time.time,
) -> bool:
    """Boolean convenience wrapper around :func:`verify_decision` (True iff it verifies)."""
    try:
        verify_decision(
            token,
            argv,
            staged_files,
            run_id,
            tool_call_id,
            channel,
            tool_family,
            public_key,
            environment=environment,
            host=host,
            now=now,
        )
    except TokenError:
        return False
    return True


# --------------------------------------------------------------------------------------
# key material: base64(raw 32 bytes) in env vars (names live in config, values in the env)
# --------------------------------------------------------------------------------------


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """A fresh ed25519 keypair (private on the agent, public on the service). For keygen/tests."""
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def encode_private_key(key: Ed25519PrivateKey) -> str:
    """base64 of the raw 32-byte private key (the value an operator sets in the signing-key env)."""
    from cryptography.hazmat.primitives import serialization

    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def encode_public_key(key: Ed25519PublicKey) -> str:
    """base64 of the raw 32-byte public key (the value an operator sets in the verify-key env)."""
    from cryptography.hazmat.primitives import serialization

    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def decode_private_key(encoded: str) -> Ed25519PrivateKey:
    """Parse a base64(raw 32-byte) private key; raise :class:`ValueError` on a bad encoding."""
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(encoded))


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    """Parse a base64(raw 32-byte) public key; raise :class:`ValueError` on a bad encoding."""
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded))


class SigningKeyUnavailable(Exception):
    """Raised when the configured signing/verify key env var is unset, empty, or malformed."""


def load_private_key_from_env(var_name: str | None) -> Ed25519PrivateKey:
    """Load the agent's ed25519 PRIVATE key from the env var *var_name* (base64 raw 32 bytes).

    Fail-closed (matches the credential-resolution pattern): an unconfigured name, an unset/empty
    variable, or a value that does not decode to a 32-byte key raises ``SigningKeyUnavailable``.
    The key value itself is never logged.
    """
    if not var_name:
        raise SigningKeyUnavailable(
            "executor signing key env var not configured (executor.signing_key_env)"
        )
    value = os.environ.get(var_name)
    if not value:
        raise SigningKeyUnavailable(f"executor signing key env var {var_name!r} is unset or empty")
    try:
        return decode_private_key(value)
    except Exception as exc:  # noqa: BLE001 - never echo the key value in the error
        raise SigningKeyUnavailable(
            f"executor signing key env var {var_name!r} is not a valid base64 ed25519 private key"
        ) from exc


def load_public_key_from_env(var_name: str | None) -> Ed25519PublicKey:
    """Load the service's ed25519 PUBLIC key from the env var *var_name* (base64 raw 32 bytes).

    Fail-closed on an unconfigured name / unset variable / malformed value, exactly like
    :func:`load_private_key_from_env`. The service holds the public key ONLY.
    """
    if not var_name:
        raise SigningKeyUnavailable(
            "executor verify key env var not configured (executor.verify_key_env)"
        )
    value = os.environ.get(var_name)
    if not value:
        raise SigningKeyUnavailable(f"executor verify key env var {var_name!r} is unset or empty")
    try:
        return decode_public_key(value)
    except Exception as exc:  # noqa: BLE001 - never echo the key value in the error
        raise SigningKeyUnavailable(
            f"executor verify key env var {var_name!r} is not a valid base64 ed25519 public key"
        ) from exc
