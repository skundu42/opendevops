"""ed25519 signed decision tokens (P5d): valid verifies; every tamper/expiry rejects.

The clock is injectable so expiry is deterministic; the argv + staging hashes are single-sourced
with the audit canonical serializer. Post-fix1 the token also binds the staging PLAN (content +
rewrite metadata) and tool_family, so substituted content / a rewritten staging plan / a swapped
credential family are rejected.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from opendevops.audit.schema import canonical_dumps
from opendevops.tools.signing import (
    DecisionToken,
    SigningKeyUnavailable,
    TokenError,
    argv_sha256,
    decode_private_key,
    decode_public_key,
    encode_private_key,
    encode_public_key,
    generate_keypair,
    load_private_key_from_env,
    load_public_key_from_env,
    sign_decision,
    staging_sha256,
    verify_decision,
    verify_ok,
)

ARGV = ["kubectl", "get", "pods", "-n", "default"]
RUN_ID = "run-123"
TCID = "call-abc"
CHANNEL = "ro"
FAMILY: str | None = "kubectl"


@dataclass
class Staged:
    """A staged-file double satisfying StagedFileLike (the wire ``sha256`` is ignored)."""

    flag: str = "--filename"
    virtual_path: str = "/manifests/deploy.yaml"
    content: str = "apiVersion: apps/v1\nkind: Deployment\n"
    argv_index: int = 5
    inline: bool = False
    inline_prefix: str | None = None
    sha256: str = "ignored-wire-sha"


def _at(t: float):
    return lambda: t


def _signed(now: float = 1000.0, **over):
    priv, pub = generate_keypair()
    argv = over.get("argv", ARGV)
    staged = over.get("staged_files", [])
    run_id = over.get("run_id", RUN_ID)
    tcid = over.get("tool_call_id", TCID)
    channel = over.get("channel", CHANNEL)
    family = over.get("tool_family", FAMILY)
    token = sign_decision(argv, staged, run_id, tcid, channel, family, priv, now=_at(now))
    return token, pub


# --------------------------------------------------------------------------------------
# happy path + injectable clock
# --------------------------------------------------------------------------------------


def test_valid_token_verifies() -> None:
    token, pub = _signed(now=1000.0)
    verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1050.0))
    assert verify_ok(token, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1050.0))


def test_injectable_clock_sets_deterministic_exp() -> None:
    token, _ = _signed(now=5000.0)
    assert token.exp == 5000.0 + 120


def test_just_before_and_at_expiry() -> None:
    token, pub = _signed(now=1000.0)  # exp == 1120
    verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1119.999))
    with pytest.raises(TokenError, match="expired"):
        verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1120.0))


# --------------------------------------------------------------------------------------
# fail-closed rejections — argv / correlation fields
# --------------------------------------------------------------------------------------


def test_expired_rejects() -> None:
    token, pub = _signed(now=1000.0)
    with pytest.raises(TokenError, match="expired"):
        verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(2000.0))


def test_tampered_argv_hash_mismatch_rejects() -> None:
    token, pub = _signed(now=1000.0)
    with pytest.raises(TokenError, match="argv hash"):
        verify_decision(
            token, ["kubectl", "delete", "pods"], [], RUN_ID, TCID, CHANNEL, FAMILY, pub,
            now=_at(1000.0),
        )


def test_wrong_run_id_rejects() -> None:
    token, pub = _signed(now=1000.0)
    with pytest.raises(TokenError, match="run_id"):
        verify_decision(token, ARGV, [], "other-run", TCID, CHANNEL, FAMILY, pub, now=_at(1000.0))


def test_wrong_tool_call_id_rejects() -> None:
    token, pub = _signed(now=1000.0)
    with pytest.raises(TokenError, match="tool_call_id"):
        verify_decision(
            token, ARGV, [], RUN_ID, "other-call", CHANNEL, FAMILY, pub, now=_at(1000.0)
        )


def test_wrong_channel_rejects() -> None:
    token, pub = _signed(now=1000.0)
    with pytest.raises(TokenError, match="channel"):
        verify_decision(token, ARGV, [], RUN_ID, TCID, "rw", FAMILY, pub, now=_at(1000.0))


def test_forged_token_bad_signature_rejects() -> None:
    """A token whose bound argv hash was swapped (but the sig kept) fails signature verification."""
    token, pub = _signed(now=1000.0)
    forged = DecisionToken(
        argv_sha256=argv_sha256(["evil"]),
        staging_sha256=token.staging_sha256,
        run_id=token.run_id,
        tool_call_id=token.tool_call_id,
        channel=token.channel,
        tool_family=token.tool_family,
        exp=token.exp,
        sig=token.sig,
    )
    with pytest.raises(TokenError, match="signature is invalid"):
        verify_decision(forged, ["evil"], [], RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1000.0))


def test_verified_under_wrong_public_key_rejects() -> None:
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    token = sign_decision(ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, priv, now=_at(1000.0))
    assert not verify_ok(token, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, other_pub, now=_at(1000.0))


def test_non_hex_signature_rejects() -> None:
    token, pub = _signed(now=1000.0)
    bad = DecisionToken(**{**token.to_dict(), "sig": "not-hex!!"})
    with pytest.raises(TokenError, match="not valid hex"):
        verify_decision(bad, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1000.0))


def test_malformed_token_dict_rejects() -> None:
    with pytest.raises(TokenError):
        DecisionToken.from_dict({})
    with pytest.raises(TokenError):
        DecisionToken.from_dict("not a dict")


# --------------------------------------------------------------------------------------
# fail-closed rejections — staging plan (C1) + tool_family (C1)
# --------------------------------------------------------------------------------------


def test_faithful_staged_request_verifies() -> None:
    staged = [Staged()]
    token, pub = _signed(now=1000.0, staged_files=staged)
    verify_decision(token, ARGV, staged, RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1050.0))


def test_substituted_content_rejects() -> None:
    """Content B where content A was signed -> recomputed staging_sha256 mismatch."""
    signed = [Staged(content="apiVersion: v1\nkind: ConfigMap\n")]
    token, pub = _signed(now=1000.0, staged_files=signed)
    attacker = [Staged(content="apiVersion: v1\nkind: Secret\n")]  # same metadata, swapped body
    with pytest.raises(TokenError, match="staging plan"):
        verify_decision(token, ARGV, attacker, RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1000.0))


def test_rewritten_argv_index_rejects() -> None:
    signed = [Staged(argv_index=5)]
    token, pub = _signed(now=1000.0, staged_files=signed)
    attacker = [Staged(argv_index=1)]  # rewrite the position the staged path lands at
    with pytest.raises(TokenError, match="staging plan"):
        verify_decision(token, ARGV, attacker, RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1000.0))


def test_rewritten_inline_prefix_rejects() -> None:
    signed = [Staged(inline=False, inline_prefix=None)]
    token, pub = _signed(now=1000.0, staged_files=signed)
    attacker = [Staged(inline=True, inline_prefix="--config=")]  # inject a flag via the rewrite
    with pytest.raises(TokenError, match="staging plan"):
        verify_decision(token, ARGV, attacker, RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1000.0))


def test_altered_flag_or_virtual_path_rejects() -> None:
    signed = [Staged(flag="--filename", virtual_path="/m/a.yaml")]
    token, pub = _signed(now=1000.0, staged_files=signed)
    for attacker in ([Staged(flag="--values")], [Staged(virtual_path="/m/evil.yaml")]):
        with pytest.raises(TokenError, match="staging plan"):
            verify_decision(
                token, ARGV, attacker, RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1000.0)
            )


def test_injected_extra_staged_file_rejects() -> None:
    token, pub = _signed(now=1000.0, staged_files=[])  # no staging signed
    with pytest.raises(TokenError, match="staging plan"):
        verify_decision(
            token, ARGV, [Staged()], RUN_ID, TCID, CHANNEL, FAMILY, pub, now=_at(1000.0)
        )


def test_swapped_tool_family_rejects() -> None:
    token, pub = _signed(now=1000.0, tool_family="kubectl")
    with pytest.raises(TokenError, match="tool_family"):
        verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, "aws", pub, now=_at(1000.0))


def test_none_family_token_verifies_and_rejects_swap() -> None:
    token, pub = _signed(now=1000.0, tool_family=None)
    verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, None, pub, now=_at(1000.0))
    with pytest.raises(TokenError, match="tool_family"):
        verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, "gh", pub, now=_at(1000.0))


def test_staging_sha256_recomputes_content_ignoring_wire_sha() -> None:
    """The plan digest hashes the actual content bytes, NOT any passed-in ``sha256`` field."""
    honest = staging_sha256([Staged(content="X", sha256="honest")])
    lying = staging_sha256([Staged(content="X", sha256="a-lie")])  # different wire sha, same bytes
    assert honest == lying
    different_bytes = staging_sha256([Staged(content="Y", sha256="honest")])
    assert honest != different_bytes


# --------------------------------------------------------------------------------------
# single-sourced hashes + key encoding + env loading
# --------------------------------------------------------------------------------------


def test_argv_hash_single_sourced_with_audit_canonical() -> None:
    """The token's argv hash MUST equal sha256(canonical_dumps(argv)) — the audit serializer."""
    expected = hashlib.sha256(canonical_dumps(list(ARGV)).encode("utf-8")).hexdigest()
    assert argv_sha256(ARGV) == expected


def test_token_dict_roundtrip_preserves_all_bound_fields() -> None:
    token, _ = _signed(now=1000.0, staged_files=[Staged()], tool_family="kubectl")
    assert DecisionToken.from_dict(token.to_dict()) == token
    # None family survives the roundtrip (not stringified to "None")
    none_token, _ = _signed(now=1000.0, tool_family=None)
    assert DecisionToken.from_dict(none_token.to_dict()).tool_family is None


def test_key_base64_roundtrip() -> None:
    priv, pub = generate_keypair()
    priv2 = decode_private_key(encode_private_key(priv))
    pub2 = decode_public_key(encode_public_key(pub))
    token = sign_decision(ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, priv2, now=_at(1000.0))
    verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, pub2, now=_at(1000.0))


def test_load_keys_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    priv, pub = generate_keypair()
    monkeypatch.setenv("AGENT_SIGN_KEY", encode_private_key(priv))
    monkeypatch.setenv("SVC_VERIFY_KEY", encode_public_key(pub))
    loaded_priv = load_private_key_from_env("AGENT_SIGN_KEY")
    loaded_pub = load_public_key_from_env("SVC_VERIFY_KEY")
    token = sign_decision(ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, loaded_priv, now=_at(1000.0))
    verify_decision(token, ARGV, [], RUN_ID, TCID, CHANNEL, FAMILY, loaded_pub, now=_at(1000.0))


def test_load_key_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SigningKeyUnavailable, match="not configured"):
        load_private_key_from_env(None)
    monkeypatch.delenv("MISSING_KEY", raising=False)
    with pytest.raises(SigningKeyUnavailable, match="unset or empty"):
        load_public_key_from_env("MISSING_KEY")
    monkeypatch.setenv("BAD_KEY", "not-base64-ed25519")
    with pytest.raises(SigningKeyUnavailable, match="not a valid"):
        load_private_key_from_env("BAD_KEY")
