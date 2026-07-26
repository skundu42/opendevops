"""{{secret:NAME}} resolver: standalone env declaration, never argv expansion."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from opendevops.tools.scrub import scrub_full
from opendevops.tools.secrets import (
    EnvSecretSource,
    SecretResolutionError,
    has_secret_tokens,
    resolve_secrets,
)


@dataclass
class DictSource:
    """A minimal SecretSource over a dict (empty string is treated as present, unlike env)."""

    data: dict[str, str]

    def get(self, name: str) -> str | None:
        return self.data.get(name)


def test_embedded_secret_reference_fails_closed() -> None:
    src = DictSource({"TOKEN": "s3cr3t-value"})
    with pytest.raises(SecretResolutionError, match="standalone argv"):
        resolve_secrets(["curl", "-H", "Authorization: Bearer {{secret:TOKEN}}", "url"], src)


def test_bare_token_declares_env_and_is_removed_from_argv() -> None:
    r = resolve_secrets(["psql", "{{secret:PGPASSWORD}}"], DictSource({"PGPASSWORD": "pw"}))
    assert r.argv == ["psql"]
    assert r.env == {"PGPASSWORD": "pw"}
    assert "pw" not in " ".join(r.argv)


def test_unknown_secret_fails_closed() -> None:
    with pytest.raises(SecretResolutionError, match="MISSING"):
        resolve_secrets(["echo", "{{secret:MISSING}}"], DictSource({}))


def test_multiple_and_repeated_dedupe_first_seen() -> None:
    src = DictSource({"A": "aaa", "B": "bbb"})
    r = resolve_secrets(["cmd", "--flag", "{{secret:A}}", "{{secret:B}}", "{{secret:A}}"], src)
    assert r.argv == ["cmd", "--flag"]
    assert r.env == {"A": "aaa", "B": "bbb"}
    assert r.values == ["aaa", "bbb"]  # first-seen order, deduped
    assert r.names == ["A", "B"]


def test_no_tokens_is_transparent_noop() -> None:
    argv = ["kubectl", "get", "pods"]
    assert has_secret_tokens(argv) is False
    r = resolve_secrets(argv, DictSource({}))
    assert r.argv == argv and r.argv is not argv  # a copy, unchanged
    assert r.env == {} and r.values == [] and r.names == []


def test_has_secret_tokens_detects() -> None:
    assert has_secret_tokens(["x", "{{secret:Y}}"]) is True
    assert has_secret_tokens(["x", "y"]) is False


def test_env_source_reads_env_with_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEVOPS_SECRET_FOO", "val")
    src = EnvSecretSource(prefix="DEVOPS_SECRET_")
    assert src.get("FOO") == "val"
    r = resolve_secrets(["app", "{{secret:FOO}}"], src)
    assert r.env == {"FOO": "val"} and r.argv == ["app"]


def test_env_source_empty_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EMPTY_SECRET", "")
    assert EnvSecretSource().get("EMPTY_SECRET") is None
    with pytest.raises(SecretResolutionError):
        resolve_secrets(["echo", "{{secret:EMPTY_SECRET}}"], EnvSecretSource())


def test_resolved_value_is_scrubbed_from_output() -> None:
    src = DictSource({"TOKEN": "supersecretvalue123"})
    r = resolve_secrets(["echo", "{{secret:TOKEN}}"], src)
    scrubbed, count = scrub_full("the log leaked supersecretvalue123 here", r.values)
    assert "supersecretvalue123" not in scrubbed
    assert "***" in scrubbed
    assert count >= 1
