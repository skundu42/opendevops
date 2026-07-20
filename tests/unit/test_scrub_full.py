"""Full literal-match scrubbing (P5d): redact exact secret VALUES over the pattern scrub."""

from __future__ import annotations

from opendevops.tools.scrub import scrub, scrub_full, scrub_literals


def test_scrub_full_with_no_values_is_identical_to_pattern_scrub() -> None:
    """The default (no secret values) must be byte-for-byte the same as the original scrub()."""
    samples = [
        "nothing secret here",
        "token AKIA1234567890ABCDEF in output",
        "plain identifiers and paths /var/lib/x deploy-abc123",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmnoPQR",
    ]
    for s in samples:
        assert scrub_full(s) == scrub(s)


def test_literal_value_redacted() -> None:
    out, n = scrub_literals("password is hunter2xyzlong here", ["hunter2xyzlong"])
    assert out == "password is *** here"
    assert n == 1


def test_multiple_occurrences_counted() -> None:
    out, n = scrub_literals("a SECRETVAL b SECRETVAL c", ["SECRETVAL"])
    assert "SECRETVAL" not in out
    assert n == 2


def test_longest_first_avoids_partial_leak() -> None:
    # "abc" is a substring of "abcdef"; redacting longest-first leaves no residue.
    out, _ = scrub_literals("value abcdef and abc", ["abc", "abcdef"])
    assert "abcdef" not in out
    assert out.count("***") == 2


def test_empty_and_blank_values_ignored() -> None:
    # An empty / whitespace value must not redact the whole string.
    out, n = scrub_literals("keep this text", ["", "   "])
    assert out == "keep this text"
    assert n == 0


def test_scrub_full_layers_literal_then_pattern() -> None:
    # A literal secret that would NOT match any structured pattern is still redacted, AND a
    # structured token in the same text is caught by the pattern pass underneath.
    text = "custom=myplainsecret and aws=AKIA1234567890ABCDEF"
    out, n = scrub_full(text, ["myplainsecret"])
    assert "myplainsecret" not in out
    assert "AKIA1234567890ABCDEF" not in out
    assert n >= 2
