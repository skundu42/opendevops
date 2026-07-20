"""Pure text helpers for the run_command output pipeline: ANSI-strip, scrub, sha256, truncate.

These are deliberately side-effect-free so they can be unit-tested in isolation and reused
by the tool orchestration in :mod:`opendevops.tools.run_command`. The pipeline order is
fixed and load-bearing: **ANSI-strip -> scrub -> sha256 (over scrubbed text) -> truncate**.
The sha256 is computed over the *scrubbed* full text so the audit record can never hash an
unscrubbed secret into a correlatable value.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable

# --------------------------------------------------------------------------------------
# ANSI / control-sequence stripping
# --------------------------------------------------------------------------------------

# CSI/SGR sequences (colour, cursor moves) plus the two-char escapes. Covers the common
# ``\x1b[...m`` colour codes that k8s/cloud CLIs emit even with NO_COLOR unset.
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(text: str) -> str:
    """Remove ANSI CSI/SGR escape sequences from *text*."""
    return _ANSI_RE.sub("", text)


# --------------------------------------------------------------------------------------
# Secret scrubber
# --------------------------------------------------------------------------------------

# Structured, high-confidence credential shapes. Each is replaced wholesale with ``***``.
# Ordered most-specific-first so e.g. ``sk-ant-`` wins over the generic ``sk-`` rule.
_STRUCTURED_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PEM private-key blocks (multiline) — match first so their base64 body is not
    # partially caught by later token rules.
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # JSON Web Tokens: header.payload.signature, each segment base64url.
    re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    # AWS access key id.
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # GitHub fine-grained PAT.
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
    # GitHub classic/app tokens: ghp_ (personal), gho_/ghu_/ghs_/ghr_ variants.
    re.compile(r"gh[oprsu]_[A-Za-z0-9]{36,}"),
    # Slack tokens (bot/app/refresh/etc).
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    # Anthropic API keys (before the generic sk- rule).
    re.compile(r"sk-ant-[A-Za-z0-9-]{20,}"),
    # OpenAI-style keys.
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
)

# High-entropy catch-all: standalone tokens of base64/base64url/hex-ish characters.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
# Pure-hex strings (sha256 image digests, pod-template hashes, git SHAs) are ubiquitous in
# kubectl/cloud output and are NOT secrets — exempt them from the entropy pass.
_PURE_HEX_RE = re.compile(r"\A[0-9a-fA-F]{32,}\Z")
_ENTROPY_THRESHOLD = 4.5  # bits/char; conservative so ordinary identifiers survive.

_REDACTION = "***"


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of *s* in bits per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_candidate_is_secret(token: str) -> bool:
    """Decide whether a >=32-char token from the entropy pass should be redacted.

    Exemptions (documented, conservative):
      * **pure hex** (``[0-9a-f]{32,}`` case-insensitive) — sha256 digests / pod-template
        hashes / git object ids are everywhere in infra output and are not secrets.
      * **path-like tokens** — the token char-class includes ``/`` (base64 alphabet), so a
        filesystem path such as ``/var/lib/kubelet/pods/...`` matches as one token. Exempt
        only when the token *starts* with ``/`` (a genuine path), never merely contains it
        (base64 bodies contain ``/`` mid-string).
    Everything else is redacted only if its Shannon entropy exceeds the threshold, keeping
    the pass conservative against ordinary long identifiers.
    """
    if _PURE_HEX_RE.match(token):
        return False
    if token.startswith("/"):
        return False
    return _shannon_entropy(token) > _ENTROPY_THRESHOLD


def scrub(text: str) -> tuple[str, int]:
    """Redact credentials from *text*, returning ``(scrubbed_text, replacement_count)``.

    Structured high-confidence patterns run first (replaced with ``***``), then a
    conservative high-entropy catch-all with the exemptions documented in
    :func:`_entropy_candidate_is_secret`.
    """
    count = 0
    scrubbed = text
    for pattern in _STRUCTURED_PATTERNS:
        scrubbed, n = pattern.subn(_REDACTION, scrubbed)
        count += n

    entropy_hits = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal entropy_hits
        token = match.group(0)
        if _entropy_candidate_is_secret(token):
            entropy_hits += 1
            return _REDACTION
        return token

    scrubbed = _TOKEN_RE.sub(_replace, scrubbed)
    count += entropy_hits
    return scrubbed, count


# --------------------------------------------------------------------------------------
# Full literal-match scrubbing (P5d) — redact the exact resolved secret VALUES
# --------------------------------------------------------------------------------------


def scrub_literals(text: str, secret_values: Iterable[str]) -> tuple[str, int]:
    """Redact every literal occurrence of each *secret_values* entry, returning ``(text, count)``.

    Given the **exact** secret VALUES resolved for a call (from :mod:`opendevops.tools.secrets`),
    replace any literal appearance in *text* with ``***`` — a belt-and-suspenders layer over the
    pattern scrubber for secrets whose shape the patterns would not catch. Values are applied
    **longest-first** so a value that is a substring of another does not leave a partial leak, and
    empty / whitespace-only values are ignored (they would otherwise redact everything).
    """
    count = 0
    scrubbed = text
    # De-duplicate and drop blanks, then longest-first.
    for value in sorted({v for v in secret_values if v and v.strip()}, key=len, reverse=True):
        occurrences = scrubbed.count(value)
        if occurrences:
            scrubbed = scrubbed.replace(value, _REDACTION)
            count += occurrences
    return scrubbed, count


def scrub_full(text: str, secret_values: Iterable[str] = ()) -> tuple[str, int]:
    """Full scrub: literal-match the resolved secret values, THEN the P1 pattern scrubber.

    The literal pass runs first (so a known value is redacted even when its shape evades the
    patterns), and the pattern pass runs underneath as the standing backstop. With no
    ``secret_values`` this is byte-for-byte identical to :func:`scrub` (the literal pass is a
    no-op), so the default output pipeline is unchanged. Returns
    ``(scrubbed_text, total_replacement_count)``.
    """
    literal_scrubbed, literal_count = scrub_literals(text, secret_values)
    pattern_scrubbed, pattern_count = scrub(literal_scrubbed)
    return pattern_scrubbed, literal_count + pattern_count


# --------------------------------------------------------------------------------------
# Hashing + truncation
# --------------------------------------------------------------------------------------


def sha256_hex(text: str) -> str:
    """Hex sha256 of *text* (UTF-8). Computed over the already-scrubbed output."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_HEAD_FRACTION = 0.6  # keep 60% head / 40% tail on truncation


def truncate_head_tail(
    text: str, max_chars: int, fs_path: str | None
) -> tuple[str, bool, int]:
    """Head+tail truncate *text* to ``max_chars``, returning ``(text, truncated, dropped)``.

    When truncation occurs, keeps the first 60% and last 40% of ``max_chars`` and splices in
    a marker. If ``fs_path`` is given the marker references the spilled full-output path;
    otherwise it states how many characters were dropped.
    """
    if len(text) <= max_chars:
        return text, False, 0

    head_len = int(max_chars * _HEAD_FRACTION)
    tail_len = max_chars - head_len
    dropped = len(text) - max_chars

    if fs_path is not None:
        marker = f"\n...[truncated {dropped} chars — full output at {fs_path}]...\n"
    else:
        marker = f"\n...[output truncated; {dropped} chars dropped]...\n"

    out = text[:head_len] + marker + text[len(text) - tail_len :]
    return out, True, dropped
