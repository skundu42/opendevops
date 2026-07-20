"""Virtual-FS -> executor staging bridge for file-consuming flags (T11 / P2).

The agent authors manifests in the deepagents virtual filesystem (graph state ``files``); a
subprocess started by :class:`~opendevops.tools.executor.LocalExecutor` cannot see them. For
file-consuming flags (``kubectl -f/--filename``, ``kubectl -k/--kustomize``, ``helm -f/--values``)
the tool must **materialize** the referenced virtual files into a per-call private tmpdir,
**rewrite** argv so the flag values point at the staged on-disk paths, and **record** each staged
file's ``{path, sha256}`` so the audit ``execution.staged_files`` captures exactly the applied
manifest (T12's dry-run-before-apply hook keys on those sha256s).

Design notes
------------
* **Original argv only.** The tool receives the *original* argv the model produced; the policy
  layer canonicalizes short flags to their long form only for *matching*. So this module handles
  both spellings itself: ``-f``/``--filename``/``-k``/``--kustomize`` for kubectl and
  ``-f``/``--values`` for helm, in both ``--flag value`` and ``--flag=value`` forms.
* **Local flag tables.** :data:`FILE_FLAGS` / :data:`_FILE_FLAG_ALIASES` deliberately mirror the
  authoritative tables in ``src/opendevops/policy/parsing.py`` (``ALIAS_TABLES`` /
  ``VALUE_FLAGS``). They are kept *local* (a tiny constants table with this cross-reference)
  rather than importing the policy package into ``tools/`` — there is no shared constants module,
  and the tool layer must not depend on the policy layer. Keep the two in sync.
* **Everything is a virtual path.** The agent has no real filesystem, so a flag value that *looks*
  like a real path (``/manifests/deploy.yaml``) is still resolved as a key into the virtual
  ``files`` mapping. A referenced path absent from the virtual FS raises :class:`StagingError` and
  the tool refuses to execute — the model must ``write_file`` it first.
* **kustomize (P2 limitation).** ``-k``/``--kustomize`` references a *directory* tree, not a single
  file. P2 stages single files only; any ``-k``/``--kustomize`` file-ref raises
  :class:`StagingError`. Policy allows the flag, but this bridge refuses it until P3+.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# NOTE: ``deepagents.backends.utils.file_data_to_string`` is imported LAZILY inside
# :func:`resolve_file_refs` (its only user), NOT at module top. Importing it here would
# transitively load ``deepagents`` -> ``langgraph`` -> ``langgraph_sdk`` into ANY importer of this
# module — including the credential-holding executor service, which reuses only ``FileRef`` /
# ``stage`` / ``staging_tmpdir`` and never calls ``resolve_file_refs``. Deferring the import keeps
# the executor image free of the langgraph stack (P5d M3). The import is cached after first use, so
# the agent path (which does call ``resolve_file_refs``) pays it once.

# --------------------------------------------------------------------------------------
# file-flag tables (mirror src/opendevops/policy/parsing.py — keep in sync)
# --------------------------------------------------------------------------------------

# Per-binary set of *long* file-consuming flags this bridge stages.
#
# gh (P5f): ``gh api --input <file>`` reads a request BODY from a file (the PR-authoring commit
# body / pulls payload). Staging materializes that virtual-FS file + records its sha into the
# audit ``staged_files`` exactly like a kubectl ``-f`` manifest, so the committed content is
# captured. A non-file operand — ``--input -`` (stdin), a ``http(s)://`` URL, or any path absent
# from the virtual FS — is NOT a key in ``files`` and so raises :class:`StagingError` (refused,
# fail-closed), the same discipline as the kubectl bridge. (gh ``-F``/``--field`` ``key=@file``
# body-field files are NOT staged in P5f; the model authors with ``--input`` or inline fields.)
FILE_FLAGS: dict[str, set[str]] = {
    "kubectl": {"--filename", "--kustomize"},
    "helm": {"--values"},
    "gh": {"--input"},
}

# Per-binary short-flag -> long-flag aliases for the file flags above. Mirrors the file-flag
# rows of ``ALIAS_TABLES`` in policy/parsing.py (``-f``/``-k`` for kubectl, ``-f`` for helm). gh's
# ``--input`` has no short form, so gh needs no alias row here.
_FILE_FLAG_ALIASES: dict[str, dict[str, str]] = {
    "kubectl": {"-f": "--filename", "-k": "--kustomize"},
    "helm": {"-f": "--values"},
}

# The kustomize flag references a directory tree; single-file staging only in P2 (see module doc).
_KUSTOMIZE_LONG = "--kustomize"


class StagingError(Exception):
    """A file-flag references a path absent from the virtual FS, or an unsupported flag (``-k``)."""


@dataclass(frozen=True)
class FileRef:
    """A resolved file-flag reference: which flag, the virtual path, its content + sha256.

    ``argv_index`` is the argv position of the *value* token to rewrite (for the ``--flag value``
    form) or of the combined token (for an inline form, where ``inline`` is ``True``). It is an
    implementation detail used by :func:`stage`; the audit only records ``virtual_path`` +
    ``sha256``.

    ``inline_prefix`` is the exact literal to prepend to the staged path when rewriting an inline
    token (``None`` when ``inline`` is ``False``, i.e. the value is a separate argv token). It is
    captured verbatim from the matched token at resolve time — ``"--filename="`` / ``"-f="`` for
    the ``=`` forms, or the bare short flag (``"-f"``) for the attached no-``=`` short form — so
    :func:`stage` can reconstruct the rewritten token without re-parsing argv (a
    ``token.split("=", 1)`` on an attached ``-fvalue`` token has no ``=`` and would silently
    corrupt the rewrite; see :func:`stage`).
    """

    flag: str
    virtual_path: str
    content: str
    sha256: str
    argv_index: int
    inline: bool
    inline_prefix: str | None = None


def _sha256_text(text: str) -> str:
    """Hex sha256 over the UTF-8 bytes of *text* (the staged file content)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _match_file_flag(
    token: str, long_flags: set[str], aliases: Mapping[str, str]
) -> tuple[str, str | None, str | None] | None:
    """Classify *token* as a file flag.

    Returns ``(long_flag, inline_value, inline_prefix)`` when *token* is a file flag:
      * ``--flag`` / ``-f``                 -> ``(long, None, None)`` (value is the next token)
      * ``--flag=value``                     -> ``(long, value, "--flag=")``
      * ``-f=value``                         -> ``(long, value, "-f=")``
      * ``-fvalue`` (attached, no ``=``)     -> ``(long, value, "-f")``
    ``inline_prefix`` is the *exact* literal to prepend to the staged path on rewrite (see
    :func:`stage`); it is ``None`` iff the value is a separate argv token (``inline`` is False).
    Returns ``None`` when *token* is not a file flag for this binary.
    """
    if token.startswith("--"):
        name, sep, rest = token.partition("=")
        if name in long_flags:
            return (name, rest, f"{name}=") if sep else (name, None, None)
        return None
    if token.startswith("-") and len(token) >= 2:
        short = token[:2]
        long_flag = aliases.get(short)
        if long_flag is None or long_flag not in long_flags:
            return None
        remainder = token[2:]
        if remainder.startswith("="):  # -f=value
            return (long_flag, remainder[1:], f"{short}=")
        if remainder == "":  # -f value
            return (long_flag, None, None)
        return (long_flag, remainder, short)  # -fvalue (attached short form)
    return None


def resolve_file_refs(argv: list[str], files: Mapping[str, Any]) -> list[FileRef]:
    """Scan *argv* for file flags and resolve each referenced path against the virtual *files*.

    ``files`` is the deepagents ``files`` state mapping ``{path: FileData}``. Content is extracted
    with :func:`deepagents.backends.utils.file_data_to_string` (the same helper the built-in FS
    tools use, so binary/base64 and legacy list content are handled), and sha256 is computed over
    those content bytes.

    Raises :class:`StagingError` if a referenced path is absent from *files*, if a ``-k`` /
    ``--kustomize`` file-ref is present (unsupported in P2), or if a file flag has no operand.
    Returns ``[]`` when *argv[0]* has no file flags (nothing to stage).
    """
    if not argv:
        return []
    binary = argv[0]
    long_flags = FILE_FLAGS.get(binary)
    if not long_flags:
        return []
    # Lazy import (M3): only the agent path reaches here; keeps deepagents/langgraph out of the
    # executor service image (see the module-top note). Cached after the first call.
    from deepagents.backends.utils import file_data_to_string

    aliases = _FILE_FLAG_ALIASES.get(binary, {})

    refs: list[FileRef] = []
    i = 1
    n = len(argv)
    while i < n:
        matched = _match_file_flag(argv[i], long_flags, aliases)
        if matched is None:
            i += 1
            continue
        long_flag, inline_value, inline_prefix = matched
        inline = inline_prefix is not None

        # kustomize references a directory tree — refuse before any lookup (P2 limitation).
        if long_flag == _KUSTOMIZE_LONG:
            raise StagingError("kustomize staging not supported in P2")

        if inline:
            value = inline_value
            value_index = i
        else:
            if i + 1 >= n:
                raise StagingError(f"file flag {long_flag} has no operand")
            value = argv[i + 1]
            value_index = i + 1

        if not value:
            raise StagingError(f"file flag {long_flag} has an empty operand")
        if value not in files:
            raise StagingError(value)

        content = file_data_to_string(files[value])
        refs.append(
            FileRef(
                flag=long_flag,
                virtual_path=value,
                content=content,
                sha256=_sha256_text(content),
                argv_index=value_index,
                inline=inline,
                inline_prefix=inline_prefix,
            )
        )
        i = value_index + 1
    return refs


def _unique_name(base: str, used: dict[str, int]) -> str:
    """Return a filename unique within *used*, suffixing on collision (``deploy-1.yaml``)."""
    if base not in used:
        used[base] = 0
        return base
    used[base] += 1
    stem, dot, ext = base.rpartition(".")
    return f"{stem}-{used[base]}.{ext}" if dot else f"{base}-{used[base]}"


def stage(argv: list[str], refs: list[FileRef], tmpdir: Path) -> list[str]:
    """Write each ref's content into *tmpdir* (mode 0o600) and return argv rewritten to the paths.

    Basenames are derived from the virtual path and de-duplicated with a numeric suffix on
    collision (two ``deploy.yaml`` from different virtual directories stay distinct). The returned
    argv is a copy; the input is not mutated.

    An inline token (``--flag=value`` / ``-f=value`` / attached ``-fvalue``) is rewritten using
    ``ref.inline_prefix`` — the exact literal captured at resolve time — rather than by
    re-deriving a prefix from ``argv[ref.argv_index]``. The attached no-``=`` short form
    (``-f/manifests/a.yaml``) has no ``=`` to split on: splitting on ``"="`` would return the
    *whole* original token as the "prefix" and corrupt the rewrite into
    ``-f/manifests/a.yaml=<staged>``.
    """
    new_argv = list(argv)
    used: dict[str, int] = {}
    for ref in refs:
        base = os.path.basename(ref.virtual_path) or "staged-file"
        staged_path = tmpdir / _unique_name(base, used)
        # write_bytes (not write_text): write_text's default newline translation makes the
        # on-disk bytes host-dependent, but ref.sha256 is computed over content.encode("utf-8")
        # verbatim — the audited sha256 must match the exact bytes staged to disk.
        staged_path.write_bytes(ref.content.encode("utf-8"))
        os.chmod(staged_path, 0o600)
        if ref.inline:
            new_argv[ref.argv_index] = f"{ref.inline_prefix}{staged_path}"
        else:
            new_argv[ref.argv_index] = str(staged_path)
    return new_argv


@contextlib.contextmanager
def staging_tmpdir() -> Iterator[Path]:
    """A per-call private staging dir (``0o700``), rmtree'd on exit (success *or* exception)."""
    path = Path(tempfile.mkdtemp(prefix="opendevops-stage-"))
    os.chmod(path, 0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
