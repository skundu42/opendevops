"""Tests for the virtual-FS -> executor staging bridge.

Covers ref resolution (both flag spellings + short form), sha256 correctness, the
missing-path and kustomize refusals, on-disk staging (mode 0o600 + argv rewrite + basename
collision handling), and the per-call tmpdir context manager cleanup on success and on
exception.
"""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from typing import Any

import pytest
from deepagents.backends.utils import create_file_data

from opendevops.tools.staging import (
    FILE_FLAGS,
    FileRef,
    StagingError,
    resolve_file_refs,
    stage,
    staging_tmpdir,
)


def _files(**paths: str) -> dict[str, Any]:
    """Build a deepagents ``files`` state mapping {path: FileData} from path->content kwargs.

    Keys use ``__`` for ``/`` so they can be passed as kwargs; e.g. ``_manifests__deploy_yaml``.
    """
    out: dict[str, Any] = {}
    for key, content in paths.items():
        path = "/" + key.strip("_").replace("__", "/").replace("_yaml", ".yaml")
        out[path] = create_file_data(content)
    return out


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------
# resolve_file_refs — happy paths / spellings
# --------------------------------------------------------------------------------------

MANIFEST = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"


def test_resolve_long_flag_space_form() -> None:
    files = {"/manifests/deploy.yaml": create_file_data(MANIFEST)}
    argv = ["kubectl", "apply", "--filename", "/manifests/deploy.yaml", "-n", "web"]
    refs = resolve_file_refs(argv, files)
    assert len(refs) == 1
    ref = refs[0]
    assert ref.flag == "--filename"
    assert ref.virtual_path == "/manifests/deploy.yaml"
    assert ref.content == MANIFEST
    assert ref.sha256 == _sha(MANIFEST)
    assert ref.inline is False
    assert ref.argv_index == 3  # the value token


def test_resolve_long_flag_equals_form() -> None:
    files = {"/manifests/deploy.yaml": create_file_data(MANIFEST)}
    argv = ["kubectl", "apply", "--filename=/manifests/deploy.yaml"]
    refs = resolve_file_refs(argv, files)
    assert len(refs) == 1
    assert refs[0].virtual_path == "/manifests/deploy.yaml"
    assert refs[0].inline is True
    assert refs[0].argv_index == 2
    assert refs[0].sha256 == _sha(MANIFEST)


def test_resolve_short_flag_form() -> None:
    files = {"/manifests/deploy.yaml": create_file_data(MANIFEST)}
    argv = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    refs = resolve_file_refs(argv, files)
    assert len(refs) == 1
    assert refs[0].flag == "--filename"  # canonicalized to long form
    assert refs[0].virtual_path == "/manifests/deploy.yaml"


def test_resolve_attached_short_form_captures_inline_prefix() -> None:
    # attached short form, no '=': -f/manifests/a.yaml (flag + value glued into one token).
    files = {"/manifests/a.yaml": create_file_data(MANIFEST)}
    argv = ["kubectl", "apply", "-f/manifests/a.yaml"]
    refs = resolve_file_refs(argv, files)
    assert len(refs) == 1
    ref = refs[0]
    assert ref.flag == "--filename"
    assert ref.virtual_path == "/manifests/a.yaml"
    assert ref.content == MANIFEST
    assert ref.sha256 == _sha(MANIFEST)
    assert ref.inline is True
    # the exact literal to reconstruct on rewrite: the bare short flag, no trailing '='.
    assert ref.inline_prefix == "-f"
    assert ref.argv_index == 2


def test_resolve_helm_values_flag() -> None:
    files = {"/values/prod.yaml": create_file_data("replicas: 3\n")}
    argv = ["helm", "upgrade", "web", "./chart", "--values", "/values/prod.yaml"]
    refs = resolve_file_refs(argv, files)
    assert len(refs) == 1
    assert refs[0].flag == "--values"
    assert refs[0].virtual_path == "/values/prod.yaml"
    assert refs[0].content == "replicas: 3\n"


def test_resolve_helm_short_f_is_values() -> None:
    files = {"/values/prod.yaml": create_file_data("replicas: 3\n")}
    argv = ["helm", "upgrade", "web", "./chart", "-f", "/values/prod.yaml"]
    refs = resolve_file_refs(argv, files)
    assert refs[0].flag == "--values"


def test_resolve_multiple_filenames() -> None:
    files = {
        "/manifests/a.yaml": create_file_data("A\n"),
        "/manifests/b.yaml": create_file_data("B\n"),
    }
    argv = ["kubectl", "apply", "-f", "/manifests/a.yaml", "-f", "/manifests/b.yaml"]
    refs = resolve_file_refs(argv, files)
    assert [r.virtual_path for r in refs] == ["/manifests/a.yaml", "/manifests/b.yaml"]
    assert refs[0].sha256 == _sha("A\n")
    assert refs[1].sha256 == _sha("B\n")


def test_resolve_no_file_flags_returns_empty() -> None:
    # kubectl get has no file flags -> nothing to stage.
    assert resolve_file_refs(["kubectl", "get", "pods", "-n", "web"], {}) == []
    # a binary with no file-flag table at all.
    assert resolve_file_refs(["ls", "-l"], {}) == []
    assert resolve_file_refs([], {}) == []


# --------------------------------------------------------------------------------------
# gh api --input body staging — same discipline as the kubectl -f bridge
# --------------------------------------------------------------------------------------

PR_BODY = '{"title":"fix crashloop","head":"remediation","base":"main"}\n'


def test_resolve_gh_api_input_space_form() -> None:
    files = {"/manifests/pr.json": create_file_data(PR_BODY)}
    argv = [
        "gh", "api", "-X", "POST", "/repos/octo-org/staging-app/pulls",
        "--input", "/manifests/pr.json",
    ]
    refs = resolve_file_refs(argv, files)
    assert len(refs) == 1
    ref = refs[0]
    assert ref.flag == "--input"
    assert ref.virtual_path == "/manifests/pr.json"
    assert ref.content == PR_BODY
    assert ref.sha256 == _sha(PR_BODY)
    assert ref.inline is False


def test_resolve_gh_api_input_equals_form() -> None:
    files = {"/manifests/pr.json": create_file_data(PR_BODY)}
    argv = ["gh", "api", "/repos/octo-org/staging-app/pulls", "--input=/manifests/pr.json"]
    refs = resolve_file_refs(argv, files)
    assert len(refs) == 1
    assert refs[0].flag == "--input"
    assert refs[0].inline is True
    assert refs[0].sha256 == _sha(PR_BODY)


def test_resolve_gh_api_input_stdin_refused() -> None:
    # `--input -` is stdin, not a virtual-FS path -> refuse fail-closed (never a key in files).
    with pytest.raises(StagingError):
        resolve_file_refs(
            ["gh", "api", "-X", "POST", "/repos/octo-org/staging-app/pulls", "--input", "-"], {}
        )


def test_resolve_gh_api_input_url_refused() -> None:
    # a URL operand is not a virtual-FS path -> refuse fail-closed.
    with pytest.raises(StagingError):
        resolve_file_refs(
            ["gh", "api", "/repos/octo-org/staging-app/pulls", "--input", "https://evil.example/x"],
            {},
        )


def test_resolve_gh_api_input_missing_path_refused() -> None:
    # a virtual path the model never wrote -> refuse (StagingError names the missing path).
    with pytest.raises(StagingError):
        resolve_file_refs(
            ["gh", "api", "/repos/octo-org/staging-app/pulls", "--input", "/manifests/absent.json"],
            {},
        )


def test_resolve_gh_no_input_returns_empty() -> None:
    # a gh api write with only inline fields has no --input -> nothing to stage.
    argv = ["gh", "api", "-X", "POST", "/repos/octo-org/staging-app/pulls", "-f", "title=fix"]
    assert resolve_file_refs(argv, {}) == []
    # gh reads never stage.
    assert resolve_file_refs(["gh", "pr", "view", "123"], {}) == []


def test_gh_input_flag_registered() -> None:
    # the bridge stages exactly --input for gh (mirrors parsing.py VALUE_FLAGS/ALIAS_TABLES).
    assert FILE_FLAGS["gh"] == {"--input"}


def test_resolve_sha256_matches_content_bytes() -> None:
    content = "some: manifest\nwith: unicode ✓\n"
    files = {"/m/x.yaml": create_file_data(content)}
    refs = resolve_file_refs(["kubectl", "apply", "-f", "/m/x.yaml"], files)
    assert refs[0].sha256 == hashlib.sha256(content.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------
# resolve_file_refs — refusals
# --------------------------------------------------------------------------------------


def test_resolve_missing_virtual_path_raises() -> None:
    argv = ["kubectl", "apply", "-f", "/manifests/missing.yaml"]
    with pytest.raises(StagingError) as exc:
        resolve_file_refs(argv, {})
    assert "/manifests/missing.yaml" in str(exc.value)


def test_resolve_real_looking_path_is_still_virtual() -> None:
    # An absolute-looking path is treated as a virtual key; absent -> StagingError.
    with pytest.raises(StagingError):
        resolve_file_refs(["kubectl", "apply", "-f", "/etc/passwd"], {})
    # present in the virtual FS under that exact key -> resolves.
    files = {"/etc/passwd": create_file_data("virtual\n")}
    refs = resolve_file_refs(["kubectl", "apply", "-f", "/etc/passwd"], files)
    assert refs[0].content == "virtual\n"


def test_resolve_kustomize_short_flag_refused() -> None:
    with pytest.raises(StagingError) as exc:
        resolve_file_refs(["kubectl", "apply", "-k", "/overlays/prod"], {})
    assert "kustomize" in str(exc.value).lower()


def test_resolve_kustomize_long_flag_refused() -> None:
    with pytest.raises(StagingError) as exc:
        resolve_file_refs(["kubectl", "apply", "--kustomize", "/overlays/prod"], {})
    assert "kustomize" in str(exc.value).lower()


def test_resolve_kustomize_refused_even_before_missing_lookup() -> None:
    # kustomize refusal fires regardless of whether the path exists in the virtual FS.
    files = {"/overlays/prod": create_file_data("(dir placeholder)")}
    with pytest.raises(StagingError):
        resolve_file_refs(["kubectl", "apply", "--kustomize", "/overlays/prod"], files)


def test_resolve_file_flag_without_operand_raises() -> None:
    with pytest.raises(StagingError):
        resolve_file_refs(["kubectl", "apply", "--filename"], {})


# --------------------------------------------------------------------------------------
# stage — on-disk write + argv rewrite + collisions
# --------------------------------------------------------------------------------------


def test_stage_writes_0600_and_rewrites_argv(tmp_path: Path) -> None:
    files = {"/manifests/deploy.yaml": create_file_data(MANIFEST)}
    argv = ["kubectl", "apply", "--filename", "/manifests/deploy.yaml", "-n", "web"]
    refs = resolve_file_refs(argv, files)
    new_argv = stage(argv, refs, tmp_path)

    # argv[0..2] unchanged; the value token now points at a real staged path.
    assert new_argv[:3] == ["kubectl", "apply", "--filename"]
    staged = Path(new_argv[3])
    assert staged.parent == tmp_path
    assert staged != Path("/manifests/deploy.yaml")
    assert staged.read_text() == MANIFEST
    assert new_argv[4:] == ["-n", "web"]  # the rest is untouched
    # mode is owner rw only.
    assert (staged.stat().st_mode & 0o777) == 0o600
    # input argv not mutated.
    assert argv[3] == "/manifests/deploy.yaml"


def test_stage_equals_form_preserves_flag_spelling(tmp_path: Path) -> None:
    files = {"/manifests/deploy.yaml": create_file_data(MANIFEST)}
    argv = ["kubectl", "apply", "--filename=/manifests/deploy.yaml"]
    refs = resolve_file_refs(argv, files)
    new_argv = stage(argv, refs, tmp_path)
    token = new_argv[2]
    assert token.startswith("--filename=")
    staged = Path(token.split("=", 1)[1])
    assert staged.parent == tmp_path
    assert staged.read_text() == MANIFEST


def test_stage_attached_short_form_rewrites_argv_correctly(tmp_path: Path) -> None:
    """Regression: `stage()` used to derive the rewrite prefix via `argv[i].split("=", 1)[0]`.

    For a no-`=` attached token (`-f/manifests/a.yaml`) that returns the WHOLE token (no `=`
    found), corrupting the rewrite into `-f/manifests/a.yaml=<staged>` — kubectl then errors
    (fail-closed) while the audit still records a staged manifest for an apply that never ran.
    """
    files = {"/manifests/a.yaml": create_file_data(MANIFEST)}
    argv = ["kubectl", "apply", "-f/manifests/a.yaml"]
    refs = resolve_file_refs(argv, files)
    new_argv = stage(argv, refs, tmp_path)

    token = new_argv[2]
    # kubectl-visible token shape: "-f" immediately followed by the staged path, no stray "=".
    assert token.startswith("-f")
    assert "=" not in token
    staged = Path(token[2:])
    assert staged.parent == tmp_path
    assert staged != Path("/manifests/a.yaml")
    assert staged.read_text() == MANIFEST
    assert (staged.stat().st_mode & 0o777) == 0o600
    # argv[0:2] untouched; input argv not mutated.
    assert new_argv[:2] == ["kubectl", "apply"]
    assert argv[2] == "-f/manifests/a.yaml"


def test_stage_mixed_inline_forms_round_trip(tmp_path: Path) -> None:
    """An attached `-fvalue` token and a `--filename=value` token both stage correctly together.

    Full resolve+stage round trip for both inline spellings named in the finding, asserting the
    rewritten argv points at the staged file and each kubectl-visible token shape is valid.
    """
    files = {
        "/m/a.yaml": create_file_data("A\n"),
        "/m/b.yaml": create_file_data("B\n"),
    }
    argv = ["kubectl", "apply", "-f/m/a.yaml", "--filename=/m/b.yaml"]
    refs = resolve_file_refs(argv, files)
    assert [r.inline_prefix for r in refs] == ["-f", "--filename="]

    new_argv = stage(argv, refs, tmp_path)
    attached_token = new_argv[2]
    equals_token = new_argv[3]

    # attached short form: "-f" immediately followed by the staged path, no "=" anywhere.
    assert attached_token.startswith("-f")
    assert "=" not in attached_token
    attached_staged = Path(attached_token[2:])
    assert attached_staged.parent == tmp_path
    assert attached_staged.read_text() == "A\n"

    # long equals form: exactly one "=" splitting the flag from the staged path.
    assert equals_token.startswith("--filename=")
    assert equals_token.count("=") == 1
    equals_staged = Path(equals_token.split("=", 1)[1])
    assert equals_staged.parent == tmp_path
    assert equals_staged.read_text() == "B\n"
    assert attached_staged != equals_staged

    # input argv untouched.
    assert argv == ["kubectl", "apply", "-f/m/a.yaml", "--filename=/m/b.yaml"]


def test_stage_writes_exact_utf8_bytes_matching_sha256(tmp_path: Path) -> None:
    """`stage()` writes the exact bytes `ref.sha256` was computed over (no newline translation)."""
    content = "line one\nline two\r\nline three\n"
    files = {"/m/x.yaml": create_file_data(content)}
    argv = ["kubectl", "apply", "-f", "/m/x.yaml"]
    refs = resolve_file_refs(argv, files)
    new_argv = stage(argv, refs, tmp_path)

    staged = Path(new_argv[3])
    on_disk = staged.read_bytes()
    assert on_disk == content.encode("utf-8")
    assert hashlib.sha256(on_disk).hexdigest() == refs[0].sha256


def test_stage_basename_collision_gets_suffixed(tmp_path: Path) -> None:
    # two different virtual dirs, same basename -> distinct staged files.
    files = {
        "/a/deploy.yaml": create_file_data("A\n"),
        "/b/deploy.yaml": create_file_data("B\n"),
    }
    argv = ["kubectl", "apply", "-f", "/a/deploy.yaml", "-f", "/b/deploy.yaml"]
    refs = resolve_file_refs(argv, files)
    new_argv = stage(argv, refs, tmp_path)
    p0 = Path(new_argv[3])
    p1 = Path(new_argv[5])
    assert p0 != p1
    assert p0.read_text() == "A\n"
    assert p1.read_text() == "B\n"
    assert p0.name == "deploy.yaml"
    assert p1.name == "deploy-1.yaml"


# --------------------------------------------------------------------------------------
# staging_tmpdir — lifecycle
# --------------------------------------------------------------------------------------


def test_staging_tmpdir_created_0700_and_cleaned_on_success() -> None:
    seen: Path | None = None
    with staging_tmpdir() as d:
        seen = d
        assert d.is_dir()
        assert d.name.startswith("opendevops-stage-")
        assert (d.stat().st_mode & 0o777) == 0o700
        (d / "x").write_text("y")
    assert seen is not None
    assert not seen.exists()  # cleaned on normal exit


def test_staging_tmpdir_cleaned_on_exception() -> None:
    seen: Path | None = None
    with pytest.raises(RuntimeError), staging_tmpdir() as d:
        seen = d
        (d / "x").write_text("y")
        raise RuntimeError("boom during exec")
    assert seen is not None
    assert not seen.exists()  # cleaned even when the body raised


# --------------------------------------------------------------------------------------
# module-level contract sanity
# --------------------------------------------------------------------------------------


def test_file_flags_table_shape() -> None:
    assert FILE_FLAGS["kubectl"] == {"--filename", "--kustomize"}
    assert FILE_FLAGS["helm"] == {"--values"}


def test_fileref_is_frozen() -> None:
    ref = FileRef(
        flag="--filename",
        virtual_path="/m/x.yaml",
        content="c",
        sha256="s",
        argv_index=3,
        inline=False,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        ref.flag = "--values"  # type: ignore[misc]
