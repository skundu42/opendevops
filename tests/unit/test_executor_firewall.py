"""Executor-service import firewall: the service must not drag in the langgraph stack.

`staging.py`'s deepagents import is lazy (inside `resolve_file_refs`), so importing the
credential-holding executor service — which reuses only `FileRef`/`stage`/`staging_tmpdir` — must
NOT transitively load `deepagents`/`langgraph`/`langgraph_sdk`. Run in a CLEAN subprocess so no
other test's imports pollute `sys.modules`.
"""

from __future__ import annotations

import subprocess
import sys


def test_executor_service_import_does_not_load_langgraph() -> None:
    code = (
        "import opendevops.executor_service.service, sys\n"
        "bad = [m for m in ('langgraph_sdk', 'langgraph', 'deepagents') "
        "if m in sys.modules or any(k.startswith(m + '.') for k in sys.modules)]\n"
        "assert not bad, f'executor service transitively imported: {bad}'\n"
        "print('CLEAN')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "CLEAN" in result.stdout


def test_agent_staging_path_still_resolves_after_lazy_import() -> None:
    """The lazy import must not break the agent path that DOES call resolve_file_refs."""
    from deepagents.backends.utils import create_file_data

    from opendevops.tools.staging import resolve_file_refs

    refs = resolve_file_refs(
        ["kubectl", "apply", "-f", "/m/a.yaml"], {"/m/a.yaml": create_file_data("kind: X\n")}
    )
    assert len(refs) == 1
    assert refs[0].virtual_path == "/m/a.yaml"
    assert refs[0].content == "kind: X\n"
