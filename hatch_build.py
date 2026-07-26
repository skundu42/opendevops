"""Build the strict TypeScript dashboard before assembling Python wheels."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Ensure browser assets are compiled from TypeScript and current."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel":
            return
        root = Path(self.root)
        sources = [root / "frontend" / "dashboard.ts", root / "frontend" / "login.ts"]
        outputs = [
            root
            / "src"
            / "opendevops"
            / "interfaces"
            / "dashboard_assets"
            / "generated"
            / f"{source.stem}.js"
            for source in sources
        ]
        inputs = [
            *sources,
            root / "tsconfig.json",
            root / "package.json",
            root / "package-lock.json",
        ]
        newest_input = max(path.stat().st_mtime for path in inputs)
        needs_build = not all(
            path.is_file() and path.stat().st_mtime >= newest_input for path in outputs
        )
        if needs_build:
            npm = shutil.which("npm")
            if npm is None:
                raise RuntimeError(
                    "Node.js/npm is required to compile the TypeScript dashboard; "
                    "run `npm ci && npm run frontend:build` before building the wheel"
                )
            if not (root / "node_modules" / "typescript").is_dir():
                subprocess.run([npm, "ci", "--ignore-scripts"], cwd=root, check=True)
            subprocess.run([npm, "run", "frontend:build"], cwd=root, check=True)

        force_include = build_data.setdefault("force_include", {})
        for output in outputs:
            force_include[str(output)] = (
                f"opendevops/interfaces/dashboard_assets/generated/{output.name}"
            )
