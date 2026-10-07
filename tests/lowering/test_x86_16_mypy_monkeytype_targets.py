from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
MYPY_TARGETS: tuple[str, ...] = (
    "inertia/cli/monkeytype_tools.py",
    "inertia/lowering/object_lowering/py.py",
    "inertia/cli/cli_access_trait_rewrite.py",
    "inertia/cli/cli_cod_globals.py",
    "monkeytype_config.py",
    "tools/dev/run_monkeytype_tracing.py",
    "tools/dev/export_monkeytype_stubs.py",
    "tools/dev/apply_monkeytype_annotations.py",
)


def _python() -> str:
    return str(PYTHON if PYTHON.exists() else Path(sys.executable))


def test_monkeytype_small_modules_typecheck_cleanly():
    subprocess.run(
        [
            _python(),
            "-m",
            "mypy",
            "--config-file",
            "pyproject.toml",
            "--follow-imports=skip",
            *MYPY_TARGETS,
        ],
        cwd=REPO_ROOT,
        check=True,
    )
