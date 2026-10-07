"""Keep pytest scratch outside maintained source and navigation indexes.

Layer: Test infrastructure.
Responsibility: allocate isolated ignored temporary roots without overriding
explicit runner/xdist basetemp policies.

Package ownership contract (canonical tools/dev package):
Layer: Tooling.
Owns development infrastructure, gates, and focused test support for repository tooling.
Do not perform decompiler pipeline semantics or CLI/reporting ownership here.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

ROOT: Path = Path(__file__).resolve().parents[2]


def workspace_basetemp(root: Path, explicit: str | Path | None) -> Path:
    """Preserve explicit roots or select a fresh ignored root for this run."""
    if explicit is not None:
        return Path(explicit)
    parent = root / ".cache" / "pytest"
    parent.mkdir(parents=True, exist_ok=True)
    return parent / f"run-{uuid4().hex}"


def pytest_configure(config: pytest.Config) -> None:
    """Configure only the default; xdist and partition workers keep their roots."""
    if config.option.basetemp is None:
        config.option.basetemp = workspace_basetemp(ROOT, None)
