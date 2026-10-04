"""Layer: imported-tool boundary.

Responsibility: load the unchanged flat-module ada_script snapshot for the
standalone CLI. Its legacy database/analyzer objects remain behind this boundary.
"""

from __future__ import annotations

import importlib
import sqlite3
import sys
from pathlib import Path
from types import ModuleType
from typing import Protocol

VENDOR_ROOT: Path = Path(__file__).resolve().parents[2] / "vendor" / "ada_script"


class DatabaseView(Protocol):
    """Minimal typed view of the upstream SQLite disassembly workspace."""

    conn: sqlite3.Connection
    binary: bytes
    header_size: int
    image_size: int
    image_base: int

    def close(self) -> None:
        """Release the upstream database connection."""


def vendor_module(name: str) -> ModuleType:
    """Load a known upstream flat module, refusing existing namespace collisions.

    The upstream snapshot uses absolute sibling imports. This path change is
    limited to the standalone ada CLI process; shared matchers stay in vextest.
    """
    if not (VENDOR_ROOT / f"{name}.py").is_file():
        raise ImportError(f"Unknown ada_script vendor module: {name}")
    if str(VENDOR_ROOT) not in sys.path:
        for path in VENDOR_ROOT.glob("*.py"):
            existing = sys.modules.get(path.stem)
            if existing is not None and existing.__file__ != str(path):
                raise ImportError(f"ada_script module name already in use: {path.stem}")
        sys.path.insert(0, str(VENDOR_ROOT))
    return importlib.import_module(name)
