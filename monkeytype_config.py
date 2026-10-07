"""MonkeyType configuration for collecting local type traces.

Layer: Tooling/gates.
Responsibility: owns repository-local MonkeyType trace configuration.
"""

from __future__ import annotations

from collections.abc import Callable
from types import CodeType
from typing import cast

from monkeytype.config import DefaultConfig  # pyright: ignore[reportMissingImports]
from monkeytype.db.base import CallTraceStore  # pyright: ignore[reportMissingImports]
from monkeytype.db.sqlite import SQLiteStore  # pyright: ignore[reportMissingImports]

from inertia.cli.monkeytype_tools import MONKEYTYPE_DB_PATH, ensure_monkeytype_dirs, monkeytype_code_filter


class InertiaMonkeyTypeConfig(DefaultConfig):  # type: ignore[misc]  # MonkeyType ships an untyped base class.
    """MonkeyType config bound to the repository-local trace database."""

    def trace_store(self) -> CallTraceStore:
        """Return the SQLite trace store used by the type-ratchet tooling."""
        ensure_monkeytype_dirs()
        return SQLiteStore.make_store(str(MONKEYTYPE_DB_PATH))

    def code_filter(self) -> Callable[[CodeType], bool]:
        """Return the repository-local code filter for trace collection."""
        return cast(Callable[[CodeType], bool], monkeytype_code_filter)


CONFIG: InertiaMonkeyTypeConfig = InertiaMonkeyTypeConfig()
