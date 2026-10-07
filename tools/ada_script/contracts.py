"""Layer: ADA analysis contracts.

Responsibility: define the database view consumed by output and orchestration.
"""

from __future__ import annotations

import sqlite3
from typing import Protocol


class DatabaseView(Protocol):
    """Minimal typed view of the upstream SQLite disassembly workspace."""

    conn: sqlite3.Connection
    binary: bytes
    header_size: int
    image_size: int
    image_base: int

    def close(self) -> None:
        """Release the upstream database connection."""

