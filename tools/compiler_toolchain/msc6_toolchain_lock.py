"""Serialize access to the shared legacy MS C toolchain.

Layer: Tooling/gates.
Responsibility: prevent concurrent compiler/linker transactions from corrupting
artifacts while leaving independent decompiler work parallel.
"""

from __future__ import annotations

import fcntl
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def msc6_toolchain_lock(msc6_root: Path) -> Iterator[None]:
    """Hold a cross-process lock on the existing compiler executable."""
    compiler_path = msc6_root / "BIN" / "CL.EXE"
    with compiler_path.open("rb") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
