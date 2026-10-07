"""Provide crash-recoverable cache producer locks.

Layer: CLI/fallback/reporting.
Responsibility: serialize content-addressed cache producers and reclaim locks
whose owning process has terminated, without deciding cache semantics.
"""

from __future__ import annotations

import contextlib
import enum
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_UNKNOWN_OWNER_GRACE_SECONDS = 5.0


class _OwnerState(enum.Enum):
    """Describe whether a cache lock owner can still release its lock."""

    LIVE = "live"
    STALE = "stale"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class _LockOwner:
    """Identify one lock owner without trusting a reusable PID alone."""

    pid: int
    process_start: str | None

    def to_bytes(self) -> bytes:
        """Serialize this owner for lock contenders."""
        return (
            json.dumps(
                {"schema": 1, "pid": self.pid, "process_start": self.process_start},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")

    @classmethod
    def from_bytes(cls, data: bytes) -> _LockOwner | None:
        """Parse current JSON records and legacy PID-only lock files."""
        text = data.decode("ascii", errors="ignore").strip()
        if text.isdigit():
            return cls(pid=int(text), process_start=None)
        try:
            record = json.loads(text)
        except (TypeError, ValueError):
            return None
        if not isinstance(record, dict) or record.get("schema") != 1:
            return None
        pid = record.get("pid")
        process_start = record.get("process_start")
        if not isinstance(pid, int) or pid <= 0:
            return None
        if process_start is not None and not isinstance(process_start, str):
            return None
        return cls(pid=pid, process_start=process_start)


def _process_start_token(pid: int) -> str | None:
    """Return Linux's stable process start tick for PID-reuse detection."""
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    except OSError:
        return None
    closing_paren = stat.rfind(")")
    if closing_paren < 0:
        return None
    fields_after_name = stat[closing_paren + 2 :].split()
    if len(fields_after_name) <= 19:
        return None
    return fields_after_name[19]


def _owner_state(owner: _LockOwner | None) -> _OwnerState:
    """Classify one recorded owner conservatively."""
    if owner is None:
        return _OwnerState.UNKNOWN
    try:
        os.kill(owner.pid, 0)
    except ProcessLookupError:
        return _OwnerState.STALE
    except PermissionError:
        return _OwnerState.LIVE
    if owner.process_start is None:
        return _OwnerState.LIVE
    current_start = _process_start_token(owner.pid)
    if current_start is None:
        return _OwnerState.LIVE
    if current_start != owner.process_start:
        return _OwnerState.STALE
    return _OwnerState.LIVE


def _read_owner(lock_path: Path) -> _LockOwner | None:
    """Read an owner record without treating partial writes as stale."""
    try:
        return _LockOwner.from_bytes(lock_path.read_bytes())
    except OSError:
        return None


def _write_all(descriptor: int, data: bytes) -> None:
    """Write a complete owner record before contenders inspect it."""
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise RuntimeError("cache lock owner record write failed")
        offset += written


def _unlink_same_inode(lock_path: Path, *, device: int, inode: int) -> bool:
    """Unlink only the lock inode that was inspected by this contender."""
    try:
        current = lock_path.stat()
    except FileNotFoundError:
        return True
    if current.st_dev != device or current.st_ino != inode:
        return False
    with contextlib.suppress(FileNotFoundError):
        lock_path.unlink()
    return True


def _reclaim_stale_lock(lock_path: Path) -> bool:
    """Remove a dead owner's unchanged lock record."""
    try:
        stat = lock_path.stat()
    except FileNotFoundError:
        return True
    owner = _read_owner(lock_path)
    state = _owner_state(owner)
    if state is _OwnerState.LIVE:
        return False
    if state is _OwnerState.UNKNOWN and time.time() - stat.st_mtime < _UNKNOWN_OWNER_GRACE_SECONDS:
        return False
    return _unlink_same_inode(lock_path, device=stat.st_dev, inode=stat.st_ino)


@contextmanager
def cache_path_lock(lock_path: Path, *, timeout_seconds: float = 600.0) -> Iterator[None]:
    """Acquire one crash-recoverable exclusive cache lock."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    descriptor: int | None = None
    lock_device: int | None = None
    lock_inode: int | None = None
    while descriptor is None:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            lock_stat = os.fstat(descriptor)
            lock_device = lock_stat.st_dev
            lock_inode = lock_stat.st_ino
            owner = _LockOwner(pid=os.getpid(), process_start=_process_start_token(os.getpid()))
            _write_all(descriptor, owner.to_bytes())
        except FileExistsError:
            if _reclaim_stale_lock(lock_path):
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for cache key lock: {lock_path}")  # noqa: B904
            time.sleep(0.05)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
                if lock_device is not None and lock_inode is not None:
                    with contextlib.suppress(OSError):
                        _unlink_same_inode(lock_path, device=lock_device, inode=lock_inode)
            raise
    try:
        yield
    finally:
        os.close(descriptor)
        if lock_device is not None and lock_inode is not None:
            with contextlib.suppress(OSError):
                _unlink_same_inode(lock_path, device=lock_device, inode=lock_inode)
