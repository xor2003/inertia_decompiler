"""Collect low-overhead process metrics for pytest profiling.

Layer: Tooling/gates.
Responsibility: expose Linux RSS and cumulative child-CPU snapshots without
wrapping subprocess APIs or changing test commands.
"""

from __future__ import annotations

import os
import resource
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple


class _ProcessStatus(NamedTuple):
    """Parent identity and resident memory parsed from one Linux status file."""

    parent_pid: int
    rss_kib: int


def current_rss_kib() -> int | None:
    """Return current process RSS on Linux for per-test endpoint sampling."""

    try:
        resident_pages = int(Path("/proc/self/statm").read_text(encoding="ascii").split()[1])
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
    except (IndexError, OSError, TypeError, ValueError):
        return None
    return resident_pages * page_size // 1024


def _process_status(pid: int) -> _ProcessStatus | None:
    """Read one Linux process status without failing on process exit races."""

    try:
        lines = (Path("/proc") / str(pid) / "status").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    parent_pid: int | None = None
    rss_kib = 0
    for line in lines:
        if line.startswith("PPid:"):
            try:
                parent_pid = int(line.split()[1])
            except (IndexError, ValueError):
                return None
        elif line.startswith("VmRSS:"):
            try:
                rss_kib = int(line.split()[1])
            except (IndexError, ValueError):
                return None
    if parent_pid is None:
        return None
    return _ProcessStatus(parent_pid=parent_pid, rss_kib=rss_kib)


def _process_statuses() -> dict[int, _ProcessStatus] | None:
    """Snapshot visible Linux process parent and RSS facts."""

    statuses: dict[int, _ProcessStatus] = {}
    try:
        proc_entries = tuple(Path("/proc").iterdir())
    except OSError:
        return None
    for entry in proc_entries:
        if not entry.name.isdecimal():
            continue
        status = _process_status(int(entry.name))
        if status is not None:
            statuses[int(entry.name)] = status
    return statuses


def process_tree_pids(root_pids: tuple[int, ...]) -> tuple[int, ...] | None:
    """Return roots and all currently visible descendants in parent-first order."""

    statuses = _process_statuses()
    if statuses is None:
        return None
    descendants = set(root_pids)
    changed = True
    while changed:
        changed = False
        for pid, status in statuses.items():
            if pid not in descendants and status.parent_pid in descendants:
                descendants.add(pid)
                changed = True
    return tuple(sorted(descendants))


def process_tree_rss_kib(root_pids: tuple[int, ...]) -> int | None:
    """Return aggregate RSS for roots and all currently visible descendants."""

    if not root_pids:
        return 0
    statuses = _process_statuses()
    if statuses is None:
        return None
    descendants = set(root_pids)
    changed = True
    while changed:
        changed = False
        for pid, status in statuses.items():
            if pid not in descendants and status.parent_pid in descendants:
                descendants.add(pid)
                changed = True
    return sum(statuses[pid].rss_kib for pid in descendants if pid in statuses)


def process_trees_rss_kib(root_pids: tuple[int, ...]) -> dict[int, int] | None:
    """Return independent process-tree RSS totals from one procfs snapshot."""

    if not root_pids:
        return {}
    statuses = _process_statuses()
    if statuses is None:
        return None
    descendants_by_root = {root_pid: {root_pid} for root_pid in root_pids}
    changed = True
    while changed:
        changed = False
        for pid, status in statuses.items():
            for descendants in descendants_by_root.values():
                if pid not in descendants and status.parent_pid in descendants:
                    descendants.add(pid)
                    changed = True
    return {
        root_pid: sum(statuses[pid].rss_kib for pid in descendants if pid in statuses)
        for root_pid, descendants in descendants_by_root.items()
    }


@dataclass(frozen=True, slots=True)
class ChildUsageSnapshot:
    """Cumulative CPU consumed by descendants already waited for by this process."""

    user_seconds: float
    system_seconds: float

    @classmethod
    def capture(cls) -> ChildUsageSnapshot | None:
        """Capture cumulative child CPU, or return ``None`` when unsupported."""

        try:
            usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        except (OSError, ValueError):
            return None
        return cls(user_seconds=float(usage.ru_utime), system_seconds=float(usage.ru_stime))

    def delta_since(self, earlier: ChildUsageSnapshot) -> ChildUsageSnapshot:
        """Return a non-negative delta from an earlier cumulative snapshot."""

        return ChildUsageSnapshot(
            user_seconds=max(0.0, self.user_seconds - earlier.user_seconds),
            system_seconds=max(0.0, self.system_seconds - earlier.system_seconds),
        )
