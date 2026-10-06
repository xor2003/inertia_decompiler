"""Cache repeated standard directory reports during one pytest collection.

Layer: Tooling/pytest adapter.
Responsibility: reuse unchanged standard Dir collection reports without caching
module/test execution or changing selectors, item ordering, or duplicate items.
This plugin uses public pytest hooks and never edits installed pytest.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from typing import TypeVar, cast

import pytest

MAX_DIRECTORIES: int = 128
MAX_CHILDREN: int = 10000

_HookFunction = TypeVar("_HookFunction", bound=Callable[..., object])
_TRY_FIRST_HOOK_IMPL = cast(Callable[[_HookFunction], _HookFunction], pytest.hookimpl(tryfirst=True))
_WRAPPER_HOOK_IMPL = cast(Callable[[_HookFunction], _HookFunction], pytest.hookimpl(wrapper=True))


@dataclass(frozen=True)
class DirectoryStamp:
    """Identity and mutation stamps of the directory whose listing was read."""

    device: int
    inode: int
    modified_ns: int
    changed_ns: int


def directory_stamp(collector: pytest.Collector) -> DirectoryStamp | None:
    """Cache only the standard directory collector, never custom collectors."""
    if type(collector) is not pytest.Dir:
        return None
    try:
        status = collector.path.stat()
    except FileNotFoundError:
        return None
    return DirectoryStamp(status.st_dev, status.st_ino, status.st_mtime_ns, status.st_ctime_ns)


@dataclass
class DirectoryReports:
    """Bounded session-local cache retaining collector identity and source stamp."""

    reports: dict[pytest.Collector, tuple[DirectoryStamp, pytest.CollectReport]] = field(default_factory=dict)
    children: int = 0
    hits: int = 0


class Lookup:
    """Answer only repeated unchanged successful standard-directory requests."""

    def __init__(self, cache: DirectoryReports) -> None:
        """Retain the session-local bounded report cache."""
        self.cache: DirectoryReports = cache

    @_TRY_FIRST_HOOK_IMPL
    def pytest_make_collect_report(self, collector: pytest.Collector) -> pytest.CollectReport | None:
        """Reuse a directory report; pytest still collects each selected module."""
        saved = self.cache.reports.get(collector)
        if saved is not None and directory_stamp(collector) == saved[0]:
            self.cache.hits += 1
            return saved[1]
        return None


class Record:
    """Retain successful listings only when their directory stayed unchanged."""

    def __init__(self, cache: DirectoryReports) -> None:
        """Share the lookup cache for this session only."""
        self.cache: DirectoryReports = cache

    @_WRAPPER_HOOK_IMPL
    def pytest_make_collect_report(
        self, collector: pytest.Collector,
    ) -> Generator[None, pytest.CollectReport, pytest.CollectReport]:
        """Observe the original hook result without swallowing collection errors."""
        before = directory_stamp(collector)
        report = yield
        if before is None or not report.passed or directory_stamp(collector) != before:
            return report
        previous = self.cache.reports.get(collector)
        previous_count = 0 if previous is None else len(previous[1].result)
        children = self.cache.children - previous_count + len(report.result)
        if children > MAX_CHILDREN or (previous is None and len(self.cache.reports) >= MAX_DIRECTORIES):
            return report
        self.cache.reports[collector] = (before, report)
        self.cache.children = children
        return report


def pytest_configure(config: pytest.Config) -> None:
    """Create fresh per-session cache state and register the two hook roles."""
    cache = DirectoryReports()
    config.pluginmanager.register(Lookup(cache), "bounded-directory-report-lookup")
    config.pluginmanager.register(Record(cache), "bounded-directory-report-record")
