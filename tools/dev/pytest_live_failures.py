"""Show failure evidence as soon as a pytest phase finishes.

Layer: Tooling/pytest adapter.
Responsibility: print existing failure reports without changing outcomes,
selection, traceback construction, or pytest's final summary.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest
from _pytest.terminal import TerminalReporter


def _report_hook[HookFunction: Callable[..., object]](function: HookFunction) -> HookFunction:
    """Retain the hook signature across pytest's dynamic decorator boundary."""
    return cast(HookFunction, pytest.hookimpl(trylast=True)(function))


class LiveFailures:
    """Forward failed phase reports to the existing terminal reporter."""

    def __init__(self, terminal: TerminalReporter) -> None:
        """Retain the session's output owner without collecting extra metrics."""
        self.terminal: TerminalReporter = terminal

    @_report_hook
    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        """Flush node identity, phase and pytest's already-rendered traceback."""
        if not report.failed:
            return
        self.terminal.write_sep("=", f"LIVE FAILURE [{report.when}] {report.nodeid}", red=True)
        self.terminal.write_line(report.longreprtext)
        self.terminal.flush()


@_report_hook
def pytest_configure(config: pytest.Config) -> None:
    """Register exactly once in serial pytest or the xdist controller."""
    # xdist adds workerinput dynamically to third-party pytest.Config objects.
    # Workers forward reports to the controller; printing there would duplicate
    # evidence and send terminal output through xdist's capture channel.
    if hasattr(config, "workerinput"):
        return
    terminal = config.pluginmanager.get_plugin("terminalreporter")
    if isinstance(terminal, TerminalReporter):
        config.pluginmanager.register(LiveFailures(terminal), "live-failure-reporter")
