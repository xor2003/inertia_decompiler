"""Failure feedback must arrive before the summary without changing outcomes."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from _pytest.terminal import TerminalReporter

from scripts import pytest_live_failures
from scripts.pytest_live_failures import LiveFailures

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("worker,terminal_enabled", [(False, True), (True, True), (False, False)])
def test_registration_only_owns_controller_terminal(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, worker: bool, terminal_enabled: bool,
) -> None:
    """Workers and explicitly disabled terminals do not acquire an observer."""
    config = request.config
    terminal = TerminalReporter(config, file=io.StringIO()) if terminal_enabled else None
    registrations: list[tuple[object, str]] = []
    monkeypatch.setattr(config.pluginmanager, "get_plugin", lambda name: terminal)
    monkeypatch.setattr(config.pluginmanager, "register", lambda plugin, name: registrations.append((plugin, name)))
    if worker:
        monkeypatch.setattr(config, "workerinput", {}, raising=False)
    else:
        monkeypatch.delattr(config, "workerinput", raising=False)
    pytest_live_failures.pytest_configure(config)
    assert len(registrations) == int(terminal_enabled and not worker)


def test_failure_flushes_immediately_without_mutating_report(request: pytest.FixtureRequest) -> None:
    """A failed hook call flushes its evidence before returning to pytest."""
    class FlushCapture(io.StringIO):
        """Record explicit flushes as well as terminal text."""

        def __init__(self) -> None:
            super().__init__()
            self.flushes = 0

        def flush(self) -> None:
            self.flushes += 1
            super().flush()

    stream = FlushCapture()
    reporter = LiveFailures(TerminalReporter(request.config, file=stream))
    report = pytest.TestReport("test_demo.py::test_bad", ("test_demo.py", 1, "test_bad"), {}, "failed", "trace evidence", "call")
    before = vars(report).copy()
    reporter.pytest_runtest_logreport(report)
    assert "LIVE FAILURE [call] test_demo.py::test_bad" in stream.getvalue()
    assert "trace evidence" in stream.getvalue()
    assert stream.flushes > 0
    assert vars(report) == before


@pytest.mark.parametrize("outcome", ["passed", "skipped"])
def test_nonfailure_reports_are_quiet(request: pytest.FixtureRequest, outcome: str) -> None:
    """Successes and expected xfail/skip reports do not add noise."""
    stream = io.StringIO()
    reporter = LiveFailures(TerminalReporter(request.config, file=stream))
    report = pytest.TestReport("test_demo.py::test_ok", ("test_demo.py", 1, "test_ok"), {}, outcome, None, "call")
    reporter.pytest_runtest_logreport(report)
    assert stream.getvalue() == ""


@pytest.mark.parametrize("workers", [0, 2])
@pytest.mark.skipif(
    "PYTEST_XDIST_WORKER" in os.environ,
    reason="Nested pytest controls run in an explicit serial lane to preserve the aggregate worker limit",
)
def test_live_failures_preserve_reports_and_emit_before_session_end(tmp_path: Path, workers: int) -> None:
    """Serial/controller output includes setup, call and teardown failures once."""
    config = tmp_path / "pytest.ini"
    config.write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "receipt_plugin.py").write_text(
        "import json, os\nfrom pathlib import Path\nimport pytest\n"
        "reports = []\n"
        "def pytest_runtest_logreport(report):\n"
        "    reports.append((report.nodeid, report.when, report.outcome))\n"
        "@pytest.hookimpl(tryfirst=True)\n"
        "def pytest_sessionfinish(session, exitstatus):\n"
        "    if hasattr(session.config, 'workerinput'): return\n"
        "    print('SESSION_END_RECEIPT', flush=True)\n"
        "    Path(os.environ['REPORT_RECEIPT']).write_text(json.dumps(sorted(reports)))\n",
        encoding="utf-8",
    )
    (tmp_path / "test_cases.py").write_text(
        "import pytest\n"
        "@pytest.fixture\n"
        "def setup_error():\n    raise RuntimeError('setup evidence')\n"
        "@pytest.fixture\n"
        "def teardown_error():\n    yield\n    raise RuntimeError('teardown evidence')\n"
        "def test_setup(setup_error): pass\n"
        "def test_two_phases(teardown_error):\n    assert False, 'call evidence'\n"
        "def test_pass(): pass\n"
        "@pytest.mark.skip(reason='control')\ndef test_skip(): pass\n"
        "@pytest.mark.xfail(reason='control')\ndef test_xfail(): assert False\n"
        "@pytest.mark.xfail(strict=True, reason='strict control')\ndef test_xpass(): pass\n",
        encoding="utf-8",
    )
    outcomes: list[tuple[int, object]] = []
    for enabled in (False, True):
        receipt = tmp_path / f"receipt-{enabled}.json"
        environment = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join((str(ROOT), str(tmp_path))),
            "PYTEST_ADDOPTS": "",
            "REPORT_RECEIPT": str(receipt),
        }
        command = [sys.executable, "-m", "pytest", "-c", str(config), "-q", "--tb=short", "-p", "receipt_plugin"]
        if enabled:
            command.extend(("-p", "scripts.pytest_live_failures"))
        if workers:
            command.extend(("-n", str(workers)))
        result = subprocess.run(
            [*command, "test_cases.py"], cwd=tmp_path, env=environment,
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout + result.stderr
        assert receipt.is_file(), output
        outcomes.append((result.returncode, json.loads(receipt.read_text(encoding="utf-8"))))
        if enabled:
            early = output.split("SESSION_END_RECEIPT", maxsplit=1)[0]
            assert early.count("LIVE FAILURE [setup] test_cases.py::test_setup") == 1, output
            assert early.count("LIVE FAILURE [call] test_cases.py::test_two_phases") == 1, output
            assert early.count("LIVE FAILURE [teardown] test_cases.py::test_two_phases") == 1, output
            assert early.count("LIVE FAILURE [call] test_cases.py::test_xpass") == 1, output
            assert early.count("LIVE FAILURE") == 4, output
            for evidence in ("setup evidence", "call evidence", "teardown evidence", "XPASS(strict)"):
                assert evidence in early, output
        else:
            assert "LIVE FAILURE" not in output
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] == 1
