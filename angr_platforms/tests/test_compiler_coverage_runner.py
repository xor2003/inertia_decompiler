"""The coverage adapter must bound execution and reject stale evidence."""

import json
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import compiler_coverage_runner as runner
from scripts.compiler_coverage_result import CoverageOutcome


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), -float("inf")])
def test_invalid_deadline_rejected_before_creating_artifacts(tmp_path, monkeypatch, timeout):
    launch = Mock()
    monkeypatch.setattr(runner.subprocess, "Popen", launch)
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="timeout"):
        runner.run_existing_case("storage_classes", output, timeout=timeout)
    assert not output.exists()
    launch.assert_not_called()


def test_existing_artifacts_cannot_be_reused(tmp_path, monkeypatch):
    launch = Mock()
    monkeypatch.setattr(runner.subprocess, "Popen", launch)
    with pytest.raises(FileExistsError):
        runner.run_existing_case("storage_classes", tmp_path)
    launch.assert_not_called()


def test_external_fixture_uses_existing_owner_and_fingerprints_headers(tmp_path, monkeypatch):
    source = tmp_path / "csmith.c"
    source.write_text("int main(void) { return 0; }")
    header = tmp_path / "runtime.h"
    header.write_text("/* fixture runtime */")
    execute = Mock(return_value=(1, False))
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    result = runner.run_source_case(source, output, expected_exit_code=0, runtime_headers={"RUNTIME.H": header})
    assert result is CoverageOutcome.HARNESS_FAILED  # No report, not a fabricated pass.
    command = execute.call_args.args[0]
    assert command[1].endswith("scripts/build_msc6_examples.py")
    assert command[command.index("--examples-dir") + 1] == str(tmp_path)
    assert command[command.index("--harvest-success-code") + 1] == "0"
    assert (output / "RUNTIME.H").read_bytes() == header.read_bytes()
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["inputs"]["runtime_headers"]["RUNTIME.H"]["sha256"]


@pytest.mark.parametrize("names", [("../escape.h",), ("file.c",), ("R.H", "r.h")])
def test_invalid_runtime_header_destinations_fail_before_launch(tmp_path, monkeypatch, names):
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    execute = Mock()
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="header"):
        runner.run_source_case(source, output, runtime_headers=dict.fromkeys(names, source))
    execute.assert_not_called()
    assert not output.exists()


@pytest.mark.parametrize("disappeared", [False, True])
def test_timeout_kills_group_and_reaps_child(tmp_path, monkeypatch, disappeared):
    process = Mock(pid=123)
    process.wait.side_effect = [subprocess.TimeoutExpired("compiler", 1), -9]
    monkeypatch.setattr(runner.subprocess, "Popen", Mock(return_value=process))
    kill = Mock(side_effect=ProcessLookupError if disappeared else None)
    monkeypatch.setattr(runner.os, "killpg", kill)
    output = tmp_path / "case"
    assert runner.run_existing_case("storage_classes", output, timeout=1) is CoverageOutcome.TIMED_OUT
    kill.assert_called_once_with(123, runner.signal.SIGKILL)
    assert process.wait.call_count == 2
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["outcome"] == "timed_out"
    assert report["returncode"] == -9


def test_launch_failure_retains_structured_result(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.subprocess, "Popen", Mock(side_effect=OSError("launch failed")))
    output = tmp_path / "case"
    assert runner.run_existing_case("storage_classes", output) is CoverageOutcome.HARNESS_FAILED
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["outcome"] == "harness_failed"
    assert "launch failed" in report["error"]


def test_missing_report_is_not_success(tmp_path, monkeypatch):
    process = Mock()
    process.wait.return_value = 0
    launch = Mock(return_value=process)
    monkeypatch.setattr(runner.subprocess, "Popen", launch)
    assert runner.run_existing_case("storage_classes", tmp_path / "case") is CoverageOutcome.HARNESS_FAILED
    assert launch.call_args.kwargs["start_new_session"] is True
    assert launch.call_args.kwargs["env"]["PYTHONHASHSEED"] == "0"


@pytest.mark.skipif(sys.platform != "linux", reason="Checks Linux descendant process state")
def test_real_timeout_stops_descendants_and_retains_both_output_streams(tmp_path):
    """A real forked child must stop, not merely the adapter's direct child."""
    inventory = tmp_path / "processes.json"
    script = """
import json, os, sys, time
child = os.fork()
if child:
    with open(sys.argv[1], "w") as report:
        json.dump([os.getpid(), child], report)
    print("parent stdout", flush=True)
    print("parent stderr", file=sys.stderr, flush=True)
time.sleep(60)
"""
    pids = []
    try:
        with (tmp_path / "runner.log").open("w") as log:
            returncode, timed_out = runner._execute(
                [sys.executable, "-c", script, str(inventory)], log, timeout=2,
            )
        assert timed_out
        assert returncode == -signal.SIGKILL
        pids = json.loads(inventory.read_text())
        deadline = time.monotonic() + 2
        while True:
            live = []
            for pid in pids:
                with suppress(FileNotFoundError):
                    # An orphan may remain a zombie until the host init reaps it.
                    state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                    if state not in {"Z", "X"}:
                        live.append(pid)
            if not live or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert not live, f"Timeout left live descendants: {live}"
        output = (tmp_path / "runner.log").read_text()
        assert "parent stdout" in output
        assert "parent stderr" in output
    finally:
        if inventory.exists():
            for pid in json.loads(inventory.read_text()):
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)


def test_interruption_kills_group_and_propagates(monkeypatch, tmp_path):
    process = Mock(pid=123)
    process.wait.side_effect = [KeyboardInterrupt, -signal.SIGKILL]
    monkeypatch.setattr(runner.subprocess, "Popen", Mock(return_value=process))
    kill = Mock()
    monkeypatch.setattr(runner.os, "killpg", kill)
    with (tmp_path / "runner.log").open("w") as log, pytest.raises(KeyboardInterrupt):
        runner._execute(["compiler"], log, timeout=1)
    kill.assert_called_once_with(123, signal.SIGKILL)
    assert process.wait.call_count == 2
