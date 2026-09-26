"""Tests for deterministic startup of the focused decompilation batch helper."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from argparse import Namespace
from functools import cached_property
from pathlib import Path

import pytest

from scripts import batch_decompile_procs


class _ReexecObserved(RuntimeError):
    """Stop a mocked successful exec replacement."""


def test_batch_decompile_reexecs_before_decompiler_use(monkeypatch) -> None:
    """A random hash runtime must restart with stable hashing and the JIT enabled."""
    monkeypatch.delenv("PYTHONHASHSEED", raising=False)
    monkeypatch.delenv("PYTHON_JIT", raising=False)
    monkeypatch.setattr(sys, "argv", ["batch_decompile_procs.py", "--help"])

    def _execvpe(executable: str, argv: list[str], environment: dict[str, str]) -> None:
        assert executable == sys.executable
        assert argv[0] == sys.executable
        assert argv[-1] == "--help"
        assert environment["PYTHONHASHSEED"] == "0"
        assert environment["PYTHON_JIT"] == "1"
        raise _ReexecObserved

    monkeypatch.setattr(os, "execvpe", _execvpe)

    with pytest.raises(_ReexecObserved):
        batch_decompile_procs._ensure_deterministic_python_runtime_8616()


def test_batch_decompile_keeps_deterministic_runtime(monkeypatch) -> None:
    """An already deterministic JIT process must not replace itself."""
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setenv("PYTHON_JIT", "1")
    monkeypatch.setattr(
        os,
        "execvpe",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected re-exec")),
    )

    batch_decompile_procs._ensure_deterministic_python_runtime_8616()


@pytest.mark.parametrize("exit_via_exception", [False, True])
def test_batch_job_streams_artifacts_before_cli_returns(tmp_path, monkeypatch, exit_via_exception):
    """A process deadline must not discard all output from its active function."""
    job = batch_decompile_procs.BatchDecompileJob("active", Path("input.exe"), ["--addr", "0x10000"])

    def run_cli(argv):
        assert argv == job.argv
        print("partial generated C")
        print("recovery checkpoint", file=sys.stderr)
        assert (tmp_path / "active.stdout.c").read_text() == "partial generated C\n"
        assert (tmp_path / "active.stderr.txt").read_text() == "recovery checkpoint\n"
        if exit_via_exception:
            raise SystemExit(3)
        return 0

    monkeypatch.setattr(batch_decompile_procs.decompiler_cli, "main", run_cli)
    result = batch_decompile_procs._run_one_job(Namespace(out_dir=tmp_path), job)
    assert result.returncode == (3 if exit_via_exception else 0)


def test_batch_job_preserves_artifacts_and_propagates_failure(tmp_path, monkeypatch):
    """Unexpected errors remain loud, with logs and process globals restored."""
    job = batch_decompile_procs.BatchDecompileJob("broken", Path("input.exe"), ["--addr", "0x10000"])
    original_argv = sys.argv[:]
    original_stdout, original_stderr = sys.stdout, sys.stderr

    def run_cli(_argv):
        print("partial generated C")
        print("failure evidence", file=sys.stderr)
        raise RuntimeError("analysis failed")

    monkeypatch.setattr(batch_decompile_procs.decompiler_cli, "main", run_cli)
    with pytest.raises(RuntimeError, match="analysis failed"):
        batch_decompile_procs._run_one_job(Namespace(out_dir=tmp_path), job)
    assert sys.argv == original_argv
    assert sys.stdout is original_stdout and sys.stderr is original_stderr
    assert (tmp_path / "broken.stdout.c").read_text() == "partial generated C\n"
    assert (tmp_path / "broken.stderr.txt").read_text() == "failure evidence\n"


def test_batch_report_checkpoints_finished_jobs_before_next_failure(tmp_path, monkeypatch):
    """A later interrupted job must not erase completed records used by fallback."""
    output = tmp_path / "batch"

    def run_job(args, job):
        if job.name == "second":
            report = json.loads((output / "batch_report.json").read_text())
            assert [result["proc"] for result in report["results"]] == ["first"]
            assert report["results"][0]["returncode"] == 3
            raise RuntimeError("second job interrupted")
        return batch_decompile_procs.BatchProcResult(
            job.name, 3, str(output / "first.stdout.c"), str(output / "first.stderr.txt"), 1.0, job.argv,
        )

    monkeypatch.setattr(batch_decompile_procs, "_run_one_job", run_job)
    with pytest.raises(RuntimeError, match="second job interrupted"):
        batch_decompile_procs.main([
            "input.exe", "--out-dir", str(output), "--proc", "first", "--proc", "second",
        ])
    report = json.loads((output / "batch_report.json").read_text())
    assert len(report["results"]) == 1


def test_batch_report_clears_stale_records_before_first_job(tmp_path, monkeypatch):
    """Reusing an output directory must not expose a prior run's accepted jobs."""
    (tmp_path / "batch_report.json").write_text(json.dumps({"results": [{"proc": "stale", "returncode": 0}]}))

    def run_job(args, job):
        assert json.loads((tmp_path / "batch_report.json").read_text())["results"] == []
        raise RuntimeError("first job interrupted")

    monkeypatch.setattr(batch_decompile_procs, "_run_one_job", run_job)
    with pytest.raises(RuntimeError, match="first job interrupted"):
        batch_decompile_procs.main(["input.exe", "--out-dir", str(tmp_path), "--proc", "first"])


def test_batch_jobs_rebind_loggers_created_during_previous_job(tmp_path, monkeypatch):
    """Lazy third-party loggers must follow the active job, not retain closed files."""
    logger = logging.getLogger("batch-test-lazy-logger")
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "propagate", False)
    original_stderr = sys.stderr

    def run_cli(argv):
        if not logger.handlers:
            logger.addHandler(logging.StreamHandler(sys.stderr))
        logger.warning("job %s", argv[0])
        return 0

    monkeypatch.setattr(batch_decompile_procs.decompiler_cli, "main", run_cli)
    for name in ("first", "second"):
        job = batch_decompile_procs.BatchDecompileJob(name, Path("input.exe"), [name])
        batch_decompile_procs._run_one_job(Namespace(out_dir=tmp_path), job)
        assert (tmp_path / f"{name}.stderr.txt").read_text() == f"job {name}\n"
        assert logger.handlers[0].stream is original_stderr


def test_batch_hard_exit_is_a_failed_job_not_the_end_of_the_batch(tmp_path):
    """The real hard-exit boundary must leave later jobs runnable and reportable."""
    script = r'''
import os
import sys
from scripts import batch_decompile_procs as batch

def cli(argv):
    name = argv[argv.index("--proc") + 1]
    print("emitted " + name, flush=True)
    if name == "first":
        os._exit(3)
    return 0

batch.decompiler_cli.main = cli
raise SystemExit(batch.main(["input.exe", "--out-dir", sys.argv[1], "--proc", "first", "--proc", "second"]))
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 1, result.stderr
    report = json.loads((tmp_path / "batch_report.json").read_text())
    assert [(item["proc"], item["returncode"]) for item in report["results"]] == [("first", 3), ("second", 0)]
    assert (tmp_path / "first.stdout.c").read_text() == "emitted first\n"
    assert (tmp_path / "second.stdout.c").read_text() == "emitted second\n"


def test_batch_isolation_uses_job_budget_and_marks_outer_timeout(tmp_path, monkeypatch):
    """Setup allowance stays outside the job's analysis deadline; timeout cannot pass."""
    from inertia_decompiler.cli_terminal_status import CliTerminalStatus, read_terminal_status

    def timeout(_work, *, timeout):
        assert timeout == 420
        raise TimeoutError("outer process deadline")

    monkeypatch.setattr(batch_decompile_procs, "run_with_timeout_in_fork", timeout)
    job = batch_decompile_procs.BatchDecompileJob("slow", Path("input.exe"), [], timeout=300)
    result = batch_decompile_procs._run_isolated_job(Namespace(out_dir=tmp_path), job)
    assert result.returncode == 3
    assert read_terminal_status(Path(result.stderr_path).read_text()) is CliTerminalStatus.TIMEOUT


def test_batch_isolation_refuses_zero_exit_without_result(tmp_path, monkeypatch):
    """A vanished IPC result must not become a fabricated successful job."""
    def incomplete(_work, *, timeout):
        raise batch_decompile_procs.ForkChildExitError("missing result", 0)

    monkeypatch.setattr(batch_decompile_procs, "run_with_timeout_in_fork", incomplete)
    job = batch_decompile_procs.BatchDecompileJob("missing", Path("input.exe"), [])
    with pytest.raises(batch_decompile_procs.ForkChildExitError):
        batch_decompile_procs._run_isolated_job(Namespace(out_dir=tmp_path), job)


def test_batch_resolves_lazy_cli_in_parent_before_fork(tmp_path, monkeypatch):
    """Expensive CLI imports must be shared, without running analysis in the parent."""
    marker = tmp_path / "import.pid"

    class LazyCLI:
        """Emulate the CLI module adapter's cached entrypoint resolution."""

        @cached_property
        def main(self):
            marker.write_text(str(os.getpid()))
            return lambda _argv: 0

    monkeypatch.setattr(batch_decompile_procs, "decompiler_cli", LazyCLI())
    assert batch_decompile_procs.main(["input.exe", "--out-dir", str(tmp_path), "--proc", "first"]) == 0
    assert int(marker.read_text()) == os.getpid()
