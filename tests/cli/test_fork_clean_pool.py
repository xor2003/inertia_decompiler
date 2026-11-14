"""Tests for the prefork clean-function worker pool lane."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

import inertia.cli.fork_clean_pool as fork_pool_module
import inertia.cli.serial_clean_worker_cli as worker_cli
from inertia.cli.fork_clean_pool import (
    FORK_CLEAN_POOL_ENV_8616,
    ensure_fork_clean_pool_8616,
    fork_clean_pool_8616,
    fork_clean_pool_enabled_8616,
    run_fork_clean_job_8616,
    shutdown_fork_clean_pool_8616,
)


@pytest.fixture(autouse=True)
def _restore_pool_state(monkeypatch: pytest.MonkeyPatch):
    """Reset the global pool singleton and sticky failure latch around each test."""
    shutdown_fork_clean_pool_8616()
    monkeypatch.setattr(fork_pool_module, "_FORK_CLEAN_POOL_FAILED_8616", False)
    monkeypatch.delenv(FORK_CLEAN_POOL_ENV_8616, raising=False)
    yield
    shutdown_fork_clean_pool_8616()
    monkeypatch.setattr(fork_pool_module, "_FORK_CLEAN_POOL_FAILED_8616", False)


def _payload(tmp_path: Path, *, outer_timeout: int = 30, argv: list | None = None, env: dict | None = None) -> dict:
    return {
        "argv": argv or ["--probe-flag"],
        "env": env if env is not None else dict(os.environ),
        "stderr_path": str(tmp_path / "worker.stderr"),
        "stdout_path": str(tmp_path / "worker.stdout"),
        "outer_timeout": outer_timeout,
    }


def test_enabled_requires_posix_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    assert fork_clean_pool_enabled_8616() is False
    monkeypatch.setenv(FORK_CLEAN_POOL_ENV_8616, "1")
    assert fork_clean_pool_enabled_8616() is (os.name == "posix" and hasattr(os, "fork"))


def test_ensure_returns_none_when_disabled() -> None:
    assert ensure_fork_clean_pool_8616(2) is None
    assert fork_clean_pool_8616() is None


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "fork"), reason="prefork lane is POSIX-only")
def test_grandchild_runs_worker_and_captures_streams(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A grandchild must run the worker callable and capture stdout/stderr to owned files."""

    def _fake_main(argv: object = None) -> int:
        print("grandchild-stdout-marker")
        print("grandchild-stderr-marker", file=sys.stderr)
        return 7

    monkeypatch.setattr(worker_cli, "main", _fake_main)
    monkeypatch.setenv(FORK_CLEAN_POOL_ENV_8616, "1")
    pool = ensure_fork_clean_pool_8616(1)
    assert pool is not None
    assert pool.worker_count == 1

    outcome = run_fork_clean_job_8616(
        pool,
        job_id="t1",
        argv=["--addr", "0x1234"],
        environment=dict(os.environ),
        stderr_path=tmp_path / "worker.stderr",
        stdout_path=tmp_path / "worker.stdout",
        outer_timeout=30,
    )
    assert outcome["timed_out"] is False
    assert outcome["returncode"] == 7
    assert "grandchild-stderr-marker" in (tmp_path / "worker.stderr").read_text()
    assert "grandchild-stdout-marker" in (tmp_path / "worker.stdout").read_text()


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "fork"), reason="prefork lane is POSIX-only")
def test_sys_argv_and_env_fidelity_in_grandchild(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """sys.argv[1:] and os.environ inside the worker must mirror the subprocess lane."""

    def _fake_main(argv: object = None) -> int:
        # Runs inside the grandchild; emit observations on stderr for the caller to read.
        print(f"ARGV={sys.argv[1:]}", file=sys.stderr)
        print(f"PPID_GUARD={os.environ.get('INERTIA_TEST_PPID_FLAG', 'unset')}", file=sys.stderr)
        return 0

    monkeypatch.setattr(worker_cli, "main", _fake_main)
    monkeypatch.setenv(FORK_CLEAN_POOL_ENV_8616, "1")
    pool = ensure_fork_clean_pool_8616(1)
    assert pool is not None
    env = dict(os.environ)
    env["INERTIA_TEST_PPID_FLAG"] = "flag-value"
    outcome = run_fork_clean_job_8616(
        pool,
        job_id="t2",
        argv=["--addr", "0xABCD", "--timeout", "5"],
        environment=env,
        stderr_path=tmp_path / "e.txt",
        stdout_path=tmp_path / "o.txt",
        outer_timeout=30,
    )
    assert outcome["returncode"] == 0
    err = (tmp_path / "e.txt").read_text()
    assert "['--addr', '0xABCD', '--timeout', '5']" in err
    assert "PPID_GUARD=flag-value" in err


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "fork"), reason="prefork lane is POSIX-only")
def test_timeout_kills_grandchild_and_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that overruns its outer timeout is killed; the pool worker stays reusable."""

    def _fake_main(argv: object = None) -> int:
        # Pool workers are fork snapshots: distinguish jobs by argv, not re-patch.
        if "--slow" in list(sys.argv[1:]):
            time.sleep(60)
        return 3

    monkeypatch.setattr(worker_cli, "main", _fake_main)
    monkeypatch.setenv(FORK_CLEAN_POOL_ENV_8616, "1")
    pool = ensure_fork_clean_pool_8616(1)
    assert pool is not None
    outcome = run_fork_clean_job_8616(
        pool,
        job_id="t3",
        argv=["--slow"],
        environment=dict(os.environ),
        stderr_path=tmp_path / "e.txt",
        stdout_path=tmp_path / "o.txt",
        outer_timeout=2,
    )
    assert outcome["timed_out"] is True
    assert outcome["returncode"] is None
    second = run_fork_clean_job_8616(
        pool,
        job_id="t4",
        argv=["--ok"],
        environment=dict(os.environ),
        stderr_path=tmp_path / "e2.txt",
        stdout_path=tmp_path / "o2.txt",
        outer_timeout=30,
    )
    assert second["timed_out"] is False
    assert second["returncode"] == 3


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "fork"), reason="prefork lane is POSIX-only")
def test_worker_exception_maps_to_failure_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A raised worker exception becomes a failed job result, not a dead pool worker."""

    def _fake_main(argv: object = None) -> int:
        if "--fail" in list(sys.argv[1:]):
            raise RuntimeError("synthetic-worker-failure")
        return 0

    monkeypatch.setattr(worker_cli, "main", _fake_main)
    monkeypatch.setenv(FORK_CLEAN_POOL_ENV_8616, "1")
    pool = ensure_fork_clean_pool_8616(1)
    assert pool is not None
    outcome = run_fork_clean_job_8616(
        pool,
        job_id="t5",
        argv=["--fail"],
        environment=dict(os.environ),
        stderr_path=tmp_path / "e.txt",
        stdout_path=tmp_path / "o.txt",
        outer_timeout=30,
    )
    assert outcome["timed_out"] is False
    assert outcome["returncode"] != 0
    recovered = run_fork_clean_job_8616(
        pool,
        job_id="t6",
        argv=[],
        environment=dict(os.environ),
        stderr_path=tmp_path / "e3.txt",
        stdout_path=tmp_path / "o3.txt",
        outer_timeout=30,
    )
    assert recovered["returncode"] == 0


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "fork"), reason="prefork lane is POSIX-only")
def test_pool_shutdown_reaps_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FORK_CLEAN_POOL_ENV_8616, "1")
    pool = ensure_fork_clean_pool_8616(2)
    assert pool is not None
    worker_pids = {worker["pid"] for worker in pool._workers}
    assert worker_pids
    shutdown_fork_clean_pool_8616()
    assert fork_clean_pool_8616() is None
    for pid in worker_pids:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        pytest.fail(f"pool worker {pid} still alive after shutdown")
