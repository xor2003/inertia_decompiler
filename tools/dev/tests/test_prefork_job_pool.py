"""Tests for bounded CLI prefork execution infrastructure."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import inertia.cli.prefork_job_pool as prefork_job_pool
from inertia.cli.prefork_job_pool import PreforkJobPool


def _delayed_identity(payload: object) -> object:
    """Return one payload with the worker process identity after a delay."""
    delay, value = payload
    time.sleep(float(delay))
    return os.getpid(), value


def _run_one_concurrent_scenario() -> None:
    """Exercise concurrent callers from an otherwise clean interpreter."""
    pool = PreforkJobPool(max_workers=2, worker_func=_delayed_identity)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = (
                executor.submit(pool.run_one, 1, (0.05, "first")),
                executor.submit(pool.run_one, 2, (0.05, "second")),
            )
            results = tuple(future.result(timeout=2) for future in futures)
        assert {result[1] for result in results} == {"first", "second"}
        assert all(result[0] != os.getpid() for result in results)
        assert len({result[0] for result in results}) == 2
    finally:
        pool.shutdown()


def _run_unordered_scenario() -> None:
    """Exercise batch dispatch from an otherwise clean interpreter."""
    pool = PreforkJobPool(max_workers=2, worker_func=_delayed_identity)
    try:
        completed = dict(
            pool.run_unordered(
                [(1, (0.03, "one")), (2, (0.01, "two")), (3, (0.0, "three"))]
            )
        )
        assert set(completed) == {1, 2, 3}
        assert {result[1] for result in completed.values()} == {"one", "two", "three"}
    finally:
        pool.shutdown()


def _run_scenario_in_clean_process(scenario: str) -> None:
    """Run one fork scenario outside the multithreaded xdist worker."""
    environment = os.environ.copy()
    project_root = Path(__file__).resolve().parents[3]
    environment["PYTHON_JIT"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONPATH"] = os.pathsep.join(
        (str(project_root), environment.get("PYTHONPATH", ""))
    ).rstrip(os.pathsep)
    completed = subprocess.run(
        [sys.executable, __file__, scenario],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "multi-threaded, use of fork()" not in completed.stderr


@pytest.mark.skipif(os.name != "posix", reason="prefork requires POSIX")
def test_prefork_pool_run_one_serves_concurrent_threads() -> None:
    """Caller threads must use workers forked before those threads existed."""
    _run_scenario_in_clean_process("concurrent")


@pytest.mark.skipif(os.name != "posix", reason="prefork requires POSIX")
def test_prefork_pool_run_unordered_closes_all_jobs() -> None:
    """Batch dispatch must return every typed job identity exactly once."""
    _run_scenario_in_clean_process("unordered")


@pytest.mark.skipif(os.name != "posix", reason="prefork requires POSIX")
def test_prefork_pool_rejects_start_after_thread_creation() -> None:
    """The pool must fail before forking from a multithreaded parent."""
    stop = threading.Event()
    thread = threading.Thread(target=stop.wait)
    thread.start()
    try:
        with pytest.raises(RuntimeError, match="single-threaded"):
            PreforkJobPool(max_workers=1, worker_func=_delayed_identity)
    finally:
        stop.set()
        thread.join(timeout=1)


def test_prefork_framing_retries_partial_pipe_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partial writes must retain one frame buffer without suffix copies."""
    read_fd, write_fd = os.pipe()
    real_write = os.write
    write_buffers: list[bytes | memoryview] = []

    def _partial_write(fd: int, data: bytes | memoryview) -> int:
        write_buffers.append(data)
        return real_write(fd, data[: max(1, min(3, len(data)))])

    monkeypatch.setattr(prefork_job_pool.os, "write", _partial_write)
    try:
        prefork_job_pool._write_framed_pickle(write_fd, {"payload": "x" * 64})
        assert prefork_job_pool._read_framed_pickle(read_fd) == {"payload": "x" * 64}
        assert write_buffers
        assert all(isinstance(data, memoryview) for data in write_buffers)
        assert len({id(data.obj) for data in write_buffers if isinstance(data, memoryview)}) == 1
    finally:
        os.close(read_fd)
        os.close(write_fd)


if __name__ == "__main__":
    scenarios = {
        "concurrent": _run_one_concurrent_scenario,
        "unordered": _run_unordered_scenario,
    }
    scenarios[sys.argv[1]]()
