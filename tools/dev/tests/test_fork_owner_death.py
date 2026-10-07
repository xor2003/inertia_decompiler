"""KVM-free lifecycle controls for supervised CLI workers and descendants."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux owner-death and pidfd lifecycle controls")


OWNER = r'''
import os, pathlib, subprocess, sys, time
import inertia.cli.fork_timeout as module
root = pathlib.Path(sys.argv[2])
original_fork = os.fork
fork_count = 0
def tracked_fork():
    global fork_count
    fork_count += 1
    if sys.argv[3] == "fork_failure" and fork_count == 2:
        raise OSError(11, "injected guardian creation failure")
    pid = original_fork()
    if pid and fork_count == 1:
        (root / "worker.pid").write_text(str(pid))
    return pid
os.fork = tracked_fork
if sys.argv[3] in {"guardian_dies_before_ready", "guardian_never_ready"}:
    def unavailable(*args, **kwargs):
        if sys.argv[3] == "guardian_never_ready":
            time.sleep(60)
        os._exit(7)
    module._guardian_child_8616 = unavailable
if sys.argv[3] == "delayed_guardian":
    def delayed(*args, **kwargs):
        (root / "guardian_pending").touch()
        time.sleep(60)
        raise AssertionError("parent must kill owner during setup")
    module._spawn_guardian_8616 = delayed
def work():
    (root / "callable_started").touch()
    if sys.argv[3] in {"ordinary_descendant", "nested_descendant"}:
        def nested():
            (root / "descendant.pid").write_text(str(os.getpid()))
            time.sleep(60)
        if sys.argv[3] == "nested_descendant":
            module.run_with_timeout_in_fork(nested, timeout=60)
        else:
            child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"])
            (root / "descendant.pid").write_text(str(child.pid))
            child.wait()
    return 42
try:
    module.run_with_timeout_in_fork(work, timeout=60 if "descendant" in sys.argv[3] else 2)
except RuntimeError as error:
    (root / "admission_error").write_text(str(error))
'''


def _wait_path(path: Path) -> None:
    deadline = time.monotonic() + 5
    while not path.exists() or (path.suffix == ".pid" and not path.read_text().strip().isdigit()):
        assert time.monotonic() < deadline, f"readiness timeout: {path.name}"
        time.sleep(0.01)


def _cleanup(owner: subprocess.Popen[str], root: Path) -> None:
    if owner.poll() is None:
        owner.kill()
    owner.wait(timeout=3)
    descendant_file = root / "descendant.pid"
    if descendant_file.exists():
        with contextlib.suppress(ProcessLookupError):
            os.kill(int(descendant_file.read_text()), signal.SIGKILL)
    worker_file = root / "worker.pid"
    if worker_file.exists():
        worker = int(worker_file.read_text())
        with contextlib.suppress(ProcessLookupError):
            os.killpg(worker, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError):
            os.kill(worker, signal.SIGKILL)


@pytest.mark.parametrize("mode", ["fork_failure", "delayed_guardian", "guardian_dies_before_ready", "guardian_never_ready"])
def test_work_requires_live_supervision(tmp_path: Path, mode: str) -> None:
    owner = subprocess.Popen(
        [sys.executable, "-c", OWNER, "production", str(tmp_path), mode],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    try:
        if mode != "delayed_guardian":
            _stdout, stderr = owner.communicate(timeout=3)
            assert owner.returncode == 0, stderr
            assert (tmp_path / "admission_error").exists(), "guardian failure was silent"
        else:
            _wait_path(tmp_path / "guardian_pending")
            owner.kill()
            owner.wait(timeout=3)
        assert not (tmp_path / "callable_started").exists(), "work ran before supervision admission"
    finally:
        _cleanup(owner, tmp_path)


@pytest.mark.parametrize("mode", ["ordinary_descendant", "nested_descendant"])
def test_owner_death_stops_owned_descendants(tmp_path: Path, mode: str) -> None:
    """An externally killed owner cannot leave its disposable group running."""
    owner = subprocess.Popen(
        [sys.executable, "-c", OWNER, "production", str(tmp_path), mode],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        text=True, start_new_session=True,
    )
    try:
        _wait_path(tmp_path / "descendant.pid")
        worker = int((tmp_path / "worker.pid").read_text())
        descendant = int((tmp_path / "descendant.pid").read_text())
        owner.kill()
        owner.wait(timeout=3)
        deadline = time.monotonic() + 3
        while any(_running(pid) for pid in (worker, descendant)):
            assert time.monotonic() < deadline, "owned process outlived its killed owner"
            time.sleep(0.01)
    finally:
        _cleanup(owner, tmp_path)


def _running(pid: int) -> bool:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1]
    except FileNotFoundError:
        return False
    return fields[0] not in {"X", "Z"}
