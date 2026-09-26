import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from inertia_decompiler.fork_timeout import ForkChildExitError, run_captured_subprocess_tree, run_with_timeout_in_fork


@pytest.mark.parametrize("exit_code", [0, 3, 17])
def test_fork_hard_exit_preserves_typed_returncode(exit_code):
    """No-result exits retain OS status, including zero without an IPC result."""
    with pytest.raises(ForkChildExitError) as captured:
        run_with_timeout_in_fork(lambda: os._exit(exit_code), timeout=5)
    assert captured.value.returncode == exit_code


def _process_is_running(pid: int) -> bool:
    stat_path = Path("/proc") / str(pid) / "stat"
    if stat_path.exists():
        try:
            fields = stat_path.read_text(encoding="utf-8").split()
        except FileNotFoundError:
            return False
        return len(fields) < 3 or fields[2] not in {"X", "Z"}
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_fork_timeout_reaps_descendants_left_by_nested_timeout(tmp_path: Path) -> None:
    if os.name != "posix":
        try:
            run_with_timeout_in_fork(lambda: None, timeout=1)
        except RuntimeError as exc:
            assert str(exc) == "fork unavailable"
            return
        raise AssertionError("non-POSIX fork timeout did not refuse execution")

    marker = tmp_path / "descendant.pid"
    script = r'''
import os
import sys
import time
from pathlib import Path
from inertia_decompiler.fork_timeout import run_with_timeout_in_fork

marker = Path(sys.argv[1])

def spawn_descendant_and_block():
    descendant_pid = os.fork()
    if descendant_pid == 0:
        marker.write_text(str(os.getpid()), encoding="ascii")
        time.sleep(60)
        os._exit(0)
    deadline = time.monotonic() + 2.0
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not marker.exists():
        raise RuntimeError("descendant did not publish its PID")
    time.sleep(60)

def run_nested_timeout():
    try:
        run_with_timeout_in_fork(spawn_descendant_and_block, timeout=1)
    except TimeoutError:
        return "nested-timeout"
    raise AssertionError("nested timeout did not fire")

print(run_with_timeout_in_fork(run_nested_timeout, timeout=4))
'''

    result = subprocess.run(
        [sys.executable, "-c", script, str(marker)],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "nested-timeout"
    descendant_pid = int(marker.read_text(encoding="ascii"))
    deadline = time.monotonic() + 2.0
    while _process_is_running(descendant_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not _process_is_running(descendant_pid)


def test_fork_timeout_bounds_partial_result_reads() -> None:
    if os.name != "posix":
        return

    script = r'''
import os
import time
import inertia_decompiler.fork_timeout as fork_timeout

def write_partial_result(_func, write_fd, read_fd, *, owns_process_group):
    del owns_process_group
    os.close(read_fd)
    os.write(write_fd, b"\x10")
    time.sleep(60)

fork_timeout._run_child = write_partial_result
started = time.monotonic()
try:
    fork_timeout.run_with_timeout_in_fork(lambda: None, timeout=1)
except TimeoutError as exc:
    print(type(exc).__name__)
    print(str(exc))
    print(f"{time.monotonic() - started:.3f}")
'''

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0] == "TimeoutError"
    assert "Timed out after 1s" in lines[1]
    assert float(lines[2]) < 2.5


def test_captured_subprocess_timeout_reaps_pipe_holding_descendants(tmp_path: Path) -> None:
    if os.name != "posix":
        return

    marker = tmp_path / "captured-descendant.pid"
    script = r'''
import subprocess
import sys
import time
from pathlib import Path

marker = Path(sys.argv[1])
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
marker.write_text(str(child.pid), encoding="ascii")
time.sleep(60)
'''
    started = time.monotonic()
    try:
        run_captured_subprocess_tree(
            [sys.executable, "-c", script, str(marker)],
            env=os.environ,
            timeout=1,
        )
    except subprocess.TimeoutExpired:
        pass
    else:
        raise AssertionError("captured subprocess tree did not time out")

    assert time.monotonic() - started < 3.0
    descendant_pid = int(marker.read_text(encoding="ascii"))
    deadline = time.monotonic() + 2.0
    while _process_is_running(descendant_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not _process_is_running(descendant_pid)
