"""Run bounded CLI work in a disposable POSIX process tree.

Layer: CLI/fallback/reporting.
Responsibility: own fork IPC, timeout enforcement, and descendant cleanup for
process-isolated decompiler work without changing decompiler semantics.
"""

from __future__ import annotations

import contextlib
import enum
import faulthandler
import os
import pickle
import select
import signal
import subprocess
import sys
import threading
import time
import traceback
import typing
from collections.abc import Callable
from dataclasses import dataclass

_ROOT_PROCESS_GROUP: int | None = None


class ForkChildExitError(RuntimeError):
    """Expose a reaped child's exit status when no complete IPC result exists."""

    returncode: int

    def __init__(self, message: str, child_status: int) -> None:
        """Keep the full diagnostic and an OS-decoded exit code or negative signal."""
        super().__init__(message)
        self.returncode = os.waitstatus_to_exitcode(child_status)


class _ForkResultKind(enum.Enum):
    """Classify the structured result sent by a timeout child."""

    OK = "ok"
    ERROR = "error"


@dataclass(frozen=True)
class _ForkResult:
    """Carry one typed result or exception report across the fork pipe."""

    kind: _ForkResultKind
    value: object | None = None
    error_type: str | None = None
    error_detail: str | None = None


def _faulthandler_output_file() -> typing.TextIO | None:
    """Return a usable diagnostic stream for child stack dumps."""
    for stream in (sys.stderr, sys.__stderr__):
        if stream is None:
            continue
        try:
            stream.fileno()
        except Exception:
            continue
        return typing.cast(typing.TextIO, stream)
    return None


def _write_all(fd: int, data: bytes) -> None:
    """Write a complete framed payload to a blocking pipe."""
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise RuntimeError("fork result pipe stopped accepting data")
        offset += written


def _write_result(fd: int, result: _ForkResult) -> None:
    """Serialize and frame one child result."""
    data = pickle.dumps(result, protocol=pickle.HIGHEST_PROTOCOL)
    _write_all(fd, len(data).to_bytes(8, "little"))
    _write_all(fd, data)


def _read_exact(fd: int, size: int, *, deadline: float) -> bytes:
    """Read up to ``size`` bytes before EOF or the shared IPC deadline."""
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            break
        chunk = os.read(fd, min(65536, size - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _child_exit_detail(status: int) -> str:
    """Render a stable child exit diagnostic."""
    if os.WIFEXITED(status):
        return f"exitcode={os.WEXITSTATUS(status)}"
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        try:
            signal_name = signal.Signals(sig).name
        except ValueError:
            signal_name = f"signal={sig}"
        return f"killed_by={signal_name}"
    return f"exit_status_raw={int(status)}"


def _join_root_process_group() -> None:
    """Make the outer timeout child the leader of its disposable process group."""
    pid = os.getpid()
    try:
        os.setpgid(0, 0)
    except OSError:
        if os.getpgrp() != pid:
            raise


def _terminate_child(pid: int, *, owns_process_group: bool) -> None:
    """Kill a direct child and, for an outer timeout, every descendant group member."""
    if owns_process_group:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)


def _configure_child_stack_dump() -> None:
    """Enable optional repeated stack dumps inside a timeout child."""
    stack_dump_raw = os.environ.get("INERTIA_FORK_STACK_DUMP_SEC", "").strip()
    if not stack_dump_raw:
        return
    with contextlib.suppress(Exception):
        stack_dump_sec = max(1, int(float(stack_dump_raw)))
        stack_dump_file = _faulthandler_output_file()
        if stack_dump_file is not None:
            faulthandler.enable(file=stack_dump_file, all_threads=True)
            faulthandler.dump_traceback_later(stack_dump_sec, repeat=True, file=stack_dump_file)


def _run_child[ResultT](func: Callable[[], ResultT], write_fd: int, read_fd: int, *, owns_process_group: bool) -> typing.NoReturn:
    """Execute and report one callable from the fork child."""
    global _ROOT_PROCESS_GROUP

    try:
        if owns_process_group:
            _join_root_process_group()
            _ROOT_PROCESS_GROUP = os.getpid()
        os.close(read_fd)
        _configure_child_stack_dump()
        try:
            result = _ForkResult(kind=_ForkResultKind.OK, value=func())
        except BaseException as ex:
            result = _ForkResult(
                kind=_ForkResultKind.ERROR,
                error_type=type(ex).__name__,
                error_detail=str(ex) + "\n" + traceback.format_exc(),
            )
        try:
            _write_result(write_fd, result)
        except BaseException as ex:
            fallback = _ForkResult(
                kind=_ForkResultKind.ERROR,
                error_type=type(ex).__name__,
                error_detail=f"fork result is not pickleable: {ex}",
            )
            _write_result(write_fd, fallback)
    finally:
        with contextlib.suppress(OSError):
            os.close(write_fd)
        os._exit(0)


def _fail_incomplete_child_8616(
    pid: int,
    owns_process_group: bool,
    deadline: float,
    timeout: int,
    render_error: Callable[[int], str],
) -> typing.NoReturn:
    """Terminate a child that produced a truncated frame and raise its failure."""
    timed_out = time.monotonic() >= deadline
    _terminate_child(pid, owns_process_group=owns_process_group)
    _waited_pid, child_status = os.waitpid(pid, 0)
    if timed_out:
        raise TimeoutError(f"Timed out after {timeout}s (child {_child_exit_detail(child_status)}).")
    raise ForkChildExitError(render_error(child_status), child_status)


def _read_result_frame_8616(
    read_fd: int,
    pid: int,
    owns_process_group: bool,
    deadline: float,
    timeout: int,
) -> tuple[bytes, int]:
    """Read the child's framed result payload and reap it."""
    header = _read_exact(read_fd, 8, deadline=deadline)
    if len(header) != 8:
        _fail_incomplete_child_8616(
            pid,
            owns_process_group,
            deadline,
            timeout,
            lambda status: f"fork child exited without result ({_child_exit_detail(status)})",
        )
    expected = int.from_bytes(header, "little")
    framed_data = _read_exact(read_fd, expected, deadline=deadline)
    if len(framed_data) != expected:
        _fail_incomplete_child_8616(
            pid,
            owns_process_group,
            deadline,
            timeout,
            lambda status: (
                "fork child returned incomplete result "
                f"(expected={expected}B got={len(framed_data)}B {_child_exit_detail(status)})"
            ),
        )
    _waited_pid, child_status = os.waitpid(pid, 0)
    return framed_data, child_status


def _decode_fork_result_8616(
    framed_data: bytes,
    child_status: int,
    timeout: int,
) -> object:
    """Decode the child's framed result, re-raising its typed failure."""
    result = pickle.loads(framed_data)
    if not isinstance(result, _ForkResult):
        raise RuntimeError(
            f"fork child returned invalid payload ({_child_exit_detail(child_status)})"
        )
    if result.kind is _ForkResultKind.OK:
        return result.value
    if result.error_type in {"TimeoutError", "AnalysisTimeout"}:
        raise TimeoutError(result.error_detail or f"Timed out after {timeout}s.")
    raise RuntimeError(
        f"{result.error_type}: {result.error_detail} ({_child_exit_detail(child_status)})"
    )


def run_with_timeout_in_fork[ResultT](
    func: Callable[[], ResultT],
    *,
    timeout: int,
) -> ResultT:
    """Run a callable in a bounded POSIX process tree and reap all descendants."""
    if os.name != "posix" or not hasattr(os, "fork"):
        raise RuntimeError("fork unavailable")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("fork-only supported from main thread")
    if threading.active_count() != 1:
        raise RuntimeError("fork-only supported without extra live threads")

    owns_process_group = _ROOT_PROCESS_GROUP is None
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        _run_child(func, write_fd, read_fd, owns_process_group=owns_process_group)

    if owns_process_group:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.setpgid(pid, pid)
    os.close(write_fd)
    child_status: int | None = None
    deadline = time.monotonic() + max(1, timeout)
    try:
        framed_data, child_status = _read_result_frame_8616(
            read_fd, pid, owns_process_group, deadline, timeout
        )
        return typing.cast(ResultT, _decode_fork_result_8616(framed_data, child_status, timeout))
    finally:
        with contextlib.suppress(OSError):
            os.close(read_fd)
        if child_status is None:
            _terminate_child(pid, owns_process_group=owns_process_group)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)
        if owns_process_group:
            # The group can outlive its leader when nested work leaked a child.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pid, signal.SIGKILL)


def run_captured_subprocess_tree(
    command: typing.Sequence[str],
    *,
    env: typing.Mapping[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run a captured command and reap its entire process tree on timeout."""
    bounded_timeout = max(1, int(timeout))
    if os.name != "posix":
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=dict(env),
            text=True,
            timeout=bounded_timeout,
        )

    process = subprocess.Popen(
        command,
        env=dict(env),
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=bounded_timeout)
    except subprocess.TimeoutExpired as ex:
        _terminate_child(process.pid, owns_process_group=True)
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            command,
            bounded_timeout,
            output=stdout,
            stderr=stderr,
        ) from ex
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
