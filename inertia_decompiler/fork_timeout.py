"""Run bounded CLI work in a disposable POSIX process tree.

Layer: CLI/fallback/reporting.
Responsibility: own fork IPC, timeout enforcement, and descendant cleanup for
process-isolated decompiler work without changing decompiler semantics.
"""

from __future__ import annotations

import contextlib
import ctypes
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
_EXPECTED_OWNER_PID: int | None = None
_CHILD_ADMIT_FDS: tuple[int, int, int, int] | None = None
_PR_SET_PDEATHSIG = 1
_ADMISSION_BOUND_SECONDS = 15.0
_GUARDIAN_ADMIT_TOKEN = b"G"


class _GuardianStatus(enum.Enum):
    """One supervision-admission result serialized over the ready pipe."""

    READY = "W"
    GONE = "D"
    FAILED = "F"


def _try_arm_owner_death_guard_8616() -> bool:
    """Arm ``PR_SET_PDEATHSIG`` so this process dies when its owner thread dies.

    Linux-only and best-effort: returns ``False`` on other platforms or when
    ``prctl`` is unavailable. The separately admitted guardian still enforces
    the original deadline and owns group cleanup in that case. The signal is ``SIGKILL`` so an externally killed owner can
    never leave a running worker; nested ``run_with_timeout_in_fork`` children
    arm their own guard against the worker pid, cascading the kill.
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return bool(libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) == 0)
    except (AttributeError, OSError):
        return False


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
        owner_pid = _EXPECTED_OWNER_PID
        armed = _try_arm_owner_death_guard_8616()
        if not armed and sys.platform.startswith("linux"):
            print(
                "fork_timeout: owner-death guard unavailable (prctl failed);"
                " bounded guardian fallback remains",
                file=sys.stderr,
            )
        if armed and owner_pid is not None and os.getppid() != owner_pid:
            # Owner died between fork and arming; prctl does not fire
            # retroactively, so refuse to continue as an orphan.
            os._exit(1)
        if _CHILD_ADMIT_FDS is not None:
            # Supervision admission barrier: run no work until the owner has
            # established the guardian and released the admit byte. EOF means
            # the owner died (its write end closed) or refused admission —
            # either way this worker must never execute the callable.
            admit_read_fd, admit_write_fd, ready_r, ready_w = _CHILD_ADMIT_FDS
            for stray_fd in (admit_write_fd, ready_r, ready_w):
                with contextlib.suppress(OSError):
                    os.close(stray_fd)
            try:
                token = os.read(admit_read_fd, 1)
            except OSError:
                token = b""
            with contextlib.suppress(OSError):
                os.close(admit_read_fd)
            if token != _GUARDIAN_ADMIT_TOKEN:
                os._exit(1)
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


def _guardian_child_8616(
    worker_pid: int, ready_fd: int, deadline_monotonic: float
) -> typing.NoReturn:
    """Supervise one owned worker group until the worker dies or the bound ends.

    The guardian is a sibling of the worker (child of the same owner). It joins
    the worker's disposable process group — pinning the group identity so the
    numeric ``killpg`` target can never be recycled while the guardian lives —
    then opens a ``pidfd`` for the worker (identity-safe death watch) and
    reports a one-byte status on ``ready_fd``: ``W`` watch established, ``D``
    worker/group already gone (nothing to supervise), ``F`` watch could not be
    established on this platform. After ``W`` it waits on the pidfd — readable
    on worker death, immune to descendants inheriting keep-alive fds — or
    until ``deadline_monotonic`` (the same bound the owner enforces, never a
    longer allowance), then SIGKILLs the whole group, which includes itself:
    the sweep finishes atomically and no guardian can linger.
    """
    status = _GuardianStatus.FAILED
    watch_fd = -1
    try:
        os.setpgid(0, worker_pid)
    except OSError:
        status = _GuardianStatus.GONE
    else:
        pidfd_open = os.pidfd_open if hasattr(os, "pidfd_open") else None
        if pidfd_open is None:
            # Non-Linux: no identity watch; supervision degrades to the
            # explicit deadline sweep only.
            status = _GuardianStatus.READY
        else:
            try:
                watch_fd = pidfd_open(worker_pid)
                status = _GuardianStatus.READY
            except ProcessLookupError:
                status = _GuardianStatus.GONE
            except OSError:
                status = _GuardianStatus.FAILED
    with contextlib.suppress(OSError):
        os.write(ready_fd, status.value.encode("ascii"))
    if status != _GuardianStatus.READY:
        os._exit(0)
    try:
        remaining = deadline_monotonic - time.monotonic()
        if remaining > 0:
            if watch_fd >= 0:
                select.select([watch_fd], [], [], remaining)
            else:
                time.sleep(remaining)
        if watch_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(watch_fd)
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(worker_pid, signal.SIGKILL)
    finally:
        os._exit(0)


def _spawn_guardian_8616(
    worker_pid: int, ready_fd: int, stray_fds: tuple[int, ...], deadline: float
) -> int:
    """Fork the sibling supervisor for the root worker's disposable group.

    Propagates ``OSError`` on fork failure — supervision is mandatory for the
    root worker, so the caller must fail admission rather than run unsupervised.
    The guardian keeps only ``ready_fd``; every other inherited fd is closed so
    worker death still shows up as EOF on the result pipe for the owner.
    """
    guardian_pid = os.fork()
    if guardian_pid == 0:
        for stray_fd in stray_fds:
            with contextlib.suppress(OSError):
                os.close(stray_fd)
        _guardian_child_8616(worker_pid, ready_fd, deadline)
    return guardian_pid


def _read_guardian_token_8616(ready_fd: int, *, deadline: float) -> _GuardianStatus:
    """Await the guardian's one-byte supervision status within a hard bound."""
    remaining = max(0.0, min(_ADMISSION_BOUND_SECONDS, deadline - time.monotonic()))
    ready, _, _ = select.select([ready_fd], [], [], remaining)
    if not ready:
        return _GuardianStatus.FAILED
    try:
        token = os.read(ready_fd, 1)
    except OSError:
        return _GuardianStatus.FAILED
    try:
        return _GuardianStatus(token.decode("ascii"))
    except ValueError:
        return _GuardianStatus.FAILED


def _close_suppressed_8616(*fds: int) -> None:
    """Close fds that may already be closed."""
    for fd in fds:
        with contextlib.suppress(OSError):
            os.close(fd)


def _establish_supervision_8616(
    worker_pid: int,
    write_fd: int,
    read_fd: int,
    admit_fds: tuple[int, int],
    ready_fds: tuple[int, int],
    deadline: float,
) -> int | None:
    """Spawn the guardian, await its watch token, then admit the parked worker.

    Returns the guardian pid. On any supervision failure the still-parked
    worker is terminated and reaped, the guardian (if forked) is reaped, and a
    loud ``RuntimeError`` is raised — the callable never runs unsupervised.
    """
    admit_read_fd, admit_write_fd = admit_fds
    ready_read_fd, ready_write_fd = ready_fds
    guardian_pid: int | None = None
    admission_error: OSError | None = None
    try:
        guardian_pid = _spawn_guardian_8616(
            worker_pid,
            ready_write_fd,
            stray_fds=(write_fd, read_fd, admit_read_fd, admit_write_fd, ready_read_fd),
            deadline=deadline,
        )
        # The parent must release its writer before waiting: otherwise a
        # guardian dying before readiness cannot produce EOF on this pipe.
        _close_suppressed_8616(ready_write_fd, admit_read_fd)
        token = _read_guardian_token_8616(ready_read_fd, deadline=deadline)
    except OSError as error:
        admission_error = error
        token = _GuardianStatus.FAILED
    _close_suppressed_8616(ready_write_fd, admit_read_fd)
    if token == _GuardianStatus.READY:
        with contextlib.suppress(OSError):
            os.write(admit_write_fd, _GUARDIAN_ADMIT_TOKEN)
    elif token != _GuardianStatus.GONE:
        # Admission failed: the worker is still parked at the barrier, so no
        # callable code or descendants can exist yet. Terminate and reap it.
        _close_suppressed_8616(admit_write_fd, ready_read_fd, write_fd, read_fd)
        _terminate_child(worker_pid, owns_process_group=True)
        with contextlib.suppress(ChildProcessError):
            os.waitpid(worker_pid, 0)
        if guardian_pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(guardian_pid, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(guardian_pid, 0)
        raise RuntimeError(
            f"fork supervision admission failed (guardian status={token.name})"
        ) from admission_error
    _close_suppressed_8616(admit_write_fd, ready_read_fd)
    return guardian_pid


def _reap_guardian_8616(guardian_pid: int) -> None:
    """Reap the guardian after the worker is reaped; force it if it lingers."""
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        done, _status = os.waitpid(guardian_pid, os.WNOHANG)
        if done == guardian_pid:
            return
        time.sleep(0.01)
    with contextlib.suppress(ProcessLookupError):
        os.kill(guardian_pid, signal.SIGKILL)
    with contextlib.suppress(ChildProcessError):
        os.waitpid(guardian_pid, 0)


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
    admit_fds: tuple[int, int] | None = None
    ready_fds: tuple[int, int] | None = None
    if owns_process_group:
        admit_fds = os.pipe()
        ready_fds = os.pipe()
    global _EXPECTED_OWNER_PID, _CHILD_ADMIT_FDS
    _EXPECTED_OWNER_PID = os.getpid()
    # Root workers park at the admit barrier; nested workers are covered by
    # the root guardian's group sweep, so they must not see the stale fds.
    _CHILD_ADMIT_FDS = (
        (admit_fds[0], admit_fds[1], ready_fds[0], ready_fds[1])
        if owns_process_group and admit_fds is not None and ready_fds is not None
        else None
    )
    pid = os.fork()
    if pid == 0:
        _run_child(func, write_fd, read_fd, owns_process_group=owns_process_group)
    # The child inherited its snapshot at fork; drop the stale parent copy.
    _CHILD_ADMIT_FDS = None

    deadline = time.monotonic() + max(1, timeout)
    guardian_pid: int | None = None
    if owns_process_group:
        assert admit_fds is not None
        assert ready_fds is not None
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.setpgid(pid, pid)
        guardian_pid = _establish_supervision_8616(
            pid, write_fd, read_fd, admit_fds, ready_fds, deadline
        )
    os.close(write_fd)
    child_status: int | None = None
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
            if guardian_pid is not None:
                _reap_guardian_8616(guardian_pid)


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
