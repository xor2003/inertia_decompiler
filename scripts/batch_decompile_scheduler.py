#!/usr/bin/env python3
"""Bounded concurrent fork dispatch for focused decompile jobs.

Layer: Tooling/gates.
Responsibility: own bounded parallel dispatch of disposable per-job fork
children, deterministic completion reporting, and interruption cleanup. Each
child speaks the same framed-result IPC protocol, per-job deadline, and
descendant process-group cleanup contract as the serial
``run_with_timeout_in_fork`` dispatch; this module only schedules it
concurrently without changing decompiler semantics.
"""

from __future__ import annotations

import contextlib
import enum
import os
import select
import signal
import threading
import time
import typing
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from inertia_decompiler import fork_timeout as _fork_timeout
from inertia_decompiler.fork_timeout import (
    ForkChildExitError,
    _child_exit_detail,
    _decode_fork_result_8616,
    _run_child,
    _terminate_child,
)

_CHILD_REAP_POLL_SECONDS: float = 0.01


@dataclass(frozen=True, slots=True)
class ScheduledJob[JobT]:
    """One unit of fork-isolated work with its own process budget."""

    name: str
    work: Callable[[], JobT]
    timeout: int


class JobEndKind(enum.Enum):
    """Classify how one dispatched job child settled."""

    COMPLETED = "completed"
    EXITED = "exited"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class JobEnd[JobT]:
    """Terminal outcome for one dispatched job, indexed for ordered reporting."""

    index: int
    kind: JobEndKind
    wall_seconds: float
    value: JobT | None = None
    returncode: int = 0
    detail: str = ""


@dataclass(slots=True)
class _ActiveJob:
    """Track one dispatched child's framed result stream, deadline, and reap state.

    ``reaped`` flips once ``os.waitpid`` collects the child. Cleanup must
    never signal a collected child PID: the kernel is free to reuse it.
    """

    index: int
    pid: int
    read_fd: int
    timeout: int
    owns_group: bool
    start: float
    deadline: float
    buffered: bytearray = field(default_factory=bytearray)
    expected: int | None = None
    reaped: bool = False
    eof: bool = False


def _spawn_job_child[JobT](index: int, job: ScheduledJob[JobT]) -> _ActiveJob:
    """Fork one disposable child running the shared job protocol."""
    owns_group = _fork_timeout._ROOT_PROCESS_GROUP is None
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        _run_child(job.work, write_fd, read_fd, owns_process_group=owns_group)
        raise AssertionError("fork child must never return")
    if owns_group:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            # Establish the child's process group from the parent too so a
            # fast child cannot race group formation during cleanup.
            os.setpgid(pid, pid)
    os.close(write_fd)
    start = time.monotonic()
    return _ActiveJob(
        index=index,
        pid=pid,
        read_fd=read_fd,
        timeout=max(1, job.timeout),
        owns_group=owns_group,
        start=start,
        deadline=start + max(1, job.timeout),
    )


def _frame_complete(child: _ActiveJob) -> bool:
    """Parse the 8-byte length prefix once, then test payload completeness."""
    if child.expected is None:
        if len(child.buffered) < 8:
            return False
        child.expected = int.from_bytes(bytes(child.buffered[:8]), "little")
    return len(child.buffered) >= 8 + child.expected


def _settle_job_child(child: _ActiveJob) -> JobEnd[object] | None:
    """Reap without blocking after frame completion or result-pipe EOF.

    A complete frame is transport evidence, not evidence that the job process
    finished. Likewise EOF may precede the child's actual exit. Keep the child
    active until exit or its original deadline; killing it earlier can mask a
    clean exit with incomplete transport as an ordinary signal-exit result.
    """
    timed_out = time.monotonic() >= child.deadline
    complete = _frame_complete(child)
    waited_pid, status = os.waitpid(child.pid, os.WNOHANG)
    if waited_pid == 0 and not timed_out:
        return None
    deadline_killed = complete and waited_pid == 0 and timed_out
    if waited_pid == 0:
        _terminate_child(child.pid, owns_process_group=child.owns_group)
        _waited_pid, status = os.waitpid(child.pid, 0)
    child.reaped = True
    if child.owns_group:
        with contextlib.suppress(ProcessLookupError):
            # The group can outlive its leader when nested work leaked a child.
            os.killpg(child.pid, signal.SIGKILL)
    wall = time.monotonic() - child.start
    if deadline_killed:
        return JobEnd(
            index=child.index,
            kind=JobEndKind.TIMED_OUT,
            wall_seconds=wall,
            detail=f"Timed out after {child.timeout}s waiting for child exit ({_child_exit_detail(status)}).",
        )
    if complete:
        assert child.expected is not None
        framed = bytes(child.buffered[8 : 8 + child.expected])
        try:
            value = _decode_fork_result_8616(framed, status, child.timeout)
        except TimeoutError as error:
            return JobEnd(index=child.index, kind=JobEndKind.TIMED_OUT, wall_seconds=wall, detail=str(error))
        return JobEnd(index=child.index, kind=JobEndKind.COMPLETED, wall_seconds=wall, value=value)
    detail = _child_exit_detail(status)
    if timed_out:
        return JobEnd(
            index=child.index,
            kind=JobEndKind.TIMED_OUT,
            wall_seconds=wall,
            detail=f"Timed out after {child.timeout}s (child {detail}).",
        )
    returncode = os.waitstatus_to_exitcode(status)
    if child.expected is None:
        message = f"fork child exited without result ({detail})"
    else:
        message = (
            "fork child returned incomplete result "
            f"(expected={child.expected}B got={len(child.buffered) - 8}B {detail})"
        )
    if returncode == 0:
        # A clean exit without its result is transport failure, not success.
        raise ForkChildExitError(message, status)
    return JobEnd(index=child.index, kind=JobEndKind.EXITED, wall_seconds=wall, returncode=returncode, detail=message)


def _abort_active(children: Iterable[_ActiveJob]) -> None:
    """Kill every live dispatched child's process group and reap it.

    Children already collected by the settle path keep their ``reaped``
    mark and are skipped: signaling a reaped PID can hit an unrelated
    process after kernel PID reuse.
    """
    pending = list(children)
    for child in pending:
        with contextlib.suppress(OSError):
            os.close(child.read_fd)
        if not child.reaped:
            _terminate_child(child.pid, owns_process_group=child.owns_group)
    for child in pending:
        if child.reaped:
            continue
        with contextlib.suppress(ChildProcessError):
            _waited_pid, _status = os.waitpid(child.pid, 0)
            child.reaped = True


def _require_single_threaded_parent() -> None:
    """Refuse dispatch from anything but a single-threaded main thread."""
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("bounded dispatch requires the main thread")
    if threading.active_count() != 1:
        raise RuntimeError("bounded dispatch requires a single live thread")


def _drain_ready_fds(active: dict[int, _ActiveJob], ready: Iterable[int]) -> set[int]:
    """Read available framed data and mark children whose streams settled.

    Only real EOF (``b""``) marks a stream settled. A genuine ``os.read``
    failure propagates with its cause so dispatch cleanup aborts the
    remaining children instead of misreporting the child as exited.
    """
    finished: set[int] = set()
    for fd in ready:
        child = active[fd]
        chunk = os.read(fd, 65536)
        if chunk:
            child.buffered.extend(chunk)
        else:
            child.eof = True
        if child.eof or _frame_complete(child):
            finished.add(fd)
    return finished


def _settle_and_report[JobT](
    active: dict[int, _ActiveJob],
    fd: int,
    on_end: Callable[[int, JobEnd[JobT]], None],
) -> None:
    """Reap one settled child and report its outcome with the job index.

    Once the child is reaped it leaves ``active`` even when settling fails
    loudly, so abort cleanup never re-signals the recycled PID. A child
    interrupted before its ``waitpid`` completes stays tracked and is
    still terminated by interruption cleanup.
    """
    child = active[fd]
    try:
        end = typing.cast(JobEnd[JobT] | None, _settle_job_child(child))
    finally:
        if child.reaped:
            del active[fd]
            with contextlib.suppress(OSError):
                os.close(fd)
    if end is not None:
        on_end(child.index, end)


def run_jobs_bounded[JobT](
    jobs: Sequence[ScheduledJob[JobT]],
    *,
    workers: int,
    on_end: Callable[[int, JobEnd[JobT]], None],
) -> None:
    """Dispatch jobs through at most ``workers`` disposable fork children.

    ``on_end`` runs in the parent once per settled job in completion order;
    the reported index preserves deterministic input order for callers. Any
    loud child failure, callback failure, or parent interruption terminates
    every surviving child's process group before propagating.
    """
    if workers < 1:
        raise ValueError("bounded dispatch requires at least one worker")
    _require_single_threaded_parent()
    limit = min(workers, len(jobs))
    active: dict[int, _ActiveJob] = {}
    next_index = 0
    try:
        while next_index < len(jobs) or active:
            while next_index < len(jobs) and len(active) < limit:
                child = _spawn_job_child(next_index, jobs[next_index])
                active[child.read_fd] = child
                next_index += 1
            if not active:
                continue
            settling_fds = {fd for fd, child in active.items() if child.eof or _frame_complete(child)}
            wait_seconds = max(0.0, min(child.deadline for child in active.values()) - time.monotonic())
            if settling_fds:
                wait_seconds = min(wait_seconds, _CHILD_REAP_POLL_SECONDS)
            # Completed and prematurely closed pipes can outlive their result
            # stream's useful data. Poll exit without repeatedly reading EOF.
            read_fds = [fd for fd in active if fd not in settling_fds]
            ready, _, _ = select.select(read_fds, [], [], wait_seconds)
            finished_fds = settling_fds | _drain_ready_fds(active, ready)
            now = time.monotonic()
            finished_fds.update(child.read_fd for child in active.values() if now >= child.deadline)
            for fd in finished_fds:
                _settle_and_report(active, fd, on_end)
    finally:
        _abort_active(active.values())
