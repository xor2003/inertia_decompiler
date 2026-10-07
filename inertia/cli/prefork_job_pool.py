"""Provide a bounded POSIX prefork pool for isolated CLI jobs.

Layer: CLI/fallback/reporting.
Responsibility: start workers from a single-threaded parent, transport typed
job payloads over owned pipes, and expose deterministic batch or thread-safe
single-job dispatch without owning decompiler semantics.
"""

from __future__ import annotations

import contextlib
import os
import pickle
import select
import threading
from collections import deque
from collections.abc import Callable, Iterator
from typing import TypedDict


class _PreforkWorkerRecord(TypedDict):
    """Track one owned prefork worker and its pipe state."""

    pid: int
    job_write: int
    result_read: int
    busy: bool
    alive: bool
    job_id: object | None
    name: str


def _read_framed_pickle(fd: int) -> object:
    """Read one length-prefixed pickle payload from an owned pipe."""
    header = b""
    while len(header) < 8:
        chunk = os.read(fd, 8 - len(header))
        if not chunk:
            return None
        header += chunk
    expected = int.from_bytes(header, "little")
    data = bytearray()
    while len(data) < expected:
        chunk = os.read(fd, min(65_536, expected - len(data)))
        if not chunk:
            return None
        data.extend(chunk)
    return pickle.loads(bytes(data))


def _write_framed_pickle(fd: int, payload: object) -> None:
    """Write one length-prefixed pickle payload to an owned pipe."""
    data = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
    framed_data = len(data).to_bytes(8, "little") + data
    framed_view = memoryview(framed_data)
    written = 0
    while written < len(framed_data):
        chunk_size = os.write(fd, framed_view[written:])
        if chunk_size <= 0:
            raise OSError("prefork pipe write made no progress")
        written += chunk_size


class PreforkJobPool:
    """Manage bounded POSIX workers created before caller threads exist."""

    def __init__(
        self,
        *,
        max_workers: int,
        worker_func: Callable[[object], object],
        name_prefix: str = "prefork",
    ) -> None:
        """Start ``max_workers`` from a single-threaded POSIX parent."""
        if os.name != "posix" or not hasattr(os, "fork"):
            raise RuntimeError("prefork unavailable")
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("prefork must start on main thread")
        if threading.active_count() != 1:
            raise RuntimeError("prefork requires a single-threaded parent")
        self._worker_func = worker_func
        self._workers: list[_PreforkWorkerRecord] = []
        self._closed = False
        self._condition = threading.Condition()
        for index in range(max(1, int(max_workers))):
            self._start_worker(index, name_prefix)

    @property
    def worker_count(self) -> int:
        """Return the number of live workers owned by this pool."""
        with self._condition:
            return sum(worker["alive"] for worker in self._workers)

    def _start_worker(self, index: int, name_prefix: str) -> None:
        """Fork one worker while the constructing parent is single-threaded."""
        job_read, job_write = os.pipe()
        result_read, result_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                for inherited_worker in self._workers:
                    os.close(inherited_worker["job_write"])
                    os.close(inherited_worker["result_read"])
                os.close(job_write)
                os.close(result_read)
                self._worker_loop(job_read, result_write)
            finally:
                with contextlib.suppress(OSError):
                    os.close(job_read)
                with contextlib.suppress(OSError):
                    os.close(result_write)
                os._exit(0)
        os.close(job_read)
        os.close(result_write)
        self._workers.append(
            {
                "pid": pid,
                "job_write": job_write,
                "result_read": result_read,
                "busy": False,
                "alive": True,
                "job_id": None,
                "name": f"{name_prefix}_{index}",
            }
        )

    def _worker_loop(self, job_read: int, result_write: int) -> None:
        """Execute framed requests in one isolated prefork worker."""
        while True:
            job = _read_framed_pickle(job_read)
            if job is None or job == ("shutdown",):
                return
            if not isinstance(job, tuple) or len(job) != 2:
                raise RuntimeError("prefork worker received an invalid request")
            job_id: object = job[0]
            payload: object = job[1]
            try:
                result = self._worker_func(payload)
                response: tuple[object, ...] = (job_id, "ok", result)
            except BaseException as error:
                response = (job_id, "err", type(error).__name__, str(error))
            _write_framed_pickle(result_write, response)

    def _acquire_worker(self, job_id: object) -> _PreforkWorkerRecord:
        """Reserve one live worker for a caller without serializing peers."""
        with self._condition:
            while True:
                if self._closed:
                    raise RuntimeError("prefork pool is closed")
                for worker in self._workers:
                    if worker["alive"] and not worker["busy"]:
                        worker["busy"] = True
                        worker["job_id"] = job_id
                        return worker
                if not any(worker["alive"] for worker in self._workers):
                    raise RuntimeError("prefork pool has no live workers")
                self._condition.wait()

    def _release_worker(self, worker: _PreforkWorkerRecord, *, alive: bool) -> None:
        """Release one worker reservation and wake a waiting caller."""
        with self._condition:
            worker["busy"] = False
            worker["alive"] = alive
            worker["job_id"] = None
            self._condition.notify_all()

    @staticmethod
    def _decode_response(
        worker: _PreforkWorkerRecord,
        expected_job_id: object,
        response: object,
    ) -> object:
        """Validate one worker response and return its typed payload."""
        if not isinstance(response, tuple) or len(response) < 3:
            raise RuntimeError(f"{worker['name']} exited without a valid result")
        if response[0] != expected_job_id:
            raise RuntimeError(
                f"{worker['name']} returned job {response[0]!r}, expected {expected_job_id!r}"
            )
        if response[1] == "ok":
            return response[2]
        detail = response[3] if len(response) > 3 else "unknown worker failure"
        raise RuntimeError(f"{response[2]}: {detail}")

    def run_one(self, job_id: object, payload: object) -> object:
        """Run one job from any caller thread on a prestarted worker."""
        worker = self._acquire_worker(job_id)
        response: object = None
        alive = True
        try:
            _write_framed_pickle(worker["job_write"], (job_id, payload))
            response = _read_framed_pickle(worker["result_read"])
            alive = response is not None
        except OSError:
            alive = False
            raise
        finally:
            self._release_worker(worker, alive=alive)
        return self._decode_response(worker, job_id, response)

    def run_unordered(
        self,
        jobs: list[tuple[object, object]],
        *,
        poll_timeout: float = 0.25,
    ) -> Iterator[tuple[object | None, object]]:
        """Yield completed prefork jobs without imposing submission order."""
        pending = deque(jobs)
        active: dict[int, _PreforkWorkerRecord] = {}

        def _dispatch_available() -> None:
            while pending:
                live_workers = self.worker_count
                if live_workers == 0:
                    raise RuntimeError("prefork pool has no live workers")
                if len(active) >= live_workers:
                    return
                worker = self._acquire_worker(pending[0][0])
                job_id, payload = pending.popleft()
                try:
                    _write_framed_pickle(worker["job_write"], (job_id, payload))
                except OSError:
                    self._release_worker(worker, alive=False)
                    raise
                active[worker["result_read"]] = worker

        _dispatch_available()
        while active:
            ready, _, _ = select.select(tuple(active), (), (), poll_timeout)
            for fd in ready:
                worker = active.pop(fd)
                expected_job_id = worker["job_id"]
                response = _read_framed_pickle(fd)
                self._release_worker(worker, alive=response is not None)
                try:
                    yield expected_job_id, self._decode_response(
                        worker,
                        expected_job_id,
                        response,
                    )
                except RuntimeError as error:
                    yield expected_job_id, error
            _dispatch_available()

    def shutdown(self) -> None:
        """Request worker shutdown, close pipes, and reap child processes."""
        with self._condition:
            if self._closed:
                return
            self._closed = True
            workers = tuple(self._workers)
            self._condition.notify_all()
        for worker in workers:
            if worker["alive"]:
                with contextlib.suppress(Exception):
                    _write_framed_pickle(worker["job_write"], ("shutdown",))
        for worker in workers:
            with contextlib.suppress(OSError):
                os.close(worker["job_write"])
            with contextlib.suppress(OSError):
                os.close(worker["result_read"])
            with contextlib.suppress(Exception):
                os.waitpid(worker["pid"], 0)


__all__ = ["PreforkJobPool"]
