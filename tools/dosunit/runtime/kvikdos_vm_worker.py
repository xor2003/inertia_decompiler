"""Layer: DOS execution backend isolation.

Responsibility: host the in-process libkvikdos VM inside a dedicated child
process so kvikdos strict-mode aborts (``exit(252)`` from its ``fatal:`` path)
cannot terminate the dosunit host, while preserving the session contract:
one stable guest VM, memory read/write, and snapshot create/restore/destroy.

Protocol: parent writes one JSON request object per line on the child's stdin;
the child writes one JSON reply object per line on an inherited reply fd
(``--reply-fd``). The child's stdout is inherited so guest program output keeps
reaching the host stdout exactly as the previous in-process backend did; the
child's stderr is captured by the parent as bounded diagnostics.

Request fields are typed per op. Replies are ``{"ok": true, "status": 0, ...}``
with an op payload, ``{"ok": false, "status": N, "api": name}`` when the native
``dosvm_*`` call returned a nonzero DosVmStatus (the worker stays alive), or
``{"ok": false, "error": msg}`` for worker-level request errors. Process
death, timeouts, and malformed replies are surfaced by the client as
:class:`KvikdosWorkerError`; they are never fabricated into results.
"""

from __future__ import annotations

import ctypes
import json
import os
import select
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Final, NoReturn

PROTOCOL_VERSION: Final[int] = 1
DOS_MEM_LIMIT: Final[int] = 0xA0000
STARTUP_TIMEOUT_S: Final[float] = 60.0
REQUEST_TIMEOUT_S: Final[float] = 30.0
RUN_TIMEOUT_S: Final[float] = 300.0
SHUTDOWN_TIMEOUT_S: Final[float] = 5.0
MAX_MESSAGE_BYTES: Final[int] = 4 * 1024 * 1024
STDERR_TAIL_LIMIT: Final[int] = 64 * 1024
DIAGNOSTIC_TAIL_BYTES: Final[int] = 4096
DOSVM_STATUS_BACKEND_ERROR: Final[int] = 5

_KNOWN_OPS = frozenset(
    {
        "run_program",
        "snapshot_create",
        "snapshot_restore",
        "snapshot_destroy",
        "read_memory",
        "write_memory",
        "shutdown",
    }
)


class WorkerState(Enum):
    """Lifecycle of one worker process attachment."""

    STARTING = "starting"
    ACTIVE = "active"
    FAILED = "failed"
    CLOSED = "closed"


class KvikdosWorkerError(Exception):
    """Worker process failed at the process/protocol boundary.

    Covers worker exit (including kvikdos strict ``exit(252)``), request
    timeouts, malformed replies, and operations attempted after failure or
    close. Never raised for a nonzero native DosVmStatus; those are reported
    as ``{"ok": false, "status": N, "api": ...}`` reply data.
    """


def _decode_tail(chunks: deque[bytes]) -> str:
    """Render the bounded stderr tail as text for diagnostics."""
    if not chunks:
        return ""
    return b"".join(chunks)[-DIAGNOSTIC_TAIL_BYTES:].decode("utf-8", "replace").strip()


class KvikdosVmClient:
    """Parent-side client for one libkvikdos worker process.

    Owns the subprocess, the request pipe, the dedicated reply fd, and a
    bounded stderr drain. A single instance maps to one child VM; once the
    child dies, times out, or sends a malformed reply, the client enters
    ``FAILED`` and every later request raises KvikdosWorkerError carrying the
    recorded failure detail. No VM or snapshot state is fabricated after
    failure.
    """

    def __init__(
        self,
        *,
        proc: subprocess.Popen[bytes],
        reply_fd: int,
        request_timeout_s: float,
        run_timeout_s: float,
    ) -> None:
        """Wrap an already-spawned worker; prefer :meth:`spawn`."""
        self._proc = proc
        self._reply_fd = reply_fd
        self.request_timeout_s = request_timeout_s
        self.run_timeout_s = run_timeout_s
        self.state = WorkerState.STARTING
        self.failure_detail = ""
        self._rx = bytearray()
        self._stderr_chunks: deque[bytes] = deque()
        self._stderr_size = 0
        if self._proc.stdin is not None:
            # Requests are written with os.write under the shared request
            # deadline; a child that stops reading must not block the host.
            os.set_blocking(self._proc.stdin.fileno(), False)
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def spawn(
        cls,
        *,
        lib_path: Path,
        command_prefix: Sequence[str] | None = None,
        startup_timeout_s: float = STARTUP_TIMEOUT_S,
        request_timeout_s: float = REQUEST_TIMEOUT_S,
        run_timeout_s: float = RUN_TIMEOUT_S,
    ) -> KvikdosVmClient:
        """Spawn a worker child, complete the ready handshake, return client.

        ``command_prefix`` defaults to this module run as a script with
        ``--lib``; tests may substitute a fake worker program. ``--reply-fd``
        is appended automatically.
        """
        worker_path = Path(__file__).resolve()
        prefix = list(command_prefix) if command_prefix is not None else [
            sys.executable,
            "-u",
            str(worker_path),
            "--lib",
            str(lib_path),
        ]
        reply_r, reply_w = os.pipe()
        try:
            proc = subprocess.Popen(
                [*prefix, "--reply-fd", str(reply_w)],
                stdin=subprocess.PIPE,
                stdout=None,
                stderr=subprocess.PIPE,
                pass_fds=(reply_w,),
                close_fds=True,
            )
        except OSError as exc:
            os.close(reply_r)
            os.close(reply_w)
            raise KvikdosWorkerError(f"cannot start kvikdos worker: {exc}") from exc
        os.close(reply_w)
        client = cls(
            proc=proc,
            reply_fd=reply_r,
            request_timeout_s=request_timeout_s,
            run_timeout_s=run_timeout_s,
        )
        try:
            hello = client._read_message(time.monotonic() + startup_timeout_s)
        except KvikdosWorkerError:
            client.close()
            raise
        if (
            isinstance(hello, dict)
            and hello.get("type") == "init_error"
        ):
            client._mark_failed(f"worker init failed: {hello.get('error', 'no detail')}")
        elif not isinstance(hello, dict) or hello.get("type") != "ready":
            client._mark_failed(f"malformed worker handshake: {hello!r:.200}")
        elif hello.get("version") != PROTOCOL_VERSION:
            client._mark_failed(
                f"unsupported worker protocol version {hello.get('version')!r} "
                f"(expected {PROTOCOL_VERSION})"
            )
        if client.state is not WorkerState.STARTING:
            client.close()
            raise KvikdosWorkerError(client.failure_detail)
        client.state = WorkerState.ACTIVE
        return client

    @property
    def is_alive(self) -> bool:
        """True while the child process exists."""
        return self._proc.poll() is None

    def close(self) -> None:
        """Shut down the worker and release pipes; safe to call repeatedly."""
        if self.state is WorkerState.ACTIVE:
            with suppress(KvikdosWorkerError):
                self.request("shutdown", timeout_s=SHUTDOWN_TIMEOUT_S)
            if self._proc.poll() is None:
                with suppress(subprocess.TimeoutExpired):
                    self._proc.wait(timeout=SHUTDOWN_TIMEOUT_S)
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=SHUTDOWN_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=SHUTDOWN_TIMEOUT_S)
        for pipe in (self._proc.stdin, self._proc.stderr):
            if pipe is not None:
                pipe.close()
        if self._reply_fd >= 0:
            os.close(self._reply_fd)
            self._reply_fd = -1
        self._stderr_thread.join(timeout=SHUTDOWN_TIMEOUT_S)
        if self.state is not WorkerState.FAILED:
            self.state = WorkerState.CLOSED

    # -- request/reply -----------------------------------------------------

    def request(self, op: str, *, timeout_s: float | None = None, **fields: object) -> dict[str, object]:
        """Send one typed request and return the decoded reply dict.

        Raises KvikdosWorkerError when the session is not ACTIVE, the worker
        died, the request timed out, or the reply was malformed or a
        worker-level ``{"ok": false, "error": ...}``. A nonzero native
        DosVmStatus is returned as reply data (``ok`` false + ``status``).
        """
        if self.state is not WorkerState.ACTIVE:
            detail = self.failure_detail or f"worker is {self.state.value}"
            raise KvikdosWorkerError(f"kvikdos worker unavailable for {op}: {detail}")
        if op not in _KNOWN_OPS:
            raise KvikdosWorkerError(f"unknown kvikdos worker op: {op}")
        payload = {"op": op, **fields}
        line = json.dumps(payload, separators=(",", ":")).encode("ascii") + b"\n"
        if len(line) > MAX_MESSAGE_BYTES:
            # Refuse without killing the worker: nothing was sent, so the
            # child still serves later well-formed requests.
            raise KvikdosWorkerError(
                f"kvikdos worker request {op} exceeds message bound "
                f"({len(line)} > {MAX_MESSAGE_BYTES} bytes)"
            )
        deadline = time.monotonic() + (timeout_s if timeout_s is not None else self.request_timeout_s)
        try:
            self._write_line(line, deadline)
            reply = self._read_message(deadline)
        except (BrokenPipeError, OSError, ValueError) as exc:
            self._fail(f"worker pipe closed during {op}: {exc}")
        if not isinstance(reply, dict) or not isinstance(reply.get("ok"), bool):
            self._fail(f"malformed worker reply to {op}: {reply!r:.200}")
        if reply.get("ok") is False and "status" not in reply:
            raise KvikdosWorkerError(f"kvikdos worker rejected {op}: {reply.get('error', 'no detail')}")
        return reply

    def _write_line(self, line: bytes, deadline: float) -> None:
        """Write one request line without ever blocking past ``deadline``.

        The request pipe is nonblocking; partial writes are retried through
        ``select`` until the shared request deadline, so a child that stops
        reading stdin is killed as a timeout instead of hanging the host in
        ``write``/``flush``.
        """
        stdin = self._proc.stdin
        if stdin is None:
            self._fail("worker stdin pipe is missing")
        fd = stdin.fileno()
        view = memoryview(line)
        while len(view) > 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail("worker request timed out")
            _, writable, _ = select.select([], [fd], [], remaining)
            if not writable:
                self._fail("worker request timed out")
            try:
                sent = os.write(fd, view)
            except BlockingIOError:
                continue
            if sent <= 0:
                self._fail("worker request pipe accepted zero bytes")
            view = view[sent:]

    def _read_message(self, deadline: float) -> object:
        """Read one newline-terminated JSON message from the reply fd."""
        while b"\n" not in self._rx:
            if len(self._rx) > MAX_MESSAGE_BYTES:
                self._fail("worker reply exceeded message bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail("worker request timed out")
            readable, _, _ = select.select([self._reply_fd], [], [], remaining)
            if not readable:
                self._fail("worker request timed out")
            chunk = os.read(self._reply_fd, 65536)
            if not chunk:
                try:
                    rc: int | None = self._proc.wait(timeout=SHUTDOWN_TIMEOUT_S)
                except subprocess.TimeoutExpired:
                    rc = None
                # Once the child is dead its stderr hits EOF; let the drain
                # thread finish so the diagnostic tail is already buffered.
                self._stderr_thread.join(timeout=SHUTDOWN_TIMEOUT_S)
                tail = _decode_tail(self._stderr_chunks)
                if rc is None:
                    self._fail(
                        "worker closed the reply channel without exiting"
                        + (f": {tail}" if tail else "")
                    )
                self._fail(f"worker exited with status {rc}" + (f": {tail}" if tail else ""))
            self._rx += chunk
        raw, sep, rest = self._rx.partition(b"\n")
        if len(raw) + len(sep) > MAX_MESSAGE_BYTES:
            self._fail("worker reply line exceeded message bound")
        self._rx = bytearray(rest)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._fail(f"malformed worker reply line: {exc}; raw={raw[:200]!r}")

    def _fail(self, detail: str) -> NoReturn:
        """Record the failure, mark the client FAILED, kill the child, raise."""
        self.state = WorkerState.FAILED
        self.failure_detail = detail
        if self.is_alive:
            self._proc.kill()
            with suppress(subprocess.TimeoutExpired):
                self._proc.wait(timeout=SHUTDOWN_TIMEOUT_S)
        raise KvikdosWorkerError(detail)

    def _mark_failed(self, detail: str) -> None:
        """Record failure without raising (used during handshake)."""
        self.state = WorkerState.FAILED
        self.failure_detail = detail

    def _drain_stderr(self) -> None:
        """Continuously drain child stderr into a bounded tail buffer."""
        stream = self._proc.stderr
        if stream is None:
            return
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            self._stderr_chunks.append(chunk)
            self._stderr_size += len(chunk)
            while self._stderr_size > STDERR_TAIL_LIMIT and self._stderr_chunks:
                self._stderr_size -= len(self._stderr_chunks.popleft())


# --------------------------------------------------------------------------
# Worker child entry point. Runs only in the spawned subprocess; talks to the
# native dosvm_* API directly (never through the isolated facade) so there is
# no recursion.
# --------------------------------------------------------------------------


def _child_send(out: BinaryIO, message: dict[str, object]) -> None:
    """Write one JSON reply line to the protocol stream."""
    out.write(json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n")


def _child_status(api: str, status: int) -> dict[str, object]:
    """Build a status reply mirroring the native DosVmStatus value."""
    return {"ok": status == 0, "status": int(status), "api": api}


@dataclass(frozen=True)
class _VmApi:
    """Bound ctypes entry points of the dosvm wrapper library."""

    create: Callable[..., int]
    destroy: Callable[..., None]
    run_program: Callable[..., int]
    snap_create: Callable[..., int]
    snap_restore: Callable[..., int]
    snap_destroy: Callable[..., None]
    read_memory: Callable[..., int]
    write_memory: Callable[..., int]


def _parse_child_argv(argv: list[str]) -> tuple[str, int]:
    """Extract ``--lib`` and ``--reply-fd`` values; reject missing arguments."""
    lib_path = ""
    reply_fd = -1
    idx = 0
    while idx < len(argv):
        if argv[idx] == "--lib" and idx + 1 < len(argv):
            lib_path = argv[idx + 1]
            idx += 2
        elif argv[idx] == "--reply-fd" and idx + 1 < len(argv):
            reply_fd = int(argv[idx + 1])
            idx += 2
        else:
            idx += 1
    if not lib_path or reply_fd < 0:
        raise ValueError("kvikdos worker: missing --lib or --reply-fd")
    return lib_path, reply_fd


def _bind_vm_api(lib: ctypes.CDLL) -> _VmApi:
    """Bind and type the wrapper library's dosvm_* entry points."""
    lib.dosvm_create.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    lib.dosvm_create.restype = ctypes.c_int
    lib.dosvm_destroy.argtypes = [ctypes.c_void_p]
    lib.dosvm_destroy.restype = None
    lib.dosvm_run_program.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.dosvm_run_program.restype = ctypes.c_int
    lib.dosvm_snapshot_create.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.dosvm_snapshot_create.restype = ctypes.c_int
    lib.dosvm_snapshot_restore.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.dosvm_snapshot_restore.restype = ctypes.c_int
    lib.dosvm_snapshot_destroy.argtypes = [ctypes.c_void_p]
    lib.dosvm_snapshot_destroy.restype = None
    lib.dosvm_read_memory.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]
    lib.dosvm_read_memory.restype = ctypes.c_int
    lib.dosvm_write_memory.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]
    lib.dosvm_write_memory.restype = ctypes.c_int
    return _VmApi(
        create=lib.dosvm_create,
        destroy=lib.dosvm_destroy,
        run_program=lib.dosvm_run_program,
        snap_create=lib.dosvm_snapshot_create,
        snap_restore=lib.dosvm_snapshot_restore,
        snap_destroy=lib.dosvm_snapshot_destroy,
        read_memory=lib.dosvm_read_memory,
        write_memory=lib.dosvm_write_memory,
    )


@dataclass
class _ChildVmState:
    """One live native VM plus its snapshot handle registry.

    Wire handles are small sequential ints minted by the child; the registry
    is the only path from a wire handle to a native snapshot pointer, so a
    stale or forged handle is refused with ``DOSVM_STATUS_BACKEND_ERROR``
    before it can reach ``dosvm_snapshot_restore``/``dosvm_snapshot_destroy``
    as a wild pointer.
    """

    vm: ctypes.c_void_p
    api: _VmApi
    snapshots: dict[int, int] = field(default_factory=dict)
    next_handle: int = 1


def _child_main(argv: list[str]) -> int:
    """Worker loop: one VM per process, one reply per request line.

    Creates the VM before the ready handshake so startup failures are reported
    as ``init_error``. Serves until a ``shutdown`` request or stdin EOF, then
    destroys the VM and exits 0. A kvikdos strict abort inside a request exits
    this process (252) with the diagnostic on stderr; that is the contained
    failure the parent translates into an exception.
    """
    try:
        lib_path, reply_fd = _parse_child_argv(argv)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    out = os.fdopen(reply_fd, "wb", buffering=0)
    try:
        api = _bind_vm_api(ctypes.CDLL(lib_path))
    except OSError as exc:
        _child_send(out, {"type": "init_error", "error": f"cannot load {lib_path}: {exc}"})
        return 1

    vm = ctypes.c_void_p()
    status = int(api.create(ctypes.byref(vm), None))
    if status != 0 or not vm.value:
        _child_send(out, {"type": "init_error", "error": f"dosvm_create status {status}"})
        return 1
    _child_send(out, {"type": "ready", "version": PROTOCOL_VERSION})

    state = _ChildVmState(vm=vm, api=api)
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline(MAX_MESSAGE_BYTES + 1)
        if not line:
            break
        if len(line) > MAX_MESSAGE_BYTES:
            _child_send(out, {"ok": False, "error": "request exceeds message bound"})
            break
        request: object = None
        try:
            request = json.loads(line.decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("request must be a JSON object")
            reply = _child_dispatch(request, state=state)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, KeyError, TypeError, OSError) as exc:
            reply = {"ok": False, "error": f"bad request: {exc}"}
        _child_send(out, reply)
        if isinstance(request, dict) and request.get("op") == "shutdown":
            break
    api.destroy(vm)
    return 0


def _req_int(request: dict[str, object], key: str) -> int:
    """Return a mandatory int request field; reject other wire types."""
    value = request.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"request field {key!r} must be an int")
    return value


def _req_str(request: dict[str, object], key: str) -> str:
    """Return a mandatory str request field; reject other wire types."""
    value = request.get(key)
    if not isinstance(value, str):
        raise ValueError(f"request field {key!r} must be a string")
    return value


_SNAPSHOT_OPS = frozenset({"snapshot_create", "snapshot_restore", "snapshot_destroy"})


def _child_snapshot_op(request: dict[str, object], *, state: _ChildVmState) -> dict[str, object]:
    """Handle one snapshot op through the handle registry.

    Only handles minted by ``snapshot_create`` and still present in the
    registry ever reach the native API; stale or forged handles are refused
    with ``DOSVM_STATUS_BACKEND_ERROR`` so they cannot become a wild
    ``dosvm_snapshot_destroy`` free or a ``dosvm_snapshot_restore``
    use-after-free.
    """
    op = request.get("op")
    if op == "snapshot_create":
        raw = ctypes.c_void_p()
        status = int(state.api.snap_create(state.vm, ctypes.byref(raw)))
        reply = _child_status("dosvm_snapshot_create", status)
        handle = 0
        if status == 0 and raw.value:
            handle = state.next_handle
            state.next_handle += 1
            state.snapshots[handle] = int(raw.value)
        reply["handle"] = handle
        return reply
    handle = _req_int(request, "handle")
    if op == "snapshot_restore":
        pointer = state.snapshots.get(handle)
        if pointer is None:
            return _child_status("dosvm_snapshot_restore", DOSVM_STATUS_BACKEND_ERROR)
        status = int(state.api.snap_restore(state.vm, ctypes.c_void_p(pointer)))
        return _child_status("dosvm_snapshot_restore", status)
    pointer = state.snapshots.pop(handle, None)
    if pointer is None:
        return _child_status("dosvm_snapshot_destroy", DOSVM_STATUS_BACKEND_ERROR)
    state.api.snap_destroy(ctypes.c_void_p(pointer))
    return _child_status("dosvm_snapshot_destroy", 0)


def _validate_memory_range(linear: int, size: int) -> None:
    """Reject invalid guest ranges before native unsigned-address conversion.

    Python integers must fit the guest domain before ctypes narrows them.
    Match the native half-open range, including an empty range at its end.
    """
    if linear < 0 or linear > DOS_MEM_LIMIT or size < 0 or size > DOS_MEM_LIMIT - linear:
        raise ValueError("memory range outside guest memory bound")


def _child_dispatch(request: dict[str, object], *, state: _ChildVmState) -> dict[str, object]:
    """Dispatch one decoded request to the native VM; returns a reply dict."""
    op = request.get("op")
    if op == "run_program":
        prog = os.fsencode(_req_str(request, "prog"))
        dump = request.get("dump")
        dump_b = os.fsencode(dump) if isinstance(dump, str) and dump else None
        status = int(state.api.run_program(state.vm, prog, dump_b))
        return _child_status("dosvm_run_program", status)
    if op in _SNAPSHOT_OPS:
        return _child_snapshot_op(request, state=state)
    if op == "read_memory":
        linear = _req_int(request, "linear")
        size = _req_int(request, "size")
        _validate_memory_range(linear, size)
        buf = (ctypes.c_ubyte * size)()
        status = int(state.api.read_memory(state.vm, linear, buf, size))
        reply = _child_status("dosvm_read_memory", status)
        if status == 0:
            reply["data"] = bytes(buf).hex()
        return reply
    if op == "write_memory":
        linear = _req_int(request, "linear")
        data = bytes.fromhex(_req_str(request, "data"))
        _validate_memory_range(linear, len(data))
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        status = int(state.api.write_memory(state.vm, linear, buf, len(data)))
        return _child_status("dosvm_write_memory", status)
    if op == "shutdown":
        return {"ok": True, "status": 0, "api": "shutdown"}
    return {"ok": False, "error": f"unknown op: {op}"}


if __name__ == "__main__":
    sys.exit(_child_main(sys.argv[1:]))
