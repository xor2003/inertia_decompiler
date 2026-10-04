"""Fake kvikdos VM worker for protocol-level isolation tests.

Layer: test fixture (child process; never imported by production code).
Responsibility: speak the exact kvikdos_vm_worker wire protocol
(stdin request lines, ``--reply-fd`` reply lines, ``ready`` handshake) while
simulating the failure modes a real libkvikdos child exhibits:

- ``FAKE_VM_CRASH_AT_RUN=N``: on the Nth ``run_program`` request, write the
  kvikdos strict diagnostic to stderr and ``os._exit(252)``.
- ``FAKE_VM_HANG=1``: ``run_program`` never replies (timeout path).
- ``FAKE_VM_GARBAGE=1``: first request gets a non-JSON reply line.
- ``FAKE_VM_BIG_REPLY=1``: first request gets a single valid JSON reply line
  larger than the 4 MiB message bound.
- ``FAKE_VM_NEVER_READ=1``: after the ready handshake the child sleeps
  forever without reading stdin (blocked-write timeout path).
- ``FAKE_VM_HELLO_VERSION=N`` sends ``version: N`` in the ready handshake;
  ``FAKE_VM_HELLO_VERSION=omit`` sends no version field at all.
- ``FAKE_VM_RUN_STATUS=N`` or ``FAKE_VM_RUN_STATUSES=a,b,c``: ``run_program``
  replies with those DosVmStatus values per run (a survived fault, not a
  crash).

Env is read once at startup so per-spawn behavior is fixed. Normal mode keeps
sparse guest memory and snapshot copies to exercise the full session API;
snapshot handles are minted sequentially and destroyed handles are refused
like the real child's registry.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

PROTOCOL_VERSION = 1
MAX_LINE = 4 * 1024 * 1024
STATUS_BACKEND_ERROR = 5
GUEST_MEM_LIMIT = 0xA0000


def _check_guest_range(linear: int, size: int) -> None:
    """Mirror the real child's transport-domain rejection of bad ranges."""
    if linear < 0 or linear > GUEST_MEM_LIMIT or size < 0 or size > GUEST_MEM_LIMIT - linear:
        raise ValueError("memory range outside guest memory bound")


def _send(out: BinaryIO, message: dict[str, object]) -> None:
    """Write one JSON reply line to the protocol stream."""
    out.write(json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n")
    out.flush()


def _status(api: str, status: int) -> dict[str, object]:
    """Build a status reply mirroring the native DosVmStatus value."""
    return {"ok": status == 0, "status": status, "api": api}


def _num(request: dict[str, object], key: str) -> int:
    """Coerce a request field to int (the fake accepts loose wire types)."""
    value = request.get(key, 0)
    if isinstance(value, (bool, int, float, str)):
        return int(value)
    return 0


class _FakeVm:
    """Scripted VM state: sparse memory, snapshots, and failure modes."""

    def __init__(self) -> None:
        """Read scripted-failure env once; start with empty guest memory."""
        self.crash_at = int(os.environ.get("FAKE_VM_CRASH_AT_RUN", "0"))
        self.hang = os.environ.get("FAKE_VM_HANG") == "1"
        self.garbage = os.environ.get("FAKE_VM_GARBAGE") == "1"
        self.big_reply = os.environ.get("FAKE_VM_BIG_REPLY") == "1"
        self.never_read = os.environ.get("FAKE_VM_NEVER_READ") == "1"
        raw_statuses = os.environ.get("FAKE_VM_RUN_STATUSES")
        self.run_statuses = [int(x) for x in raw_statuses.split(",")] if raw_statuses else []
        self.run_status = int(os.environ.get("FAKE_VM_RUN_STATUS", "0"))
        self.mem: dict[int, int] = {}
        self.snapshots: dict[int, dict[int, int]] = {}
        self.next_handle = 1
        self.run_count = 0
        self.dispatch: dict[str, Callable[[dict[str, object]], dict[str, object]]] = {
            "run_program": self._run_program,
            "snapshot_create": self._snapshot_create,
            "snapshot_restore": self._snapshot_restore,
            "snapshot_destroy": self._snapshot_destroy,
            "read_memory": self._read_memory,
            "write_memory": self._write_memory,
            "shutdown": self._shutdown,
        }

    def _run_program(self, request: dict[str, object]) -> dict[str, object]:
        """Simulate a dosvm run: scriptable crash/hang/status plus dump write."""
        self.run_count += 1
        if self.crash_at and self.run_count == self.crash_at:
            sys.stderr.write("fatal: unsupported int 0xf0 ah:00 cs:0100 ip:0102\n")
            sys.stderr.flush()
            os._exit(252)
        if self.hang:
            time.sleep(3600)
        dump = request.get("dump")
        if isinstance(dump, str) and dump:
            Path(dump).write_bytes(b"\xfa" * 256)
        idx = min(self.run_count - 1, len(self.run_statuses) - 1)
        status = self.run_statuses[idx] if self.run_statuses else self.run_status
        return _status("dosvm_run_program", status)

    def _snapshot_create(self, request: dict[str, object]) -> dict[str, object]:
        """Snapshot sparse guest memory under a fresh handle."""
        self.snapshots[self.next_handle] = dict(self.mem)
        reply = {**_status("dosvm_snapshot_create", 0), "handle": self.next_handle}
        self.next_handle += 1
        return reply

    def _snapshot_restore(self, request: dict[str, object]) -> dict[str, object]:
        """Restore a snapshot by handle; unknown handle is a status-5 fault."""
        handle = _num(request, "handle")
        if handle not in self.snapshots:
            return _status("dosvm_snapshot_restore", 5)
        self.mem.clear()
        self.mem.update(self.snapshots[handle])
        return _status("dosvm_snapshot_restore", 0)

    def _snapshot_destroy(self, request: dict[str, object]) -> dict[str, object]:
        """Release a snapshot handle; absent handles are refused, not freed."""
        if self.snapshots.pop(_num(request, "handle"), None) is None:
            return _status("dosvm_snapshot_destroy", STATUS_BACKEND_ERROR)
        return _status("dosvm_snapshot_destroy", 0)

    def _read_memory(self, request: dict[str, object]) -> dict[str, object]:
        """Return sparse guest memory bytes as hex."""
        linear = _num(request, "linear")
        size = _num(request, "size")
        _check_guest_range(linear, size)
        data = bytes(self.mem.get(linear + i, 0) for i in range(size))
        return {**_status("dosvm_read_memory", 0), "data": data.hex()}

    def _write_memory(self, request: dict[str, object]) -> dict[str, object]:
        """Write hex-encoded bytes into sparse guest memory."""
        linear = _num(request, "linear")
        data = bytes.fromhex(str(request.get("data", "")))
        _check_guest_range(linear, len(data))
        for i, byte in enumerate(data):
            self.mem[linear + i] = byte
        return _status("dosvm_write_memory", 0)

    def _shutdown(self, request: dict[str, object]) -> dict[str, object]:
        """Acknowledge shutdown; main loop exits after sending this reply."""
        return _status("shutdown", 0)


def _scripted_first_reply(vm: _FakeVm, out: BinaryIO) -> bool:
    """Emit the scripted non-standard first reply, if any mode armed one.

    Returns True when a reply was emitted and the caller must skip normal
    request handling for this line.
    """
    if vm.garbage:
        out.write(b"this-is-not-json\n")
        out.flush()
        return True
    if vm.big_reply:
        # Boundary-sized valid JSON line: raw is just over the bound, so
        # the newline arrives in the same read that crosses the limit --
        # this is exactly the accumulation-guard bypass under test.
        prefix = b'{"ok":true,"status":0,"api":"dosvm_read_memory","data":"'
        pad = MAX_LINE + 100 - len(prefix) - 3  # closing '"}\n'
        out.write(prefix + b"aa" * (pad // 2) + b'"}\n')
        out.flush()
        return True
    return False


def _serve_requests(vm: _FakeVm, out: BinaryIO) -> None:
    """Serve request lines from stdin until EOF or a ``shutdown`` request."""
    stdin = sys.stdin.buffer
    first_request = True
    while True:
        line = stdin.readline(MAX_LINE + 1)
        if not line:
            return
        if len(line) > MAX_LINE:
            _send(out, {"ok": False, "error": "request exceeds message bound"})
            return
        if first_request and _scripted_first_reply(vm, out):
            first_request = False
            continue
        first_request = False
        try:
            request = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            _send(out, {"ok": False, "error": f"bad request: {exc}"})
            continue
        handler = vm.dispatch.get(str(request.get("op")))
        try:
            reply = handler(request) if handler is not None else {"ok": False, "error": f"unknown op: {request.get('op')}"}
        except ValueError as exc:
            reply = {"ok": False, "error": f"bad request: {exc}"}
        _send(out, reply)
        if request.get("op") == "shutdown":
            return


def main(argv: list[str]) -> int:
    """Parse --reply-fd, emit the ready handshake, serve request lines."""
    reply_fd = -1
    for idx, arg in enumerate(argv[:-1]):
        if arg == "--reply-fd":
            reply_fd = int(argv[idx + 1])
    if reply_fd < 0:
        sys.stderr.write("fake worker: missing --reply-fd\n")
        return 2
    out = os.fdopen(reply_fd, "wb", buffering=0)
    vm = _FakeVm()

    hello: dict[str, object] = {"type": "ready"}
    raw_version = os.environ.get("FAKE_VM_HELLO_VERSION")
    if raw_version != "omit":
        hello["version"] = int(raw_version) if raw_version else PROTOCOL_VERSION
    _send(out, hello)

    if vm.never_read:
        # Handshake complete, then never service stdin: requests pile up in
        # the pipe until the parent's bounded write gives up.
        time.sleep(3600)

    _serve_requests(vm, out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
