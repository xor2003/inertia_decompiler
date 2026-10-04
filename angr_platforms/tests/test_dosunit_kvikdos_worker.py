"""Focused tests for the libkvikdos worker-process isolation stage.

Layer: Tests.
Responsibility: prove the embedded-backend session now runs its VM inside a
dedicated child process, so kvikdos strict aborts (exit 252) surface as
KvikdosBackendError with diagnostics while runner-level result accounting
continues per vector.

The protocol surface is exercised against ``fake_vm_worker.py``, a real child
process speaking the same wire protocol with scripted crash/hang/garbage
modes -- containment is proven by an actual process exit, not by mocks.
Real libkvikdos coverage is marked ``requires_kvm`` and deferred to the
parent's native acceptance run (/dev/kvm absent in this sandbox).
"""
# mypy: disable-error-code="untyped-decorator"

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from dosunit_kvikdos_test_support import mz_exe

from tools.dosunit import kvikdos_backend as backend
from tools.dosunit import kvikdos_vm_worker as vmw

FAKE_WORKER = Path(__file__).with_name("dosunit_kvikdos_fake_worker.py")

KvikdosVmClient = vmw.KvikdosVmClient
KvikdosWorkerError = vmw.KvikdosWorkerError
WorkerState = vmw.WorkerState
KvikdosBackendError = backend.KvikdosBackendError



def _fake_prefix() -> list[str]:
    """Command prefix that runs the scripted fake worker instead of libkvikdos."""
    return [sys.executable, "-u", str(FAKE_WORKER), "--lib", "/dev/null"]


def _fake_spawn(**kwargs: float) -> KvikdosVmClient:
    """Spawn a client bound to the fake worker child."""
    client: KvikdosVmClient = KvikdosVmClient.spawn(
        lib_path=Path("/dev/null"),
        command_prefix=_fake_prefix(),
        request_timeout_s=kwargs.get("request_timeout_s", 5.0),
        run_timeout_s=kwargs.get("run_timeout_s", 5.0),
        startup_timeout_s=kwargs.get("startup_timeout_s", 15.0),
    )
    return client


@pytest.fixture
def fake_session_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route the production backend's worker spawn at the fake child process."""
    monkeypatch.setattr(backend, "_build_libkvikdos", lambda: Path("/dev/null"))
    monkeypatch.setattr(
        backend,
        "_spawn_vm_worker",
        lambda *, lib_path, request_timeout_s, run_timeout_s: _fake_spawn(
            request_timeout_s=request_timeout_s, run_timeout_s=run_timeout_s
        ),
    )


def test_client_successful_ops_and_clean_close(tmp_path: Path) -> None:
    """A healthy worker answers all ops on one stable process, then exits."""
    client = _fake_spawn()
    dump = tmp_path / "fake.dmp"
    try:
        assert client.state is WorkerState.ACTIVE
        pid = client._proc.pid
        reply = client.request("write_memory", linear=0x100, data="aabb")
        assert reply["status"] == 0
        reply = client.request("read_memory", linear=0x100, size=2)
        assert reply["data"] == "aabb"
        snap = client.request("snapshot_create")
        assert snap["handle"]
        client.request("write_memory", linear=0x100, data="0000")
        client.request("snapshot_restore", handle=snap["handle"])
        assert client.request("read_memory", linear=0x100, size=2)["data"] == "aabb"
        client.request("snapshot_destroy", handle=snap["handle"])
        reply = client.request("run_program", prog="/tmp/none.exe", dump=str(dump))
        assert reply["status"] == 0
        assert dump.exists()
        assert client._proc.pid == pid  # same process across all requests
    finally:
        client.close()
    assert client.state is WorkerState.CLOSED
    assert client._proc.poll() == 0
    assert not client.is_alive


def test_client_crash252_surfaces_diagnostic_and_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A strict abort in the child must raise with the stderr diagnostic."""
    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "1")
    client = _fake_spawn()
    try:
        with pytest.raises(KvikdosWorkerError) as excinfo:
            client.request("run_program", prog="/tmp/x.exe", dump="/tmp/x.dmp")
        message = str(excinfo.value)
        assert "status 252" in message
        assert "unsupported int 0xf0" in message
        assert client.state is WorkerState.FAILED
        assert not client.is_alive
    finally:
        client.close()


def test_failed_client_refuses_all_later_ops(monkeypatch: pytest.MonkeyPatch) -> None:
    """After a worker death every later op raises immediately, nothing is
    fabricated: no snapshot state, no silent reset."""
    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "1")
    client = _fake_spawn()
    try:
        snap = client.request("snapshot_create")
        with pytest.raises(KvikdosWorkerError):
            client.request("run_program", prog="/tmp/x.exe", dump="/tmp/x.dmp")
        for op, fields in (
            ("read_memory", {"linear": 0, "size": 1}),
            ("write_memory", {"linear": 0, "data": "00"}),
            ("snapshot_restore", {"handle": snap["handle"]}),
            ("snapshot_destroy", {"handle": snap["handle"]}),
            ("run_program", {"prog": "/tmp/x.exe", "dump": "/tmp/x.dmp"}),
        ):
            with pytest.raises(KvikdosWorkerError, match="worker exited with status 252"):
                client.request(op, timeout_s=None, **fields)
    finally:
        client.close()


def test_client_timeout_kills_hung_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung request must fail bounded and kill the child."""
    monkeypatch.setenv("FAKE_VM_HANG", "1")
    client = _fake_spawn(request_timeout_s=0.5)
    try:
        with pytest.raises(KvikdosWorkerError, match="timed out"):
            client.request("run_program", prog="x.exe", dump="x.dmp", timeout_s=0.5)
        assert client.state is WorkerState.FAILED
        assert not client.is_alive
    finally:
        client.close()


def test_client_malformed_reply_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-JSON reply line is a protocol failure, not data."""
    monkeypatch.setenv("FAKE_VM_GARBAGE", "1")
    client = _fake_spawn()
    try:
        with pytest.raises(KvikdosWorkerError, match="malformed"):
            client.request("read_memory", linear=0, size=1)
        assert client.state is WorkerState.FAILED
    finally:
        client.close()


def test_fresh_session_recovers_after_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A new client after a crash works; only the dead one stays refused."""
    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "1")
    dead = _fake_spawn()
    with pytest.raises(KvikdosWorkerError):
        dead.request("run_program", prog="/tmp/x.exe", dump="/tmp/x.dmp")
    dead.close()
    fresh = _fake_spawn()
    try:
        assert fresh.request("read_memory", linear=0, size=1)["status"] == 0
    finally:
        fresh.close()


def test_session_maps_worker_failure_to_backend_error(
    fake_session_spawn: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KvikdosSession.run_harness raises KvikdosBackendError on worker death and
    keeps refusing subsequent calls on the same session."""
    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "2")
    with backend.KvikdosSession() as session:
        dump = session.run_harness(b"MZ-stub")
        assert dump == b"\xfa" * 256  # first run succeeded
        with pytest.raises(KvikdosBackendError, match="status 252"):
            session.run_harness(b"MZ-stub2")
        with pytest.raises(KvikdosBackendError, match="unavailable"):
            session.read_memory(0, 1)


def test_session_survives_native_status_fault(
    fake_session_spawn: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A nonzero DosVmStatus reply is an error but the worker stays usable."""
    monkeypatch.setenv("FAKE_VM_RUN_STATUS", "3")
    with backend.KvikdosSession() as session:
        with pytest.raises(KvikdosBackendError, match="dosvm_run_program failed with status 3"):
            session.run_harness(b"MZ-stub")
        assert session.read_memory(0x100, 1) == b"\x00"


def test_oneshot_run_isolated_and_recovers(
    fake_session_spawn: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """_run_with_libkvikdos is contained too: crash -> error, next call is a
    fresh worker and succeeds."""
    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "1")
    with pytest.raises(KvikdosBackendError, match="status 252"):
        backend._run_with_libkvikdos(Path("bad.exe"), tmp_path / "bad.dmp")
    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "0")
    assert backend._run_with_libkvikdos(Path("ok.exe"), tmp_path / "ok.dmp") == 0


def test_oneshot_uses_fresh_worker_vm_per_call(
    fake_session_spawn: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Each one-shot run gets its own process and a fresh guest VM, matching
    the original dosunit_kvikdos_run create/run/destroy-per-call contract.

    FAKE_VM_CRASH_AT_RUN=2 would fire on a shared worker's second run; with
    per-call workers each VM only ever sees run #1, so both calls succeed.
    """
    spawned: list[KvikdosVmClient] = []
    inner = backend._spawn_vm_worker

    def recording_spawn(*, lib_path: Path, request_timeout_s: float, run_timeout_s: float) -> KvikdosVmClient:
        client = inner(lib_path=lib_path, request_timeout_s=request_timeout_s, run_timeout_s=run_timeout_s)
        spawned.append(client)
        return client

    monkeypatch.setattr(backend, "_spawn_vm_worker", recording_spawn)
    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "2")
    assert backend._run_with_libkvikdos(Path("a.exe"), tmp_path / "a.dmp") == 0
    assert backend._run_with_libkvikdos(Path("b.exe"), tmp_path / "b.dmp") == 0
    assert len(spawned) == 2
    assert spawned[0]._proc.pid != spawned[1]._proc.pid
    for client in spawned:
        assert not client.is_alive  # every worker closed after its call


def test_snapshot_stale_and_double_destroy_are_refused() -> None:
    """Stale/double-destroy handles are refused, never reach native free, and
    the worker stays usable."""
    client = _fake_spawn()
    try:
        snap = client.request("snapshot_create")["handle"]
        assert client.request("snapshot_destroy", handle=snap)["status"] == 0
        again = client.request("snapshot_destroy", handle=snap)
        assert again["ok"] is False and again["status"] == 5
        stale = client.request("snapshot_restore", handle=snap)
        assert stale["ok"] is False and stale["status"] == 5
        wild = client.request("snapshot_restore", handle=0xDEADBEEF)
        assert wild["ok"] is False and wild["status"] == 5
        wild_destroy = client.request("snapshot_destroy", handle=0xDEADBEEF)
        assert wild_destroy["ok"] is False and wild_destroy["status"] == 5
        # A live snapshot created later is unaffected and the worker survives.
        snap2 = client.request("snapshot_create")["handle"]
        assert snap2 != snap
        client.request("write_memory", linear=0x100, data="aa")
        assert client.request("snapshot_restore", handle=snap2)["status"] == 0
        assert client.request("read_memory", linear=0x100, size=1)["data"] == "00"
        assert client.state is WorkerState.ACTIVE
        assert client.is_alive
    finally:
        client.close()


def test_close_is_idempotent_and_preserves_failure_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    """close() is safe to repeat after clean shutdown AND after failure; a
    failed client keeps its FAILED state and diagnostic detail."""
    client = _fake_spawn()
    client.close()
    client.close()
    assert client.state is WorkerState.CLOSED

    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "1")
    client = _fake_spawn()
    with pytest.raises(KvikdosWorkerError):
        client.request("run_program", prog="/tmp/x.exe", dump="/tmp/x.dmp")
    client.close()
    client.close()
    assert client.state is WorkerState.FAILED
    assert "status 252" in client.failure_detail


def test_oversized_request_refused_without_killing_worker() -> None:
    """A request line over the message bound is refused before any write; the
    healthy worker keeps serving later requests."""
    client = _fake_spawn()
    try:
        too_big = "ab" * (vmw.MAX_MESSAGE_BYTES // 2 + 1)
        with pytest.raises(KvikdosWorkerError, match="exceeds message bound"):
            client.request("write_memory", linear=0, data=too_big)
        assert client.state is WorkerState.ACTIVE
        assert client.request("read_memory", linear=0, size=1)["status"] == 0
    finally:
        client.close()


def test_blocked_request_write_times_out_and_kills_child(monkeypatch: pytest.MonkeyPatch) -> None:
    """A child that handshakes but never reads stdin must not block the
    request write past the deadline; the timeout kills and reaps it."""
    monkeypatch.setenv("FAKE_VM_NEVER_READ", "1")
    client = _fake_spawn(request_timeout_s=0.5)
    try:
        big = "ab" * (512 * 1024)  # ~1 MiB line: under bound, over pipe capacity
        with pytest.raises(KvikdosWorkerError, match="timed out"):
            client.request("write_memory", linear=0, data=big, timeout_s=0.5)
        assert client.state is WorkerState.FAILED
        rc = client._proc.wait(timeout=5)
        assert rc < 0  # killed by signal, already reaped
        assert not client.is_alive
    finally:
        client.close()


def test_out_of_domain_memory_ops_rejected_and_worker_stays_usable() -> None:
    """Range errors must leave the protocol aligned for subsequent requests."""
    client = _fake_spawn()
    try:
        for op, fields in (
            ("read_memory", {"linear": 2**32, "size": 1}),
            ("read_memory", {"linear": 0xA0000, "size": 1}),
            ("read_memory", {"linear": 0x9FFFF, "size": 2}),
            ("write_memory", {"linear": -1, "data": "00"}),
            ("write_memory", {"linear": 2**32, "data": "00"}),
        ):
            with pytest.raises(KvikdosWorkerError, match="rejected"):
                client.request(op, timeout_s=None, **fields)
        assert client.state is WorkerState.ACTIVE
        assert client.request("read_memory", linear=0, size=1)["status"] == 0
    finally:
        client.close()


def test_oversized_reply_line_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reply line over the bound is refused even when the oversized chunk
    already contains its newline -- the bound is checked before JSON parse."""
    monkeypatch.setenv("FAKE_VM_BIG_REPLY", "1")
    client = _fake_spawn()
    try:
        with pytest.raises(KvikdosWorkerError, match="exceeded message bound"):
            client.request("read_memory", linear=0, size=1)
        assert client.state is WorkerState.FAILED
        assert not client.is_alive
    finally:
        client.close()


def test_handshake_rejects_wrong_or_missing_protocol_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ready hello with a wrong or absent protocol version is refused and
    the child process is still cleaned up."""
    clients: list[KvikdosVmClient] = []
    real_init = KvikdosVmClient.__init__

    def spy_init(self: KvikdosVmClient, *, proc: subprocess.Popen[bytes], reply_fd: int,
                 request_timeout_s: float, run_timeout_s: float) -> None:
        real_init(self, proc=proc, reply_fd=reply_fd, request_timeout_s=request_timeout_s,
                  run_timeout_s=run_timeout_s)
        clients.append(self)

    monkeypatch.setattr(KvikdosVmClient, "__init__", spy_init)
    for scripted in ("99", "omit"):
        monkeypatch.setenv("FAKE_VM_HELLO_VERSION", scripted)
        with pytest.raises(KvikdosWorkerError, match="protocol version"):
            KvikdosVmClient.spawn(
                lib_path=Path("/dev/null"),
                command_prefix=_fake_prefix(),
                startup_timeout_s=15.0,
            )
    assert len(clients) == 2
    for client in clients:
        assert client._proc.wait(timeout=5) is not None  # cleaned up
        assert client.state is WorkerState.FAILED
        assert "protocol version" in client.failure_detail


def test_runner_accounts_failure_per_vector(
    fake_session_spawn: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Production runner keeps emitting a result per vector after the crash."""
    import tools.dosunit.runner as runner

    monkeypatch.setattr(runner, "KvikdosSession", backend.KvikdosSession)
    monkeypatch.setattr(runner, "execute_vector", backend.execute_vector)
    monkeypatch.setenv("FAKE_VM_CRASH_AT_RUN", "2")

    vectors = {
        "schema": "dosunit.vectors.v1",
        "vectors": [
            {
                "id": f"v{i}",
                "module": "demo.exe",
                "function": {"name": f"f{i}", "entry": {"cs": "0x0000", "ip": "0x0200", "kind": "near"}},
                "pre": {"regs": {"sp": "0xfffe"}},
                "observe": {"regs": ["ax"]},
            }
            for i in range(3)
        ],
    }
    exe = tmp_path / "demo.exe"
    image = bytearray(0x300)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe.write_bytes(mz_exe(bytes(image)))

    document = runner.record_oracle(vectors, backend="libkvikdos", exe_path=exe)

    assert len(document["results"]) == 3
    for result in document["results"]:
        assert result["status"] == "refused"
        assert result["verdict"]["kind"] == "backend_failure"
        assert result["diagnostics"][0]["reason"] == "backend_error"
    # Vector 0 failed on observation parsing (fake dump), vectors 1/2 carry
    # the contained worker diagnostics.
    assert "status 252" in document["results"][1]["diagnostics"][0]["message"]
    assert "status 252" in document["results"][2]["diagnostics"][0]["message"]
