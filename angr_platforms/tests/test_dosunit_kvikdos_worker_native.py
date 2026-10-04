"""Layer: Tests.

Responsibility: exercise native snapshots, strict aborts and per-vector reset channels.
"""
from __future__ import annotations

import resource
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from dosunit_kvikdos_test_support import mz_exe

from tools.dosunit import kvikdos_backend as backend
from tools.dosunit.kvikdos_backend import KvikdosBackendError

KVIKDOS_C = Path("/home/xor/kvikdos/kvikdos.c")
requires_kvikdos_c = pytest.mark.skipif(
    not KVIKDOS_C.exists(), reason="embedded wrapper build requires kvikdos.c"
)


pytestmark = pytest.mark.xdist_group("native_kvikdos_worker")


@pytest.fixture(scope="module", autouse=True)
def native_wrapper(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Compile one isolated wrapper for this cohort; every VM still starts fresh."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("DOSUNIT_CACHE_DIR", str(tmp_path_factory.mktemp("native-wrapper")))
        patch.setattr(backend, "_LIB_PATH", None)
        yield


@pytest.mark.requires_kvm
@requires_kvikdos_c
def test_real_libkvikdos_session_via_worker() -> None:
    """Native acceptance hook (parent's run): real wrapper inside the worker.

    Uses the real ``_build_libkvikdos`` build and real worker child; deferred
    while /dev/kvm is absent.
    """
    with backend.KvikdosSession() as session:
        session.run_harness(mz_exe(bytes.fromhex("b8 00 4c cd 21")))
        session.write_memory(0x400, b"\xaa\xbb")
        assert session.read_memory(0x400, 2) == b"\xaa\xbb"
        snap = session.snapshot_create()
        session.write_memory(0x400, b"\x00\x00")
        session.snapshot_restore(snap)
        assert session.read_memory(0x400, 2) == b"\xaa\xbb"
        session.snapshot_destroy(snap)


@pytest.mark.requires_kvm
@requires_kvikdos_c
def test_real_strict_abort_is_contained_and_fresh_session_recovers() -> None:
    """Actual unsupported DOS execution must kill only its isolated worker."""
    with backend.KvikdosSession() as session:
        with pytest.raises(KvikdosBackendError, match="status 252"):
            session.run_harness(mz_exe(bytes.fromhex("cd f0 b8 00 4c cd 21")))
        with pytest.raises(KvikdosBackendError, match="unavailable"):
            session.read_memory(0x400, 1)
    with backend.KvikdosSession() as fresh_session:
        dump = fresh_session.run_harness(mz_exe(bytes.fromhex("b8 00 4c cd 21")))
        assert len(dump) == backend.DOS_MEM_LIMIT


# The native MZ loader places these fixtures at CS=0x0110 (PSP at 0x0100), so
# a byte stored at CS:0x0100 lands at linear 0x1200 in the memory dump.
OBS_LINEAR = 0x1200

# mov ax,a000h; mov ds,ax; mov byte ptr [0],5ah; exit(0). Writes one byte into
# the mapped VGA window [0xA0000, 0xC0000) that reset_emu() never clears.
VIDEO_WRITER = mz_exe(bytes.fromhex("b8 00 a0 8e d8 c6 06 00 00 5a b8 00 4c cd 21"))
# Read A000:0000 into AL, store it at CS:0x0100 via ES=CS, exit(0).
VIDEO_READER = mz_exe(bytes.fromhex(
    "b8 00 a0 8e d8 a0 00 00 0e 07 26 a2 00 01 b8 00 4c cd 21"
))
# Same shape through the environment block at 0064:0000 (ENV_PARA << 4), which
# reset_emu() deliberately preserves for DOS exec() variable reuse.
ENV_WRITER = mz_exe(bytes.fromhex("b8 64 00 8e d8 c6 06 00 00 5a b8 00 4c cd 21"))
ENV_READER = mz_exe(bytes.fromhex(
    "b8 64 00 8e d8 a0 00 00 0e 07 26 a2 00 01 b8 00 4c cd 21"
))
# mov bx,1; mov ah,45h; int 21h; push cs; pop es; mov es:[0100],ax; exit(0).
# DOS dup() of stdout allocates a fresh handle through the process-static
# mapped_handles table without touching filename resolution (filename opens
# would abort anyway: init_parsed_cmd_args leaves dir_state.case_mode
# UNSPECIFIED, so get_linux_filename asserts). Exiting without closing the
# new handle leaks the host fd and keeps the slot occupied.
HANDLE_DUP = mz_exe(bytes.fromhex(
    "bb 01 00 b4 45 cd 21 0e 07 26 a3 00 01 b8 00 4c cd 21"
))


def _dup_handle(session: backend.KvikdosSession) -> int:
    """Run the dup fixture and return the DOS handle the guest observed."""
    dump = session.run_harness(HANDLE_DUP)
    return int.from_bytes(dump[OBS_LINEAR : OBS_LINEAR + 2], "little")


@pytest.mark.requires_kvm
@requires_kvikdos_c
def test_reused_session_overflow_handles_match_first_vector() -> None:
    """Real guest overflow handles must not survive into the next reset vector."""
    # CLD; ES=CS; DI=0100; CX=128; repeat DOS dup(stdout), STOSW; exit.
    # The loop is wholly native; the Python side reads every returned handle.
    program = mz_exe(bytes.fromhex("fc0e07bf0001b98000bb0100b445cd21abe2f6b8004ccd21"))
    with backend.KvikdosSession() as session:
        first = session.run_harness(program)[OBS_LINEAR:OBS_LINEAR + 256]
        second = session.run_harness(program)[OBS_LINEAR:OBS_LINEAR + 256]
    handles = tuple(int.from_bytes(first[i:i + 2], "little") for i in range(0, 256, 2))
    assert handles[:15] == tuple(range(5, 20))
    assert len(set(handles)) == 128, "native dup must succeed for all mapped and overflow handles"
    assert second == first, "native overflow handles survived a vector reset"


@pytest.mark.requires_kvm
@requires_kvikdos_c
def test_overflow_reset_failure_cannot_rearm_a_worker() -> None:
    """Exceed the bounded native ledger and keep both later vectors refused."""
    if resource.getrlimit(resource.RLIMIT_NOFILE)[0] < 4200:
        pytest.skip("native ledger exhaustion control needs 4200 available descriptor slots")
    # 4100 successful native dup calls exceed the 4096-entry ownership ledger.
    # DOS runs normally; uncertain cleanup must refuse every subsequent vector.
    program = mz_exe(bytes.fromhex("b90410bb0100b445cd21e2f7b8004ccd21"))
    exit_program = mz_exe(bytes.fromhex("b8004ccd21"))
    with backend.KvikdosSession() as session:
        session.run_harness(program)
        for _ in range(2):
            with pytest.raises(KvikdosBackendError, match="status 6"):
                session.run_harness(exit_program)
    # A destroyed worker's uncertain descriptors do not poison a fresh process.
    with backend.KvikdosSession() as fresh:
        assert len(fresh.run_harness(exit_program)) == backend.DOS_MEM_LIMIT


@requires_kvikdos_c
def test_failed_close_cannot_close_a_reoccupied_unowned_descriptor(tmp_path: Path) -> None:
    """Compile the real wrapper and preserve a new owner after inconsistent release.

    No VM executes in this control, so it requires the native source/compiler
    but not /dev/kvm. Every acquisition/release uses the generated C helpers.
    """
    wrapper = backend._build_libkvikdos().parent / "libkvikdos_wrapper.c"
    probe = tmp_path / "close_failure.c"
    probe.write_text(f'#include "{wrapper}"\n' + r'''
int main(void) {
    DosVm vm;
    memset(&vm, 0, sizeof(vm));
    init_emu(&vm.emu);
    vm.emu.kvm_fds.kvm_fd = -1;
    vm.emu.kvm_fds.vm_fd = -1;
    vm.emu.kvm_fds.vcpu_fd = -1;
    int fd = dosvm_fd_open("/dev/null", O_RDWR);
    if (fd < 0 || close(fd) != 0) return 2;
    if (dosvm_fd_close(fd) == 0) return 3;
    int replacement = open("/dev/null", O_RDWR);
    if (replacement != fd) return 4;
    DosVmStatus first = dosvm_reset_reused_vm(&vm);
    DosVmStatus second = dosvm_reset_reused_vm(&vm);
    if (first != DOSVM_STATUS_RESET_FAILED || second != DOSVM_STATUS_RESET_FAILED) return 5;
    if (fcntl(replacement, F_GETFD) < 0) return 6;
    return close(replacement) == 0 ? 0 : 7;
}
''')
    executable = tmp_path / "close_failure"
    compiled = subprocess.run(["cc", "-O2", str(probe), "-o", str(executable)],
                              capture_output=True, text=True, check=False, timeout=90)
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=5)
    assert result.returncode == 0, f"native ownership probe exited {result.returncode}: {result.stderr}"


@pytest.mark.requires_kvm
@requires_kvikdos_c
def test_reused_session_video_state_matches_fresh_vector() -> None:
    """Authoritative fixture: a prior vector's video store must not survive."""
    with backend.KvikdosSession() as fresh:
        fresh_dump = fresh.run_harness(VIDEO_READER)
    assert fresh_dump[OBS_LINEAR] == 0
    with backend.KvikdosSession() as reused:
        reused.run_harness(VIDEO_WRITER)
        reused_dump = reused.run_harness(VIDEO_READER)
    assert reused_dump[OBS_LINEAR] == fresh_dump[OBS_LINEAR], (
        "prior vector's video RAM survived reset"
    )
    # [0xFF0, 0xA0000) contains no per-run path state (the DOS env block below
    # it embeds the program pathname, so it is excluded) and must match a
    # fresh worker byte-for-byte after reset.
    assert reused_dump[0xFF0:] == fresh_dump[0xFF0:], (
        "reused-session post-run memory differs from a fresh worker"
    )


@pytest.mark.requires_kvm
@requires_kvikdos_c
def test_repeated_writer_reader_vectors_and_snapshot_contract() -> None:
    """Repeated dirty vectors in one session plus intact snapshot/memory ops."""
    with backend.KvikdosSession() as session:
        for _ in range(3):
            session.run_harness(VIDEO_WRITER)
            assert session.run_harness(VIDEO_READER)[OBS_LINEAR] == 0
        session.write_memory(0x400, b"\xaa\xbb")
        snap = session.snapshot_create()
        session.write_memory(0x400, b"\x00\x00")
        session.snapshot_restore(snap)
        assert session.read_memory(0x400, 2) == b"\xaa\xbb"
        session.snapshot_destroy(snap)
        session.run_harness(VIDEO_WRITER)
        assert session.run_harness(VIDEO_READER)[OBS_LINEAR] == 0


@pytest.mark.requires_kvm
@requires_kvikdos_c
def test_env_block_residue_cleared() -> None:
    """Guest writes into the preserved DOS env block must not cross runs."""
    with backend.KvikdosSession() as fresh:
        expected = fresh.run_harness(ENV_READER)[OBS_LINEAR]
    assert expected == 0
    with backend.KvikdosSession() as reused:
        reused.run_harness(ENV_WRITER)
        assert reused.run_harness(ENV_READER)[OBS_LINEAR] == expected


@pytest.mark.requires_kvm
@requires_kvikdos_c
def test_handle_table_residue_cleared() -> None:
    """A guest leaking a dup'd handle must not shift the next run's handle."""
    with backend.KvikdosSession() as fresh:
        expected = _dup_handle(fresh)
    with backend.KvikdosSession() as reused:
        first = _dup_handle(reused)
        second = _dup_handle(reused)
    assert first == expected
    assert second == expected, "leaked guest handle shifted handle allocation"


@pytest.mark.requires_kvm
@requires_kvikdos_c
@pytest.mark.parametrize("paragraphs", [0, 1, 0x15EA, 0x9F00, 0x9F01, 0xFFFF])
def test_resize_response_matches_independent_native_execution(paragraphs: int) -> None:
    """Run the same INT21 in real KVM, checking metadata and register/flag outputs."""
    from test_real16_program_replay import mz
    from test_real16_program_resize import MCB, POLICY, resize_code

    from tools.dosunit.real16_program_resize import ResizeAccepted, program_resize_call

    # Save EAX/EBX and FLAGS before replacing AX with the termination request.
    code = resize_code(paragraphs)[:-10] + "66a3000266891e04029c58a30802b8004ccd21"
    image = bytearray(mz(bytes.fromhex(code)))
    image[12:14] = b"\xff\xff"
    with backend.KvikdosSession() as session:
        dump = session.run_harness(bytes(image))
    expected = program_resize_call(POLICY, segment=0x100, paragraphs=paragraphs, ax=0x4A01, metadata=MCB)
    assert isinstance(expected, ResizeAccepted)
    assert dump[0xFF0:0x1000] == expected.metadata
    assert int.from_bytes(dump[0x1200:0x1204], "little") == 0x12340000 | expected.ax
    assert int.from_bytes(dump[0x1204:0x1208], "little") == 0xABCD0000 | expected.bx
    assert bool(int.from_bytes(dump[0x1208:0x120A], "little") & 1) is expected.carry
