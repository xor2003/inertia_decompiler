"""Declared file, scratch and read-only observation regression controls."""

from __future__ import annotations

from tools.dosunit.tests.flat32_replay_test_support import (
    ELF_CODE,
    ELF_RDATA,
    ELF_RWDATA,
    ESP,
    PE_DATA,
    PE_TEXT,
    SCRATCH,
    _elf_image,
    _file_denied,
    _grant,
    _pe_image,
    _vector,
)

from tools.dosunit.runtime.flat32_memory_permissions import (
    DeclaredAccess,
    DeclaredRegion,
    MappingOrigin,
)
from tools.dosunit.runtime.flat32_replay import (
    MemoryRange,
    ObservationStatus,
    ReplayAgreement,
    ReplayStatus,
    ReplayVector,
    compare_replays,
    replay,
)


def test_elf32_rx_execution_and_rw_store_return() -> None:
    """Positive: ELF PT_LOAD R+X executes; a declared RW segment stores."""
    image = _elf_image(
        [
            (ELF_CODE, bytes.fromhex("b807000000c3"), 5),
            (ELF_RWDATA, bytes(16), 6),
        ]
    )
    result = replay(image, ELF_CODE, _vector(), instruction_limit=100)
    assert result.status is ReplayStatus.RETURNED
    assert dict(result.registers)["eax"] == 7
    assert _grant(result, ELF_CODE).access == (DeclaredAccess.READ | DeclaredAccess.EXECUTE)
    assert MappingOrigin.FILE in _grant(result, ELF_CODE).origins

    stored = _elf_image(
        [
            (ELF_CODE, bytes.fromhex("891d00000300c3"), 5),  # mov [0x30000],ebx
            (ELF_RWDATA, bytes(16), 6),
        ]
    )
    written = replay(stored, ELF_CODE, _vector(ebx=0x11), instruction_limit=100)
    assert written.status is ReplayStatus.RETURNED
    assert written.writes == ((ELF_RWDATA, bytes.fromhex("11000000")),)
    assert _grant(written, ELF_RWDATA).access == (DeclaredAccess.READ | DeclaredAccess.WRITE)


def test_pe32_rx_execution_and_rw_store_return() -> None:
    """Positive: PE .text R+X executes; a declared-writable .data stores."""
    image = _pe_image(
        [
            (b".text\0\0\0", 6, 0x1000, 0x200, 0x60000020, bytes.fromhex("b807000000c3")),
            (b".data\0\0\0", 16, 0x2000, 0x400, 0xC0000040, bytes(16)),
        ]
    )
    result = replay(image, PE_TEXT, _vector(), instruction_limit=100)
    assert result.status is ReplayStatus.RETURNED
    assert dict(result.registers)["eax"] == 7
    assert _grant(result, PE_TEXT).access == (DeclaredAccess.READ | DeclaredAccess.EXECUTE)

    stored = _pe_image(
        [
            (b".text\0\0\0", 7, 0x1000, 0x200, 0x60000020, bytes.fromhex("891d00204000c3")),  # mov [0x402000],ebx
            (b".data\0\0\0", 16, 0x2000, 0x400, 0xC0000040, bytes(16)),
        ]
    )
    written = replay(stored, PE_TEXT, _vector(ebx=0x11), instruction_limit=100)
    assert written.status is ReplayStatus.RETURNED
    assert written.writes == ((PE_DATA, bytes.fromhex("11000000")),)


def test_elf32_readonly_load_denies_store() -> None:
    """Negative: a store into a file-declared read-only PT_LOAD faults."""
    image = _elf_image(
        [
            (ELF_CODE, bytes.fromhex("a100000200891d00000200c3"), 5),
            (ELF_RDATA, b"\x2a" * 16, 4),
        ]
    )
    result = replay(image, ELF_CODE, _vector(ebx=0x11), instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "write_protected"
    assert result.writes == ()
    assert _grant(result, ELF_RDATA).access == DeclaredAccess.READ


def test_elf32_readonly_data_denies_execution() -> None:
    """Negative: control flow into a declared non-executable region faults."""
    # jmp rel32 at 0x10000: 0x10005 + 0xfffb == 0x20000 (R-only data page).
    image = _elf_image(
        [
            (ELF_CODE, bytes.fromhex("e9fbff0000"), 5),
            (ELF_RDATA, b"\xc3" * 16, 4),
        ]
    )
    result = replay(image, ELF_CODE, _vector(), instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "fetch_protected"


def test_pe32_writable_section_denies_execution() -> None:
    """Negative: a declared-writable PE section is not executable."""
    # jmp rel32 at 0x401000: 0x401005 + 0xffb == 0x402000 (.data RW page).
    image = _pe_image(
        [
            (b".text\0\0\0", 5, 0x1000, 0x200, 0x60000020, bytes.fromhex("e9fb0f0000")),
            (b".data\0\0\0", 16, 0x2000, 0x400, 0xC0000040, b"\xc3" * 16),
        ]
    )
    result = replay(image, PE_TEXT, _vector(), instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "fetch_protected"


def test_elf32_noaccess_load_denies_guest_and_vector_roles() -> None:
    """An ELF PT_LOAD with p_flags=0 is an explicit file denial: a guest
    store or load faults and vector scratch/patch/observation requests on
    the shared page cannot widen it."""
    image = _elf_image([(ELF_CODE, bytes.fromhex("891d00000200c3"), 5), (ELF_RDATA, bytes(16), 0)])
    assert _file_denied(image, ELF_RDATA)
    vector = ReplayVector(
        (("esp", ESP), ("ebx", 0x11)),
        memory=((ELF_RDATA + 8, b"\xaa\xbb\xcc\xdd"),),
        observations=(MemoryRange(ELF_RDATA + 8, 4),),
        mappings=(DeclaredRegion(ELF_RDATA + 8, 4, SCRATCH, MappingOrigin.VECTOR),),
    )
    result = replay(image, ELF_CODE, vector, instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "write_protected"
    assert result.writes == ()
    grant = _grant(result, ELF_RDATA)
    assert grant.access == DeclaredAccess.NONE
    assert {MappingOrigin.FILE, MappingOrigin.UNSUPPORTED, MappingOrigin.VECTOR} <= set(grant.origins)
    # The admitted byte patch is seeded host-side without granting access;
    # the observation is a pure host read of the protected mapped bytes.
    (observation,) = result.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == b"\xaa\xbb\xcc\xdd"
    assert (observation.address, observation.size) == (ELF_RDATA + 8, 4)
    assert MappingOrigin.FILE in observation.origins
    assert compare_replays(result, result) is ReplayAgreement.INCOMPLETE

    # The denial is not write-only: a guest load from the page faults too.
    reader = _elf_image([(ELF_CODE, bytes.fromhex("a100000200c3"), 5), (ELF_RDATA, b"\x2a" * 16, 0)])
    read = replay(reader, ELF_CODE, _vector(), instruction_limit=100)
    assert read.status is ReplayStatus.FAULTED
    assert read.detail == "read_protected"


def test_pe32_noaccess_section_denies_guest_and_vector_roles() -> None:
    """A PE section without MEM_READ/WRITE/EXECUTE characteristics is an
    explicit file denial that vector declarations cannot widen."""
    image = _pe_image(
        [
            (b".text\0\0\0", 7, 0x1000, 0x200, 0x60000020, bytes.fromhex("891d00204000c3")),  # mov [0x402000],ebx; ret
            (b".deny\0\0\0", 16, 0x2000, 0x400, 0x40, bytes(16)),
        ]
    )
    assert _file_denied(image, PE_DATA)
    vector = ReplayVector(
        (("esp", ESP), ("ebx", 0x11)),
        memory=((PE_DATA + 8, b"\xaa\xbb\xcc\xdd"),),
        observations=(MemoryRange(PE_DATA + 8, 4),),
        mappings=(DeclaredRegion(PE_DATA + 8, 4, SCRATCH, MappingOrigin.VECTOR),),
    )
    result = replay(image, PE_TEXT, vector, instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "write_protected"
    assert result.writes == ()
    grant = _grant(result, PE_DATA)
    assert grant.access == DeclaredAccess.NONE
    assert {MappingOrigin.FILE, MappingOrigin.VECTOR} <= set(grant.origins)
    (observation,) = result.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == b"\xaa\xbb\xcc\xdd"
    assert MappingOrigin.FILE in observation.origins
    assert compare_replays(result, result) is ReplayAgreement.INCOMPLETE

    reader = _pe_image(
        [
            (b".text\0\0\0", 6, 0x1000, 0x200, 0x60000020, bytes.fromhex("a100204000c3")),  # mov eax,[0x402000]; ret
            (b".deny\0\0\0", 16, 0x2000, 0x400, 0x40, b"\x2a" * 16),
        ]
    )
    read = replay(reader, PE_TEXT, _vector(), instruction_limit=100)
    assert read.status is ReplayStatus.FAULTED
    assert read.detail == "read_protected"
