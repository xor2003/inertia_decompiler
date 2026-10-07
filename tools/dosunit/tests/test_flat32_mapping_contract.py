"""Declared file, scratch and read-only observation regression controls."""

from __future__ import annotations

import pytest
from tools.dosunit.tests.flat32_replay_test_support import (
    ELF_CODE,
    ELF_RDATA,
    ESP,
    SCRATCH,
    _elf_image,
    _grant,
    _vector,
)

from tools.dosunit.runtime.flat32_memory_permissions import (
    MAX_MAPPED_PAGES,
    PAGE_SIZE,
    DeclaredAccess,
    DeclaredRegion,
    MappingOrigin,
    plan_page_grants,
)
from tools.dosunit.runtime.flat32_replay import (
    MemoryRange,
    ObservationStatus,
    ReplayImage,
    ReplayStatus,
    ReplayVector,
    replay,
)


def test_observation_overlap_cannot_widen_file_permissions() -> None:
    """An observation on file-declared read-only bytes keeps the page R."""
    code = bytes.fromhex("a100000200891d00000200c3")
    image = _elf_image([(ELF_CODE, code, 5), (ELF_RDATA, b"\x2a" * 16, 4)])
    observed = ReplayVector((("esp", ESP), ("ebx", 0x11)), observations=(MemoryRange(ELF_RDATA, 4),))
    result = replay(image, ELF_CODE, observed, instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "write_protected"
    grant = _grant(result, ELF_RDATA)
    assert grant.access == DeclaredAccess.READ
    assert MappingOrigin.FILE in grant.origins
    assert MappingOrigin.VECTOR not in grant.origins

    reader = _elf_image([(ELF_CODE, bytes.fromhex("a100000200c3"), 5), (ELF_RDATA, b"\x2a" * 16, 4)])
    read = replay(
        reader,
        ELF_CODE,
        ReplayVector((("esp", ESP),), observations=(MemoryRange(ELF_RDATA, 4),)),
        instruction_limit=100,
    )
    assert read.status is ReplayStatus.RETURNED
    (observation,) = read.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == b"\x2a" * 4
    assert MappingOrigin.FILE in observation.origins


def test_vector_patch_cannot_widen_file_page_or_grant_execution() -> None:
    """A vector patch shares a read-only file page and stays non-executable."""
    # mov eax,[0x20010]; mov [0x20010],ebx; ret -- patch bytes live at 0x20010,
    # inside the file-declared R page that covers 0x20000..0x21000.
    code = bytes.fromhex("a110000200891d10000200c3")
    image = _elf_image([(ELF_CODE, code, 5), (ELF_RDATA, bytes(0x40), 4)])
    vector = ReplayVector(
        (("esp", ESP), ("ebx", 0x22)),
        memory=((ELF_RDATA + 0x10, b"\x33\x44"),),
        observations=(MemoryRange(ELF_RDATA + 0x10, 2),),
    )
    result = replay(image, ELF_CODE, vector, instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "write_protected"
    grant = _grant(result, ELF_RDATA + 0x10)
    assert grant.access == DeclaredAccess.READ
    assert MappingOrigin.FILE in grant.origins
    assert MappingOrigin.VECTOR not in grant.origins

    # Reading the patched bytes through the file-declared R page still works.
    loaded = _elf_image([(ELF_CODE, bytes.fromhex("a110000200c3"), 5), (ELF_RDATA, bytes(0x40), 4)])
    read = replay(
        loaded,
        ELF_CODE,
        ReplayVector((("esp", ESP),), memory=((ELF_RDATA + 0x10, b"\x33\x44\x55\x66"),)),
        instruction_limit=100,
    )
    assert read.status is ReplayStatus.RETURNED
    assert dict(read.registers)["eax"] == 0x66554433

    # A caller-declared scratch page is data only: jumping into it faults.
    jump = _elf_image([(ELF_CODE, bytes.fromhex("e9fbff0100"), 5)])
    # jmp rel32 at 0x10000: 0x10005 + 0x1fffb == 0x30000.
    jumped = replay(
        jump,
        ELF_CODE,
        ReplayVector(
            (("esp", ESP),),
            memory=((0x30000, b"\xc3"),),
            mappings=(DeclaredRegion(0x30000, 1, SCRATCH, MappingOrigin.VECTOR),),
        ),
        instruction_limit=100,
    )
    assert jumped.status is ReplayStatus.FAULTED
    assert jumped.detail == "fetch_protected"
    assert _grant(jumped, 0x30000).access == SCRATCH
    assert MappingOrigin.VECTOR in _grant(jumped, 0x30000).origins


def test_missing_declaration_denies_guest_access() -> None:
    """Bytes CLE loads with no declared access stay mapped but deny access."""
    image = _elf_image([(ELF_CODE, bytes.fromhex("b807000000c3"), 5)])
    file_covered = [region for region in image.declared if region.origin is MappingOrigin.FILE]

    def covered(page: int) -> bool:
        """Whether any file declaration covers part of ``page``."""
        return any(region.address < page + 0x1000 and page < region.address + region.size for region in file_covered)

    synthetic = sorted(address for address, _data in image.chunks if not covered(address // 0x1000 * 0x1000))
    assert synthetic, "expected CLE synthetic backers outside declared regions"
    # mov eax,[synthetic]
    target = synthetic[0]
    probe = _elf_image([(ELF_CODE, bytes.fromhex("a1") + target.to_bytes(4, "little") + b"\xc3", 5)])
    result = replay(probe, ELF_CODE, _vector(), instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "read_protected"
    grant = _grant(result, target)
    assert grant.access == DeclaredAccess.NONE
    assert MappingOrigin.UNSUPPORTED in grant.origins

    # Observing the unsupported bytes is a pure host projection: the page
    # grant is unchanged and the guest load still faults.
    watched = replay(
        probe, ELF_CODE, ReplayVector((("esp", ESP),), observations=(MemoryRange(target, 1),)), instruction_limit=100
    )
    assert watched.status is ReplayStatus.FAULTED
    assert watched.detail == "read_protected"
    watched_grant = _grant(watched, target)
    assert watched_grant.access == DeclaredAccess.NONE
    assert watched_grant.origins == grant.origins
    (observation,) = watched.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert MappingOrigin.UNSUPPORTED in observation.origins

    # A guest store into the observed unsupported page still faults; the
    # observation never created writable memory. Guest outcome and page
    # plan are identical with or without the observation.
    storing = _elf_image([(ELF_CODE, bytes.fromhex("a3") + target.to_bytes(4, "little") + b"\xc3", 5)])
    stored = replay(
        storing,
        ELF_CODE,
        ReplayVector((("esp", ESP), ("ebx", 0x11)), observations=(MemoryRange(target, 1),)),
        instruction_limit=100,
    )
    blind = replay(storing, ELF_CODE, ReplayVector((("esp", ESP), ("ebx", 0x11))), instruction_limit=100)
    assert stored.status is ReplayStatus.FAULTED
    assert stored.detail == "write_protected"
    assert stored.writes == ()
    assert (stored.status, stored.registers, stored.writes, stored.instructions, stored.pages) == (
        blind.status,
        blind.registers,
        blind.writes,
        blind.instructions,
        blind.pages,
    )


def test_undeclared_address_and_page_boundary_faults() -> None:
    """A store with no coverage faults unmapped; a store crossing a declared
    RW page into uncovered space still faults at page granularity."""
    image = _elf_image([(ELF_CODE, bytes.fromhex("a300004000c3"), 5)])
    result = replay(image, ELF_CODE, _vector(), instruction_limit=100)
    assert result.status is ReplayStatus.FAULTED
    assert result.detail == "write_unmapped"

    # A scratch mapping claims page 0x31000 only (4 bytes); a store at
    # 0x31ffe crosses into the undeclared next page and must fault.
    cross = _elf_image([(ELF_CODE, bytes.fromhex("a3fe1f0300c3"), 5)])
    scratch = (DeclaredRegion(0x31000, 4, SCRATCH, MappingOrigin.VECTOR),)
    crossed = replay(cross, ELF_CODE, ReplayVector((("esp", ESP),), mappings=scratch), instruction_limit=100)
    assert crossed.status is ReplayStatus.FAULTED
    assert crossed.detail == "write_unmapped"

    # A store inside the declared scratch page boundary succeeds.
    inside = _elf_image([(ELF_CODE, bytes.fromhex("a3fc1f0300c3"), 5)])
    kept = replay(inside, ELF_CODE, ReplayVector((("esp", ESP),), mappings=scratch), instruction_limit=100)
    assert kept.status is ReplayStatus.RETURNED
    assert kept.writes == ((0x31FFC, bytes(4)),)


def test_stack_and_trap_pages_keep_declared_harness_roles() -> None:
    """The stack window stays RW and the return trap stays executable."""
    image = _elf_image([(ELF_CODE, bytes.fromhex("535bc3"), 5)])  # push/pop/ret
    result = replay(image, ELF_CODE, _vector(ebx=0x1234), instruction_limit=100)
    assert result.status is ReplayStatus.RETURNED
    stack_grant = _grant(result, ESP - 4)
    assert stack_grant.access == (DeclaredAccess.READ | DeclaredAccess.WRITE)
    assert MappingOrigin.STACK in stack_grant.origins
    trap_grant = _grant(result, 0xFFFF0000)
    assert trap_grant.access == DeclaredAccess.EXECUTE
    assert trap_grant.origins == (MappingOrigin.RETURN_TRAP,)


def test_manual_image_executable_contract_bounds_pages() -> None:
    """Two-argument images keep working: executable declares file-level R+X."""
    image = ReplayImage(
        ((0x10000, bytes.fromhex("e8090000004975fda300000300c3b807000000c3")),), (MemoryRange(0x10000, 21),)
    )
    vector = ReplayVector(
        (("eax", 0), ("ecx", 3), ("esp", ESP)),
        (),
        (MemoryRange(0x30000, 4),),
        (DeclaredRegion(0x30000, 4, SCRATCH, MappingOrigin.VECTOR),),
    )
    result = replay(image, 0x10000, vector, instruction_limit=100)
    assert result.status is ReplayStatus.RETURNED
    assert dict(result.registers)["eax"] == 7
    (observation,) = result.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == bytes.fromhex("07000000")
    assert MappingOrigin.VECTOR in observation.origins
    assert _grant(result, 0x10000).access == (DeclaredAccess.READ | DeclaredAccess.EXECUTE)
    assert _grant(result, 0x30000).access == SCRATCH
    # Vector scratch cannot be executed even when declared by the caller.
    jump = ReplayImage(((0x10000, bytes.fromhex("e9fbff0100")),), (MemoryRange(0x10000, 5),))
    jumped = replay(
        jump,
        0x10000,
        ReplayVector((("esp", ESP),), mappings=(DeclaredRegion(0x30000, 1, SCRATCH, MappingOrigin.VECTOR),)),
        instruction_limit=100,
    )
    assert jumped.status is ReplayStatus.FAULTED
    assert jumped.detail == "fetch_protected"


def test_page_plan_resolution_policy() -> None:
    """Unit-level policy: file bounds harness roles; unsupported grants none."""
    plans = plan_page_grants(
        (
            DeclaredRegion(0x20000, 0x10, DeclaredAccess.READ, MappingOrigin.FILE),
            DeclaredRegion(0x20008, 4, DeclaredAccess.READ | DeclaredAccess.WRITE, MappingOrigin.VECTOR),
            DeclaredRegion(0x30000, 4, DeclaredAccess.NONE, MappingOrigin.UNSUPPORTED),
            DeclaredRegion(0x40000, 4, DeclaredAccess.READ | DeclaredAccess.EXECUTE, MappingOrigin.FILE),
            DeclaredRegion(0x40004, 8, DeclaredAccess.WRITE, MappingOrigin.FILE),
            DeclaredRegion(0x50000, 4, DeclaredAccess.READ | DeclaredAccess.WRITE, MappingOrigin.STACK),
            DeclaredRegion(0x60000, 0x10, DeclaredAccess.NONE, MappingOrigin.FILE),
            DeclaredRegion(0x60008, 4, DeclaredAccess.READ | DeclaredAccess.WRITE, MappingOrigin.VECTOR),
        )
    )
    by_page = {grant.address: grant for grant in plans}
    assert by_page[0x20000].access == DeclaredAccess.READ
    assert set(by_page[0x20000].origins) == {MappingOrigin.FILE, MappingOrigin.VECTOR}
    assert by_page[0x30000].access == DeclaredAccess.NONE
    assert by_page[0x40000].access == (DeclaredAccess.READ | DeclaredAccess.WRITE | DeclaredAccess.EXECUTE)
    assert by_page[0x50000].access == (DeclaredAccess.READ | DeclaredAccess.WRITE)
    assert by_page[0x60000].access == DeclaredAccess.NONE
    assert set(by_page[0x60000].origins) == {MappingOrigin.FILE, MappingOrigin.VECTOR}
    with pytest.raises(ValueError):
        plan_page_grants((DeclaredRegion(0x1000, 0, DeclaredAccess.READ, MappingOrigin.FILE),))
    with pytest.raises(ValueError):
        plan_page_grants((DeclaredRegion(0, 2**32, DeclaredAccess.READ, MappingOrigin.FILE),))
    # Intake is bounded before per-page claim allocation: more distinct
    # pages than the 64 MiB budget refuses while claiming, and arbitrarily
    # many overlapping claims on one page still resolve to a single grant.
    with pytest.raises(ValueError, match="64 MiB"):
        plan_page_grants(
            tuple(
                DeclaredRegion(page * PAGE_SIZE, 1, DeclaredAccess.NONE, MappingOrigin.UNSUPPORTED)
                for page in range(MAX_MAPPED_PAGES + 1)
            )
        )
    overlap = plan_page_grants(
        tuple(DeclaredRegion(0x1000, 4, DeclaredAccess.READ, MappingOrigin.FILE) for _ in range(MAX_MAPPED_PAGES + 1))
    )
    assert len(overlap) == 1 and overlap[0].access == DeclaredAccess.READ
