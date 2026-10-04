"""Declared file, scratch and read-only observation regression controls."""

from __future__ import annotations

from dataclasses import replace

import pytest
from flat32_replay_test_support import (
    ELF_CODE,
    ESP,
    SCRATCH,
    _elf_image,
    _grant,
    _vector,
)

from tools.dosunit.flat32_memory_permissions import (
    MAX_MAPPED_BYTES,
    MAX_MAPPED_PAGES,
    DeclaredAccess,
    DeclaredRegion,
    MappingOrigin,
    plan_page_grants,
)
from tools.dosunit.flat32_replay import (
    MemoryRange,
    ObservationStatus,
    ReplayAgreement,
    ReplayImage,
    ReplayStatus,
    ReplayVector,
    compare_replays,
    replay,
)
from tools.dosunit.flat32_replay_memory import _check_ranges


def test_observation_of_unmapped_target_is_typed_missing_evidence() -> None:
    """Observing undeclared space neither maps it nor counts as evidence."""
    image = _elf_image([(ELF_CODE, bytes.fromhex("a300004000c3"), 5)])
    # mov [0x400000],eax; ret -- the observation cannot manufacture the page.
    watched = replay(
        image,
        ELF_CODE,
        ReplayVector((("esp", ESP), ("eax", 0x11)), observations=(MemoryRange(0x400000, 4),)),
        instruction_limit=100,
    )
    blind = replay(image, ELF_CODE, ReplayVector((("esp", ESP), ("eax", 0x11))), instruction_limit=100)
    assert watched.status is ReplayStatus.FAULTED
    assert watched.detail == "write_unmapped"
    assert watched.writes == ()
    (observation,) = watched.observations
    assert observation.status is ObservationStatus.UNMAPPED
    assert observation.data == b""
    assert observation.origins == ()
    # Removing the observation changes only the projection, never the guest.
    assert (watched.status, watched.registers, watched.writes, watched.instructions, watched.pages) == (
        blind.status,
        blind.registers,
        blind.writes,
        blind.instructions,
        blind.pages,
    )


def test_missing_observation_keeps_returned_runs_incomplete() -> None:
    """A RETURNED run with uncaptured observation evidence cannot agree."""
    image = _elf_image([(ELF_CODE, bytes.fromhex("b807000000c3"), 5)])
    watched = replay(
        image, ELF_CODE, ReplayVector((("esp", ESP),), observations=(MemoryRange(0x400000, 4),)), instruction_limit=100
    )
    assert watched.status is ReplayStatus.RETURNED
    assert compare_replays(watched, watched) is ReplayAgreement.INCOMPLETE
    complete = replay(image, ELF_CODE, _vector(), instruction_limit=100)
    assert compare_replays(complete, complete) is ReplayAgreement.AGREED
    # Divergent requested ranges are missing evidence on each side too.
    other = replay(
        image, ELF_CODE, ReplayVector((("esp", ESP),), observations=(MemoryRange(0x410000, 4),)), instruction_limit=100
    )
    assert compare_replays(watched, other) is ReplayAgreement.INCOMPLETE
    assert compare_replays(complete, watched) is ReplayAgreement.INCOMPLETE


def test_explicit_scratch_mapping_supplies_guest_access() -> None:
    """Only an explicit VECTOR mapping creates caller scratch storage."""
    image = _elf_image([(ELF_CODE, bytes.fromhex("a300004000c3"), 5)])
    vector = ReplayVector(
        (("esp", ESP), ("eax", 0x11)), mappings=(DeclaredRegion(0x400000, 4, SCRATCH, MappingOrigin.VECTOR),)
    )
    result = replay(image, ELF_CODE, vector, instruction_limit=100)
    assert result.status is ReplayStatus.RETURNED
    assert result.writes == ((0x400000, bytes.fromhex("11000000")),)
    grant = _grant(result, 0x400000)
    assert grant.access == SCRATCH
    assert grant.origins == (MappingOrigin.VECTOR,)
    # Observing declared scratch reads it back and changes nothing else.
    observed = replay(
        image,
        ELF_CODE,
        ReplayVector((("esp", ESP), ("eax", 0x11)), observations=(MemoryRange(0x400000, 4),), mappings=vector.mappings),
        instruction_limit=100,
    )
    (observation,) = observed.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == bytes.fromhex("11000000")
    assert MappingOrigin.VECTOR in observation.origins
    assert (observed.status, observed.registers, observed.writes, observed.instructions, observed.pages) == (
        result.status,
        result.registers,
        result.writes,
        result.instructions,
        result.pages,
    )
    # Scratch is data-only and cannot impersonate a file declaration.
    with pytest.raises(ValueError, match="data-only"):
        replay(
            image,
            ELF_CODE,
            ReplayVector(
                (("esp", ESP),),
                mappings=(
                    DeclaredRegion(0x50000, 4, DeclaredAccess.READ | DeclaredAccess.EXECUTE, MappingOrigin.VECTOR),
                ),
            ),
            instruction_limit=10,
        )
    with pytest.raises(ValueError, match="VECTOR scratch origin"):
        replay(
            image,
            ELF_CODE,
            ReplayVector(
                (("esp", ESP),), mappings=(DeclaredRegion(0x50000, 4, DeclaredAccess.READ, MappingOrigin.FILE),)
            ),
            instruction_limit=10,
        )


def test_byte_patch_requires_declared_mapping() -> None:
    """A patch seeds host bytes only; undeclared targets refuse loudly."""
    image = _elf_image([(ELF_CODE, bytes.fromhex("b807000000c3"), 5)])
    with pytest.raises(ValueError, match="outside declared mapped memory"):
        replay(image, ELF_CODE, ReplayVector((("esp", ESP),), memory=((0x40000, b"\x11"),)), instruction_limit=10)
    # A patch straddling a mapped scratch page and undeclared space refuses.
    with pytest.raises(ValueError, match="outside declared mapped memory"):
        replay(
            image,
            ELF_CODE,
            ReplayVector(
                (("esp", ESP),),
                memory=((0x30FFC, b"\x11" * 8),),
                mappings=(DeclaredRegion(0x31000, 4, SCRATCH, MappingOrigin.VECTOR),),
            ),
            instruction_limit=10,
        )
    # On declared scratch the same patch seeds bytes an observation reads.
    seeded = replay(
        image,
        ELF_CODE,
        ReplayVector(
            (("esp", ESP),),
            memory=((0x31000, b"\x11\x22"),),
            observations=(MemoryRange(0x31000, 2),),
            mappings=(DeclaredRegion(0x31000, 8, SCRATCH, MappingOrigin.VECTOR),),
        ),
        instruction_limit=10,
    )
    assert seeded.status is ReplayStatus.RETURNED
    (observation,) = seeded.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == b"\x11\x22"
    assert MappingOrigin.VECTOR in observation.origins


def _observed_return():
    image = ReplayImage(((0x10000, b"\xc3"),), (MemoryRange(0x10000, 1),))
    vector = ReplayVector(
        (("esp", 0x28000),),
        observations=(MemoryRange(0x40000, 4),),
        mappings=(DeclaredRegion(0x40000, 4, SCRATCH, MappingOrigin.VECTOR),),
    )
    result = replay(image, 0x10000, vector, instruction_limit=10)
    assert result.status is ReplayStatus.RETURNED
    assert compare_replays(result, result) is ReplayAgreement.AGREED
    return result


def test_same_missing_requested_observation_cannot_agree() -> None:
    """A record manifest survives when both sides lose the same output row."""
    result = _observed_return()
    missing = replace(result, observations=())
    assert compare_replays(missing, missing) is ReplayAgreement.INCOMPLETE


def test_truncated_captured_observation_cannot_agree() -> None:
    """CAPTURED alone does not prove that every requested byte was materialized."""
    result = _observed_return()
    observation = replace(result.observations[0], data=b"\0")
    partial = replace(result, observations=(observation,))
    assert compare_replays(partial, partial) is ReplayAgreement.INCOMPLETE


def test_repeated_overlapping_declarations_have_finite_claim_budget() -> None:
    """Repeated one-page declarations cannot bypass the page-work budget."""
    repeated = (DeclaredRegion(0x40000, 1, SCRATCH, MappingOrigin.VECTOR) for _ in range(4 * MAX_MAPPED_PAGES + 1))
    with pytest.raises(ValueError):
        plan_page_grants(repeated)


def test_total_observation_bytes_have_one_budget() -> None:
    """Repeated individually valid projections cannot allocate unbounded output."""
    vector = ReplayVector((("esp", 0x28000),), observations=(MemoryRange(0x40000, MAX_MAPPED_BYTES),) * 2)
    with pytest.raises(ValueError):
        _check_ranges(vector)
