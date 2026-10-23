"""Address authority grants only bytes proven written on every path."""
from typing import cast

import pytest

from inertia.ir.core import IRAddress, IRInstr, IRValue, MemSpace
from inertia.ir.real16_initial_memory8616 import InvocationInitialMemory8616
from inertia.ir.real16_path_memory8616 import PathMemory8616, path_load_value_8616

pytestmark = pytest.mark.decompiler


def load(memory: PathMemory8616, initial: InvocationInitialMemory8616 | None, base: int = 0x2000) -> int | None:
    """Load a bound two-byte stack span through the memory contract."""
    row = IRInstr("LOAD", IRValue(MemSpace.TMP, name="t1", size=2, source_tmp=1), (IRAddress(MemSpace.SS, (), 0, size=2),), size=2)
    return path_load_value_8616(row, (base, 2), memory, initial)


def test_known_writes_need_no_original_bytes() -> None:
    """Proven writes may be loaded without any initial contents."""
    initial = InvocationInitialMemory8616((), write_ranges=((0x2000, 2),))
    memory = PathMemory8616()
    memory.apply_write(0x2000, 2, b"\x34\x12")
    assert initial.byte_at(0x2000) is None
    assert load(memory, initial) == 0x1234


@pytest.mark.parametrize("defect", ["unwritten", "partial", "unknown", "tainted", "outside", "unbound", "disagree"])
def test_authority_never_creates_content(defect: str) -> None:
    """Unwritten, unknown, tainted or unauthorized bytes cannot become constants."""
    from inertia.ir.real16_path_memory8616 import meet_path_memory_8616
    initial = InvocationInitialMemory8616((), write_ranges=((0x2000, 2),))
    memory = PathMemory8616()
    if defect != "unwritten":
        memory.apply_write(0x2000, 2, b"\x34\x12")
    if defect == "partial":
        del memory.known[0x2001]
    elif defect == "unknown":
        memory.apply_write(0x2000, 1, None)
    elif defect == "tainted":
        memory.taint()
    elif defect == "outside":
        initial = InvocationInitialMemory8616((), write_ranges=((0x3000, 2),))
    elif defect == "unbound":
        initial = None
    elif defect == "disagree":
        memory = meet_path_memory_8616((memory, PathMemory8616()))
    assert load(memory, initial) is None


@pytest.mark.parametrize("ranges", [((0x2000, 0),), ((-1, 2),), ((0x9ffff, 2),), ((True, 2),), ((0x2000, True),), ((0x2000, b"x"),), ((0x2000, 2, 3),), [(0x2000, 2)], ((0x2000, 2),) * 69])
def test_malformed_ranges_refused(ranges: object) -> None:
    """Malformed range declarations are rejected at construction."""
    with pytest.raises(ValueError, match="write_ranges"):
        InvocationInitialMemory8616((), write_ranges=cast(tuple[tuple[int, int], ...], ranges))


def test_mutated_ranges_cannot_retain_authority() -> None:
    """Changed or malformed authority cannot reuse old range permissions."""
    initial = InvocationInitialMemory8616((), write_ranges=((0x2000, 2),))
    memory = PathMemory8616()
    memory.apply_write(0x2000, 2, b"\x34\x12")
    assert load(memory, initial) == 0x1234
    object.__setattr__(initial, "write_ranges", ((0x3000, 2),))
    assert load(memory, initial) is None
    object.__setattr__(initial, "write_ranges", ((0x2000, 0xA0000),))
    assert load(memory, initial) is None


def test_existing_chunks_and_overlap_are_preserved() -> None:
    """Existing initialized chunks and overlapping ranges remain admissible."""
    initial = InvocationInitialMemory8616(((0x2000, b"\x78\x56"),), write_ranges=((0x2000, 2), (0x2000, 3)))
    assert load(PathMemory8616(), initial) == 0x5678
    memory = PathMemory8616()
    memory.apply_write(0x2000, 2, b"\x34\x12")
    assert load(memory, initial) == 0x1234
    assert not initial.permits_write_read(0xA0000)
    assert not initial.permits_write_read(True)


def test_default_empty_ranges_preserve_refusal() -> None:
    """Default construction grants no new address authority."""
    initial = InvocationInitialMemory8616(())
    memory = PathMemory8616()
    memory.apply_write(0x2000, 2, b"\x34\x12")
    assert load(memory, initial) is None
