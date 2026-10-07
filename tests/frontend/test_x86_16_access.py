from __future__ import annotations

from inertia.frontend.x86_16.addressing_helpers import resolve_memory_operand_8616
from inertia.ir.core import AddressStatus, MemSpace, SegmentOrigin
from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY
from inertia.frontend.x86_16.regs import sgreg_t

from inertia.frontend.x86_16.access import MODE_READ, MODE_WRITE, DataAccess


class _FakeValue:
    def __init__(self, expression):
        self.expression = expression

    def cast_to(self, ty):
        return _FakeValue(("cast", self.expression, ty))

    def __lshift__(self, count):
        return _FakeValue(("shl", self.expression, count))

    def __rshift__(self, count):
        return _FakeValue(("shr", self.expression, count))

    def __or__(self, other):
        return _FakeValue(("or", self.expression, other.expression))


class _FakeAccess:
    def __init__(self):
        self._inertia_last_resolved_operand = None
        self._inertia_resolved_operands = []
        self._inertia_semantic_access_log = []
        self.reads = []
        self.writes = []

    _record_resolved_operand = DataAccess._record_resolved_operand
    _resolve_memory_operand = DataAccess._resolve_memory_operand
    _resolved_segment_operand = DataAccess._resolved_segment_operand
    _segment_byte_addresses = DataAccess._segment_byte_addresses

    def constant(self, value, _ty):
        return _FakeValue(("constant", value))

    def convert_ss_vaddr(self, addr):
        return ("ss-linear", addr)

    def v2p(self, seg, addr):
        return ("linear", seg, addr)

    def read_mem8(self, paddr):
        self.reads.append((8, paddr))
        return _FakeValue(("byte", paddr))

    def read_mem16(self, paddr):
        self.reads.append((16, paddr))
        return ("word", paddr)

    def read_mem32(self, paddr):
        self.reads.append((32, paddr))
        return ("dword", paddr)

    def write_mem8(self, paddr, value):
        self.writes.append((8, paddr, value))

    def write_mem16(self, paddr, value):
        self.writes.append((16, paddr, value))

    def write_mem32(self, paddr, value):
        self.writes.append((32, paddr, value))


class _FakeSimpleExecution:
    _load_real_mode16 = Instruction_ANY._load_real_mode16
    _store_real_mode16 = Instruction_ANY._store_real_mode16

    def __init__(self):
        self.reads = []
        self.writes = []

    def _const16(self, value):
        return value & 0xFFFF

    def _real_mode_linear(self, seg_reg, offset):
        return ("linear", seg_reg, offset)

    def constant(self, value, _ty):
        return value

    def load(self, address, _ty):
        self.reads.append(address)
        return _FakeValue(("byte", address))

    def store(self, value, address):
        self.writes.append((address, value))


def test_segment_access_records_typed_operand_before_flattening():
    access = _FakeAccess()

    result = DataAccess.read_mem16_seg(access, sgreg_t.DS, 0x1234)

    assert isinstance(result, _FakeValue)
    assert access.reads == [
        (8, ("linear", sgreg_t.DS, 0x1234)),
        (8, ("linear", sgreg_t.DS, 0x1235)),
    ]
    assert len(access._inertia_resolved_operands) == 1
    mode, operand = access._inertia_resolved_operands[-1]
    assert mode == MODE_READ
    typed = operand.typed_address()
    assert typed.space is MemSpace.DS
    assert typed.status is AddressStatus.STABLE
    assert typed.segment_origin is SegmentOrigin.PROVEN
    semantic_mode, semantic_address = access._inertia_semantic_access_log[-1]
    assert semantic_mode == MODE_READ
    assert semantic_address.space is MemSpace.DS


def test_ss_access_keeps_stack_space_in_recorded_operand():
    access = _FakeAccess()

    DataAccess.write_mem16_seg(access, sgreg_t.SS, 0x20, 0xABCD)

    assert [write[:2] for write in access.writes] == [
        (8, ("ss-linear", 0x20)),
        (8, ("ss-linear", 0x21)),
    ]
    assert len(access._inertia_resolved_operands) == 1
    mode, operand = access._inertia_resolved_operands[-1]
    assert mode == MODE_WRITE
    assert operand.linear == ("ss-linear", 0x20)
    typed = operand.typed_address()
    assert typed.space is MemSpace.SS
    assert typed.status is AddressStatus.STABLE
    assert typed.segment_origin is SegmentOrigin.PROVEN
    semantic_mode, semantic_address = access._inertia_semantic_access_log[-1]
    assert semantic_mode == MODE_WRITE
    assert semantic_address.space is MemSpace.SS


def test_segment_word_execution_crosses_host_page_without_duplicate_record() -> None:
    access = _FakeAccess()

    DataAccess.read_mem16_seg(access, sgreg_t.DS, 0x0FFF)

    assert access.reads == [
        (8, ("linear", sgreg_t.DS, 0x0FFF)),
        (8, ("linear", sgreg_t.DS, 0x1000)),
    ]
    assert len(access._inertia_resolved_operands) == 1


def test_segmented_wide_execution_wraps_each_16_bit_offset_independently() -> None:
    read_word = _FakeAccess()
    read_dword = _FakeAccess()
    write_word = _FakeAccess()
    write_dword = _FakeAccess()

    DataAccess.read_mem16_seg(read_word, sgreg_t.DS, 0xFFFF)
    DataAccess.read_mem32_seg(read_dword, sgreg_t.DS, 0xFFFE)
    DataAccess.write_mem16_seg(write_word, sgreg_t.DS, 0xFFFF, 0x1234)
    DataAccess.write_mem32_seg(write_dword, sgreg_t.DS, 0xFFFE, 0x12345678)

    assert [address for _size, address in read_word.reads] == [
        ("linear", sgreg_t.DS, 0xFFFF),
        ("linear", sgreg_t.DS, 0x0000),
    ]
    assert [address for _size, address in read_dword.reads] == [
        ("linear", sgreg_t.DS, 0xFFFE),
        ("linear", sgreg_t.DS, 0xFFFF),
        ("linear", sgreg_t.DS, 0x0000),
        ("linear", sgreg_t.DS, 0x0001),
    ]
    assert [address for _size, address, _value in write_word.writes] == [
        ("linear", sgreg_t.DS, 0xFFFF),
        ("linear", sgreg_t.DS, 0x0000),
    ]
    assert [address for _size, address, _value in write_dword.writes] == [
        ("linear", sgreg_t.DS, 0xFFFE),
        ("linear", sgreg_t.DS, 0xFFFF),
        ("linear", sgreg_t.DS, 0x0000),
        ("linear", sgreg_t.DS, 0x0001),
    ]
    assert all(
        len(access._inertia_resolved_operands) == 1
        for access in (read_word, read_dword, write_word, write_dword)
    )


def test_optimized_word_execution_resolves_wrapped_offsets_before_linearization() -> None:
    access = _FakeSimpleExecution()

    access._load_real_mode16("ds", 0xFFFF)
    access._store_real_mode16("ss", 0xFFFF, _FakeValue(("word", 0x1234)))

    assert access.reads == [
        ("linear", "ds", 0xFFFF),
        ("linear", "ds", 0x0000),
    ]
    assert [address for address, _value in access.writes] == [
        ("linear", "ss", 0xFFFF),
        ("linear", "ss", 0x0000),
    ]


def test_resolve_memory_operand_builder_owns_linear_and_typed_policy():
    access = _FakeAccess()

    ds_operand = resolve_memory_operand_8616(access, sgreg_t.DS, 0x100, 16)
    ss_operand = resolve_memory_operand_8616(access, sgreg_t.SS, 0x22, 16)

    assert ds_operand.linear == ("linear", sgreg_t.DS, 0x100)
    assert ds_operand.typed_address().space is MemSpace.DS
    assert ds_operand.typed_address().segment_origin is SegmentOrigin.PROVEN

    assert ss_operand.linear == ("ss-linear", 0x22)
    assert ss_operand.typed_address().space is MemSpace.SS
    assert ss_operand.typed_address().segment_origin is SegmentOrigin.PROVEN
    _segment_byte_addresses = DataAccess._segment_byte_addresses
