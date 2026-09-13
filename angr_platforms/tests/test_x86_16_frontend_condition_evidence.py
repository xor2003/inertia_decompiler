"""Regression tests for typed branch evidence emitted by the x86-16 frontend."""

from __future__ import annotations

from types import SimpleNamespace

import bitstring
import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR, ConditionSource
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRCondition, IRValue, MemSpace
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY
from angr_platforms.X86_16.lowering.condition_transfer import collect_typed_conditions_from_emulator_8616

CODE_BASE = 0x4000
BYTE_WIDTH = 8


class _ConditionEmulator:
    """Minimal owned test double for the lifter's typed-condition state."""

    def __init__(self) -> None:
        self._inertia_current_block_addr = 0x4000
        self._inertia_last_condition_source: ConditionSource | None = None
        self._last_condition: IRCondition | None = None

    def set_last_condition(self, condition: IRCondition) -> None:
        """Store the latest typed condition."""
        self._last_condition = condition

    def update_eflags_and(self, _lhs: object, _rhs: object) -> None:
        """Accept one logical flag update through the shared EFLAGS owner."""


def test_direct_byte_test_mask_is_classified_before_a_jcc() -> None:
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=b"\xf6\x06\x34\x12\x01\x74\x02"),
        Arch86_16(),
        0x4000,
    )

    assert instruction.simple_semantics == ("test_abs_imm8", 0x1234, 1)


def test_frame_byte_test_mask_is_classified_before_a_jcc() -> None:
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=b"\xf6\x46\xfc\x01\x74\x02"),
        Arch86_16(),
        0x4000,
    )

    assert instruction.simple_semantics == ("test_mem_imm8", ("bp", 0xFFFC, -4), 1)


def test_frame_byte_test_mask_emits_exact_typed_condition(monkeypatch) -> None:
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex("f646fc01740290c3"),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    [condition] = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "zero"
    assert condition.src_insn == CODE_BASE + 4
    assert condition.producer_insn == CODE_BASE
    assert condition.producer_semantics == (
        "test_mem_imm8",
        ("bp", 0xFFFC, -4),
        1,
    )
    assert condition.lhs == IRBinaryValue(
        op="and",
        lhs=IRValue(
            MemSpace.SS,
            name="bp",
            offset=-4,
            size=1,
            expr=("cmp-stack", "bp"),
        ),
        rhs=IRValue(MemSpace.CONST, const=1, size=1, expr=("cmp-imm",)),
        size=1,
    )


@pytest.mark.parametrize(
    ("machine_code", "size", "mask", "branch_op"),
    (
        ("f706b8030002740290c3", 2, 0x0200, "zero"),
        ("f606b80301740290c3", 1, 1, "zero"),
        ("f606b80304750290c3", 1, 4, "nonzero"),
    ),
)
def test_direct_test_full_lift_emits_exact_typed_condition(
    monkeypatch, machine_code: str, size: int, mask: int, branch_op: str,
) -> None:
    """Byte and word TEST must retain masks and branch polarity through lifting."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex(machine_code),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    [condition] = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert isinstance(condition, ConditionIR)
    assert condition.op == branch_op
    assert condition.width_bits == size * 8
    assert condition.src_insn == 0x4004 + size
    assert condition.producer_insn == CODE_BASE
    assert condition.producer_semantics == (f"test_abs_imm{size * 8}", 0x03B8, mask)
    assert condition.lhs == IRBinaryValue(
        op="and",
        lhs=IRValue(
            MemSpace.DS,
            offset=0x03B8,
            size=size,
            expr=("cmp-ds",),
            memory_access_size=size,
            memory_access_insn=0x4000,
        ),
        rhs=IRValue(MemSpace.CONST, const=mask, size=size, expr=("cmp-imm",)),
        size=size,
    )


@pytest.mark.parametrize(
    ("machine_code", "register_name", "register_size", "width_bits", "fallthrough"),
    (
        ("e2fec3", "cx", 2, 16, 0x4002),
        ("67e2fdc3", "ecx", 4, 32, 0x4003),
    ),
)
def test_plain_loop_emits_exact_address_sized_counter_condition(
    monkeypatch,
    machine_code: str,
    register_name: str,
    register_size: int,
    width_bits: int,
    fallthrough: int,
) -> None:
    """LOOP must publish the exact CX or ECX architectural register view."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    arch = Arch86_16()
    pyvex.lift(bytes.fromhex(machine_code), 0x4000, arch, opt_level=0)

    [condition] = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "ne"
    assert condition.lhs == IRValue(
        MemSpace.REG,
        name=register_name,
        offset=arch.get_register_offset(register_name),
        size=register_size,
    )
    assert condition.width_bits == width_bits
    assert condition.rhs == IRValue(
        MemSpace.CONST,
        const=1,
        size=register_size,
    )
    assert condition.producer_semantics == (
        "loop_counter_predecrement",
        register_name,
        1,
    )
    assert condition.source == ("loop",)
    assert condition.src_insn == CODE_BASE
    assert condition.producer_insn == CODE_BASE
    assert condition.taken_target == CODE_BASE
    assert condition.fallthrough_target == fallthrough


def test_inc_ax_before_jne_emits_exact_zero_boundary_condition(monkeypatch) -> None:
    """An unbound input becomes a zero test of AX at the following JCC."""
    monkeypatch.delenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", raising=False)
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex("83c40440750190c3"),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    conditions = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert len(conditions) == 1
    condition = conditions[0]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "nonzero"
    assert condition.lhs == IRValue(
        MemSpace.REG,
        name="ax",
        offset=0,
        size=2,
        expr=("cmp-reg",),
    )
    assert condition.rhs is None
    assert condition.operand_bind_insn == condition.src_insn
    assert condition.producer_insn == CODE_BASE + 3
    assert condition.src_insn == CODE_BASE + 4
    assert condition.producer_semantics == ("inc_reg16", "ax", 1)


@pytest.mark.parametrize(
    ("machine_code", "producer_semantics", "expected_boundary"),
    (
        ("4040750190c3", ("inc_reg16", "ax", 2), 0xFFFE),
        ("4848750190c3", ("dec_reg16", "ax", 2), 2),
    ),
    ids=("two-increments", "two-decrements"),
)
def test_repeated_inc_dec_result_test_preserves_original_value_boundary(
    monkeypatch,
    machine_code: str,
    producer_semantics: tuple[str, str, int],
    expected_boundary: int,
) -> None:
    """A JCC-bound result test agrees with the pre-chain boundary for every word."""
    monkeypatch.delenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", raising=False)
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex(machine_code),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    condition = Instruction_ANY._inertia_module_condition_cache[0x4000][0]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "nonzero"
    assert condition.rhs is None
    assert condition.operand_bind_insn == condition.src_insn
    assert isinstance(condition.lhs, IRValue)
    assert condition.lhs.space is MemSpace.REG
    assert condition.lhs.name == "ax"
    assert condition.producer_insn == CODE_BASE + 1
    assert condition.src_insn == CODE_BASE + 2
    assert condition.producer_semantics == producer_semantics
    kind, _register, count = producer_semantics
    delta = count if kind == "inc_reg16" else -count
    for initial in range(0x10000):
        updated = (initial + delta) & 0xFFFF
        assert (updated != 0) == (initial != expected_boundary), initial


@pytest.mark.parametrize(
    ("machine_code", "expected_op"),
    (
        ("4e79fdc3", "sge"),
        ("4e78fdc3", "slt"),
    ),
    ids=("dec-jns", "dec-js"),
)
def test_dec_sign_branch_uses_signed_predecrement_boundary(
    monkeypatch,
    machine_code: str,
    expected_op: str,
) -> None:
    """DEC sign branches compare the pre-decrement register with one."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    arch = Arch86_16()
    pyvex.lift(bytes.fromhex(machine_code), 0x4000, arch, opt_level=0)

    [condition] = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert isinstance(condition, ConditionIR)
    assert condition.op == expected_op
    assert condition.lhs == IRValue(
        MemSpace.REG,
        name="si",
        offset=arch.get_register_offset("si"),
        size=2,
        expr=("cmp-reg",),
    )
    assert condition.rhs == IRValue(
        MemSpace.CONST,
        const=1,
        size=2,
        expr=("cmp-imm",),
    )
    assert condition.producer_semantics == ("dec_reg16", "si", 1)


def test_register_left_indexed_byte_cmp_emits_explicit_unsigned_condition(
    monkeypatch,
) -> None:
    """CMP AL, [SI+disp16] must not leave a VEX flag-temporary branch."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    arch = Arch86_16()
    machine_code = bytes.fromhex("3a849425730190c3")
    instruction = Instruction_ANY(bitstring.ConstBitStream(bytes=machine_code), arch, 0x4000)
    assert instruction.simple_semantics == (
        "cmp_reg_indexed_abs8",
        "al",
        ("si", 0x2594, 0x2594),
    )

    pyvex.lift(machine_code, 0x4000, arch, opt_level=0)

    [condition] = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "uge"
    assert condition.lhs == IRValue(
        MemSpace.REG,
        name="al",
        offset=arch.get_register_offset("al"),
        size=1,
        expr=("cmp-reg",),
    )
    assert condition.producer_semantics == (
        "cmp_reg_indexed_abs8",
        "al",
        ("si", 0x2594, 0x2594),
    )


def test_byte_register_copy_preserves_direct_load_condition_evidence(monkeypatch) -> None:
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex("a0341288c380fb00750190c3"),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    conditions = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert len(conditions) == 1
    condition = conditions[0]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "ne"
    assert condition.width_bits == BYTE_WIDTH
    assert condition.producer_insn == CODE_BASE + 5
    assert condition.producer_semantics == ("cmp_reg_imm8", "bl", 0)
    assert condition.lhs == IRValue(
        MemSpace.DS,
        offset=0x1234,
        size=1,
        expr=("cmp-ds",),
        memory_access_size=1,
        memory_access_insn=0x4000,
    )
    assert condition.rhs == IRValue(
        MemSpace.CONST,
        const=0,
        size=1,
        expr=("cmp-imm",),
    )


@pytest.mark.parametrize(
    "machine_code",
    (
        bytes.fromhex("a0341288c3fec380fb00750190c3"),
        bytes.fromhex("a0341288e380fb00750190c3"),
    ),
    ids=("incremented-copy", "unknown-high-byte-copy"),
)
def test_byte_register_transform_clears_direct_load_condition_evidence(
    monkeypatch,
    machine_code: bytes,
) -> None:
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        machine_code,
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    condition = Instruction_ANY._inertia_module_condition_cache[0x4000][0]
    assert isinstance(condition, ConditionIR)
    assert isinstance(condition.lhs, IRValue)
    assert condition.lhs.space is MemSpace.REG
    assert condition.lhs.name == "bl"
    assert condition.lhs.size == 1
    assert condition.lhs.memory_access_insn is None


def test_direct_byte_test_mask_emits_exact_typed_access_evidence() -> None:
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4000
    instruction.emu = _ConditionEmulator()
    instruction.simple_semantics = ("test_abs_imm8", 0x1234, 1)
    instruction._load_abs8 = lambda _offset: 5
    instruction.constant = lambda value, _type: value

    assert instruction._lift_simple_test_8616("test_abs_imm8")
    source = instruction.emu._inertia_last_condition_source
    assert isinstance(source, ConditionSource)
    assert source.width_bits == BYTE_WIDTH
    assert source.normalized_lhs == IRBinaryValue(
        op="and",
        lhs=IRValue(
            MemSpace.DS,
            offset=0x1234,
            size=1,
            expr=("cmp-ds",),
            memory_access_size=1,
            memory_access_insn=0x4000,
        ),
        rhs=IRValue(MemSpace.CONST, const=1, size=1, expr=("cmp-imm",)),
        size=1,
    )
    assert instruction.emu._last_condition == IRCondition(
        op="masked_zero",
        args=(source.normalized_lhs.lhs, source.normalized_lhs.rhs),
        expr=("test_abs_imm8",),
    )


def test_dec_jcc_does_not_mutate_disabled_affine_state(monkeypatch) -> None:
    """Publish DEC flags without consulting disabled affine condition state."""
    monkeypatch.delenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", raising=False)
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4000
    instruction.arch = Arch86_16()
    instruction._future_instructions = (SimpleNamespace(simple_semantics=("jne", 0x4000)),)
    flag_inputs = []
    instruction.emu = SimpleNamespace(
        _inertia_current_block_addr=0x4000, update_eflags_dec=flag_inputs.append
    )
    instruction.simple_semantics = ("dec_reg16", "ax")
    instruction._restore_condition_reg_affine_snapshot_8616 = lambda: None
    instruction._reset_condition_reg_value_state_at_block_entry_8616 = lambda: None
    instruction._lift_simple_cmp_8616 = lambda _kind: False
    instruction._lift_simple_test_8616 = lambda _kind: False
    instruction._lift_simple_jcc_8616 = lambda _kind: False
    instruction._get_reg16 = lambda _name: 4
    instruction._const16 = lambda value: value
    instruction._same_preceding_incdec_reg16_count_8616 = lambda _name, mnemonic: 1
    instruction._condition_proven_reg_value_8616 = lambda _name, width_bits: None
    instruction._normalized_reg_imm_condition_operands_8616 = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("disabled affine state was read")
    )
    recorded = []
    instruction._record_test_condition_source = lambda value, **kwargs: recorded.append((value, kwargs))
    instruction.put = lambda _value, _name: None
    instruction._update_condition_reg_affine_offset_8616 = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("disabled affine state was mutated")
    )
    instruction._clear_condition_index_reg_state_8616 = lambda _name: None
    instruction._clear_condition_reg_value_state_8616 = lambda _name: None

    instruction._lift_simple()

    assert recorded == [(3, {
        "normalized_value": IRValue(MemSpace.REG, name="ax", offset=0, size=2, expr=("cmp-reg",)),
        "bind_operand_at_jcc": True,
        "producer_semantics": ("dec_reg16", "ax", 1),
    })]
    assert flag_inputs == [4]


def test_dec_jcc_semantics_keep_typed_register_operands_without_affine_state() -> None:
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.arch = Arch86_16()
    instruction.addr = 0x4001
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x4000)

    operands = instruction._condition_operands_from_cmp_semantics_8616(
        ("dec_reg16", "ax", 1)
    )

    assert operands == (
        IRValue(MemSpace.REG, name="ax", offset=0, size=2, expr=("cmp-reg",)),
        IRValue(MemSpace.CONST, const=1, size=2, expr=("cmp-imm",)),
    )


def test_conditionless_blocks_do_not_force_repeated_condition_relifts() -> None:
    original_cache = Instruction_ANY._inertia_module_condition_cache
    original_pending = Instruction_ANY._inertia_pending_condition_sources_by_addr
    original_affine = Instruction_ANY._inertia_condition_reg_affine_state_8616
    original_snapshots = Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616
    original_index = Instruction_ANY._inertia_condition_index_reg_state_8616
    original_values = Instruction_ANY._inertia_condition_reg_value_state_8616
    fresh = ConditionIR(
        "eq",
        "ax",
        1,
        source=("cmp", "je"),
        src_insn=0x4011,
        block_addr=0x4010,
        taken_target=0x4020,
        fallthrough_target=0x4013,
    )

    def lift_block(block_addr: int, opt_level: int = 0) -> None:
        raise AssertionError(f"unexpected relift of {block_addr:#x} at opt_level={opt_level}")

    terminal = SimpleNamespace(
        address=0x4011,
        size=2,
        mnemonic="je",
        operands=(SimpleNamespace(imm=0x4020),),
    )
    conditional_block = SimpleNamespace(
        addr=0x4010,
        capstone=SimpleNamespace(insns=(SimpleNamespace(insn=terminal),)),
    )
    conditionless_block = SimpleNamespace(
        addr=0x4014,
        capstone=SimpleNamespace(
            insns=(SimpleNamespace(insn=SimpleNamespace(address=0x4014, size=1, mnemonic="ret")),)
        ),
    )
    function = SimpleNamespace(
        block_addrs_set={0x4010, 0x4014},
        blocks=(conditional_block, conditionless_block),
    )
    Instruction_ANY._inertia_module_condition_cache = {0x4010: [fresh]}
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {}
    Instruction_ANY._inertia_condition_reg_affine_state_8616 = {}
    Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 = {}
    Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
    Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: function)
        ),
        factory=SimpleNamespace(block=lift_block),
    )
    try:
        conditions = collect_typed_conditions_from_emulator_8616(project, 0x4010)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending
        Instruction_ANY._inertia_condition_reg_affine_state_8616 = original_affine
        Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 = original_snapshots
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index
        Instruction_ANY._inertia_condition_reg_value_state_8616 = original_values

    assert conditions == [fresh]
