from __future__ import annotations

from types import SimpleNamespace

import bitstring
from angr_platforms.X86_16.ir.condition_ir import ConditionIR, ConditionSource
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRCondition, IRValue, MemSpace
from angr_platforms.X86_16.lowering.condition_transfer import (
    _condition_from_pending_source_8616,
    collect_typed_condition_artifacts_8616,
    collect_typed_conditions_from_emulator_8616,
    transfer_typed_conditions_to_codegen_8616,
)


class _Emu:
    def __init__(self, condition=None):
        self._last_condition = condition

    def set_last_condition(self, condition):
        self._last_condition = condition

    def get_last_condition(self):
        return self._last_condition

    def clear_last_condition(self):
        self._last_condition = None


def test_dec_reg_chain_to_jcc_is_simple_condition_semantics_without_affine(monkeypatch):
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    monkeypatch.delenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", raising=False)
    operand = SimpleNamespace(type=0)

    dec_before_jcc = SimpleNamespace(
        cs=SimpleNamespace(mnemonic="dec"),
        _next_instruction_is_incdec_reg16_from_bytes_8616=lambda: False,
        _next_instruction_is_simple_jcc_from_bytes_8616=lambda: True,
        _reg16_name=lambda op: "ax" if op is operand else None,
    )
    dec_before_dec = SimpleNamespace(
        cs=SimpleNamespace(mnemonic="dec"),
        _next_instruction_is_incdec_reg16_from_bytes_8616=lambda: True,
        _next_instruction_is_simple_jcc_from_bytes_8616=lambda: False,
        _reg16_name=lambda op: "ax" if op is operand else None,
    )
    inc_before_jcc = SimpleNamespace(
        cs=SimpleNamespace(mnemonic="inc"),
        _SIMPLE_JCC_8616=(),
        _next_instruction_is_incdec_reg16_from_bytes_8616=lambda: False,
        _next_instruction_is_simple_jcc_from_bytes_8616=lambda: True,
        _reg16_name=lambda op: "ax" if op is operand else None,
    )

    assert Instruction_ANY._match_simple_unary_semantics_8616(dec_before_jcc, (operand,)) == ("dec_reg16", "ax")
    assert Instruction_ANY._match_simple_unary_semantics_8616(dec_before_dec, (operand,)) == ("dec_reg16", "ax")
    assert Instruction_ANY._match_simple_unary_semantics_8616(inc_before_jcc, (operand,)) == ("inc_reg16", "ax")


def test_dec_reg_chain_counts_same_register_predecessors():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    chained = SimpleNamespace(start=1, bitstrm=bitstring.ConstBitStream(bytes=b"\x48\x48\x75"))
    single = SimpleNamespace(start=0, bitstrm=bitstring.ConstBitStream(bytes=b"\x48\x75"))

    assert Instruction_ANY._same_preceding_incdec_reg16_count_8616(chained, "ax", mnemonic="dec") == 2
    assert Instruction_ANY._same_preceding_incdec_reg16_count_8616(single, "ax", mnemonic="dec") == 1
    assert Instruction_ANY._same_preceding_incdec_reg16_count_8616(chained, "cx", mnemonic="dec") == 1


def test_sub_flags_are_suppressed_when_cmp_overwrites_them_after_mov() -> None:
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction._future_instructions = (
        SimpleNamespace(cs=SimpleNamespace(mnemonic="mov")),
        SimpleNamespace(cs=SimpleNamespace(mnemonic="cmp")),
    )

    assert instruction._flags_fully_overwritten_before_use_8616()
    assert not instruction._should_update_binop_flags_8616("sub", logical_condition_recorded=False)


def test_sub_flags_survive_transparent_instruction_before_jcc() -> None:
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction._future_instructions = (
        SimpleNamespace(cs=SimpleNamespace(mnemonic="mov")),
        SimpleNamespace(cs=SimpleNamespace(mnemonic="jl")),
    )

    assert not instruction._flags_fully_overwritten_before_use_8616()
    assert instruction._should_update_binop_flags_8616("sub", logical_condition_recorded=False)


def test_sub_flag_suppression_refuses_unknown_future_instruction() -> None:
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction._future_instructions = (SimpleNamespace(cs=SimpleNamespace(mnemonic="mystery")),)

    assert not instruction._flags_fully_overwritten_before_use_8616()
    assert instruction._should_update_binop_flags_8616("sub", logical_condition_recorded=False)


def test_sub_register_memory_semantics_are_classified_before_cmp() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    arch = Arch86_16()
    code = b"\x2b\x46\x06\x8b\x4e\x04\x2b\x4e\x02\x3b\xc1\x7c\x02"
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=code),
        arch,
        0x4000,
    )

    assert instruction.simple_semantics is None
    assert instruction.condition_value_semantics == (
        "sub_reg_mem16",
        "ax",
        ("bp", 6, 6),
    )


def test_sub_register_memory_semantics_are_classified_before_dec() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    arch = Arch86_16()
    code = b"\x2b\x46\x04\x48\x74\x02"
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=code),
        arch,
        0x4000,
    )

    assert instruction.simple_semantics is None
    assert instruction.condition_value_semantics == (
        "sub_reg_mem16",
        "ax",
        ("bp", 4, 4),
    )


def test_sub_immediate_semantics_do_not_depend_on_a_cmp_consumer() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    arch = Arch86_16()
    code = b"\x2d\x07\x00\x50\x90\x0e\xe8\x00\x00"
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=code),
        arch,
        0x4000,
    )

    assert instruction.simple_semantics == ("sub_reg_imm16", "ax", 7)


def test_sub_immediate_semantics_do_not_depend_on_a_later_clobber() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    arch = Arch86_16()
    code = b"\x2d\x07\x00\xb8\x01\x00\x3d\x02\x00\x7c\x02"
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=code),
        arch,
        0x4000,
    )

    assert instruction.simple_semantics == ("sub_reg_imm16", "ax", 7)


def test_pending_cmp_condition_harmonizes_mixed_width_operands_before_transfer():
    lhs = IRValue(MemSpace.REG, name="al", size=1)
    rhs = IRValue(MemSpace.CONST, const=0x1234, size=2)
    source = ConditionSource(kind="cmp", lhs=lhs, rhs=rhs, width_bits=16, addr=0x4010, block_addr=0x4000)

    cond = _condition_from_pending_source_8616(source, "jbe", src_insn=0x4013, block_addr=0x4000)

    assert isinstance(cond, ConditionIR)
    assert cond.op == "ule"
    assert cond.width_bits == 16
    assert isinstance(cond.lhs, IRValue)
    assert isinstance(cond.rhs, IRValue)
    assert cond.lhs.size == 2
    assert cond.rhs.size == 2


def test_logical_or_result_preserves_direct_global_operands():
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(Instruction_ANY._inertia_condition_index_reg_state_8616)
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()
    instr.addr = 0x1003
    instr.emu = _Emu()
    instr.simple_semantics = ("or_reg_abs16", "ax", 0x132)
    instr._next_instruction_is_simple_jcc = lambda: True

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "ax": (IRValue(MemSpace.DS, offset=0x134, size=2), 0)
        }
        recorded = Instruction_ANY._record_logical_result_condition_source_8616(
            instr,
            "or",
            "ax",
            object(),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state

    assert recorded is True
    source = instr.emu._inertia_last_condition_source
    assert isinstance(source, ConditionSource)
    assert source.semantics == ("or_reg_abs16", "ax", 0x132)
    assert source.bind_operand_at_jcc is False
    assert source.normalized_lhs == IRBinaryValue(
        op="or",
        lhs=IRValue(MemSpace.DS, offset=0x134, size=2),
            rhs=IRValue(
                MemSpace.DS,
                offset=0x132,
                size=2,
                expr=("cmp-ds",),
                memory_access_size=2,
            ),
        size=2,
    )
    condition = instr.emu.get_last_condition()
    assert isinstance(condition, IRCondition)
    assert condition.op == "zero"
    assert condition.args == (source.normalized_lhs,)


def test_pending_logical_result_condition_preserves_typed_value_expression():
    value = IRBinaryValue(
        op="or",
        lhs=IRValue(MemSpace.DS, offset=0x134, size=2),
        rhs=IRValue(MemSpace.DS, offset=0x132, size=2),
        size=2,
    )
    source = ConditionSource(
        kind="test",
        lhs=object(),
        normalized_lhs=value,
        semantics=("or_reg_abs16", "ax", 0x132),
        width_bits=16,
        addr=0x1003,
        block_addr=0x1000,
    )

    cond = _condition_from_pending_source_8616(
        source,
        "je",
        src_insn=0x1007,
        block_addr=0x1000,
    )

    assert isinstance(cond, ConditionIR)
    assert cond.op == "zero"
    assert cond.lhs is value
    assert cond.producer_insn == 0x1003
    assert cond.operand_bind_insn is None


def test_collect_typed_conditions_relifts_blocks_when_cache_is_empty(monkeypatch):
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    condition = ConditionIR("sgt", "ax", "bx")
    lifted_blocks: list[int] = []

    def _lift_block(block_addr: int, opt_level: int = 0):
        lifted_blocks.append(block_addr)
        Instruction_ANY._inertia_module_condition_cache[block_addr] = [condition]
        return None

    Instruction_ANY._inertia_module_condition_cache = {}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(block_addrs_set={addr, addr + 4})
            )
        ),
        factory=SimpleNamespace(block=_lift_block),
    )

    try:
        conditions = collect_typed_conditions_from_emulator_8616(project, 0x4010)
        artifact_conditions, edge_evidence = collect_typed_condition_artifacts_8616(project, 0x4010)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache

    assert lifted_blocks == [0x4010, 0x4014]
    assert conditions == [condition]
    assert artifact_conditions == [condition]
    assert edge_evidence == []


def test_collect_typed_conditions_relifts_partial_cache_after_reset(monkeypatch):
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    original_affine_state = dict(getattr(Instruction_ANY, "_inertia_condition_reg_affine_state_8616", {}))
    original_affine_snapshots = dict(getattr(Instruction_ANY, "_inertia_condition_reg_affine_state_snapshots_8616", {}))
    original_index_state = dict(getattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", {}))
    stale_condition = ConditionIR("eq", "stale", "stale", src_insn=0x4010, block_addr=0x4010)
    fresh_condition = ConditionIR("eq", "fresh", "fresh", src_insn=0x4014, block_addr=0x4014)
    lifted_blocks: list[int] = []
    affine_state_at_relift: list[dict[object, object]] = []

    def _lift_block(block_addr: int, opt_level: int = 0):
        lifted_blocks.append(block_addr)
        affine_state_at_relift.append(dict(Instruction_ANY._inertia_condition_reg_affine_state_8616))
        if block_addr == 0x4014:
            Instruction_ANY._inertia_module_condition_cache[block_addr] = [fresh_condition]
        else:
            Instruction_ANY._inertia_module_condition_cache[block_addr] = []
        return None

    Instruction_ANY._inertia_module_condition_cache = {0x4010: [stale_condition]}
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x4010: object(), 0x4014: object()}
    Instruction_ANY._inertia_condition_reg_affine_state_8616 = {"ax": (IRValue(MemSpace.REG, name="ax", size=2), 19)}
    Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 = {
        0x4014: {"ax": (IRValue(MemSpace.REG, name="ax", size=2), 19)}
    }
    Instruction_ANY._inertia_condition_index_reg_state_8616 = {
        "bx": (IRValue(MemSpace.SS, name="bp", offset=-2, size=2), 1)
    }
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(block_addrs_set={addr, addr + 4})
            )
        ),
        factory=SimpleNamespace(block=_lift_block),
    )

    try:
        conditions = collect_typed_conditions_from_emulator_8616(project, 0x4010)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending
        Instruction_ANY._inertia_condition_reg_affine_state_8616 = original_affine_state
        Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 = original_affine_snapshots
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state

    assert lifted_blocks == [0x4010, 0x4014]
    assert affine_state_at_relift[0] == {}
    assert conditions == [fresh_condition]


def test_collect_typed_conditions_refuses_stale_block_generations():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = Instruction_ANY._inertia_module_condition_cache
    original_pending = Instruction_ANY._inertia_pending_condition_sources_by_addr
    current = ConditionIR(
        "ne",
        "current",
        2,
        source=("cmp", "jne"),
        src_insn=0x4014,
        block_addr=0x4010,
        taken_target=0x4020,
        fallthrough_target=0x4016,
    )
    stale_extent = ConditionIR(
        "ne",
        "stale-extent",
        2,
        source=("cmp", "jne"),
        src_insn=0x4018,
        block_addr=0x4010,
        taken_target=0x4030,
        fallthrough_target=0x401A,
    )
    stale_semantics = ConditionIR(
        "sgt",
        "stale-semantics",
        2,
        source=("cmp", "jg"),
        src_insn=0x4014,
        block_addr=0x4010,
        taken_target=0x4020,
        fallthrough_target=0x4016,
    )
    stale_targets = ConditionIR(
        "ne",
        "stale-targets",
        2,
        source=("cmp", "jne"),
        src_insn=0x4014,
        block_addr=0x4010,
        taken_target=0x4030,
        fallthrough_target=0x4016,
    )
    immediate = SimpleNamespace(imm=0x4020)
    terminal = SimpleNamespace(
        address=0x4014,
        size=2,
        mnemonic="jne",
        operands=(immediate,),
    )
    block = SimpleNamespace(
        addr=0x4010,
        capstone=SimpleNamespace(insns=(SimpleNamespace(insn=terminal),)),
    )
    function = SimpleNamespace(block_addrs_set={0x4010}, blocks=(block,))
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function)),
    )
    codegen = SimpleNamespace()
    Instruction_ANY._inertia_module_condition_cache = {
        0x4010: [stale_extent, current, stale_semantics, stale_targets, current]
    }
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {}

    try:
        transferred = transfer_typed_conditions_to_codegen_8616(project, 0x4010, codegen)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert transferred == 1
    assert codegen._inertia_typed_conditions == [current]
    stats = codegen._inertia_condition_ownership_stats
    assert stats.raw_fact_count == 5
    assert stats.normalized_fact_count == 4
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    # The liveness pass also refuses the synthetic fixture's incomplete CFG
    # topology, in addition to the three stale condition generations.
    assert stats.failure_count == 4


def test_record_typed_condition_deduplicates_module_cache():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = Instruction_ANY._inertia_module_condition_cache
    condition = ConditionIR(
        "ne",
        "ax",
        0,
        source=("cmp", "jne"),
        src_insn=0x4014,
        block_addr=0x4010,
        taken_target=0x4020,
        fallthrough_target=0x4016,
    )
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4014
    instruction.emu = SimpleNamespace(
        _inertia_current_block_addr=0x4010,
        _inertia_typed_conditions=[],
    )
    Instruction_ANY._inertia_module_condition_cache = {}

    try:
        instruction._record_typed_condition_8616(condition)
        instruction._record_typed_condition_8616(condition)
    finally:
        cache = Instruction_ANY._inertia_module_condition_cache
        Instruction_ANY._inertia_module_condition_cache = original_cache

    assert instruction.emu._inertia_typed_conditions == [condition, condition]
    assert cache == {0x4010: [condition]}


def test_indexed_byte_cmp_condition_operands_use_stack_index_state():
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(getattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", {}))
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "bx": (IRValue(MemSpace.SS, name="bp", offset=-2, size=2), 1)
        }
        lhs, rhs = Instruction_ANY._condition_operands_from_cmp_semantics_8616(
            instr,
            ("cmp_indexed_abs_reg8", ("bx", 0xB4C, 0xB4C), "al"),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state

    assert lhs == IRValue(
        MemSpace.DS,
        offset=0xB4C,
        size=1,
        index=IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
        index_shift=1,
        memory_access_size=1,
    )
    assert rhs == IRValue(MemSpace.REG, name="al", offset=0, size=1, expr=("cmp-reg",))


def test_indexed_word_immediate_cmp_uses_architectural_di_index() -> None:
    """An ordinary DS:[DI+disp] compare keeps exact typed index evidence."""
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(Instruction_ANY._inertia_condition_index_reg_state_8616)
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.arch = Arch86_16()
    instruction.addr = 0x11386

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
        operands = instruction._condition_operands_from_cmp_semantics_8616(
            ("cmp_mem_imm16", ("di", 0x25F6, 0x25F6), 0xFFFF),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state

    assert operands == (
        IRValue(
            MemSpace.DS,
            offset=0x25F6,
            size=2,
            index=IRValue(MemSpace.REG, name="di", offset=0x1C, size=2, expr=("cmp-reg",)),
            index_shift=0,
            memory_access_size=2,
            memory_access_insn=0x11386,
        ),
        IRValue(MemSpace.CONST, const=0xFFFF, size=2, expr=("cmp-imm",)),
    )


def test_lifted_indexed_word_immediate_cmp_materializes_jcc_condition() -> None:
    """The full CMP/JZ lift must retain its typed indexed-memory condition."""
    import pyvex
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.ir.condition_lift_capture import isolated_condition_lift_session_8616

    instruction_addr = 0x11386
    data = bytes.fromhex("81 bd f6 25 ff ff 74 05")
    with isolated_condition_lift_session_8616() as capture:
        pyvex.lift(data, instruction_addr, Arch86_16(), max_bytes=len(data), opt_level=0)

    conditions = capture.condition_cache[instruction_addr]
    assert len(conditions) == 1
    condition = conditions[0]
    assert condition.op == "eq"
    assert condition.lhs == IRValue(
        MemSpace.DS,
        offset=0x25F6,
        size=2,
        index=IRValue(MemSpace.REG, name="di", offset=0x1C, size=2, expr=("cmp-reg",)),
        index_shift=0,
        memory_access_size=2,
        memory_access_insn=instruction_addr,
    )
    assert condition.rhs == IRValue(MemSpace.CONST, const=0xFFFF, size=2, expr=("cmp-imm",))


def test_lifted_indexed_cmp_falls_back_to_live_register_after_ds_load() -> None:
    """A DS-derived index still denotes the live architectural register at CMP."""
    import pyvex
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.ir.condition_lift_capture import isolated_condition_lift_session_8616

    instruction_addr = 0x4000
    data = bytes.fromhex("8b36420083bc351a00750390c3")
    with isolated_condition_lift_session_8616() as capture:
        pyvex.lift(data, instruction_addr, Arch86_16(), max_bytes=len(data), opt_level=0)

    [condition] = capture.condition_cache[instruction_addr]
    assert condition.op == "ne"
    assert condition.lhs == IRValue(
        MemSpace.DS,
        offset=0x1A35,
        size=2,
        index=IRValue(
            MemSpace.REG,
            name="si",
            offset=0x18,
            size=2,
            expr=("cmp-reg",),
        ),
        index_shift=0,
        memory_access_size=2,
        memory_access_insn=instruction_addr + 4,
    )
    assert condition.rhs == IRValue(
        MemSpace.CONST,
        const=0,
        size=2,
        expr=("cmp-imm",),
    )


def test_indexed_byte_cmp_uses_exact_loaded_rhs_until_register_clobber():
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(
        Instruction_ANY._inertia_condition_index_reg_state_8616
    )
    original_value_state = dict(
        Instruction_ANY._inertia_condition_reg_value_state_8616
    )
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()
    instr.addr = 0x4010
    instr.cs = SimpleNamespace(size=4)
    instr.emu = SimpleNamespace(_inertia_current_block_addr=0x4000)

    try:
        low_index = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
        high_index = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "bx": (low_index, 1),
            "si": (high_index, 1),
        }
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instr._set_condition_reg_indexed_value_8616(
            "al",
            ("si", 0xB4C, 0xB4C),
            width_bits=8,
        )
        instr.addr = 0x4014
        lhs, rhs = instr._condition_operands_from_cmp_semantics_8616(
            ("cmp_indexed_abs_reg8", ("bx", 0xB4C, 0xB4C), "al"),
        )
        instr._clear_condition_reg_value_state_8616("ax")
        _, clobbered_rhs = instr._condition_operands_from_cmp_semantics_8616(
            ("cmp_indexed_abs_reg8", ("bx", 0xB4C, 0xB4C), "al"),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = (
            original_index_state
        )
        Instruction_ANY._inertia_condition_reg_value_state_8616 = (
            original_value_state
        )

    assert lhs == IRValue(
        MemSpace.DS,
        offset=0xB4C,
        size=1,
        index=IRValue(MemSpace.SS, name="bp", offset=4, size=2),
        index_shift=1,
        memory_access_size=1,
    )
    assert rhs == IRValue(
        MemSpace.DS,
        offset=0xB4C,
        size=1,
        index=IRValue(MemSpace.SS, name="bp", offset=6, size=2),
        index_shift=1,
        memory_access_size=1,
    )
    assert clobbered_rhs == IRValue(
        MemSpace.REG,
        name="al",
        offset=0,
        size=1,
        expr=("cmp-reg",),
    )


def test_stack_subtraction_value_survives_unrelated_instruction_until_clobber():
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(
        Instruction_ANY._inertia_condition_index_reg_state_8616
    )
    original_value_state = dict(
        Instruction_ANY._inertia_condition_reg_value_state_8616
    )
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()
    instr.addr = 0x4010
    instr.cs = SimpleNamespace(size=3)
    instr.emu = SimpleNamespace(_inertia_current_block_addr=0x4000)

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instr._set_condition_index_reg_stack_state_8616(
            "ax",
            ("bp", 6, 6),
        )
        instr.addr = 0x4013
        arithmetic = instr._arithmetic_result_value_from_semantics_8616(
            ("sub_reg_mem16", "ax", ("bp", 4, 4)),
        )
        assert arithmetic is not None
        register_name, value = arithmetic
        instr._clear_condition_reg_value_state_8616(register_name)
        instr._set_condition_reg_value_state_8616(register_name, value)
        instr.addr = 0x4019
        proven = instr._condition_proven_reg_value_8616(
            "ax",
            width_bits=16,
        )
        instr._clear_condition_reg_value_state_8616("ax")
        refused = instr._condition_proven_reg_value_8616(
            "ax",
            width_bits=16,
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = (
            original_index_state
        )
        Instruction_ANY._inertia_condition_reg_value_state_8616 = (
            original_value_state
        )

    assert proven == IRBinaryValue(
        "sub",
        IRValue(
            MemSpace.SS,
            name="bp",
            offset=6,
            size=2,
            expr=("cmp-stack", "bp"),
        ),
        IRValue(
            MemSpace.SS,
            name="bp",
            offset=4,
            size=2,
            expr=("cmp-stack", "bp"),
        ),
        size=2,
    )
    assert refused is None


def test_full_lift_inc_preserves_exact_stack_value_for_following_cmp() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(
        Instruction_ANY._inertia_condition_index_reg_state_8616
    )
    original_value_state = dict(
        Instruction_ANY._inertia_condition_reg_value_state_8616
    )
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.arch = Arch86_16()
    instruction.addr = 0x4010
    instruction.cs = SimpleNamespace(size=3)
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x4010)
    instruction.condition_value_semantics = None

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instruction._set_condition_index_reg_stack_state_8616(
            "ax",
            ("bp", 0xFFFC, -4),
        )
        instruction.addr = 0x4013
        operand = SimpleNamespace(type=1, size=2, reg=0)
        instruction.cs = SimpleNamespace(
            mnemonic="inc",
            operands=(operand,),
            reg_name=lambda _register: "ax",
            regs_access=lambda: ((), (0,)),
            size=1,
        )
        instruction._transfer_full_lift_condition_value_semantics_8616()
        instruction.addr = 0x4014
        lhs, rhs = instruction._condition_operands_from_cmp_semantics_8616(
            ("cmp_reg_mem16", "ax", ("bp", 4, 4)),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = (
            original_index_state
        )
        Instruction_ANY._inertia_condition_reg_value_state_8616 = (
            original_value_state
        )

    assert lhs == IRBinaryValue(
        "add",
        IRValue(
            MemSpace.SS,
            name="bp",
            offset=-4,
            size=2,
            expr=("cmp-stack", "bp"),
        ),
        IRValue(
            MemSpace.CONST,
            const=1,
            size=2,
            expr=("cmp-imm",),
        ),
        size=2,
    )
    assert rhs == IRValue(
        MemSpace.SS,
        name="bp",
        offset=4,
        size=2,
        expr=("cmp-stack", "bp"),
        memory_access_size=2,
        memory_access_insn=instruction.addr,
    )


def test_full_lift_unmodeled_register_write_invalidates_condition_value() -> None:
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(
        Instruction_ANY._inertia_condition_index_reg_state_8616
    )
    original_value_state = dict(
        Instruction_ANY._inertia_condition_reg_value_state_8616
    )
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4020
    instruction.cs = SimpleNamespace(
        mnemonic="mul",
        operands=(),
        reg_name=lambda _register: "ax",
        regs_access=lambda: ((), (0,)),
        size=2,
    )
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x4020)
    instruction.condition_value_semantics = None

    try:
        stack_value = IRValue(MemSpace.SS, name="bp", offset=-2, size=2)
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "ax": (stack_value, 0)
        }
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instruction._set_condition_reg_value_state_8616("ax", stack_value)
        instruction._transfer_full_lift_condition_value_semantics_8616()

        assert "ax" not in Instruction_ANY._inertia_condition_index_reg_state_8616
        assert instruction._condition_proven_reg_value_8616("ax") is None
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = (
            original_index_state
        )
        Instruction_ANY._inertia_condition_reg_value_state_8616 = (
            original_value_state
        )


def test_indexed_byte_load_provenance_survives_word_cmp_operand_recovery():
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.ir.condition_value_extensions import sign_extend_condition_value_8616
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(
        getattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", {})
    )
    original_value_state = dict(
        getattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})
    )
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()
    instr.addr = 0x4010
    instr.cs = SimpleNamespace(size=2)
    instr.emu = SimpleNamespace(_inertia_current_block_addr=0x4000)

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "bx": (IRValue(MemSpace.SS, name="bp", offset=-4, size=2), 1)
        }
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instr._set_condition_reg_indexed_value_8616(
            "al",
            ("bx", 0xB4A, 0xB4A),
            width_bits=8,
        )
        instr.addr = 0x4012
        instr.cs = SimpleNamespace(size=1)
        instr._widen_condition_reg_value_state_8616("ax")
        instr.addr = 0x4013
        instr.cs = SimpleNamespace(size=3)
        instr.simple_semantics = (
            "cmp_reg_mem16",
            "ax",
            ("bp", 0xFFFA, -6),
        )
        lhs, rhs = instr._condition_operands_from_cmp_semantics_8616(
            instr.simple_semantics,
        )
        instr._record_cmp_condition_source(object(), object())
        source = instr.emu._inertia_last_condition_source
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = (
            original_index_state
        )
        Instruction_ANY._inertia_condition_reg_value_state_8616 = (
            original_value_state
        )

    assert lhs == sign_extend_condition_value_8616(IRValue(
        MemSpace.DS,
        offset=0xB4A,
        size=1,
        index=IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
        index_shift=1,
        memory_access_size=1,
    ), 2)
    assert rhs == IRValue(
        MemSpace.SS,
        name="bp",
        offset=-6,
        size=2,
        expr=("cmp-stack", "bp"),
        memory_access_size=2,
        memory_access_insn=instr.addr,
    )
    assert source.normalized_lhs == lhs
    assert source.normalized_rhs == rhs


def test_indexed_byte_load_provenance_refuses_noncontiguous_word_cmp():
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(
        getattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", {})
    )
    original_value_state = dict(
        getattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})
    )
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()
    instr.addr = 0x4010
    instr.cs = SimpleNamespace(size=2)
    instr.emu = SimpleNamespace(_inertia_current_block_addr=0x4000)

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "bx": (IRValue(MemSpace.SS, name="bp", offset=-4, size=2), 1)
        }
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instr._set_condition_reg_indexed_value_8616(
            "al",
            ("bx", 0xB4A, 0xB4A),
            width_bits=8,
        )
        instr.addr = 0x4013
        instr.cs = SimpleNamespace(size=3)
        lhs, _rhs = instr._condition_operands_from_cmp_semantics_8616(
            ("cmp_reg_mem16", "ax", ("bp", 0xFFFA, -6)),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = (
            original_index_state
        )
        Instruction_ANY._inertia_condition_reg_value_state_8616 = (
            original_value_state
        )

    assert lhs == IRValue(
        MemSpace.REG,
        name="ax",
        offset=0,
        size=2,
        expr=("cmp-reg",),
    )


def test_cbw_is_simple_sign_extension_semantics() -> None:
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    instruction = SimpleNamespace(cs=SimpleNamespace(mnemonic="cwde", bytes=b"\x98"))

    assert (
        Instruction_ANY._match_simple_unary_semantics_8616(instruction, ())
        == ("sign_extend_al_ax",)
    )


def test_stack_cmp_register_operand_uses_unshifted_stack_register_state():
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(getattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", {}))
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()
    instr.addr = 0x4000

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "ax": (IRValue(MemSpace.SS, name="bp", offset=-6, size=2), 0)
        }
        lhs, rhs = Instruction_ANY._condition_operands_from_cmp_semantics_8616(
            instr,
            ("cmp_mem_reg16", ("bp", 0xFFFC, -4), "ax"),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state

    assert lhs == IRValue(MemSpace.SS, name="bp", offset=-4, size=2, expr=("cmp-stack", "bp"), memory_access_size=2, memory_access_insn=instr.addr)
    assert rhs == IRValue(MemSpace.SS, name="bp", offset=-6, size=2)


def test_stack_cmp_register_operand_uses_unshifted_direct_global_register_state():
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(getattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", {}))
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()
    instr.addr = 0x4000

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "ax": (IRValue(MemSpace.DS, offset=0xBA2, size=2, expr=("cmp-ds",)), 0)
        }
        lhs, rhs = Instruction_ANY._condition_operands_from_cmp_semantics_8616(
            instr,
            ("cmp_mem_reg16", ("bp", 0xFFFE, -2), "ax"),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state

    assert lhs == IRValue(MemSpace.SS, name="bp", offset=-2, size=2, expr=("cmp-stack", "bp"), memory_access_size=2, memory_access_insn=instr.addr)
    assert rhs == IRValue(MemSpace.DS, offset=0xBA2, size=2, expr=("cmp-ds",))


def test_register_carried_direct_global_keeps_load_instruction_not_cmp() -> None:
    from angr_platforms.X86_16.arch_86_16 import Arch86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_index_state = dict(Instruction_ANY._inertia_condition_index_reg_state_8616)
    original_value_state = dict(Instruction_ANY._inertia_condition_reg_value_state_8616)
    instr = Instruction_ANY.__new__(Instruction_ANY)
    instr.arch = Arch86_16()
    instr.addr = 0x1047
    instr.cs = SimpleNamespace(size=3)
    instr.emu = SimpleNamespace(_inertia_current_block_addr=0x1047)

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        Instruction_ANY._set_condition_index_reg_direct_state_8616(
            instr,
            "ax",
            0x160,
        )
        instr.addr = 0x104A
        lhs, _rhs = Instruction_ANY._condition_operands_from_cmp_semantics_8616(
            instr,
            ("cmp_reg_imm16", "ax", 0),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state
        Instruction_ANY._inertia_condition_reg_value_state_8616 = original_value_state

    assert isinstance(lhs, IRValue)
    assert lhs.space == MemSpace.DS
    assert lhs.offset == 0x160
    assert lhs.memory_access_insn == 0x1047


def test_direct_jcc_preserves_condition_for_back_to_back_jcc(monkeypatch):
    from angr_platforms.X86_16 import lift_86_16
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    condition = IRCondition(
        op="compare",
        args=(
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.CONST, const=69, size=2),
        ),
    )
    prev_emu = _Emu(condition)
    current_emu = _Emu()
    instr = SimpleNamespace(
        _past_instructions=[SimpleNamespace(emu=prev_emu, addr=0x423)],
        _future_instructions=[SimpleNamespace(simple_semantics=("jle",))],
        emu=current_emu,
        _next_instruction_is_simple_jcc=lambda: True,
    )

    monkeypatch.setattr(lift_86_16, "_direct_jcc_condition_from_last_condition_8616", lambda *_args: object())

    assert Instruction_ANY._direct_jcc_condition(instr, "jne") is not None
    assert prev_emu.get_last_condition() is condition
    assert current_emu.get_last_condition() is condition


def test_emit_simple_jcc_propagates_condition_source_for_following_jcc():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    rhs = IRValue(MemSpace.CONST, const=69, size=2)
    source = ConditionSource(kind="cmp", lhs=lhs, rhs=rhs, addr=0x423, block_addr=0x423)
    prev_emu = _Emu()
    prev_emu._inertia_last_condition_source = source
    current_emu = _Emu()
    recorded: list[ConditionIR] = []
    instr = SimpleNamespace(
        _past_instructions=[SimpleNamespace(emu=prev_emu, addr=0x423)],
        simple_semantics=("jne",),
        addr=0x426,
        cs=SimpleNamespace(size=2),
        emu=current_emu,
        _condition_operands_from_cmp_semantics_8616=lambda _semantics: None,
        _record_typed_condition_8616=recorded.append,
        jump=lambda *_args: None,
    )

    try:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = {}
        Instruction_ANY._emit_simple_jcc(instr, object(), SimpleNamespace(con=SimpleNamespace(value=0x42B)))

        assert current_emu._inertia_last_condition_source is source
        pending = Instruction_ANY._inertia_pending_condition_sources_by_addr[0x428]
        assert pending is not source
        assert pending.lhs is lhs
        assert pending.rhs is rhs
        assert pending.fallthrough_from_jcc == "jne"
        target_pending = Instruction_ANY._inertia_pending_condition_sources_by_addr[0x42B]
        assert target_pending is not source
        assert target_pending.lhs is lhs
        assert target_pending.rhs is rhs
        assert target_pending.fallthrough_from_jcc is None
        assert [(cond.src_insn, cond.block_addr, cond.producer_insn, cond.op) for cond in recorded] == [
            (0x426, 0x423, 0x423, "ne")
        ]
    finally:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending


def test_emit_simple_jcc_consumes_pending_fallthrough_condition_source():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    rhs = IRValue(MemSpace.CONST, const=69, size=2)
    source = ConditionSource(kind="cmp", lhs=lhs, rhs=rhs, addr=0x423, block_addr=0x423)
    current_emu = _Emu()
    recorded: list[ConditionIR] = []
    instr = SimpleNamespace(
        _past_instructions=[],
        simple_semantics=("jle",),
        addr=0x428,
        cs=SimpleNamespace(size=2),
        emu=current_emu,
        _condition_operands_from_cmp_semantics_8616=lambda _semantics: None,
        _record_typed_condition_8616=recorded.append,
        jump=lambda *_args: None,
    )

    try:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x428: source}
        Instruction_ANY._emit_simple_jcc(instr, object(), 0x452)

        assert current_emu._inertia_last_condition_source is source
        assert [(cond.src_insn, cond.block_addr, cond.producer_insn, cond.op) for cond in recorded] == [
            (0x428, 0x423, 0x423, "sle")
        ]
    finally:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending


def test_direct_jcc_rebuilds_pending_cmp_guard_without_packed_flags():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    class _SignedValue:
        def __ge__(self, _other):
            return object()

    original_pending = dict(Instruction_ANY._inertia_pending_condition_sources_by_addr)
    source = ConditionSource(
        kind="cmp",
        lhs=IRValue(MemSpace.REG, name="dx", size=2),
        rhs=IRValue(MemSpace.SS, offset=-2, size=2),
        semantics=("cmp_reg_mem16", "dx", ("bp", -2)),
        addr=0x10F55,
        block_addr=0x10F55,
    )
    signed_lhs = _SignedValue()
    signed_rhs = object()
    lhs = SimpleNamespace(signed=signed_lhs)
    rhs = SimpleNamespace(signed=signed_rhs)
    instr = SimpleNamespace(
        addr=0x10F5D,
        _past_instructions=[],
        _cmp_operands_from_semantics=lambda _semantics: (lhs, rhs),
    )

    try:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x10F5D: source}
        condition = Instruction_ANY._direct_jcc_condition(instr, "jge")
    finally:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert condition is not None


def test_emit_simple_jcc_prefers_normalized_condition_operands():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    raw_lhs = object()
    raw_rhs = object()
    normalized_lhs = IRValue(MemSpace.REG, name="ax", size=2)
    normalized_rhs = IRValue(MemSpace.CONST, const=60, size=2)
    source = ConditionSource(
        kind="cmp",
        lhs=raw_lhs,
        rhs=raw_rhs,
        normalized_lhs=normalized_lhs,
        normalized_rhs=normalized_rhs,
        semantics=("sub_reg_imm16", "ax", 33),
        addr=0x438,
        block_addr=0x438,
    )
    current_emu = _Emu()
    recorded: list[ConditionIR] = []
    instr = SimpleNamespace(
        _past_instructions=[],
        simple_semantics=("jne",),
        addr=0x43B,
        cs=SimpleNamespace(size=2),
        emu=current_emu,
        _condition_operands_from_cmp_semantics_8616=lambda _semantics: (
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.CONST, const=33, size=2),
        ),
        _record_typed_condition_8616=recorded.append,
        jump=lambda *_args: None,
    )

    try:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x43B: source}
        Instruction_ANY._emit_simple_jcc(instr, object(), 0x450)

        [cond] = recorded
        assert cond.lhs == normalized_lhs
        assert cond.rhs == normalized_rhs
        pending = Instruction_ANY._inertia_pending_condition_sources_by_addr[0x43D]
        assert pending.lhs == normalized_lhs
        assert pending.rhs == normalized_rhs
    finally:
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending


def test_collect_typed_conditions_materializes_pending_fallthrough_jcc():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    rhs = IRValue(MemSpace.CONST, const=69, size=2)
    source = ConditionSource(kind="cmp", lhs=lhs, rhs=rhs, width_bits=16, addr=0x1153, block_addr=0x1153)
    first_condition = ConditionIR(
        "ne",
        lhs,
        rhs,
        src_insn=0x1153,
        block_addr=0x1153,
        producer_insn=0x114E,
        source=("cmp", "jne"),
    )
    decoded_addrs: list[int] = []

    def _lift_block(block_addr: int, **_kwargs):
        decoded_addrs.append(block_addr)
        if block_addr == 0x1153:
            Instruction_ANY._inertia_module_condition_cache[0x1153] = [first_condition]
            Instruction_ANY._inertia_pending_condition_sources_by_addr[0x1158] = source
        return SimpleNamespace(capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="jle"),)))

    Instruction_ANY._inertia_module_condition_cache = {
        0x1153: [first_condition],
        0x1158: [],
    }
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x1158: source}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: SimpleNamespace(block_addrs_set={0x1153, 0x1158}))
        ),
        factory=SimpleNamespace(block=_lift_block),
    )

    try:
        conditions = collect_typed_conditions_from_emulator_8616(project, 0x1100)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert decoded_addrs == [0x1158]
    assert [(cond.src_insn, cond.block_addr, cond.producer_insn, cond.op) for cond in conditions] == [
        (0x1153, 0x1153, 0x114E, "ne"),
        (0x1158, 0x1158, 0x1153, "sle"),
    ]


def test_transfer_records_pending_fallthrough_jmp_as_edge_evidence_not_guard_condition():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    rhs = IRValue(MemSpace.CONST, const=69, size=2)
    source = ConditionSource(
        kind="cmp",
        lhs=lhs,
        rhs=rhs,
        fallthrough_from_jcc="jne",
        semantics=("cmp_reg_imm16", "ax", 69),
        width_bits=16,
        addr=0x1153,
        block_addr=0x1153,
    )
    first_condition = ConditionIR(
        "ne",
        lhs,
        rhs,
        src_insn=0x1153,
        block_addr=0x1153,
        producer_insn=0x114E,
        source=("cmp", "jne"),
    )

    def _lift_block(block_addr: int, **_kwargs):
        if block_addr == 0x1153:
            Instruction_ANY._inertia_module_condition_cache[0x1153] = [first_condition]
            Instruction_ANY._inertia_pending_condition_sources_by_addr[0x1158] = source
        operand = SimpleNamespace(type=2, imm=0x109C)
        insn = SimpleNamespace(mnemonic="jmp", operands=(operand,))
        return SimpleNamespace(capstone=SimpleNamespace(insns=(insn,)))

    Instruction_ANY._inertia_module_condition_cache = {0x1153: [first_condition]}
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x1158: source}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: SimpleNamespace(block_addrs_set={0x1153, 0x1158}))
        ),
        factory=SimpleNamespace(block=_lift_block),
    )
    codegen = SimpleNamespace()

    try:
        transferred = transfer_typed_conditions_to_codegen_8616(project, 0x1100, codegen)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert transferred == 1
    assert [(cond.src_insn, cond.block_addr, cond.producer_insn, cond.op) for cond in codegen._inertia_typed_conditions] == [
        (0x1153, 0x1153, 0x114E, "ne")
    ]
    edge_evidence = codegen._inertia_condition_edge_evidence
    assert len(edge_evidence) == 1
    edge = edge_evidence[0]
    assert (edge.edge_block_addr, edge.edge_kind, edge.source_jcc, edge.producer_insn) == (
        0x1158,
        "fallthrough_jmp",
        "jne",
        0x1153,
    )
    assert edge.producer_semantics == ("cmp_reg_imm16", "ax", 69)
    assert (edge.condition.src_insn, edge.condition.block_addr, edge.condition.op) == (0x1158, 0x1158, "eq")


def test_transfer_pending_fallthrough_jmp_preserves_normalized_edge_condition():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    raw_lhs = IRValue(MemSpace.REG, name="ax", size=2)
    raw_rhs = IRValue(MemSpace.CONST, const=4, size=2)
    normalized_lhs = IRValue(MemSpace.REG, name="ax", size=2)
    normalized_rhs = IRValue(MemSpace.CONST, const=66, size=2)
    source = ConditionSource(
        kind="cmp",
        lhs=raw_lhs,
        rhs=raw_rhs,
        normalized_lhs=normalized_lhs,
        normalized_rhs=normalized_rhs,
        fallthrough_from_jcc="jne",
        semantics=("sub_reg_imm16", "ax", 4),
        width_bits=16,
        addr=0x1177,
        block_addr=0x1177,
    )

    def _lift_block(_block_addr: int, **_kwargs):
        operand = SimpleNamespace(type=2, imm=0x109C)
        insn = SimpleNamespace(mnemonic="jmp", operands=(operand,))
        return SimpleNamespace(capstone=SimpleNamespace(insns=(insn,)))

    Instruction_ANY._inertia_module_condition_cache = {0x117C: []}
    Instruction_ANY._inertia_pending_condition_sources_by_addr = {0x117C: source}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: SimpleNamespace(block_addrs_set={0x117C}))
        ),
        factory=SimpleNamespace(block=_lift_block),
    )
    codegen = SimpleNamespace()

    try:
        transferred = transfer_typed_conditions_to_codegen_8616(project, 0x1100, codegen)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert transferred == 0
    [edge] = codegen._inertia_condition_edge_evidence
    assert edge.condition.lhs == normalized_lhs
    assert edge.condition.rhs == normalized_rhs
    assert edge.producer_semantics == (
        "normalized_cmp_reg_imm16",
        "ax",
        66,
        ("sub_reg_imm16", "ax", 4),
    )


def test_transfer_preserves_existing_edge_evidence_when_later_collection_is_empty():
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    original_pending = dict(getattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {}))
    edge = object()
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: SimpleNamespace(block_addrs_set={0x1153}))
        ),
        factory=SimpleNamespace(block=lambda *_args, **_kwargs: None),
    )
    codegen = SimpleNamespace(_inertia_condition_edge_evidence=(edge,))

    try:
        Instruction_ANY._inertia_module_condition_cache = {0x1153: []}
        Instruction_ANY._inertia_pending_condition_sources_by_addr = {}
        transfer_typed_conditions_to_codegen_8616(project, 0x1100, codegen)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending

    assert codegen._inertia_condition_edge_evidence == [edge]
