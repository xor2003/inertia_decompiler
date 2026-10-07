"""Tests for exact cross-block condition-register storage bindings."""

from dataclasses import replace

import pytest
from inertia.semantics.callsite_register_provenance import (
    recover_register_source_before_instruction_8616,
)
from inertia.ir.condition_ir import ConditionIR, ConditionRegisterBindingIR
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace
from inertia.pipeline.errors import PipelineHardError

from inertia.alias.condition_register_bindings import (
    ConditionRegisterSourceBindingVerdict8616,
    bind_condition_register_sources_8616,
)
from inertia.alias.condition_register_carriers import (
    normalize_condition_register_carriers_8616,
)
from inertia.alias.register_reaching_source import (
    RegisterReachingSourceVerdict8616,
)
from inertia.cli.project_loading import _build_project_from_bytes


def _function_from_bytes(code: bytes):
    project = _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    return cfg.kb.functions[0x1000]


def _root_condition(*, producer_insn: int = 0x1005) -> ConditionIR:
    return ConditionIR(
        op="zero",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        source=("test", "je"),
        src_insn=producer_insn + 2,
        block_addr=producer_insn,
        producer_insn=producer_insn,
        taken_target=0x100F,
        fallthrough_target=0x1009,
        producer_semantics=("or_reg_reg16", "ax", "ax"),
    )


def _dec_condition(
    block_addr: int,
    *,
    op: str,
    taken_target: int,
    fallthrough_target: int,
) -> ConditionIR:
    return ConditionIR(
        op=op,
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=1, size=2),
        source=("cmp", "je" if op == "eq" else "jne"),
        src_insn=block_addr + 1,
        block_addr=block_addr,
        producer_insn=block_addr,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
        producer_semantics=("dec_reg16", "ax", 1),
    )


def _absolute_memory_register_condition(
    *,
    block_addr: int,
    producer_insn: int,
) -> ConditionIR:
    return ConditionIR(
        op="sgt",
        lhs=IRValue(MemSpace.DS, offset=0x0BA2, size=2),
        rhs=IRValue(MemSpace.REG, name="ax", size=2),
        source=("cmp", "jg"),
        src_insn=producer_insn + 4,
        block_addr=block_addr,
        producer_insn=producer_insn,
        taken_target=producer_insn + 7,
        fallthrough_target=producer_insn + 6,
        producer_semantics=("cmp_abs_reg16", ("ds", 0x0BA2), "ax"),
    )


def test_ds_selector_source_binds_and_seeds_decrement_dispatch() -> None:
    function = _function_from_bytes(
        bytes.fromhex("a1 34 12 eb 00 09 c0 74 06 48 74 03 48 75 01 c3 c3")
    )
    root = _root_condition()
    first = _dec_condition(
        0x1009,
        op="eq",
        taken_target=0x100F,
        fallthrough_target=0x100C,
    )
    second = _dec_condition(
        0x100C,
        op="ne",
        taken_target=0x1010,
        fallthrough_target=0x100F,
    )

    reaching = recover_register_source_before_instruction_8616(
        function,
        instruction_addr=0x1005,
        register="ax",
    )
    binding = bind_condition_register_sources_8616(function, (root, first, second))
    carrier = normalize_condition_register_carriers_8616(binding.conditions)

    selector = IRValue(MemSpace.DS, offset=0x1234, size=2)
    by_source = {condition.src_insn: condition for condition in carrier.conditions}
    assert reaching.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert reaching.source == ("global", 0x1234, 2)
    assert binding.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    assert binding.stats.raw_fact_count == 3
    assert binding.stats.normalized_fact_count == 1
    assert binding.stats.classified_fact_count == binding.stats.materialized_count == 1
    assert binding.stats.failure_count == 0
    assert by_source[0x1007].register_bindings == (
        ConditionRegisterBindingIR("ax", selector),
    )
    assert by_source[0x100A].lhs == selector
    assert by_source[0x100A].rhs == IRValue(MemSpace.CONST, const=1, size=2)
    assert by_source[0x100D].lhs == selector
    assert by_source[0x100D].rhs == IRValue(MemSpace.CONST, const=2, size=2)
    assert carrier.stats.classified_fact_count == carrier.stats.materialized_count == 2


def test_explicit_es_absolute_source_refuses_ds_binding() -> None:
    function = _function_from_bytes(bytes.fromhex("26 a1 34 12 eb 00 09 c0 74 01 c3 c3"))
    root = _root_condition(producer_insn=0x1006)

    reaching = recover_register_source_before_instruction_8616(
        function,
        instruction_addr=0x1006,
        register="ax",
    )
    result = bind_condition_register_sources_8616(function, (root,))

    assert reaching.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.UNKNOWN_REFUSE
    assert result.conditions == (root,)
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_stack_snapshot_source_binds_ss_bp_storage() -> None:
    function = _function_from_bytes(
        bytes.fromhex("b8 34 12 89 46 fe eb 00 09 c0 74 01 c3 c3")
    )
    root = _root_condition(producer_insn=0x1008)

    result = bind_condition_register_sources_8616(function, (root,))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    assert result.conditions[0].register_bindings == (
        ConditionRegisterBindingIR(
            "ax",
            IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
        ),
    )


def test_cmp_absolute_memory_register_binds_stack_snapshot_source() -> None:
    function = _function_from_bytes(bytes.fromhex("8b46fe 3906a20b 7f01 c3 c3"))
    condition = _absolute_memory_register_condition(
        block_addr=0x1000,
        producer_insn=0x1003,
    )

    result = bind_condition_register_sources_8616(function, (condition,))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    assert result.conditions[0].register_bindings == (
        ConditionRegisterBindingIR(
            "ax",
            IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
        ),
    )
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_cmp_binding_honors_normalized_overlapping_block_bounds() -> None:
    function = _function_from_bytes(
        bytes.fromhex(
            "c746fe0000 eb03 ff46fe 8b46fe 3906a20b 7f02 eb02 ebf0 c3"
        )
    )
    condition = _absolute_memory_register_condition(
        block_addr=0x100A,
        producer_insn=0x100D,
    )

    result = bind_condition_register_sources_8616(function, (condition,))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    assert result.conditions[0].register_bindings == (
        ConditionRegisterBindingIR(
            "ax",
            IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
        ),
    )
    assert result.stats.failure_count == 0


def test_cmp_register_binding_refuses_conflicting_cfg_sources() -> None:
    function = _function_from_bytes(
        bytes.fromhex("7505 8b46fe eb03 8b46fc 3906a20b 7f01 c3 c3")
    )
    condition = _absolute_memory_register_condition(
        block_addr=0x100A,
        producer_insn=0x100A,
    )

    result = bind_condition_register_sources_8616(function, (condition,))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.UNKNOWN_REFUSE
    assert result.conditions == (condition,)
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_proven_source_conflicting_with_existing_binding_is_hard_failure() -> None:
    function = _function_from_bytes(bytes.fromhex("a1 34 12 eb 00 09 c0 74 01 c3 c3"))
    root = replace(
        _root_condition(),
        register_bindings=(
            ConditionRegisterBindingIR(
                "ax",
                IRValue(MemSpace.DS, offset=0x4321, size=2),
            ),
        ),
    )

    with pytest.raises(PipelineHardError, match="conflicts with an existing binding"):
        bind_condition_register_sources_8616(function, (root,))


def test_non_self_test_has_no_binding_candidate() -> None:
    condition = _dec_condition(
        0x1009,
        op="eq",
        taken_target=0x100F,
        fallthrough_target=0x100C,
    )

    result = bind_condition_register_sources_8616(object(), (condition,))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.NO_CANDIDATE
    assert result.conditions == (condition,)
    assert result.stats.normalized_fact_count == 0
    assert result.stats.failure_count == 0


def test_plain_loop_counter_binds_proven_immediate_input() -> None:
    """Alias must expose the exact pre-decrement value consumed by LOOP."""
    function = _function_from_bytes(bytes.fromhex("b9 c8 00 e2 fe c3"))
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, name="cx", size=2),
        rhs=IRValue(MemSpace.CONST, const=1, size=2),
        width_bits=16,
        source=("loop",),
        src_insn=0x1003,
        block_addr=0x1003,
        producer_insn=0x1003,
        taken_target=0x1003,
        fallthrough_target=0x1005,
        producer_semantics=("loop_counter_predecrement", "cx", 1),
    )

    result = bind_condition_register_sources_8616(function, (condition,))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    assert result.conditions[0].register_bindings == (
        ConditionRegisterBindingIR(
            "cx",
            IRValue(MemSpace.CONST, const=0xC8, size=2),
        ),
    )
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_high_byte_condition_binds_same_block_word_update() -> None:
    """Alias must retain a byte projection of an exact word-register update."""
    function = _function_from_bytes(
        bytes.fromhex("31 db bd 6c 01 01 eb 80 ff 40 72 f9 c3")
    )
    condition = ConditionIR(
        op="ult",
        lhs=IRValue(MemSpace.REG, name="bh", size=1),
        rhs=IRValue(MemSpace.CONST, const=0x40, size=1),
        width_bits=8,
        source=("cmp", "jb"),
        src_insn=0x100A,
        block_addr=0x1000,
        producer_insn=0x1007,
        taken_target=0x1005,
        fallthrough_target=0x100C,
        producer_semantics=("cmp_reg_imm8", "bh", 0x40),
    )

    result = bind_condition_register_sources_8616(function, (condition,))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    assert len(result.conditions[0].register_bindings) == 1
    projection = result.conditions[0].register_bindings[0]
    assert projection.register_name == "bh"
    assert isinstance(projection.value, IRBinaryValue)
    assert projection.value.op == "and"
    assert isinstance(projection.value.lhs, IRBinaryValue)
    assert projection.value.lhs.op == "shr"
    assert isinstance(projection.value.lhs.lhs, IRBinaryValue)
    assert projection.value.lhs.lhs.op == "add"
    assert result.stats.classified_fact_count == result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
