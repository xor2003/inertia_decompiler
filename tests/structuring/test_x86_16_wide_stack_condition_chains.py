from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir.condition_ir import (
    ConditionIR,
    ConditionRegisterBindingIR,
)
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.semantic_cast import CSemanticCast8616
from inertia.lowering.wide_stack_pair_evidence import (
    materialize_proven_wide_stack_pair_variable_8616,
    proven_wide_stack_ir_pair_8616,
)
from archinfo import ArchX86

from inertia.structuring.local_wide_stack_condition_chains import (
    recover_local_wide_stack_condition_chain_8616,
)
from inertia.structuring.wide_stack_condition_chains import (
    reachable_wide_stack_conditions_8616,
    recover_wide_stack_condition_chain_8616,
)
from inertia.structuring.wide_stack_single_branches import (
    recover_wide_stack_single_body_condition_8616,
)


def _word(offset: int) -> IRValue:
    return IRValue(space=MemSpace.SS, name="bp", offset=offset, size=2)


def _condition(
    op: str,
    lhs: int,
    rhs: int,
    block: int,
    taken: int,
    fallthrough: int,
) -> ConditionIR:
    return ConditionIR(
        op=op,
        lhs=_word(lhs),
        rhs=_word(rhs),
        width_bits=16,
        source=("cmp", "jcc"),
        src_insn=block + 2,
        block_addr=block,
        taken_target=taken,
        fallthrough_target=fallthrough,
    )


def _adjacent(high: IRValue, low: IRValue) -> bool:
    return high.offset == low.offset + 2


class _Codegen:
    def __init__(self) -> None:
        self._ident = 0
        self._node_idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())

    def next_ident(self, prefix: str) -> str:
        self._ident += 1
        return f"{prefix}_{self._ident}"

    def next_node_idx(self) -> int:
        self._node_idx += 1
        return self._node_idx


def _stack_expression(
    codegen: _Codegen,
    offset: int,
    size: int,
    *,
    name: str,
    region: int = 0x1000,
) -> CVariable:
    return CVariable(
        SimStackVariable(offset, size, base="bp", name=name, region=region),
        codegen=codegen,
    )


def test_materializes_proven_wide_stack_pair_as_four_byte_variable() -> None:
    codegen = _Codegen()
    low = _stack_expression(codegen, -4, 2, name="goal_lo")
    high = _stack_expression(codegen, -2, 2, name="goal_hi")
    display_candidate = _stack_expression(codegen, -4, 2, name="goal")

    result = materialize_proven_wide_stack_pair_variable_8616(
        codegen,
        high,
        low,
        display_candidate,
    )

    assert result is not None
    assert isinstance(result.variable, SimStackVariable)
    assert result.variable.offset == -4
    assert result.variable.size == 4
    assert result.variable.name == "goal"
    assert result.variable.region == 0x1000


def test_wide_stack_pair_materialization_refuses_unproved_adjacency() -> None:
    codegen = _Codegen()
    low = _stack_expression(codegen, -4, 2, name="goal_lo", region=0x1000)
    high = _stack_expression(codegen, -2, 2, name="goal_hi", region=0x2000)

    result = materialize_proven_wide_stack_pair_variable_8616(
        codegen,
        high,
        low,
        low,
    )

    assert result is None


def test_wide_stack_pair_materialization_refuses_wrong_candidate_offset() -> None:
    codegen = _Codegen()
    low = _stack_expression(codegen, -4, 2, name="goal_lo")
    high = _stack_expression(codegen, -2, 2, name="goal_hi")
    wrong_candidate = _stack_expression(codegen, -6, 2, name="other")

    result = materialize_proven_wide_stack_pair_variable_8616(
        codegen,
        high,
        low,
        wrong_candidate,
    )

    assert result is None


def test_wide_stack_pair_accepts_low_owner_with_adjacent_high_slice() -> None:
    """A projected four-byte low owner proves its separate upper-word slice."""
    codegen = _Codegen()
    low_owner = _stack_expression(codegen, 10, 4, name="value")
    high_slice = _stack_expression(codegen, 12, 2, name="value_hi")
    low_projection = CBinaryOp(
        "And",
        low_owner,
        CConstant(0xFFFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    assert proven_wide_stack_ir_pair_8616(
        _word(14),
        _word(12),
        high_slice,
        low_projection,
    )
    unrelated_high = _stack_expression(
        codegen, 12, 2, name="other_hi", region=0x2000
    )
    assert not proven_wide_stack_ir_pair_8616(
        _word(14),
        _word(12),
        unrelated_high,
        low_projection,
    )


def test_wide_stack_pair_accepts_semantic_low_word_cast() -> None:
    """A required 32-to-16 cast proves the low slice of its stack owner."""
    codegen = _Codegen()
    low_owner = _stack_expression(codegen, 10, 4, name="value")
    high_slice = _stack_expression(codegen, 12, 2, name="value_hi")
    low_projection = CSemanticCast8616(
        SimTypeLong(False),
        SimTypeShort(False),
        low_owner,
        codegen=codegen,
    )

    assert proven_wide_stack_ir_pair_8616(
        _word(14),
        _word(12),
        high_slice,
        low_projection,
    )


def test_wide_stack_pair_refuses_non_word_semantic_cast() -> None:
    """Narrowing to a byte does not prove a complete low-word projection."""
    codegen = _Codegen()
    low_owner = _stack_expression(codegen, 10, 4, name="value")
    high_slice = _stack_expression(codegen, 12, 2, name="value_hi")
    byte_projection = CSemanticCast8616(
        SimTypeLong(False),
        SimTypeChar(False),
        low_owner,
        codegen=codegen,
    )

    assert not proven_wide_stack_ir_pair_8616(
        _word(14),
        _word(12),
        high_slice,
        byte_projection,
    )


def test_wide_stack_condition_chain_recovers_signed_less_equal() -> None:
    true_target = 0x1030
    false_target = 0x1040
    root = _condition("sle", 10, 6, 0x1000, 0x1010, false_target)
    equal_or_less = _condition("sge", 10, 6, 0x1010, 0x1020, true_target)
    low = _condition("ule", 8, 4, 0x1020, true_target, false_target)

    result = recover_wide_stack_condition_chain_8616(
        root,
        {0x1000: root, 0x1010: equal_or_less, 0x1020: low},
        {},
        true_target,
        false_target,
        _adjacent,
    )

    assert result.condition is not None
    assert result.condition.op == "sle"
    assert result.condition.width_bits == 32
    assert result.condition.lhs == IRValue(space=MemSpace.SS, name="bp", offset=8, size=4)
    assert result.condition.rhs == IRValue(space=MemSpace.SS, name="bp", offset=4, size=4)
    assert result.stats.materialized_count == 1


def test_wide_stack_condition_chain_propagates_one_proven_operand_pair() -> None:
    """One proven wide operand anchors its exhaustively checked comparison peer."""
    true_target = 0x1030
    false_target = 0x1040
    root = _condition("sle", 10, 6, 0x1000, 0x1010, false_target)
    equal_or_less = _condition("sge", 10, 6, 0x1010, 0x1020, true_target)
    low = _condition("ule", 8, 4, 0x1020, true_target, false_target)

    result = recover_wide_stack_condition_chain_8616(
        root,
        {0x1000: root, 0x1010: equal_or_less, 0x1020: low},
        {},
        true_target,
        false_target,
        lambda high, low: (high.offset, low.offset) == (10, 8),
    )

    assert result.condition is not None
    assert result.condition.op == "sle"
    assert result.condition.width_bits == 32


def test_wide_stack_condition_chain_refuses_missing_low_word_decision() -> None:
    root = _condition("sle", 10, 6, 0x1000, 0x1030, 0x1040)

    result = recover_wide_stack_condition_chain_8616(
        root,
        {0x1000: root},
        {},
        0x1030,
        0x1040,
        _adjacent,
    )

    assert result.condition is None
    assert result.stats.materialized_count == 0


def test_local_wide_stack_condition_stops_before_later_comparison() -> None:
    """A following independent predicate is outside the direct wide proof."""
    true_target = 0x1030
    false_target = 0x1040
    root = _condition("sle", 10, 6, 0x1000, 0x1010, false_target)
    equal_or_less = _condition("sge", 10, 6, 0x1010, 0x1020, true_target)
    low = _condition("ule", 8, 4, 0x1020, true_target, false_target)
    later = _condition("sgt", 22, 18, true_target, 0x1050, 0x1060)

    result = recover_local_wide_stack_condition_chain_8616(
        root,
        {
            0x1000: root,
            0x1010: equal_or_less,
            0x1020: low,
            true_target: later,
        },
        {},
        _adjacent,
    )

    assert result.condition is not None
    assert result.condition.op == "sle"
    assert result.true_target == true_target
    assert result.false_target == false_target
    assert result.consumed_conditions == (root, equal_or_less, low)


def test_local_wide_stack_condition_consumes_bound_register_high_word() -> None:
    """Alias-proven register storage keeps one wide comparison indivisible."""
    continue_target = 0x1030
    return_target = 0x1040
    register_high = IRValue(space=MemSpace.REG, name="dx", size=2)
    binding = (ConditionRegisterBindingIR("dx", _word(6)),)
    root = ConditionIR(
        op="sgt",
        lhs=register_high,
        rhs=_word(22),
        width_bits=16,
        block_addr=0x1000,
        taken_target=return_target,
        fallthrough_target=0x1010,
        producer_semantics=("cmp_reg_mem16", "dx", ("bp", 22, 22)),
        register_bindings=binding,
    )
    high_less = ConditionIR(
        op="slt",
        lhs=register_high,
        rhs=_word(22),
        width_bits=16,
        block_addr=0x1010,
        taken_target=continue_target,
        fallthrough_target=0x1020,
        producer_semantics=("cmp_reg_mem16", "dx", ("bp", 22, 22)),
        register_bindings=binding,
    )
    low = _condition("ugt", 4, 20, 0x1020, return_target, continue_target)

    result = recover_local_wide_stack_condition_chain_8616(
        root,
        {0x1000: root, 0x1010: high_less, 0x1020: low},
        {},
        _adjacent,
    )

    assert result.condition is not None
    assert result.condition.op == "sle"
    assert result.condition.lhs == IRValue(
        space=MemSpace.SS, name="bp", offset=4, size=4
    )
    assert result.condition.rhs == IRValue(
        space=MemSpace.SS, name="bp", offset=20, size=4
    )
    assert result.consumed_conditions == (root, high_less, low)


def test_reachable_conditions_do_not_compare_symbolic_operands() -> None:
    class SymbolicOperand:
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("CFG node traversal must not compare operands")

    second = ConditionIR(
        op="eq",
        lhs=SymbolicOperand(),
        rhs=0,
        block_addr=0x1010,
        taken_target=0x1020,
        fallthrough_target=0x1030,
    )
    root = ConditionIR(
        op="eq",
        lhs=SymbolicOperand(),
        rhs=0,
        block_addr=0x1000,
        taken_target=0x1010,
        fallthrough_target=0x1030,
    )

    result = reachable_wide_stack_conditions_8616(
        root,
        {0x1000: root, 0x1010: second},
        {},
    )

    assert len(result) == 2
    assert result[0] is root
    assert result[1] is second


def test_wide_stack_single_body_recovers_signed_less_than() -> None:
    true_target = 0x1030
    false_target = 0x1040
    root = _condition("slt", 10, 6, 0x1000, true_target, 0x1010)
    high_equal = _condition("eq", 10, 6, 0x1010, 0x1020, false_target)
    low = _condition("ult", 8, 4, 0x1020, true_target, false_target)

    result = recover_wide_stack_single_body_condition_8616(
        root,
        {0x1000: root, 0x1010: high_equal, 0x1020: low},
        {},
        _adjacent,
        lambda target: True if target == true_target else False if target == false_target else None,
    )

    assert result.condition is not None
    assert result.condition.op == "slt"
    assert result.condition.width_bits == 32


def test_wide_stack_single_body_recovers_low_then_high_equality() -> None:
    true_target = 0x1030
    false_target = 0x1040
    root = _condition("eq", 8, 4, 0x1000, 0x1010, false_target)
    high = _condition("eq", 10, 6, 0x1010, true_target, false_target)

    result = recover_wide_stack_single_body_condition_8616(
        root,
        {0x1000: root, 0x1010: high},
        {},
        _adjacent,
        lambda target: True if target == true_target else False if target == false_target else None,
    )

    assert result.condition is not None
    assert result.condition.op == "eq"
    assert result.condition.lhs.size == 4
    assert result.condition.rhs.size == 4


def test_wide_stack_single_body_refuses_unclassified_exit() -> None:
    root = _condition("slt", 10, 6, 0x1000, 0x1030, 0x1010)
    high_equal = _condition("eq", 10, 6, 0x1010, 0x1020, 0x1040)
    low = _condition("ult", 8, 4, 0x1020, 0x1030, 0x1040)

    result = recover_wide_stack_single_body_condition_8616(
        root,
        {0x1000: root, 0x1010: high_equal, 0x1020: low},
        {},
        _adjacent,
        lambda _target: None,
    )

    assert result.condition is None
    assert result.stats.failure_count == 1
