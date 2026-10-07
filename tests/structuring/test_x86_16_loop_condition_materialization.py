"""Focused tests for typed loop continuation materialization."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CForLoop,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import (
    ConditionIR,
    ConditionRegisterBindingIR,
    ConditionRegisterUpdateIR,
)
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace

from inertia.structuring.loop_condition_materialization import (
    materialize_typed_loop_continuation_conditions_8616,
)


class _Codegen:
    """Minimal angr structured-C codegen fixture."""

    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return one deterministic structured-C node index."""
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _loop_fixture() -> tuple[_Codegen, CForLoop, CStatements, ConditionIR]:
    """Build one loop whose JCC fallthrough edge is the continuation."""
    codegen = _Codegen()
    value_type = SimTypeShort(True).with_arch(codegen.project.arch)
    condition = CBinaryOp(
        "CmpGE",
        CConstant(1, value_type, codegen=codegen),
        CConstant(4, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10126, "vex_block_addr": 0x10120},
    )
    loop = CForLoop(
        None,
        condition,
        None,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    typed = ConditionIR(
        op="sge",
        lhs=1,
        rhs=4,
        src_insn=0x10126,
        block_addr=0x10120,
        taken_target=0x1012B,
        fallthrough_target=0x10128,
    )
    return codegen, loop, root, typed


def test_materializes_inverted_fallthrough_loop_continuation() -> None:
    """The loop guard must use the edge that returns to the condition block."""
    codegen, loop, root, typed = _loop_fixture()
    successors = {0x10128: (0x10093,), 0x10093: (0x10120,), 0x1012B: ()}

    def lower_condition(_condition: ConditionIR) -> CBinaryOp:
        return CBinaryOp(
            "CmpGE",
            CConstant(1, SimTypeShort(True), codegen=codegen),
            CConstant(4, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lower_condition,
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.changed_count == 1
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpLT"
    assert loop.condition.tags["inertia_typed_loop_condition_key_8616"] == (0x10126, 0x10120)
    assert loop.condition.tags["inertia_typed_loop_continuation_edge_8616"] == "fallthrough"

    repeated = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lower_condition,
    )
    assert repeated.materialized_count == 1
    assert repeated.changed_count == 0


def test_materializes_bound_word_update_before_high_byte_loop_condition() -> None:
    """A projected byte guard must retain its Alias-proven word update."""
    codegen = _Codegen()
    value_type = SimTypeShort(False).with_arch(codegen.project.arch)
    bx_offset, bx_size = codegen.project.arch.registers["bx"]
    prior = CVariable(
        SimRegisterVariable(bx_offset, bx_size, ident="ir_5", region=0x1000, name="bx"),
        variable_type=value_type,
        codegen=codegen,
    )
    initialized = CVariable(
        SimRegisterVariable(bx_offset, bx_size, ident="ir_6", region=0x1000, name="bx"),
        variable_type=value_type,
        codegen=codegen,
    )
    initializer = CAssignment(
        initialized,
        CBinaryOp("Xor", prior, prior, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1000, "vex_block_addr": 0x1000},
    )
    current = CBinaryOp(
        "CmpLT",
        CVariable(
            SimRegisterVariable(bx_offset + 1, 1, ident="bh", region=0x1000, name="bh"),
            codegen=codegen,
        ),
        CConstant(0x40, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1012, "vex_block_addr": 0x100D},
    )
    body = CStatements([], codegen=codegen, tags={"vex_block_addr": 0x0FFE})
    loop = CForLoop(None, current, None, body, codegen=codegen)
    later_use = CVariable(
        SimRegisterVariable(bx_offset, bx_size, ident="ir_6", region=0x1000, name="bx"),
        variable_type=value_type,
        codegen=codegen,
    )
    later_return = CReturn(later_use, codegen=codegen)
    root = CStatements([initializer, loop, later_return], codegen=codegen)
    target = IRValue(MemSpace.REG, name="bx", size=2)
    stride = IRValue(MemSpace.CONST, const=0x16C, size=2)
    update = ConditionRegisterUpdateIR(0x100D, "bx", "add", stride)
    projected = IRBinaryValue(
        "and",
        IRBinaryValue(
            "shr",
            IRBinaryValue("add", target, stride, size=2),
            IRValue(MemSpace.CONST, const=8, size=2),
            size=2,
        ),
        IRValue(MemSpace.CONST, const=0xFF, size=2),
        size=1,
    )
    typed = ConditionIR(
        op="ult",
        lhs=IRValue(MemSpace.REG, name="bh", size=1),
        rhs=IRValue(MemSpace.CONST, const=0x40, size=1),
        width_bits=8,
        src_insn=0x1012,
        block_addr=0x100D,
        producer_insn=0x100F,
        taken_target=0x0FFE,
        fallthrough_target=0x1014,
        register_bindings=(ConditionRegisterBindingIR("bh", projected, update),),
    )

    def lower_condition(lowered: ConditionIR) -> CBinaryOp:
        binding = lowered.register_bindings[0].value
        assert isinstance(binding, IRBinaryValue)
        assert isinstance(binding.lhs, IRBinaryValue)
        assert isinstance(binding.lhs.lhs, IRValue)
        register = CVariable(
            SimRegisterVariable(bx_offset, bx_size, ident="anonymous", region=0x1000, name="bx"),
            codegen=codegen,
        )
        return CBinaryOp(
            "CmpLT",
            CBinaryOp(
                "And",
                CBinaryOp(
                    "Shr",
                    register,
                    CConstant(8, value_type, codegen=codegen),
                    codegen=codegen,
                ),
                CConstant(0xFF, value_type, codegen=codegen),
                codegen=codegen,
            ),
            CConstant(0x40, value_type, codegen=codegen),
            codegen=codegen,
        )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {0x0FFE: (0x100D,), 0x1014: ()},
        lower_condition,
    )

    assert stats.counter_update_materialized_count == 1
    assert isinstance(initializer.rhs, CConstant)
    assert initializer.rhs.value == 0
    assert len(body.statements) == 1
    materialized_update = body.statements[0]
    assert isinstance(materialized_update, CAssignment)
    assert materialized_update.lhs.variable.ident == "inertia-register-bx"
    assert isinstance(materialized_update.rhs, CBinaryOp)
    assert materialized_update.rhs.op == "Add"
    assert materialized_update.rhs.rhs.value == 0x16C
    assert isinstance(loop.condition, CBinaryOp)
    projected_register = loop.condition.lhs.lhs.lhs
    assert isinstance(projected_register, CVariable)
    assert projected_register.variable.ident == "inertia-register-bx"
    assert isinstance(later_return.retval, CVariable)
    assert later_return.retval.variable.ident == "inertia-register-bx"


def test_refuses_ambiguous_loop_continuation_polarity() -> None:
    """No condition is replaced when both JCC edges can return to the header."""
    codegen, loop, root, typed = _loop_fixture()
    original = loop.condition
    successors = {
        0x10128: (0x10120,),
        0x1012B: (0x10120,),
    }

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lambda _condition: None,
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.changed is False
    assert loop.condition is original
    assert loop.condition.tags.get("inertia_typed_loop_condition_bound_8616") is not True


def test_linear_jump_trampoline_preserves_nested_loop_edge_ownership() -> None:
    """A jump-only latch block must retain the inner loop's continuation edge."""
    codegen, loop, root, typed = _loop_fixture()
    loop.body.tags = {"vex_block_addr": 0x10100}
    successors = {
        0x10128: (0x10100,),
        0x10100: (0x10120,),
        0x1012B: (0x10080,),
        0x10080: (0x10090, 0x100A0),
    }

    def lower_condition(_condition: ConditionIR) -> CBinaryOp:
        return CBinaryOp(
            "CmpGE",
            CConstant(1, SimTypeShort(True), codegen=codegen),
            CConstant(4, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lower_condition,
    )

    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpLT"
    assert loop.condition.tags["inertia_typed_loop_continuation_edge_8616"] == "fallthrough"


def test_nested_loop_uses_structured_body_ownership_when_both_edges_return() -> None:
    """An outer-loop re-entry must not make an inner-loop edge ambiguous."""
    codegen, loop, root, typed = _loop_fixture()
    loop.body.tags = {"vex_block_addr": 0x1012B}
    successors = {
        0x10128: (0x10080,),
        0x10080: (0x10120,),
        0x1012B: (0x10120,),
    }

    def lower_condition(_condition: ConditionIR) -> CBinaryOp:
        return CBinaryOp(
            "CmpGE",
            CConstant(1, SimTypeShort(True), codegen=codegen),
            CConstant(4, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lower_condition,
    )

    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpGE"
    assert loop.condition.tags["inertia_typed_loop_continuation_edge_8616"] == "taken"


def test_composite_loop_exit_owns_root_loop_condition_fact() -> None:
    """A proven condition-chain exit must consume its root JCC before it becomes a break."""
    codegen, loop, root, typed = _loop_fixture()
    original = loop.condition
    composite = CBinaryOp(
        "CmpGT",
        CConstant(5, SimTypeShort(True), codegen=codegen),
        CConstant(4, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x10126,
            "vex_block_addr": 0x10120,
            "inertia_structuring_shared_body_condition_chain_materialized_8616": True,
            "inertia_structuring_shared_body_target_8616": 0x1012B,
        },
    )
    guard = CIfElse(
        [
            (
                composite,
                CStatements([CReturn(None, codegen=codegen)], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    loop.body = CStatements([guard], codegen=codegen)

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {0x10128: (0x10120,), 0x1012B: ()},
        lambda _condition: (_ for _ in ()).throw(
            AssertionError("body-owned condition was lowered twice")
        ),
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.changed_count == 0
    assert stats.composite_loop_exit_owned_count == 1
    assert loop.condition is original


def test_nested_composite_exit_does_not_own_outer_loop_condition() -> None:
    """A nested loop's condition chain must not consume the outer loop's header fact."""
    codegen, loop, root, typed = _loop_fixture()
    original_outer_condition = loop.condition
    composite = CBinaryOp(
        "CmpGT",
        CConstant(5, SimTypeShort(True), codegen=codegen),
        CConstant(4, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x10126,
            "vex_block_addr": 0x10120,
            "inertia_structuring_shared_body_condition_chain_materialized_8616": True,
            "inertia_structuring_shared_body_target_8616": 0x1012B,
        },
    )
    nested_guard = CIfElse(
        [(composite, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )
    nested_loop = CForLoop(
        None,
        CConstant(1, SimTypeShort(True), codegen=codegen),
        None,
        CStatements([nested_guard], codegen=codegen),
        codegen=codegen,
    )
    loop.body = CStatements([nested_loop], codegen=codegen)

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {0x10128: (0x10120,), 0x1012B: ()},
        lambda _condition: CBinaryOp(
            "CmpGE",
            CConstant(1, SimTypeShort(True), codegen=codegen),
            CConstant(4, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        ),
    )

    assert stats.composite_loop_exit_owned_count == 1
    assert stats.changed_count == 1
    assert loop.condition is not original_outer_condition


def test_ifbreak_projection_retains_composite_loop_exit_ownership() -> None:
    """Converting the proven exit to CIfBreak must preserve root-JCC ownership."""
    codegen, loop, root, typed = _loop_fixture()
    original = loop.condition
    composite = CBinaryOp(
        "CmpGT",
        CConstant(5, SimTypeShort(True), codegen=codegen),
        CConstant(4, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x10126,
            "vex_block_addr": 0x10120,
            "inertia_structuring_shared_body_condition_chain_materialized_8616": True,
            "inertia_structuring_shared_body_target_8616": 0x1012B,
        },
    )
    loop.body = CStatements([CIfBreak(composite, codegen=codegen)], codegen=codegen)

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {0x10128: (0x10120,), 0x1012B: ()},
        lambda _condition: (_ for _ in ()).throw(
            AssertionError("projected body-owned condition was lowered twice")
        ),
    )

    assert stats.composite_loop_exit_owned_count == 1
    assert stats.changed_count == 0
    assert loop.condition is original


def test_reentering_composite_target_does_not_own_loop_exit() -> None:
    """A shared target that reaches the loop header is not a loop exit."""
    codegen, loop, root, typed = _loop_fixture()
    composite = CBinaryOp(
        "CmpGT",
        CConstant(5, SimTypeShort(True), codegen=codegen),
        CConstant(4, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x10126,
            "vex_block_addr": 0x10120,
            "inertia_structuring_shared_body_condition_chain_materialized_8616": True,
            "inertia_structuring_shared_body_target_8616": 0x10128,
        },
    )
    loop.body = CStatements(
        [
            CIfElse(
                [(composite, CStatements([], codegen=codegen))],
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {0x10128: (0x10120,), 0x1012B: ()},
        lambda _condition: CBinaryOp(
            "CmpGE",
            CConstant(1, SimTypeShort(True), codegen=codegen),
            CConstant(4, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        ),
    )

    assert stats.composite_loop_exit_owned_count == 0
    assert stats.changed_count == 1


def test_plain_loop_binds_dirty_counter_read_for_nonunit_stride() -> None:
    """A typed loop binds its exact dirty register read for stride two."""
    codegen = _Codegen()
    value_type = SimTypeShort(False).with_arch(codegen.project.arch)
    counter_variable = SimRegisterVariable(
        4,
        2,
        ident="inertia-register-cx",
        region=0x1106F,
        name="cx",
    )
    counter = CVariable(counter_variable, variable_type=value_type, codegen=codegen)
    decrement = CAssignment(
        counter,
        CBinaryOp(
            "Sub",
            CDirtyExpression(SimpleNamespace(varid=1), codegen=codegen),
            CConstant(2, value_type, codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x1107C, "vex_block_addr": 0x1107B},
    )
    body = CStatements([decrement], codegen=codegen, tags={"vex_block_addr": 0x1107B})
    loop = CForLoop(None, counter, None, body, codegen=codegen)
    root = CStatements([loop], codegen=codegen)
    typed = ConditionIR(
        op="nonzero",
        lhs=IRValue(MemSpace.REG, name="cx", size=2),
        source=("loop",),
        src_insn=0x1107C,
        block_addr=0x1107B,
        taken_target=0x1107B,
        fallthrough_target=0x1107E,
    )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {0x1107B: (0x1107B, 0x1107E), 0x1107E: ()},
        lambda _condition: CBinaryOp(
            "CmpNE",
            counter,
            CConstant(0, value_type, codegen=codegen),
            codegen=codegen,
        ),
    )

    assert stats.counter_update_materialized_count == 1
    assert isinstance(decrement.rhs, CBinaryOp)
    assert isinstance(decrement.rhs.lhs, CVariable)
    assert decrement.rhs.lhs.variable.ident == "inertia-register-cx"
