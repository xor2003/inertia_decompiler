from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.structuring.decompiler_structuring_stage import DECOMPILER_STRUCTURING_PASSES
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.pipeline.errors import PipelineHardError

from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.widening.stack_memory_objects import (
    build_x86_16_stack_memory_object_widening_artifact,
)
from inertia.widening.stack_subview_projection import (
    materialize_contained_stack_subviews_8616,
)

FUNCTION_ADDR = 0x4010


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cfunc: SimpleNamespace | None = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _constant(value: int, codegen: _DummyCodegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _stack_var(
    offset: int,
    size: int,
    name: str,
    codegen: _DummyCodegen,
    *,
    region: int = FUNCTION_ADDR,
) -> CVariable:
    return CVariable(
        SimStackVariable(offset, size, base="bp", name=name, region=region),
        codegen=codegen,
    )


def _bp_slot(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def _store(address: IRAddress) -> IRInstr:
    return IRInstr(
        "STORE",
        None,
        (address, IRValue(MemSpace.CONST, const=1, size=address.size)),
        size=address.size,
    )


def _load(address: IRAddress) -> IRInstr:
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.REG, name="ax", size=address.size),
        (address,),
        size=address.size,
    )


def _attach_word_proof(
    codegen: _DummyCodegen,
    offset: int,
    *,
    view_offsets: tuple[int, ...] = (1,),
) -> None:
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=FUNCTION_ADDR,
            blocks=(
                IRBlock(
                    addr=FUNCTION_ADDR,
                    instrs=(_store(_bp_slot(offset, 2)), *tuple(_load(_bp_slot(offset + delta, 1)) for delta in view_offsets)),
                ),
            ),
        )
    )
    source = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    codegen._inertia_stack_memory_ssa_alias_artifact = source
    codegen._inertia_stack_memory_object_widening_artifact = (
        build_x86_16_stack_memory_object_widening_artifact(source)
    )


def _word_recomposition(
    low: CVariable,
    high: CVariable,
    codegen: _DummyCodegen,
    *,
    shift: int = 8,
) -> CBinaryOp:
    return CBinaryOp(
        "Or",
        low,
        CBinaryOp("Shl", high, _constant(shift, codegen), codegen=codegen),
        codegen=codegen,
    )


def test_stack_subview_projection_materializes_current_widening_owner() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    high_byte = _stack_var(-3, 1, "local_3", codegen)
    recomposed = _word_recomposition(word, high_byte, codegen)
    assignment = CAssignment(
        word,
        CBinaryOp("Add", recomposed, _constant(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, high_byte.variable: high_byte},
    )
    _attach_word_proof(codegen, -4)

    changed = materialize_contained_stack_subviews_8616(codegen)

    assert changed is True
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert isinstance(assignment.rhs.lhs, CVariable)
    assert assignment.rhs.lhs.variable is word.variable
    assert codegen._inertia_stack_subview_last_stats_8616.materialized_count == 1
    assert codegen._inertia_stack_subview_last_stats_8616.failure_count == 0


def test_stack_subview_projection_resolves_adjacent_bytes_to_unique_owner() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-6, 2, "local_6", codegen)
    low_byte = _stack_var(-6, 1, "local_6_low", codegen)
    high_byte = _stack_var(-5, 1, "local_5", codegen)
    recomposed = _word_recomposition(low_byte, high_byte, codegen)
    destination = CVariable(SimpleNamespace(name="inertia_es"), codegen=codegen)
    assignment = CAssignment(destination, recomposed, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, low_byte.variable: low_byte, high_byte.variable: high_byte},
    )
    _attach_word_proof(codegen, -6)

    changed = materialize_contained_stack_subviews_8616(codegen)

    assert changed is True
    assert isinstance(assignment.rhs, CVariable)
    assert assignment.rhs.variable is word.variable


def test_stack_subview_projection_refuses_wrong_region_and_scale() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    wrong_region_high = _stack_var(-3, 1, "local_3", codegen, region=0x5000)
    correct_high = _stack_var(-3, 1, "local_3", codegen)
    wrong_region = _word_recomposition(word, wrong_region_high, codegen)
    wrong_scale = _word_recomposition(word, correct_high, codegen, shift=7)
    first = CAssignment(word, wrong_region, codegen=codegen)
    second = CAssignment(word, wrong_scale, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([first, second], codegen=codegen),
        variables_in_use={word.variable: word, correct_high.variable: correct_high},
    )
    _attach_word_proof(codegen, -4)

    changed = materialize_contained_stack_subviews_8616(codegen)

    assert changed is True
    assert first.rhs is wrong_region
    assert second.rhs is wrong_scale
    stats = codegen._inertia_stack_subview_last_stats_8616
    assert stats.raw_fact_count == 3
    assert stats.failure_count == 2
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 1


def test_stack_subview_projection_refuses_syntax_without_widening_proof() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    high_byte = _stack_var(-3, 1, "local_3", codegen)
    recomposed = _word_recomposition(word, high_byte, codegen)
    assignment = CAssignment(word, recomposed, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, high_byte.variable: high_byte},
    )

    assert materialize_contained_stack_subviews_8616(codegen) is False
    assert assignment.rhs is recomposed
    assert codegen._inertia_stack_subview_last_stats_8616.failure_count == 1


def test_stack_subview_projection_rejects_stale_widening_artifact() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    high_byte = _stack_var(-3, 1, "local_3", codegen)
    assignment = CAssignment(word, _word_recomposition(word, high_byte, codegen), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, high_byte.variable: high_byte},
    )
    _attach_word_proof(codegen, -4)
    current_source = codegen._inertia_stack_memory_ssa_alias_artifact
    _attach_word_proof(codegen, -8)
    codegen._inertia_stack_memory_ssa_alias_artifact = current_source

    with pytest.raises(PipelineHardError, match="current complete Widening artifact"):
        materialize_contained_stack_subviews_8616(codegen)


def test_stack_subview_projection_does_not_rewrite_assignment_lvalue() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    high_byte = _stack_var(-3, 1, "local_3", codegen)
    recomposed_lvalue = _word_recomposition(word, high_byte, codegen)
    assignment = CAssignment(recomposed_lvalue, _constant(1, codegen), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, high_byte.variable: high_byte},
    )
    _attach_word_proof(codegen, -4)

    assert materialize_contained_stack_subviews_8616(codegen) is False
    assert assignment.lhs is recomposed_lvalue
    assert codegen._inertia_stack_subview_last_stats_8616.raw_fact_count == 0


@pytest.mark.parametrize("context", ["read", "Reference", "AddressOf"])
def test_stack_subview_projection_distinguishes_value_and_address(context: str) -> None:
    for relative_offset in (0, 1):
        codegen = _DummyCodegen()
        word = _stack_var(-4, 2, "local_4", codegen)
        byte = _stack_var(-4 + relative_offset, 1, "byte_view", codegen)
        destination = CVariable(SimpleNamespace(name="inertia_ax"), codegen=codegen)
        rhs = byte if context == "read" else CUnaryOp(context, byte, codegen=codegen)
        assignment = CAssignment(destination, rhs, codegen=codegen)
        codegen.cfunc = SimpleNamespace(
            addr=FUNCTION_ADDR,
            statements=CStatements([assignment], codegen=codegen),
            variables_in_use={word.variable: word, byte.variable: byte},
        )
        _attach_word_proof(codegen, -4, view_offsets=(relative_offset,))

        changed = materialize_contained_stack_subviews_8616(codegen)
        if context != "read":
            assert changed is False
            assert assignment.rhs.operand is byte
            assert codegen._inertia_stack_subview_last_stats_8616.raw_fact_count == 0
            continue
        assert changed is True
        assert isinstance(assignment.rhs, CBinaryOp) and assignment.rhs.op == "And"
        if relative_offset:
            assert isinstance(assignment.rhs.lhs, CBinaryOp) and assignment.rhs.lhs.op == "Shr"


@pytest.mark.parametrize(("relative_offset", "side_effecting"), ((0, False), (1, False), (1, True)))
def test_stack_subview_projection_materializes_only_safe_direct_writes(
    relative_offset: int,
    side_effecting: bool,
) -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    byte = _stack_var(-4 + relative_offset, 1, "byte_view", codegen)
    rhs = (
        CFunctionCall("callee", SimpleNamespace(addr=0x5000, name="callee"), [], codegen=codegen)
        if side_effecting
        else _constant(7, codegen)
    )
    assignment = CAssignment(byte, rhs, codegen=codegen, tags={"ins_addr": 0x4020})
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, byte.variable: byte},
    )
    _attach_word_proof(codegen, -4, view_offsets=(relative_offset,))

    changed = materialize_contained_stack_subviews_8616(codegen)

    projected = codegen.cfunc.statements.statements[0]
    assert changed is not side_effecting
    if side_effecting:
        assert projected is assignment
        assert codegen._inertia_stack_subview_last_stats_8616.failure_count == 1
    else:
        assert isinstance(projected, CAssignment) and projected.tags == assignment.tags
        assert isinstance(projected.lhs, CVariable) and projected.lhs.variable is word.variable
        assert isinstance(projected.rhs, CBinaryOp) and projected.rhs.op == "Or"


def test_stack_subview_projection_declared_after_object_widening() -> None:
    names = tuple(spec.name for spec in DECOMPILER_STRUCTURING_PASSES)

    assert names.index("_stack_memory_object_widening_artifact") < names.index(
        "_widening_copy_propagation_8616"
    )
