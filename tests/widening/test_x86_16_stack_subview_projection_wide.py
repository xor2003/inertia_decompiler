from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CTypeCast,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
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
OWNER_OFFSET = -8


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


def _stack_var(offset: int, size: int, name: str, codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimStackVariable(offset, size, base="bp", name=name, region=FUNCTION_ADDR),
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


def _attach_dword_proof(
    codegen: _DummyCodegen,
    views: tuple[tuple[int, int], ...],
) -> None:
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=FUNCTION_ADDR,
            blocks=(
                IRBlock(
                    addr=FUNCTION_ADDR,
                    instrs=(_store(_bp_slot(OWNER_OFFSET, 4)), *tuple(_load(_bp_slot(OWNER_OFFSET + offset, size)) for offset, size in views)),
                ),
            ),
        )
    )
    source = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    codegen._inertia_stack_memory_ssa_alias_artifact = source
    codegen._inertia_stack_memory_object_widening_artifact = (
        build_x86_16_stack_memory_object_widening_artifact(source)
    )


@pytest.mark.parametrize(
    ("view_size", "relative_offset", "expected_mask"),
    ((1, 0, 0xFF), (1, 3, 0xFF), (2, 0, 0xFFFF), (2, 1, 0xFFFF), (2, 2, 0xFFFF)),
)
def test_dword_stack_owner_projects_proven_scalar_reads(
    view_size: int,
    relative_offset: int,
    expected_mask: int,
) -> None:
    codegen = _DummyCodegen()
    owner = _stack_var(OWNER_OFFSET, 4, "owner", codegen)
    view = _stack_var(OWNER_OFFSET + relative_offset, view_size, "view", codegen)
    destination = CVariable(SimpleNamespace(name="inertia_ax"), codegen=codegen)
    assignment = CAssignment(destination, view, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={owner.variable: owner, view.variable: view},
    )
    _attach_dword_proof(codegen, ((relative_offset, view_size),))

    assert materialize_contained_stack_subviews_8616(codegen) is True
    assert isinstance(assignment.rhs, CBinaryOp) and assignment.rhs.op == "And"
    assert isinstance(assignment.rhs.rhs, CConstant) and assignment.rhs.rhs.value == expected_mask
    if relative_offset:
        shifted = assignment.rhs.lhs
        assert isinstance(shifted, CBinaryOp) and shifted.op == "Shr"
        assert isinstance(shifted.rhs, CConstant) and shifted.rhs.value == relative_offset * 8
    stats = codegen._inertia_stack_subview_last_stats_8616
    assert stats.raw_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0


def test_dword_stack_owner_projects_non_laminar_word_views() -> None:
    codegen = _DummyCodegen()
    owner = _stack_var(OWNER_OFFSET, 4, "owner", codegen)
    low_word = _stack_var(OWNER_OFFSET, 2, "low_word", codegen)
    shifted_word = _stack_var(OWNER_OFFSET + 1, 2, "shifted_word", codegen)
    low_assignment = CAssignment(
        CVariable(SimpleNamespace(name="inertia_ax"), codegen=codegen),
        low_word,
        codegen=codegen,
    )
    shifted_assignment = CAssignment(
        CVariable(SimpleNamespace(name="inertia_dx"), codegen=codegen),
        shifted_word,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([low_assignment, shifted_assignment], codegen=codegen),
        variables_in_use={
            owner.variable: owner,
            low_word.variable: low_word,
            shifted_word.variable: shifted_word,
        },
    )
    _attach_dword_proof(codegen, ((0, 2), (1, 2)))

    widening = codegen._inertia_stack_memory_object_widening_artifact
    assert widening.refusals == ()
    assert len(widening.candidates) == 1
    assert materialize_contained_stack_subviews_8616(codegen) is True
    assert isinstance(low_assignment.rhs, CBinaryOp) and low_assignment.rhs.op == "And"
    assert isinstance(shifted_assignment.rhs, CBinaryOp) and shifted_assignment.rhs.op == "And"
    shifted_owner = shifted_assignment.rhs.lhs
    assert isinstance(shifted_owner, CBinaryOp) and shifted_owner.op == "Shr"
    assert isinstance(shifted_owner.rhs, CConstant) and shifted_owner.rhs.value == 8
    stats = codegen._inertia_stack_subview_last_stats_8616
    assert stats.raw_fact_count == stats.materialized_count == 2
    assert stats.failure_count == 0


@pytest.mark.parametrize(
    ("view_size", "relative_offset", "preserved_mask", "view_mask"),
    (
        (1, 3, 0x00FFFFFF, 0xFF),
        (2, 1, 0xFF0000FF, 0xFFFF),
        (2, 2, 0x0000FFFF, 0xFFFF),
    ),
)
def test_dword_stack_owner_projects_pure_scalar_writes(
    view_size: int,
    relative_offset: int,
    preserved_mask: int,
    view_mask: int,
) -> None:
    codegen = _DummyCodegen()
    owner = _stack_var(OWNER_OFFSET, 4, "owner", codegen)
    view = _stack_var(OWNER_OFFSET + relative_offset, view_size, "view", codegen)
    assignment = CAssignment(view, _constant(7, codegen), codegen=codegen, tags={"ins_addr": 0x4030})
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={owner.variable: owner, view.variable: view},
    )
    _attach_dword_proof(codegen, ((relative_offset, view_size),))

    assert materialize_contained_stack_subviews_8616(codegen) is True
    projected = codegen.cfunc.statements.statements[0]
    assert isinstance(projected, CAssignment) and projected.tags == assignment.tags
    assert isinstance(projected.lhs, CVariable) and projected.lhs.variable is owner.variable
    assert isinstance(projected.rhs, CBinaryOp) and projected.rhs.op == "Or"
    preserved = projected.rhs.lhs
    assert isinstance(preserved, CBinaryOp) and preserved.op == "And"
    assert isinstance(preserved.rhs, CConstant) and preserved.rhs.value == preserved_mask
    inserted = projected.rhs.rhs
    assert isinstance(inserted, CBinaryOp) and inserted.op == "Shl"
    assert isinstance(inserted.rhs, CConstant) and inserted.rhs.value == relative_offset * 8
    assert isinstance(inserted.lhs, CBinaryOp) and inserted.lhs.op == "And"
    assert isinstance(inserted.lhs.rhs, CConstant) and inserted.lhs.rhs.value == view_mask


def test_dword_stack_owner_refuses_unsupported_three_byte_write() -> None:
    codegen = _DummyCodegen()
    owner = _stack_var(OWNER_OFFSET, 4, "owner", codegen)
    view = _stack_var(OWNER_OFFSET, 3, "view", codegen)
    assignment = CAssignment(view, _constant(7, codegen), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={owner.variable: owner, view.variable: view},
    )
    _attach_dword_proof(codegen, ((0, 3),))

    assert materialize_contained_stack_subviews_8616(codegen) is False
    assert codegen.cfunc.statements.statements[0] is assignment
    stats = codegen._inertia_stack_subview_last_stats_8616
    assert stats.raw_fact_count == stats.failure_count == 1
    assert stats.materialized_count == 0


def test_dword_stack_owner_projects_nested_rhs_view_before_owner_write() -> None:
    codegen = _DummyCodegen()
    owner = _stack_var(OWNER_OFFSET, 4, "owner", codegen)
    view = _stack_var(OWNER_OFFSET + 2, 2, "view", codegen)
    incremented = CBinaryOp("Add", view, _constant(1, codegen), codegen=codegen)
    assignment = CAssignment(view, incremented, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={owner.variable: owner, view.variable: view},
    )
    _attach_dword_proof(codegen, ((2, 2),))

    assert materialize_contained_stack_subviews_8616(codegen) is True
    projected = codegen.cfunc.statements.statements[0]
    assert isinstance(projected, CAssignment)
    assert isinstance(projected.rhs, CBinaryOp) and projected.rhs.op == "Or"
    inserted = projected.rhs.rhs
    assert isinstance(inserted, CBinaryOp) and inserted.op == "Shl"
    masked = inserted.lhs
    assert isinstance(masked, CBinaryOp) and masked.op == "And"
    assert isinstance(masked.lhs, CTypeCast)
    nested_rhs = masked.lhs.expr
    assert isinstance(nested_rhs, CBinaryOp) and nested_rhs.op == "Add"
    assert isinstance(nested_rhs.lhs, CBinaryOp) and nested_rhs.lhs.op == "And"
    stats = codegen._inertia_stack_subview_last_stats_8616
    assert stats.raw_fact_count == stats.materialized_count == 2
    assert stats.failure_count == 0


def test_dword_owner_never_replaces_word_recomposition() -> None:
    codegen = _DummyCodegen()
    owner = _stack_var(OWNER_OFFSET, 4, "owner", codegen)
    low = _stack_var(OWNER_OFFSET, 1, "low", codegen)
    high = _stack_var(OWNER_OFFSET + 1, 1, "high", codegen)
    recomposed = CBinaryOp(
        "Or",
        low,
        CBinaryOp("Shl", high, _constant(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    destination = CVariable(SimpleNamespace(name="inertia_ax"), codegen=codegen)
    assignment = CAssignment(destination, recomposed, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={owner.variable: owner, low.variable: low, high.variable: high},
    )
    _attach_dword_proof(codegen, ((0, 1), (1, 1)))

    assert materialize_contained_stack_subviews_8616(codegen) is True
    assert isinstance(assignment.rhs, CBinaryOp) and assignment.rhs.op == "Or"
    assert not isinstance(assignment.rhs, CVariable)
    stats = codegen._inertia_stack_subview_last_stats_8616
    assert stats.failure_count == 1
    assert stats.materialized_count == 2
