"""Tests for typed zero-index global-load replay after AST regeneration."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import MemSpace
import inertia.lowering.segmented_global_loads as segmented_global_loads
from inertia.lowering.segmented_global_loads import (
    DirectSegmentedGlobalLoadEvidence8616,
    materialize_named_segmented_global_loads_8616,
    recover_direct_segmented_global_load_evidence_8616,
)
from capstone import CS_AC_READ, CS_AC_WRITE
from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_CMP,
    X86_INS_MOV,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_ES,
    X86_REG_INVALID,
)

from inertia.structuring.simple_loop_recovery import InsnSummary8616


def _surface() -> tuple[object, object, CBinaryOp]:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
        project=project,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    direct_load = CVariable(
        SimMemoryVariable(0x44, 12, name="g_work"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expression = CBinaryOp(
        "Add",
        direct_load,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([expression], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        size=4,
        statements=root,
        body=root,
    )
    return project, codegen, expression


def _install_binary_evidence(
    monkeypatch: pytest.MonkeyPatch,
    *,
    space: MemSpace,
) -> None:
    summary = InsnSummary8616(
        mnemonic="add",
        op0_kind="reg",
        op0_value="ax",
        op0_size=2,
        op1_kind="direct_mem",
        op1_value=0x44,
        op1_size=2,
        address=0x4010,
    )
    load = DirectSegmentedGlobalLoadEvidence8616(
        offset=0x44,
        width=2,
        space=space,
        ins_addr=0x4010,
    )
    monkeypatch.setattr(
        segmented_global_loads,
        "_function_instruction_summaries_8616",
        lambda _project, _function: [summary],
    )
    monkeypatch.setattr(
        segmented_global_loads,
        "recover_direct_segmented_global_load_evidence_8616",
        lambda _project, _function: (load,),
    )
    monkeypatch.setattr(
        segmented_global_loads,
        "may_lower_codegen_access_to_entry_ds_object_8616",
        lambda *_args, instruction_addrs=frozenset(), **_kwargs: (
            space is MemSpace.DS and instruction_addrs == frozenset({0x4010})
        ),
    )


def _register_operand(*, access: int) -> SimpleNamespace:
    return SimpleNamespace(
        type=X86_OP_REG,
        access=access,
        reg=X86_REG_AX,
        size=2,
        imm=0,
        mem=None,
    )


def _memory_operand(
    displacement: int,
    *,
    access: int,
    segment: int = X86_REG_INVALID,
) -> SimpleNamespace:
    return SimpleNamespace(
        type=X86_OP_MEM,
        access=access,
        reg=X86_REG_INVALID,
        size=2,
        imm=0,
        mem=SimpleNamespace(
            segment=segment,
            base=X86_REG_INVALID,
            index=X86_REG_INVALID,
            disp=displacement,
        ),
    )


def _recover_load_evidence(*instructions: SimpleNamespace) -> tuple[DirectSegmentedGlobalLoadEvidence8616, ...]:
    project = SimpleNamespace(arch=Arch86_16())
    block = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    function = SimpleNamespace(blocks=(block,))
    return recover_direct_segmented_global_load_evidence_8616(project, function)


def test_exact_ds_load_rebuilds_zero_index_after_provenance_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, expression = _surface()
    _install_binary_evidence(monkeypatch, space=MemSpace.DS)

    assert materialize_named_segmented_global_loads_8616(
        project,
        codegen,
        {0x44: ("g_work", 12)},
    )
    assert isinstance(expression.lhs, CIndexedVariable)
    assert expression.lhs.variable.name == "g_work"
    assert expression.lhs.index.value == 0


def test_es_load_does_not_authorize_ds_array_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, expression = _surface()
    original = expression.lhs
    _install_binary_evidence(monkeypatch, space=MemSpace.ES)

    assert not materialize_named_segmented_global_loads_8616(
        project,
        codegen,
        {0x44: ("g_work", 12)},
    )
    assert expression.lhs is original


def test_direct_load_evidence_uses_decoder_read_access_for_alu_operands() -> None:
    add_load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_ADD,
        operands=(
            _register_operand(access=CS_AC_READ | CS_AC_WRITE),
            _memory_operand(0x44, access=CS_AC_READ),
        ),
    )
    cmp_es_load = SimpleNamespace(
        address=0x4014,
        id=X86_INS_CMP,
        operands=(
            _register_operand(access=CS_AC_READ),
            _memory_operand(0x46, access=CS_AC_READ, segment=X86_REG_ES),
        ),
    )

    assert _recover_load_evidence(add_load, cmp_es_load) == (
        DirectSegmentedGlobalLoadEvidence8616(0x44, 2, MemSpace.DS, 0x4010),
        DirectSegmentedGlobalLoadEvidence8616(0x46, 2, MemSpace.ES, 0x4014),
    )


def test_direct_load_evidence_refuses_write_only_memory_operand() -> None:
    store = SimpleNamespace(
        address=0x4020,
        id=X86_INS_MOV,
        operands=(
            _memory_operand(0x48, access=CS_AC_WRITE),
            _register_operand(access=CS_AC_READ),
        ),
    )

    assert _recover_load_evidence(store) == ()
