"""Tests for identity-based Structuring condition evidence closure."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace

from inertia.structuring.condition_chain_provenance import (
    bind_condition_chain_provenance_8616,
)
from inertia.structuring.condition_evidence_closure import (
    classify_condition_evidence_closure_8616,
)


def _condition(src_insn: int, block_addr: int) -> ConditionIR:
    """Build one minimal exact typed branch condition."""
    return ConditionIR(
        op="eq",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        width_bits=16,
        source=("cmp", "je"),
        src_insn=src_insn,
        block_addr=block_addr,
        taken_target=block_addr + 4,
        fallthrough_target=block_addr + 2,
    )


def _codegen() -> SimpleNamespace:
    """Build the minimal third-party structured-codegen test boundary."""
    return SimpleNamespace(
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=Arch86_16()),
    )


def _if_node(
    *,
    instruction_addr: int,
    block_addr: int,
    materialized: bool,
) -> CIfElse:
    """Build one tagged structured condition owner."""
    codegen = _codegen()
    tags: dict[str, object] = {
        "ins_addr": instruction_addr,
        "vex_block_addr": block_addr,
    }
    if materialized:
        tags["inertia_structuring_condition_cfg_materialized_8616"] = True
    expression = CConstant(1, SimTypeShort(False), codegen=codegen, tags=tags)
    return CIfElse(
        [(expression, CStatements([], codegen=codegen))],
        None,
        codegen=codegen,
        tags=tags,
    )


def test_condition_evidence_closure_accepts_materialized_typed_branch() -> None:
    """A final AST owner with the same JCC/block key closes its typed fact."""
    condition = _condition(0x101B0, 0x101A9)
    root = CStatements(
        [_if_node(instruction_addr=0x101B0, block_addr=0x101A9, materialized=True)],
        codegen=_codegen(),
    )

    result = classify_condition_evidence_closure_8616(
        root,
        (condition,),
        {0x101A9: (0x101B2, 0x101B5)},
    )

    assert result.complete is True


def test_condition_evidence_closure_accepts_complete_composite_provenance() -> None:
    """One compound AST guard closes every exact JCC it consumed."""
    first = _condition(0x101B0, 0x101A9)
    second = _condition(0x101C0, 0x101B2)
    owner = _if_node(
        instruction_addr=first.src_insn,
        block_addr=first.block_addr,
        materialized=True,
    )
    expression = owner.condition_and_nodes[0][0]
    assert bind_condition_chain_provenance_8616(expression, (first, second)) is not None
    root = CStatements([owner], codegen=_codegen())

    result = classify_condition_evidence_closure_8616(
        root,
        (first, second),
        {0x101A9: (0x101B2, 0x101B5), 0x101B2: (0x101C2, 0x101C5)},
    )

    assert result.complete is True
    assert result.materialized_keys == result.required_keys


def test_condition_evidence_closure_refuses_untyped_binary_cfg_owner() -> None:
    """A real two-successor branch without ConditionIR remains unclosed."""
    root = CStatements(
        [_if_node(instruction_addr=0x2002, block_addr=0x2000, materialized=False)],
        codegen=_codegen(),
    )

    result = classify_condition_evidence_closure_8616(
        root,
        (),
        {0x2000: (0x2010, 0x2020)},
    )

    assert result.complete is False
    assert result.unresolved_branch_owners == frozenset({0x2000})


def test_condition_evidence_closure_ignores_single_successor_flag_ite() -> None:
    """An internal flag ITE at a non-branch instruction does not block DCE."""
    root = CStatements(
        [_if_node(instruction_addr=0x101D2, block_addr=0x101D2, materialized=False)],
        codegen=_codegen(),
    )

    result = classify_condition_evidence_closure_8616(
        root,
        (),
        {0x101D2: (0x101D5,)},
    )

    assert result.complete is True
