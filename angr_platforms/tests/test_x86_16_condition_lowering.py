from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.c_ast_utils import _iter_c_nodes_deep_8616
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import (
    SEGMENTED_LOAD_ADDRESS_TAG_8616,
    IRCondition,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.structuring.condition_lowering import (
    condition_origin_tags_8616,
    lower_ir_value_to_c_expr_8616,
)
from angr_platforms.X86_16.structuring.condition_materialization import (
    materialize_condition_ir_expression_8616,
)

INDEXED_DATA_OFFSET = 0xB4C

class _Codegen:
    def __init__(self, project):
        self._next_idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name):
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_condition_origin_tags_preserve_branch_provenance():
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.SS, name="bp", offset=4, size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x100F,
        block_addr=0x1009,
        producer_insn=0x100B,
    )

    assert condition_origin_tags_8616(condition) == {
        "typed_condition": True,
        "ins_addr": 0x100F,
        "vex_block_addr": 0x1009,
        "condition_producer_insn": 0x100B,
    }


def test_condition_origin_tags_keep_ircondition_fallback_minimal():
    condition = IRCondition(
        op="ne",
        args=(
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.CONST, const=0, size=2),
        ),
    )

    assert condition_origin_tags_8616(condition) == {"typed_condition": True}


@pytest.mark.parametrize("load_address", [0x1030, None])
def test_stack_condition_keeps_operand_provenance_distinct_from_branch(load_address):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.SS, name="bp", offset=-2, size=2,
                    memory_access_size=2, memory_access_insn=load_address),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x1043,
        block_addr=0x1030,
        producer_insn=0x1040,
    )
    expression = materialize_condition_ir_expression_8616(project, codegen, condition)
    assert expression is not None
    assert expression.tags["ins_addr"] == condition.src_insn
    if load_address is None:
        assert "inertia_source_instruction_addrs" not in expression.lhs.tags
    else:
        assert expression.lhs.tags["inertia_source_instruction_addrs"] == (load_address,)


def test_materialized_segmented_condition_preserves_operand_access_provenance():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    condition = ConditionIR(
        op="sle",
        lhs=IRValue(
            MemSpace.DS,
            offset=0x134,
            size=2,
            memory_access_insn=0x103E,
        ),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x1043,
        block_addr=0x103E,
        producer_insn=0x1040,
    )

    expression = materialize_condition_ir_expression_8616(project, codegen, condition)

    assert expression is not None
    helpers = [
        node
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall)
        and SEGMENTED_LOAD_ADDRESS_TAG_8616 in node.tags
    ]
    assert len(helpers) == 1
    assert helpers[0].tags["inertia_source_instruction_addrs"] == (0x103E,)


@pytest.mark.parametrize("load_address", [0x1030, None])
def test_direct_stack_value_lowering_preserves_only_supplied_provenance(load_address):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    operand = IRValue(MemSpace.SS, name="bp", offset=-2, size=2,
                      memory_access_insn=load_address)
    expression = lower_ir_value_to_c_expr_8616(operand, project, codegen)
    assert expression is not None
    expected = () if load_address is None else (load_address,)
    assert expression.tags.get("inertia_source_instruction_addrs", ()) == expected


def test_materialized_segmented_condition_refuses_branch_only_provenance():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    condition = ConditionIR(
        op="sle",
        lhs=IRValue(MemSpace.DS, offset=0x134, size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x1043,
        block_addr=0x103E,
        producer_insn=0x1040,
    )

    expression = materialize_condition_ir_expression_8616(project, codegen, condition)

    assert expression is not None
    helper = next(
        node
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall)
        and SEGMENTED_LOAD_ADDRESS_TAG_8616 in node.tags
    )
    assert "inertia_source_instruction_addrs" not in helper.tags


def test_materialized_indexed_segmented_condition_keeps_address_and_access():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    condition = ConditionIR(
        op="sgt",
        lhs=IRValue(
            MemSpace.DS,
            offset=INDEXED_DATA_OFFSET,
            size=1,
            index=IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
            index_shift=1,
            memory_access_size=1,
            memory_access_insn=0x10AC8,
        ),
        rhs=IRValue(MemSpace.CONST, const=0, size=1),
        src_insn=0x10ACB,
        block_addr=0x10AC8,
        producer_insn=0x10AC9,
    )

    expression = materialize_condition_ir_expression_8616(project, codegen, condition)

    assert expression is not None
    helper = next(
        node
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall)
        and SEGMENTED_LOAD_ADDRESS_TAG_8616 in node.tags
    )
    address = helper.tags[SEGMENTED_LOAD_ADDRESS_TAG_8616]
    assert address.offset == INDEXED_DATA_OFFSET
    assert address.size == 1
    assert helper.tags["inertia_source_instruction_addrs"] == (0x10AC8,)
