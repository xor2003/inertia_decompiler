from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CForLoop, CFunctionCall, CStatements
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import SEGMENTED_LOAD_ADDRESS_TAG_8616, IRValue, MemSpace

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.structuring.condition_materialization import (
    materialize_condition_ir_expression_8616,
)
from inertia.structuring.condition_provenance import (
    replay_codegen_structured_condition_segment_provenance_8616,
    transport_structured_condition_segment_provenance_8616,
)
from inertia.widening.segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_tags_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _loop_condition_fixture(
    *,
    memory_access_insn: int | None,
) -> tuple[CStatements, ConditionIR, CFunctionCall]:
    condition = ConditionIR(
        op="sgt",
        lhs=IRValue(
            MemSpace.DS,
            offset=0x0BA2,
            size=2,
            memory_access_insn=memory_access_insn,
        ),
        rhs=IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
        src_insn=0x1027,
        block_addr=0x1020,
        producer_insn=0x1023,
    )
    codegen = _Codegen()
    expression = materialize_condition_ir_expression_8616(codegen.project, codegen, condition)
    assert expression is not None
    helper = next(
        node
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall)
        and SEGMENTED_LOAD_ADDRESS_TAG_8616 in node.tags
    )
    helper.tags.pop(SEGMENTED_LOAD_ADDRESS_TAG_8616)
    helper.tags = segmented_load_tags_8616(
        SegmentedLoadIdentity8616(
            space=MemSpace.DS,
            offset=0x0BA2,
            width=2,
            region=0x1000,
        ),
        existing=helper.tags,
    )
    helper.tags.pop("inertia_source_instruction_addrs", None)
    loop = CForLoop(
        None,
        expression,
        None,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    return CStatements([loop], codegen=codegen), condition, helper


def test_structured_loop_condition_recovers_exact_operand_access() -> None:
    root, condition, helper = _loop_condition_fixture(memory_access_insn=0x101F)

    stats = transport_structured_condition_segment_provenance_8616(root, (condition,))

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.updated_count == 1
    assert helper.tags["inertia_source_instruction_addrs"] == (0x101F,)


def test_codegen_provenance_replay_targets_current_regenerated_root() -> None:
    root, condition, helper = _loop_condition_fixture(memory_access_insn=0x101F)
    codegen = SimpleNamespace(
        _inertia_typed_conditions=(condition,),
        cfunc=SimpleNamespace(statements=root),
    )

    stats = replay_codegen_structured_condition_segment_provenance_8616(codegen)

    assert stats.updated_count == 1
    assert helper.tags["inertia_source_instruction_addrs"] == (0x101F,)
    assert codegen._inertia_structured_condition_provenance_stats_8616 is stats


def test_structured_loop_condition_refuses_missing_operand_access() -> None:
    root, condition, helper = _loop_condition_fixture(memory_access_insn=None)

    stats = transport_structured_condition_segment_provenance_8616(root, (condition,))

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.updated_count == 0
    assert "inertia_source_instruction_addrs" not in helper.tags


def test_structured_loop_condition_refuses_ambiguous_exact_facts() -> None:
    root, condition, helper = _loop_condition_fixture(memory_access_insn=0x101F)
    duplicate = ConditionIR(
        op=condition.op,
        lhs=IRValue(
            MemSpace.DS,
            offset=0x0BA2,
            size=2,
            memory_access_insn=0x1021,
        ),
        rhs=condition.rhs,
        src_insn=condition.src_insn,
        block_addr=condition.block_addr,
        producer_insn=0x1023,
    )

    stats = transport_structured_condition_segment_provenance_8616(
        root,
        (condition, duplicate),
    )

    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert "inertia_source_instruction_addrs" not in helper.tags
