import networkx as nx
from inertia.ir.condition_ir import ConditionEdgeEvidence, ConditionIR
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)

from inertia.structuring.structuring_grouped_graph_builder import (
    build_grouped_region_graph,
    describe_x86_16_grouped_region_graph_surface,
)


class _Node:
    def __init__(self, addr):
        self.addr = addr


class _Clinic:
    def __init__(self, graph):
        self.graph = graph


class _CFunc:
    def __init__(self, addr):
        self.addr = addr
        self.name = "func"


class _Codegen:
    def __init__(self, addr, clinic, artifact=None, typed_conditions=None, edge_evidence=None):
        self.cfunc = _CFunc(addr)
        self._clinic = clinic
        self.project = None
        self._inertia_vex_ir_artifact = artifact
        self._inertia_vex_ir_function_ssa = None
        self._inertia_typed_conditions = tuple(typed_conditions or ())
        self._inertia_condition_edge_evidence = tuple(edge_evidence or ())


def test_grouped_region_graph_builder_materializes_grouping_on_region_metadata():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    result = build_grouped_region_graph(_Codegen(0x1000, _Clinic(graph)))

    assert result.graph_result.graph is not None
    by_id = {region.region_id: region for region in result.graph_result.graph.nodes}
    assert by_id[0x1000].metadata["cross_entry_grouping_kind"] == "primary_entry"
    assert by_id[0x1001].metadata["cross_entry_grouping_kind"] == "entry_fragment"
    assert by_id[0x1002].metadata["cross_entry_grouping_kind"] == "grouped_entry_candidate"


def test_grouped_region_graph_builder_surface_is_deterministic():
    assert describe_x86_16_grouped_region_graph_surface() == {
        "producer": "build_grouped_region_graph",
        "graph_surface": "Region.metadata[cross_entry_*, typed_ir_*, typed_condition_edge_*]",
        "unit_surface": "CrossEntryGroupedUnitArtifact",
        "purpose": "Materialize cross-entry grouping directly onto the region graph before structuring.",
    }


def test_grouped_region_graph_builder_materializes_typed_ir_condition_metadata_without_grouping():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    graph.add_nodes_from([a, b])
    graph.add_edge(a, b)
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "CJMP",
                        None,
                        (
                            IRCondition(
                                op="eq",
                                args=(
                                    IRValue(MemSpace.REG, name="ax", size=2),
                                    IRValue(MemSpace.CONST, const=0, size=2),
                                ),
                                expr=("update_eflags_sub",),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    result = build_grouped_region_graph(_Codegen(0x1000, _Clinic(graph), artifact=artifact))

    by_id = {region.region_id: region for region in result.graph_result.graph.nodes}
    assert by_id[0x1000].metadata["typed_ir_has_condition"] is True
    assert by_id[0x1000].metadata["typed_ir_condition_kinds"] == ("eq",)
    assert by_id[0x1000].metadata["typed_ir_allow_abnormal_loop_normalization"] is True
    assert by_id[0x1000].metadata["typed_ir_condition_hint"] == "ax == 0"
    assert "cross_entry_grouping_kind" not in by_id[0x1000].metadata


def test_grouped_region_graph_builder_materializes_condition_ir_metadata_without_vex_artifact():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    graph.add_nodes_from([a, b])
    graph.add_edge(a, b)
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=27, size=2),
        src_insn=0x1003,
        block_addr=0x1000,
    )

    result = build_grouped_region_graph(_Codegen(0x1000, _Clinic(graph), typed_conditions=(condition,)))

    by_id = {region.region_id: region for region in result.graph_result.graph.nodes}
    metadata = by_id[0x1000].metadata
    assert metadata["typed_ir_has_condition"] is True
    assert metadata["typed_ir_condition_kinds"] == ("ne",)
    assert metadata["typed_ir_allow_abnormal_loop_normalization"] is True
    assert metadata["typed_ir_condition_hint"] == "ax != 27"
    assert metadata["typed_condition_ir_has_condition"] is True
    assert metadata["typed_condition_ir_ops"] == ("ne",)
    assert metadata["typed_condition_ir_hint"] == "ax != 27"
    assert metadata["typed_condition_ir_count"] == 1


def test_grouped_region_graph_builder_materializes_condition_ir_metadata_at_source_insn_region():
    graph = nx.DiGraph()
    cmp_block = _Node(0x1153)
    split_jcc = _Node(0x1158)
    graph.add_nodes_from([cmp_block, split_jcc])
    graph.add_edge(cmp_block, split_jcc)
    condition = ConditionIR(
        op="sle",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=69, size=2),
        src_insn=0x1158,
        block_addr=0x1153,
        producer_insn=0x1153,
        source=("cmp", "jle"),
    )

    result = build_grouped_region_graph(_Codegen(0x1153, _Clinic(graph), typed_conditions=(condition,)))

    by_id = {region.region_id: region for region in result.graph_result.graph.nodes}
    block_metadata = by_id[0x1153].metadata
    split_metadata = by_id[0x1158].metadata
    assert block_metadata["typed_condition_ir_has_condition"] is True
    assert block_metadata["typed_condition_ir_hint"] == "ax <= 69"
    assert split_metadata["typed_condition_ir_has_condition"] is True
    assert split_metadata["typed_condition_ir_ops"] == ("sle",)
    assert split_metadata["typed_condition_ir_hint"] == "ax <= 69"
    assert split_metadata["typed_ir_allow_abnormal_loop_normalization"] is True


def test_grouped_region_graph_builder_materializes_condition_edge_guard_metadata():
    graph = nx.DiGraph()
    a = _Node(0x1153)
    b = _Node(0x1158)
    graph.add_nodes_from([a, b])
    graph.add_edge(a, b)
    condition = ConditionIR(
        op="eq",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=69, size=2),
        src_insn=0x1158,
        block_addr=0x1158,
        producer_insn=0x1153,
        source=("cmp", "je"),
    )
    edge = ConditionEdgeEvidence(
        edge_block_addr=0x1158,
        condition=condition,
        edge_kind="fallthrough_jmp",
        source_jcc="jne",
        producer_insn=0x1153,
        producer_semantics=("cmp_reg_imm16", "ax", 69),
    )

    result = build_grouped_region_graph(_Codegen(0x1153, _Clinic(graph), edge_evidence=(edge,)))

    by_id = {region.region_id: region for region in result.graph_result.graph.nodes}
    metadata = by_id[0x1158].metadata
    assert metadata["typed_ir_has_condition"] is True
    assert metadata["typed_ir_condition_kinds"] == ("eq",)
    assert metadata["typed_ir_condition_hint"] == "ax == 69"
    assert metadata["typed_condition_ir_has_condition"] is False
    assert metadata["typed_condition_edge_has_guard"] is True
    assert metadata["typed_condition_edge_guard_ops"] == ("eq",)
    assert metadata["typed_condition_edge_guard_hints"] == ("ax == 69",)
    assert metadata["typed_condition_edge_guards"] == (condition,)
    assert metadata["typed_condition_edge_guard_count"] == 1
    assert metadata["typed_condition_edge_producer_semantics"] == (("cmp_reg_imm16", "ax", 69),)
    producer_metadata = by_id[0x1153].metadata
    assert producer_metadata["typed_condition_edge_has_guard"] is False
    assert producer_metadata["typed_condition_edge_guards"] == ()
    assert producer_metadata["typed_condition_edge_guard_count"] == 0
    assert producer_metadata["typed_condition_edge_producer_semantics"] == (("cmp_reg_imm16", "ax", 69),)


def test_grouped_region_graph_builder_preserves_vex_hint_when_condition_ir_is_also_present():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    graph.add_node(a)
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "CJMP",
                        None,
                        (
                            IRCondition(
                                op="eq",
                                args=(
                                    IRValue(MemSpace.REG, name="ax", size=2),
                                    IRValue(MemSpace.CONST, const=0, size=2),
                                ),
                                expr=("update_eflags_sub",),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=27, size=2),
        src_insn=0x1003,
        block_addr=0x1000,
    )

    result = build_grouped_region_graph(
        _Codegen(0x1000, _Clinic(graph), artifact=artifact, typed_conditions=(condition,))
    )

    by_id = {region.region_id: region for region in result.graph_result.graph.nodes}
    metadata = by_id[0x1000].metadata
    assert metadata["typed_ir_condition_kinds"] == ("eq", "ne")
    assert metadata["typed_ir_condition_hint"] == "ax == 0"
    assert metadata["typed_condition_ir_ops"] == ("ne",)
    assert metadata["typed_condition_ir_hint"] == "ax != 27"
    assert metadata["typed_condition_ir_count"] == 1


def test_grouped_region_graph_builder_formats_signed_and_unsigned_condition_hints():
    graph = nx.DiGraph()
    a = _Node(0x1200)
    b = _Node(0x1201)
    graph.add_nodes_from([a, b])
    graph.add_edge(a, b)
    artifact = IRFunctionArtifact(
        function_addr=0x1200,
        blocks=(
            IRBlock(
                addr=0x1200,
                instrs=(
                    IRInstr(
                        "CJMP",
                        None,
                        (
                            IRCondition(
                                op="slt",
                                args=(
                                    IRValue(MemSpace.REG, name="ax", size=2),
                                    IRValue(MemSpace.REG, name="bx", size=2),
                                ),
                                expr=("cmp",),
                            ),
                        ),
                    ),
                ),
            ),
            IRBlock(
                addr=0x1201,
                instrs=(
                    IRInstr(
                        "CJMP",
                        None,
                        (
                            IRCondition(
                                op="uge",
                                args=(
                                    IRValue(MemSpace.REG, name="cx", size=2),
                                    IRValue(MemSpace.CONST, const=4, size=2),
                                ),
                                expr=("cmp",),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    result = build_grouped_region_graph(_Codegen(0x1200, _Clinic(graph), artifact=artifact))

    by_id = {region.region_id: region for region in result.graph_result.graph.nodes}
    assert by_id[0x1200].metadata["typed_ir_condition_hint"] == "ax < bx"
    assert by_id[0x1201].metadata["typed_ir_condition_hint"] == "cx >= 4"


def test_grouped_region_graph_builder_materializes_typed_ir_address_metadata():
    graph = nx.DiGraph()
    a = _Node(0x1100)
    graph.add_node(a)
    artifact = IRFunctionArtifact(
        function_addr=0x1100,
        blocks=(
            IRBlock(
                addr=0x1100,
                instrs=(
                    IRInstr(
                        "LOAD",
                        IRValue(MemSpace.TMP, name="t0", size=2),
                        (
                            IRAddress(
                                space=MemSpace.SS,
                                base=("bp",),
                                offset=-2,
                                size=2,
                                status=AddressStatus.STABLE,
                                segment_origin=SegmentOrigin.PROVEN,
                                expr=("load",),
                            ),
                        ),
                    ),
                    IRInstr(
                        "STORE",
                        None,
                        (
                            IRAddress(
                                space=MemSpace.DS,
                                base=("bx", "si"),
                                offset=4,
                                size=1,
                                status=AddressStatus.PROVISIONAL,
                                segment_origin=SegmentOrigin.DEFAULTED,
                                expr=("store",),
                            ),
                            IRValue(MemSpace.CONST, const=1, size=1),
                        ),
                    ),
                ),
            ),
        ),
    )

    result = build_grouped_region_graph(_Codegen(0x1100, _Clinic(graph), artifact=artifact))

    by_id = {region.region_id: region for region in result.graph_result.graph.nodes}
    metadata = by_id[0x1100].metadata
    assert metadata["typed_ir_has_address"] is True
    assert metadata["typed_ir_address_spaces"] == ("ds", "ss")
    assert metadata["typed_ir_stable_address_spaces"] == ("ss",)
    assert metadata["typed_ir_segment_origin_kinds"] == ("defaulted", "proven")
    assert metadata["typed_ir_address_hint"] == "ss:[bp - 2]"
