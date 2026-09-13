import networkx as nx
import pytest
from angr_platforms.X86_16.ir.condition_ir import ConditionEdgeEvidence, ConditionIR
from angr_platforms.X86_16.ir.core import IRBlock, IRCondition, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.structuring_analysis import _collect_edge_guard_decision_tree_cases_8616
from angr_platforms.X86_16.structuring_grouped_pass import (
    GroupedRegionBasedStructuringPass,
    apply_grouped_region_based_structuring,
    describe_x86_16_grouped_structuring_pass_surface,
)
from angr_platforms.X86_16.structuring_region import Region, RegionGraph


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


class _SlottedCFunc:
    __slots__ = ("addr", "name")

    def __init__(self, addr):
        self.addr = addr
        self.name = "func"


class _Codegen:
    def __init__(self, addr, clinic, *, slotted_cfunc=False):
        self.cfunc = _SlottedCFunc(addr) if slotted_cfunc else _CFunc(addr)
        self._clinic = clinic
        self.project = None


def test_grouped_structuring_pass_builds_grouped_region_graph_for_driver():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    pass_instance = GroupedRegionBasedStructuringPass()
    built_graph, entry = pass_instance._build_region_graph(_Codegen(0x1000, _Clinic(graph)))

    assert built_graph is not None
    assert entry is not None
    by_id = {region.region_id: region for region in built_graph.nodes}
    assert by_id[0x1000].metadata["cross_entry_grouping_kind"] == "primary_entry"
    assert by_id[0x1001].metadata["cross_entry_grouping_kind"] == "entry_fragment"
    assert by_id[0x1002].metadata["cross_entry_grouping_kind"] == "grouped_entry_candidate"


def test_grouped_structuring_pass_surface_is_deterministic():
    assert describe_x86_16_grouped_structuring_pass_surface() == {
        "pass_class": "GroupedRegionBasedStructuringPass",
        "graph_builder": "build_grouped_region_graph",
        "analysis_class": "AbnormalLoopStructureAnalysis",
        "purpose": "Feed grouped region graphs into the real region-based structuring driver.",
    }


def test_grouped_structuring_pass_runs_by_default_and_keeps_opt_out(monkeypatch):
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    graph.add_edge(a, b)
    codegen = _Codegen(0x1000, _Clinic(graph))

    monkeypatch.delenv("INERTIA_RUN_GROUPED_STRUCTURING_IN_STAGE", raising=False)
    assert apply_grouped_region_based_structuring(codegen) is False
    assert getattr(codegen, "_inertia_grouped_structuring_stats_8616", None) is not None

    disabled = _Codegen(0x1000, _Clinic(graph))
    monkeypatch.setenv("INERTIA_RUN_GROUPED_STRUCTURING_IN_STAGE", "0")
    assert apply_grouped_region_based_structuring(disabled) is False
    assert not hasattr(disabled, "_inertia_grouped_structuring_stats_8616")


def test_grouped_structuring_pass_annotates_typed_ir_support_on_regions():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)

    codegen = _Codegen(0x1000, _Clinic(graph))
    codegen._inertia_vex_ir_artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1002,
                instrs=(
                    IRInstr(
                        "CJMP",
                        None,
                        (
                            IRCondition(
                                "eq",
                                (IRValue(MemSpace.REG, name="ax", size=2), IRValue(MemSpace.REG, name="bx", size=2)),
                            ),
                            IRValue(MemSpace.CONST, const=0x1010, size=2),
                        ),
                    ),
                ),
            ),
        ),
    )
    codegen._inertia_vex_ir_function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(),
        phi_nodes=(),
        predecessor_map={},
        summary={"phi_node_count": 0},
    )

    pass_instance = GroupedRegionBasedStructuringPass()
    built_graph, _entry = pass_instance._build_region_graph(codegen)
    by_id = {region.region_id: region for region in built_graph.nodes}

    assert by_id[0x1002].metadata["typed_ir_has_condition"] is True
    assert by_id[0x1002].metadata["typed_ir_allow_abnormal_loop_normalization"] is True


def test_grouped_structuring_pass_records_typed_edge_switch_detection():
    graph = nx.DiGraph()
    nodes = {addr: _Node(addr) for addr in (0x1110, 0x1120, 0x1130, 0x1140, 0x1150, 0x1160, 0x1170)}
    graph.add_nodes_from(nodes.values())
    graph.add_edge(nodes[0x1110], nodes[0x1150])
    graph.add_edge(nodes[0x1110], nodes[0x1120])
    graph.add_edge(nodes[0x1120], nodes[0x1160])
    graph.add_edge(nodes[0x1120], nodes[0x1130])
    graph.add_edge(nodes[0x1130], nodes[0x1170])
    graph.add_edge(nodes[0x1130], nodes[0x1140])

    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    edge_evidence = []
    for edge_block_addr, value in ((0x1150, 69), (0x1160, 27), (0x1170, 33)):
        condition = ConditionIR(
            op="eq",
            lhs=lhs,
            rhs=IRValue(MemSpace.CONST, const=value, size=2),
            src_insn=edge_block_addr,
            block_addr=edge_block_addr,
            producer_insn=edge_block_addr - 1,
        )
        edge_evidence.append(
            ConditionEdgeEvidence(
                edge_block_addr=edge_block_addr,
                condition=condition,
                edge_kind="fallthrough_jmp",
                source_jcc="jne",
                producer_insn=edge_block_addr - 1,
                producer_semantics=("cmp_reg_imm16", "ax", value),
            )
        )

    codegen = _Codegen(0x1110, _Clinic(graph))
    codegen._inertia_condition_edge_evidence = tuple(edge_evidence)

    changed = GroupedRegionBasedStructuringPass()(codegen)

    assert changed is False
    assert codegen._inertia_grouped_structuring_graph is not None
    assert codegen.cfunc._structuring_stats["edge_guard_switches_detected"] == 1
    structured_regions = codegen.cfunc._structuring_stats["structured_regions"]
    assert any(
        region["type"] == "incswitch" and "switch_detection" in region["metadata_keys"]
        for region in structured_regions
    )
    [artifact] = codegen.cfunc._structuring_stats["typed_edge_switch_region_artifacts"]
    assert artifact["status"] == "ready"
    assert artifact["owner"] == "structuring.analysis"
    assert artifact["detection"] == "typed_condition_edge_cascade"
    assert artifact["region_id"] == 0x1110
    assert set(artifact["case_region_ids"]) == {0x1150, 0x1160, 0x1170}
    assert set(artifact["case_values"]) == {69, 27, 33}
    assert artifact["decision_tree_summary"]["case_count"] == 3
    assert set(artifact["decision_tree_summary"]["case_values"]) == {69, 27, 33}
    assert set(artifact["decision_tree_case_region_ids"]) == {0x1150, 0x1160, 0x1170}
    assert set(artifact["decision_tree_case_values"]) == {69, 27, 33}
    assert artifact["decision_tree_summary"]["default_candidate_count"] == 1
    assert artifact["decision_tree_summary"]["default_candidate_region_ids"] == [0x1140]
    assert artifact["decision_tree_summary"]["default_candidate_successor_region_ids"] == {0x1140: []}
    assert artifact["decision_tree_summary"]["partition_status"] == "single_default_candidate"
    assert artifact["decision_tree_summary"]["normalization_status"] == "complete"
    assert set(artifact["decision_tree_summary"]["normalized_case_values"]) == {69, 27, 33}
    assert artifact["decision_tree_summary"]["affine_reg_imm_case_count"] == 3
    assert artifact["decision_tree_summary"]["producer_semantics_kinds"] == ["cmp_reg_imm16"]
    assert artifact["decision_tree_summary"]["producer_semantics_registers"] == ["ax"]
    assert artifact["decision_tree_summary"]["range_split_count"] == 0
    assert artifact["default_region_id"] == 0x1140
    assert artifact["guard_span_complete"] is False


def test_decision_tree_records_ready_branch_partition_when_subtrees_have_unique_defaults():
    graph = RegionGraph()
    regions = {
        name: Region(block_addr=addr)
        for name, addr in {
            "root": 0x3100,
            "case69": 0x3110,
            "split": 0x3120,
            "low": 0x3130,
            "high": 0x3140,
            "case33": 0x3150,
            "case72": 0x3160,
            "default": 0x3170,
        }.items()
    }
    for region in regions.values():
        graph.add_node(region)
    graph.entry = regions["root"]
    graph.add_edge(regions["root"], regions["case69"])
    graph.add_edge(regions["root"], regions["split"])
    graph.add_edge(regions["split"], regions["low"])
    graph.add_edge(regions["split"], regions["high"])
    graph.add_edge(regions["low"], regions["case33"])
    graph.add_edge(regions["low"], regions["default"])
    graph.add_edge(regions["high"], regions["case72"])
    graph.add_edge(regions["high"], regions["default"])

    lhs = IRValue(MemSpace.REG, name="ax", size=2)

    def _attach_guard(region: Region, op: str, value: int, *, hint: str | None = None) -> None:
        condition = ConditionIR(
            op=op,
            lhs=lhs,
            rhs=IRValue(MemSpace.CONST, const=value, size=2),
            src_insn=region.region_id,
            block_addr=region.region_id,
            producer_insn=(region.region_id or 0) - 1,
        )
        region.metadata["typed_condition_edge_guards"] = (condition,)
        region.metadata["typed_condition_edge_guard_count"] = 1
        region.metadata["typed_condition_edge_guard_ops"] = (op,)
        if op == "eq":
            region.metadata["typed_condition_edge_producer_semantics"] = (("cmp_reg_imm16", "ax", value),)
        if hint is not None:
            region.metadata["typed_ir_condition_hint"] = hint
            region.metadata["typed_ir_condition_kinds"] = (op,)

    _attach_guard(regions["case69"], "eq", 69)
    _attach_guard(regions["case33"], "eq", 33)
    _attach_guard(regions["case72"], "eq", 72)
    _attach_guard(regions["high"], "sgt", 69, hint="ax > 69")

    summary = _collect_edge_guard_decision_tree_cases_8616(graph, regions["root"])

    assert summary["normalization_readiness"] == {
        "branch_split_count": 1,
        "case_count": 3,
        "normalized_case_count": 3,
        "partition_status": "single_default_candidate",
        "ready": True,
        "ready_branch_split_count": 1,
        "status": "branch_splits_ready",
        "unready_branch_splits": [],
    }
    [split] = summary["normalization_branch_splits"]
    assert split["branch_partition"]["status"] == "ready"
    assert split["branch_partition"]["ready"] is True
    assert split["branch_partition"]["explicit_successor_region_id"] == 0x3140
    assert split["branch_partition"]["implicit_complement_successor_region_id"] == 0x3130
    assert split["branch_partition"]["implicit_complement_op"] == "sle"
    assert split["branch_partition"]["subtree_partition_statuses"] == [
        "single_default_candidate",
        "single_default_candidate",
    ]
    successors = {item["region_id"]: item for item in split["branch_partition"]["successors"]}
    assert successors[0x3130]["partition_predicate_op"] == "sle"
    assert successors[0x3130]["normalized_case_region_ids"] == [0x3150]
    assert successors[0x3130]["normalized_case_values"] == [33]
    assert successors[0x3130]["predicate_matching_normalized_case_region_ids"] == [0x3150]
    assert successors[0x3130]["predicate_matching_normalized_case_values"] == [33]
    assert successors[0x3130]["predicate_mismatching_normalized_case_region_ids"] == []
    assert successors[0x3130]["predicate_mismatching_normalized_case_values"] == []
    assert successors[0x3140]["partition_predicate_op"] == "sgt"
    assert successors[0x3140]["normalized_case_region_ids"] == [0x3160]
    assert successors[0x3140]["normalized_case_values"] == [72]
    assert successors[0x3140]["predicate_matching_normalized_case_region_ids"] == [0x3160]
    assert successors[0x3140]["predicate_matching_normalized_case_values"] == [72]
    assert successors[0x3140]["predicate_mismatching_normalized_case_region_ids"] == []
    assert successors[0x3140]["predicate_mismatching_normalized_case_values"] == []


def test_decision_tree_prefers_normalized_edge_cmp_value_over_affine_delta():
    graph = RegionGraph()
    root = Region(block_addr=0x4100)
    case_region = Region(block_addr=0x4110)
    default = Region(block_addr=0x4120)
    for region in (root, case_region, default):
        graph.add_node(region)
    graph.entry = root
    graph.add_edge(root, case_region)
    graph.add_edge(root, default)

    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    condition = ConditionIR(
        op="eq",
        lhs=lhs,
        rhs=IRValue(MemSpace.CONST, const=4, size=2),
        src_insn=0x117C,
        block_addr=0x117C,
        producer_insn=0x1177,
    )
    case_region.metadata["typed_condition_edge_guards"] = (condition,)
    case_region.metadata["typed_condition_edge_guard_count"] = 1
    case_region.metadata["typed_condition_edge_guard_ops"] = ("eq",)
    case_region.metadata["typed_condition_edge_producer_semantics"] = (
        ("normalized_cmp_reg_imm16", "ax", 66, ("sub_reg_imm16", "ax", 4)),
    )

    summary = _collect_edge_guard_decision_tree_cases_8616(graph, root, initial_affine_offset=34)

    assert summary["case_values"] == [4]
    assert summary["normalized_case_values"] == [66]
    assert summary["normalization_status"] == "complete"


@pytest.mark.parametrize("zero_test", [False, True])
def test_decision_tree_accumulates_unresolved_normalized_affine_producers(zero_test: bool) -> None:
    """A DEC zero-test must remain a case in the normalized selector ladder."""
    graph = RegionGraph()
    regions = {
        name: Region(block_addr=addr)
        for name, addr in {
            "root": 0x4180,
            "case27": 0x4190,
            "cont33": 0x41A0,
            "case33": 0x41B0,
            "cont_dec2": 0x41C0,
            "case_dec2": 0x41D0,
            "cont4": 0x41E0,
            "case4": 0x41F0,
            "default": 0x4200,
        }.items()
    }
    for region in regions.values():
        graph.add_node(region)
    graph.entry = regions["root"]
    graph.add_edge(regions["root"], regions["case27"])
    graph.add_edge(regions["root"], regions["cont33"])
    graph.add_edge(regions["cont33"], regions["case33"])
    graph.add_edge(regions["cont33"], regions["cont_dec2"])
    graph.add_edge(regions["cont_dec2"], regions["case_dec2"])
    graph.add_edge(regions["cont_dec2"], regions["cont4"])
    graph.add_edge(regions["cont4"], regions["case4"])
    graph.add_edge(regions["cont4"], regions["default"])

    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    cases = (
        ("case27", 27, ("normalized_cmp_reg_imm16", "ax", 27, ("sub_reg_imm16", "ax", 27))),
        ("case33", 33, ("normalized_cmp_reg_imm16", "ax", 33, ("sub_reg_imm16", "ax", 33))),
        ("case_dec2", 27, ("dec_reg16", "ax", 2)),
        ("case4", 4, ("normalized_cmp_reg_imm16", "ax", 4, ("sub_reg_imm16", "ax", 4))),
    )
    for name, raw_value, producer_semantics in cases:
        region = regions[name]
        unary_zero = zero_test and producer_semantics[0] == "dec_reg16"
        condition = ConditionIR(
            op="zero" if unary_zero else "eq",
            lhs=lhs,
            rhs=None if unary_zero else IRValue(MemSpace.CONST, const=raw_value, size=2),
            src_insn=region.region_id,
            block_addr=region.region_id,
            producer_insn=(region.region_id or 0) - 1,
        )
        region.metadata["typed_condition_edge_guards"] = (condition,)
        region.metadata["typed_condition_edge_guard_count"] = 1
        region.metadata["typed_condition_edge_guard_ops"] = (condition.op,)
        region.metadata["typed_condition_edge_producer_semantics"] = (producer_semantics,)

    summary = _collect_edge_guard_decision_tree_cases_8616(graph, regions["root"])

    assert summary["normalized_case_values"] == [27, 60, 62, 66]
    assert summary["normalized_duplicate_value_count"] == 0
    assert summary["normalization_status"] == "complete"
    assert summary["partition_status"] == "single_default_candidate"


def test_decision_tree_carries_affine_delta_from_exit_sibling_to_continuation():
    graph = RegionGraph()
    regions = {
        name: Region(block_addr=addr)
        for name, addr in {
            "root": 0x4200,
            "exit_case": 0x4210,
            "cont": 0x4220,
            "case33": 0x4230,
            "default": 0x4240,
        }.items()
    }
    for region in regions.values():
        graph.add_node(region)
    graph.entry = regions["root"]
    graph.add_edge(regions["root"], regions["exit_case"])
    graph.add_edge(regions["root"], regions["cont"])
    graph.add_edge(regions["cont"], regions["case33"])
    graph.add_edge(regions["cont"], regions["exit_case"])

    regions["exit_case"].metadata["typed_condition_edge_producer_semantics"] = (("sub_reg_imm16", "ax", 27),)
    condition = ConditionIR(
        op="eq",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=33, size=2),
        src_insn=0x4230,
        block_addr=0x4230,
        producer_insn=0x4228,
    )
    regions["case33"].metadata["typed_condition_edge_guards"] = (condition,)
    regions["case33"].metadata["typed_condition_edge_guard_count"] = 1
    regions["case33"].metadata["typed_condition_edge_guard_ops"] = ("eq",)
    regions["case33"].metadata["typed_condition_edge_producer_semantics"] = (("sub_reg_imm16", "ax", 33),)

    summary = _collect_edge_guard_decision_tree_cases_8616(graph, regions["root"])

    assert summary["case_values"] == [33]
    assert summary["normalized_case_values"] == [60]


def test_decision_tree_accepts_duplicate_raw_values_when_normalized_values_are_unique():
    graph = RegionGraph()
    root = Region(block_addr=0x4300)
    case_a = Region(block_addr=0x4310)
    cont = Region(block_addr=0x4320)
    case_b = Region(block_addr=0x4330)
    default = Region(block_addr=0x4340)
    for region in (root, case_a, cont, case_b, default):
        graph.add_node(region)
    graph.entry = root
    graph.add_edge(root, case_a)
    graph.add_edge(root, cont)
    graph.add_edge(cont, case_b)
    graph.add_edge(cont, default)

    lhs = IRValue(MemSpace.REG, name="ax", size=2)
    for region, normalized_value in ((case_a, 83), (case_b, 84)):
        condition = ConditionIR(
            op="eq",
            lhs=lhs,
            rhs=IRValue(MemSpace.CONST, const=24, size=2),
            src_insn=region.region_id,
            block_addr=region.region_id,
            producer_insn=(region.region_id or 0) - 1,
        )
        region.metadata["typed_condition_edge_guards"] = (condition,)
        region.metadata["typed_condition_edge_guard_count"] = 1
        region.metadata["typed_condition_edge_guard_ops"] = ("eq",)
        region.metadata["typed_condition_edge_producer_semantics"] = (
            ("normalized_cmp_reg_imm16", "ax", normalized_value, ("dec_reg16", "ax", 1)),
        )

    summary = _collect_edge_guard_decision_tree_cases_8616(graph, root)

    assert summary["duplicate_value_count"] == 1
    assert summary["normalized_duplicate_value_count"] == 0
    assert summary["normalized_case_values"] == [83, 84]
    assert summary["normalization_status"] == "complete"
    assert summary["partition_status"] == "single_default_candidate"


def test_grouped_structuring_pass_records_stats_on_codegen_when_cfunc_is_slotted():
    graph = nx.DiGraph()
    nodes = {addr: _Node(addr) for addr in (0x2110, 0x2120, 0x2130)}
    graph.add_nodes_from(nodes.values())
    graph.add_edge(nodes[0x2110], nodes[0x2120])
    graph.add_edge(nodes[0x2120], nodes[0x2130])

    codegen = _Codegen(0x2110, _Clinic(graph), slotted_cfunc=True)

    changed = GroupedRegionBasedStructuringPass()(codegen)

    assert changed is False
    assert codegen._inertia_grouped_structuring_graph is not None
    assert codegen._inertia_grouped_structuring_stats_8616["final_node_count"] >= 1
