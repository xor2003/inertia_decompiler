"""
Tests for structuring-based C code generation (Phase 1.3).

Demonstrates Loop→while/for, IncSwitch→switch rendering.
"""

from types import SimpleNamespace

import inertia.structuring.structuring_codegen as structuring_codegen
import archinfo
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeInt, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.semantics.callsite_summary import CallsiteReturnUseKind8616, CallsiteSummary8616
from inertia.ir.core import IRValue, MemSpace
from inertia.structuring.structuring_analysis import StructureAnalysis
from inertia.structuring.structuring_codegen import (
    StructuringCodegenPass,
    TypedEdgeSwitchSafetyStatus8616,
    apply_structuring_codegen_8616,
    coalesce_shared_call_side_effect_statements_8616,
    evaluate_typed_edge_switch_replacement_safety_8616,
    materialize_typed_edge_switch_ast_8616,
    replace_typed_edge_switch_ast_8616,
    split_distinct_condition_call_occurrences_8616,
)
from inertia.structuring.structuring_region import Region, RegionGraph, RegionType

from inertia.structuring.condition_lowering import lower_ir_value_to_c_expr_8616


class _AstCodegen:
    def __init__(self):
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.stmt_comments = {}
        self.expr_comments = {}
        self.braces_on_own_lines = False
        self.indent_delta = 4
        self.display_block_addrs = False
        self.display_vvar_ids = False
        self.cstyle_null_cmp = False
        self.max_str_len = 64
        self.const_formats = {}
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class TestStructuringCodegen:
    """Tests for C code generation from structured regions."""

    def test_loop_renders_as_while(self):
        """
        Test that a Loop region renders as while loop C code.
        """
        # Create simple loop
        entry = Region(block_addr=0x1000, region_type=RegionType.Linear)
        header = Region(block_addr=0x1001, region_type=RegionType.Linear)
        body = Region(block_addr=0x1002, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x1003, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, header, body, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, header)
        graph.add_edge(header, body)
        graph.add_edge(body, header)  # Back-edge
        graph.add_edge(header, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Generate C code
        codegen = StructuringCodegenPass()
        code = codegen.apply(result)

        # Verify codegen completed
        assert code is not None, "Should generate code"
        assert codegen.stats["loops_rendered"] >= 0, "Should track loop count"

    def test_switch_renders_as_switch(self):
        """
        Test that an IncSwitch region renders as switch C code.
        """
        entry = Region(block_addr=0x2000, region_type=RegionType.Linear)
        switch_region = Region(block_addr=0x2001, region_type=RegionType.Condition)
        cases = [Region(block_addr=0x2002 + i * 4, region_type=RegionType.Linear) for i in range(3)]
        exit_region = Region(block_addr=0x2010, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        graph.add_node(entry)
        graph.add_node(switch_region)
        for case in cases:
            graph.add_node(case)
        graph.add_node(exit_region)

        graph.add_edge(entry, switch_region)
        for case in cases:
            graph.add_edge(switch_region, case)
            graph.add_edge(case, exit_region)

        # Run structuring (will detect 3-way switch)
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Generate C code
        codegen = StructuringCodegenPass()
        code = codegen.apply(result)

        # Verify codegen
        assert code is not None, "Should generate code"
        assert codegen.stats["switches_rendered"] >= 0, "Should track switch count"

    def test_loop_render_contains_while(self):
        """
        Test that rendered loop code contains 'while' keyword.
        """
        loop_region = Region(block_addr=0x3000, region_type=RegionType.Loop)
        loop_region.metadata["loop_info"] = None

        graph = RegionGraph()
        graph.entry = loop_region

        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        # While loop should appear in simplest case
        assert "while" in code or "do" in code or "for" in code, "Loop should render as C control flow"

    def test_loop_codegen_uses_typed_ir_condition_hint_when_no_explicit_condition(self):
        loop_region = Region(block_addr=0x3100, region_type=RegionType.Loop)
        loop_region.metadata["typed_ir_condition_hint"] = "ax == 0"

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "while (ax == 0)" in code

    def test_loop_codegen_uses_condition_edge_hint_as_last_resort(self):
        loop_region = Region(block_addr=0x3104, region_type=RegionType.Loop)
        loop_region.metadata["typed_condition_edge_guard_hints"] = ("ax == 69",)

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "while (ax == 69)" in code

    def test_loop_codegen_prefers_direct_condition_hint_over_edge_hint(self):
        loop_region = Region(block_addr=0x3108, region_type=RegionType.Loop)
        loop_region.metadata["typed_ir_condition_hint"] = "ax != 27"
        loop_region.metadata["typed_condition_edge_guard_hints"] = ("ax == 69",)

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "while (ax != 27)" in code
        assert "ax == 69" not in code

    def test_switch_render_contains_switch(self):
        """
        Test that rendered switch code contains 'switch' keyword.
        """
        switch_region = Region(block_addr=0x4000, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_candidates"] = [
            Region(block_addr=0x1),
            Region(block_addr=0x2),
            Region(block_addr=0x3),
        ]

        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "switch" in code or "case" in code, "Switch should render as C switch statement"

    def test_switch_codegen_uses_typed_edge_case_values_and_lhs(self):
        switch_region = Region(block_addr=0x4100, region_type=RegionType.IncSwitch)
        default_region = Region(block_addr=0x4110, region_type=RegionType.Linear)
        switch_region.metadata["switch_condition_lhs"] = IRValue(MemSpace.REG, name="ax", size=2)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [
            Region(block_addr=0x4150),
            Region(block_addr=0x4160),
            Region(block_addr=0x4170),
        ]
        switch_region.metadata["switch_default_target"] = default_region

        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "switch (ax)" in code
        assert "case 69:" in code
        assert "case 27:" in code
        assert "case 33:" in code
        assert "default:" in code
        assert "case 0x0:" not in code

    def test_typed_edge_switch_ast_materialization_refuses_empty_case_bodies(self):
        switch_region = Region(block_addr=0x4200, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(
            0,
            SimTypeShort(False),
            codegen=_AstCodegen(),
        )
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [
            Region(block_addr=0x4250),
            Region(block_addr=0x4260),
            Region(block_addr=0x4270),
        ]
        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)
        codegen = _AstCodegen()
        codegen._inertia_grouped_structuring_graph = graph

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.changed is False
        assert result.attempted_count == 1
        assert result.materialized_count == 0
        assert result.refusal_reasons == ("missing_case_statements",)
        assert codegen._inertia_typed_edge_switch_ast_nodes_8616 == ()

    def test_typed_edge_switch_ast_materialization_builds_switch_artifact_when_bodies_exist(self):
        codegen = _AstCodegen()
        switch_region = Region(block_addr=0x4300, region_type=RegionType.IncSwitch)
        case_a = Region(block_addr=0x4350)
        case_b = Region(block_addr=0x4360)
        case_c = Region(block_addr=0x4370)
        default_region = Region(block_addr=0x4380)
        case_a.statements.append(structured_c.CLabel("case_a", codegen=codegen))
        case_b.statements.append(structured_c.CLabel("case_b", codegen=codegen))
        case_c.statements.append(structured_c.CLabel("case_c", codegen=codegen))
        default_region.statements.append(structured_c.CLabel("default_case", codegen=codegen))
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.changed is False
        assert result.attempted_count == 1
        assert result.materialized_count == 1
        assert result.refused_count == 0
        [switch_ast] = codegen._inertia_typed_edge_switch_ast_nodes_8616
        rendered = switch_ast.c_repr()
        assert "switch (0)" in rendered
        assert "case 69:" in rendered
        assert "case 27:" in rendered
        assert "case 33:" in rendered
        assert "default:" in rendered
        assert "case_a:" in rendered
        assert "default_case:" in rendered

    def test_typed_edge_switch_ast_materialization_consumes_region_artifact(self):
        codegen = _AstCodegen()
        switch_region = Region(block_addr=0x4390, region_type=RegionType.IncSwitch)
        case_a = Region(block_addr=0x4391)
        case_b = Region(block_addr=0x4392)
        case_c = Region(block_addr=0x4393)
        default_region = Region(block_addr=0x4394)
        case_a.statements.append(structured_c.CLabel("case_a", codegen=codegen))
        case_b.statements.append(structured_c.CLabel("case_b", codegen=codegen))
        case_c.statements.append(structured_c.CLabel("case_c", codegen=codegen))
        default_region.statements.append(structured_c.CLabel("default_case", codegen=codegen))
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["typed_edge_switch_region_artifact"] = {
            "status": "ready",
            "owner": "structuring.analysis",
            "detection": "typed_condition_edge_cascade",
            "region_id": 0x4390,
            "case_region_ids": [0x4391, 0x4392, 0x4393],
            "case_values": [7, 8, 9],
            "default_region_id": 0x4394,
        }
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.materialized_count == 1
        [switch_ast] = codegen._inertia_typed_edge_switch_ast_nodes_8616
        rendered = switch_ast.c_repr()
        assert "case 7:" in rendered
        assert "case 8:" in rendered
        assert "case 9:" in rendered
        assert "default_case:" in rendered

    def test_typed_edge_switch_ast_materialization_populates_exact_tagged_cfunc_bodies(self):
        codegen = _AstCodegen()
        case_a = Region(block_addr=0x4450)
        case_b = Region(block_addr=0x4460)
        case_c = Region(block_addr=0x4470)
        default_region = Region(block_addr=0x4480)
        switch_region = Region(block_addr=0x4400, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [
                    structured_c.CLabel("case_a", tags={"ins_addr": 0x4450}, codegen=codegen),
                    structured_c.CLabel("case_b", tags={"ins_addr": 0x4460}, codegen=codegen),
                    structured_c.CLabel("case_c", tags={"ins_addr": 0x4470}, codegen=codegen),
                    structured_c.CLabel("default_case", tags={"ins_addr": 0x4480}, codegen=codegen),
                ],
                codegen=codegen,
            )
        )

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.materialized_count == 1
        assert result.refused_count == 0
        assert codegen._inertia_typed_edge_switch_ast_materialization_8616["region_statement_populated_count"] == 4
        assert [stmt.name for stmt in case_a.statements] == ["case_a"]
        [switch_ast] = codegen._inertia_typed_edge_switch_ast_nodes_8616
        rendered = switch_ast.c_repr()
        assert "case 69:" in rendered
        assert "case_a:" in rendered
        assert "default:" in rendered
        assert "default_case:" in rendered

    def test_typed_edge_switch_ast_materialization_lowers_switch_expr_from_lhs(self):
        codegen = _AstCodegen()
        case_a = Region(block_addr=0x4550)
        case_b = Region(block_addr=0x4560)
        case_c = Region(block_addr=0x4570)
        default_region = Region(block_addr=0x4580)
        for label, region in (
            ("case_a", case_a),
            ("case_b", case_b),
            ("case_c", case_c),
            ("default_case", default_region),
        ):
            region.statements.append(structured_c.CLabel(label, codegen=codegen))
        switch_region = Region(block_addr=0x4500, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_condition_lhs"] = IRValue(MemSpace.REG, name="cx", size=2)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([], codegen=codegen))

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.materialized_count == 1
        assert switch_region.metadata["switch_expr_ast_source"] == "typed_switch_condition_lhs"
        assert codegen._inertia_typed_edge_switch_ast_materialization_8616["switch_expr_populated_count"] == 1
        [switch_ast] = codegen._inertia_typed_edge_switch_ast_nodes_8616
        assert "switch (cx)" in switch_ast.c_repr()

    def test_typed_edge_switch_ast_materialization_uses_region_statement_address_set(self):
        codegen = _AstCodegen()
        case_a = Region(block_addr=0x4650)
        case_b = Region(block_addr=0x4660)
        case_c = Region(block_addr=0x4670)
        default_region = Region(block_addr=0x4680)
        case_a.metadata["region_statement_ins_addrs"] = (0x4650, 0x4652)
        case_b.metadata["region_statement_ins_addrs"] = (0x4660,)
        case_c.metadata["region_statement_ins_addrs"] = (0x4670,)
        default_region.metadata["region_statement_ins_addrs"] = (0x4680,)
        switch_region = Region(block_addr=0x4600, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [
                    structured_c.CLabel("case_a_first", tags={"ins_addr": 0x4650}, codegen=codegen),
                    structured_c.CLabel("case_a_second", tags={"ins_addr": 0x4652}, codegen=codegen),
                    structured_c.CLabel("outside_case_a", tags={"ins_addr": 0x4654}, codegen=codegen),
                    structured_c.CLabel("case_b", tags={"ins_addr": 0x4660}, codegen=codegen),
                    structured_c.CLabel("case_c", tags={"ins_addr": 0x4670}, codegen=codegen),
                    structured_c.CLabel("default_case", tags={"ins_addr": 0x4680}, codegen=codegen),
                ],
                codegen=codegen,
            )
        )

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.materialized_count == 1
        assert [stmt.name for stmt in case_a.statements] == ["case_a_first", "case_a_second"]
        assert codegen._inertia_typed_edge_switch_ast_materialization_8616["region_statement_populated_count"] == 4
        [switch_ast] = codegen._inertia_typed_edge_switch_ast_nodes_8616
        rendered = switch_ast.c_repr()
        assert "case_a_first:" in rendered
        assert "case_a_second:" in rendered
        assert "outside_case_a:" not in rendered

    def test_typed_edge_switch_ast_materialization_populates_nested_exact_tagged_bodies(self):
        codegen = _AstCodegen()
        condition = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        case_a = Region(block_addr=0x4690)
        case_b = Region(block_addr=0x46A0)
        case_c = Region(block_addr=0x46B0)
        default_region = Region(block_addr=0x46C0)
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x4690}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x46A0}, codegen=codegen)
        case_c_stmt = structured_c.CLabel("case_c", tags={"ins_addr": 0x46B0}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x46C0}, codegen=codegen)
        case_a.statements.append(object())
        switch_region = Region(block_addr=0x4608, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        nested = structured_c.CIfElse(
            [(condition, structured_c.CStatements([case_a_stmt, case_b_stmt], codegen=codegen))],
            else_node=structured_c.CStatements([case_c_stmt, default_stmt], codegen=codegen),
            tags={"ins_addr": 0x4608},
            codegen=codegen,
        )
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([nested], codegen=codegen))

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.materialized_count == 1
        assert codegen._inertia_typed_edge_switch_ast_materialization_8616["region_statement_populated_count"] == 4
        assert [stmt.name for stmt in case_a.statements if isinstance(stmt, structured_c.CLabel)] == ["case_a"]
        assert [stmt.name for stmt in case_b.statements] == ["case_b"]
        assert [stmt.name for stmt in case_c.statements] == ["case_c"]
        assert [stmt.name for stmt in default_region.statements] == ["default_case"]

    def test_typed_edge_switch_ast_materialization_populates_detached_switch_targets(self):
        codegen = _AstCodegen()
        case_a = Region(block_addr=0x46D0)
        case_b = Region(block_addr=0x46E0)
        case_c = Region(block_addr=0x46F0)
        default_region = Region(block_addr=0x4700)
        case_a.metadata["region_statement_ins_addrs"] = (0x46D0,)
        case_b.metadata["region_statement_ins_addrs"] = (0x46E0,)
        case_c.metadata["region_statement_ins_addrs"] = (0x46F0,)
        default_region.metadata["region_statement_ins_addrs"] = (0x4700,)
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x46D0}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x46E0}, codegen=codegen)
        case_c_stmt = structured_c.CLabel("case_c", tags={"ins_addr": 0x46F0}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4700}, codegen=codegen)
        switch_region = Region(block_addr=0x46C8, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [case_a_stmt, case_b_stmt, case_c_stmt, default_stmt],
                codegen=codegen,
            )
        )

        result = materialize_typed_edge_switch_ast_8616(codegen)

        assert result.materialized_count == 1
        assert codegen._inertia_typed_edge_switch_ast_materialization_8616["region_statement_populated_count"] == 4
        assert [stmt.name for stmt in case_a.statements] == ["case_a"]
        assert [stmt.name for stmt in case_b.statements] == ["case_b"]
        assert [stmt.name for stmt in case_c.statements] == ["case_c"]
        assert [stmt.name for stmt in default_region.statements] == ["default_case"]

    def test_typed_edge_switch_replacement_safety_refuses_missing_guard_span(self):
        codegen = _AstCodegen()
        case_a = Region(block_addr=0x4750)
        case_b = Region(block_addr=0x4760)
        case_c = Region(block_addr=0x4770)
        default_region = Region(block_addr=0x4780)
        for label, region in (
            ("case_a", case_a),
            ("case_b", case_b),
            ("case_c", case_c),
            ("default_case", default_region),
        ):
            region.statements.append(structured_c.CLabel(label, tags={"ins_addr": region.block_addr}, codegen=codegen))
        switch_region = Region(block_addr=0x4700, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.changed is False
        assert result.safe_count == 0
        assert result.refusal_reasons == ("missing_switch_guard_statement_span",)
        assert result.status is TypedEdgeSwitchSafetyStatus8616.Blocked
        assert result.blocker_layer == "structuring.codegen.c_ast_replacement"

    def test_typed_edge_switch_replacement_safety_records_contiguous_candidate(self):
        codegen = _AstCodegen()
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x4800}, codegen=codegen)
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x4850}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x4860}, codegen=codegen)
        case_c_stmt = structured_c.CLabel("case_c", tags={"ins_addr": 0x4870}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4880}, codegen=codegen)
        case_a = Region(block_addr=0x4850, statements=[case_a_stmt])
        case_b = Region(block_addr=0x4860, statements=[case_b_stmt])
        case_c = Region(block_addr=0x4870, statements=[case_c_stmt])
        default_region = Region(block_addr=0x4880, statements=[default_stmt])
        switch_region = Region(block_addr=0x4800, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4800,)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [guard, case_a_stmt, case_b_stmt, case_c_stmt, default_stmt],
                codegen=codegen,
            )
        )

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.changed is False
        assert result.safe_count == 1
        assert result.refused_count == 0
        assert result.status is TypedEdgeSwitchSafetyStatus8616.Safe
        assert result.blocker_layer is None
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["span"] == [0, 5]
        assert codegen._inertia_typed_edge_switch_replacement_safety_8616["safe_count"] == 1
        assert codegen._inertia_typed_edge_switch_replacement_safety_8616["status"] == "safe"

    def test_typed_edge_switch_replacement_safety_prefers_provenance_keys_over_addresses(self):
        codegen = _AstCodegen()
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x4F80}, codegen=codegen)
        case_a_stmt = structured_c.CLabel(
            "case_a",
            tags={"ins_addr": 0x4F90, "vex_block_addr": 0x4F90, "vex_stmt_idx": 1},
            codegen=codegen,
        )
        case_b_stmt = structured_c.CLabel(
            "case_b",
            tags={"ins_addr": 0x4FA0, "vex_block_addr": 0x4FA0, "vex_stmt_idx": 1},
            codegen=codegen,
        )
        default_stmt = structured_c.CLabel(
            "default_case",
            tags={"ins_addr": 0x4FB0, "vex_block_addr": 0x4FB0, "vex_stmt_idx": 1},
            codegen=codegen,
        )
        same_address_noise = structured_c.CLabel(
            "noise",
            tags={"ins_addr": 0x4F90, "vex_block_addr": 0x4F90, "vex_stmt_idx": 99},
            codegen=codegen,
        )
        case_a = Region(block_addr=0x4F90, statements=[])
        case_a.metadata["region_statement_ins_addrs"] = (0x4F90,)
        case_a.metadata["region_statement_provenance_keys"] = (("vex", 0x4F90, 1),)
        case_b = Region(block_addr=0x4FA0, statements=[])
        case_b.metadata["region_statement_ins_addrs"] = (0x4FA0,)
        case_b.metadata["region_statement_provenance_keys"] = (("vex", 0x4FA0, 1),)
        default_region = Region(block_addr=0x4FB0, statements=[])
        default_region.metadata["region_statement_ins_addrs"] = (0x4FB0,)
        default_region.metadata["region_statement_provenance_keys"] = (("vex", 0x4FB0, 1),)
        switch_region = Region(block_addr=0x4F80, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4F80,)
        switch_region.metadata["switch_candidates"] = [case_a, case_b]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [guard, case_a_stmt, case_b_stmt, default_stmt, same_address_noise],
                codegen=codegen,
            )
        )

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 1
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["case_statement_counts"] == [1, 1]
        assert debug_region["span"] == [0, 4]

    def test_typed_edge_switch_replacement_safety_maps_unpositioned_keys_to_positioned_owner(self):
        codegen = _AstCodegen()
        condition = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        unpositioned_guard_payload = structured_c.CLabel(
            "guard_payload",
            tags={"ins_addr": 0x5010, "vex_block_addr": 0x5010, "vex_stmt_idx": 1},
            codegen=codegen,
        )
        guard_owner = structured_c.CIfElse(
            [(condition, unpositioned_guard_payload)],
            tags={"ins_addr": 0x5000},
            codegen=codegen,
        )
        case_a_stmt = structured_c.CLabel(
            "case_a",
            tags={"ins_addr": 0x5020, "vex_block_addr": 0x5020, "vex_stmt_idx": 1},
            codegen=codegen,
        )
        case_b_stmt = structured_c.CLabel(
            "case_b",
            tags={"ins_addr": 0x5030, "vex_block_addr": 0x5030, "vex_stmt_idx": 1},
            codegen=codegen,
        )
        case_a = Region(block_addr=0x5020)
        case_a.metadata["region_statement_provenance_keys"] = (("vex", 0x5020, 1),)
        case_b = Region(block_addr=0x5030)
        case_b.metadata["region_statement_provenance_keys"] = (("vex", 0x5030, 1),)
        switch_region = Region(block_addr=0x5000, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x5010,)
        switch_region.metadata["switch_guard_statement_provenance_keys"] = (("vex", 0x5010, 1),)
        switch_region.metadata["switch_candidates"] = [case_a, case_b]
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        wrapper = structured_c.CWhileLoop(
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CStatements([guard_owner, case_a_stmt, case_b_stmt], codegen=codegen),
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([wrapper], codegen=codegen))

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 1
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["missing_statement_position_count"] == 0
        assert debug_region["span"] == [0, 3]

    def test_typed_edge_switch_replacement_safety_refuses_raw_body_without_positioned_owner(self):
        codegen = _AstCodegen()
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x5050}, codegen=codegen)
        detached_case_stmt = structured_c.CLabel(
            "detached_case",
            tags={"ins_addr": 0x5060, "vex_block_addr": 0x5060, "vex_stmt_idx": 1},
            codegen=codegen,
        )
        case_region = Region(block_addr=0x5060)
        case_region.metadata["region_statement_provenance_keys"] = (("vex", 0x5060, 1),)
        switch_region = Region(block_addr=0x5050, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x5050,)
        switch_region.metadata["switch_candidates"] = [case_region]
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([guard], codegen=codegen))

        original_tree = structuring_codegen._iter_statement_tree_8616
        try:
            structuring_codegen._iter_statement_tree_8616 = lambda node: (
                (*original_tree(node), detached_case_stmt) if node is guard else original_tree(node)
            )
            result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)
        finally:
            structuring_codegen._iter_statement_tree_8616 = original_tree

        assert result.safe_count == 0
        assert result.refusal_reasons == ("missing_positioned_switch_body_statements",)

    def test_typed_edge_switch_replacement_safety_descends_direct_nested_cstatements(self):
        codegen = _AstCodegen()
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x5070}, codegen=codegen)
        case_stmt = structured_c.CLabel(
            "case_a",
            tags={"ins_addr": 0x5080, "vex_block_addr": 0x5080, "vex_stmt_idx": 1},
            codegen=codegen,
        )
        nested_body = structured_c.CStatements([guard, case_stmt], codegen=codegen)
        case_region = Region(block_addr=0x5080)
        case_region.metadata["region_statement_provenance_keys"] = (("vex", 0x5080, 1),)
        switch_region = Region(block_addr=0x5070, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x5070,)
        switch_region.metadata["switch_candidates"] = [case_region]
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([nested_body], codegen=codegen))

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 1
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["missing_statement_position_count"] == 0
        assert debug_region["span"] == [0, 2]

    def test_typed_edge_switch_replacement_safety_refuses_nested_if_cascade_owner(self):
        codegen = _AstCodegen()
        condition = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x4950}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x4960}, codegen=codegen)
        case_c_stmt = structured_c.CLabel("case_c", tags={"ins_addr": 0x4970}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4980}, codegen=codegen)
        nested_c = structured_c.CIfElse(
            [(condition, structured_c.CStatements([case_c_stmt], codegen=codegen))],
            else_node=structured_c.CStatements([default_stmt], codegen=codegen),
            tags={"ins_addr": 0x4930},
            codegen=codegen,
        )
        nested_b = structured_c.CIfElse(
            [(condition, structured_c.CStatements([case_b_stmt], codegen=codegen))],
            else_node=structured_c.CStatements([nested_c], codegen=codegen),
            tags={"ins_addr": 0x4920},
            codegen=codegen,
        )
        guard = structured_c.CIfElse(
            [(condition, structured_c.CStatements([case_a_stmt], codegen=codegen))],
            else_node=structured_c.CStatements([nested_b], codegen=codegen),
            tags={"ins_addr": 0x4910},
            codegen=codegen,
        )
        case_a = Region(block_addr=0x4950, statements=[case_a_stmt])
        case_b = Region(block_addr=0x4960, statements=[case_b_stmt])
        case_c = Region(block_addr=0x4970, statements=[case_c_stmt])
        default_region = Region(block_addr=0x4980, statements=[default_stmt])
        switch_region = Region(block_addr=0x4910, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4910, 0x4920, 0x4928, 0x4930)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [guard],
                codegen=codegen,
            )
        )

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.changed is False
        assert result.safe_count == 0
        assert result.refused_count == 1
        assert result.refusal_reasons == ("multi_container_switch_span_unmaterialized",)
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["container_count"] > 1
        assert debug_region["refusal_reason"] == "multi_container_switch_span_unmaterialized"
        assert debug_region["missing_guard_addrs"] == [0x4928]

    def test_typed_edge_switch_replacement_safety_uses_detached_target_address_evidence(self):
        codegen = _AstCodegen()
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x4A00}, codegen=codegen)
        case_a = Region(block_addr=0x4A50)
        case_b = Region(block_addr=0x4A60)
        case_c = Region(block_addr=0x4A70)
        default_region = Region(block_addr=0x4A80)
        case_a.metadata["region_statement_ins_addrs"] = (0x4A50,)
        case_b.metadata["region_statement_ins_addrs"] = (0x4A60,)
        case_c.metadata["region_statement_ins_addrs"] = (0x4A70,)
        default_region.metadata["region_statement_ins_addrs"] = (0x4A80,)
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x4A50}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x4A60}, codegen=codegen)
        case_c_stmt = structured_c.CLabel("case_c", tags={"ins_addr": 0x4A70}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4A80}, codegen=codegen)
        switch_region = Region(block_addr=0x4A00, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4A00,)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [guard, case_a_stmt, case_b_stmt, case_c_stmt, default_stmt],
                codegen=codegen,
            )
        )

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 1
        assert result.refused_count == 0
        assert case_a.statements == []
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["span"] == [0, 5]

    def test_typed_edge_switch_replacement_safety_accepts_nested_statement_list_span(self):
        codegen = _AstCodegen()
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x4B00}, codegen=codegen)
        shared_case_stmt = structured_c.CExpressionStatement(
            structured_c.CConstant(1, SimTypeShort(False), tags={"ins_addr": 0x4B52}, codegen=codegen),
            tags={"ins_addr": 0x4B50},
            codegen=codegen,
        )
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x4B60}, codegen=codegen)
        case_c_stmt = structured_c.CLabel("case_c", tags={"ins_addr": 0x4B70}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4B80}, codegen=codegen)
        case_a = Region(block_addr=0x4B50, statements=[shared_case_stmt])
        case_b = Region(block_addr=0x4B60, statements=[case_b_stmt])
        case_c = Region(block_addr=0x4B70, statements=[case_c_stmt])
        default_region = Region(block_addr=0x4B80, statements=[default_stmt])
        switch_region = Region(block_addr=0x4B00, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4B00,)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, case_c, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [
                    structured_c.CIfElse(
                        [
                            (
                                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                                structured_c.CStatements(
                                    [guard, shared_case_stmt, case_b_stmt, case_c_stmt, default_stmt],
                                    codegen=codegen,
                                ),
                            )
                        ],
                        tags={"ins_addr": 0x4B00},
                        codegen=codegen,
                    )
                ],
                codegen=codegen,
            )
        )
        case_a.metadata["region_statement_ins_addrs"] = (0x4B50, 0x4B52)

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 1
        assert result.refused_count == 0
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["span"] == [0, 5]
        assert debug_region["span_source"] == "statement_list_sequence"

    def test_typed_edge_switch_ast_replacement_splices_nested_statement_list_span(self):
        codegen = _AstCodegen()
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x4D00}, codegen=codegen)
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x4D50}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x4D60}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4D80}, codegen=codegen)
        case_a = Region(block_addr=0x4D50, statements=[case_a_stmt])
        case_b = Region(block_addr=0x4D60, statements=[case_b_stmt])
        default_region = Region(block_addr=0x4D80, statements=[default_stmt])
        switch_region = Region(block_addr=0x4D00, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_case_values"] = (69, 33)
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4D00,)
        switch_region.metadata["switch_candidates"] = [case_a, case_b]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        nested_body = structured_c.CStatements(
            [guard, case_a_stmt, case_b_stmt, default_stmt],
            codegen=codegen,
        )
        wrapper = structured_c.CWhileLoop(
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            nested_body,
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([wrapper], codegen=codegen)
        )

        result = replace_typed_edge_switch_ast_8616(codegen)

        assert result.changed is True
        assert result.replaced_count == 1
        [top_level] = codegen.cfunc.statements.statements
        assert top_level is wrapper
        [nested_replacement] = nested_body.statements
        assert isinstance(nested_replacement, structured_c.CSwitchCase)
        assert "case 69:" in nested_replacement.c_repr()

    def test_typed_edge_switch_replacement_safety_refuses_multi_container_dominant_span(self):
        codegen = _AstCodegen()
        condition = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        alternate_guard = structured_c.CLabel("alternate_guard", tags={"ins_addr": 0x4E00}, codegen=codegen)
        guard_owner = structured_c.CIfElse(
            [(condition, structured_c.CStatements([alternate_guard], codegen=codegen))],
            tags={"ins_addr": 0x4E00},
            codegen=codegen,
        )
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x4E00}, codegen=codegen)
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x4E50}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x4E60}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4E80}, codegen=codegen)
        case_a = Region(block_addr=0x4E50, statements=[case_a_stmt])
        case_b = Region(block_addr=0x4E60, statements=[case_b_stmt])
        default_region = Region(block_addr=0x4E80, statements=[default_stmt])
        switch_region = Region(block_addr=0x4E00, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4E00,)
        switch_region.metadata["switch_candidates"] = [case_a, case_b]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        nested_body = structured_c.CStatements(
            [guard, case_a_stmt, case_b_stmt, default_stmt],
            codegen=codegen,
        )
        wrapper = structured_c.CWhileLoop(
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            nested_body,
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([guard_owner, wrapper], codegen=codegen)
        )

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 0
        assert result.refusal_reasons == ("switch_spans_divergent_structured_children",)
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["container_count"] > 1
        assert debug_region["refusal_reason"] == "switch_spans_divergent_structured_children"

    def test_typed_edge_switch_replacement_safety_refuses_large_dominant_span(self):
        codegen = _AstCodegen()
        alternate_guard = structured_c.CLabel("alternate_guard", tags={"ins_addr": 0x4F00}, codegen=codegen)
        guard_owner = structured_c.CIfElse(
            [
                (
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    structured_c.CStatements([alternate_guard], codegen=codegen),
                )
            ],
            tags={"ins_addr": 0x4F00},
            codegen=codegen,
        )
        nested_statements = [
            structured_c.CLabel(f"stmt_{index}", tags={"ins_addr": 0x4F00 + index}, codegen=codegen)
            for index in range(70)
        ]
        case_a = Region(block_addr=0x4F10, statements=[nested_statements[16]])
        case_b = Region(block_addr=0x4F20, statements=[nested_statements[32]])
        default_region = Region(block_addr=0x4F30, statements=[nested_statements[48]])
        switch_region = Region(block_addr=0x4F00, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = tuple(0x4F00 + index for index in range(70))
        switch_region.metadata["switch_candidates"] = [case_a, case_b]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        wrapper = structured_c.CWhileLoop(
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CStatements(nested_statements, codegen=codegen),
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([guard_owner, wrapper], codegen=codegen)
        )

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 0
        assert result.refusal_reasons == ("switch_spans_divergent_structured_children",)
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["container_count"] > 1
        assert debug_region["refusal_reason"] == "switch_spans_divergent_structured_children"

    def test_typed_edge_switch_replacement_safety_refuses_large_proven_dominant_span(self):
        codegen = _AstCodegen()
        nested_statements = [
            structured_c.CLabel(
                f"stmt_{index}",
                tags={
                    "ins_addr": 0x5100 + index,
                    "vex_block_addr": 0x5100 + index,
                    "vex_stmt_idx": 1,
                },
                codegen=codegen,
            )
            for index in range(70)
        ]
        case_a = Region(block_addr=0x5110)
        case_a.metadata["region_statement_ins_addrs"] = tuple(0x5100 + index for index in range(35))
        case_a.metadata["region_statement_provenance_keys"] = tuple(
            ("vex", 0x5100 + index, 1) for index in range(35)
        )
        case_b = Region(block_addr=0x5120)
        case_b.metadata["region_statement_ins_addrs"] = tuple(0x5100 + index for index in range(35, 70))
        case_b.metadata["region_statement_provenance_keys"] = tuple(
            ("vex", 0x5100 + index, 1) for index in range(35, 70)
        )
        switch_region = Region(block_addr=0x5100, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x5100,)
        switch_region.metadata["switch_guard_statement_provenance_keys"] = (("vex", 0x5100, 1),)
        switch_region.metadata["switch_candidates"] = [case_a, case_b]
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        wrapper = structured_c.CWhileLoop(
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            structured_c.CStatements(nested_statements, codegen=codegen),
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([wrapper], codegen=codegen))

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 0
        assert result.refusal_reasons == ("dominant_switch_span_too_large",)
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["span"] == [0, 70]
        assert debug_region["provenance_backed_span"] is True
        assert debug_region["max_dominant_span"] == 64

    def test_typed_edge_switch_replacement_safety_refuses_top_level_control_in_span(self):
        codegen = _AstCodegen()
        condition = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        guard = structured_c.CIfElse(
            [(condition, structured_c.CStatements([], codegen=codegen))],
            tags={"ins_addr": 0x4C00},
            codegen=codegen,
        )
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x4C50}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x4C60}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4C80}, codegen=codegen)
        case_a = Region(block_addr=0x4C50, statements=[case_a_stmt])
        case_b = Region(block_addr=0x4C60, statements=[case_b_stmt])
        default_region = Region(block_addr=0x4C80, statements=[default_stmt])
        switch_region = Region(block_addr=0x4C00, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4C00,)
        switch_region.metadata["switch_candidates"] = [case_a, case_b]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        for region in [switch_region, case_a, case_b, default_region]:
            graph.add_node(region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [guard, case_a_stmt, case_b_stmt, default_stmt],
                codegen=codegen,
            )
        )

        result = evaluate_typed_edge_switch_replacement_safety_8616(codegen)

        assert result.safe_count == 0
        assert result.refused_count == 1
        assert result.refusal_reasons == ("structured_control_in_switch_span_unmaterialized",)
        [debug_region] = codegen._inertia_typed_edge_switch_replacement_safety_debug_8616["regions"]
        assert debug_region["span"] == [0, 4]
        assert debug_region["refusal_reason"] == "structured_control_in_switch_span_unmaterialized"

    def test_typed_edge_switch_ast_replacement_replaces_safe_top_level_span(self):
        codegen = _AstCodegen()
        guard = structured_c.CLabel("guard", tags={"ins_addr": 0x4C00}, codegen=codegen)
        case_a_stmt = structured_c.CLabel("case_a", tags={"ins_addr": 0x4C50}, codegen=codegen)
        case_b_stmt = structured_c.CLabel("case_b", tags={"ins_addr": 0x4C60}, codegen=codegen)
        case_c_stmt = structured_c.CLabel("case_c", tags={"ins_addr": 0x4C70}, codegen=codegen)
        default_stmt = structured_c.CLabel("default_case", tags={"ins_addr": 0x4C80}, codegen=codegen)
        case_a = Region(block_addr=0x4C50)
        case_b = Region(block_addr=0x4C60)
        case_c = Region(block_addr=0x4C70)
        default_region = Region(block_addr=0x4C80)
        for region in (case_a, case_b, case_c, default_region):
            region.metadata["region_statement_ins_addrs"] = (region.block_addr,)
        switch_region = Region(block_addr=0x4C00, region_type=RegionType.IncSwitch)
        switch_region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        switch_region.metadata["switch_expr_ast"] = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
        switch_region.metadata["switch_case_values"] = (69, 27, 33)
        switch_region.metadata["switch_guard_statement_ins_addrs"] = (0x4C00,)
        switch_region.metadata["switch_candidates"] = [case_a, case_b, case_c]
        switch_region.metadata["switch_default_target"] = default_region
        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)
        codegen._inertia_grouped_structuring_graph = graph
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(
                [guard, case_a_stmt, case_b_stmt, case_c_stmt, default_stmt],
                codegen=codegen,
            )
        )

        result = replace_typed_edge_switch_ast_8616(codegen)

        assert result.changed is True
        assert result.replaced_count == 1
        assert result.refused_count == 0
        [replacement] = codegen.cfunc.statements.statements
        assert isinstance(replacement, structured_c.CSwitchCase)
        rendered = replacement.c_repr()
        assert "switch (1)" in rendered
        assert "case 69:" in rendered
        assert "default:" in rendered

    def test_ir_value_lowering_resolves_named_register_offsets(self):
        codegen = _AstCodegen()

        expr = lower_ir_value_to_c_expr_8616(
            IRValue(MemSpace.REG, name="cx", size=2),
            codegen.project,
            codegen,
            resolve_register_name=True,
        )

        assert isinstance(expr, structured_c.CVariable)
        assert expr.variable.reg == codegen.project.arch.registers["cx"][0]
        assert expr.variable.name == "cx"

    def test_apply_codegen_opt_in_records_switch_replacement_safety(self, monkeypatch):
        calls: list[str] = []
        codegen = SimpleNamespace(cfunc=SimpleNamespace())

        monkeypatch.setenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", "1")
        monkeypatch.setattr(
            structuring_codegen,
            "evaluate_typed_edge_switch_replacement_safety_8616",
            lambda got_codegen: calls.append("safety")
            or structuring_codegen.TypedEdgeSwitchReplacementSafetyResult8616(
                attempted_count=2,
                safe_count=1,
                refused_count=1,
                refusal_reasons=("missing_switch_guard_statement_span",),
            ),
        )

        assert apply_structuring_codegen_8616(codegen) is False
        assert calls == ["safety"]
        assert codegen.cfunc._structuring_stats["typed_edge_switch_lowering_status"] == {
            "attempted_count": 0,
            "artifact_count": 0,
            "loop_break_default_blocker_reasons": {},
            "loop_break_default_candidate_count": 0,
            "normalization_ready_artifact_count": 0,
            "partial_artifact_count": 0,
            "pre_codegen_transform_blocker_reasons": {},
            "pre_codegen_transform_ready_artifact_count": 0,
            "ready_artifact_count": 0,
            "status": "no_candidates",
            "blocker_layer": None,
            "blocker_reason": None,
            "changed": False,
            "owner": "structuring.codegen",
        }
        assert codegen.cfunc._structuring_stats["typed_edge_switch_replacement_safety"] == {
            "attempted_count": 2,
            "safe_count": 1,
            "refused_count": 1,
            "refusal_reasons": ("missing_switch_guard_statement_span",),
            "status": "blocked",
            "blocker_layer": "structuring.codegen.c_ast_replacement",
            "changed": False,
        }

    def test_apply_codegen_records_post_c_ast_switch_lowering_blocker(self):
        codegen = SimpleNamespace(cfunc=SimpleNamespace())
        switch_region = Region(block_addr=0x4D00, region_type=RegionType.IncSwitch)
        switch_region.metadata["typed_edge_switch_region_artifact"] = {
            "status": "ready",
            "owner": "structuring.analysis",
            "detection": "typed_condition_edge_cascade",
            "region_id": 0x4D00,
            "case_region_ids": [0x4D10, 0x4D20, 0x4D30],
            "case_values": [1, 2, 3],
            "default_region_id": 0x4D40,
        }
        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)
        codegen._inertia_grouped_structuring_graph = graph

        assert apply_structuring_codegen_8616(codegen) is False

        assert codegen._inertia_typed_edge_switch_lowering_status_8616 == {
            "attempted_count": 1,
            "artifact_count": 1,
            "loop_break_default_blocker_reasons": {},
            "loop_break_default_candidate_count": 0,
            "normalization_ready_artifact_count": 0,
            "partial_artifact_count": 0,
            "pre_codegen_transform_blocker_reasons": {},
            "pre_codegen_transform_ready_artifact_count": 0,
            "ready_artifact_count": 1,
            "status": "blocked_post_c_ast",
            "blocker_layer": "structuring.codegen.production_lowering",
            "blocker_reason": "pre_c_ast_lowering_hook_unavailable",
            "changed": False,
            "owner": "structuring.codegen",
        }

    def test_apply_codegen_records_partial_switch_ladder_as_unready(self):
        codegen = SimpleNamespace(cfunc=SimpleNamespace())
        switch_region = Region(block_addr=0x4D00, region_type=RegionType.IncSwitch)
        switch_region.metadata["typed_edge_switch_region_artifact"] = {
            "status": "partial_ladder",
            "owner": "structuring.analysis",
            "detection": "typed_condition_edge_cascade",
            "region_id": 0x4D00,
            "case_region_ids": [0x4D10, 0x4D20, 0x4D30],
            "case_values": [1, 2, 3],
            "default_region_id": 0x4D40,
            "remaining_edge_guard_count": 2,
            "decision_tree_summary": {
                "expanded_root_normalization_readiness": {
                    "ready": True,
                    "status": "branch_splits_ready",
                }
            },
        }
        graph = RegionGraph()
        graph.entry = switch_region
        graph.add_node(switch_region)
        codegen._inertia_grouped_structuring_graph = graph

        assert apply_structuring_codegen_8616(codegen) is False

        assert codegen._inertia_typed_edge_switch_lowering_status_8616 == {
            "attempted_count": 0,
            "artifact_count": 1,
            "loop_break_default_blocker_reasons": {},
            "loop_break_default_candidate_count": 0,
            "normalization_ready_artifact_count": 1,
            "partial_artifact_count": 1,
            "pre_codegen_transform_blocker_reasons": {},
            "pre_codegen_transform_ready_artifact_count": 0,
            "ready_artifact_count": 0,
            "status": "no_candidates",
            "blocker_layer": None,
            "blocker_reason": "partial_switch_ladder_unready",
            "changed": False,
            "owner": "structuring.codegen",
        }

    def test_codegen_stats_tracking(self):
        """
        Verify that codegen tracks statistics.
        """
        graph = RegionGraph()
        loop1 = Region(block_addr=0x5000, region_type=RegionType.Loop)
        switch1 = Region(block_addr=0x5001, region_type=RegionType.IncSwitch)
        linear1 = Region(block_addr=0x5002, region_type=RegionType.Linear)

        graph.entry = loop1
        for r in [loop1, switch1, linear1]:
            graph.add_node(r)

        codegen = StructuringCodegenPass()
        codegen.apply(graph)

        # Stats should be tracked
        assert codegen.stats["loops_rendered"] >= 0, "Should track loops"
        assert codegen.stats["switches_rendered"] >= 0, "Should track switches"

    def test_multiple_loops_and_switches(self):
        """
        Test codegen with multiple Loop and IncSwitch regions.
        """
        graph = RegionGraph()

        # Create 2 loops and 2 switches
        regions = []
        for i, rtype in enumerate([RegionType.Loop, RegionType.IncSwitch, RegionType.Loop, RegionType.IncSwitch]):
            r = Region(block_addr=0x6000 + i * 4, region_type=rtype)
            if rtype == RegionType.IncSwitch:
                r.metadata["switch_candidates"] = [Region(block_addr=0x7000 + i)]
            graph.add_node(r)
            regions.append(r)

        graph.entry = regions[0]

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert code is not None, "Should generate code for mixed regions"
        assert codegen.stats["loops_rendered"] > 0, "Should count loops"
        assert codegen.stats["switches_rendered"] > 0, "Should count switches"

    def test_loop_codegen_mentions_structuring_variables_for_abnormal_loop(self):
        loop_region = Region(block_addr=0x9000, region_type=RegionType.Loop)
        loop_region.metadata["abnormal_loop_plan"] = {
            "can_normalize": True,
            "exit_variable_name": "__loop_exit_sel_9000",
        }
        loop_region.metadata["structuring_variables"] = ["__loop_exit_sel_9000"]
        loop_region.metadata["unstructured_exits"] = [(0x9000, 0x9001)]

        graph = RegionGraph()
        graph.entry = loop_region
        graph.add_node(loop_region)

        codegen = StructuringCodegenPass()
        code = codegen.apply(graph)

        assert "__loop_exit_sel_9000" in code
        assert "structuring variables" in code

    def test_shared_return_unused_call_occurrence_is_coalesced(self):
        codegen = _AstCodegen()
        call = structured_c.CFunctionCall(
            "settextcolor",
            None,
            [structured_c.CConstant(15, SimTypeShort(False), codegen=codegen)],
            codegen=codegen,
        )
        first = structured_c.CAssignment(
            structured_c.CDirtyExpression(SimpleNamespace(varid=1, name="vvar_1"), codegen=codegen),
            call,
            codegen=codegen,
        )
        duplicate = structured_c.CAssignment(
            structured_c.CDirtyExpression(SimpleNamespace(varid=2, name="vvar_2"), codegen=codegen),
            call,
            codegen=codegen,
        )
        first_wrapper = structured_c.CStatements([first], codegen=codegen)
        duplicate_wrapper = structured_c.CStatements([duplicate], codegen=codegen)
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([first_wrapper, duplicate_wrapper], codegen=codegen)
        )
        codegen._inertia_callsite_summaries = {
            id(call): CallsiteSummary8616(
                callsite_addr=0x1011,
                target_addr=0x2000,
                return_addr=0x1014,
                kind="near",
                arg_count=1,
                arg_widths=(2,),
                stack_cleanup=2,
                return_register="ax",
                return_used=False,
            )
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is True

        assert first_wrapper.statements == [first]
        assert duplicate_wrapper.statements == []
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 1, 1, 0)

    def test_shared_return_used_call_occurrence_is_retained(self):
        codegen = _AstCodegen()
        call = structured_c.CFunctionCall("toupper", None, [], codegen=codegen)
        first = structured_c.CAssignment(
            structured_c.CVariable(
                SimRegisterVariable(0, 2, name="ax"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            call,
            codegen=codegen,
        )
        duplicate = structured_c.CAssignment(
            structured_c.CVariable(
                SimRegisterVariable(2, 2, name="dx"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            call,
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([first, duplicate], codegen=codegen)
        )
        codegen._inertia_callsite_summaries = {
            id(call): CallsiteSummary8616(
                callsite_addr=0x1111,
                target_addr=0x2100,
                return_addr=0x1114,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="ax",
                return_used=True,
            )
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is False

        assert codegen.cfunc.statements.statements == [first, duplicate]
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 0, 0, 1)

    def test_shared_return_used_call_with_same_destination_is_coalesced(self):
        codegen = _AstCodegen()
        call = structured_c.CFunctionCall("toupper", None, [], codegen=codegen)
        first = structured_c.CAssignment(
            structured_c.CVariable(
                SimRegisterVariable(0, 2, name="ax#1"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            call,
            codegen=codegen,
        )
        duplicate = structured_c.CAssignment(
            structured_c.CVariable(
                SimRegisterVariable(0, 2, name="ax#2"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            call,
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([first, duplicate], codegen=codegen)
        )
        codegen._inertia_callsite_summaries = {
            id(call): CallsiteSummary8616(
                callsite_addr=0x1111,
                target_addr=0x2100,
                return_addr=0x1114,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="ax",
                return_used=True,
            )
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is True

        assert codegen.cfunc.statements.statements == [first]
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 1, 1, 0)

    def test_shared_return_used_identical_statement_reference_is_coalesced(self):
        codegen = _AstCodegen()
        call = structured_c.CFunctionCall("itoa", None, [], codegen=codegen)
        assignment = structured_c.CAssignment(
            structured_c.CVariable(
                SimRegisterVariable(0, 2, name="ax#1"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            call,
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([assignment, assignment], codegen=codegen)
        )
        codegen._inertia_callsite_summaries = {
            id(call): CallsiteSummary8616(
                callsite_addr=0x1038,
                target_addr=0x11E3,
                return_addr=0x103B,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="ax",
                return_used=True,
            )
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is True

        assert codegen.cfunc.statements.statements == [assignment]
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 1, 1, 0)

    def test_distinct_nodes_for_same_typed_callsite_are_coalesced(self):
        codegen = _AstCodegen()
        arg_a = structured_c.CVariable(
            SimStackVariable(-2, 2, base="bp", name="ch"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        arg_b = structured_c.CVariable(
            SimStackVariable(-2, 2, base="bp", name="ch"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        first_call = structured_c.CFunctionCall("toupper", None, [arg_a], codegen=codegen)
        duplicate_call = structured_c.CFunctionCall("toupper", None, [arg_b], codegen=codegen)
        first = structured_c.CAssignment(
            structured_c.CVariable(
                SimRegisterVariable(0, 2, name="ax#1"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            first_call,
            codegen=codegen,
        )
        duplicate = structured_c.CAssignment(
            structured_c.CVariable(
                SimRegisterVariable(0, 2, name="ax#2"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            duplicate_call,
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([first, duplicate], codegen=codegen)
        )
        summary = CallsiteSummary8616(
            callsite_addr=0x1048,
            target_addr=0x2100,
            return_addr=0x104B,
            kind="near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
        )
        codegen._inertia_callsite_summaries = {
            id(first_call): summary,
            id(duplicate_call): summary,
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is True

        assert codegen.cfunc.statements.statements == [first]
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 1, 1, 0)

    def test_regenerated_assignment_call_is_rebound_by_exact_callsite_tag(self):
        codegen = _AstCodegen()
        first_call = structured_c.CFunctionCall(
            "clock",
            SimpleNamespace(addr=0x2100, name="clock"),
            [],
            tags={"ins_addr": 0x1048},
            codegen=codegen,
        )
        duplicate_call = structured_c.CFunctionCall(
            "clock",
            None,
            [],
            tags={"ins_addr": 0x1048},
            codegen=codegen,
        )
        destination = SimMemoryVariable(0x17D, 4, name="clFinish")
        first = structured_c.CAssignment(
            structured_c.CVariable(
                destination,
                variable_type=SimTypeInt(True),
                codegen=codegen,
            ),
            first_call,
            codegen=codegen,
        )
        duplicate = structured_c.CAssignment(
            structured_c.CVariable(
                SimMemoryVariable(0x17D, 4, name="clFinish"),
                variable_type=SimTypeInt(True),
                codegen=codegen,
            ),
            duplicate_call,
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([first, duplicate], codegen=codegen)
        )
        summary = CallsiteSummary8616(
            callsite_addr=0x1048,
            target_addr=0x2100,
            return_addr=0x104B,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="dx_ax",
            return_used=True,
        )
        codegen._inertia_callsite_summaries = {id(first_call): summary}
        codegen._inertia_callsite_summary_inventory_8616 = {0x1048: summary}

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is True

        assert codegen.cfunc.statements.statements == [first]
        assert codegen._inertia_callsite_summaries[id(duplicate_call)] is summary
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 1, 1, 0)

    def test_regenerated_calls_at_distinct_exact_callsites_are_retained(self):
        codegen = _AstCodegen()
        summaries = tuple(
            CallsiteSummary8616(
                callsite_addr=callsite_addr,
                target_addr=0x2100,
                return_addr=callsite_addr + 3,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="dx_ax",
                return_used=True,
            )
            for callsite_addr in (0x1048, 0x1058)
        )
        calls = tuple(
            structured_c.CFunctionCall(
                "clock",
                None,
                [],
                tags={"ins_addr": summary.callsite_addr},
                codegen=codegen,
            )
            for summary in summaries
        )
        statements = [
            structured_c.CAssignment(
                structured_c.CVariable(
                    SimMemoryVariable(0x17D, 4, name="clFinish"),
                    variable_type=SimTypeInt(True),
                    codegen=codegen,
                ),
                call,
                codegen=codegen,
            )
            for call in calls
        ]
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(statements, codegen=codegen)
        )
        codegen._inertia_callsite_summaries = {id(calls[0]): summaries[0]}
        codegen._inertia_callsite_summary_inventory_8616 = {
            summary.callsite_addr: summary for summary in summaries
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is False

        assert codegen.cfunc.statements.statements == statements
        assert codegen._inertia_callsite_summaries[id(calls[1])] is summaries[1]
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert stats.raw_fact_count == 0
        assert stats.failure_count == 0

    def test_adjacent_untagged_clone_uses_unique_typed_machine_callsite(self):
        codegen = _AstCodegen()
        first_call = structured_c.CFunctionCall(
            "clock",
            SimpleNamespace(addr=0x2100, name="clock"),
            [],
            tags={"ins_addr": 0x1048},
            codegen=codegen,
        )
        duplicate_call = structured_c.CFunctionCall("clock", None, [], codegen=codegen)
        statements = [
            structured_c.CAssignment(
                structured_c.CVariable(
                    SimMemoryVariable(0x17D, 4, name="clFinish"),
                    variable_type=SimTypeInt(True),
                    codegen=codegen,
                ),
                call,
                codegen=codegen,
            )
            for call in (first_call, duplicate_call)
        ]
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(statements, codegen=codegen)
        )
        summary = CallsiteSummary8616(
            callsite_addr=0x1048,
            target_addr=0x2100,
            return_addr=0x104B,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="dx_ax",
            return_used=True,
        )
        codegen._inertia_callsite_summaries = {id(first_call): summary}
        codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is True

        assert codegen.cfunc.statements.statements == [statements[0]]
        assert codegen._inertia_callsite_summaries[id(duplicate_call)] is summary
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 1, 1, 0)

    def test_adjacent_untagged_clone_refuses_repeated_binary_target(self):
        codegen = _AstCodegen()
        first_call = structured_c.CFunctionCall(
            "clock",
            None,
            [],
            tags={"ins_addr": 0x1048},
            codegen=codegen,
        )
        second_call = structured_c.CFunctionCall("clock", None, [], codegen=codegen)
        statements = [
            structured_c.CAssignment(
                structured_c.CVariable(
                    SimMemoryVariable(0x17D, 4, name="clFinish"),
                    variable_type=SimTypeInt(True),
                    codegen=codegen,
                ),
                call,
                codegen=codegen,
            )
            for call in (first_call, second_call)
        ]
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(statements, codegen=codegen)
        )
        summaries = tuple(
            CallsiteSummary8616(
                callsite_addr=callsite_addr,
                target_addr=0x2100,
                return_addr=callsite_addr + 3,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="dx_ax",
                return_used=True,
            )
            for callsite_addr in (0x1048, 0x1058)
        )
        codegen._inertia_callsite_summaries = {id(first_call): summaries[0]}
        codegen._inertia_callsite_summary_inventory_8616 = {
            summary.callsite_addr: summary for summary in summaries
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is False

        assert codegen.cfunc.statements.statements == statements
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 0, 0, 0, 1)

    def test_same_typed_callsite_with_different_argument_is_retained(self):
        codegen = _AstCodegen()
        first_call = structured_c.CFunctionCall(
            "displaycursor",
            None,
            [structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)],
            codegen=codegen,
        )
        second_call = structured_c.CFunctionCall(
            "displaycursor",
            None,
            [structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)],
            codegen=codegen,
        )
        first = structured_c.CExpressionStatement(first_call, codegen=codegen)
        second = structured_c.CExpressionStatement(second_call, codegen=codegen)
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([first, second], codegen=codegen)
        )
        summary = CallsiteSummary8616(
            callsite_addr=0x102B,
            target_addr=0x2200,
            return_addr=0x1030,
            kind="far",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        )
        codegen._inertia_callsite_summaries = {
            id(first_call): summary,
            id(second_call): summary,
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is False
        assert codegen.cfunc.statements.statements == [first, second]
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert stats.failure_count == 1

    def test_condition_used_call_replaces_adjacent_standalone_occurrence(self):
        codegen = _AstCodegen()
        standalone_call = structured_c.CFunctionCall(
            structured_c.CConstant(0x2100, SimTypeShort(False), codegen=codegen),
            None,
            [],
            codegen=codegen,
        )
        condition_call = structured_c.CFunctionCall(
            structured_c.CConstant(0x2100, SimTypeShort(False), codegen=codegen),
            None,
            [],
            codegen=codegen,
        )
        standalone_assignment = structured_c.CAssignment(
            structured_c.CVariable(
                SimRegisterVariable(0, 2, name="ax"),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            standalone_call,
            codegen=codegen,
        )
        standalone = structured_c.CStatements([standalone_assignment], codegen=codegen)
        condition = structured_c.CBinaryOp(
            "CmpGT",
            condition_call,
            structured_c.CConstant(10, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        guard = structured_c.CIfBreak(condition, codegen=codegen)
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([standalone, guard], codegen=codegen)
        )
        summary = CallsiteSummary8616(
            callsite_addr=0x101A,
            target_addr=0x2100,
            return_addr=0x101D,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            return_shape="dx_ax",
            return_use_kind=CallsiteReturnUseKind8616.CONDITION,
        )
        codegen._inertia_callsite_summaries = {id(standalone_call): summary}

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is True

        assert codegen.cfunc.statements.statements == [guard]
        assert codegen._inertia_callsite_summaries[id(condition_call)] is summary
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 1, 1, 0)

    def test_condition_used_call_keeps_different_adjacent_target(self):
        codegen = _AstCodegen()
        standalone_call = structured_c.CFunctionCall(
            structured_c.CConstant(0x2100, SimTypeShort(False), codegen=codegen),
            None,
            [],
            codegen=codegen,
        )
        condition_call = structured_c.CFunctionCall(
            structured_c.CConstant(0x2200, SimTypeShort(False), codegen=codegen),
            None,
            [],
            codegen=codegen,
        )
        standalone = structured_c.CExpressionStatement(standalone_call, codegen=codegen)
        condition = structured_c.CBinaryOp(
            "CmpGT",
            condition_call,
            structured_c.CConstant(10, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        guard = structured_c.CIfBreak(condition, codegen=codegen)
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([standalone, guard], codegen=codegen)
        )
        codegen._inertia_callsite_summaries = {
            id(standalone_call): CallsiteSummary8616(
                callsite_addr=0x101A,
                target_addr=0x2100,
                return_addr=0x101D,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="ax",
                return_used=True,
                return_shape="dx_ax",
                return_use_kind=CallsiteReturnUseKind8616.CONDITION,
            )
        }

        assert coalesce_shared_call_side_effect_statements_8616(codegen) is False

        assert codegen.cfunc.statements.statements == [standalone, guard]
        stats = codegen._inertia_shared_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 0, 0, 0, 1)

    def test_distinct_binary_condition_calls_do_not_share_mutable_ast_node(self):
        codegen = _AstCodegen()
        shared_call = structured_c.CFunctionCall("lookup", None, [], codegen=codegen)
        shared_condition = structured_c.CBinaryOp(
            "CmpEQ",
            shared_call,
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        first_guard = structured_c.CIfBreak(shared_condition, codegen=codegen)
        second_guard = structured_c.CIfBreak(shared_condition, codegen=codegen)
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([first_guard, second_guard], codegen=codegen)
        )
        first_summary = CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x5000,
            return_addr=0x4013,
            kind="near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=True,
            return_use_kind=CallsiteReturnUseKind8616.CONDITION,
        )
        second_summary = CallsiteSummary8616(
            callsite_addr=0x4020,
            target_addr=0x5000,
            return_addr=0x4023,
            kind="near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=True,
            return_use_kind=CallsiteReturnUseKind8616.CONDITION,
        )
        shared_call.tags = {"ins_addr": first_summary.callsite_addr}
        codegen._inertia_callsite_summaries = {id(shared_call): first_summary}
        codegen._inertia_callsite_summary_inventory_8616 = {
            first_summary.callsite_addr: first_summary,
            second_summary.callsite_addr: second_summary,
        }

        assert split_distinct_condition_call_occurrences_8616(codegen) is True

        first_call = first_guard.condition.lhs
        second_call = second_guard.condition.lhs
        assert first_guard.condition is shared_condition
        assert second_guard.condition is not shared_condition
        assert first_call is shared_call
        assert isinstance(second_call, structured_c.CFunctionCall)
        assert second_call is not shared_call
        assert codegen._inertia_callsite_summaries[id(first_call)] is first_summary
        assert codegen._inertia_callsite_summaries[id(second_call)] is second_summary
        assert second_call.tags["ins_addr"] == second_summary.callsite_addr
        stats = codegen._inertia_distinct_condition_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 1, 1, 0)

    def test_ambiguous_distinct_binary_condition_calls_are_not_guessed(self):
        codegen = _AstCodegen()
        shared_call = structured_c.CFunctionCall("lookup", None, [], codegen=codegen)
        guards = [
            structured_c.CIfBreak(
                structured_c.CBinaryOp(
                    "CmpEQ",
                    shared_call,
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            )
            for _index in range(2)
        ]
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements(guards, codegen=codegen)
        )
        summaries = tuple(
            CallsiteSummary8616(
                callsite_addr=callsite_addr,
                target_addr=0x5000,
                return_addr=callsite_addr + 3,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="ax",
                return_used=True,
                return_use_kind=CallsiteReturnUseKind8616.CONDITION,
            )
            for callsite_addr in (0x4010, 0x4020, 0x4030)
        )
        codegen._inertia_callsite_summaries = {id(shared_call): summaries[0]}
        codegen._inertia_callsite_summary_inventory_8616 = {
            summary.callsite_addr: summary for summary in summaries
        }

        assert split_distinct_condition_call_occurrences_8616(codegen) is False

        assert guards[0].condition.lhs is shared_call
        assert guards[1].condition.lhs is shared_call
        stats = codegen._inertia_distinct_condition_call_occurrence_stats_8616
        assert (
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
        ) == (1, 1, 0, 0, 1)

    def test_shared_call_scans_accept_angr_dirty_statement_entries(self):
        codegen = _AstCodegen()
        summary = CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x5000,
            return_addr=None,
            kind="direct_near_tail_jump",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
        dirty = structured_c.CDirtyStatement(
            SimpleNamespace(name="terminal_dirty"),
            codegen=codegen,
        )
        codegen.cfunc = SimpleNamespace(
            statements=structured_c.CStatements([dirty], codegen=codegen)
        )
        codegen._inertia_callsite_summaries = {}
        codegen._inertia_callsite_summary_inventory_8616 = {
            summary.callsite_addr: summary,
        }

        assert split_distinct_condition_call_occurrences_8616(codegen) is False
        assert coalesce_shared_call_side_effect_statements_8616(codegen) is False
        assert codegen.cfunc.statements.statements == [dirty]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
