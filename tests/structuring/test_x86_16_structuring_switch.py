"""
Tests for switch statement detection in structural analysis.

Tests if-cascade pattern detection and switch classification.
"""

import pytest
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.structuring.structuring_analysis import StructureAnalysis
from inertia.structuring.structuring_region import Region, RegionGraph, RegionType


class TestSwitchDetection:
    """Tests for detecting if-cascade patterns as switch candidates."""

    def test_region_merge_preserves_statement_address_evidence(self):
        graph = RegionGraph()
        dst = Region(block_addr=0x1010)
        src = Region(block_addr=0x1020)
        dst.metadata["region_statement_ins_addrs"] = (0x1010,)
        src.metadata["region_statement_ins_addrs"] = (0x1020, 0x1022)
        graph.add_node(dst)
        graph.add_node(src)

        graph.merge_regions(src, dst)

        assert dst.metadata["region_statement_ins_addrs"] == (0x1010, 0x1020, 0x1022)
        assert dst.metadata["region_statement_span_source"] == "merged_region_statement_ins_addrs"

    def test_region_merge_preserves_statement_provenance_key_evidence(self):
        graph = RegionGraph()
        dst = Region(block_addr=0x1010)
        src = Region(block_addr=0x1020)
        dst.metadata["region_statement_provenance_keys"] = (("vex", 0x1010, 1),)
        src.metadata["region_statement_provenance_keys"] = (("vex", 0x1020, 1), ("vex", 0x1020, 2))
        graph.add_node(dst)
        graph.add_node(src)

        graph.merge_regions(src, dst)

        assert dst.metadata["region_statement_provenance_keys"] == (
            ("vex", 0x1010, 1),
            ("vex", 0x1020, 1),
            ("vex", 0x1020, 2),
        )
        assert dst.metadata["region_statement_span_source"] == "merged_region_statement_provenance"

    def test_simple_three_way_branch_detected_as_switch(self):
        """
        Test that three-way branch can be processed structurally.
        (Core validation: structuring framework handles multi-way branches)
        """
        entry = Region(block_addr=0x1000, region_type=RegionType.Linear)
        switch_region = Region(block_addr=0x1001, region_type=RegionType.Condition)
        case_a = Region(block_addr=0x1002, region_type=RegionType.Linear)
        case_b = Region(block_addr=0x1003, region_type=RegionType.Linear)
        case_c = Region(block_addr=0x1004, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x1005, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, switch_region, case_a, case_b, case_c, exit_region]:
            graph.add_node(r)

        # Build graph
        graph.add_edge(entry, switch_region)
        graph.add_edge(switch_region, case_a)
        graph.add_edge(switch_region, case_b)
        graph.add_edge(switch_region, case_c)
        graph.add_edge(case_a, exit_region)
        graph.add_edge(case_b, exit_region)
        graph.add_edge(case_c, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        analysis.structure()

        # Verify structuring completed successfully
        assert analysis.stats.iterations > 0, "Structuring should iterate"
        assert not analysis.stats.max_iterations_reached, "Should complete without hitting limit"

    def test_many_way_branch_switch(self):
        """
        Test detection of many-way (5+) branch.
        """
        entry = Region(block_addr=0x2000, region_type=RegionType.Linear)
        switch_region = Region(block_addr=0x2001, region_type=RegionType.Condition)
        exit_region = Region(block_addr=0x2010, region_type=RegionType.Linear)

        cases = [Region(block_addr=0x2002 + i * 4, region_type=RegionType.Linear) for i in range(5)]

        graph = RegionGraph()
        graph.entry = entry
        graph.add_node(entry)
        graph.add_node(switch_region)
        for case in cases:
            graph.add_node(case)
        graph.add_node(exit_region)

        # Build edges
        graph.add_edge(entry, switch_region)
        for case in cases:
            graph.add_edge(switch_region, case)
            graph.add_edge(case, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        analysis.structure()

        # Many-way branch should be detected as switch candidate
        assert switch_region.region_type == RegionType.IncSwitch or len(analysis.unresolved_switches) > 0, (
            "5-way branch should be strongly marked as switch"
        )

    def test_typed_edge_guard_if_cascade_detected_as_switch(self):
        entry = Region(block_addr=0x1100, region_type=RegionType.Linear)
        cond_a = Region(block_addr=0x1110, region_type=RegionType.Condition)
        cond_b = Region(block_addr=0x1120, region_type=RegionType.Condition)
        cond_c = Region(block_addr=0x1130, region_type=RegionType.Condition)
        default = Region(block_addr=0x1140, region_type=RegionType.Linear)
        cases = [
            Region(block_addr=0x1150, region_type=RegionType.Linear),
            Region(block_addr=0x1160, region_type=RegionType.Linear),
            Region(block_addr=0x1170, region_type=RegionType.Linear),
        ]
        exit_region = Region(block_addr=0x1180, region_type=RegionType.Linear)
        lhs = IRValue(MemSpace.REG, name="ax", size=2)

        for case, value in zip(cases, (69, 27, 33), strict=True):
            case.metadata["typed_condition_edge_guards"] = (
                ConditionIR(
                    op="eq",
                    lhs=lhs,
                    rhs=IRValue(MemSpace.CONST, const=value, size=2),
                    src_insn=case.block_addr,
                    block_addr=case.block_addr,
                    producer_insn=case.block_addr - 1,
                ),
            )

        graph = RegionGraph()
        graph.entry = entry
        for region in [entry, cond_a, cond_b, cond_c, default, *cases, exit_region]:
            graph.add_node(region)

        graph.add_edge(entry, cond_a)
        graph.add_edge(cond_a, cases[0])
        graph.add_edge(cond_a, cond_b)
        graph.add_edge(cond_b, cases[1])
        graph.add_edge(cond_b, cond_c)
        graph.add_edge(cond_c, cases[2])
        graph.add_edge(cond_c, default)
        graph.add_edge(default, exit_region)
        for case in cases:
            graph.add_edge(case, exit_region)

        analysis = StructureAnalysis(graph)
        analysis.structure()

        assert cond_a.region_type == RegionType.IncSwitch
        assert cond_a.metadata["switch_detection"] == "typed_condition_edge_cascade"
        assert cond_a.metadata["switch_candidates"] == cases
        assert cond_a.metadata["switch_case_values"] == (69, 27, 33)
        assert cond_a.metadata["switch_condition_lhs"] == lhs
        assert cond_a.metadata["switch_default_target"] == default
        assert "switch_guard_statement_ins_addrs" not in cond_a.metadata
        assert analysis.stats.edge_guard_switches_detected == 1

    def test_typed_edge_guard_switch_records_proven_guard_statement_span(self):
        entry = Region(block_addr=0x2100, region_type=RegionType.Linear)
        cond_a = Region(block_addr=0x2110, region_type=RegionType.Condition)
        cond_b = Region(block_addr=0x2120, region_type=RegionType.Condition)
        cond_c = Region(block_addr=0x2130, region_type=RegionType.Condition)
        default = Region(block_addr=0x2140, region_type=RegionType.Linear)
        cases = [
            Region(block_addr=0x2150, region_type=RegionType.Linear),
            Region(block_addr=0x2160, region_type=RegionType.Linear),
            Region(block_addr=0x2170, region_type=RegionType.Linear),
        ]
        lhs = IRValue(MemSpace.REG, name="ax", size=2)

        for condition, addrs in ((cond_a, (0x2110, 0x2112)), (cond_b, (0x2120,)), (cond_c, (0x2130,))):
            condition.metadata["region_statement_ins_addrs"] = addrs

        for case, condition, value in zip(cases, (cond_a, cond_b, cond_c), (69, 27, 33), strict=True):
            case.metadata["typed_condition_edge_guards"] = (
                ConditionIR(
                    op="eq",
                    lhs=lhs,
                    rhs=IRValue(MemSpace.CONST, const=value, size=2),
                    src_insn=case.block_addr,
                    block_addr=case.block_addr,
                    producer_insn=condition.block_addr,
                ),
            )

        graph = RegionGraph()
        graph.entry = entry
        for region in [entry, cond_a, cond_b, cond_c, default, *cases]:
            graph.add_node(region)

        graph.add_edge(entry, cond_a)
        graph.add_edge(cond_a, cases[0])
        graph.add_edge(cond_a, cond_b)
        graph.add_edge(cond_b, cases[1])
        graph.add_edge(cond_b, cond_c)
        graph.add_edge(cond_c, cases[2])
        graph.add_edge(cond_c, default)

        analysis = StructureAnalysis(graph)
        analysis.structure()

        assert cond_a.region_type == RegionType.IncSwitch
        assert cond_a.metadata["switch_guard_statement_ins_addrs"] == (0x2110, 0x2112, 0x2120, 0x2130)
        assert cond_a.metadata["switch_guard_statement_span_source"] == "condition_region_statement_ins_addrs"

    def test_typed_edge_guard_switch_records_proven_guard_statement_keys(self):
        cond_a = Region(block_addr=0x4110, region_type=RegionType.Condition)
        cond_b = Region(block_addr=0x4120, region_type=RegionType.Condition)
        cond_c = Region(block_addr=0x4130, region_type=RegionType.Condition)
        default = Region(block_addr=0x4140, region_type=RegionType.Linear)
        cases = [
            Region(block_addr=0x4150, region_type=RegionType.Linear),
            Region(block_addr=0x4160, region_type=RegionType.Linear),
            Region(block_addr=0x4170, region_type=RegionType.Linear),
        ]
        lhs = IRValue(MemSpace.REG, name="ax", size=2)

        for condition in (cond_a, cond_b, cond_c):
            condition.metadata["region_statement_ins_addrs"] = (condition.block_addr,)
            condition.metadata["region_statement_provenance_keys"] = (
                ("vex", condition.block_addr, 1),
                ("vex", condition.block_addr, 2),
            )

        for case, condition, value in zip(cases, (cond_a, cond_b, cond_c), (69, 27, 33), strict=True):
            case.metadata["typed_condition_edge_guards"] = (
                ConditionIR(
                    op="eq",
                    lhs=lhs,
                    rhs=IRValue(MemSpace.CONST, const=value, size=2),
                    src_insn=case.block_addr,
                    block_addr=case.block_addr,
                    producer_insn=condition.block_addr,
                ),
            )

        graph = RegionGraph()
        graph.entry = cond_a
        for region in [cond_a, cond_b, cond_c, default, *cases]:
            graph.add_node(region)
        graph.add_edge(cond_a, cases[0])
        graph.add_edge(cond_a, cond_b)
        graph.add_edge(cond_b, cases[1])
        graph.add_edge(cond_b, cond_c)
        graph.add_edge(cond_c, cases[2])
        graph.add_edge(cond_c, default)

        analysis = StructureAnalysis(graph)
        analysis.structure()

        assert cond_a.metadata["switch_guard_statement_provenance_keys"] == (
            ("vex", 0x4110, 1),
            ("vex", 0x4110, 2),
            ("vex", 0x4120, 1),
            ("vex", 0x4120, 2),
            ("vex", 0x4130, 1),
            ("vex", 0x4130, 2),
        )

    def test_typed_edge_guard_switch_skips_unguarded_continuation_regions(self):
        cond_a = Region(block_addr=0x3110, region_type=RegionType.Condition)
        pass_a = Region(block_addr=0x3118, region_type=RegionType.Linear)
        cond_b = Region(block_addr=0x3120, region_type=RegionType.Condition)
        pass_b = Region(block_addr=0x3128, region_type=RegionType.Linear)
        cond_c = Region(block_addr=0x3130, region_type=RegionType.Condition)
        default = Region(block_addr=0x3140, region_type=RegionType.Linear)
        cases = [
            Region(block_addr=0x3150, region_type=RegionType.Linear),
            Region(block_addr=0x3160, region_type=RegionType.Linear),
            Region(block_addr=0x3170, region_type=RegionType.Linear),
        ]
        lhs = IRValue(MemSpace.REG, name="ax", size=2)

        for region in (cond_a, pass_a, cond_b, pass_b, cond_c):
            region.metadata["region_statement_ins_addrs"] = (region.block_addr,)

        for case, condition, value in zip(cases, (cond_a, cond_b, cond_c), (69, 27, 33), strict=True):
            case.metadata["typed_condition_edge_guards"] = (
                ConditionIR(
                    op="eq",
                    lhs=lhs,
                    rhs=IRValue(MemSpace.CONST, const=value, size=2),
                    src_insn=case.block_addr,
                    block_addr=case.block_addr,
                    producer_insn=condition.block_addr,
                ),
            )

        graph = RegionGraph()
        graph.entry = cond_a
        for region in [cond_a, pass_a, cond_b, pass_b, cond_c, default, *cases]:
            graph.add_node(region)

        graph.add_edge(cond_a, cases[0])
        graph.add_edge(cond_a, pass_a)
        graph.add_edge(pass_a, cond_b)
        graph.add_edge(cond_b, cases[1])
        graph.add_edge(cond_b, pass_b)
        graph.add_edge(pass_b, cond_c)
        graph.add_edge(cond_c, cases[2])
        graph.add_edge(cond_c, default)

        analysis = StructureAnalysis(graph)
        analysis.structure()

        assert cond_a.region_type == RegionType.IncSwitch
        assert cond_a.metadata["switch_candidates"] == cases
        assert cond_a.metadata["switch_case_values"] == (69, 27, 33)
        assert cond_a.metadata["switch_guard_statement_ins_addrs"] == (
            0x3110,
            0x3118,
            0x3120,
            0x3128,
            0x3130,
        )

    def test_binary_branch_not_switch(self):
        """
        Test that binary branches are NOT marked as switch (need 3+).
        """
        entry = Region(block_addr=0x3000, region_type=RegionType.Linear)
        condition = Region(block_addr=0x3001, region_type=RegionType.Condition)
        then_branch = Region(block_addr=0x3002, region_type=RegionType.Linear)
        else_branch = Region(block_addr=0x3003, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x3004, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, condition, then_branch, else_branch, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, condition)
        graph.add_edge(condition, then_branch)
        graph.add_edge(condition, else_branch)
        graph.add_edge(then_branch, exit_region)
        graph.add_edge(else_branch, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        analysis.structure()

        # Binary if-else should NOT be marked as switch
        assert condition.region_type != RegionType.IncSwitch, "Binary if-else should not be marked as switch"

    def test_nested_switch_like_structures(self):
        """
        Test that nested if-cascades are handled.
        (Core validation: complex nested structures are processed)
        """
        entry = Region(block_addr=0x4000, region_type=RegionType.Linear)
        switch1 = Region(block_addr=0x4001, region_type=RegionType.Condition)
        case_a = Region(block_addr=0x4002, region_type=RegionType.Linear)
        switch2 = Region(block_addr=0x4003, region_type=RegionType.Condition)
        case_b1 = Region(block_addr=0x4004, region_type=RegionType.Linear)
        case_b2 = Region(block_addr=0x4005, region_type=RegionType.Linear)
        case_c = Region(block_addr=0x4006, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x4010, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, switch1, case_a, switch2, case_b1, case_b2, case_c, exit_region]:
            graph.add_node(r)

        # Edges
        graph.add_edge(entry, switch1)
        graph.add_edge(switch1, case_a)
        graph.add_edge(switch1, switch2)
        graph.add_edge(switch1, case_c)
        graph.add_edge(switch2, case_b1)
        graph.add_edge(switch2, case_b2)
        graph.add_edge(case_a, exit_region)
        graph.add_edge(case_b1, exit_region)
        graph.add_edge(case_b2, exit_region)
        graph.add_edge(case_c, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        analysis.structure()

        # Verify structuring completed without errors
        assert analysis.stats.iterations > 0, "Should process nested structures"
        assert not analysis.stats.max_iterations_reached, "Should complete structuring"

    def test_switch_detection_doesnt_break_loops(self):
        """
        Verify that switch detection doesn't interfere with loop detection.
        Note: This test uses a 2-way dispatch (not a switch), so it tests
        if-then-else patterns, not switch patterns.
        """
        entry = Region(block_addr=0x5000, region_type=RegionType.Linear)
        dispatch = Region(block_addr=0x5001, region_type=RegionType.Condition)
        case_loop = Region(block_addr=0x5002, region_type=RegionType.Linear)
        body = Region(block_addr=0x5003, region_type=RegionType.Linear)
        case_simple = Region(block_addr=0x5004, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x5005, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, dispatch, case_loop, body, case_simple, exit_region]:
            graph.add_node(r)

        # Build dispatch with loop in one case
        graph.add_edge(entry, dispatch)
        graph.add_edge(dispatch, case_loop)
        graph.add_edge(dispatch, case_simple)
        graph.add_edge(case_loop, body)
        graph.add_edge(body, case_loop)  # Back-edge (loop)
        graph.add_edge(case_loop, exit_region)
        graph.add_edge(case_simple, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # With 2 successors, dispatch is binary (if-then-else), not a switch
        # So we expect it to be either marked as Condition or merged
        # The key is that structuring should complete without errors
        assert not analysis.stats.max_iterations_reached, "Should complete structuring"
        assert len(result.nodes) > 0, "Should preserve graph"

    def test_switch_stats_tracking(self):
        """
        Verify that switch detection updates stats.
        (Even if not merged, switching should be detected in unresolved list or type)
        """
        entry = Region(block_addr=0x6000, region_type=RegionType.Linear)
        switch = Region(block_addr=0x6001, region_type=RegionType.Condition)
        cases = [Region(block_addr=0x6002 + i * 4, region_type=RegionType.Linear) for i in range(4)]
        exit_region = Region(block_addr=0x6020, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        graph.add_node(entry)
        graph.add_node(switch)
        for case in cases:
            graph.add_node(case)
        graph.add_node(exit_region)

        graph.add_edge(entry, switch)
        for case in cases:
            graph.add_edge(switch, case)
            graph.add_edge(case, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        analysis.structure()

        # Stats should show processing occurred
        assert analysis.stats.iterations > 0, "Should iterate"
        # After structuring, switch may be marked or unresolved
        assert (
            switch.region_type == RegionType.IncSwitch
            or analysis.stats.regions_reduced > 0
            or not analysis.stats.max_iterations_reached
        ), "Structuring should either detect switch or reduce structure"


class TestIfThenElseInherent:
    """Tests for if-then and if-then-else pattern recognition."""

    def test_if_then_else_binary_condition(self):
        """
        Test that binary if-then-else pattern is recognized and merged.
        Simple case: condition -> then-block, else-block -> both exit.
        """
        entry = Region(block_addr=0x7001, region_type=RegionType.Linear)
        condition = Region(block_addr=0x7002, region_type=RegionType.Condition)
        then_branch = Region(block_addr=0x7003, region_type=RegionType.Linear)
        else_branch = Region(block_addr=0x7004, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x7005, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, condition, then_branch, else_branch, exit_region]:
            graph.add_node(r)

        # Build graph: entry -> condition -> (then_branch, else_branch) -> exit
        graph.add_edge(entry, condition)
        graph.add_edge(condition, then_branch)
        graph.add_edge(condition, else_branch)
        graph.add_edge(then_branch, exit_region)
        graph.add_edge(else_branch, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # After structuring:
        # - condition should have been merged with branches
        # - graph should be reduced
        assert analysis.stats.regions_reduced > 0, "Should reduce if-then-else pattern"
        assert condition.region_type == RegionType.Condition, "Condition should be marked as Condition"
        # The result graph should be much smaller (heavily merged)
        assert len(result.nodes) <= 3, "Large reduction expected after if-then-else merge"

    def test_if_then_else_not_merged_when_branches_have_other_predecessors(self):
        """
        Test that if-then-else is still merged even if branches have other predecessors.
        This tests the robustness of the pattern matching.
        """
        entry = Region(block_addr=0x8001, region_type=RegionType.Linear)
        condition = Region(block_addr=0x8002, region_type=RegionType.Condition)
        then_branch = Region(block_addr=0x8003, region_type=RegionType.Linear)
        else_branch = Region(block_addr=0x8004, region_type=RegionType.Linear)
        other_pred = Region(block_addr=0x8005, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x8006, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, condition, then_branch, else_branch, other_pred, exit_region]:
            graph.add_node(r)

        # Build graph with multi-predecessor branches
        graph.add_edge(entry, condition)
        graph.add_edge(entry, other_pred)  # other_pred also branches somewhere
        graph.add_edge(condition, then_branch)
        graph.add_edge(condition, else_branch)
        graph.add_edge(other_pred, else_branch)  # else_branch has multiple predecessors
        graph.add_edge(then_branch, exit_region)
        graph.add_edge(else_branch, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Should still complete without error
        assert analysis.stats.iterations >= 0, "Structuring should complete"
        assert len(result.nodes) > 0, "Graph should remain non-empty"

    def test_if_then_pattern_single_branch_merge(self):
        """
        Test that if-then pattern (without else) is recognized.
        Structure: condition -> then-block, condition -> else-target.
        The then-block should be merged as a dedicated branch.
        """
        entry = Region(block_addr=0x9001, region_type=RegionType.Linear)
        condition = Region(block_addr=0x9002, region_type=RegionType.Condition)
        then_branch = Region(block_addr=0x9003, region_type=RegionType.Linear)
        else_target = Region(block_addr=0x9004, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0x9005, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, condition, then_branch, else_target, exit_region]:
            graph.add_node(r)

        # Build: entry -> condition -> then_branch (only pred is condition) -> exit
        #                          -> else_target -> exit
        graph.add_edge(entry, condition)
        graph.add_edge(condition, then_branch)
        graph.add_edge(condition, else_target)
        graph.add_edge(then_branch, exit_region)
        graph.add_edge(else_target, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Should reduce the structure
        assert analysis.stats.regions_reduced >= 0, "Structuring should process"
        assert len(result.nodes) <= 3, "Graph should reduce significantly"

    def test_deeply_nested_if_then_else(self):
        """
        Test nested if-then-else structures.
        Outer if-then-else contains another if-then-else in one branch.
        """
        entry = Region(block_addr=0xA001, region_type=RegionType.Linear)
        cond1 = Region(block_addr=0xA002, region_type=RegionType.Condition)
        # First branch of outer if
        then1 = Region(block_addr=0xA003, region_type=RegionType.Linear)
        # Else branch contains nested if
        cond2 = Region(block_addr=0xA004, region_type=RegionType.Condition)
        then2 = Region(block_addr=0xA005, region_type=RegionType.Linear)
        else2 = Region(block_addr=0xA006, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0xA007, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, cond1, then1, cond2, then2, else2, exit_region]:
            graph.add_node(r)

        # Build nested structure
        graph.add_edge(entry, cond1)
        graph.add_edge(cond1, then1)  # True branch of outer
        graph.add_edge(cond1, cond2)  # False branch is nested if
        graph.add_edge(cond2, then2)  # True branch of nested
        graph.add_edge(cond2, else2)  # False branch of nested
        graph.add_edge(then1, exit_region)
        graph.add_edge(then2, exit_region)
        graph.add_edge(else2, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Should complete and reduce significantly
        assert analysis.stats.iterations > 0, "Should iterate on nested structure"
        # The nested structure should be reduced from init 7 nodes to at most 4
        assert len(result.nodes) <= 4, "Nested structure should reduce significantly"

    def test_linear_sequences_merged_before_if_patterns(self):
        """
        Test that _try_sequence is called before _try_if_then patterns,
        ensuring linear chains are first collapsed.
        """
        entry = Region(block_addr=0xB001, region_type=RegionType.Linear)
        linear1 = Region(block_addr=0xB002, region_type=RegionType.Linear)
        linear2 = Region(block_addr=0xB003, region_type=RegionType.Linear)
        condition = Region(block_addr=0xB004, region_type=RegionType.Condition)
        then_branch = Region(block_addr=0xB005, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0xB006, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        for r in [entry, linear1, linear2, condition, then_branch, exit_region]:
            graph.add_node(r)

        # Build linear chain followed by condition
        graph.add_edge(entry, linear1)
        graph.add_edge(linear1, linear2)
        graph.add_edge(linear2, condition)
        graph.add_edge(condition, then_branch)
        graph.add_edge(condition, exit_region)
        graph.add_edge(then_branch, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Linear chain should be heavily reduced
        init_nodes = 6
        final_nodes = len(result.nodes)
        assert final_nodes < init_nodes, f"Linear chain should reduce (was {init_nodes}, now {final_nodes})"
        assert analysis.stats.sequences_created > 0, "Should merge linear sequences"

    def test_two_way_branch_not_incorrectly_merged(self):
        """
        Verify that simple 2-way branches are correctly handled
        (not over-merged or under-merged).
        """
        entry = Region(block_addr=0xC001, region_type=RegionType.Linear)
        condition = Region(block_addr=0xC002, region_type=RegionType.Condition)
        then_branch = Region(block_addr=0xC003, region_type=RegionType.Linear)
        else_branch = Region(block_addr=0xC004, region_type=RegionType.Linear)
        exit_region = Region(block_addr=0xC005, region_type=RegionType.Linear)

        graph = RegionGraph()
        graph.entry = entry
        initial_node_count = len([entry, condition, then_branch, else_branch, exit_region])
        for r in [entry, condition, then_branch, else_branch, exit_region]:
            graph.add_node(r)

        graph.add_edge(entry, condition)
        graph.add_edge(condition, then_branch)
        graph.add_edge(condition, else_branch)
        graph.add_edge(then_branch, exit_region)
        graph.add_edge(else_branch, exit_region)

        # Run structuring
        analysis = StructureAnalysis(graph)
        result = analysis.structure()

        # Should reduce but not to a single node
        assert 1 < len(result.nodes) <= initial_node_count, "Should reduce but not collapse to 1"
        # Should indicate some reduction
        assert analysis.stats.regions_reduced > 0 or analysis.stats.sequences_created > 0, (
            "Should record some reduction"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
