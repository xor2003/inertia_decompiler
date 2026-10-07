from __future__ import annotations

"""Test the pipeline contracts: SemanticLaneState and assert_closed_loop."""

from types import SimpleNamespace

import pytest

from inertia.pipeline.contracts import (
    CORE_DECOMPILER_PIPELINE_ORDER_8616,
    SemanticLaneState,
    assert_pipeline_contracts_8616,
)
from inertia.pipeline.errors import PipelineHardError


def test_core_decompiler_pipeline_order_matches_agents_contract():
    assert CORE_DECOMPILER_PIPELINE_ORDER_8616 == (
        "IR",
        "Alias",
        "Widening",
        "Types",
        "Structuring",
        "Rewrite",
    )
    assert CORE_DECOMPILER_PIPELINE_ORDER_8616.index("Rewrite") > CORE_DECOMPILER_PIPELINE_ORDER_8616.index(
        "Structuring"
    )


class TestSemanticLaneState:
    """Unit tests for SemanticLaneState."""

    def test_empty_state_is_closed(self):
        lane = SemanticLaneState(name="test")
        assert lane.is_closed
        # assert_closed_loop should not raise
        lane.assert_closed_loop(layer="test")

    def test_classified_without_materialized_raises(self):
        lane = SemanticLaneState(
            name="test",
            raw=5,
            normalized=5,
            classified=3,
            materialized=0,
        )
        assert not lane.is_closed
        with pytest.raises(PipelineHardError, match="classified but 0 materialized"):
            lane.assert_closed_loop(layer="test")

    def test_bound_without_materialized_raises(self):
        lane = SemanticLaneState(
            name="test",
            raw=5,
            normalized=5,
            classified=3,
            bound=3,
            materialized=0,
        )
        assert not lane.is_closed
        with pytest.raises(PipelineHardError, match="bindings created but 0 materialized"):
            lane.assert_closed_loop(layer="test")

    def test_classified_and_materialized_is_closed(self):
        lane = SemanticLaneState(
            name="test",
            raw=5,
            normalized=5,
            classified=3,
            bound=3,
            materialized=3,
        )
        assert lane.is_closed
        # should not raise
        lane.assert_closed_loop(layer="test")

    def test_to_dict(self):
        lane = SemanticLaneState(
            name="stack",
            raw=10,
            normalized=8,
            classified=5,
            bound=5,
            materialized=5,
            verified=5,
            failures=1,
        )
        d = lane.to_dict()
        assert d["name"] == "stack"
        assert d["raw"] == 10
        assert d["materialized"] == 5
        assert d["raw_fact_count"] == 10
        assert d["normalized_fact_count"] == 8
        assert d["classified_fact_count"] == 5
        assert d["materialized_count"] == 5
        assert d["failure_count"] == 1

    def test_recorded_failure_is_not_closed_after_partial_materialization(self):
        lane = SemanticLaneState(
            name="storage",
            raw=4,
            normalized=4,
            classified=4,
            materialized=3,
            verified=3,
            failures=1,
        )

        assert not lane.is_closed
        assert "BROKEN" in lane.summary_line()
        with pytest.raises(PipelineHardError, match="storage: 1 evidence failures recorded"):
            lane.assert_closed_loop(layer="validation:storage")

    def test_summary_line(self):
        lane = SemanticLaneState(
            name="condition",
            raw=3,
            normalized=3,
            classified=3,
            materialized=3,
        )
        line = lane.summary_line()
        assert "condition" in line
        assert "CLOSED" in line
        assert "raw=3" in line

    def test_summary_line_broken(self):
        lane = SemanticLaneState(
            name="stack",
            raw=5,
            normalized=5,
            classified=3,
            materialized=0,
        )
        line = lane.summary_line()
        assert "BROKEN" in line


class TestAssertPipelineContracts:
    """Test integration: assert_pipeline_contracts_8616."""

    @pytest.mark.parametrize("lane_name", ["_inertia_stack_lane", "_inertia_condition_lane"])
    def test_absent_other_lane_does_not_hide_broken_lane(self, lane_name: str) -> None:
        """A missing attachment cannot erase another lane's unconsumed facts."""
        broken = SemanticLaneState(name="retained", raw=1, normalized=1,
                                   classified=1, materialized=0)
        codegen = SimpleNamespace(**{lane_name: broken})
        with pytest.raises(PipelineHardError, match="classified but 0 materialized"):
            assert_pipeline_contracts_8616(codegen)

    def test_no_lanes_no_error(self):
        """When no lanes are set, no error should be raised."""
        codegen = type("Codegen", (), {})()
        # Should not raise
        assert_pipeline_contracts_8616(codegen)

    def test_closed_lanes_no_error(self):
        """Both lanes closed → no error."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_stack_lane = SemanticLaneState(
            name="stack",
            raw=5,
            normalized=5,
            classified=3,
            materialized=3,
        )
        codegen._inertia_condition_lane = SemanticLaneState(
            name="condition",
            raw=2,
            normalized=2,
            classified=2,
            materialized=2,
        )
        # Should not raise
        assert_pipeline_contracts_8616(codegen)

    def test_broken_stack_raises(self):
        """Broken stack lane → PipelineHardError."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_stack_lane = SemanticLaneState(
            name="stack",
            raw=5,
            normalized=5,
            classified=3,
            bound=3,
            materialized=0,
        )
        codegen._inertia_condition_lane = SemanticLaneState(
            name="condition",
            raw=0,
            normalized=0,
            classified=0,
        )
        with pytest.raises(PipelineHardError, match="bindings created but 0 materialized"):
            assert_pipeline_contracts_8616(codegen)

    def test_broken_condition_raises(self):
        """Broken condition lane → PipelineHardError."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_stack_lane = SemanticLaneState(
            name="stack",
            raw=0,
            normalized=0,
            classified=0,
        )
        codegen._inertia_condition_lane = SemanticLaneState(
            name="condition",
            raw=3,
            normalized=3,
            classified=3,
            materialized=0,
        )
        with pytest.raises(PipelineHardError, match="classified but 0 materialized"):
            assert_pipeline_contracts_8616(codegen)

    def test_broken_extra_semantic_lane_raises(self):
        """Additional semantic lanes obey the same closed-loop rule."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_semantic_lanes_8616 = (
            SemanticLaneState(
                name="pointer_arg_indirect",
                raw=1,
                normalized=1,
                classified=1,
                materialized=0,
                failures=1,
            ),
        )
        with pytest.raises(PipelineHardError, match="pointer_arg_indirect: 1 facts classified but 0 materialized"):
            assert_pipeline_contracts_8616(codegen)

    def test_invalid_stack_lane_type_raises(self):
        """Owned lane contracts must use SemanticLaneState, not dynamic duck types."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_stack_lane = {"raw": 1}

        with pytest.raises(PipelineHardError, match="stack lane has invalid contract type"):
            assert_pipeline_contracts_8616(codegen)

    def test_invalid_extra_semantic_lane_type_raises(self):
        """Additional semantic lanes must also use the owned SemanticLaneState contract."""
        codegen = type("Codegen", (), {})()
        codegen._inertia_semantic_lanes_8616 = ({"name": "bad"},)

        with pytest.raises(PipelineHardError, match="semantic lane has invalid contract type"):
            assert_pipeline_contracts_8616(codegen)
