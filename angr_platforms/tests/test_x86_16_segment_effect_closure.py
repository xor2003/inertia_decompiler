"""Require complete local body/state evidence before segment-effect publication."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from angr_platforms.X86_16.ir import IRBlock, IRFunctionArtifact, IRInstr, build_x86_16_segment_state_artifact
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from angr_platforms.X86_16.ir.segment_effect_closure import prove_segment_effect_closure_8616


@pytest.mark.parametrize("defect", (None, "foreign", "missing_block", "missing_register", "no_return", "no_coverage"))
def test_segment_effect_closure_requires_complete_bound_evidence(defect: str | None) -> None:
    """Refuse partial state/body evidence even when a local contract could exist."""
    project = SimpleNamespace()
    terminal = "NOP" if defect == "no_return" else "RET"
    artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        IRInstr("CALL", None, (), addr=0x1000),
        IRInstr(terminal, None, (), addr=0x1003),
    )),))
    publish_function_ir_artifact_8616(project, artifact)
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 4, frozenset({0x1000}), frozenset({0x1000, 0x1003}), (),
    )
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    state = build_x86_16_segment_state_artifact(artifact)
    if defect == "foreign":
        state = replace(state, source_artifact=replace(artifact))
    elif defect == "missing_block":
        state = replace(state, exit_states={})
    elif defect == "missing_register":
        state.entry_states[0x1000].pop("ds")
    elif defect == "no_coverage":
        coverage = replace(coverage, materialized_count=0)
    result = prove_segment_effect_closure_8616(coverage, state)
    assert result.complete is (defect is None)
    assert result.raw_fact_count == result.normalized_fact_count == 1
    assert result.materialized_count + result.failure_count == 1
    if defect is None:
        assert result.callsite_addrs == (0x1000,)
        assert result.return_block_addrs == (0x1000,)
        assert not replace(result, callsite_addrs=()).complete
