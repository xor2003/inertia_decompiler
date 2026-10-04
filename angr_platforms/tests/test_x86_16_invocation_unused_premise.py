"""A source-bound invocation is retained only when a CALL target consumes it."""
from unittest.mock import patch

from angr_platforms.X86_16.alias.segment_stack_restore import build_x86_16_segment_stack_restore_artifact
from angr_platforms.X86_16.ir.direct_call_segment_context import bind_direct_call_segment_context_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from angr_platforms.X86_16.ir.real16_invocation_domain import (
    Real16InvocationDomain8616,
    prove_real16_invocation_domain_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from test_x86_16_direct_call_segment_entry import (
    _BASE,
    _binary_callsite_index,
    _callee_boundary,
    _lift_caller,
    exact_function_range_boundary_8616,
    publish_function_ir_artifact_8616,
)


def _raise_unused_replay(premise: Real16InvocationDomain8616) -> bool:
    """Make any unintended consumption of an unused premise fail loudly."""
    del premise
    raise RuntimeError("unused invocation replayed")


def test_unused_refused_invocation_does_not_break_forward_call_context() -> None:
    """An all-selector-valid native CALL neither retains nor replays a refused premise."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    caller = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller is not None
    callee = _callee_boundary(project, 0x1007, 0x1008)
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    index = _binary_callsite_index(project, caller)
    publish_function_ir_artifact_8616(project, artifact)
    callee_artifact = build_x86_16_ir_function_artifact(project, callee)
    publish_function_ir_artifact_8616(project, callee_artifact)
    caller_coverage = prove_ir_boundary_coverage_8616(project, caller, artifact)
    callee_coverage = prove_ir_boundary_coverage_8616(project, callee, callee_artifact)
    baseline = bind_direct_call_segment_context_8616(
        caller_coverage, callee_coverage, index, restoration.restore_sources, 0x1002,
    )
    assert baseline.complete
    refused = prove_real16_invocation_domain_8616(
        project, None, 0x1002, boot=None, boot_recompute=None,
    )
    assert not refused.complete
    # An unused prerequisite must not trigger fresh native lifting or a
    # callback. A property error deliberately makes such replay observable.
    with patch.object(Real16InvocationDomain8616, "complete", property(_raise_unused_replay)):
        result = bind_direct_call_segment_context_8616(
            caller_coverage, callee_coverage, index, restoration.restore_sources, 0x1002,
            invocation=refused,
        )
        assert result.complete
    assert result.invocation is None
    assert result.proof.invocation is None
    assert result.proof == baseline.proof
