"""Actual frontend condition capture retains source-bound relative control."""
from __future__ import annotations

import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionFailure, ConditionIR
from angr_platforms.X86_16.ir.condition_lift_capture import isolated_condition_lift_session_8616
from angr_platforms.X86_16.ir.condition_relative_edge import RelativeConditionReason, attach_relative_condition_edge
from angr_platforms.X86_16.relative_control_edge import RelativeEdgeForm, decode_relative_edge


@pytest.mark.parametrize(("code", "branch_offset", "form"), [
    ("39d87402", 2, RelativeEdgeForm.JCC_REL8),
    ("09c07402", 2, RelativeEdgeForm.JCC_REL8),
    ("4875fc", 1, RelativeEdgeForm.JCC_REL8),
    ("e2fe", 0, RelativeEdgeForm.LOOP_REL8),
    ("39d80f840200", 2, RelativeEdgeForm.JCC_REL16),
])
def test_binary_condition_producers_retain_exact_edge(code, branch_offset, form) -> None:
    """CMP, TEST-builder, consumed arithmetic and LOOP share exact byte evidence."""
    data = bytes.fromhex(code)
    head = 0x1200
    with isolated_condition_lift_session_8616() as capture:
        pyvex.lift(data, head, Arch86_16(), max_bytes=len(data), opt_level=0)
        conditions = tuple(item for item in capture.condition_cache[head] if isinstance(item, ConditionIR))
        capture.record_successful_block(head)
        artifact = capture.complete_artifact(frozenset({head}), frozenset({head}))
    assert artifact is not None and artifact.stats.complete
    assert (artifact.stats.raw_fact_count, artifact.stats.normalized_fact_count,
            artifact.stats.classified_fact_count, artifact.stats.materialized_count,
            artifact.stats.failure_count) == (1, 1, 1, 1, 0)
    assert len(conditions) == 1
    edge = conditions[0].relative_edge
    assert edge is not None
    assert edge.head == head + branch_offset
    assert edge.encoding == data[branch_offset:]
    assert edge.form is form
    assert conditions[0].src_insn == edge.head


def test_relative_capture_preserves_unresolved_targets_and_refuses_source_drift() -> None:
    """Raw bytes cannot fill an unproved loaded address or borrow another edge."""
    condition = ConditionIR("eq", "ax", 0, src_insn=0x1200)
    captured = attach_relative_condition_edge(condition, 0x1200, b"\x74\xfe")
    assert isinstance(captured, ConditionIR) and captured.relative_edge is not None
    assert captured.taken_target is None and captured.fallthrough_target is None
    assert decode_relative_edge(0x1200, b"\x74\xfe") == captured.relative_edge
    drift = attach_relative_condition_edge(captured, 0x1200, b"\x74\x01")
    assert isinstance(drift, ConditionFailure) and drift.reason is RelativeConditionReason.SOURCE
    wrong_owner = attach_relative_condition_edge(condition, 0x1201, b"\x74\xfe")
    assert isinstance(wrong_owner, ConditionFailure) and wrong_owner.reason is RelativeConditionReason.SOURCE
    assert attach_relative_condition_edge(condition, 0x1200, b"\x67\xe2\xfe") is condition
