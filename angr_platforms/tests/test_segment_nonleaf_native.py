"""Native-byte controls for segment preservation through nested direct calls.

Layer: Tests.
Responsibility: bind both CALLs to decoded native instructions and propagate
only segment identities preserved by a fully covered leaf through its caller.
"""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.ir.segment_call_preservation import (
    prove_segment_call_preservation_8616,
)
from angr_platforms.X86_16.ir.segment_effect_closure import prove_segment_effect_closure_8616
from angr_platforms.X86_16.ir.segment_state import build_x86_16_segment_state_artifact
from test_segment_call_binding_regression import _coverage, _program_index, _project


@pytest.mark.parametrize("write_ds", (False, True))
def test_native_nested_calls_preserve_only_unchanged_segments(write_ds: bool) -> None:
    """A child's segment mutation remains observable through two native CALLs."""
    leaf_bytes = bytes.fromhex("b8 34 12 8e c0")
    if write_ds:
        leaf_bytes += bytes.fromhex("8e d8")
    leaf_bytes += b"\xc3"
    image = bytearray(b"\x90" * (0x20 + len(leaf_bytes)))
    image[0:4] = bytes.fromhex("e8 0d 00 c3")
    image[0x10:0x14] = bytes.fromhex("e8 0d 00 c3")
    image[0x20:] = leaf_bytes
    project = _project(image)
    root = _coverage(project, 0x1000, 0x1004)
    middle = _coverage(project, 0x1010, 0x1014)
    leaf = _coverage(project, 0x1020, 0x1020 + len(leaf_bytes))
    leaf_closure = prove_segment_effect_closure_8616(
        leaf, build_x86_16_segment_state_artifact(leaf.artifact),
    )
    inner = prove_segment_call_preservation_8616(
        middle, leaf_closure, _program_index(project, 0x1010, 0x1014), 0x1010,
    )
    assert inner.complete
    middle_closure = prove_segment_effect_closure_8616(
        middle, build_x86_16_segment_state_artifact(middle.artifact, call_preservations=(inner,)),
    )
    outer = prove_segment_call_preservation_8616(
        root, middle_closure, _program_index(project, 0x1000, 0x1004), 0x1000,
    )
    assert outer.complete
    expected = {"cs", "ss", "fs", "gs"}
    if not write_ds:
        expected.add("ds")
    assert set(outer.preserved_registers) == expected
    assert (outer.raw_fact_count, outer.normalized_fact_count,
            outer.classified_fact_count, outer.materialized_count,
            outer.failure_count) == (1, 1, 1, 1, 0)
