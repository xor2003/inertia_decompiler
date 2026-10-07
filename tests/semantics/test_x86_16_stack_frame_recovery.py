from __future__ import annotations

from types import SimpleNamespace

import pytest
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.pipeline.errors import PipelineHardError

from inertia.semantics.stack_frame_recovery import (
    StackFrameInfo8616,
    assert_no_unresolved_stable_ss_before_alias_8616,
    detect_stack_frame_8616,
    normalize_semantic_accesses_8616,
)


def test_detect_stack_frame_prefers_proven_bp_access() -> None:
    access = SimpleNamespace(
        mode=1,
        addr=IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=-4,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    )

    frame = detect_stack_frame_8616(function_addr=0x1234, semantic_accesses=(access,))

    assert frame.function_addr == 0x1234
    assert frame.uses_bp_frame is True
    assert frame.bp_established is True
    assert frame.frame_base == "bp"
    assert frame.frame_kind == "bp"


def test_normalize_semantic_accesses_uses_bp_frame_for_stable_ss_address() -> None:
    frame = StackFrameInfo8616(
        function_addr=0x1234,
        uses_bp_frame=True,
        bp_established=True,
        frame_base="bp",
        frame_kind="bp",
    )
    access = SimpleNamespace(
        mode=7,
        addr=IRAddress(
            space=MemSpace.SS,
            base=("ss",),
            offset=-6,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    )

    normalized = normalize_semantic_accesses_8616((access,), frame)

    assert normalized == [
        (
            7,
            IRAddress(
                space=MemSpace.SS,
                base=("bp",),
                offset=-6,
                size=2,
                status=AddressStatus.STABLE,
                segment_origin=SegmentOrigin.PROVEN,
            ),
        )
    ]


def test_assert_no_unresolved_stable_ss_before_alias_refuses_unbased_stack_address() -> None:
    access = SimpleNamespace(
        mode=0,
        addr=IRAddress(
            space=MemSpace.SS,
            base=("ss",),
            offset=-2,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    )

    with pytest.raises(PipelineHardError):
        assert_no_unresolved_stable_ss_before_alias_8616((access,))
