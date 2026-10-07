"""Replay CALL execution-frame pruning after call materialization.

Layer: Types/Lowering.
Responsibility: join typed callsite frame evidence to structured call nodes and
delegate exact SP-carrier removal to the CALL execution-frame owner.
Consumes alias, widening, and typed facts; it does not create those facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Callsite summaries and already-materialized calls are required; this module
does not recover arguments, call targets, stack identity, or control flow.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from inertia.semantics.callsite_summary import (
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)

from .call_execution_frame_carriers import (
    CallExecutionFrameCarrierStats8616,
    prune_consumed_call_execution_frame_carriers_8616,
)

__all__ = ["prune_materialized_call_execution_frames_8616"]


class _CodegenFrameStats8616(Protocol):
    """Owned metadata field published on the dynamic angr codegen object."""

    _inertia_call_execution_frame_carrier_stats_8616: CallExecutionFrameCarrierStats8616


def prune_materialized_call_execution_frames_8616(
    codegen: object,
    calls: Iterable[tuple[CFunctionCall, CallsiteSummary8616]],
) -> bool:
    """Prune exact SP execution carriers for all summarized calls."""
    current = CallExecutionFrameCarrierStats8616()
    for call, summary in calls:
        frame_kind = callsite_machine_frame_kind_8616(summary)
        if frame_kind is None:
            continue
        result = prune_consumed_call_execution_frame_carriers_8616(
            codegen,
            call,
            callsite_addr=summary.callsite_addr,
            return_frame_width=frame_kind.return_frame_width,
        )
        current = current.merged(result.stats)

    boundary = cast(_CodegenFrameStats8616, codegen)
    try:
        previous = boundary._inertia_call_execution_frame_carrier_stats_8616
    except AttributeError:
        previous = CallExecutionFrameCarrierStats8616()
    boundary._inertia_call_execution_frame_carrier_stats_8616 = previous.merged(
        current
    )
    return current.materialized_count > 0
