"""Produce the scoped per-call SP coordinate carrier under dual scopes.

Layer: Semantics.
Responsibility: run the established universal coordinate producer for the
physical callsite evidence and the scoped call-effect adapter for the body
proof, then bind both records through the IR scoped carrier. The universal
coordinate record is never forged to look complete — its ``net_sp_delta``
may stay unproven while the scoped effect carries the conditional
displacement. Neither pending markers nor conditional IR are republished as
universal evidence; the carrier refuses mismatched coordinates and every
scalar projection requires the dual entry scopes.
Owns call-effect semantics. Do not perform alias-state, IR projection,
frontend decode, lowering, rewrite, postprocess, or CLI/reporting work here.
Owns instruction effects, flags, branch meaning, and expression interpretation
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.ir.scoped_call_stack_coordinates import (
    IRScopedCallStackCoordinates8616,
    prove_scoped_ir_call_stack_coordinates_8616,
)

from .call_return_segment import ReturnSegmentFrame8616
from .call_stack_coordinates import prove_call_stack_coordinates_8616
from .callsite_summary import (
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)
from .scoped_callee_stack_effects import (
    prove_scoped_direct_callee_stack_effect_8616,
)

__all__ = [
    "prove_scoped_call_stack_coordinates_8616",
]


def prove_scoped_call_stack_coordinates_8616(
    project: object,
    summary: CallsiteSummary8616,
    *,
    instruction: IRInstr | None = None,
    block: IRBlock | None = None,
    return_frame: ReturnSegmentFrame8616 | None = None,
    caller_scope: Real16InvocationDomain8616 | None,
    callee_scope: Real16InvocationDomain8616 | None,
    coverage: IRBoundaryCoverageResult8616 | None,
) -> IRScopedCallStackCoordinates8616:
    """Produce the dual-scope coordinate carrier or a typed refusal.

    The universal producer supplies the independently evidenced physical
    fields (callsite identity, return frame, purge/cleanup decomposition);
    it may legitimately leave ``net_sp_delta`` unproven. The scoped adapter
    supplies the dual-scope body proof. The carrier refuses whenever the two
    records bind different calls, when the coordinate record lost its source
    or frame evidence, or when the adapter refused.
    """
    coordinates = prove_call_stack_coordinates_8616(
        project, summary,
        instruction=instruction, block=block, return_frame=return_frame,
    )
    frame_kind = callsite_machine_frame_kind_8616(summary)
    effect = prove_scoped_direct_callee_stack_effect_8616(
        project, summary.callsite_addr, summary.return_addr,
        summary.target_addr, frame_kind,
        caller_scope=caller_scope, callee_scope=callee_scope,
        coverage=coverage,
    )
    return prove_scoped_ir_call_stack_coordinates_8616(coordinates, effect)
