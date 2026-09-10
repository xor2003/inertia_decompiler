"""Publish accepted logical call shapes into the matching physical inventory.

Layer: Types/Lowering.
Responsibility: keep node and inventory projections coherent using an existing
typed reconciliation. No argument recovery, signature guessing or C-text matching.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import replace

from ..callsite_summary import CallsiteSummary8616
from .call_argument_shape import (
    CallsiteArgumentShapeDecision8616,
    CallsiteArgumentShapeReconciliation8616,
    carry_forward_logical_call_argument_shape_8616,
)


def publish_reconciled_call_argument_shape_8616(
    inventory: CallsiteSummary8616,
    updated: CallsiteSummary8616,
    reconciliation: CallsiteArgumentShapeReconciliation8616,
) -> CallsiteSummary8616:
    """Synchronize a proven node shape without changing physical call evidence."""
    if (
        updated is not reconciliation.summary
        or reconciliation.failure_count != 0
        or reconciliation.materialized_count <= 0
        or reconciliation.decision not in {
            CallsiteArgumentShapeDecision8616.MATERIALIZED_PROVEN_LOGICAL_SHAPE,
            CallsiteArgumentShapeDecision8616.MATERIALIZED_LOGICAL_FAR_POINTER,
        }
    ):
        return inventory
    shape_unchanged = (
        inventory.logical_arg_widths == updated.logical_arg_widths
        and inventory.logical_arg_classes == updated.logical_arg_classes
    )
    if shape_unchanged:
        return inventory
    # The existing owner verifies every physical fact before carrying widths.
    physical_snapshot = replace(inventory, logical_arg_widths=())
    published = carry_forward_logical_call_argument_shape_8616(physical_snapshot, updated)
    return inventory if published is physical_snapshot else published
