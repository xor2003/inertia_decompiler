"""Prove that a materialized argument PUSH leaves no observed runtime SP value.

Layer: Types/Lowering.
Responsibility: consume authoritative runtime-register identity and structured
ordering after the caller proves exact PUSH provenance and materialized args.
This helper never establishes call arguments or stack ownership. Unknown
control flow, nested candidates and later numeric register uses refuse DCE.
Consumes alias, widening, and typed facts; never assembly or rendered C text.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from enum import StrEnum

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CDirtyExpression,
    CGoto,
    CLoop,
    CStatements,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .gp_register_state import runtime_gp_expression_view_8616
from .physical_registers import physical_register_view_8616


class RuntimePushCarrierVerdict8616(StrEnum):
    """Explicit outcome for one runtime SP projection, not generic deadness."""

    NOT_APPLICABLE = "not_applicable"
    UNKNOWN_REFUSE = "unknown_refuse"
    OBSERVED = "observed"
    UNOBSERVED = "unobserved"


def _linear_statements_8616(root: CStatements) -> list[object]:
    """Flatten sequence wrappers without entering conditional or loop bodies."""
    result: list[object] = []
    for statement in root.statements:
        if isinstance(statement, CStatements):
            result.extend(_linear_statements_8616(statement))
        else:
            result.append(statement)
    return result


def classify_runtime_push_carrier_8616(
    root: object, assignment: CAssignment, arguments: tuple[object, ...], *, sp_offset: int,
) -> RuntimePushCarrierVerdict8616:
    """Check a top-level runtime ESP write against arguments and its full suffix.

    Earlier reads do not observe this write. Refuse loops and explicit jumps
    anywhere because structured order alone cannot establish their use order.
    Native physical-register and owned runtime-register views share this check.
    """
    view = runtime_gp_expression_view_8616(assignment.lhs)
    if view is None or view.parent_name != "esp" or view.width != 4 or view.bit_shift != 0:
        return RuntimePushCarrierVerdict8616.NOT_APPLICABLE
    if not arguments or not isinstance(root, CStatements):
        return RuntimePushCarrierVerdict8616.UNKNOWN_REFUSE
    statements = _linear_statements_8616(root)
    positions = [index for index, item in enumerate(statements) if item is assignment]
    if len(positions) != 1 or any(isinstance(node, (CLoop, CGoto)) for node in _iter_c_nodes_deep_8616(root)):
        return RuntimePushCarrierVerdict8616.UNKNOWN_REFUSE
    suffix = (*arguments, *statements[positions[0] + 1:])
    for expression in suffix:
        for node in _iter_c_nodes_deep_8616(expression):
            runtime = runtime_gp_expression_view_8616(node)
            if runtime is not None and runtime.parent_name == "esp":
                return RuntimePushCarrierVerdict8616.OBSERVED
            physical = physical_register_view_8616(node)
            if physical is not None and physical.reg_offset < sp_offset + 4 and sp_offset < physical.reg_offset + physical.width:
                return RuntimePushCarrierVerdict8616.OBSERVED
            if isinstance(node, CDirtyExpression) and physical is None:
                return RuntimePushCarrierVerdict8616.UNKNOWN_REFUSE
    return RuntimePushCarrierVerdict8616.UNOBSERVED
