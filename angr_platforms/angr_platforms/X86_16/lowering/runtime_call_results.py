"""Read already-executed call outputs from proven architectural register state.

Layer: Types/Lowering.
Responsibility: consume exact callsite return-source and owned GP-write evidence
to materialize a value read without replaying a live call.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
No calls or statements are deleted or moved. Unknown placement, write shapes,
or intervening effects refuse reuse; physical register spelling is not proof.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable, SimTemporaryVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import structured_callsite_addr_8616
from .gp_register_state import (
    RuntimeGPExpressionView8616,
    runtime_gp_expression_view_8616,
    runtime_gp_name_for_variable_8616,
    runtime_gp_state_expr_8616,
)

_WORD_BYTES: int = 2
_DWORD_BYTES: int = 4
_BITS_PER_BYTE: int = 8
_LOWER_WORD_MASK: int = 0xFFFF
_UPPER_WORD_MASK: int = 0xFFFF0000
_LOG = logging.getLogger(__name__)


class RuntimeCallResultVerdict8616(StrEnum):
    """Whether a live producer can be read without executing it again."""

    ABSENT = "absent"
    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class RuntimeCallResultRefusal8616(StrEnum):
    """The first unproven obligation when reusing an executed call result."""

    OWNERSHIP = "ownership"
    REGISTER_VIEW = "register_view"
    CAPTURE_SHAPE = "capture_shape"
    CAPTURE_STORAGE = "capture_storage"
    CAPTURE_WIDTH = "capture_width"
    CAPTURE_TYPE = "capture_type"
    MISSING_PUBLICATION = "missing_publication"
    PUBLICATION_MISMATCH = "publication_mismatch"
    INTERVENING_EFFECT = "intervening_effect"


@dataclass(frozen=True, slots=True)
class RuntimeCallResultRead8616:
    """One return-source request and its explicit materialization counters."""

    verdict: RuntimeCallResultVerdict8616
    expression: structured_c.CExpression | None = None
    raw_fact_count: int = 1
    normalized_fact_count: int = 1
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refusal_reason: RuntimeCallResultRefusal8616 | None = None


def _calls_at_8616(root: object, callsite_addr: int) -> tuple[structured_c.CFunctionCall, ...]:
    """Find exact tagged call nodes, without resolving targets by name."""
    return tuple(
        node for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CFunctionCall)
        and structured_callsite_addr_8616(node) == callsite_addr
    )


def _flatten_8616(statements: Sequence[object]) -> list[object]:
    """Flatten transparent sequences only, retaining control-flow boundaries."""
    result: list[object] = []
    for statement in statements:
        if isinstance(statement, structured_c.CStatements):
            result.extend(_flatten_8616(statement.statements))
        else:
            result.append(statement)
    return result


def _masked_value_write_8616(
    statement: object, source: structured_c.CExpression, requested: RuntimeGPExpressionView8616,
) -> bool:
    """Recognize the exact low-word publication emitted by GP-state Lowering."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    lhs = runtime_gp_expression_view_8616(statement.lhs)
    rhs = statement.rhs
    if lhs is None or lhs.width != _DWORD_BYTES or not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Or":
        return False
    preserved, inserted = rhs.lhs, rhs.rhs
    if not isinstance(preserved, structured_c.CBinaryOp) or preserved.op != "And":
        return False
    preserved_view = runtime_gp_expression_view_8616(preserved.lhs)
    if preserved_view != lhs or not isinstance(preserved.rhs, structured_c.CConstant):
        return False
    if preserved.rhs.value != _UPPER_WORD_MASK:
        return False
    if not isinstance(inserted, structured_c.CBinaryOp) or inserted.op != "And":
        return False
    if inserted.lhs is not source or not isinstance(inserted.rhs, structured_c.CConstant):
        return False
    return bool(
        inserted.rhs.value == _LOWER_WORD_MASK
        and requested.width == _WORD_BYTES and requested.bit_shift == 0
        and requested.parent_name == lhs.parent_name
    )


def _enclosing_prefix_8616(root: object, prefix: list[object]) -> list[object]:
    """Extend an exact live prefix through transparent sibling sequences only.

    Branches and loops remain opaque barriers. Rebuilt or ambiguous prefix
    nodes cannot establish placement in the root and retain the supplied scope.
    No statement is rewritten and all added effects still need preservation proof.
    """
    if not prefix or not isinstance(root, structured_c.CStatements):
        return prefix
    statements = _flatten_8616(root.statements)
    positions = [index for index, statement in enumerate(statements) if statement is prefix[0]]
    if len(positions) != 1:
        return prefix
    start = positions[0]
    end = start + len(prefix)
    candidate = statements[start:end]
    if len(candidate) != len(prefix) or any(lhs is not rhs for lhs, rhs in zip(candidate, prefix, strict=True)):
        return prefix
    return statements[:end]


def _publication_index_8616(
    statements: Sequence[object], index: int, call: structured_c.CFunctionCall,
    requested: RuntimeGPExpressionView8616,
) -> int | RuntimeCallResultRefusal8616:
    """Prove direct publication or one adjacent, exact temporary capture.

    Adjacency excludes intervening writes and effects before publication. A
    temporary has no aliasable storage; stack captures require a separate proof.
    The publication must read this same expression, not a similarly named value.
    """
    statement = statements[index]
    if _masked_value_write_8616(statement, call, requested):
        return index
    if not isinstance(statement, structured_c.CAssignment) or statement.rhs is not call:
        return RuntimeCallResultRefusal8616.CAPTURE_SHAPE
    target = statement.lhs
    if not isinstance(target, structured_c.CVariable) or not isinstance(target.variable, SimTemporaryVariable):
        return RuntimeCallResultRefusal8616.CAPTURE_STORAGE
    if target.variable.size != requested.width:
        return RuntimeCallResultRefusal8616.CAPTURE_WIDTH
    if index + 1 >= len(statements):
        return RuntimeCallResultRefusal8616.MISSING_PUBLICATION
    target_type = target.type
    if target_type is None:
        return RuntimeCallResultRefusal8616.CAPTURE_TYPE
    try:
        if target_type.size != requested.width * _BITS_PER_BYTE:
            return RuntimeCallResultRefusal8616.CAPTURE_TYPE
    except ValueError:
        # Native architecture-dependent types may not yet have a known width.
        return RuntimeCallResultRefusal8616.CAPTURE_TYPE
    if not _masked_value_write_8616(statements[index + 1], target, requested):
        return RuntimeCallResultRefusal8616.PUBLICATION_MISMATCH
    return index + 1


def _preserves_result_8616(statement: object, parent_name: str) -> bool:
    """Allow only explicit writes to disjoint stack storage or other GP lanes."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    if any(not isinstance(node, (structured_c.CVariable, structured_c.CConstant,
                                 structured_c.CBinaryOp, structured_c.CTypeCast))
           for node in _iter_c_nodes_deep_8616(statement.rhs)):
        return False
    lhs = statement.lhs
    while isinstance(lhs, structured_c.CTypeCast):
        lhs = lhs.expr
    if not isinstance(lhs, structured_c.CVariable):
        return False
    if isinstance(lhs.variable, SimStackVariable):
        return True
    register = runtime_gp_name_for_variable_8616(lhs.variable)
    return register is not None and register != parent_name


def materialize_runtime_call_result_read_8616(
    root: object,
    prefix: Sequence[object],
    callsite_addr: int,
    register_name: str,
    *,
    codegen: object,
    function_addr: int,
) -> RuntimeCallResultRead8616:
    """Read a uniquely placed, unchanged GP call result or refuse live replay."""
    calls = _calls_at_8616(root, callsite_addr)
    statements = _flatten_8616(prefix)
    def refuse(
        reason: RuntimeCallResultRefusal8616, index: int | None = None,
    ) -> RuntimeCallResultRead8616:
        """Keep the failure typed and expose bounded diagnostics only on request."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            statement = statements[index] if index is not None else None
            target = statement.lhs if isinstance(statement, structured_c.CAssignment) else None
            storage = target.variable if isinstance(target, structured_c.CVariable) else None
            _LOG.warning(
                "[runtime-call-result-refuse] function=%#x callsite=%#x register=%s "
                "reason=%s statement_index=%s statement=%s capture_storage=%r "
                "root_calls=%d prefix_matches=%d prefix_length=%d",
                function_addr, callsite_addr, register_name, reason.value,
                index, type(statement).__name__, storage, len(calls), len(positions), len(statements),
            )
        return RuntimeCallResultRead8616(
            RuntimeCallResultVerdict8616.UNKNOWN_REFUSE,
            failure_count=1, refusal_reason=reason,
        )

    positions = [index for index, statement in enumerate(statements) if _calls_at_8616(statement, callsite_addr)]
    if calls and not positions:
        statements = _enclosing_prefix_8616(root, statements)
        positions = [index for index, statement in enumerate(statements) if _calls_at_8616(statement, callsite_addr)]
    if not calls and not positions:
        return RuntimeCallResultRead8616(RuntimeCallResultVerdict8616.ABSENT)
    if len(calls) > 1 or len(positions) != 1:
        return refuse(RuntimeCallResultRefusal8616.OWNERSHIP)
    index = positions[0]
    call = _calls_at_8616(statements[index], callsite_addr)
    expression = runtime_gp_state_expr_8616(register_name, codegen=codegen, function_addr=function_addr)
    view = runtime_gp_expression_view_8616(expression)
    if view is None or len(call) != 1:
        return refuse(RuntimeCallResultRefusal8616.REGISTER_VIEW, index)
    publication_index = _publication_index_8616(statements, index, call[0], view)
    if isinstance(publication_index, RuntimeCallResultRefusal8616):
        return refuse(publication_index, index)
    for following_index in range(publication_index + 1, len(statements)):
        if not _preserves_result_8616(statements[following_index], view.parent_name):
            return refuse(RuntimeCallResultRefusal8616.INTERVENING_EFFECT, following_index)
    return RuntimeCallResultRead8616(
        RuntimeCallResultVerdict8616.PROVEN, expression,
        classified_fact_count=1, materialized_count=1,
    )
