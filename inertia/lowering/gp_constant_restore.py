# cython: language_level=3, infer_types=True
"""Publish constant GP restores whose addressing use was folded.

Layer: Types/Lowering.
Responsibility: retain an Alias-proven register effect beside its exact surviving
segment publication. Consume typed machine evidence, never infer deadness from
the absence of a C assignment or from rendered expressions.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from enum import Enum

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort

from inertia.alias.segment_stack_restore import SegmentStackRestoreFact8616, SegmentStackRestoreVerdict8616

from .gp_register_state import (
    runtime_gp_expression_view_8616,
    runtime_gp_live_in_name_8616,
    runtime_gp_state_assignment_8616,
)
from .gp_stack_restore_identity import (
    _independent_segment_assignment_8616,
    _masked_value_8616,
    _runtime_restore_word_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616
import operator


class ConstantRestorePublication8616(Enum):
    """Outcome of publishing one proven constant register effect."""

    REFUSED = "refused"
    EXISTING = "existing"
    INSERTED = "inserted"


@cython.ccall
def _constant_write_matches(statement: c.CAssignment, fact: SegmentStackRestoreFact8616) -> cython.bint:
    """Recognize an exact word write, including a simplified zero low word."""
    target: object
    word = _runtime_restore_word_8616(statement, fact.restore_register)
    if isinstance(word, c.CConstant):
        return bool(operator.eq(word.value, fact.constant_value))
    target = runtime_gp_expression_view_8616(statement.lhs)
    source = runtime_gp_expression_view_8616(_masked_value_8616(statement.rhs, 0xFFFF0000))
    return (fact.constant_value == 0 and target is not None and target.width == 4
            and operator.eq(target.register_name, runtime_gp_live_in_name_8616(fact.restore_register))
            and operator.eq(source, target))


@cython.ccall
def _publication_site(
    containers: object,
    fact: SegmentStackRestoreFact8616,
) -> object:
    """Find one pure segment sibling, refusing conflicting GP publications."""
    container: object
    index: object
    statement: object
    anchors: list[tuple[c.CStatements, cython.longlong]] = []
    existing = False
    for container in containers:
        for index, statement in enumerate(container.statements):
            if isinstance(statement, c.CStatements):
                continue
            if fact.restore_instruction_addr not in instruction_addrs_from_node_8616(statement):
                continue
            if not isinstance(statement, c.CAssignment):
                return None
            if _constant_write_matches(statement, fact):
                existing = True
            elif _independent_segment_assignment_8616(statement):
                anchors.append((container, index))
            else:
                return None
    if len(anchors) != 1:
        return None
    container, index = anchors[0]
    return container, index, existing


@cython.ccall
def publish_constant_gp_restore_8616(
    codegen: object,
    containers: object,
    fact: SegmentStackRestoreFact8616,
    function_addr: cython.longlong,
) -> ConstantRestorePublication8616:
    """Publish only at a unique pure segment sibling of the proven restore.

    A same-instruction non-segment effect is a conflict unless it is already
    the exact constant write. Aggregate control-flow tags are not anchors.
    """
    publication: object
    site: object
    if fact.verdict is not SegmentStackRestoreVerdict8616.PROVEN or fact.constant_value is None:
        return ConstantRestorePublication8616.REFUSED
    site = _publication_site(containers, fact)
    if site is None:
        return ConstantRestorePublication8616.REFUSED
    container, index, existing = site
    if existing:
        return ConstantRestorePublication8616.EXISTING
    value = c.CConstant(fact.constant_value, SimTypeShort(False), codegen=codegen)
    publication = runtime_gp_state_assignment_8616(
        fact.restore_register, value, codegen=codegen, function_addr=function_addr,
    )
    if publication is None:
        return ConstantRestorePublication8616.REFUSED
    publication.tags = {"ins_addr": fact.restore_instruction_addr}
    container.statements.insert(index + 1, publication)
    return ConstantRestorePublication8616.INSERTED
