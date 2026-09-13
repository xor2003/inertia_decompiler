"""Verify an existing word-local representation of a GP reload.

Layer: Types/Lowering.
Responsibility: consume Alias-proven storage and exact C byte stores without
inventing a second saved-register object. Unknown writers, escaped addresses,
incomplete stores and conditional paths refuse. No semantic recovery belongs
here; the machine save/reload identity must already be proven by Alias.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort

from ..alias.segment_stack_restore import SegmentStackRestoreFact8616, SegmentStackRestoreVerdict8616
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import callsite_summary_inventory_8616
from .call_return_stack_bindings import call_return_stack_destination_matches_8616
from .call_return_stack_stores import classify_call_return_stack_store_8616
from .gp_register_state import runtime_gp_expression_view_8616
from .gp_stack_restore_identity import (
    _entry_sp_byte_offset_8616,
    _is_saved_register_byte_8616,
    _masked_value_8616,
    _runtime_restore_word_8616,
    _unconditional_sequence_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616

_WORD_BYTES = 2
_WORD_MASK = 0xFFFF
_UPPER_WORD_MASK = 0xFFFF0000
_PARENT_BYTES = 4


def _stored_call_word(value: object) -> structured_c.CFunctionCall | None:
    """Read a word call result under exact masks, retaining all live effects."""
    if isinstance(value, structured_c.CBinaryOp) and value.op == "Or":
        upper = _masked_value_8616(value.lhs, _UPPER_WORD_MASK)
        view = runtime_gp_expression_view_8616(upper)
        if view is None or view.width != _PARENT_BYTES:
            return None
        # The destination is independently proved to be a word. This pure
        # parent-register read contributes no bits to that stored value.
        value = value.rhs
    if isinstance(value, structured_c.CBinaryOp) and value.op == "And":
        value = _masked_value_8616(value, _WORD_MASK)
    while isinstance(value, structured_c.CTypeCast):
        if not isinstance(value.dst_type, SimTypeShort):
            return None
        value = value.expr
    return value if isinstance(value, structured_c.CFunctionCall) else None


def _proven_call_store(
    codegen: object, statement: structured_c.CAssignment, fact: SegmentStackRestoreFact8616,
) -> bool:
    """Join an already folded call-result assignment to its exact machine store."""
    value = _stored_call_word(statement.rhs)
    if value is None:
        return False
    callsite = value.tags.get("ins_addr") if isinstance(value.tags, dict) else None
    if not isinstance(callsite, int) or isinstance(callsite, bool):
        return False
    summary = callsite_summary_inventory_8616(codegen).get(callsite)
    if summary is None:
        return False
    evidence = classify_call_return_stack_store_8616(summary)
    if evidence is None:
        return False
    return (evidence.store_ins_addr == fact.saved_instruction_addr
            and evidence.source_register_name == fact.saved_register
            and evidence.width == _WORD_BYTES
            and call_return_stack_destination_matches_8616(codegen, statement.lhs, evidence))


def _same_local(node: object, local: structured_c.CVariable) -> bool:
    """Compare owned C storage, never generated names or equal offsets alone."""
    return isinstance(node, structured_c.CVariable) and node.variable == local.variable


def _stored_byte(node: object, local: structured_c.CVariable) -> int | None:
    """Require an unsigned-byte lvalue into the exact word object."""
    if not isinstance(node, structured_c.CIndexedVariable):
        return None
    index = node.index
    if not isinstance(index, structured_c.CConstant) or index.value not in {0, 1}:
        return None
    pointer = node.variable
    if not isinstance(pointer, structured_c.CTypeCast):
        return None
    pointer_type = pointer.dst_type
    if not isinstance(pointer_type, SimTypePointer):
        return None
    byte_type = pointer_type.pts_to
    if not isinstance(byte_type, SimTypeChar) or byte_type.signed is not False:
        return None
    reference = pointer.expr
    if not isinstance(reference, structured_c.CUnaryOp) or reference.op != "Reference":
        return None
    return int(index.value) if _same_local(reference.operand, local) else None


def _exact_local(codegen: object, node: object, fact: SegmentStackRestoreFact8616) -> bool:
    """Require a complete two-byte local at the Alias-proven entry-SP range."""
    if not isinstance(node, structured_c.CVariable):
        return False
    if node.variable.size != _WORD_BYTES or not isinstance(node.variable_type, SimTypeShort):
        return False
    offset = _entry_sp_byte_offset_8616(codegen, node)
    return offset is not None and fact.stack_offsets == (offset, offset + 1)


def _address_escapes(nodes: dict[int, object], local: structured_c.CVariable, allowed: set[int]) -> bool:
    """Refuse address-taking outside the exact byte lvalues being verified."""
    return any(isinstance(node, structured_c.CUnaryOp) and node.op == "Reference"
               and _same_local(node.operand, local) and id(node) not in allowed
               for node in nodes.values())


def _stores_for_local(
    codegen: object,
    containers: tuple[structured_c.CStatements, ...],
    local: structured_c.CVariable,
    fact: SegmentStackRestoreFact8616,
) -> tuple[structured_c.CAssignment, ...]:
    """Require exactly one source-register store per byte and no other writers."""
    stores: dict[int, structured_c.CAssignment] = {}
    word_stores: list[structured_c.CAssignment] = []
    allowed_references: set[int] = set()
    nodes = {id(node): node for container in containers for node in _iter_c_nodes_deep_8616(container)}
    for node in nodes.values():
        if not isinstance(node, structured_c.CAssignment):
            continue
        owns_lvalue = any(_same_local(child, local) for child in (node.lhs, *_iter_c_nodes_deep_8616(node.lhs)))
        if not owns_lvalue:
            continue
        if _same_local(node.lhs, local):
            if not _proven_call_store(codegen, node, fact):
                return ()
            word_stores.append(node)
            continue
        byte = _stored_byte(node.lhs, local)
        if byte is None or byte in stores or fact.saved_register is None:
            return ()
        valid_store = (fact.saved_instruction_addr in instruction_addrs_from_node_8616(node)
                       and _is_saved_register_byte_8616(node.rhs, fact.saved_register, byte))
        if not valid_store:
            return ()
        stores[byte] = node
        allowed_references.update(id(child) for child in _iter_c_nodes_deep_8616(node.lhs)
                                  if isinstance(child, structured_c.CUnaryOp) and child.op == "Reference")
    if _address_escapes(nodes, local, allowed_references):
        return ()
    if word_stores:
        return tuple(word_stores) if len(word_stores) == 1 and not stores else ()
    return (stores[0], stores[1]) if len(stores) == _WORD_BYTES else ()


def _dominates_reload(
    statements: list[object], restore_index: int, stores: tuple[structured_c.CAssignment, ...],
) -> bool:
    """Require adjacent byte stores and an assignment-only path to the reload."""
    indices = [index for index, statement in enumerate(statements)
               if any(statement is store for store in stores)]
    if not stores or len(indices) != len(stores) or indices[-1] >= restore_index:
        return False
    if indices[-1] - indices[0] + 1 != len(stores):
        return False
    for statement in statements[indices[-1] + 1:restore_index]:
        if not isinstance(statement, structured_c.CAssignment):
            return False
        if not any(statement is store for store in stores) and not isinstance(statement.lhs, structured_c.CVariable):
            return False
        if any(isinstance(node, structured_c.CFunctionCall) for node in _iter_c_nodes_deep_8616(statement)):
            return False
    return True


def has_materialized_gp_local_reload_8616(
    codegen: object, containers: tuple[structured_c.CStatements, ...], fact: SegmentStackRestoreFact8616,
) -> bool:
    """Accept every exact runtime reload only when its local stores dominate it."""
    if fact.verdict is not SegmentStackRestoreVerdict8616.PROVEN:
        return False
    candidates: set[int] = set()
    verified: set[int] = set()
    for container in containers:
        statements = _unconditional_sequence_8616(container)
        for index, statement in enumerate(statements):
            if not isinstance(statement, structured_c.CAssignment):
                continue
            if fact.restore_instruction_addr not in instruction_addrs_from_node_8616(statement):
                continue
            candidates.add(id(statement))
            local = _runtime_restore_word_8616(statement, fact.restore_register)
            if not _exact_local(codegen, local, fact):
                continue
            assert isinstance(local, structured_c.CVariable)
            stores = _stores_for_local(codegen, containers, local, fact)
            if _dominates_reload(statements, index, stores):
                verified.add(id(statement))
    # Transparent nested containers can revisit a statement without its
    # parent's prefix. A proof in that parent still dominates the same node.
    return bool(candidates) and candidates == verified
