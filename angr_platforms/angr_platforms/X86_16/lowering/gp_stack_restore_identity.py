"""Check the byte ownership consumed by GP stack-restore materialization.

Layer: Types/Lowering.
Responsibility: compare structured byte views against the exact entry-SP bytes
already proven by Alias. Syntax recognition alone is never storage evidence.
Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer
from angr.sim_variable import SimStackVariable

from ..alias.segment_stack_restore import SegmentStackRestoreFact8616
from ..c_ast_utils import _iter_c_nodes_deep_8616
from .gp_register_state import runtime_gp_expression_view_8616, runtime_gp_live_in_name_8616
from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_variable_coordinates import stack_variable_coordinate_registry_8616
from .stack_word_recomposition import recognize_stack_word_recomposition_8616


def _entry_sp_byte_offset_8616(codegen: object, node: object) -> int | None:
    """Read native entry-SP storage or its explicit Lowering projection."""
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if (
        not isinstance(variable, SimStackVariable)
        or variable.base not in {"bp", "sp"}
        or not isinstance(variable.offset, int)
        or isinstance(node.variable_type, SimTypePointer)
    ):
        return None
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_variable(variable)
    if projection is None:
        projection = registry.for_equivalent_entry_sp_variable(variable)
    # Native angr BP-based variables use entry-SP offsets. Rebound variables
    # must consume their registered entry coordinate rather than a BP delta.
    return projection.entry_sp_offset if projection is not None else variable.offset


def matches_gp_restore_stack_bytes_8616(
    codegen: object,
    node: object,
    fact: SegmentStackRestoreFact8616,
) -> bool:
    """Require both byte operands to match the Alias-proven restore range."""
    recomposition = recognize_stack_word_recomposition_8616(node)
    if recomposition is None:
        return False
    low = _entry_sp_byte_offset_8616(codegen, recomposition.low)
    high = _entry_sp_byte_offset_8616(codegen, recomposition.high)
    return low is not None and high is not None and (low, high) == fact.stack_offsets


_BYTE_BITS_8616 = 8
_WORD_BYTES_8616 = 2
_WORD_MASK_8616 = 0xFFFF
_UPPER_WORD_MASK_8616 = 0xFFFF0000


def _masked_value_8616(node: object, mask: int) -> object | None:
    """Read the operand of an exact mask without discarding other operations."""
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "And":
        return None
    if isinstance(node.rhs, structured_c.CConstant) and node.rhs.value == mask:
        return cast(object, node.lhs)
    return None


def _runtime_restore_word_8616(
    statement: structured_c.CAssignment,
    register: str,
) -> object | None:
    """Require a low-word write that preserves the destination's upper word."""
    target = runtime_gp_expression_view_8616(statement.lhs)
    expected = runtime_gp_live_in_name_8616(register)
    if target is None or target.register_name != expected:
        return None
    rhs = statement.rhs
    if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Or":
        return None
    preserved = _masked_value_8616(rhs.lhs, _UPPER_WORD_MASK_8616)
    source = runtime_gp_expression_view_8616(preserved)
    if source != target:
        return None
    return _masked_value_8616(rhs.rhs, _WORD_MASK_8616)


def _is_saved_register_byte_8616(node: object, register: str, byte: int) -> bool:
    """Match the exact runtime low word or its unsigned high-byte projection."""
    if byte:
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
            return False
        if not isinstance(node.rhs, structured_c.CConstant) or node.rhs.value != _BYTE_BITS_8616:
            return False
        node = node.lhs
    view = runtime_gp_expression_view_8616(node)
    return view is not None and view.register_name == register and view.width == _WORD_BYTES_8616


def _same_stack_variable_8616(node: object, operand: structured_c.CVariable) -> bool:
    """Compare existing C storage identities, not their names or equal offsets."""
    return isinstance(node, structured_c.CVariable) and node.variable == operand.variable


def _unique_byte_save_8616(
    containers: tuple[structured_c.CStatements, ...],
    operand: structured_c.CVariable,
) -> structured_c.CAssignment | None:
    """Refuse multiple writers or an escaped address of this byte object."""
    writers: dict[int, structured_c.CAssignment] = {}
    for container in containers:
        for node in _iter_c_nodes_deep_8616(container):
            if (isinstance(node, structured_c.CUnaryOp) and node.op == "Reference"
                    and any(_same_stack_variable_8616(child, operand)
                            for child in _iter_c_nodes_deep_8616(node))):
                return None
            if isinstance(node, structured_c.CAssignment) and _same_stack_variable_8616(node.lhs, operand):
                writers[id(node)] = node
    return next(iter(writers.values())) if len(writers) == 1 else None


def _existing_byte_saves_8616(
    codegen: object,
    containers: tuple[structured_c.CStatements, ...],
    word: object,
    fact: SegmentStackRestoreFact8616,
) -> tuple[structured_c.CAssignment, ...]:
    """Verify each byte's C storage, unique writer and saved-register value."""
    if not matches_gp_restore_stack_bytes_8616(codegen, word, fact):
        return ()
    pair = recognize_stack_word_recomposition_8616(word)
    assert pair is not None
    assert fact.saved_register is not None
    saves: list[structured_c.CAssignment] = []
    for byte, operand in enumerate((pair.low, pair.high)):
        if not isinstance(operand, structured_c.CVariable):
            return ()
        if (operand.variable.size != 1 or not isinstance(operand.variable_type, SimTypeChar)
                or operand.variable_type.signed is not False):
            return ()
        save = _unique_byte_save_8616(containers, operand)
        if save is None or fact.saved_instruction_addr not in instruction_addrs_from_node_8616(save):
            return ()
        if not _is_saved_register_byte_8616(save.rhs, fact.saved_register, byte):
            return ()
        saves.append(save)
    return tuple(saves)


def _unconditional_sequence_8616(container: structured_c.CStatements) -> list[object]:
    """Flatten only transparent statement lists, never control-flow bodies."""
    result: list[object] = []
    for statement in container.statements:
        if isinstance(statement, structured_c.CStatements):
            result.extend(_unconditional_sequence_8616(statement))
        else:
            result.append(statement)
    return result


def has_materialized_gp_stack_bytes_8616(
    codegen: object,
    containers: tuple[structured_c.CStatements, ...],
    fact: SegmentStackRestoreFact8616,
) -> bool:
    """Accept an unchanged exact byte representation before inventing a snapshot.

    This is deliberately limited to adjacent byte definitions dominating the
    restore in the same unconditional sequence. Alias proves machine provenance; this
    check additionally proves its existing structured-C value/storage binding.
    Other shapes retain the normal materialization and validation path.
    """
    if any(isinstance(node, structured_c.CGoto) for container in containers
           for node in _iter_c_nodes_deep_8616(container)):
        return False
    candidates: set[int] = set()
    verified: set[int] = set()
    for container in containers:
        statements = _unconditional_sequence_8616(container)
        for restore_index, statement in enumerate(statements):
            if not isinstance(statement, structured_c.CAssignment):
                continue
            if fact.restore_instruction_addr not in instruction_addrs_from_node_8616(statement):
                continue
            candidates.add(id(statement))
            word = _runtime_restore_word_8616(statement, fact.restore_register)
            saves = _existing_byte_saves_8616(codegen, containers, word, fact)
            if len(saves) != _WORD_BYTES_8616:
                continue
            indices = [index for index, candidate in enumerate(statements)
                       if any(candidate is save for save in saves)]
            if len(indices) == _WORD_BYTES_8616 and indices[1] == indices[0] + 1 and indices[1] < restore_index:
                verified.add(id(statement))
    return bool(candidates) and verified == candidates
