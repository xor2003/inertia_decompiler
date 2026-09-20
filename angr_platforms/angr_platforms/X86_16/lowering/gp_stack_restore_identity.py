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
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ..alias.segment_stack_restore import SegmentStackRestoreFact8616
from ..c_ast_utils import _iter_c_nodes_deep_8616
from .gp_register_state import runtime_gp_expression_view_8616, runtime_gp_live_in_name_8616
from .physical_registers import physical_register_name_8616
from .segment_access_policy import instruction_addrs_from_node_8616
from .segment_register_state import runtime_segment_name_for_variable_8616
from .stack_variable_coordinates import stack_variable_coordinate_registry_8616
from .stack_word_recomposition import recognize_stack_word_recomposition_8616
from .terminal_return_expressions import _safe_scalar_expression_8616


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
        return fact.constant_value is not None and _word_local_from_byte_views_8616(codegen, node, fact) is not None
    low = _entry_sp_byte_offset_8616(codegen, recomposition.low)
    high = _entry_sp_byte_offset_8616(codegen, recomposition.high)
    return low is not None and high is not None and (low, high) == fact.stack_offsets


def _unsigned_byte_view_8616(node: object) -> object | None:
    """Require an actual unsigned-byte truncation, not an arbitrary cast."""
    if isinstance(node, structured_c.CTypeCast) and isinstance(node.dst_type, SimTypeChar) and node.dst_type.signed is False:
        return cast(object, node.expr)
    return None


def _shifted_view_8616(node: object, operation: str) -> object | None:
    """Require exactly one byte of shift in the requested direction."""
    if (isinstance(node, structured_c.CBinaryOp) and node.op == operation
            and isinstance(node.rhs, structured_c.CConstant) and node.rhs.value == 8):
        return cast(object, node.lhs)
    return None


def _word_local_from_byte_views_8616(
    codegen: object, node: object, fact: SegmentStackRestoreFact8616,
) -> structured_c.CVariable | None:
    """Find the local behind exact byte views; this alone does not prove its value."""
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None
    for low, high in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        local = _unsigned_byte_view_8616(low)
        upper = _shifted_view_8616(_unsigned_byte_view_8616(_shifted_view_8616(high, "Shl")), "Shr")
        if not isinstance(local, structured_c.CVariable) or not isinstance(upper, structured_c.CVariable):
            continue
        if local.variable != upper.variable or local.variable.size not in {2, 4}:
            continue
        offset = _entry_sp_byte_offset_8616(codegen, local)
        if offset is not None and fact.stack_offsets == (offset, offset + 1):
            return local
    return None


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
    """Read an exact native word write or a preserving runtime-parent write."""
    destination = statement.lhs
    if isinstance(destination, structured_c.CVariable) and isinstance(destination.variable, SimRegisterVariable):
        native_word = destination.variable.size == _WORD_BYTES_8616 and isinstance(destination.variable_type, SimTypeShort)
        if native_word and physical_register_name_8616(destination) == register:
            return cast(object, statement.rhs)
        return None
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


def _assignment_prefix_before_origin_8616(statements: list[object], instruction: int | None) -> set[int]:
    """Identify direct preceding assignments, never crossing control-flow boundaries.

    Consumers must independently prove complete replacement stores and dominance.
    This only establishes order; it neither deletes nor classifies earlier effects.
    """
    prefix: set[int] = set()
    for statement in statements:
        if not isinstance(statement, structured_c.CAssignment) or id(statement) in prefix:
            return set()
        if instruction in instruction_addrs_from_node_8616(statement):
            return prefix
        prefix.add(id(statement))
    return set()


def _independent_segment_assignment_8616(statement: structured_c.CAssignment) -> bool:
    """Separate a pure owned segment publication from a GP destination census.

    The segment value remains subject to segment and whole-tail validation.
    Calls and nested effects may alter GP state and cannot be excluded here.
    """
    target = statement.lhs
    if not isinstance(target, structured_c.CVariable) or runtime_segment_name_for_variable_8616(target.variable) is None:
        return False
    return bool(_safe_scalar_expression_8616(statement.rhs))


def _stack_write_offsets_8616(codegen: object, target: object) -> tuple[int, ...] | None:
    """Resolve only exact word locals and unsigned indexed bytes of those locals."""
    if isinstance(target, structured_c.CVariable):
        offset = _entry_sp_byte_offset_8616(codegen, target)
        if offset is not None and target.variable.size == 2 and isinstance(target.variable_type, SimTypeShort):
            return (offset, offset + 1)
        return None
    if not isinstance(target, structured_c.CIndexedVariable):
        return None
    index, pointer = target.index, target.variable
    if not isinstance(index, structured_c.CConstant) or index.value not in {0, 1}:
        return None
    if not isinstance(pointer, structured_c.CTypeCast) or not isinstance(pointer.dst_type, SimTypePointer):
        return None
    byte_type, reference = pointer.dst_type.pts_to, pointer.expr
    unsigned_byte = isinstance(byte_type, SimTypeChar) and byte_type.signed is False
    if not unsigned_byte or not isinstance(reference, structured_c.CUnaryOp) or reference.op != "Reference":
        return None
    offsets = _stack_write_offsets_8616(codegen, reference.operand)
    return (offsets[int(index.value)],) if offsets is not None and len(offsets) == 2 else None


def _disjoint_stack_write_8616(
    statement: structured_c.CAssignment, stores: tuple[structured_c.CAssignment, ...],
) -> bool:
    """Require every written stack byte to avoid every protected saved byte."""
    target = _stack_write_offsets_8616(statement.codegen, statement.lhs)
    if target is None or not stores:
        return False
    saved_ranges = tuple(_stack_write_offsets_8616(store.codegen, store.lhs) for store in stores)
    return all(saved is not None and set(target).isdisjoint(saved) for saved in saved_ranges)


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
