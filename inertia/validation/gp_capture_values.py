"""Validate immutable values retained by GP register capture.

Layer: Tail validation.
Responsibility: consume the Lowering capture marker and independently prove a
current, uniquely defined, dominating constant value. Never infer aliases from
names, cached writer maps, or a capture tag alone.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CGoto,
    CLabel,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimTemporaryVariable

from inertia.lowering.c_ast_utils import (
    _structured_codegen_node_8616,
    _structured_slot_names_8616,
)
from inertia.lowering.gp_register_versions import _CAPTURE_TAG
from inertia.validation.typed_constant_values import constant_integer_value_8616, integer_bounds_8616


class _CaptureTraversalRefused8616(Exception):
    """A current AST census could not prove complete bounded coverage."""


def _occurrences(root: object) -> tuple[object, ...]:
    """Walk each shared edge using the C-AST schema; refuse cycles and oversized trees."""
    result: list[object] = []
    visited_edges = 0

    def walk(value: object, active: frozenset[int]) -> None:
        nonlocal visited_edges
        structured = _structured_codegen_node_8616(value)
        container = isinstance(value, (dict, list, tuple))
        if not structured and not container:
            return
        visited_edges += 1
        if visited_edges > 8192 or id(value) in active:
            raise _CaptureTraversalRefused8616
        child_active = active | {id(value)}
        if isinstance(value, dict):
            children = tuple(value.values())
        elif isinstance(value, (list, tuple)):
            children = tuple(value)
        else:
            result.append(value)
            # Dynamic boundary: schema-owned fields belong to third-party angr C nodes.
            children = tuple(getattr(value, attr, None) for attr in _structured_slot_names_8616(value))
        for child in children:
            walk(child, child_active)

    walk(root, frozenset())
    return tuple(result)


def _bounded_linear_sequence(root: CStatements) -> tuple[object, ...]:
    """Flatten unconditional grouping only with bounded work, including malformed cycles."""
    pending: list[object] = [root]
    result: list[object] = []
    visited = 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > 8192:
            raise _CaptureTraversalRefused8616
        if isinstance(item, CStatements):
            if len(item.statements) + len(pending) + visited > 8192:
                raise _CaptureTraversalRefused8616
            pending.extend(reversed(item.statements))
        else:
            result.append(item)
    return tuple(result)


def resolve_gp_capture_constant_8616(node: object) -> CConstant | None:
    """Resolve a current immutable capture, refusing incomplete AST coverage."""
    try:
        return _resolve_current_capture(node)
    except (_CaptureTraversalRefused8616, RecursionError, AttributeError):
        return None


def _resolve_current_capture(node: object) -> CConstant | None:
    """Resolve a current GP capture read only when all its uses follow one constant definition.

    Only integer constants with the capture storage type are admitted. Loads,
    register reads and effectful expressions stay unresolved: a snapshot of a
    mutable expression cannot be replaced by evaluating that expression later.
    The root sequence flattens unconditional grouping, matching the producer;
    definitions inside a branch or loop are outside this small proof.
    """
    if not isinstance(node, CVariable) or not isinstance(node.variable, SimTemporaryVariable):
        return None
    # Dynamic boundary: angr CVariable/codegen can be partially constructed.
    cfunc = getattr(node.codegen, "cfunc", None)
    if cfunc is None:
        return None
    # Dynamic boundary: angr CFunction may not yet expose structured statements.
    root = getattr(cfunc, "statements", None)
    if not isinstance(root, CStatements):
        return None
    variable = node.variable
    # Required cheap admission: ordinary temporaries must never census expressions.
    linear = _bounded_linear_sequence(root)
    if not _has_literal_candidate(linear, node, variable):
        return None
    return _prove_current_capture(root, linear, node, variable)


def _prove_current_capture(
    root: CStatements, linear: tuple[object, ...], node: CVariable, variable: SimTemporaryVariable,
) -> CConstant | None:
    """Complete the current-tree identity, definition and dominance proof for a candidate."""
    occurrences = _occurrences(root)
    uses = tuple(item for item in occurrences if isinstance(item, CVariable) and item.variable is variable)
    if not any(item is node for item in uses):
        return None
    if not _capture_uses_are_read_only(occurrences, variable):
        return None
    definitions = tuple(item for item in occurrences if isinstance(item, CAssignment)
                        and isinstance(item.lhs, CVariable) and item.lhs.variable is variable)
    if len(definitions) != 1:
        return None
    definition = definitions[0]
    value = _capture_literal(definition, node, variable)
    if value is None:
        return None
    positions = tuple(index for index, item in enumerate(linear) if item is definition)
    if len(positions) != 1:
        return None
    later_uses = sum(
        isinstance(item, CVariable) and item.variable is variable
        for statement in linear[positions[0] + 1:]
        for item in _occurrences(statement)
    )
    if len(uses) != later_uses + 1:
        return None
    return value


def _has_literal_candidate(linear: tuple[object, ...], node: CVariable, variable: SimTemporaryVariable) -> bool:
    """Require one unconditional literal capture before paying for a complete AST census."""
    candidates = tuple(item for item in linear if isinstance(item, CAssignment)
                       and isinstance(item.lhs, CVariable) and item.lhs.variable is variable)
    return len(candidates) == 1 and _capture_literal(candidates[0], node, variable) is not None


def _capture_uses_are_read_only(occurrences: tuple[object, ...], variable: SimTemporaryVariable) -> bool:
    """Refuse collisions, control bypass and address-taking/mutating unary uses."""
    if any(isinstance(item, CVariable) and isinstance(item.variable, SimTemporaryVariable)
           and item.variable.tmp_id == variable.tmp_id and item.variable is not variable
           for item in occurrences):
        return False
    if any(isinstance(item, (CGoto, CLabel)) for item in occurrences):
        return False
    for item in occurrences:
        if (isinstance(item, CUnaryOp) and item.op not in {"Neg", "Not", "LogicalNot", "BitwiseNeg"}
                and any(isinstance(child, CVariable) and child.variable is variable
                        for child in _occurrences(item))):
            return False
    return True


def _capture_literal(definition: CAssignment, node: CVariable, variable: SimTemporaryVariable) -> CConstant | None:
    """Prove an exact integer conversion into the capture type without truncation."""
    if definition.tags.get(_CAPTURE_TAG) is not True or node.type != definition.lhs.type:
        return None
    value = constant_integer_value_8616(definition.rhs)
    bounds = integer_bounds_8616(node.type, variable.size * 8)
    if value is None or bounds is None or not bounds[0] <= value <= bounds[1]:
        return None
    if isinstance(definition.rhs, CConstant) and definition.rhs.type == node.type:
        return definition.rhs
    return CConstant(value, node.type, codegen=node.codegen)
