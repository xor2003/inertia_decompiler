"""Layer: Rewrite/Postprocess cleanup.

Responsibility: distinguish local C values from reused physical registers when
proving redundant assignments. Consumes already-proven IR, alias, widening,
typed, and structuring facts. Do not recover new semantics, storage identity,
types, call signatures, control flow, or facts from rendered text, COD, source,
or CLI/reporting evidence here.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CConstant, CTypeCast, CVariable
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ...c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616


def _value_views_8616(root: object) -> tuple[tuple[object, ...], ...]:
    """Retain version identity and type views omitted by storage comparison."""
    views: list[tuple[object, ...]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CVariable) and isinstance(node.variable, SimRegisterVariable):
            views.append(("register", id(node.variable), node.variable.size, node.type))
        elif isinstance(node, CTypeCast):
            views.append(("cast", node.src_type, node.dst_type))
        elif isinstance(node, CConstant):
            views.append(("constant", node.type))
    return tuple(views)


def same_local_value_expression_8616(first: object, second: object) -> bool:
    """Require value identity, not merely equal machine-storage coordinates.

    Distinct register objects conservatively refuse even if their printed names
    or physical offsets match. Existing stack coordinates remain Alias-owned.
    """
    return bool(
        _same_c_expression_8616(first, second)
        and _value_views_8616(first) == _value_views_8616(second)
    )


def _stack_read_overlaps_8616(destination: object, source: object) -> bool:
    """Consume exact stack ranges; unresolved frame relationships refuse."""
    if not isinstance(destination, SimStackVariable) or not isinstance(source, SimStackVariable):
        return False
    if (destination.base, destination.region) != (source.base, source.region):
        return True
    return bool(
        destination.offset < source.offset + source.size
        and source.offset < destination.offset + destination.size
    )


def assignment_reads_destination_8616(lhs: object, rhs: object) -> bool:
    """Refuse repeated updates whose first write can change the second RHS."""
    if not isinstance(lhs, CVariable):
        return True
    for node in _iter_c_nodes_deep_8616(rhs):
        if not isinstance(node, CVariable):
            continue
        if _same_c_expression_8616(lhs, node) or _stack_read_overlaps_8616(lhs.variable, node.variable):
            return True
    return False
