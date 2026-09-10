"""Remove unread captured FLAGS definitions using whole-function evidence.

Layer: Rewrite/Postprocess cleanup.
Responsibility: consume existing physical-register and SSA identities to remove
pure definitions with no remaining read. Do not recover new semantics, storage
identity, types, call signatures, control flow, or facts from rendered text,
COD, source, or CLI/reporting evidence here.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Block-local absence of reads is not proof: enclosing guards and captured older
SSA values remain consumers. Unknown identities and side effects are retained.
"""

from __future__ import annotations

from angr.ailment.expression import VirtualVariable
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import (
    _iter_c_node_children_8616,
    _iter_c_nodes_deep_8616,
    _structured_slot_names_8616,
)
from ..lowering.physical_registers import physical_register_offset_8616
from ..semantics.expression_analysis import (
    VirtualValueIdentityKind8616,
    describe_virtual_value_identity_8616,
)

type _ValueKey = tuple[str, int | str, int | str | None]


def _value_keys(node: object) -> frozenset[_ValueKey]:
    """Consume exact SSA and shared emitted-storage identities, never names."""
    if isinstance(node, c.CVariable) and isinstance(node.variable, SimRegisterVariable):
        keys: set[_ValueKey] = set()
        variable = node.variable
        if isinstance(node.vvar_id, (int, str)):
            keys.add(("virtual", node.vvar_id, None))
        if isinstance(variable.ident, (int, str)):
            keys.add(("register", variable.ident, variable.region))
        if node.unified_variable is not None:
            # Unification can join distinct SSA carriers into one emitted local.
            keys.add(("unified", id(node.unified_variable), None))
        return frozenset(keys)
    if not isinstance(node, c.CDirtyExpression) or not isinstance(node.dirty, VirtualVariable):
        return frozenset()
    identity = describe_virtual_value_identity_8616(node)
    if identity is not None and identity.kind is VirtualValueIdentityKind8616.VARIABLE_ID:
        return frozenset({("virtual", identity.value, None)})
    return frozenset()


def _read_keys(root: object, flags_offset: int) -> set[_ValueKey] | None:
    """Collect reads across all structured scopes, excluding plain write targets."""
    reads: set[_ValueKey] = set()
    work = [root]
    seen: set[int] = set()
    while work:
        node = work.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, c.CAssignment):
            work.append(node.rhs)
            if not isinstance(node.lhs, c.CVariable) and not _value_keys(node.lhs):
                work.append(node.lhs)
            continue
        # AIL payloads are not C-AST children. Only a known atomic vvar is safe
        # to census without inspecting hidden operands or guessing their effects.
        if isinstance(node, c.CDirtyExpression) and not isinstance(node.dirty, VirtualVariable):
            return None
        keys = _value_keys(node)
        if physical_register_offset_8616(node) == flags_offset and not keys:
            return None
        reads.update(keys)
        for attribute in _structured_slot_names_8616(node):
            # Shared traversal schema is the dynamic third-party C-AST boundary.
            value = getattr(node, attribute, None)
            work.extend(_iter_c_node_children_8616(value))
    return reads


def _pure_value(root: object) -> bool:
    """Refuse calls, memory reads, trapping operations and opaque expressions."""
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, c.CConstant):
            continue
        if isinstance(node, (c.CVariable, c.CDirtyExpression)) and _value_keys(node):
            continue
        if isinstance(node, c.CBinaryOp) and node.op in {
            "And", "Or", "Xor", "Add", "Sub", "Mul", "Shl", "Shr",
        }:
            continue
        if isinstance(node, c.CUnaryOp) and node.op in {"Not", "Neg", "BitwiseNeg"}:
            continue
        if isinstance(node, c.CTypeCast):
            continue
        return False
    return isinstance(root, c.CExpression)


def prune_unread_flag_definitions_8616(root: object, flags_offset: int) -> bool:
    """Remove only globally unread, pure flag definitions, to a fixed point.

    Each successful iteration removes at least one assignment. Cyclic or
    unknown dependencies are retained rather than presumed dead.
    """
    changed = False
    while True:
        reads = _read_keys(root, flags_offset)
        if reads is None:
            return changed
        removed = False
        for node in tuple(_iter_c_nodes_deep_8616(root)):
            if not isinstance(node, c.CStatements):
                continue
            kept = []
            for statement in node.statements:
                keys = _value_keys(statement.lhs) if isinstance(statement, c.CAssignment) else frozenset()
                unread_flag = (
                    isinstance(statement, c.CAssignment)
                    and physical_register_offset_8616(statement.lhs) == flags_offset
                    and bool(keys)
                    and keys.isdisjoint(reads)
                )
                if unread_flag and isinstance(statement, c.CAssignment) and _pure_value(statement.rhs):
                    removed = True
                    continue
                kept.append(statement)
            node.statements = kept
        if not removed:
            return changed
        changed = True
