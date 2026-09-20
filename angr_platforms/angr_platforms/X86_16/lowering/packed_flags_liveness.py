"""Remove unread captured FLAGS definitions using whole-function evidence.

Layer: Types/Lowering.
Responsibility: prove packed-FLAGS definition liveness after typed consumers
have been materialized, using existing physical-register and SSA identities.
Consumes alias, widening, and typed facts after condition materialization.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not infer storage identity, types, call signatures, or control flow here.
Block-local absence of reads is not proof: enclosing guards and captured older
SSA values remain consumers. Unknown identities and side effects are retained.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.ailment.expression import VirtualVariable
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import (
    _iter_c_node_children_8616,
    _iter_c_nodes_deep_8616,
    _structured_slot_names_8616,
)
from ..ir.status_flag_lift_context import StatusFlagLiftArtifact8616
from ..semantics.expression_analysis import (
    VirtualValueIdentityKind8616,
    describe_virtual_value_identity_8616,
)
from .packed_flags_calls import call_has_no_implicit_status_inputs_8616, flag_artifact_for_structured_root_8616
from .physical_registers import physical_register_offset_8616

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


def _read_keys(
    root: object, flags_offset: int, ignored_assignments: frozenset[int] = frozenset(),
) -> set[_ValueKey] | None:
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
            if id(node) in ignored_assignments:
                continue
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
            "And", "Or", "Xor", "Add", "Sub", "Mul", "Mull", "Shl", "Shr",
            "CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE",
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


@dataclass(frozen=True, slots=True)
class PackedFlagsCycleStats8616:
    """Closed accounting for pure definitions disconnected from observable uses."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _flag_component_candidates(
    blocks: tuple[c.CStatements, ...], flags_offset: int,
) -> tuple[dict[int, c.CAssignment], int]:
    """Include pure register carriers connected to physical FLAGS definitions."""
    definitions = {
        id(statement): statement
        for block in blocks for statement in block.statements
        if isinstance(statement, c.CAssignment) and _value_keys(statement.lhs)
    }
    connected = {
        key for statement in definitions.values()
        if physical_register_offset_8616(statement.lhs) == flags_offset
        for key in _value_keys(statement.lhs)
    }
    pure = {identity: statement for identity, statement in definitions.items() if _pure_value(statement.rhs)}
    selected: dict[int, c.CAssignment] = {}
    while True:
        added = False
        for identity, statement in pure.items():
            keys = _value_keys(statement.lhs) | (_read_keys(statement.rhs, flags_offset) or set())
            if identity not in selected and not keys.isdisjoint(connected):
                selected[identity] = statement
                connected.update(keys)
                added = True
        if not added:
            return selected, len(definitions)


def prune_unobserved_flag_cycles_8616(
    root: object, flags_offset: int, *, lift_artifact: StatusFlagLiftArtifact8616 | None = None,
) -> PackedFlagsCycleStats8616:
    """Remove pure flag-only dependency components without an external consumer.

    Call only after complete condition materialization. Reads by any retained
    statement are roots; liveness propagates backward through every definition
    sharing an existing SSA/unified-storage key. Calls require binary evidence
    proving no implicit status inputs; explicit arguments always remain roots.
    Opaque payloads refuse effects outside this census.
    """
    nodes = tuple(_iter_c_nodes_deep_8616(root))
    lift_artifact = lift_artifact or flag_artifact_for_structured_root_8616(root)
    opaque_types = (c.CDirtyStatement, c.CUnsupportedStatement, c.CAILBlock, c.CVEXCCallExpression)
    if any(
        isinstance(node, opaque_types)
        or (isinstance(node, c.CFunctionCall) and not call_has_no_implicit_status_inputs_8616(node, lift_artifact))
        for node in nodes
    ):
        return PackedFlagsCycleStats8616(failure_count=1)
    blocks = tuple(node for node in nodes if isinstance(node, c.CStatements))
    definitions = {
        id(statement): statement
        for block in blocks for statement in block.statements
        if isinstance(statement, c.CAssignment)
        and physical_register_offset_8616(statement.lhs) == flags_offset
    }
    if any(not _value_keys(statement.lhs) for statement in definitions.values()):
        return PackedFlagsCycleStats8616(len(definitions), failure_count=1)
    candidates, definition_count = _flag_component_candidates(blocks, flags_offset)
    live = _read_keys(root, flags_offset, frozenset(candidates))
    if live is None:
        return PackedFlagsCycleStats8616(definition_count, len(candidates), failure_count=1)
    dependencies = {
        key: (_value_keys(statement.lhs), _read_keys(statement.rhs, flags_offset))
        for key, statement in candidates.items()
    }
    if any(inputs is None for _outputs, inputs in dependencies.values()):
        return PackedFlagsCycleStats8616(definition_count, len(candidates), failure_count=1)
    # Start at observable reads, not at the cycle's own reads. This is the least
    # fixed point; seeding every backedge read would keep every dead cycle alive.
    while True:
        expanded = set(live)
        for outputs, inputs in dependencies.values():
            if not outputs.isdisjoint(live):
                expanded.update(outputs)
                expanded.update(inputs or ())
        if expanded == live:
            break
        live = expanded
    dead = {key for key, (outputs, _inputs) in dependencies.items() if outputs.isdisjoint(live)}
    for block in blocks:
        block.statements = [statement for statement in block.statements if id(statement) not in dead]
    return PackedFlagsCycleStats8616(definition_count, len(candidates), len(dead), len(dead))
