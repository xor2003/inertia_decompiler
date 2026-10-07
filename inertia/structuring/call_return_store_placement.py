"""Place standalone calls into proven adjacent return-value stores.

Layer: Structuring.
Responsibility: prove and materialize adjacency between one structured call
and one exact Lowering-owned call-return stack destination.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CFunctionCall,
    CStatements,
    CVariable,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from inertia.lowering.call_return_stack_bindings import (
    call_return_stack_destination_matches_8616 as is_exact_call_return_stack_destination_8616,
)
from inertia.lowering.call_return_stack_stores import CallReturnStackStoreEvidence8616
from inertia.lowering.structured_tags import copy_structured_tags_8616


@dataclass(frozen=True, slots=True)
class CallReturnStorePlacement8616:
    """Unique structured call statement and its proven destination store."""

    call_container: CStatements
    call_index: int
    store_assignment: CAssignment

__all__ = (
    "CallReturnStorePlacement8616",
    "bind_adjacent_standalone_call_store_8616",
    "bind_proven_call_result_bridge_8616",
    "find_adjacent_assigned_call_store_8616",
    "find_adjacent_standalone_call_store_8616",
    "find_proven_call_result_bridge_8616",
    "is_exact_call_return_stack_destination_8616",
)


def _sole_nested_statement_8616(statement: object) -> object | None:
    """Unwrap only bounded singleton statement containers."""
    current = statement
    for _depth in range(12):
        if not isinstance(current, CStatements):
            return current
        statements = tuple(current.statements or ())
        if len(statements) != 1:
            return None
        current = statements[0]
    return None


def _contains_identity_8616(root: object, target: object) -> bool:
    """Return whether one structured subtree contains the exact target node."""
    return root is target or any(node is target for node in _iter_c_nodes_deep_8616(root))


def _assignment_ins_addr_8616(assignment: CAssignment) -> int | None:
    """Return the exact source instruction tag on one structured assignment."""
    tags = copy_structured_tags_8616(assignment.tags)
    if tags is None:
        return None
    ins_addr = tags.get("ins_addr")
    return ins_addr if isinstance(ins_addr, int) else None


def _statement_containers_8616(root: object) -> tuple[CStatements, ...]:
    """Return identity-deduplicated statement containers in one AST."""
    return tuple(
        {
            id(container): container
            for container in (root, *_iter_c_nodes_deep_8616(root))
            if isinstance(container, CStatements)
        }.values()
    )


def _unique_direct_owner_8616(
    root: object,
    statement: object,
) -> tuple[CStatements, int] | None:
    """Return the unique container that directly owns one statement."""
    owners = tuple(
        (container, index)
        for container in _statement_containers_8616(root)
        for index, candidate in enumerate(tuple(container.statements or ()))
        if candidate is statement
    )
    return owners[0] if len(owners) == 1 else None


def _has_unique_adjacent_order_witness_8616(
    root: object,
    call_assignment: CAssignment,
    store_assignment: CAssignment,
) -> bool:
    """Prove sequential ownership in adjacent sibling subtrees."""
    witnesses = 0
    for container in _statement_containers_8616(root):
        statements = tuple(container.statements or ())
        call_indices = tuple(
            index for index, statement in enumerate(statements) if _contains_identity_8616(statement, call_assignment)
        )
        store_indices = tuple(
            index for index, statement in enumerate(statements) if _contains_identity_8616(statement, store_assignment)
        )
        if len(call_indices) == 1 and len(store_indices) == 1 and store_indices[0] == call_indices[0] + 1:
            witnesses += 1
    return witnesses == 1


def find_adjacent_assigned_call_store_8616(
    root: object,
    call_assignment: CAssignment,
    call: CFunctionCall,
    evidence: CallReturnStackStoreEvidence8616,
    *,
    codegen: object,
) -> CallReturnStorePlacement8616 | None:
    """Find a tagged call assignment followed by its exact proven store."""
    if (
        _assignment_ins_addr_8616(call_assignment) != evidence.callsite_addr
        or not isinstance(evidence.store_ins_addr, int)
        or not _contains_identity_8616(call_assignment.rhs, call)
    ):
        return None
    call_owner = _unique_direct_owner_8616(root, call_assignment)
    if call_owner is None:
        return None
    call_container, call_index = call_owner
    if call_index != len(tuple(call_container.statements or ())) - 1:
        return None
    stores = tuple(
        {
            id(node): node
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, CAssignment)
            and _assignment_ins_addr_8616(node) == evidence.store_ins_addr
            and is_exact_call_return_stack_destination_8616(codegen, node.lhs, evidence)
        }.values()
    )
    if len(stores) != 1:
        return None
    store_assignment = stores[0]
    if _unique_direct_owner_8616(root, store_assignment) is None:
        return None
    if not _has_unique_adjacent_order_witness_8616(root, call_assignment, store_assignment):
        return None
    return CallReturnStorePlacement8616(call_container, call_index, store_assignment)


def _assignment_source_position_8616(
    assignment: CAssignment,
) -> tuple[int, int, int] | None:
    """Return exact instruction, block, and VEX-statement identity."""
    tags = copy_structured_tags_8616(assignment.tags)
    if tags is None:
        return None
    ins_addr = tags.get("ins_addr")
    block_addr = tags.get("vex_block_addr")
    statement_index = tags.get("vex_stmt_idx")
    if not (
        isinstance(ins_addr, int)
        and isinstance(block_addr, int)
        and isinstance(statement_index, int)
    ):
        return None
    return ins_addr, block_addr, statement_index


def find_proven_call_result_bridge_8616(
    root: object,
    call: CFunctionCall,
    evidence: CallReturnStackStoreEvidence8616,
    *,
    codegen: object,
) -> CallReturnStorePlacement8616 | None:
    """Find a unique call-carrier-to-stack-store chain from exact source tags."""
    if not isinstance(evidence.store_ins_addr, int):
        return None
    call_assignments = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and node.rhs is call
        and (position := _assignment_source_position_8616(node)) is not None
        and position[0] == evidence.store_ins_addr
    )
    if len(call_assignments) != 1:
        return None
    call_assignment = call_assignments[0]
    call_position = _assignment_source_position_8616(call_assignment)
    if call_position is None:
        return None
    stores = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and is_exact_call_return_stack_destination_8616(codegen, node.lhs, evidence)
        and _same_c_expression_8616(node.rhs, call_assignment.lhs)
        and (position := _assignment_source_position_8616(node)) is not None
        and position[0] == evidence.store_ins_addr
        and position[1] == call_position[1]
        and position[2] > call_position[2]
    )
    if len(stores) != 1:
        return None
    call_owner = _unique_direct_owner_8616(root, call_assignment)
    if call_owner is None or _unique_direct_owner_8616(root, stores[0]) is None:
        return None
    return CallReturnStorePlacement8616(call_owner[0], call_owner[1], stores[0])


def bind_proven_call_result_bridge_8616(
    root: object,
    placement: CallReturnStorePlacement8616,
    call: CFunctionCall,
    destination: CVariable,
) -> int | None:
    """Bind one proven store and replace only later identity-shared call uses."""
    statements = list(placement.call_container.statements or ())
    if not 0 <= placement.call_index < len(statements):
        return None
    source = statements[placement.call_index]
    if not isinstance(source, CAssignment) or source.rhs is not call:
        return None
    source_position = _assignment_source_position_8616(source)
    store_position = _assignment_source_position_8616(placement.store_assignment)
    if (
        source_position is None
        or store_position is None
        or source_position[1] != store_position[1]
        or source_position[2] >= store_position[2]
    ):
        return None
    aliases = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and node is not source
        and node is not placement.store_assignment
        and node.rhs is call
    )
    alias_positions = tuple(_assignment_source_position_8616(alias) for alias in aliases)
    if any(
        position is None
        or position[1] != store_position[1]
        or position[2] <= store_position[2]
        for position in alias_positions
    ):
        return None
    placement.store_assignment.rhs = call
    for alias in aliases:
        alias.rhs = destination
    del statements[placement.call_index]
    placement.call_container.statements = statements
    return len(aliases)


def find_adjacent_standalone_call_store_8616(
    root: object,
    call: CFunctionCall,
    evidence: CallReturnStackStoreEvidence8616,
    *,
    codegen: object,
) -> CallReturnStorePlacement8616 | None:
    """Find one unique adjacent call/store pair through singleton wrappers."""
    matches: dict[tuple[int, int], CallReturnStorePlacement8616] = {}
    containers: dict[int, CStatements] = {
        id(container): container
        for container in (root, *_iter_c_nodes_deep_8616(root))
        if isinstance(container, CStatements)
    }
    for container in containers.values():
        statements = tuple(container.statements or ())
        for index, statement in enumerate(statements[:-1]):
            first = _sole_nested_statement_8616(statement)
            second = _sole_nested_statement_8616(statements[index + 1])
            if (
                first is call
                and isinstance(second, CAssignment)
                and is_exact_call_return_stack_destination_8616(codegen, second.lhs, evidence)
            ):
                matches[(id(container), index)] = CallReturnStorePlacement8616(container, index, second)
    return next(iter(matches.values())) if len(matches) == 1 else None


def bind_adjacent_standalone_call_store_8616(
    placement: CallReturnStorePlacement8616,
    call: CFunctionCall,
) -> CAssignment:
    """Move one proven standalone call into its adjacent destination store."""
    placement.store_assignment.rhs = call
    statements = list(placement.call_container.statements or ())
    del statements[placement.call_index]
    placement.call_container.statements = statements
    return placement.store_assignment
