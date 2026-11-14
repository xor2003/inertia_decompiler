# cython: language_level=3, infer_types=True
"""Match direct stack moves to proven structured loop entry sites.

Layer: Structuring.
Responsibility: join binary loop-entry edges to exact AST instruction tags and
move one already-lowered assignment to the unique owning repeated loop.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
This module changes placement only; it never infers storage, types, or semantics.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Any

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from inertia.lowering.real_mode_linear import DirectStackMoveFact8616
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
)

from .direct_stack_move_loop_evidence import (
    DirectStackMoveLoopEntryEdge8616,
    boundary_tuple_8616,
    candidate_addresses_8616,
    comparable_address_8616,
)
import dataclasses
import operator
import builtins


@dataclasses.dataclass(frozen=True, )
class DirectStackMoveLoopEntrySite8616:
    """One structured loop body uniquely covered by a machine loopback."""

    statements: object
    depth: cython.longlong


@dataclasses.dataclass(frozen=True, )
class DirectStackMoveAssignmentLocation8616:
    """One exact tagged assignment location in the structured tree."""

    statements: object
    index: cython.longlong
    assignment: structured_c.CAssignment


@cython.ccall
def _ast_field_8616(node: object | None, name: object) -> object | None:
    """Read one optional field from a heterogeneous third-party angr AST node."""
    # Dynamic boundary: structured-codegen nodes expose fields by concrete node shape.
    return getattr(node, name, None)


@cython.ccall
def _node_tag_values_8616(node: object, addresses: object) -> None:
    """Collect instruction-origin tag values from one structured node."""
    address: object
    key: object
    tags = _ast_field_8616(node, "tags")
    if isinstance(tags, dict):
        for key in ("ins_addr", "inertia_relocated_from_ins_addr"):
            address = tags.get(key)
            if isinstance(address, int):
                addresses.add(address)


@cython.ccall
def _push_tag_children_8616(node: object, stack: object) -> None:
    """Push the structured children of one node onto the tag walk stack."""
    child: object
    attr: object
    body: object
    condition: object
    for attr in ("condition", "body", "else_node", "statements"):
        child = _ast_field_8616(node, attr)
        if child is not None:
            stack.append(child)
    pairs = _ast_field_8616(node, "condition_and_nodes")
    if pairs:
        for condition, body in boundary_tuple_8616(pairs):
            stack.extend((condition, body))


@cython.ccall
def _tree_tag_addresses_8616(root: object) -> frozenset[cython.longlong]:
    """Collect exact instruction-origin tags from one structured subtree."""
    node: object
    addresses: set[cython.longlong] = set()
    seen: set[cython.longlong] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        if isinstance(node, (list, tuple)):
            stack.extend(node)
            continue
        seen.add(id(node))
        _node_tag_values_8616(node, addresses)
        _push_tag_children_8616(node, stack)
    return frozenset(addresses)


@cython.ccall
def _stack_offset_8616(codegen: object, expression: object) -> int | None:
    """Return the registry-proven machine-BP offset for one C variable."""
    if not isinstance(expression, structured_c.CVariable):
        return None
    variable = expression.variable
    if isinstance(variable, SimStackVariable):
        return machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return None


@cython.ccall
def _tree_reads_stack_offset_8616(codegen: object, root: object, offset: cython.longlong) -> cython.bint:
    """Return whether a structured subtree reads one exact stack slot."""
    child: object
    node: object
    attr: object
    pair: object
    seen: set[cython.longlong] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        if isinstance(node, (list, tuple)):
            stack.extend(node)
            continue
        seen.add(id(node))
        if isinstance(node, structured_c.CAssignment):
            stack.append(node.rhs)
            continue
        if operator.eq(_stack_offset_8616(codegen, node), offset):
            return True
        for attr in (
            "lhs", "rhs", "expr", "operand", "operands",
            "condition", "body", "else_node", "statements",
        ):
            child = _ast_field_8616(node, attr)
            if child is not None:
                stack.append(child)
        for pair in boundary_tuple_8616(_ast_field_8616(node, "condition_and_nodes") or ()):
            stack.extend(boundary_tuple_8616(pair))
    return False


def _statement_lists_8616(root: object) -> tuple[list[Any], ...]:
    """Return every executable statement list in one structured tree."""
    results: list[list[Any]] = []
    seen: set[cython.longlong] = set()
    seen_statement_lists: set[cython.longlong] = set()

    def visit(node: object) -> None:
        _condition: object
        attr: object
        body: object
        statement: object
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = _ast_field_8616(node, "statements")
        if isinstance(statements, list):
            if id(statements) not in seen_statement_lists:
                seen_statement_lists.add(id(statements))
                results.append(statements)
            for statement in tuple(statements):
                visit(statement)
        for attr in ("body", "else_node"):
            visit(_ast_field_8616(node, attr))
        pairs = _ast_field_8616(node, "condition_and_nodes")
        if pairs:
            for _condition, body in boundary_tuple_8616(pairs):
                visit(body)

    visit(root)
    return tuple(results)


@cython.ccall
def _same_unique_binary_block_8616(
    function: object | None,
    first_addr: cython.longlong,
    second_addr: cython.longlong,
) -> cython.bint:
    """Prove that two instructions belong to one unique binary basic block."""
    block: object
    matches = 0
    for block in boundary_tuple_8616(_ast_field_8616(function, "blocks") or ()):
        capstone = _ast_field_8616(block, "capstone")
        addresses = {
            address
            for wrapped in builtins.iter(boundary_tuple_8616(_ast_field_8616(capstone, "insns") or ()))
            if isinstance(
                address := _ast_field_8616(
                    _ast_field_8616(wrapped, "insn") or wrapped,
                    "address",
                ),
                int,
            )
        }
        matches += int(first_addr in addresses and second_addr in addresses)
    return matches == 1


@cython.ccall
def _posttest_site_8616(
    node: object,
    condition: object,
    codegen: object,
    dst_offset: cython.longlong,
    jump_owns_posttest_condition: cython.bint,
) -> cython.bint:
    """Return whether a do-while loop's posttest reads the moved stack slot."""
    return bool(
        isinstance(node, structured_c.CDoWhileLoop)
        and jump_owns_posttest_condition
        and _tree_reads_stack_offset_8616(codegen, condition, dst_offset)
    )


@cython.ccall
def _pretest_site_8616(
    node: object,
    condition: object,
    jump_owns_pretest_body_tail: cython.bint,
) -> cython.bint:
    """Return whether a while(1) loop's pretest tail owns the move edge."""
    return bool(
        isinstance(node, structured_c.CWhileLoop)
        and isinstance(condition, structured_c.CConstant)
        and condition.value == 1
        and jump_owns_pretest_body_tail
    )


def loop_entry_sites_8616(
    project: object,
    codegen: object,
    root: object,
    edge: DirectStackMoveLoopEntryEdge8616,
    dst_offset: cython.longlong,
    *,
    function: object | None = None,
) -> tuple[DirectStackMoveLoopEntrySite8616, ...]:
    """Find structured loops uniquely covered by one repeated move edge."""
    sites: list[DirectStackMoveLoopEntrySite8616] = []
    seen: set[cython.longlong] = set()

    def visit(node: object, depth: cython.longlong, enclosing_loop_count: cython.longlong) -> None:
        _condition: object
        attr: object
        guarded_body: object
        statement: object
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        body = _ast_field_8616(node, "body")
        statements = _ast_field_8616(body, "statements")
        if isinstance(
            node,
            (structured_c.CDoWhileLoop, structured_c.CWhileLoop),
        ) and isinstance(statements, list):
            body_entry_addresses = {
                comparable_address_8616(project, address, edge.entry_addr)
                for address in builtins.iter(_tree_tag_addresses_8616(body))
            }
            body_jump_addresses = {
                comparable_address_8616(project, address, edge.jump_addr)
                for address in builtins.iter(_tree_tag_addresses_8616(body))
            }
            condition = node.condition
            condition_addresses = {
                comparable_address_8616(project, address, edge.jump_addr)
                for address in builtins.iter(_tree_tag_addresses_8616(condition))
            }
            entry_reaches_body = bool(body_entry_addresses) and (
                edge.entry_addr <= min(body_entry_addresses)
                and min(body_entry_addresses) - edge.entry_addr <= 16
            )
            jump_owns_posttest_condition = bool(condition_addresses) and (
                max(condition_addresses) <= edge.jump_addr
                and edge.jump_addr - max(condition_addresses) <= 16
            )
            body_origins_before_jump = tuple(
                address
                for address in iter(body_jump_addresses)
                if address <= edge.jump_addr
            )
            jump_owns_pretest_body_tail = bool(body_origins_before_jump) and (
                edge.jump_addr - max(body_origins_before_jump) <= 16
                or (
                    enclosing_loop_count == 0
                    and any(
                        _same_unique_binary_block_8616(function, address, edge.jump_addr)
                        for address in iter(body_origins_before_jump)
                    )
                )
            )
            if entry_reaches_body and (
                _posttest_site_8616(
                    node, condition, codegen, dst_offset, jump_owns_posttest_condition,
                )
                or _pretest_site_8616(node, condition, jump_owns_pretest_body_tail)
            ):
                sites.append(DirectStackMoveLoopEntrySite8616(statements, depth))
        nested_loop_count = enclosing_loop_count + int(
            isinstance(node, (structured_c.CDoWhileLoop, structured_c.CWhileLoop))
        )
        statements_value = _ast_field_8616(node, "statements")
        if isinstance(statements_value, list):
            for statement in tuple(statements_value):
                visit(statement, depth + 1, nested_loop_count)
        for attr in ("body", "else_node"):
            visit(_ast_field_8616(node, attr), depth + 1, nested_loop_count)
        pairs = _ast_field_8616(node, "condition_and_nodes")
        if pairs:
            for _condition, guarded_body in boundary_tuple_8616(pairs):
                visit(guarded_body, depth + 1, nested_loop_count)

    visit(root, 0, 0)
    return tuple(sites)


@cython.ccall
def tagged_assignment_locations_8616(
    project: object,
    codegen: object,
    root: object,
    move_fact: DirectStackMoveFact8616,
) -> tuple[DirectStackMoveAssignmentLocation8616, ...]:
    """Find exact assignments tagged to one move fact and destination slot."""
    index: object
    statement: object
    statements: object
    candidates = candidate_addresses_8616(project, move_fact.ins_addr)
    locations: list[DirectStackMoveAssignmentLocation8616] = []
    for statements in _statement_lists_8616(root):
        for index, statement in enumerate(tuple(statements)):
            if not isinstance(statement, structured_c.CAssignment):
                continue
            if operator.ne(_stack_offset_8616(codegen, statement.lhs), move_fact.dst_offset):
                continue
            if _tree_tag_addresses_8616(statement) & candidates:
                locations.append(
                    DirectStackMoveAssignmentLocation8616(statements, index, statement)
                )
    return tuple(locations)


def _ordered_insertion_index_8616(
    project: object,
    codegen: object,
    statements: object,
    move_addr: cython.longlong,
    dst_offset: cython.longlong,
) -> int | None:
    """Return the exact tag- and data-ordered loop-entry index."""
    index: object
    statement: object
    following: list[tuple[cython.longlong, cython.longlong]] = []
    for index, statement in enumerate(statements):
        comparable = [
            comparable_address_8616(project, tagged, move_addr)
            for tagged in builtins.iter(_tree_tag_addresses_8616(statement))
            if comparable_address_8616(project, tagged, move_addr) > move_addr
        ]
        if comparable:
            following.append((min(comparable), index))
    if not following:
        return None
    first_address = min(address for address, _index in iter(following))
    indexes = tuple(index for address, index in iter(following) if address == first_address)
    if len(indexes) != 1:
        return None
    tagged_index = indexes[0]
    prior_read_indexes = tuple(
        index
        for index, statement in builtins.iter(enumerate(statements[:tagged_index]))
        if _tree_reads_stack_offset_8616(codegen, statement, dst_offset)
    )
    return min((tagged_index, ) + tuple(prior_read_indexes))


@cython.ccall
def place_assignment_8616(
    project: object,
    codegen: object,
    site: DirectStackMoveLoopEntrySite8616,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
    location: object,
) -> tuple[cython.bint, cython.bint]:
    """Place one assignment at the exact ordered loop-entry site."""
    insertion_index: object
    target = site.statements
    ordered_target = [statement for statement in iter(target) if statement is not assignment]
    insertion_index = _ordered_insertion_index_8616(
        project,
        codegen,
        ordered_target,
        move_fact.ins_addr,
        move_fact.dst_offset,
    )
    if insertion_index is None:
        return False, False
    if location is not None and location.statements is target and operator.eq(location.index, insertion_index):
        return True, True
    if location is not None:
        del location.statements[location.index]
    target.insert(insertion_index, assignment)
    return True, False
