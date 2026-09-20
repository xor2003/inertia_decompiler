"""Locate exact call-output carriers at the dynamic angr C-AST boundary.

Layer: Types/Lowering.
Responsibility: map an immutable wide call-output Lowering fact to exact
instruction-tagged angr C-AST statements without deriving semantic facts from
AST shape, rendered text, symbols, or source names.
Consumes alias, widening, and typed facts at the dynamic C-AST boundary.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .wide_call_output_assignment_contracts import WideCallOutputAssignmentFact8616

_NEAR_OFFSET_MAX: int = 0xFFFF


class _TaggedNodeBoundary8616(Protocol):
    """Dynamic tag field exposed by angr C-AST nodes."""

    tags: object


class _FunctionBoundary8616(Protocol):
    """Dynamic address field exposed by angr function objects."""

    addr: int


class _ProjectAddressBoundary8616(Protocol):
    """Owned active-project extension exposing an exact slice rebase delta."""

    _inertia_original_linear_delta: int


class _LoadedObjectBoundary8616(Protocol):
    """Third-party loaded-object base used for near-offset normalization."""

    min_addr: int


class _LoaderBoundary8616(Protocol):
    """Third-party loader surface exposing the main loaded object."""

    main_object: _LoadedObjectBoundary8616


class _ProjectLoaderBoundary8616(Protocol):
    """Third-party project surface exposing its loader."""

    loader: _LoaderBoundary8616


@dataclass(frozen=True, slots=True)
class WideCallOutputCallSite8616:
    """One exact structured statement carrying the proven machine call."""

    statements: CStatements
    index: int
    statement: object
    call: CFunctionCall


def c_node_instruction_addrs_8616(node: object) -> frozenset[int]:
    """Return instruction tags from one dynamic angr C-AST subtree."""
    addresses: set[int] = set()
    for child in _iter_c_nodes_deep_8616(node):
        try:
            tags = cast(_TaggedNodeBoundary8616, child).tags
        except AttributeError:
            continue
        if not isinstance(tags, dict):
            continue
        address = tags.get("ins_addr")
        if isinstance(address, int):
            addresses.add(address)
    return frozenset(addresses)


def _statement_groups_8616(root: object) -> tuple[CStatements, ...]:
    """Return every mutable statement group once in deterministic tree order."""
    groups: dict[int, CStatements] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CStatements):
            groups.setdefault(id(node), node)
    return tuple(groups.values())


def direct_statement_group_parents_8616(
    root: object,
    child: CStatements,
) -> tuple[tuple[CStatements, int], ...]:
    """Return direct statement-list parents of one exact group by identity."""
    parents: list[tuple[CStatements, int]] = []
    for group in _statement_groups_8616(root):
        parents.extend(
            (group, index)
            for index, statement in enumerate(group.statements)
            if statement is child
        )
    return tuple(parents)


def _standalone_call_8616(statement: object) -> CFunctionCall | None:
    """Return a call carried by one complete statement."""
    if isinstance(statement, CFunctionCall):
        return statement
    if isinstance(statement, CExpressionStatement) and isinstance(
        statement.expr, CFunctionCall
    ):
        return statement.expr
    if isinstance(statement, CAssignment) and isinstance(statement.rhs, CFunctionCall):
        return statement.rhs
    return None


def _call_target_variants_8616(target_addr: int, project: object) -> set[int]:
    """Project the proven target into existing original, slice and near coordinates."""
    target_variants = {target_addr}
    try:
        delta = cast(_ProjectAddressBoundary8616, project)._inertia_original_linear_delta
    except AttributeError:
        delta = 0
    if isinstance(delta, int) and delta:
        target_variants.update((target_addr - delta, target_addr + delta))
    try:
        image_base = cast(_ProjectLoaderBoundary8616, project).loader.main_object.min_addr
    except AttributeError:
        image_base = None
    if isinstance(image_base, int):
        near_offset = target_addr - image_base
        if 0 <= near_offset <= _NEAR_OFFSET_MAX:
            target_variants.add(near_offset)
        if 0 <= target_addr <= _NEAR_OFFSET_MAX:
            target_variants.add(image_base + target_addr)
    return target_variants


def _call_target_matches_8616(
    call: CFunctionCall,
    target_addr: int,
    project: object,
) -> bool:
    """Match binary identity before and after symbol projection.

    Naming may detach the angr function but retains its exact target tag.
    A label alone proves nothing; conflicting numeric evidence refuses a match.
    """
    target_variants = _call_target_variants_8616(target_addr, project)
    attached_target = call.tags.get("inertia_target_addr_8616")
    if attached_target is not None and (
        type(attached_target) is not int or attached_target not in target_variants
    ):
        return False
    if isinstance(call.callee_target, int):
        return call.callee_target in target_variants
    if isinstance(call.callee_target, CConstant):
        constant_target = call.callee_target.value
        if isinstance(constant_target, int):
            return constant_target in target_variants
    if call.callee_func is None:
        return isinstance(call.callee_target, str) and attached_target in target_variants
    try:
        return cast(_FunctionBoundary8616, call.callee_func).addr in target_variants
    except AttributeError:
        return False


def exact_wide_call_output_call_sites_8616(
    root: object,
    fact: WideCallOutputAssignmentFact8616,
    project: object,
) -> tuple[WideCallOutputCallSite8616, ...]:
    """Collect structured calls matching exact instruction and target identity."""
    matches: list[WideCallOutputCallSite8616] = []
    for group in _statement_groups_8616(root):
        for index, statement in enumerate(group.statements):
            call = _standalone_call_8616(statement)
            if (
                call is not None
                and fact.call_output.callsite_addr
                in c_node_instruction_addrs_8616(statement)
                and _call_target_matches_8616(
                    call,
                    fact.call_output.target_addr,
                    project,
                )
            ):
                matches.append(
                    WideCallOutputCallSite8616(group, index, statement, call)
                )
    return tuple(matches)


def exact_wide_call_output_calls_in_node_8616(
    node: object,
    fact: WideCallOutputAssignmentFact8616,
    project: object,
) -> tuple[CFunctionCall, ...]:
    """Return calls carrying the fact's exact instruction and target identity."""
    return tuple(
        child
        for child in _iter_c_nodes_deep_8616(node)
        if isinstance(child, CFunctionCall)
        and fact.call_output.callsite_addr in c_node_instruction_addrs_8616(child)
        and _call_target_matches_8616(child, fact.call_output.target_addr, project)
    )


def callsite_tagged_calls_in_node_8616(
    node: object,
    callsite_addr: int,
) -> tuple[CFunctionCall, ...]:
    """Return calls carrying one exact machine-call instruction tag."""
    return tuple(
        child
        for child in _iter_c_nodes_deep_8616(node)
        if isinstance(child, CFunctionCall)
        and callsite_addr in c_node_instruction_addrs_8616(child)
    )


def exact_wide_call_output_statement_owners_8616(
    root: object,
    fact: WideCallOutputAssignmentFact8616,
    project: object,
) -> tuple[WideCallOutputCallSite8616, ...]:
    """Locate exact fact calls in mutable expression or assignment statements."""
    owners: list[WideCallOutputCallSite8616] = []
    for group in _statement_groups_8616(root):
        for index, statement in enumerate(group.statements):
            if not isinstance(
                statement,
                (CAssignment, CExpressionStatement, CFunctionCall),
            ):
                continue
            owners.extend(
                WideCallOutputCallSite8616(group, index, statement, call)
                for call in exact_wide_call_output_calls_in_node_8616(
                    statement,
                    fact,
                    project,
                )
            )
    return tuple(owners)


def callsite_tagged_statement_owners_8616(
    root: object,
    callsite_addr: int,
) -> tuple[WideCallOutputCallSite8616, ...]:
    """Locate tagged call occurrences in mutable expression statements."""
    owners: list[WideCallOutputCallSite8616] = []
    for group in _statement_groups_8616(root):
        for index, statement in enumerate(group.statements):
            if not isinstance(
                statement,
                (CAssignment, CExpressionStatement, CFunctionCall),
            ):
                continue
            owners.extend(
                WideCallOutputCallSite8616(group, index, statement, call)
                for call in callsite_tagged_calls_in_node_8616(
                    statement,
                    callsite_addr,
                )
            )
    return tuple(owners)


__all__ = [
    "WideCallOutputCallSite8616",
    "c_node_instruction_addrs_8616",
    "callsite_tagged_calls_in_node_8616",
    "callsite_tagged_statement_owners_8616",
    "direct_statement_group_parents_8616",
    "exact_wide_call_output_call_sites_8616",
    "exact_wide_call_output_calls_in_node_8616",
    "exact_wide_call_output_statement_owners_8616",
]
