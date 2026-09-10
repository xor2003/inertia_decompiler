"""Restore binary-proven stack initializers before structured pretest loops.

Layer: Structuring.
Responsibility: join typed direct-stack assignments to exact machine
initializer, condition, body, iterator, and loopback evidence, then place the
already-lowered assignment before its unique pretest loop without moving an
existing unconditional initializer past intervening reads.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Lowering owns the assignment value and stack identity; this module does not
infer aliases, values, types, names, or calls.
Missing or ambiguous binary/AST evidence leaves the original AST unchanged.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from capstone import CS_GRP_JUMP
from capstone.x86_const import X86_INS_JMP, X86_OP_IMM

from ..lowering.real_mode_linear import DirectStackMoveFact8616
from .direct_stack_move_loop_evidence import (
    boundary_tuple_8616,
    comparable_address_8616,
)
from .direct_stack_move_loop_sites import (
    _tree_reads_stack_offset_8616,
    _tree_tag_addresses_8616,
    tagged_assignment_locations_8616,
)
from .direct_stack_move_ownership import (
    direct_stack_move_branch_owned_addresses_8616,
)
from .pretest_condition_surface import pretest_condition_surface_8616
from .pretest_initializer_placement import place_pretest_initializer_8616 as _place_pretest_initializer_8616

log: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DirectStackMovePretestInitializerEvidence8616:
    """One exact machine pretest-loop initializer control-flow shape."""

    move_addr: int
    entry_jump_addr: int
    condition_entry_addr: int
    condition_branch_addrs: tuple[int, ...]
    iterator_entry_addr: int
    backedge_addr: int


@dataclass(frozen=True, slots=True)
class DirectStackMovePretestInitializerSite8616:
    """One structured pretest loop and its owning statement list."""

    statements: list[Any]
    loop: structured_c.CForLoop | structured_c.CWhileLoop
    depth: int


@dataclass(frozen=True, slots=True)
class DirectStackMovePretestInitializerStats8616:
    """Closed evidence counters for pretest-loop initializer placement."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    already_materialized_count: int
    refused_no_evidence_count: int
    refused_no_site_count: int
    refused_assignment_count: int
    refused_branch_owner_count: int


def _boundary_field_8616(
    value: object | None,
    name: str,
    default: object | None = None,
) -> object | None:
    """Read an optional field from a heterogeneous angr/Capstone boundary."""
    # Dynamic angr/Capstone boundary: decoded and structured nodes vary by shape.
    return getattr(value, name, default)


def _ordered_instructions_8616(
    project: object,
    function: object,
    reference_addr: int,
) -> tuple[tuple[int, object], ...]:
    """Return deterministic unique Capstone instructions in fact coordinates."""
    instructions: dict[int, object] = {}
    blocks = boundary_tuple_8616(_boundary_field_8616(function, "blocks", ()) or ())
    for block in blocks:
        capstone = _boundary_field_8616(block, "capstone")
        wrapped_instructions = boundary_tuple_8616(
            _boundary_field_8616(capstone, "insns", ()) or ()
        )
        for wrapped in wrapped_instructions:
            instruction = _boundary_field_8616(wrapped, "insn", wrapped)
            address = _boundary_field_8616(instruction, "address")
            if not isinstance(address, int):
                continue
            comparable = comparable_address_8616(project, address, reference_addr)
            instructions.setdefault(comparable, instruction)
    return tuple(sorted(instructions.items()))


def _jump_target_8616(instruction: object) -> int | None:
    """Return one direct jump target from a decoded Capstone instruction."""
    groups = frozenset(
        group
        for group in boundary_tuple_8616(
            _boundary_field_8616(instruction, "groups", ()) or ()
        )
        if isinstance(group, int)
    )
    operands = boundary_tuple_8616(
        _boundary_field_8616(instruction, "operands", ()) or ()
    )
    if CS_GRP_JUMP not in groups or len(operands) != 1:
        return None
    operand = operands[0]
    target = _boundary_field_8616(operand, "imm")
    return (
        target
        if _boundary_field_8616(operand, "type") == X86_OP_IMM
        and isinstance(target, int)
        else None
    )


def pretest_initializer_evidence_8616(
    project: object,
    function: object,
    move_addr: int,
) -> tuple[DirectStackMovePretestInitializerEvidence8616, ...]:
    """Recover exact one-time initializer jumps leading to pretest loops."""
    instructions = _ordered_instructions_8616(project, function, move_addr)
    move_indexes = tuple(
        index for index, (address, _instruction) in enumerate(instructions) if address == move_addr
    )
    if len(move_indexes) != 1 or move_indexes[0] + 1 >= len(instructions):
        return ()
    entry_jump_addr, entry_jump = instructions[move_indexes[0] + 1]
    condition_target = _jump_target_8616(entry_jump)
    if (
        _boundary_field_8616(entry_jump, "id") != X86_INS_JMP
        or not isinstance(condition_target, int)
    ):
        return ()
    condition_entry_addr = comparable_address_8616(
        project,
        condition_target,
        move_addr,
    )
    if condition_entry_addr <= entry_jump_addr:
        return ()

    evidence: list[DirectStackMovePretestInitializerEvidence8616] = []
    for backedge_addr, backedge in instructions:
        target = _jump_target_8616(backedge)
        if (
            _boundary_field_8616(backedge, "id") != X86_INS_JMP
            or not isinstance(target, int)
            or backedge_addr <= condition_entry_addr
        ):
            continue
        iterator_entry_addr = comparable_address_8616(project, target, move_addr)
        if not (entry_jump_addr < iterator_entry_addr <= condition_entry_addr):
            continue
        condition_branches = tuple(
            address
            for address, instruction in instructions
            if condition_entry_addr <= address < backedge_addr
            and _boundary_field_8616(instruction, "id") != X86_INS_JMP
            and _jump_target_8616(instruction) is not None
        )
        if not condition_branches:
            continue
        evidence.append(
            DirectStackMovePretestInitializerEvidence8616(
                move_addr=move_addr,
                entry_jump_addr=entry_jump_addr,
                condition_entry_addr=condition_entry_addr,
                condition_branch_addrs=condition_branches,
                iterator_entry_addr=iterator_entry_addr,
                backedge_addr=backedge_addr,
            )
        )
    return tuple(dict.fromkeys(evidence))


def _pretest_initializer_sites_8616(
    project: object,
    codegen: object,
    root: object,
    evidence: DirectStackMovePretestInitializerEvidence8616,
    dst_offset: int,
) -> tuple[DirectStackMovePretestInitializerSite8616, ...]:
    """Find the unique structured pretest loop owned by machine evidence."""
    sites: list[DirectStackMovePretestInitializerSite8616] = []
    seen: set[int] = set()

    def visit(node: object, depth: int) -> None:
        """Visit each owned statement list and correlate its pretest loops."""
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = _boundary_field_8616(node, "statements")
        if isinstance(statements, list):
            for statement in tuple(statements):
                if isinstance(statement, (structured_c.CForLoop, structured_c.CWhileLoop)):
                    surface = pretest_condition_surface_8616(statement)
                    body = statement.body
                    condition_addresses = {
                        comparable_address_8616(project, address, evidence.move_addr)
                        for condition in surface.conditions
                        for address in _tree_tag_addresses_8616(condition)
                    }
                    body_addresses = {
                        comparable_address_8616(project, address, evidence.move_addr)
                        for address in _tree_tag_addresses_8616(body)
                    }
                    owns_condition = any(
                        evidence.condition_entry_addr
                        <= address
                        <= max(evidence.condition_branch_addrs)
                        for address in condition_addresses
                    )
                    owns_body = any(
                        branch_addr < address < evidence.backedge_addr
                        for branch_addr in evidence.condition_branch_addrs
                        for address in body_addresses
                    )
                    if (
                        owns_condition
                        and owns_body
                        and any(
                            _tree_reads_stack_offset_8616(codegen, condition, dst_offset)
                            for condition in surface.conditions
                        )
                    ):
                        sites.append(
                            DirectStackMovePretestInitializerSite8616(
                                statements=statements,
                                loop=statement,
                                depth=depth,
                            )
                        )
                visit(statement, depth + 1)
        for attr in ("body", "else_node"):
            child = _boundary_field_8616(node, attr)
            if child is not None:
                visit(child, depth + 1)
        pairs = _boundary_field_8616(node, "condition_and_nodes")
        if pairs:
            for _condition, guarded_body in boundary_tuple_8616(pairs):
                visit(guarded_body, depth + 1)

    visit(root, 0)
    return tuple(sites)


def place_direct_stack_move_pretest_initializer_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
) -> bool:
    """Place one Lowering-built assignment at its proven pretest-loop scope."""
    if move_fact.ins_addr in direct_stack_move_branch_owned_addresses_8616(
        project,
        codegen,
        function,
    ):
        return False
    codegen_contract = cast(Any, codegen)
    try:
        root = codegen_contract.cfunc.statements
    except AttributeError:
        return False
    evidence = pretest_initializer_evidence_8616(
        project,
        function,
        move_fact.ins_addr,
    )
    sites = (
        _pretest_initializer_sites_8616(
            project,
            codegen,
            root,
            evidence[0],
            move_fact.dst_offset,
        )
        if root is not None and len(evidence) == 1
        else ()
    )
    locations = (
        tagged_assignment_locations_8616(project, codegen, root, move_fact)
        if root is not None
        else ()
    )
    if len(evidence) != 1 or len(sites) != 1 or len(locations) > 1:
        return False
    location = locations[0] if locations else None
    owned_assignment = location.assignment if location is not None else assignment
    placed, _already = _place_pretest_initializer_8616(
        sites[0],
        owned_assignment,
        location,
    )
    return placed


def materialize_direct_stack_move_pretest_initializers_8616(
    project: object,
    codegen: object,
    function: object,
) -> bool:
    """Relocate tagged direct-stack assignments to proven pretest-loop scope."""
    codegen_contract = cast(Any, codegen)
    try:
        root = codegen_contract.cfunc.statements
        raw_facts = codegen_contract._inertia_direct_stack_move_facts_8616
    except AttributeError:
        return False
    facts = tuple(
        fact
        for fact in boundary_tuple_8616(raw_facts or ())
        if isinstance(fact, DirectStackMoveFact8616)
    )
    normalized = 0
    classified = 0
    materialized = 0
    failures = 0
    already_materialized = 0
    refused_no_evidence = 0
    refused_no_site = 0
    refused_assignment = 0
    refused_branch_owner = 0
    changed = False
    branch_owned = direct_stack_move_branch_owned_addresses_8616(
        project,
        codegen,
        function,
    )
    debug = bool(
        os.environ.get("INERTIA_DEBUG_STACK_PRETEST_INIT")
        or os.environ.get("INERTIA_DEBUG_STACK_NOISE")
    )
    for fact in sorted(facts, key=lambda candidate: candidate.ins_addr):
        if fact.ins_addr in branch_owned:
            refused_branch_owner += 1
            continue
        evidence = pretest_initializer_evidence_8616(project, function, fact.ins_addr)
        if not evidence:
            refused_no_evidence += 1
            continue
        normalized += 1
        if len(evidence) != 1 or root is None:
            failures += 1
            continue
        sites = _pretest_initializer_sites_8616(
            project,
            codegen,
            root,
            evidence[0],
            fact.dst_offset,
        )
        if len(sites) != 1:
            refused_no_site += 1
            failures += int(len(sites) > 1)
            continue
        locations = tagged_assignment_locations_8616(project, codegen, root, fact)
        if len(locations) != 1:
            refused_assignment += 1
            failures += int(len(locations) > 1)
            continue
        classified += 1
        placed, already = _place_pretest_initializer_8616(
            sites[0],
            locations[0].assignment,
            locations[0],
        )
        if not placed:
            failures += 1
            continue
        materialized += 1
        already_materialized += int(already)
        changed = changed or not already
    stats = DirectStackMovePretestInitializerStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
        already_materialized_count=already_materialized,
        refused_no_evidence_count=refused_no_evidence,
        refused_no_site_count=refused_no_site,
        refused_assignment_count=refused_assignment,
        refused_branch_owner_count=refused_branch_owner,
    )
    codegen_contract._inertia_direct_stack_move_pretest_initializer_placement_8616 = stats
    if debug:
        log.warning("[direct-stack-move-pretest-init] stats=%r", stats)
    if classified > materialized:
        raise RuntimeError(
            "classified direct-stack pretest initializers were not fully materialized"
        )
    return changed
