# cython: language_level=3, infer_types=True
"""Keep binary-proven stack moves inside their owning structured branch.

Layer: Structuring.
Responsibility: join typed direct-stack-move facts to ConditionIR/CFG evidence
and preserve the proven branch owner when angr regenerates the structured C AST.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

Lowering owns the value and destination of a direct stack move. It must not
decide whether that write belongs inside an ``if`` arm. This module owns that
control-flow placement and refuses ambiguous condition, jump-target, AST, or
assignment joins. Rewrite and postprocess may replay this service after AST
regeneration, but they must not infer or alter branch ownership themselves.

Dynamic boundary: angr structured-C nodes, codegen objects, Capstone
instructions, and function block inventories expose version-dependent
attributes. Dynamic access below is restricted to those third-party surfaces.
"""

from __future__ import annotations
import typing
import cython

import contextlib
import logging
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable
from capstone.x86_const import X86_OP_IMM

from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from inertia.lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616
from inertia.pipeline.errors import PipelineHardError

from .condition_replay import (
    StructuringConditionReplayFact8616,
    condition_replay_facts_8616,
)
import dataclasses
import operator
import builtins

log: logging.Logger = logging.getLogger(__name__)


class DirectStackMoveBranchArm8616(Enum):
    """A structured branch arm proven to execute one direct stack move."""

    TAKEN = "taken"


@dataclasses.dataclass(frozen=True, )
class DirectStackMoveBranchFact8616:
    """Typed join between one stack move and one machine branch."""

    move_ins_addr: cython.longlong
    condition_ins_addr: cython.longlong
    condition_producer_insn: int | None
    arm: DirectStackMoveBranchArm8616
    arm_start: cython.longlong
    merge_addr: cython.longlong


@dataclasses.dataclass(frozen=True, )
class DirectStackMoveBranchStats8616:
    """Closed evidence counters for one branch-placement replay."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    already_materialized_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class _DirectStackMovePlacementSite8616:
    """One mutable statement sequence and its machine-taken suffix start."""

    statements: object
    start_index: cython.longlong
    bounded_owner: cython.bint


_BRANCH_OWNED_SOURCE_KINDS_8616 = frozenset(
    {
        DirectStackMoveSourceKind8616.IMMEDIATE,
        DirectStackMoveSourceKind8616.STACK_SLOT,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
    }
)


@cython.ccall
def _boundary_tuple_8616(value: object) -> tuple[Any, ...]:
    """Convert one dynamic angr collection to a stable tuple."""
    return tuple(cast(Iterable[Any], value))


@cython.ccall
def _candidate_addresses_8616(project: object, address: cython.longlong) -> frozenset[cython.longlong]:
    """Return current/original address-domain candidates for one instruction."""
    delta: object
    candidates = {address}
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and delta:
        candidates.update((address + delta, address - delta))
    return frozenset(candidates)


@cython.ccall
def direct_stack_move_instruction_targets_8616(
    project: object,
    function: object,
    conditions: Iterable[ConditionIR],
) -> object:
    """Return exact immediate targets for decoded function instructions."""
    address: object
    capstone: object
    factory: object
    insn: object
    local_blocks: object
    block: object
    condition: object
    wrapper: object
    result: dict[cython.longlong, cython.longlong] = {}
    blocks = _boundary_tuple_8616(getattr(function, "blocks", ()) or ())
    local_blocks = getattr(function, "_local_blocks", None)
    if isinstance(local_blocks, dict) and local_blocks:
        blocks = tuple(local_blocks.values())
    for block in blocks:
        capstone = getattr(block, "capstone", None)
        for wrapper in _boundary_tuple_8616(getattr(capstone, "insns", ()) or ()):
            insn = getattr(wrapper, "insn", wrapper)
            address = getattr(insn, "address", None)
            operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
            if (
                isinstance(address, int)
                and len(operands) == 1
                and operator.eq(getattr(operands[0], "type", None), X86_OP_IMM)
                and isinstance(getattr(operands[0], "imm", None), int)
            ):
                result[address] = int(operands[0].imm)
    factory = getattr(project, "factory", None)
    for condition in conditions:
        fallthrough = condition.fallthrough_target
        if not isinstance(fallthrough, int) or fallthrough in result or factory is None:
            continue
        with contextlib.suppress(Exception):
            block = factory.block(fallthrough, num_inst=1, opt_level=0)
            wrappers = _boundary_tuple_8616(
                getattr(getattr(block, "capstone", None), "insns", ()) or ()
            )
            if not wrappers:
                continue
            insn = getattr(wrappers[0], "insn", wrappers[0])
            operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
            if (
                operator.eq(getattr(insn, "address", None), fallthrough)
                and len(operands) == 1
                and operator.eq(getattr(operands[0], "type", None), X86_OP_IMM)
                and isinstance(getattr(operands[0], "imm", None), int)
            ):
                result[fallthrough] = int(operands[0].imm)
    return result


def recover_direct_stack_move_branch_facts_8616(
    conditions: Iterable[ConditionIR],
    move_facts: Iterable[DirectStackMoveFact8616],
    instruction_targets: object,
) -> tuple[DirectStackMoveBranchFact8616, ...]:
    """Recover unique taken-arm ownership from ConditionIR and exact jumps.

    The accepted machine shape is a conditional jump to the body followed by
    an unconditional jump to the merge. This is sufficient to prove the body
    interval without source, names, rendered C, or address-specific rules.
    """
    merge_addr: object
    condition: object
    move: object
    recovered: list[DirectStackMoveBranchFact8616] = []
    for move in move_facts:
        if move.source_kind not in _BRANCH_OWNED_SOURCE_KINDS_8616:
            continue
        candidates: list[DirectStackMoveBranchFact8616] = []
        for condition in conditions:
            condition_addr = condition.src_insn
            arm_start = condition.taken_target
            fallthrough = condition.fallthrough_target
            if (
                not isinstance(condition_addr, int)
                or not isinstance(arm_start, int)
                or not isinstance(fallthrough, int)
            ):
                continue
            merge_addr = instruction_targets.get(fallthrough)
            if not isinstance(merge_addr, int):
                continue
            if arm_start <= move.ins_addr < merge_addr:
                candidates.append(
                    DirectStackMoveBranchFact8616(
                        move_ins_addr=move.ins_addr,
                        condition_ins_addr=condition_addr,
                        condition_producer_insn=condition.producer_insn,
                        arm=DirectStackMoveBranchArm8616.TAKEN,
                        arm_start=arm_start,
                        merge_addr=merge_addr,
                    )
                )
        if not candidates:
            continue
        smallest_span = min(candidate.merge_addr - candidate.arm_start for candidate in iter(candidates))
        innermost = tuple(
            candidate
            for candidate in iter(candidates)
            if operator.eq(candidate.merge_addr - candidate.arm_start, smallest_span)
        )
        if len(innermost) == 1:
            recovered.append(innermost[0])
    return tuple(recovered)


def _node_tag_addresses_8616(node: object) -> frozenset[cython.longlong]:
    """Return instruction-origin addresses attached to one angr C node."""
    tags: object
    tags = getattr(node, "tags", None)
    if not isinstance(tags, dict):
        return frozenset()
    return frozenset(
        value
        for value in iter((
            tags.get("ins_addr"),
            tags.get("inertia_relocated_from_ins_addr"),
        ))
        if isinstance(value, int)
    )


def _tree_nodes_8616(root: object) -> Iterator[object]:
    """Yield each node in one dynamic angr structured-expression tree once."""
    child: object
    children: object
    node: object
    pairs: object
    attribute: object
    body: object
    condition: object
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
        yield node
        for attribute in (
            "lhs",
            "rhs",
            "operand",
            "expr",
            "condition",
            "cond",
            "body",
            "else_node",
            "statements",
            "initializer",
            "iterator",
        ):
            child = getattr(node, attribute, None)
            if child is not None:
                stack.append(child)
        for attribute in ("args", "operands"):
            children = getattr(node, attribute, None)
            if children:
                stack.extend(_boundary_tuple_8616(children))
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for condition, body in _boundary_tuple_8616(pairs):
                stack.extend((condition, body))


@cython.ccall
def _tree_tag_addresses_8616(root: object) -> frozenset[cython.longlong]:
    """Collect instruction-origin tags from one structured expression tree."""
    node: object
    addresses: set[cython.longlong] = set()
    for node in _tree_nodes_8616(root):
        addresses.update(_node_tag_addresses_8616(node))
    return frozenset(addresses)


def _statement_lists_8616(root: object) -> tuple[list[Any], ...]:
    """Return all mutable statement lists below one structured-C root."""
    result: list[list[Any]] = []
    seen: set[cython.longlong] = set()

    def visit(node: object) -> None:
        pairs: object
        statements: object
        _condition: object
        attribute: object
        body: object
        statement: object
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            result.append(statements)
            for statement in tuple(statements):
                visit(statement)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in _boundary_tuple_8616(pairs):
                visit(body)
        for attribute in ("body", "else_node"):
            visit(getattr(node, attribute, None))

    visit(root)
    return tuple(result)


@cython.ccall
def _stack_variable_offset_8616(codegen: object, node: object) -> int | None:
    """Return the canonical BP-relative offset of one typed C variable."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimStackVariable) or variable.base != "bp":
        return None
    offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    if not isinstance(offset, int):
        return None
    return offset - 0x10000 if offset >= 0x8000 else offset


@cython.ccall
def _indexed_stack_offsets_8616(codegen: object, node: object) -> object:
    """Return the base and index BP offsets of one typed indexed stack access."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    if not isinstance(node, structured_c.CIndexedVariable):
        return None
    base_offset = _stack_variable_offset_8616(codegen, node.variable)
    index_offset = _stack_variable_offset_8616(codegen, node.index)
    if not isinstance(base_offset, int) or not isinstance(index_offset, int):
        return None
    return base_offset, index_offset


@cython.ccall
def _assignment_destination_matches_stack_move_fact_8616(
    codegen: object,
    assignment: object,
    move_fact: DirectStackMoveFact8616,
) -> cython.bint:
    """Return whether an assignment writes the fact's exact stack object."""
    if not isinstance(assignment, structured_c.CAssignment):
        return False
    if isinstance(move_fact.dst_index_stack_offset, int):
        return operator.eq(_indexed_stack_offsets_8616(codegen, assignment.lhs), (
            move_fact.dst_offset,
            move_fact.dst_index_stack_offset,
        ))
    return bool(operator.eq(_stack_variable_offset_8616(codegen, assignment.lhs), move_fact.dst_offset))


@cython.ccall
def _assignment_matches_stack_move_fact_8616(
    codegen: object,
    assignment: object,
    fact: DirectStackMoveBranchFact8616,
    move_fact: DirectStackMoveFact8616,
) -> cython.bint:
    """Join a tagless typed assignment to one exact stack-store fact."""
    if (
        not isinstance(assignment, structured_c.CAssignment)
        or operator.ne(fact.move_ins_addr, move_fact.ins_addr)
        or not _assignment_destination_matches_stack_move_fact_8616(
            codegen,
            assignment,
            move_fact,
        )
    ):
        return False
    if move_fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT:
        return isinstance(move_fact.source_offset, int) and operator.eq(_stack_variable_offset_8616(codegen, assignment.rhs), move_fact.source_offset)
    if move_fact.source_kind is DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT:
        return (
            isinstance(move_fact.source_aggregate_base_offset, int)
            and isinstance(move_fact.source_index_offset, int)
            and operator.eq(_indexed_stack_offsets_8616(codegen, assignment.rhs), (
                move_fact.source_aggregate_base_offset,
                move_fact.source_index_offset,
            ))
        )
    return bool(
        move_fact.source_kind is DirectStackMoveSourceKind8616.IMMEDIATE
        and isinstance(move_fact.source_value, int)
        and isinstance(assignment.rhs, structured_c.CConstant)
        and isinstance(assignment.rhs.value, int)
        and operator.eq((assignment.rhs.value & ((1 << (move_fact.width * 8)) - 1)), move_fact.source_value)
    )


@cython.dataclasses.dataclass()
class _BranchSiteScan8616:
    """Placement-site scan state for one stack-move branch fact."""

    project: object
    fact: DirectStackMoveBranchFact8616
    replay_facts: object
    candidates: object = field(default_factory=list)
    seen: object = field(default_factory=set)
    move_addresses: object = field(init=False)

    def __post_init__(self) -> None:
        """Cache the candidate addresses of the move instruction."""
        self.move_addresses = _candidate_addresses_8616(
            self.project, self.fact.move_ins_addr
        )

    @cython.ccall
    def _branch_addresses_8616(self) -> object:
        """Return candidate addresses of the condition and its producer."""
        addresses = set(
            _candidate_addresses_8616(self.project, self.fact.condition_ins_addr)
        )
        if isinstance(self.fact.condition_producer_insn, int):
            addresses.update(
                _candidate_addresses_8616(
                    self.project, self.fact.condition_producer_insn
                )
            )
        return addresses

    def has_taken_provenance(self, nodes: object) -> cython.bint:
        """Return whether nodes own non-target instructions in the taken interval."""
        address: object
        for address in _tree_tag_addresses_8616(nodes):
            candidates_for_address = _candidate_addresses_8616(self.project, address)
            if candidates_for_address & self.move_addresses:
                continue
            if any(
                self.fact.arm_start <= candidate < self.fact.merge_addr
                for candidate in iter(candidates_for_address)
            ):
                return True
        return False

    def _replay_arm_8616(self, body: object, else_node: object) -> object:
        """Recover the taken arm from a unique matching replay fact."""
        replay_arm: object
        matching_replays = tuple(
            replay
            for replay in iter(self.replay_facts)
            if operator.eq(replay.root_src_insn, self.fact.condition_ins_addr)
        )
        if len(matching_replays) != 1:
            return []
        replay = matching_replays[0]
        true_is_taken = self.fact.arm_start <= replay.true_target < self.fact.merge_addr
        false_is_taken = (
            self.fact.arm_start <= replay.false_target < self.fact.merge_addr
        )
        if true_is_taken == false_is_taken:
            return []
        replay_arm = body if true_is_taken else else_node
        return [] if replay_arm is None else [replay_arm]

    @cython.ccall
    def _loop_site_8616(self, node: object) -> None:
        """Record a taken loop body as a bounded placement site."""
        body_statements: object
        if not isinstance(node, (structured_c.CForLoop, structured_c.CWhileLoop)):
            return
        condition = node.condition
        body_statements = getattr(node.body, "statements", None)
        if (
            _tree_tag_addresses_8616(condition) & self._branch_addresses_8616()
            and self.has_taken_provenance(node.body)
            and isinstance(body_statements, list)
        ):
            self.candidates.append(
                _DirectStackMovePlacementSite8616(body_statements, 0, True)
            )

    @cython.ccall
    def _pair_site_8616(
        self,
        node: object,
        condition: object,
        body: object,
        owner: object,
        owner_index: int | None,
    ) -> None:
        """Record a taken if/else arm or proven guarded fallthrough site."""
        arm_statements: object
        else_node: object
        addresses = _tree_tag_addresses_8616(condition)
        if not (addresses & self._branch_addresses_8616()):
            return
        arms = [body]
        else_node = getattr(node, "else_node", None)
        if else_node is not None:
            arms.append(else_node)
        proven_arms = [arm for arm in iter(arms) if self.has_taken_provenance(arm)]
        if not proven_arms:
            proven_arms = self._replay_arm_8616(body, else_node)
        if len(proven_arms) == 1:
            arm_statements = getattr(proven_arms[0], "statements", None)
            if isinstance(arm_statements, list):
                self.candidates.append(
                    _DirectStackMovePlacementSite8616(arm_statements, 0, True)
                )
        elif (
            not proven_arms
            and owner is not None
            and isinstance(owner_index, int)
        ):
            start_index = owner_index + 1
            if self.has_taken_provenance(owner[start_index:]):
                self.candidates.append(
                    _DirectStackMovePlacementSite8616(owner, start_index, False)
                )

    @cython.ccall
    def visit(
        self,
        node: object,
        owner: object = None,
        owner_index: int | None = None,
    ) -> None:
        """Walk one structured node, recording proven placement sites."""
        pairs: object
        statements: object
        attribute: object
        body: object
        condition: object
        index: object
        statement: object
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        self._loop_site_8616(node)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for condition, body in _boundary_tuple_8616(pairs):
                self._pair_site_8616(node, condition, body, owner, owner_index)
                self.visit(body)
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for index, statement in enumerate(tuple(statements)):
                self.visit(statement, statements, index)
        for attribute in ("body", "else_node"):
            self.visit(getattr(node, attribute, None))


@cython.ccall
def _condition_branch_site_8616(
    root: object,
    project: object,
    fact: DirectStackMoveBranchFact8616,
    replay_facts: object,
) -> _DirectStackMovePlacementSite8616 | None:
    """Find the unique rendered arm or guarded fallthrough for a taken range."""
    scan = _BranchSiteScan8616(project, fact, replay_facts)
    scan.visit(root)
    unique = {
        (id(candidate.statements), candidate.start_index): candidate
        for candidate in iter(scan.candidates)
    }
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE") and len(unique) != 1:
        log.warning(
            "[direct-stack-move-branch-site] condition=%#x candidates=%d replays=%r",
            fact.condition_ins_addr,
            len(unique),
            replay_facts,
        )
    return next(iter(unique.values())) if len(unique) == 1 else None


def _arm_statement_addresses_8616(
    statement: object,
    project: object,
    fact: DirectStackMoveBranchFact8616,
) -> tuple[list[cython.longlong], list[cython.longlong]]:
    """Return tagged and in-range non-move candidate addresses for one statement."""
    tagged_addresses = sorted(
        candidate
        for tagged_addr in builtins.iter(_tree_tag_addresses_8616(statement))
        for candidate in builtins.iter(_candidate_addresses_8616(project, tagged_addr))
    )
    addresses = [
        candidate
        for candidate in iter(tagged_addresses)
        if fact.arm_start <= candidate < fact.merge_addr
        and operator.ne(candidate, fact.move_ins_addr)
    ]
    return tagged_addresses, addresses


@cython.dataclasses.dataclass()
class _ArmInsertionScan8616:
    """Ordered insertion-index scan state within one proven arm."""

    project: object
    fact: DirectStackMoveBranchFact8616
    insertion_index: int | None = None
    saw_after: cython.bint = False

    @cython.ccall
    def rejects(self, index: cython.longlong, statement: object) -> cython.bint:
        """Advance one statement; return True when the arm order is ambiguous."""
        tagged_addresses, addresses = _arm_statement_addresses_8616(
            statement, self.project, self.fact
        )
        move_addr = self.fact.move_ins_addr
        if not addresses:
            if _empty_statement_wrapper_8616(statement):
                return False
            if tagged_addresses and min(tagged_addresses) >= self.fact.merge_addr:
                self._mark_after(index)
                return False
            return True
        if addresses[0] < move_addr < addresses[-1]:
            return True
        if addresses[-1] < move_addr:
            return self.saw_after
        if addresses[0] > move_addr:
            self._mark_after(index)
            return False
        return True

    @cython.ccall
    def _mark_after(self, index: cython.longlong) -> None:
        """Record that following statements start after the move."""
        self.saw_after = True
        if self.insertion_index is None:
            self.insertion_index = index


@cython.ccall
def _ordered_arm_insertion_index_8616(
    statements: Iterable[object],
    project: object,
    fact: DirectStackMoveBranchFact8616,
) -> int | None:
    """Return the unique instruction-ordered insertion index within one arm."""
    index: object
    statement: object
    ordered_statements = tuple(statements)
    scan = _ArmInsertionScan8616(project, fact)
    for index, statement in enumerate(ordered_statements):
        if scan.rejects(index, statement):
            return None
    return (
        len(ordered_statements)
        if scan.insertion_index is None
        else scan.insertion_index
    )


def _empty_statement_wrapper_8616(node: object) -> cython.bint:
    """Return whether an angr statement wrapper is recursively empty."""
    if not isinstance(node, structured_c.CStatements):
        return False
    return all(_empty_statement_wrapper_8616(statement) for statement in iter(node.statements))


def _site_suffix_owns_assignment_8616(
    site: _DirectStackMovePlacementSite8616,
    assignment: structured_c.CAssignment,
) -> cython.bint:
    """Return whether a proven arm suffix recursively contains an assignment."""
    return any(
        node is assignment
        for statement in iter(site.statements[site.start_index :])
        for node in builtins.iter(_tree_nodes_8616(statement))
    )


def place_direct_stack_move_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
) -> cython.bint:
    """Place one Lowering-built assignment at its unique CFG-proven site."""
    cfunc: object
    placement_site: object
    relative_index: object
    conditions = tuple(
        condition
        for condition in builtins.iter(_boundary_tuple_8616(
            getattr(codegen, "_inertia_typed_conditions", ()) or ()
        ))
        if isinstance(condition, ConditionIR)
    )
    branch_facts = recover_direct_stack_move_branch_facts_8616(
        conditions,
        (move_fact,),
        direct_stack_move_instruction_targets_8616(project, function, conditions),
    )
    if len(branch_facts) != 1:
        return False
    fact = branch_facts[0]
    cfunc = getattr(codegen, "cfunc", None)
    placement_site = _condition_branch_site_8616(
        root=getattr(cfunc, "statements", None),
        project=project,
        fact=fact,
        replay_facts=condition_replay_facts_8616(codegen),
    )
    if placement_site is None:
        return False
    target_statements = placement_site.statements
    relative_index = _ordered_arm_insertion_index_8616(
        target_statements[placement_site.start_index :],
        project,
        fact,
    )
    if relative_index is None:
        return False
    target_statements.insert(placement_site.start_index + relative_index, assignment)
    return True


@cython.ccall
def _transparent_assignment_8616(statement: object) -> structured_c.CAssignment | None:
    """Return an assignment through angr's transparent statement wrapper."""
    if isinstance(statement, structured_c.CExpressionStatement):
        statement = statement.expr
    return statement if isinstance(statement, structured_c.CAssignment) else None


class _BranchPlacementOutcome8616(Enum):
    """Per-fact placement outcome for the materialize stats contract."""

    FAILURE = "failure"
    ALREADY_MATERIALIZED = "already_materialized"
    MATERIALIZED = "materialized"


@cython.ccall
def _tagged_fact_locations_8616(
    root: object,
    codegen: object,
    move_fact: DirectStackMoveFact8616,
    candidate_addrs: object,
) -> list[tuple[list[Any], cython.longlong, object]]:
    """Return rendered assignment locations proven by move-instruction tags."""
    return [
        (statements, index, statement)
        for statements in builtins.iter(_statement_lists_8616(root))
        for index, statement in builtins.iter(enumerate(tuple(statements)))
        if (
            (assignment := _transparent_assignment_8616(statement))
            is not None
            and _assignment_destination_matches_stack_move_fact_8616(
                codegen,
                assignment,
                move_fact,
            )
            and bool(_tree_tag_addresses_8616(statement) & candidate_addrs)
            )
        ]


@cython.ccall
def _joined_fact_locations_8616(
    root: object,
    codegen: object,
    move_fact: DirectStackMoveFact8616,
    fact: DirectStackMoveBranchFact8616,
) -> list[tuple[list[Any], cython.longlong, object]]:
    """Return rendered assignment locations joined by exact shape evidence."""
    return [
        (statements, index, statement)
        for statements in builtins.iter(_statement_lists_8616(root))
        for index, statement in builtins.iter(enumerate(tuple(statements)))
        if (
            (assignment := _transparent_assignment_8616(statement))
            is not None
            and _assignment_matches_stack_move_fact_8616(
                codegen,
                assignment,
                fact,
                move_fact,
            )
        )
    ]


def _detached_tagged_assignments_8616(
    root: object,
    codegen: object,
    move_fact: DirectStackMoveFact8616,
    candidate_addrs: object,
) -> tuple[structured_c.CAssignment, ...]:
    """Return proven tagged assignments no statement list still owns."""
    return tuple(
        assignment
        for node in builtins.iter(_tree_nodes_8616(root))
        if (assignment := _transparent_assignment_8616(node)) is not None
        and _assignment_destination_matches_stack_move_fact_8616(
            codegen,
            assignment,
            move_fact,
        )
        and bool(_tree_tag_addresses_8616(node) & candidate_addrs)
        and all(assignment is not statement for statements in builtins.iter(_statement_lists_8616(root)) for statement in iter(statements))
    )


@cython.ccall
def _insert_assignment_8616(
    owner: object,
    index: cython.longlong,
    assignment: object,
    target_statements: object,
    insertion_index: cython.longlong,
    fact: DirectStackMoveBranchFact8616,
) -> None:
    """Move one rendered assignment into its proven arm insertion slot."""
    del owner[index]
    if owner is target_statements and index < insertion_index:
        insertion_index -= 1
    target_statements.insert(insertion_index, assignment)
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[direct-stack-move-branch] moved move=%#x assignment=%r target=%r",
            fact.move_ins_addr,
            assignment,
            target_statements,
        )


@cython.ccall
def _place_branch_fact_8616(
    fact: DirectStackMoveBranchFact8616,
    move_fact: DirectStackMoveFact8616,
    placement_site: _DirectStackMovePlacementSite8616,
    root: object,
    project: object,
    codegen: object,
) -> _BranchPlacementOutcome8616:
    """Relocate one branch fact's assignment into its proven arm."""
    target_statements = placement_site.statements
    candidate_addrs = _candidate_addresses_8616(project, fact.move_ins_addr)
    locations = _tagged_fact_locations_8616(root, codegen, move_fact, candidate_addrs)
    detached_tagged = _detached_tagged_assignments_8616(
        root, codegen, move_fact, candidate_addrs,
    )
    if not locations and len(detached_tagged) == 1:
        return _BranchPlacementOutcome8616.ALREADY_MATERIALIZED
    if not locations:
        locations = _joined_fact_locations_8616(root, codegen, move_fact, fact)
    if len(locations) != 1:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-move-branch] assignment-count move=%#x count=%d move_fact=%r",
                fact.move_ins_addr,
                len(locations),
                move_fact,
            )
        return _BranchPlacementOutcome8616.FAILURE
    owner, index, assignment = locations[0]
    if (
        owner is target_statements
        and index >= placement_site.start_index
        and placement_site.bounded_owner
    ):
        return _BranchPlacementOutcome8616.ALREADY_MATERIALIZED
    if owner is not target_statements and _site_suffix_owns_assignment_8616(
        placement_site,
        assignment,
    ):
        return _BranchPlacementOutcome8616.ALREADY_MATERIALIZED
    return _relocate_proven_assignment_8616(
        fact, placement_site, owner, index, assignment, project,
    )


def _relocate_proven_assignment_8616(
    fact: DirectStackMoveBranchFact8616,
    placement_site: _DirectStackMovePlacementSite8616,
    owner: object,
    index: cython.longlong,
    assignment: object,
    project: object,
) -> _BranchPlacementOutcome8616:
    """Insert one proven assignment at its ordered arm index."""
    relative_insertion_index: object
    target_statements = placement_site.statements
    ordered_target = tuple(
        statement
        for statement in iter(target_statements[placement_site.start_index :])
        if statement is not assignment
    )
    relative_insertion_index = _ordered_arm_insertion_index_8616(
        ordered_target,
        project,
        fact,
    )
    if relative_insertion_index is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-move-branch] insertion-refused move=%#x owner_is_target=%s "
                "index=%d start=%d assignment_tags=%r target_tags=%r",
                fact.move_ins_addr,
                owner is target_statements,
                index,
                placement_site.start_index,
                getattr(assignment, "tags", None),
                tuple(_tree_tag_addresses_8616(statement) for statement in iter(target_statements)),
            )
        return _BranchPlacementOutcome8616.FAILURE
    insertion_index = placement_site.start_index + relative_insertion_index
    if owner is target_statements and index == insertion_index:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-move-branch] already move=%#x assignment=%r target=%r",
                fact.move_ins_addr,
                assignment,
                target_statements,
            )
        return _BranchPlacementOutcome8616.ALREADY_MATERIALIZED
    _insert_assignment_8616(
        owner, index, assignment, target_statements, insertion_index, fact,
    )
    return _BranchPlacementOutcome8616.MATERIALIZED


def materialize_direct_stack_move_branch_ownership_8616(
    project: object,
    codegen: object,
    function: object,
) -> cython.bint:
    """Relocate tagged stack assignments into CFG-proven conditional arms."""
    cfunc: object
    placement_site: object
    root: object
    fact: object
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "statements", None)
    conditions = tuple(
        condition
        for condition in builtins.iter(_boundary_tuple_8616(
            getattr(codegen, "_inertia_typed_conditions", ()) or ()
        ))
        if isinstance(condition, ConditionIR)
    )
    move_facts = tuple(
        fact
        for fact in builtins.iter(_boundary_tuple_8616(
            getattr(codegen, "_inertia_direct_stack_move_facts_8616", ()) or ()
        ))
        if isinstance(fact, DirectStackMoveFact8616)
        and fact.source_kind in _BRANCH_OWNED_SOURCE_KINDS_8616
    )
    if root is None or not conditions or not move_facts:
        return False
    branch_facts = recover_direct_stack_move_branch_facts_8616(
        conditions,
        move_facts,
        direct_stack_move_instruction_targets_8616(project, function, conditions),
    )
    changed = False
    classified = 0
    materialized = 0
    already_materialized = 0
    failures = 0
    for fact in branch_facts:
        matching_move_facts = tuple(
            move_fact
            for move_fact in iter(move_facts)
            if operator.eq(move_fact.ins_addr, fact.move_ins_addr)
        )
        if len(matching_move_facts) != 1:
            failures += 1
            continue
        move_fact = matching_move_facts[0]
        placement_site = _condition_branch_site_8616(
            root,
            project,
            fact,
            condition_replay_facts_8616(codegen),
        )
        if placement_site is None:
            failures += 1
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[direct-stack-move-branch] no-target move=%#x condition=%#x producer=%r",
                    fact.move_ins_addr,
                    fact.condition_ins_addr,
                    fact.condition_producer_insn,
                )
            continue
        classified += 1
        outcome = _place_branch_fact_8616(
            fact, move_fact, placement_site, root, project, codegen,
        )
        if outcome is _BranchPlacementOutcome8616.ALREADY_MATERIALIZED:
            already_materialized += 1
            materialized += 1
        elif outcome is _BranchPlacementOutcome8616.MATERIALIZED:
            materialized += 1
            changed = True
        else:
            failures += 1
    stats = DirectStackMoveBranchStats8616(
        raw_fact_count=len(move_facts),
        normalized_fact_count=len(branch_facts),
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
        already_materialized_count=already_materialized,
    )
    cast(Any, codegen)._inertia_direct_stack_move_branch_placement_8616 = stats
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning("[direct-stack-move-branch] stats=%r facts=%r", stats, branch_facts)
    with contextlib.suppress(Exception):
        cfunc.body = root
    with contextlib.suppress(Exception):
        cfunc.statements = root
    with contextlib.suppress(Exception):
        cfunc.stmt = root
    return changed


@cython.ccall
def finalize_direct_stack_move_branch_ownership_8616(
    project: object,
    codegen: object,
    function: object,
) -> cython.bint:
    """Materialize final branch writes and enforce the closed evidence contract."""
    changed = materialize_direct_stack_move_branch_ownership_8616(project, codegen, function)
    try:
        stats = cast(Any, codegen)._inertia_direct_stack_move_branch_placement_8616
    except AttributeError:
        return changed
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified direct stack move branch was not materialized")
    return changed
