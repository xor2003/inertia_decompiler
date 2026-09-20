"""Consume alias-proven terminal far-return CS frame carriers.

Layer: Types/Lowering.
Responsibility: remove the structured CS-restore assignment of one
block-terminal RETF only when Alias, typed IR, and decoded terminal evidence
agree that the assignment is the machine far-return frame pop itself, so the
generated ``return`` owns the frame boundary instead of program-visible frame
reads. Incomplete evidence refuses and keeps every assignment.
Consumes alias facts, IR terminal control flow, and terminal decode evidence.
Do not infer return boundaries from opcodes, assembly text, or rendered C.

Dynamic boundary: third-party angr C-AST statements and codegen attachments
expose version-dependent tags and child containers.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable

from ..alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreVerdict8616,
)
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.vex_control_flow import terminal_ret_instruction_addrs_8616
from ..semantics.terminal_return_contract import TerminalReturnFrameKind8616
from ..semantics.terminal_stack_cleanup import terminal_stack_cleanup_at_address_8616
from ..structured_tags import copy_structured_tags_8616
from .segment_register_state import runtime_segment_name_for_variable_8616

__all__ = [
    "FarReturnBoundaryCarrierStats8616",
    "consume_terminal_far_return_boundary_carriers_8616",
]

_FAR_RETURN_BOUNDARY_RESTORE_REGISTER_8616 = "cs"
_FAR_RETURN_BOUNDARY_OPERAND_BITS_8616 = 16
_FAR_RETURN_BOUNDARY_CLEANUP_8616 = 0


class FarReturnBoundaryRefusal8616(StrEnum):
    """Reason a terminal far-return CS carrier must stay in the AST."""

    NOT_TERMINAL_RET = "not_terminal_ret"
    NOT_FAR_RETURN_FRAME = "not_far_return_frame"
    UNSUPPORTED_WIDTH_OR_CLEANUP = "unsupported_width_or_cleanup"
    CARRIER_ABSENT = "carrier_absent"
    NOT_CS_STATE_CARRIER = "not_cs_state_carrier"


class _FarReturnBoundaryCodegen8616(Protocol):
    """Owned fields consumed and published at the dynamic codegen boundary."""

    cfunc: _FarReturnBoundaryCFunction8616
    _inertia_vex_ir_artifact: object
    _inertia_segment_stack_restore_artifact: SegmentStackRestoreArtifact8616
    _inertia_far_return_boundary_consumed_restores_8616: frozenset[int]
    _inertia_far_return_boundary_carrier_stats_8616: FarReturnBoundaryCarrierStats8616


class _FarReturnBoundaryCFunction8616(Protocol):
    """Owned C-function surface needed by the far-return carrier consumer."""

    statements: object


@dataclass(frozen=True, slots=True)
class FarReturnBoundaryCarrierStats8616:
    """Closed accounting for terminal far-return CS carrier consumption."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    already_materialized_count: int
    failure_count: int
    removed_assignment_count: int
    refusals: tuple[tuple[int, FarReturnBoundaryRefusal8616], ...] = ()

    @property
    def refused_candidate_count(self) -> int:
        """Return candidates retained because boundary evidence is incomplete."""
        return len(self.refusals)

    @property
    def closed(self) -> bool:
        """Return whether every candidate reached one terminal lane."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count + self.refused_candidate_count
            and self.classified_fact_count
            == self.materialized_count + self.already_materialized_count
        )


def _statement_instruction_addr_8616(statement: object) -> int | None:
    """Return one exact structured assignment instruction address."""
    tags = copy_structured_tags_8616(getattr(statement, "tags", None))
    if tags is not None:
        instruction_addr = tags.get("ins_addr")
        if isinstance(instruction_addr, int):
            return instruction_addr
    instruction_addr = getattr(statement, "ins_addr", None)
    return instruction_addr if isinstance(instruction_addr, int) else None


def _statement_lists_8616(root: object) -> tuple[list[object], ...]:
    """Collect mutable statement lists using the shared child schema once."""
    lists = [root] if isinstance(root, list) else []
    roots = tuple(root) if isinstance(root, list) else (root,)
    seen: set[int] = set()
    for candidate in roots:
        lists.extend(
            node.statements
            for node in _iter_c_nodes_deep_8616(candidate, seen)
            if isinstance(node, structured_c.CStatements) and isinstance(node.statements, list)
        )
    return tuple(lists)


def _physical_cs_carrier_8616(variable: object, project: object) -> bool:
    """Return whether one physical register variable is the architectural CS."""
    if not isinstance(variable, SimRegisterVariable) or not isinstance(variable.reg, int):
        return False
    register_names = getattr(getattr(project, "arch", None), "register_names", None)
    register_name = register_names.get(variable.reg) if isinstance(register_names, dict) else None
    return isinstance(register_name, str) and (
        register_name.lower() == _FAR_RETURN_BOUNDARY_RESTORE_REGISTER_8616
    )


def _cs_carrier_lhs_8616(lhs: object, project: object) -> bool:
    """Return whether one assignment LHS carries the architectural CS state."""
    if not isinstance(lhs, structured_c.CVariable):
        return False
    for variable in (lhs.unified_variable, lhs.variable):
        if runtime_segment_name_for_variable_8616(variable) == (
            _FAR_RETURN_BOUNDARY_RESTORE_REGISTER_8616
        ):
            return True
        if _physical_cs_carrier_8616(variable, project):
            return True
    return False


@dataclass(frozen=True, slots=True)
class _FarReturnClassification8616:
    """Terminal decision lanes for every candidate address of one function."""

    refusals: dict[int, FarReturnBoundaryRefusal8616]
    removals_by_addr: dict[int, tuple[structured_c.CAssignment, ...]]
    already: frozenset[int]


def _far_return_candidate_addrs_8616(
    artifact: SegmentStackRestoreArtifact8616,
) -> dict[int, None]:
    """Collect deduplicated far-return candidate restore addresses."""
    candidates: dict[int, None] = {}
    for fact in artifact.facts:
        if (
            fact.restore_register == _FAR_RETURN_BOUNDARY_RESTORE_REGISTER_8616
            and fact.saved_instruction_addr is None
            and fact.verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
        ):
            candidates.setdefault(fact.restore_instruction_addr, None)
    return candidates


def _assignments_by_address_8616(
    statement_lists: tuple[list[object], ...],
) -> dict[int, list[structured_c.CAssignment]]:
    """Index every structured assignment by its exact instruction address."""
    assignments_by_addr: dict[int, list[structured_c.CAssignment]] = {}
    for statements in statement_lists:
        for statement in statements:
            if not isinstance(statement, structured_c.CAssignment):
                continue
            address = _statement_instruction_addr_8616(statement)
            if address is not None:
                assignments_by_addr.setdefault(address, []).append(statement)
    return assignments_by_addr


def _far_return_evidence_refusal_8616(
    project: object,
    address: int,
    terminal_rets: frozenset[int],
) -> FarReturnBoundaryRefusal8616 | None:
    """Refuse when terminal evidence is not a complete 16-bit zero-cleanup far frame."""
    if address not in terminal_rets:
        return FarReturnBoundaryRefusal8616.NOT_TERMINAL_RET
    evidence = terminal_stack_cleanup_at_address_8616(project, address)
    if (
        not evidence.complete
        or evidence.consistent_return_frame_kind is not TerminalReturnFrameKind8616.FAR
    ):
        return FarReturnBoundaryRefusal8616.NOT_FAR_RETURN_FRAME
    if (
        evidence.consistent_return_operand_bits != _FAR_RETURN_BOUNDARY_OPERAND_BITS_8616
        or evidence.consistent_cleanup != _FAR_RETURN_BOUNDARY_CLEANUP_8616
    ):
        return FarReturnBoundaryRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP
    return None


def _classify_far_return_candidates_8616(
    project: object,
    candidates: dict[int, None],
    terminal_rets: frozenset[int],
    assignments_by_addr: dict[int, list[structured_c.CAssignment]],
    typed_prior: frozenset[int],
) -> _FarReturnClassification8616:
    """Send every candidate to exactly one terminal decision lane."""
    refusals: dict[int, FarReturnBoundaryRefusal8616] = {}
    removals_by_addr: dict[int, tuple[structured_c.CAssignment, ...]] = {}
    already: set[int] = set()
    for address in candidates:
        refusal = _far_return_evidence_refusal_8616(project, address, terminal_rets)
        if refusal is not None:
            refusals[address] = refusal
            continue
        assignments = assignments_by_addr.get(address, [])
        if not assignments:
            if address in typed_prior:
                already.add(address)
            else:
                refusals[address] = FarReturnBoundaryRefusal8616.CARRIER_ABSENT
            continue
        cs_assignments = tuple(
            assignment for assignment in assignments if _cs_carrier_lhs_8616(assignment.lhs, project)
        )
        if len(cs_assignments) != len(assignments):
            refusals[address] = FarReturnBoundaryRefusal8616.NOT_CS_STATE_CARRIER
            continue
        removals_by_addr[address] = cs_assignments
    return _FarReturnClassification8616(refusals, removals_by_addr, frozenset(already))


def _remove_proven_cs_carriers_8616(
    statement_lists: tuple[list[object], ...],
    removals_by_addr: dict[int, tuple[structured_c.CAssignment, ...]],
) -> int:
    """Remove proven carriers in place; return how many assignments were removed."""
    removed_assignment_count = 0
    if not removals_by_addr:
        return removed_assignment_count
    removal_ids = {
        id(carrier)
        for carriers in removals_by_addr.values()
        for carrier in carriers
    }
    for statements in statement_lists:
        if not any(id(statement) in removal_ids for statement in statements):
            continue
        kept: list[object] = [
            statement
            for statement in statements
            if id(statement) not in removal_ids
        ]
        removed_assignment_count += len(statements) - len(kept)
        statements[:] = kept
    return removed_assignment_count


def consume_terminal_far_return_boundary_carriers_8616(project: object, codegen: object) -> bool:
    """Remove exact terminal far-return CS carriers proven by complete evidence.

    A candidate is one Alias-refused CS stack restore with no in-function save
    pair: the RETF frame pop itself. It is consumed only when the restore
    instruction is a block-terminal RET, the decoded terminal evidence agrees
    on a 16-bit far return frame with zero immediate cleanup, and the structured
    assignment at that instruction carries exactly the CS state. Anything less
    refuses and keeps the carrier.
    """
    boundary = cast(_FarReturnBoundaryCodegen8616, codegen)
    try:
        artifact = boundary._inertia_segment_stack_restore_artifact
        ir_artifact = boundary._inertia_vex_ir_artifact
        root = boundary.cfunc.statements
    except AttributeError:
        return False
    if not isinstance(artifact, SegmentStackRestoreArtifact8616):
        return False
    candidates = _far_return_candidate_addrs_8616(artifact)
    terminal_rets = terminal_ret_instruction_addrs_8616(ir_artifact)
    prior: object = getattr(
        boundary,
        "_inertia_far_return_boundary_consumed_restores_8616",
        frozenset(),
    )
    typed_prior: frozenset[int] = prior if isinstance(prior, frozenset) else frozenset()
    statement_lists = _statement_lists_8616(root)
    classification = _classify_far_return_candidates_8616(
        project,
        candidates,
        terminal_rets,
        _assignments_by_address_8616(statement_lists),
        typed_prior,
    )
    removed_assignment_count = _remove_proven_cs_carriers_8616(
        statement_lists,
        classification.removals_by_addr,
    )

    consumed = frozenset(
        typed_prior | set(classification.removals_by_addr) | classification.already
    )
    stats = FarReturnBoundaryCarrierStats8616(
        raw_fact_count=len(candidates),
        normalized_fact_count=len(candidates),
        classified_fact_count=len(classification.removals_by_addr) + len(classification.already),
        materialized_count=len(classification.removals_by_addr),
        already_materialized_count=len(classification.already),
        failure_count=0,
        removed_assignment_count=removed_assignment_count,
        refusals=tuple(sorted(classification.refusals.items())),
    )
    boundary._inertia_far_return_boundary_consumed_restores_8616 = consumed
    boundary._inertia_far_return_boundary_carrier_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_FAR_RETURN_BOUNDARY"):
        logging.getLogger(__name__).warning(
            "[far-return-boundary] consumed=%s stats=%s",
            tuple(sorted(consumed)),
            stats,
        )
    return removed_assignment_count > 0