"""Prune register SSA carriers made obsolete by stack lowering.

Layer: Types/Lowering.
Responsibility: consume alias-backed stack materialization by removing only
structured register assignments whose value has no remaining C AST read.
Consumes alias, widening, and typed facts; it removes only consumers made
provably obsolete by earlier storage materialization.
Do not recover semantics from COD, source, assembly, or rendered C text.
Postprocess and CLI may invoke this consumer, but proof belongs here.

This pass requires structured SSA identity, a pure RHS containing a BP-relative
stack variable, and whole-function unread proof. When angr omits SSA identity,
an exact same-block physical-register overwrite before any read is also
sufficient. It does not infer storage, recover semantics, or perform general
dead-code elimination. Unknown, effectful, memory-reading, and live carriers
are preserved for validation. Segment-register writes are caller-visible even
without C AST reads; this local-carrier pass cannot prove them dead.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616, _structured_codegen_node_8616, _structured_slot_names_8616
from ..ir.segment_state_transfer import SEGMENT_REGISTER_SET
from ..pipeline.errors import PipelineHardError
from .gp_register_state import runtime_gp_live_in_name_8616, runtime_gp_state_names_8616
from .register_overwrite_evidence import (
    StackMoveRegisterOverwriteFact8616,
    stack_initializer_overwrites_register_8616,
)

__all__ = [
    "LoweredRegisterCarrierPruneStats8616",
    "prune_unread_stack_lowered_register_carriers_8616",
]

log: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RegisterSsaIdentity8616:
    """Structured identity for one angr register SSA variable."""

    region: int
    ident: int | str
    reg_offset: int
    width: int
    vvar_id: int | None


@dataclass(frozen=True, slots=True)
class PhysicalRegisterIdentity8616:
    """Physical register range used only for same-block overwrite proof."""

    reg_offset: int
    width: int


class LoweredRegisterCarrierDecision8616(Enum):
    """Typed outcome for one stack-lowered register assignment."""

    DEFINITELY_DEAD = "definitely_dead"
    LIVE_USE = "live_use"
    EFFECTFUL_OR_UNKNOWN_RHS = "effectful_or_unknown_rhs"
    NO_STACK_SOURCE = "no_stack_source"
    UNSTRUCTURED_IDENTITY = "unstructured_identity"


@dataclass(frozen=True, slots=True)
class LoweredRegisterCarrierPruneStats8616:
    """Evidence counters for stack-lowered register-carrier pruning."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    live_use_refused_count: int
    rhs_refused_count: int
    no_stack_source_refused_count: int
    unstructured_identity_refused_count: int


class _CFunctionSurface8616(Protocol):
    """Third-party codegen function surface needed by the Lowering consumer."""

    statements: object


class _CodegenSurface8616(Protocol):
    """Third-party codegen surface plus the owned result attached by this pass."""

    cfunc: _CFunctionSurface8616
    _inertia_direct_stack_move_facts_8616: tuple[StackMoveRegisterOverwriteFact8616, ...]
    _inertia_lowered_register_carrier_prune_8616: LoweredRegisterCarrierPruneStats8616


def _register_ssa_identity_8616(node: object) -> RegisterSsaIdentity8616 | None:
    """Return a register identity only when angr exposes region and SSA identity."""
    if not isinstance(node, CVariable) or not isinstance(node.variable, SimRegisterVariable):
        return None
    variable = node.variable
    if not isinstance(variable.region, int) or not isinstance(variable.ident, (int, str)):
        return None
    if not isinstance(variable.reg, int) or not isinstance(variable.size, int) or variable.size <= 0:
        return None
    return RegisterSsaIdentity8616(
        region=variable.region,
        ident=variable.ident,
        reg_offset=variable.reg,
        width=variable.size,
        vvar_id=node.vvar_id if isinstance(node.vvar_id, int) and not isinstance(node.vvar_id, bool) else None,
    )


def _physical_register_identity_8616(node: object) -> PhysicalRegisterIdentity8616 | None:
    """Return an exact physical register range from an angr C variable."""
    if not isinstance(node, CVariable) or not isinstance(node.variable, SimRegisterVariable):
        return None
    variable = node.variable
    if not isinstance(variable.reg, int) or not isinstance(variable.size, int) or variable.size <= 0:
        return None
    return PhysicalRegisterIdentity8616(reg_offset=variable.reg, width=variable.size)


def _walk_structured_values_8616(value: object, visit: object, active: set[int]) -> None:
    """Walk shared structured-C nodes, including owned casts, without ownership cycles."""
    if value is None:
        return
    if isinstance(value, dict):
        for child in value.values():
            _walk_structured_values_8616(child, visit, active)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _walk_structured_values_8616(child, visit, active)
        return
    if not _structured_codegen_node_8616(value):
        return
    marker = id(value)
    if marker in active:
        return
    active.add(marker)
    try:
        cast("_StructuredValueVisitor8616", visit)(value)
    finally:
        active.remove(marker)


class _StructuredValueVisitor8616(Protocol):
    """Callback used while traversing dynamic structured-C children."""

    def __call__(self, value: object) -> None:
        """Visit one structured-C value."""
        ...


def _register_read_owner_ids_8616(
    root: object,
) -> dict[RegisterSsaIdentity8616, frozenset[int | None]]:
    """Map register reads to their containing direct assignment, if any."""
    mutable_reads: dict[RegisterSsaIdentity8616, set[int | None]] = {}
    active: set[int] = set()
    assignment_owners: list[CAssignment] = []

    def visit(value: object) -> None:
        """Visit one structured-C node and distinguish definitions from reads."""
        if isinstance(value, CVariable):
            identity = _register_ssa_identity_8616(value)
            if identity is not None:
                owner = assignment_owners[-1] if assignment_owners else None
                mutable_reads.setdefault(identity, set()).add(id(owner) if owner is not None else None)
            return
        if isinstance(value, CAssignment):
            if not isinstance(value.lhs, CVariable):
                _walk_structured_values_8616(value.lhs, visit, active)
            assignment_owners.append(value)
            try:
                _walk_structured_values_8616(value.rhs, visit, active)
            finally:
                assignment_owners.pop()
            return
        for attr in _structured_slot_names_8616(value):
            # Dynamic third-party angr structured-C child boundary.
            child = getattr(value, attr, None)
            _walk_structured_values_8616(child, visit, active)

    _walk_structured_values_8616(root, visit, active)
    return {identity: frozenset(owners) for identity, owners in mutable_reads.items()}


def _register_read_identities_8616(root: object) -> frozenset[RegisterSsaIdentity8616]:
    """Collect register identities read outside direct assignment definitions."""
    return frozenset(_register_read_owner_ids_8616(root))


def _physical_register_read_identities_8616(root: object) -> frozenset[PhysicalRegisterIdentity8616]:
    """Collect physical register ranges read outside direct assignment definitions."""
    reads: set[PhysicalRegisterIdentity8616] = set()
    active: set[int] = set()

    def visit(value: object) -> None:
        """Visit one structured-C node and distinguish definitions from reads."""
        if isinstance(value, CVariable):
            identity = _physical_register_identity_8616(value)
            if identity is not None:
                reads.add(identity)
            return
        if isinstance(value, CAssignment):
            if not isinstance(value.lhs, CVariable):
                _walk_structured_values_8616(value.lhs, visit, active)
            _walk_structured_values_8616(value.rhs, visit, active)
            return
        for attr in _structured_slot_names_8616(value):
            # Dynamic third-party angr structured-C child boundary.
            child = getattr(value, attr, None)
            _walk_structured_values_8616(child, visit, active)

    _walk_structured_values_8616(root, visit, active)
    return frozenset(reads)


def _rhs_variable_verdict_8616(node: CVariable) -> tuple[bool, tuple[object, ...], bool]:
    """Return the acceptance verdict for one variable node."""
    variable = node.variable
    if isinstance(variable, SimStackVariable):
        if variable.base != "bp" or not isinstance(variable.offset, int):
            return False, (), False
        return True, (), True
    if isinstance(variable, SimMemoryVariable):
        return False, (), False
    return True, (), False


def _rhs_node_children_8616(node: object) -> tuple[bool, tuple[object, ...], bool]:
    """Return ``(accepted, children, stack_source)`` for one value-only node."""
    if isinstance(node, CConstant):
        return True, (), False
    if isinstance(node, CVariable):
        return _rhs_variable_verdict_8616(node)
    if isinstance(node, CBinaryOp):
        return True, (node.lhs, node.rhs), False
    if isinstance(node, CTypeCast):
        return True, (node.expr,), False
    if isinstance(node, CUnaryOp):
        if node.op in {"Dereference", "Reference"}:
            return False, (), False
        return True, (node.operand,), False
    if isinstance(node, CITE):
        return True, (node.cond, node.iftrue, node.iffalse), False
    return False, (), False


def _pure_stack_lowered_rhs_8616(rhs: object) -> tuple[bool, bool]:
    """Return ``(pure, has_stack_source)`` for a bounded value-only RHS."""
    has_stack_source = False
    pending = [rhs]
    active: set[int] = set()
    while pending:
        node = pending.pop()
        if node is None:
            return False, has_stack_source
        marker = id(node)
        if marker in active:
            return False, has_stack_source
        active.add(marker)
        accepted, children, stack_source = _rhs_node_children_8616(node)
        if not accepted:
            return False, has_stack_source
        has_stack_source = has_stack_source or stack_source
        pending.extend(children)
    return True, has_stack_source


def _first_following_register_event_8616(
    block: CStatements,
    statement_index: int,
    identity: RegisterSsaIdentity8616,
) -> tuple[str, int | None]:
    """Return the next same-block read or overwrite for one register identity."""
    for following_index, statement in enumerate(
        block.statements[statement_index + 1 :],
        start=statement_index + 1,
    ):
        if identity in _register_read_identities_8616(statement):
            return "read", following_index
        if isinstance(statement, CAssignment) and _register_ssa_identity_8616(statement.lhs) == identity:
            return "overwrite", following_index
    return "block_end", None


def _first_following_physical_register_event_8616(
    block: CStatements,
    statement_index: int,
    identity: PhysicalRegisterIdentity8616,
    stack_move_facts: tuple[StackMoveRegisterOverwriteFact8616, ...],
) -> tuple[str, int | None]:
    """Return the next same-block physical-register read or overwrite."""
    for following_index, statement in enumerate(
        block.statements[statement_index + 1 :],
        start=statement_index + 1,
    ):
        if stack_initializer_overwrites_register_8616(
            statement,
            register_offset=identity.reg_offset,
            register_width=identity.width,
            facts=stack_move_facts,
        ):
            return "overwrite", following_index
        if identity in _physical_register_read_identities_8616(statement):
            return "read", following_index
        if isinstance(statement, CAssignment) and _physical_register_identity_8616(statement.lhs) == identity:
            return "overwrite", following_index
    return "block_end", None


@dataclass(slots=True)
class _CarrierPruneScan8616:
    """Mutable census of unread stack-lowered register carriers."""

    stack_move_facts: tuple[StackMoveRegisterOverwriteFact8616, ...]
    read_owner_ids: dict[RegisterSsaIdentity8616, frozenset[int | None]]
    runtime_gp_names: frozenset[str]
    raw: int = 0
    normalized: int = 0
    classified: int = 0
    live_refused: int = 0
    rhs_refused: int = 0
    no_stack_refused: int = 0
    identity_refused: int = 0
    removable_ids: set[int] = field(default_factory=set)
    candidate_locations: dict[int, tuple[CStatements, int]] = field(default_factory=dict)

    def scan_node(self, node: object) -> None:
        """Census one node and classify register assignment candidates."""
        if isinstance(node, CStatements):
            for statement_index, statement in enumerate(node.statements):
                self.candidate_locations[id(statement)] = (node, statement_index)
        if not isinstance(node, CAssignment):
            return
        if not isinstance(node.lhs, CVariable) or not isinstance(node.lhs.variable, SimRegisterVariable):
            return
        self.raw += 1
        self.classify_assignment(node)

    def classify_assignment(self, node: CAssignment) -> None:
        """Apply the full evidence ladder to one register assignment."""
        identity = _register_ssa_identity_8616(node.lhs)
        location = self.candidate_locations.get(id(node))
        physical_identity = _physical_register_identity_8616(node.lhs)
        physical_next_event = (
            _first_following_physical_register_event_8616(
                location[0],
                location[1],
                physical_identity,
                self.stack_move_facts,
            )
            if identity is None and location is not None and physical_identity is not None
            else ("unknown", None)
        )
        physical_overwrite_proven = physical_next_event[0] == "overwrite"
        register_name = node.lhs.codegen.project.arch.register_names.get(node.lhs.variable.reg)
        caller_visible_state = register_name in SEGMENT_REGISTER_SET or (
            register_name is not None and runtime_gp_live_in_name_8616(register_name) in self.runtime_gp_names
        )
        if identity is None and not physical_overwrite_proven:
            self.identity_refused += 1
            return
        self.normalized += 1
        pure, has_stack_source = _pure_stack_lowered_rhs_8616(node.rhs)
        next_event = (
            _first_following_register_event_8616(location[0], location[1], identity)
            if identity is not None and location is not None
            else physical_next_event
        )
        if not pure:
            self.rhs_refused += 1
            decision = LoweredRegisterCarrierDecision8616.EFFECTFUL_OR_UNKNOWN_RHS
        elif not has_stack_source:
            self.no_stack_refused += 1
            decision = LoweredRegisterCarrierDecision8616.NO_STACK_SOURCE
        elif caller_visible_state or (
            identity is not None and any(owner != id(node) for owner in self.read_owner_ids.get(identity, ()))
        ):
            self.live_refused += 1
            decision = LoweredRegisterCarrierDecision8616.LIVE_USE
        else:
            self.classified += 1
            decision = LoweredRegisterCarrierDecision8616.DEFINITELY_DEAD
            self.removable_ids.add(id(node))
        if os.environ.get("INERTIA_DEBUG_LOWERED_CARRIERS") == "1":
            log.warning(
                "[lowered-register-carrier] identity=%r decision=%s next=%r tags=%r",
                identity,
                decision.value,
                next_event,
                node.tags,
            )


def _remove_removable_8616(root: CStatements, removable_ids: set[int]) -> int:
    """Delete all proven-dead assignments from their owning blocks."""
    materialized = 0
    seen_blocks: set[int] = set()
    blocks: list[CStatements] = []
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if isinstance(node, CStatements) and id(node) not in seen_blocks:
            seen_blocks.add(id(node))
            blocks.append(node)
    for block in blocks:
        kept = [statement for statement in block.statements if id(statement) not in removable_ids]
        removed = len(block.statements) - len(kept)
        if removed:
            block.statements[:] = kept
            materialized += removed
    return materialized


def prune_unread_stack_lowered_register_carriers_8616(codegen: object) -> bool:
    """Delete only globally unread register SSA assignments consumed by stack lowering.

    ``codegen`` and its C AST are dynamic third-party angr boundaries. The
    attached stats object is an owned typed contract and is written through a
    protocol cast.
    """
    typed_codegen = cast(_CodegenSurface8616, codegen)
    try:
        root = typed_codegen.cfunc.statements
    except AttributeError:
        return False
    if root is None:
        return False
    try:
        stack_move_facts = typed_codegen._inertia_direct_stack_move_facts_8616
    except AttributeError:
        stack_move_facts = ()

    scan = _CarrierPruneScan8616(
        stack_move_facts=stack_move_facts,
        read_owner_ids=_register_read_owner_ids_8616(root),
        runtime_gp_names=runtime_gp_state_names_8616(codegen),
    )
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        scan.scan_node(node)
    materialized = _remove_removable_8616(root, scan.removable_ids)

    normalized_outcomes = scan.classified + scan.live_refused + scan.rhs_refused + scan.no_stack_refused
    failures = (
        abs(scan.raw - scan.normalized - scan.identity_refused)
        + abs(scan.normalized - normalized_outcomes)
        + abs(scan.classified - materialized)
    )

    stats = LoweredRegisterCarrierPruneStats8616(
        raw_fact_count=scan.raw,
        normalized_fact_count=scan.normalized,
        classified_fact_count=scan.classified,
        materialized_count=materialized,
        failure_count=failures,
        live_use_refused_count=scan.live_refused,
        rhs_refused_count=scan.rhs_refused,
        no_stack_source_refused_count=scan.no_stack_refused,
        unstructured_identity_refused_count=scan.identity_refused,
    )
    typed_codegen._inertia_lowered_register_carrier_prune_8616 = stats
    if scan.classified > 0 and materialized == 0:
        raise PipelineHardError(
            "stack-lowered register carriers classified but not materialized",
            layer="lowering",
            details={
                "classified_fact_count": scan.classified,
                "materialized_count": materialized,
                "failure_count": failures,
            },
        )
    return materialized > 0
