"""Prune unread pure virtual condition carriers after condition materialization.

Layer: Rewrite/Postprocess cleanup.
Responsibility: remove semantically inert SSA condition temporaries only after
their structured consumers have been materialized and complete def-use evidence
proves that the destination is unread.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.

This pass does not recover conditions, decode instructions, or infer storage.
Unknown, live, non-SSA, and side-effecting candidates are retained.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment.expression import VirtualVariable
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)

from ...c_ast_utils import (
    _iter_c_node_children_8616,
    _iter_c_nodes_deep_8616,
    _structured_slot_names_8616,
)
from .dce_purity import PURE_LOCAL_BINARY_OPS_8616, PURE_LOCAL_UNARY_OPS_8616

__all__ = [
    "DeadConditionCarrierStats8616",
    "VirtualConditionCarrierIdentity8616",
    "prune_unread_pure_condition_carriers_8616",
    "prune_unread_pure_condition_carriers_pass_8616",
]

_CONDITION_OPS_8616: frozenset[str] = frozenset({"CmpEQ", "CmpGE", "CmpGT", "CmpLE", "CmpLT", "CmpNE"})

log: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class VirtualConditionCarrierIdentity8616:
    """Stable SSA identity for one dynamic angr virtual variable."""

    vvar_id: int


@dataclass(frozen=True, slots=True)
class DeadConditionCarrierStats8616:
    """Closed evidence accounting for unread virtual condition carriers."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    live_refusal_count: int = 0
    side_effect_refusal_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether at least one dead carrier was removed."""
        return self.materialized_count > 0

    def merge(self, other: DeadConditionCarrierStats8616) -> DeadConditionCarrierStats8616:
        """Return cumulative evidence across repeated cleanup rounds."""
        return DeadConditionCarrierStats8616(
            raw_fact_count=self.raw_fact_count + other.raw_fact_count,
            normalized_fact_count=self.normalized_fact_count + other.normalized_fact_count,
            classified_fact_count=self.classified_fact_count + other.classified_fact_count,
            materialized_count=self.materialized_count + other.materialized_count,
            failure_count=self.failure_count + other.failure_count,
            live_refusal_count=self.live_refusal_count + other.live_refusal_count,
            side_effect_refusal_count=self.side_effect_refusal_count + other.side_effect_refusal_count,
        )


class _DeadConditionCarrierCodegen8616(Protocol):
    """Owned telemetry slot and dynamic C-function boundary used by the pass."""

    cfunc: _DeadConditionCarrierCFunction8616
    _inertia_dead_condition_carrier_stats_8616: DeadConditionCarrierStats8616


class _DeadConditionCarrierCFunction8616(Protocol):
    """Dynamic angr C-function statement root consumed by the cleanup pass."""

    statements: object


def _carrier_identity_8616(node: object) -> VirtualConditionCarrierIdentity8616 | None:
    """Return an exact virtual-variable identity without using rendered names."""
    if isinstance(node, CVariable) and isinstance(node.vvar_id, int):
        return VirtualConditionCarrierIdentity8616(node.vvar_id)
    if isinstance(node, CDirtyExpression) and isinstance(node.dirty, VirtualVariable):
        return VirtualConditionCarrierIdentity8616(node.dirty.varid)
    return None


def _is_pure_expression_8616(node: object) -> bool:
    """Return whether an expression has no calls, memory access, or address effects."""
    if isinstance(node, (CConstant, CVariable)):
        return True
    if isinstance(node, CDirtyExpression):
        return isinstance(node.dirty, VirtualVariable)
    if isinstance(node, CTypeCast):
        return _is_pure_expression_8616(node.expr)
    if isinstance(node, CUnaryOp):
        return node.op in PURE_LOCAL_UNARY_OPS_8616 and _is_pure_expression_8616(node.operand)
    if isinstance(node, CBinaryOp):
        return (
            node.op in PURE_LOCAL_BINARY_OPS_8616
            and _is_pure_expression_8616(node.lhs)
            and _is_pure_expression_8616(node.rhs)
        )
    return False


def _statement_blocks_8616(root: object) -> tuple[CStatements, ...]:
    """Return each dynamic structured-C statement block exactly once."""
    return tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements))


def _read_counts_8616(
    root: object,
    definitions: dict[VirtualConditionCarrierIdentity8616, int],
) -> dict[VirtualConditionCarrierIdentity8616, int]:
    """Count whole-tree identity occurrences after removing direct definitions."""
    occurrences: dict[VirtualConditionCarrierIdentity8616, int] = {}
    for node in _iter_c_nodes_deep_8616(root):
        identity = _carrier_identity_8616(node)
        if identity is not None:
            occurrences[identity] = occurrences.get(identity, 0) + 1
    return {
        identity: max(count - definitions.get(identity, 0), 0)
        for identity, count in occurrences.items()
    }


def _definition_counts_8616(blocks: tuple[CStatements, ...]) -> dict[VirtualConditionCarrierIdentity8616, int]:
    """Count direct virtual-variable definitions across the structured function."""
    definitions: dict[VirtualConditionCarrierIdentity8616, int] = {}
    for block in blocks:
        for statement in block.statements:
            if not isinstance(statement, CAssignment):
                continue
            identity = _carrier_identity_8616(statement.lhs)
            if identity is not None:
                definitions[identity] = definitions.get(identity, 0) + 1
    return definitions


def _debug_identity_filter_8616() -> frozenset[int]:
    """Return optional virtual IDs selected for detailed diagnostics."""
    selected: set[int] = set()
    for item in os.environ.get("INERTIA_DEBUG_DEAD_CONDITION_CARRIER_IDS", "").split(","):
        try:
            selected.add(int(item.strip(), 0))
        except ValueError:
            continue
    return frozenset(selected)


def _identity_parent_contexts_8616(
    root: object,
    identity: VirtualConditionCarrierIdentity8616,
) -> tuple[str, ...]:
    """Describe direct C-AST parents of one virtual identity for diagnostics."""
    contexts: set[str] = set()
    for parent in _iter_c_nodes_deep_8616(root):
        for attr in _structured_slot_names_8616(parent):
            try:
                # Dynamic third-party angr C-AST boundary: slot names vary by release.
                value = getattr(parent, attr)
            except (AttributeError, TypeError):
                continue
            for child in _iter_c_node_children_8616(value, set()):
                if _carrier_identity_8616(child) == identity:
                    contexts.add(f"{type(parent).__name__}.{attr}")
    return tuple(sorted(contexts))


@dataclass(slots=True)
class _CarrierPruneScan8616:
    """Mutable per-statement prune verdicts and evidence counters."""

    root: object
    debug_identity_filter: frozenset[int]
    raw: int = 0
    normalized: int = 0
    classified: int = 0
    materialized: int = 0
    failures: int = 0
    live_refusals: int = 0
    side_effect_refusals: int = 0

    def keep(
        self,
        statement: object,
        definitions: Mapping[VirtualConditionCarrierIdentity8616, int],
        reads: Mapping[VirtualConditionCarrierIdentity8616, int],
    ) -> bool:
        """Return whether one statement survives the carrier prune."""
        if not isinstance(statement, CAssignment) or not isinstance(statement.rhs, CBinaryOp):
            return True
        if statement.rhs.op not in _CONDITION_OPS_8616:
            return True
        identity = _carrier_identity_8616(statement.lhs)
        if identity is None:
            return True
        definition_count = definitions.get(identity, 0)
        read_count = reads.get(identity, 0)
        pure = _is_pure_expression_8616(statement.rhs)
        if os.environ.get("INERTIA_DEBUG_DEAD_CONDITION_CARRIERS") == "1" and (
            not self.debug_identity_filter or identity.vvar_id in self.debug_identity_filter
        ):
            log.warning(
                "[dead-condition-carrier] varid=%d lhs_type=%s definitions=%d reads=%d pure=%s "
                "parents=%r tags=%r",
                identity.vvar_id,
                type(statement.lhs).__name__,
                definition_count,
                read_count,
                pure,
                _identity_parent_contexts_8616(self.root, identity),
                statement.tags,
            )
        self.raw += 1
        if definition_count != 1:
            self.failures += 1
            return True
        self.normalized += 1
        if read_count > 0:
            self.classified += 1
            self.live_refusals += 1
            return True
        if not pure:
            self.classified += 1
            self.side_effect_refusals += 1
            return True
        self.classified += 1
        self.materialized += 1
        return False


def prune_unread_pure_condition_carriers_8616(codegen: object) -> DeadConditionCarrierStats8616:
    """Remove uniquely defined, unread, pure virtual comparison assignments."""
    boundary = cast(_DeadConditionCarrierCodegen8616, codegen)
    try:
        root = boundary.cfunc.statements
    except AttributeError:
        root = None
    if root is None:
        return DeadConditionCarrierStats8616()

    blocks = _statement_blocks_8616(root)
    definitions = _definition_counts_8616(blocks)
    reads = _read_counts_8616(root, definitions)
    scan = _CarrierPruneScan8616(root, _debug_identity_filter_8616())

    for block in blocks:
        kept = [
            statement
            for statement in block.statements
            if scan.keep(statement, definitions, reads)
        ]
        if len(kept) != len(block.statements):
            block.statements = kept

    current = DeadConditionCarrierStats8616(
        raw_fact_count=scan.raw,
        normalized_fact_count=scan.normalized,
        classified_fact_count=scan.classified,
        materialized_count=scan.materialized,
        failure_count=scan.failures,
        live_refusal_count=scan.live_refusals,
        side_effect_refusal_count=scan.side_effect_refusals,
    )
    try:
        previous = boundary._inertia_dead_condition_carrier_stats_8616
    except AttributeError:
        previous = DeadConditionCarrierStats8616()
    boundary._inertia_dead_condition_carrier_stats_8616 = previous.merge(current)
    return current


def prune_unread_pure_condition_carriers_pass_8616(codegen: object) -> bool:
    """Run dead condition-carrier cleanup as a typed optimization pass."""
    return prune_unread_pure_condition_carriers_8616(codegen).changed
