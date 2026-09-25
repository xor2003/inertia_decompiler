"""CFG-proven ownership for duplicated calls at structured shared tails.

Layer: Structuring.
Responsibility: remove synthetic returned-call AST clones only when one exact
machine callsite is retained at its proven common CFG tail.

This pass consumes callsite summaries and CFG topology. It does not infer call
arguments, return types, alias identity, or semantics from rendered C.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import _same_c_expression_8616
from ..caller_return_use_contracts import CallsiteReturnUseKind8616
from ..callsite_summary import (
    CallsiteSummary8616,
    structured_callsite_addr_8616,
)
from ..pipeline.errors import PipelineHardError
from .shared_tail_cfg_topology import (
    SharedTailCfgTopology8616,
    recover_shared_tail_cfg_topology_8616,
    shared_callsite_tail_is_proven_8616,
)
from .shared_tail_structured_ancestry import (
    SharedTailCallOccurrence8616,
    SharedTailCallOccurrenceKind8616,
    collect_shared_tail_call_occurrences_8616,
    standalone_follows_nested_clone_8616,
)

__all__ = (
    "SharedTailCallOwnershipResult8616",
    "SharedTailCallOwnershipStats8616",
    "SharedTailCallOwnershipStatus8616",
    "materialize_shared_tail_call_ownership_8616",
)


class SharedTailCallOwnershipStatus8616(Enum):
    """Typed outcome for one shared-tail call ownership pass."""

    NO_CANDIDATE = "no_candidate"
    MATERIALIZED = "materialized"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class SharedTailCallOwnershipStats8616:
    """Closed evidence counters for shared-tail call ownership."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class SharedTailCallOwnershipResult8616:
    """Immutable pass result retained on the codegen boundary."""

    status: SharedTailCallOwnershipStatus8616
    stats: SharedTailCallOwnershipStats8616
    refusal_reasons: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        """Return whether at least one synthetic call clone was removed."""
        return self.stats.materialized_count > 0


class _CFunctionSurface8616(Protocol):
    """Third-party C-function fields consumed by this pass."""

    addr: int
    statements: object


class _CodegenSurface8616(Protocol):
    """Codegen metadata boundary consumed and published by this pass."""

    cfunc: _CFunctionSurface8616
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_shared_tail_call_ownership_result_8616: SharedTailCallOwnershipResult8616


class _RegisterArchitecture8616(Protocol):
    """Architecture register map consumed at the third-party project boundary."""

    registers: Mapping[str, tuple[int, int]]


class _RegisterProject8616(Protocol):
    """Project architecture surface needed for physical carrier identity."""

    arch: _RegisterArchitecture8616


def _same_call_arguments_8616(
    left: structured_c.CFunctionCall,
    right: structured_c.CFunctionCall,
) -> bool:
    """Compare cloned call arguments without depending on rendered target names."""
    left_args = tuple(left.args or ())
    right_args = tuple(right.args or ())
    return len(left_args) == len(right_args) and all(
        _same_c_expression_8616(left_arg, right_arg)
        for left_arg, right_arg in zip(left_args, right_args, strict=True)
    )


def _return_carrier_matches_8616(
    project: object,
    occurrence: SharedTailCallOccurrence8616,
    summary: CallsiteSummary8616,
) -> bool:
    """Match a cloned return carrier by physical register identity and width."""
    variable = occurrence.destination_variable
    if not isinstance(variable, SimRegisterVariable) or not isinstance(
        summary.return_register, str
    ):
        return False
    try:
        arch = cast(_RegisterProject8616, project).arch
    except AttributeError:
        return False
    expected = arch.registers.get(summary.return_register.lower())
    return (
        expected is not None
        and variable.reg == expected[0]
        and variable.size == expected[1]
    )


def _owned_callsite_addr_8616(
    call: structured_c.CFunctionCall,
    summary_map: dict[int, CallsiteSummary8616],
) -> int | None:
    """Resolve one callsite from owned evidence and reject projection drift."""
    raw_tagged_addr = structured_callsite_addr_8616(call)
    if raw_tagged_addr is not None and not isinstance(raw_tagged_addr, int):
        raise TypeError("structured callsite identity must be an integer")
    tagged_addr: int | None = raw_tagged_addr
    summary = summary_map.get(id(call))
    if summary is None:
        return tagged_addr
    if not isinstance(summary, CallsiteSummary8616):
        raise TypeError("shared-tail call identity requires a typed callsite summary")
    summary_addr = summary.callsite_addr
    if not isinstance(summary_addr, int):
        raise TypeError("owned callsite summary identity must be an integer")
    if tagged_addr is not None and tagged_addr != summary_addr:
        raise PipelineHardError("structured callsite tag contradicts its owned callsite summary")
    return summary_addr


@dataclass(frozen=True, slots=True)
class _CallsiteOccurrenceShapes8616:
    """One callsite's occurrences bucketed by kind with derived shape flags."""

    conditions: tuple[SharedTailCallOccurrence8616, ...]
    returned: tuple[SharedTailCallOccurrence8616, ...]
    return_carriers: tuple[SharedTailCallOccurrence8616, ...]
    standalone: tuple[SharedTailCallOccurrence8616, ...]
    returned_clone_shape: bool
    nested_standalone_shape: bool
    condition_carrier_shape: bool


def _occurrence_shapes_8616(
    occurrences: list[SharedTailCallOccurrence8616],
) -> _CallsiteOccurrenceShapes8616:
    """Bucket one callsite's occurrences by kind and derive shape flags."""
    conditions = tuple(
        item for item in occurrences if item.kind is SharedTailCallOccurrenceKind8616.CONDITION
    )
    returned = tuple(
        item for item in occurrences if item.kind is SharedTailCallOccurrenceKind8616.RETURNED
    )
    return_carriers = tuple(
        item
        for item in occurrences
        if item.kind is SharedTailCallOccurrenceKind8616.RETURN_CARRIER
    )
    standalone = tuple(
        item for item in occurrences if item.kind is SharedTailCallOccurrenceKind8616.STANDALONE
    )
    return _CallsiteOccurrenceShapes8616(
        conditions,
        returned,
        return_carriers,
        standalone,
        returned_clone_shape=bool(returned and standalone),
        nested_standalone_shape=not returned and len(standalone) > 1,
        condition_carrier_shape=(
            len(conditions) == 1
            and len(return_carriers) == 1
            and not returned
            and not standalone
        ),
    )


def _ownership_proof_8616(
    project: object,
    summary: CallsiteSummary8616,
    shapes: _CallsiteOccurrenceShapes8616,
) -> tuple[
    SharedTailCallOccurrence8616 | None,
    tuple[SharedTailCallOccurrence8616, ...],
    bool,
]:
    """Prove retained-call ownership and select clone occurrences."""
    retained: SharedTailCallOccurrence8616 | None
    clones: tuple[SharedTailCallOccurrence8616, ...]
    if shapes.condition_carrier_shape:
        retained = shapes.conditions[0]
        clones = shapes.return_carriers
        ownership_proven = (
            summary.return_used is True
            and summary.return_use_kind is CallsiteReturnUseKind8616.CONDITION
            and _return_carrier_matches_8616(project, shapes.return_carriers[0], summary)
            and standalone_follows_nested_clone_8616(retained, shapes.return_carriers[0])
            and _same_call_arguments_8616(retained.call, shapes.return_carriers[0].call)
        )
    elif shapes.returned_clone_shape and len(shapes.standalone) == 1:
        retained = shapes.standalone[0]
        clones = shapes.returned
        ownership_proven = all(
            standalone_follows_nested_clone_8616(item, retained) for item in clones
        )
    elif shapes.nested_standalone_shape and summary.return_used is False:
        retained_candidates = tuple(
            candidate
            for candidate in shapes.standalone
            if all(
                other is candidate
                or (
                    standalone_follows_nested_clone_8616(other, candidate)
                    and _same_c_expression_8616(candidate.call, other.call)
                )
                for other in shapes.standalone
            )
        )
        retained = retained_candidates[0] if len(retained_candidates) == 1 else None
        clones = tuple(item for item in shapes.standalone if item is not retained)
        ownership_proven = retained is not None and bool(clones)
    else:
        retained = None
        clones = ()
        ownership_proven = False
    return retained, clones, ownership_proven


@dataclass(slots=True)
class _OwnershipScan8616:
    """Mutable per-callsite shared-tail ownership scan state."""

    project: object
    topology: SharedTailCfgTopology8616 | None
    inventory: Mapping[int, CallsiteSummary8616]
    raw_count: int = 0
    normalized_count: int = 0
    classified_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refusals: list[str] = field(default_factory=list)
    removals: list[SharedTailCallOccurrence8616] = field(default_factory=list)
    retained_call_ids: set[int] = field(default_factory=set)

    def process(
        self,
        callsite_addr: int,
        occurrences: list[SharedTailCallOccurrence8616],
    ) -> None:
        """Classify one callsite's occurrences into retained call and clones."""
        shapes = _occurrence_shapes_8616(occurrences)
        if (
            not shapes.returned_clone_shape
            and not shapes.nested_standalone_shape
            and not shapes.condition_carrier_shape
        ):
            return
        self.raw_count += 1
        summary = self.inventory.get(callsite_addr)
        if summary is None or self.topology is None:
            self.failure_count += 1
            self.refusals.append(f"callsite={callsite_addr:#x}:incomplete-census")
            return
        self.normalized_count += 1
        if not shared_callsite_tail_is_proven_8616(summary, self.topology):
            self.failure_count += 1
            self.refusals.append(f"callsite={callsite_addr:#x}:not-proven-shared-cfg-tail")
            return
        retained, clones, ownership_proven = _ownership_proof_8616(
            self.project,
            summary,
            shapes,
        )
        if not ownership_proven or retained is None:
            self.failure_count += 1
            self.refusals.append(f"callsite={callsite_addr:#x}:ast-ownership-conflict")
            return
        self.classified_count += len(clones)
        self.retained_call_ids.add(id(retained.call))
        self.removals.extend(clones)


def _proven_surface_8616(
    codegen: object,
) -> (
    tuple[
        _CodegenSurface8616,
        structured_c.CStatements,
        dict[int, CallsiteSummary8616],
        dict[int, CallsiteSummary8616],
    ]
    | None
):
    """Return the proven codegen surface pieces, or None when absent."""
    boundary = cast(_CodegenSurface8616, codegen)
    try:
        cfunc = boundary.cfunc
        root = cfunc.statements
        summary_map = boundary._inertia_callsite_summaries
        inventory = boundary._inertia_callsite_summary_inventory_8616
    except AttributeError:
        return None
    if not isinstance(root, structured_c.CStatements):
        return None
    if not isinstance(summary_map, dict) or not isinstance(inventory, dict):
        raise TypeError("shared-tail call ownership requires typed callsite mappings")
    if any(
        not isinstance(callsite_addr, int)
        or not isinstance(summary, CallsiteSummary8616)
        or summary.callsite_addr != callsite_addr
        for callsite_addr, summary in inventory.items()
    ):
        raise TypeError("shared-tail callsite inventory contains an invalid owned contract")
    return boundary, root, summary_map, inventory


def _materialize_removals_8616(
    scan: _OwnershipScan8616,
    summary_map: dict[int, CallsiteSummary8616],
) -> None:
    """Delete proven clone occurrences from their owning containers."""
    for occurrence in sorted(
        scan.removals,
        key=lambda item: (id(item.parent), item.statement_index),
        reverse=True,
    ):
        statements = occurrence.parent.statements
        if (
            not isinstance(statements, list)
            or occurrence.statement_index >= len(statements)
            or statements[occurrence.statement_index] is not occurrence.statement
        ):
            raise PipelineHardError("classified shared-tail call clone lost its AST owner")
        del statements[occurrence.statement_index]
        if id(occurrence.call) not in scan.retained_call_ids:
            summary_map.pop(id(occurrence.call), None)
        scan.materialized_count += 1


def materialize_shared_tail_call_ownership_8616(
    project: object,
    codegen: object,
) -> SharedTailCallOwnershipResult8616:
    """Remove only CFG-proven returned-call clones of one retained shared tail."""
    empty = SharedTailCallOwnershipResult8616(
        SharedTailCallOwnershipStatus8616.NO_CANDIDATE,
        SharedTailCallOwnershipStats8616(),
    )
    surface = _proven_surface_8616(codegen)
    if surface is None:
        return empty
    boundary, root, summary_map, inventory = surface
    topology: SharedTailCfgTopology8616 | None = recover_shared_tail_cfg_topology_8616(
        project,
        boundary.cfunc.addr,
    )
    occurrences_by_callsite: dict[int, list[SharedTailCallOccurrence8616]] = {}
    for occurrence in collect_shared_tail_call_occurrences_8616(root):
        callsite_addr = _owned_callsite_addr_8616(occurrence.call, summary_map)
        if isinstance(callsite_addr, int):
            occurrences_by_callsite.setdefault(callsite_addr, []).append(occurrence)

    scan = _OwnershipScan8616(project, topology, inventory)
    for callsite_addr, occurrences in sorted(occurrences_by_callsite.items()):
        scan.process(callsite_addr, occurrences)

    _materialize_removals_8616(scan, summary_map)

    stats = SharedTailCallOwnershipStats8616(
        scan.raw_count,
        scan.normalized_count,
        scan.classified_count,
        scan.materialized_count,
        scan.failure_count,
    )
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified shared-tail call ownership was not materialized")
    status = (
        SharedTailCallOwnershipStatus8616.MATERIALIZED
        if scan.materialized_count
        else SharedTailCallOwnershipStatus8616.UNKNOWN_REFUSE
        if scan.failure_count
        else SharedTailCallOwnershipStatus8616.NO_CANDIDATE
    )
    result = SharedTailCallOwnershipResult8616(status, stats, tuple(scan.refusals))
    boundary._inertia_shared_tail_call_ownership_result_8616 = result
    return result
