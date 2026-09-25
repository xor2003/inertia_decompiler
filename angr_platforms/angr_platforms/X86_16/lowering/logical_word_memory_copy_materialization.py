"""Materialize proven stack-word to direct-global copies in structured C.

Layer: Types/Lowering.
Responsibility: consume the Widening-owned logical word-copy artifact and
replace one exact tagged direct-global assignment RHS with its canonical stack
variable. No memory, register, or copy semantics are inferred from C shape.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from ..alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.structured_ast_query_index import StructuredAstQuerySession8616
from ..widening.logical_word_memory_copies import (
    LogicalWordMemoryCopy8616,
    LogicalWordMemoryCopyArtifact8616,
    build_logical_word_memory_copy_artifact_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_cvar_for_machine_bp_range_8616,
)


class LogicalWordMemoryCopyLoweringFailure8616(StrEnum):
    """Reason one exact C assignment kept its prior RHS."""

    FACT_AMBIGUOUS = "fact_ambiguous"
    SOURCE_VARIABLE_MISSING = "source_variable_missing"
    SOURCE_VARIABLE_AMBIGUOUS = "source_variable_ambiguous"


@dataclass(frozen=True, slots=True)
class LogicalWordMemoryCopyLoweringRefusal8616:
    """One exact assignment that could not consume its Widening fact."""

    fact: LogicalWordMemoryCopy8616 | None
    failure: LogicalWordMemoryCopyLoweringFailure8616
    detail: str


@dataclass(frozen=True, slots=True)
class LogicalWordMemoryCopyLoweringStats8616:
    """Closed evidence counters for C materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every matched assignment was changed or refused."""
        return bool(
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class LogicalWordMemoryCopyLoweringArtifact8616:
    """Closed Lowering outcomes tied to one Widening artifact."""

    source_widening: LogicalWordMemoryCopyArtifact8616 | None
    refusals: tuple[LogicalWordMemoryCopyLoweringRefusal8616, ...]
    stats: LogicalWordMemoryCopyLoweringStats8616

    @property
    def complete(self) -> bool:
        """Return whether source and Lowering accounting agree."""
        return bool(
            self.stats.complete
            and len(self.refusals) == self.stats.failure_count
            and (
                self.source_widening is None
                or self.source_widening.complete
            )
        )


@dataclass(frozen=True, slots=True)
class LogicalWordMemoryCopyLoweringResult8616:
    """Changed state and durable evidence from one replay."""

    changed: bool
    artifact: LogicalWordMemoryCopyLoweringArtifact8616


class _CodegenBoundary8616(Protocol):
    """Dynamic angr codegen extension carrying owned pipeline artifacts."""

    cfunc: object
    _inertia_stack_memory_ssa_alias_artifact: object
    _inertia_logical_word_memory_copy_artifact_8616: (
        LogicalWordMemoryCopyArtifact8616
    )
    _inertia_logical_word_memory_copy_lowering_artifact_8616: (
        LogicalWordMemoryCopyLoweringArtifact8616
    )


def _direct_global_identity_8616(
    assignment: structured_c.CAssignment,
) -> tuple[int, int] | None:
    """Return one exact direct global lvalue identity."""
    lhs = assignment.lhs
    if not isinstance(lhs, structured_c.CVariable):
        return None
    variable = lhs.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    if not isinstance(variable.addr, int) or not isinstance(variable.size, int):
        return None
    return variable.addr & 0xFFFF, variable.size


def _fact_index_8616(
    artifact: LogicalWordMemoryCopyArtifact8616,
) -> dict[tuple[int, int, int], tuple[LogicalWordMemoryCopy8616, ...]]:
    """Index Widening facts by destination instruction and DS word range."""
    grouped: dict[tuple[int, int, int], list[LogicalWordMemoryCopy8616]] = {}
    for fact in artifact.facts:
        destination = fact.destination_transfer.access
        key = (
            destination.key.insn_addr,
            destination.address.offset & 0xFFFF,
            destination.address.size,
        )
        grouped.setdefault(key, []).append(fact)
    return {
        key: tuple(value)
        for key, value in sorted(grouped.items())
    }


def _source_cvar_8616(
    codegen: object,
    assignment: structured_c.CAssignment,
    fact: LogicalWordMemoryCopy8616,
) -> structured_c.CVariable | bool | None:
    """Resolve one canonical source variable; ``False`` means ambiguous."""
    address = fact.source_transfer.access.address
    canonical = stack_cvar_for_machine_bp_range_8616(
        codegen,
        address.offset,
        address.size,
    )
    if isinstance(canonical, structured_c.CVariable):
        return canonical
    candidates: list[structured_c.CVariable] = []
    for node in _iter_c_nodes_deep_8616(assignment.rhs):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = node.variable
        if (
            isinstance(variable, SimStackVariable)
            and variable.size == address.size
            and machine_bp_offset_for_stack_variable_8616(codegen, variable)
            == address.offset
        ):
            candidates.append(node)
    unique = {id(candidate): candidate for candidate in candidates}
    if len(unique) == 1:
        return next(iter(unique.values()))
    if len(unique) > 1:
        return False
    return None


def _apply_copy_fact_8616(
    codegen: object,
    node: object,
    fact_index: dict[tuple[int, int, int], tuple[LogicalWordMemoryCopy8616, ...]],
    refusals: list[LogicalWordMemoryCopyLoweringRefusal8616],
) -> int | None:
    """Apply one matched copy fact to one global assignment RHS.

    Returns ``None`` when the node is not a matching global assignment,
    ``0`` when a match refused, and ``1`` when the RHS was replaced.
    """
    if not isinstance(node, structured_c.CAssignment):
        return None
    identity = _direct_global_identity_8616(node)
    if identity is None:
        return None
    destination_offset, destination_size = identity
    instruction_addrs = instruction_addrs_from_node_8616(node)
    matches = tuple(
        fact
        for instruction_addr in instruction_addrs
        for fact in fact_index.get(
            (instruction_addr, destination_offset, destination_size),
            (),
        )
    )
    if not matches:
        return None
    if len(matches) != 1:
        refusals.append(
            LogicalWordMemoryCopyLoweringRefusal8616(
                None,
                LogicalWordMemoryCopyLoweringFailure8616.FACT_AMBIGUOUS,
                f"matching fact count={len(matches)}",
            )
        )
        return 0
    fact = matches[0]
    source_cvar = _source_cvar_8616(codegen, node, fact)
    if source_cvar is False:
        refusals.append(
            LogicalWordMemoryCopyLoweringRefusal8616(
                fact,
                LogicalWordMemoryCopyLoweringFailure8616.SOURCE_VARIABLE_AMBIGUOUS,
                "multiple C variables represent the exact source stack range",
            )
        )
        return 0
    if source_cvar is None:
        refusals.append(
            LogicalWordMemoryCopyLoweringRefusal8616(
                fact,
                LogicalWordMemoryCopyLoweringFailure8616.SOURCE_VARIABLE_MISSING,
                "no C variable represents the exact source stack range",
            )
        )
        return 0
    node.rhs = source_cvar
    return 1


def materialize_logical_word_memory_copies_8616(
    codegen: object,
    *,
    query_session: StructuredAstQuerySession8616 | None = None,
) -> LogicalWordMemoryCopyLoweringResult8616:
    """Replace exact global assignment RHSs from closed copy evidence.

    ``query_session`` may accelerate assignment discovery for the current root.
    This pass changes RHS children only, so its copied assignment projection
    remains complete for the duration of this request.
    """
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        source = None
    source_alias = (
        source if isinstance(source, StackMemorySSAAliasArtifact8616) else None
    )
    widening = (
        build_logical_word_memory_copy_artifact_8616(source_alias)
        if source_alias is not None
        else None
    )
    if widening is not None:
        boundary._inertia_logical_word_memory_copy_artifact_8616 = widening
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        # Dynamic boundary: lightweight replay fixtures may omit an angr CFunction.
        cfunc = None
    root = cfunc.statements if isinstance(cfunc, structured_c.CFunction) else None
    fact_index = _fact_index_8616(widening) if widening is not None and widening.complete else {}
    raw_fact_count = 0
    materialized_count = 0
    refusals: list[LogicalWordMemoryCopyLoweringRefusal8616] = []
    if root is not None and fact_index:
        query_index = query_session.current() if query_session is not None else None
        if query_index is not None:
            query_index.require_root(root)
        nodes = (
            query_index.assignments
            if query_index is not None
            else _iter_c_nodes_deep_8616(root)
        )
        for node in nodes:
            delta = _apply_copy_fact_8616(
                codegen, node, fact_index, refusals
            )
            raw_fact_count += 1 if delta is not None else 0
            materialized_count += delta or 0
    if query_session is not None:
        query_session.record_mutation(materialized_count > 0)
    stats = LogicalWordMemoryCopyLoweringStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
    )
    artifact = LogicalWordMemoryCopyLoweringArtifact8616(
        widening,
        tuple(refusals),
        stats,
    )
    boundary._inertia_logical_word_memory_copy_lowering_artifact_8616 = artifact
    return LogicalWordMemoryCopyLoweringResult8616(
        changed=materialized_count > 0,
        artifact=artifact,
    )


__all__ = [
    "LogicalWordMemoryCopyLoweringArtifact8616",
    "LogicalWordMemoryCopyLoweringFailure8616",
    "LogicalWordMemoryCopyLoweringRefusal8616",
    "LogicalWordMemoryCopyLoweringResult8616",
    "LogicalWordMemoryCopyLoweringStats8616",
    "materialize_logical_word_memory_copies_8616",
]
