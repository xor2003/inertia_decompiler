"""Materialize Alias-proven stack word-load recompositions in C ASTs.

Layer: Types/Lowering.
Responsibility: replace a structured ``low | (high << 8)`` projection with
the canonical stack scalar value only when instruction provenance, the exact
Alias load range, and the BP-to-entry-SP coordinate registry all agree.
Pointer owners yield guest offset bits through the owned storage bridge;
their host C addresses must never replace machine integer word values.
Consumes alias, widening, and typed facts. Unproven candidates are retained and
reported as typed refusals.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType
from angr.sim_variable import SimStackVariable

from inertia.alias.stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemorySSAAliasArtifact8616,
)
from inertia.lowering.c_ast_utils import _replace_c_children_8616

from .instruction_bp_stack_access import (
    InstructionBpStackAccess8616,
    InstructionBpStackAccessIndex8616,
    ensure_instruction_bp_stack_access_index_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_prototype_layout import stack_prototype_cvar_for_machine_bp_range_8616
from .stack_value_projection import project_pointer_storage_value_8616
from .stack_variable_coordinates import stack_cvar_for_machine_bp_range_8616
from .stack_word_load_candidate import (
    direct_machine_bp_word_owner_8616,
    stack_word_byte_pair_matches_machine_bp_view_8616,
    stack_word_load_expression_has_side_effect_8616,
    stack_word_operand_is_captured_value_8616,
)
from .stack_word_load_projection import (
    resolve_logical_stack_word_owner_8616,
    resolve_stack_word_load_projection_8616,
)
from .stack_word_projection import stack_word_projection_owner_8616
from .stack_word_recomposition import recognize_stack_word_recomposition_8616

_LOG = logging.getLogger(__name__)


class StackWordLoadRefusalKind8616(StrEnum):
    """Reason one syntactic word projection remained unchanged."""

    SIDE_EFFECTFUL_HIGH = "side_effectful_high"
    ALIAS_ARTIFACT_UNAVAILABLE = "alias_artifact_unavailable"
    NO_INSTRUCTION_PROVENANCE = "no_instruction_provenance"
    ALIAS_LOAD_MISSING = "alias_load_missing"
    ALIAS_LOAD_AMBIGUOUS = "alias_load_ambiguous"
    STACK_PROJECTION_MISMATCH = "stack_projection_mismatch"
    CAPTURED_VALUE = "captured_value"
    VALUE_WIDTH_UNPROVEN = "value_width_unproven"


@dataclass(frozen=True, slots=True)
class StackWordLoadRefusal8616:
    """One retained word projection and its typed refusal reason."""

    kind: StackWordLoadRefusalKind8616
    instruction_addrs: tuple[int, ...] = ()
    detail: str = ""


@dataclass(frozen=True, slots=True)
class StackWordLoadMaterializationStats8616:
    """Closed evidence accounting for stack word-load materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every candidate was materialized or refused."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class StackWordLoadMaterializationArtifact8616:
    """Result of one AST replay against an exact Alias artifact."""

    source_alias: StackMemorySSAAliasArtifact8616 | None
    refusals: tuple[StackWordLoadRefusal8616, ...]
    stats: StackWordLoadMaterializationStats8616

    @property
    def complete(self) -> bool:
        """Return whether the materialization evidence loop closes."""
        return self.stats.complete and (
            self.source_alias is None or self.source_alias.complete
        )


@dataclass(frozen=True, slots=True)
class StackWordLoadMaterializationResult8616:
    """Possibly replaced AST root plus its durable evidence artifact."""

    root: object
    artifact: StackWordLoadMaterializationArtifact8616

    @property
    def changed(self) -> bool:
        """Return whether at least one proven projection was materialized."""
        return self.artifact.stats.materialized_count > 0


class _CodegenBoundary8616(Protocol):
    """Dynamic angr codegen extension carrying typed pipeline artifacts."""

    _inertia_stack_memory_ssa_alias_artifact: object
    _inertia_stack_word_load_materialization_artifact_8616: (
        StackWordLoadMaterializationArtifact8616
    )


def _word_load_candidates_8616(
    index: InstructionBpStackAccessIndex8616,
    instruction_addrs: frozenset[int],
) -> tuple[InstructionBpStackAccess8616, ...]:
    """Return deterministic exact two-byte Alias loads in one C subtree."""
    return tuple(sorted({
        fact
        for instruction_addr in instruction_addrs
        for fact in index.by_instruction_addr.get(instruction_addr, ())
        if fact.kind is StackMemoryAliasFactKind8616.LOAD and fact.size == 2
    }, key=lambda fact: (fact.displacement, fact.size, fact.kind.value)))


def _owner_represents_word_value_8616(owner: structured_c.CVariable) -> bool:
    """Require all loaded bits in the C value, independently of slot padding."""
    value_type = owner.variable_type
    if not isinstance(value_type, SimType):
        return False
    try:
        size_bits: object = value_type.size
        return isinstance(size_bits, int) and size_bits == 16
    except (AttributeError, TypeError, ValueError):
        # Third-party SimType can lack an architecture-dependent size.
        return False


@dataclass
class _StackWordRecomposition8616:
    """Replace proven word projections and retain every typed refusal."""

    codegen: object
    source_alias: StackMemorySSAAliasArtifact8616 | None
    index: InstructionBpStackAccessIndex8616 | None = None
    raw_fact_count: int = 0
    materialized_count: int = 0
    refusals: list[StackWordLoadRefusal8616] = field(default_factory=list)

    def _refuse(
        self,
        kind: StackWordLoadRefusalKind8616,
        instruction_addrs: frozenset[int] = frozenset(),
        detail: str = "",
    ) -> None:
        """Retain one candidate with deterministic typed diagnostics."""
        self.refusals.append(
            StackWordLoadRefusal8616(
                kind,
                tuple(sorted(instruction_addrs)),
                detail,
            )
        )

    def _materialized_word_value(
        self,
        owner: structured_c.CExpression,
        instruction_addrs: frozenset[int] = frozenset(),
    ) -> structured_c.CExpression | None:
        """Return the guest scalar storage value for one proven word owner.

        A machine word recomposition stores the owner's guest offset bits, so
        host C pointer owners must be projected through the scalar bridge.
        Non-pointer owners pass through unchanged. The caller's word-width
        gate rejects wider pointer owners before this projection; a missing
        storage projection retains the original expression with a typed refusal.
        """
        projected = project_pointer_storage_value_8616(self.codegen, owner, 2)
        if projected is None:
            self._refuse(
                StackWordLoadRefusalKind8616.VALUE_WIDTH_UNPROVEN,
                instruction_addrs,
                detail="pointer owner width is not a supported machine word",
            )
            return None
        self.materialized_count += 1
        return projected

    def _logical_owner(self, node: object, low: object, high: object) -> object:
        """Resolve an owner when no instruction provenance exists."""
        if not isinstance(low, structured_c.CVariable):
            self._refuse(
                StackWordLoadRefusalKind8616.NO_INSTRUCTION_PROVENANCE,
                detail="instructionless byte view has no canonical stack variable",
            )
            return node
        assert self.source_alias is not None  # Established by _operand_gates.
        logical_owner = resolve_logical_stack_word_owner_8616(
            self.codegen,
            self.source_alias,
            low,
            high,
        )
        if logical_owner.resolved and logical_owner.cvar is not None:
            if not _owner_represents_word_value_8616(logical_owner.cvar):
                self._refuse(StackWordLoadRefusalKind8616.VALUE_WIDTH_UNPROVEN)
                return node
            value = self._materialized_word_value(logical_owner.cvar)
            return node if value is None else value
        self._refuse(
            StackWordLoadRefusalKind8616.NO_INSTRUCTION_PROVENANCE,
            detail=logical_owner.detail,
        )
        return node

    def _single_load(
        self,
        instruction_addrs: frozenset[int],
    ) -> InstructionBpStackAccess8616 | None:
        """Require exactly one Alias-proven BP load range."""
        assert self.index is not None
        loads = _word_load_candidates_8616(self.index, instruction_addrs)
        if len(loads) == 1:
            return loads[0]
        self._refuse(
            StackWordLoadRefusalKind8616.ALIAS_LOAD_MISSING
            if not loads
            else StackWordLoadRefusalKind8616.ALIAS_LOAD_AMBIGUOUS,
            instruction_addrs,
            detail=(
                f"candidate BP ranges={tuple((load.displacement, load.size) for load in loads)!r}; "
                f"logical inventory={self.index.logical_inventory!r}"
            ),
        )
        return None

    def _canonical_owner(
        self,
        load: InstructionBpStackAccess8616,
    ) -> structured_c.CVariable | None:
        """Return the canonical or prototype BP owner for one proven load."""
        canonical_owner = stack_cvar_for_machine_bp_range_8616(
            self.codegen,
            load.displacement,
            load.size,
        )
        if canonical_owner is None:
            canonical_owner = stack_prototype_cvar_for_machine_bp_range_8616(
                self.codegen,
                load.displacement,
                load.size,
            )
        if isinstance(canonical_owner, structured_c.CVariable) and _owner_represents_word_value_8616(canonical_owner):
            return canonical_owner
        return None

    def _projected_owner(
        self,
        node: object,
        low: object,
        high: object,
        load: InstructionBpStackAccess8616,
        instruction_addrs: frozenset[int],
    ) -> object:
        """Resolve the remaining owner ladder after canonical lookup fails."""
        if not stack_word_byte_pair_matches_machine_bp_view_8616(low, high):
            self._refuse(
                StackWordLoadRefusalKind8616.STACK_PROJECTION_MISMATCH,
                instruction_addrs,
                detail="low and high byte variables are not adjacent stack views",
            )
            return node
        direct_owner = direct_machine_bp_word_owner_8616(low, load)
        if direct_owner is not None:
            if not _owner_represents_word_value_8616(direct_owner):
                self._refuse(StackWordLoadRefusalKind8616.VALUE_WIDTH_UNPROVEN, instruction_addrs)
                return node
            value = self._materialized_word_value(direct_owner, instruction_addrs)
            return node if value is None else value
        if not isinstance(low, structured_c.CVariable):
            self._refuse(
                StackWordLoadRefusalKind8616.STACK_PROJECTION_MISMATCH,
                instruction_addrs,
                detail="tagged byte-load recomposition has no canonical BP projection",
            )
            return node
        variable = low.variable
        if not isinstance(variable, SimStackVariable):
            self._refuse(
                StackWordLoadRefusalKind8616.STACK_PROJECTION_MISMATCH,
                instruction_addrs,
            )
            return node
        resolution = resolve_stack_word_load_projection_8616(
            self.codegen, variable, bp_offset=load.displacement, size=load.size
        )
        if not resolution.resolved or resolution.cvar is None:
            self._refuse(
                StackWordLoadRefusalKind8616.STACK_PROJECTION_MISMATCH,
                instruction_addrs,
                detail=(
                    f"expected BP range {(load.displacement, load.size)!r}; "
                    f"resolution={resolution.status.value}: {resolution.detail}"
                ),
            )
            return node
        if not _owner_represents_word_value_8616(resolution.cvar):
            self._refuse(StackWordLoadRefusalKind8616.VALUE_WIDTH_UNPROVEN, instruction_addrs)
            return node
        value = self._materialized_word_value(resolution.cvar, instruction_addrs)
        return node if value is None else value

    def _operand_gates(self, low: object, high: object) -> bool:
        """Refuse captured, side-effectful, or alias-unproven candidates."""
        if any(stack_word_operand_is_captured_value_8616(operand) for operand in (low, high)):
            self._refuse(
                StackWordLoadRefusalKind8616.CAPTURED_VALUE,
                detail="saved scalar bytes have no current-memory value-lifetime proof",
            )
            return False
        if stack_word_load_expression_has_side_effect_8616(high):
            self._refuse(StackWordLoadRefusalKind8616.SIDE_EFFECTFUL_HIGH)
            return False
        if self.source_alias is None:
            self._refuse(StackWordLoadRefusalKind8616.ALIAS_ARTIFACT_UNAVAILABLE)
            return False
        return True

    def transform(self, node: object) -> object:
        """Replace one proven word projection and retain every refusal."""
        projected_owner = stack_word_projection_owner_8616(self.codegen, node)
        if projected_owner is not None:
            self.raw_fact_count += 1
            if not _owner_represents_word_value_8616(projected_owner):
                self._refuse(StackWordLoadRefusalKind8616.VALUE_WIDTH_UNPROVEN)
                return node
            value = self._materialized_word_value(projected_owner)
            return node if value is None else value
        recomposition = recognize_stack_word_recomposition_8616(node)
        if recomposition is None:
            return node
        self.raw_fact_count += 1
        low, high = recomposition.low, recomposition.high
        if not self._operand_gates(low, high):
            return node
        instruction_addrs = instruction_addrs_from_node_8616(high)
        if not instruction_addrs:
            instruction_addrs = instruction_addrs_from_node_8616(node)
        if not instruction_addrs:
            return self._logical_owner(node, low, high)
        if self.index is None:
            assert self.source_alias is not None  # Established by _operand_gates.
            self.index = ensure_instruction_bp_stack_access_index_8616(
                self.codegen,
                self.source_alias,
            )
        load = self._single_load(instruction_addrs)
        if load is None:
            return node
        canonical_owner = self._canonical_owner(load)
        if canonical_owner is not None:
            value = self._materialized_word_value(canonical_owner, instruction_addrs)
            return node if value is None else value
        return self._projected_owner(node, low, high, load, instruction_addrs)


def materialize_stack_word_load_recompositions_8616(
    codegen: object,
    root: object,
) -> StackWordLoadMaterializationResult8616:
    """Materialize only word projections closed by exact Alias evidence."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        source = None
    source_alias = (
        source if isinstance(source, StackMemorySSAAliasArtifact8616) else None
    )
    scan = _StackWordRecomposition8616(codegen=codegen, source_alias=source_alias)
    replaced_root = scan.transform(root)
    _replace_c_children_8616(replaced_root, scan.transform)
    raw_fact_count = scan.raw_fact_count
    materialized_count = scan.materialized_count
    refusals = scan.refusals
    stats = StackWordLoadMaterializationStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
    )
    artifact = StackWordLoadMaterializationArtifact8616(
        source_alias,
        tuple(refusals),
        stats,
    )
    boundary._inertia_stack_word_load_materialization_artifact_8616 = artifact
    if os.environ.get("INERTIA_DEBUG_STACK_FACTS"):
        _LOG.warning(
            "[stack-word-load] function=%s raw=%d classified=%d materialized=%d failures=%d refusals=%r",
            hex(source_alias.function_addr) if source_alias is not None else "unknown",
            stats.raw_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            artifact.refusals,
        )
    return StackWordLoadMaterializationResult8616(replaced_root, artifact)


__all__ = [
    "StackWordLoadMaterializationArtifact8616",
    "StackWordLoadMaterializationResult8616",
    "StackWordLoadMaterializationStats8616",
    "StackWordLoadRefusal8616",
    "StackWordLoadRefusalKind8616",
    "materialize_stack_word_load_recompositions_8616",
]
