"""Validate final global and stack-object storage without repairing output.

Layer: Tail validation.
Responsibility: compare Types/Lowering global storage identity facts with final
structured-C storage, and compare stack-aggregate shape facts with final frame
objects and whole-copy facts with final assignments; report missing, mismatched,
or shadowed objects.
Forbidden: semantic recovery, source/COD/assembly/rendered-C inspection, AST
mutation, name-based storage recovery, or validation-driven output repair.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIndexedVariable,
    CTypeCast,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeArray, TypeRef
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from .c_ast_utils import _iter_c_nodes_deep_8616
from .ir.core import MemSpace
from .lowering.segmented_global_loads import (
    IndexedGlobalStackAggregateCopyFact8616,
    NamedGlobalAggregateTypeFact8616,
    StackAggregateFieldProjectionFact8616,
    indexed_global_stack_aggregate_copy_facts_8616,
    named_global_aggregate_type_facts_8616,
    named_global_aggregate_types_match_8616,
    stack_aggregate_field_projection_facts_8616,
)
from .lowering.stack_aggregate_objects import (
    StackAggregateEvidenceKind8616,
    StackAggregateObjectFact8616,
    stack_aggregate_object_facts_8616,
)
from .lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
)
from .lowering.storage_identity_facts import (
    GlobalStorageIdentityFact8616,
    global_storage_identity_facts_8616,
)
from .pipeline.structured_ast_query_index import StructuredAstQueryIndex8616

log: logging.Logger = logging.getLogger(__name__)

__all__ = [
    "IndexedGlobalStackAggregateCopyIssue8616",
    "IndexedGlobalStackAggregateCopyIssueKind8616",
    "StackAggregateObjectIssue8616",
    "StackAggregateObjectIssueKind8616",
    "StackFieldProjectionIssue8616",
    "StackFieldProjectionIssueKind8616",
    "StorageIdentityIssue8616",
    "StorageIdentityIssueKind8616",
    "StorageIdentityValidationReport8616",
    "validate_storage_identities_8616",
]


class StorageIdentityIssueKind8616(StrEnum):
    """Final storage contradictions detected from typed lowering facts."""

    CONFLICTING_EVIDENCE_WIDTH = "conflicting-evidence-width"
    MISSING_GLOBAL = "missing-global"
    WIDTH_MISMATCH = "width-mismatch"
    LOCAL_SHADOW = "local-shadow"
    UNREPRESENTED_SEGMENT = "unrepresented-segment"


class StackAggregateObjectIssueKind8616(StrEnum):
    """Final stack-object contradictions detected from typed lowering facts."""

    CONFLICTING_EVIDENCE_SHAPE = "conflicting-evidence-shape"
    INVALID_EVIDENCE_SHAPE = "invalid-evidence-shape"
    MISSING_OBJECT = "missing-object"
    WIDTH_MISMATCH = "width-mismatch"
    ELEMENT_STRIDE_MISMATCH = "element-stride-mismatch"


class StackFieldProjectionIssueKind8616(StrEnum):
    """Final stack-field contradictions detected from typed lowering facts."""

    CONFLICTING_EVIDENCE = "conflicting-evidence"
    INVALID_EVIDENCE = "invalid-evidence"
    MISSING_PROJECTION = "missing-projection"
    SOURCE_IDENTITY_MISMATCH = "source-identity-mismatch"
    FIELD_OFFSET_MISMATCH = "field-offset-mismatch"
    STRUCT_TYPE_MISMATCH = "struct-type-mismatch"


class IndexedGlobalStackAggregateCopyIssueKind8616(StrEnum):
    """Final whole-copy contradictions detected from typed Lowering facts."""

    CONFLICTING_EVIDENCE = "conflicting-evidence"
    INVALID_EVIDENCE = "invalid-evidence"
    MISSING_COPY = "missing-copy"
    SOURCE_IDENTITY_MISMATCH = "source-identity-mismatch"
    SOURCE_INDEX_MISMATCH = "source-index-mismatch"
    WIDTH_MISMATCH = "width-mismatch"
    STRUCT_TYPE_MISMATCH = "struct-type-mismatch"


@dataclass(frozen=True, order=True, slots=True)
class StorageIdentityIssue8616:
    """One contradiction between proven storage and the final C variable surface."""

    kind: StorageIdentityIssueKind8616
    space: MemSpace
    offset: int
    expected_width: int
    name: str
    evidence_addrs: tuple[int, ...]
    actual_widths: tuple[int, ...] = ()
    shadow_locations: tuple[str, ...] = ()

    def token(self) -> str:
        """Return a deterministic storage-identity failure fingerprint."""
        evidence = ",".join(f"{addr:#x}" for addr in self.evidence_addrs)
        token = (
            f"storage-identity:{self.kind.value}:space={self.space.value}:"
            f"offset={self.offset:#x}:width={self.expected_width}:"
            f"name={self.name}:evidence={evidence}"
        )
        if self.actual_widths:
            token += ":actual-widths=" + ",".join(
                str(width) for width in self.actual_widths
            )
        if self.shadow_locations:
            token += ":shadows=" + ",".join(self.shadow_locations)
        return token


@dataclass(frozen=True, order=True, slots=True)
class StackAggregateObjectIssue8616:
    """One contradiction between a proven frame object and final C array shape."""

    kind: StackAggregateObjectIssueKind8616
    base_offset: int
    expected_byte_size: int
    expected_element_width: int
    evidence_kind: StackAggregateEvidenceKind8616
    indexed_offsets: tuple[int, ...]
    evidence_shapes: tuple[tuple[int, int], ...] = ()
    actual_shapes: tuple[tuple[int, int, int], ...] = ()

    def token(self) -> str:
        """Return a deterministic stack-object validation fingerprint."""
        indexed = ",".join(f"{offset:+#x}" for offset in self.indexed_offsets)
        token = (
            f"storage-object:{self.kind.value}:space=ss:"
            f"base=BP{self.base_offset:+#x}:bytes={self.expected_byte_size}:"
            f"stride={self.expected_element_width}:"
            f"evidence={self.evidence_kind.value}:indexed={indexed}"
        )
        if self.actual_shapes:
            token += ":actual-shapes=" + ",".join(
                f"{storage_width}/{declared_width}/{element_width}"
                for storage_width, declared_width, element_width in self.actual_shapes
            )
        if self.evidence_shapes:
            token += ":evidence-shapes=" + ",".join(
                f"{byte_size}/{element_width}"
                for byte_size, element_width in self.evidence_shapes
            )
        return token


@dataclass(frozen=True, order=True, slots=True)
class StackFieldProjectionIssue8616:
    """One contradiction between a proven and final stack field projection."""

    kind: StackFieldProjectionIssueKind8616
    source_base: str
    source_offset: int
    destination_base: str
    destination_offset: int
    expected_field_offset: int
    expected_struct_name: str
    evidence_projections: tuple[tuple[int, str], ...] = ()
    actual_projections: tuple[tuple[str, int, int, str], ...] = ()

    def token(self) -> str:
        """Return a deterministic stack field-projection failure fingerprint."""
        token = (
            f"storage-field:{self.kind.value}:"
            f"source={self.source_base}:{self.source_offset:+#x}:"
            f"destination={self.destination_base}:{self.destination_offset:+#x}:"
            f"field={self.expected_field_offset:#x}:"
            f"struct={self.expected_struct_name}"
        )
        if self.evidence_projections:
            token += ":evidence-projections=" + ",".join(
                f"{field_offset:#x}/{struct_name}"
                for field_offset, struct_name in self.evidence_projections
            )
        if self.actual_projections:
            token += ":actual-projections=" + ",".join(
                f"{base}:{offset:+#x}/{field_offset:#x}/{struct_name}"
                for base, offset, field_offset, struct_name in self.actual_projections
            )
        return token


@dataclass(frozen=True, order=True, slots=True)
class IndexedGlobalStackAggregateCopyIssue8616:
    """One contradiction between a proven and final whole aggregate copy."""

    kind: IndexedGlobalStackAggregateCopyIssueKind8616
    source_global_offset: int
    source_index_base: str
    source_index_offset: int
    source_index_adjustment: int
    destination_base: str
    destination_offset: int
    expected_width: int
    expected_struct_name: str
    load_ins_addr: int
    store_ins_addr: int
    evidence_variants: tuple[tuple[int, int, int, int, str], ...] = ()
    actual_copies: tuple[
        tuple[int, str, int, int, int, int, str, str],
        ...,
    ] = ()

    def token(self) -> str:
        """Return a deterministic whole aggregate-copy failure fingerprint."""
        token = (
            f"storage-copy:{self.kind.value}:"
            f"source=ds:{self.source_global_offset:#x}"
            f"[{self.source_index_base}:{self.source_index_offset:+#x}"
            f"{self.source_index_adjustment:+d}]:"
            f"destination={self.destination_base}:{self.destination_offset:+#x}:"
            f"width={self.expected_width}:struct={self.expected_struct_name}:"
            f"evidence={self.load_ins_addr:#x}/{self.store_ins_addr:#x}"
        )
        if self.evidence_variants:
            token += ":evidence-variants=" + ",".join(
                f"{source:#x}/{index:+#x}/{adjustment:+d}/"
                f"{destination:+#x}/{struct_name}"
                for (
                    source,
                    index,
                    adjustment,
                    destination,
                    struct_name,
                ) in self.evidence_variants
            )
        if self.actual_copies:
            token += ":actual-copies=" + ",".join(
                f"ds:{source:#x}[{index_base}:{index_offset:+#x}"
                f"{adjustment:+d}]/{source_width}->{destination_width}/"
                f"{source_struct}/{destination_struct}"
                for (
                    source,
                    index_base,
                    index_offset,
                    adjustment,
                    source_width,
                    destination_width,
                    source_struct,
                    destination_struct,
                ) in self.actual_copies
            )
        return token


type StorageValidationIssue8616 = (
    StorageIdentityIssue8616
    | StackAggregateObjectIssue8616
    | StackFieldProjectionIssue8616
    | IndexedGlobalStackAggregateCopyIssue8616
)


@dataclass(frozen=True, slots=True)
class StorageIdentityValidationReport8616:
    """Closed evidence-loop counters and final storage identity failures."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    issues: tuple[StorageValidationIssue8616, ...] = ()

    @property
    def failure_count(self) -> int:
        """Return the number of final storage contradictions."""
        return len(self.issues)

    @property
    def passed(self) -> bool:
        """Return whether every classified identity exists without contradiction."""
        return (
            self.failure_count == 0
            and self.classified_fact_count == self.materialized_count
        )

    def issue_tokens(self) -> tuple[str, ...]:
        """Return stable issue fingerprints for tail-validation summaries."""
        return tuple(issue.token() for issue in self.issues)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible closed-loop evidence report."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
            "issues": list(self.issue_tokens()),
        }


class _StorageValidationTypeStore8616(Protocol):
    """Third-party angr type store used to validate named aggregate bindings."""

    def __getitem__(self, name: str) -> object:
        """Return one registered function-local type."""
        ...


class _StorageValidationVariableManager8616(Protocol):
    """Third-party variable-manager surface carrying the final type store."""

    types: _StorageValidationTypeStore8616


class _StorageValidationCFunction8616(Protocol):
    """Third-party CFunction containers that may emit variable declarations."""

    arg_list: object
    variables_in_use: object
    unified_local_vars: object
    variable_manager: _StorageValidationVariableManager8616


class _StorageValidationCodegen8616(Protocol):
    """Third-party codegen surface needed to inspect emitted declarations."""

    cfunc: _StorageValidationCFunction8616


class _NamedStorage8616(Protocol):
    """Third-party SimVariable name field used only for emitted-name diagnostics."""

    name: str | None


class _SizedType8616(Protocol):
    """Third-party SimType size field used for final declaration validation."""

    size: int


@dataclass(frozen=True, slots=True)
class _FinalStackFieldProjection8616:
    """One field projection observed in the final structured C AST."""

    source_base: str
    source_offset: int
    field_offset: int
    struct_name: str
    struct_type: SimStruct


@dataclass(frozen=True, slots=True)
class _FinalIndexedGlobalStackAggregateCopy8616:
    """One whole indexed-global-to-stack copy observed in final structured C."""

    source_global_offset: int
    source_global_name: str
    source_index_base: str
    source_index_offset: int
    source_index_adjustment: int
    source_width: int
    destination_width: int
    source_struct_name: str
    destination_struct_name: str
    source_struct_type: SimStruct | None
    destination_struct_type: SimStruct | None


def _iter_container_cvariables_8616(value: object) -> Iterator[CVariable]:
    """Yield C variables from known third-party declaration containers."""
    if isinstance(value, CVariable):
        yield value
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _iter_container_cvariables_8616(item)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_container_cvariables_8616(item)


def _root_cvariables_8616(
    root: object,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> tuple[CVariable, ...]:
    """Collect variables that are referenced by the actual final statement tree."""
    nodes = query_index.nodes if query_index is not None else _iter_c_nodes_deep_8616(root)
    variables = [
        node for node in nodes if isinstance(node, CVariable)
    ]
    unique: dict[int, CVariable] = {}
    for variable in variables:
        unique.setdefault(id(variable), variable)
    return tuple(unique.values())


def _declaration_cvariables_8616(
    codegen: object,
    root_variables: tuple[CVariable, ...],
) -> tuple[CVariable, ...]:
    """Collect root variables plus declaration-producing CFunction containers."""
    variables = list(root_variables)
    surface = cast(_StorageValidationCodegen8616, codegen)
    try:
        cfunc = surface.cfunc
    except AttributeError:
        cfunc = None
    if cfunc is not None:
        for field_name in ("arg_list", "variables_in_use", "unified_local_vars"):
            try:
                value = (
                    cfunc.arg_list
                    if field_name == "arg_list"
                    else cfunc.variables_in_use
                    if field_name == "variables_in_use"
                    else cfunc.unified_local_vars
                )
            except AttributeError:
                continue
            variables.extend(_iter_container_cvariables_8616(value))
    unique: dict[int, CVariable] = {}
    for variable in variables:
        unique.setdefault(id(variable), variable)
    return tuple(unique.values())


def _cvariable_storage_views_8616(node: CVariable) -> tuple[object, ...]:
    """Return direct and unified storage views from an angr C variable."""
    views: list[object] = [node.variable]
    try:
        unified = node.unified_variable
    except AttributeError:
        unified = None
    if unified is not None and unified is not node.variable:
        views.append(unified)
    return tuple(views)


def _cvariable_name_8616(node: CVariable) -> str | None:
    """Return the emitted variable name from the third-party C AST boundary."""
    try:
        name = node.name
    except AttributeError:
        name = None
    if isinstance(name, str) and name:
        return name
    for storage in _cvariable_storage_views_8616(node):
        try:
            storage_name = cast(_NamedStorage8616, storage).name
        except AttributeError:
            continue
        if isinstance(storage_name, str) and storage_name:
            return storage_name
    return None


def _covering_global_cvariables_8616(
    variables: tuple[CVariable, ...],
    offset: int,
    width: int,
) -> tuple[CVariable, ...]:
    """Return final globals whose byte span covers one proven access."""
    access_end = offset + width
    if access_end > 0x10000:
        return ()
    covering: list[CVariable] = []
    for variable in variables:
        for storage in _cvariable_storage_views_8616(variable):
            if not (
                isinstance(storage, SimMemoryVariable)
                and isinstance(storage.addr, int)
                and isinstance(storage.size, int)
            ):
                continue
            if (
                storage.size > 0
                and storage.addr <= offset
                and access_end <= storage.addr + storage.size
            ):
                covering.append(variable)
                break
    return tuple(covering)


def _global_storage_candidate_widths_8616(
    variables: tuple[CVariable, ...],
    offset: int,
) -> tuple[int, ...]:
    """Return widths of final globals that contain the access start byte."""
    widths = {
        storage.size
        for variable in variables
        for storage in _cvariable_storage_views_8616(variable)
        if isinstance(storage, SimMemoryVariable)
        and isinstance(storage.addr, int)
        and isinstance(storage.size, int)
        and storage.size > 0
        and storage.addr <= offset < storage.addr + storage.size
    }
    return tuple(sorted(widths))


def _covering_global_names_8616(
    variables: tuple[CVariable, ...],
) -> tuple[str, ...]:
    """Return emitted names for final globals that cover one access."""
    return tuple(
        sorted(
            {
                name
                for variable in variables
                if (name := _cvariable_name_8616(variable)) is not None
            }
        )
    )


def _local_storage_location_8616(node: CVariable) -> str | None:
    """Return a stable local-storage token for shadow diagnostics."""
    for storage in _cvariable_storage_views_8616(node):
        if isinstance(storage, SimStackVariable):
            return f"SS:BP{storage.offset:+#x}:size{storage.size}"
        if (
            isinstance(storage, SimMemoryVariable)
            and isinstance(storage.addr, int)
            and storage.addr < 0
        ):
            return f"SS:BP{storage.addr:+#x}:size{storage.size}"
    return None


def _shadow_locations_8616(
    variables: tuple[CVariable, ...],
    name: str,
) -> tuple[str, ...]:
    """Return local storage declarations that shadow one proven global name."""
    locations = {
        location
        for variable in variables
        if _cvariable_name_8616(variable) == name
        if (location := _local_storage_location_8616(variable)) is not None
    }
    return tuple(sorted(locations))


def _normalized_facts_8616(
    facts: tuple[GlobalStorageIdentityFact8616, ...],
) -> tuple[GlobalStorageIdentityFact8616, ...]:
    """Deduplicate exact facts while preserving deterministic order."""
    return tuple(dict.fromkeys(facts))


def _normalized_stack_aggregate_facts_8616(
    facts: tuple[StackAggregateObjectFact8616, ...],
) -> tuple[StackAggregateObjectFact8616, ...]:
    """Deduplicate exact stack-object facts while preserving deterministic order."""
    return tuple(dict.fromkeys(facts))


def _normalized_stack_field_projection_facts_8616(
    facts: tuple[StackAggregateFieldProjectionFact8616, ...],
) -> tuple[StackAggregateFieldProjectionFact8616, ...]:
    """Deduplicate exact stack field facts while preserving deterministic order."""
    return tuple(dict.fromkeys(facts))


def _normalized_indexed_global_stack_copy_facts_8616(
    facts: tuple[IndexedGlobalStackAggregateCopyFact8616, ...],
) -> tuple[IndexedGlobalStackAggregateCopyFact8616, ...]:
    """Deduplicate exact whole-copy facts while preserving deterministic order."""
    return tuple(dict.fromkeys(facts))


def _stack_storage_matches_8616(
    codegen: object,
    variable: CVariable,
    *,
    base: str,
    offset: int,
) -> bool:
    """Return whether one final C variable has the exact stack identity."""
    return any(
        isinstance(storage, SimStackVariable)
        and storage.base == base
        and machine_bp_offset_for_stack_variable_8616(codegen, storage) == offset
        for storage in _cvariable_storage_views_8616(variable)
    )


def _strip_type_casts_8616(expression: object) -> object:
    """Return the value under any final structured type casts."""
    while isinstance(expression, CTypeCast):
        expression = expression.expr
    return expression


def _struct_name_8616(struct_type: object) -> str:
    """Return a stable diagnostic name for one typed struct."""
    if not isinstance(struct_type, SimStruct):
        return f"<invalid-{type(struct_type).__name__}>"
    return (
        struct_type.name
        if isinstance(struct_type.name, str) and struct_type.name
        else "<anonymous>"
    )


def _final_stack_field_projections_8616(
    codegen: object,
    nodes: Iterable[object],
    fact: StackAggregateFieldProjectionFact8616,
) -> tuple[_FinalStackFieldProjection8616, ...]:
    """Return final field projections assigned to the fact destination."""
    projections: set[_FinalStackFieldProjection8616] = set()
    for node in nodes:
        if (
            not isinstance(node, CAssignment)
            or not isinstance(node.lhs, CVariable)
            or not _stack_storage_matches_8616(
                codegen,
                node.lhs,
                base=fact.destination_base,
                offset=fact.destination_offset,
            )
        ):
            continue
        rhs = _strip_type_casts_8616(node.rhs)
        if not isinstance(rhs, CVariableField) or not isinstance(
            rhs.variable,
            CVariable,
        ):
            continue
        source_storage = next(
            (
                storage
                for storage in _cvariable_storage_views_8616(rhs.variable)
                if isinstance(storage, SimStackVariable)
                and isinstance(storage.base, str)
                and isinstance(storage.offset, int)
            ),
            None,
        )
        if source_storage is None or not isinstance(rhs.field.struct_type, SimStruct):
            continue
        source_base = source_storage.base
        source_offset = (
            machine_bp_offset_for_stack_variable_8616(codegen, source_storage)
            if source_base == "bp"
            else source_storage.offset
        )
        if not isinstance(source_base, str) or not isinstance(source_offset, int):
            continue
        projections.add(
            _FinalStackFieldProjection8616(
                source_base=source_base,
                source_offset=source_offset,
                field_offset=rhs.field.offset,
                struct_name=_struct_name_8616(rhs.field.struct_type),
                struct_type=rhs.field.struct_type,
            )
        )
    return tuple(
        sorted(
            projections,
            key=lambda projection: (
                projection.source_base,
                projection.source_offset,
                projection.field_offset,
                projection.struct_name,
            ),
        )
    )


def _stack_field_projection_fact_is_valid_8616(
    fact: StackAggregateFieldProjectionFact8616,
) -> bool:
    """Return whether one lowering fact has exact BP-local identities."""
    return (
        fact.source_base == "bp"
        and fact.destination_base == "bp"
        and fact.source_offset < 0
        and fact.destination_offset < 0
        and fact.field_offset >= 0
        and isinstance(fact.struct_type, SimStruct)
    )


def _stack_field_projection_issue_8616(
    fact: StackAggregateFieldProjectionFact8616,
    kind: StackFieldProjectionIssueKind8616,
    *,
    evidence_projections: tuple[tuple[int, str], ...] = (),
    actual: tuple[_FinalStackFieldProjection8616, ...] = (),
) -> StackFieldProjectionIssue8616:
    """Build one stable field-projection validation issue."""
    return StackFieldProjectionIssue8616(
        kind=kind,
        source_base=fact.source_base,
        source_offset=fact.source_offset,
        destination_base=fact.destination_base,
        destination_offset=fact.destination_offset,
        expected_field_offset=fact.field_offset,
        expected_struct_name=_struct_name_8616(fact.struct_type),
        evidence_projections=evidence_projections,
        actual_projections=tuple(
            (
                projection.source_base,
                projection.source_offset,
                projection.field_offset,
                projection.struct_name,
            )
            for projection in actual
        ),
    )


def _resolved_struct_type_8616(type_value: object) -> SimStruct | None:
    """Resolve a final direct or named-reference struct type."""
    resolved = type_value.type if isinstance(type_value, TypeRef) else type_value
    return resolved if isinstance(resolved, SimStruct) else None


def _registered_named_global_copy_type_matches_8616(
    codegen: object,
    fact: IndexedGlobalStackAggregateCopyFact8616,
    copy: _FinalIndexedGlobalStackAggregateCopy8616,
    named_global_facts: tuple[NamedGlobalAggregateTypeFact8616, ...],
) -> bool:
    """Validate an untyped indexed node through its exact registered global type."""
    matching_facts = tuple(
        named_fact
        for named_fact in named_global_facts
        if named_fact.global_name == copy.source_global_name
        and named_fact.struct_type == fact.struct_type
        and isinstance(named_fact.array_len, int)
        and named_fact.array_len > 0
    )
    struct_name = fact.struct_type.name
    if len(matching_facts) != 1 or not isinstance(struct_name, str) or not struct_name:
        if os.environ.get("INERTIA_DEBUG_VALIDATION_STORAGE") == "1":
            log.warning(
                "registered aggregate-copy type refused matching_facts=%r "
                "struct_name=%r source_name=%r",
                matching_facts,
                struct_name,
                copy.source_global_name,
            )
        return False
    surface = cast(_StorageValidationCodegen8616, codegen)
    try:
        registered_type = surface.cfunc.variable_manager.types[struct_name]
    except (AttributeError, KeyError, TypeError) as error:
        if os.environ.get("INERTIA_DEBUG_VALIDATION_STORAGE") == "1":
            log.warning(
                "registered aggregate-copy type lookup refused struct=%r "
                "error=%r",
                struct_name,
                error,
            )
        return False
    matched = named_global_aggregate_types_match_8616(
        _resolved_struct_type_8616(registered_type),
        fact.struct_type,
    )
    if not matched and os.environ.get("INERTIA_DEBUG_VALIDATION_STORAGE") == "1":
        log.warning(
            "registered aggregate-copy type mismatch registered=%r expected=%r",
            registered_type,
            fact.struct_type,
        )
    return bool(matched)


def _final_stack_index_identity_8616(
    codegen: object,
    expression: object,
) -> tuple[str, int, int] | None:
    """Return one final BP-stack index identity and logical adjustment."""
    if isinstance(expression, CTypeCast):
        return _final_stack_index_identity_8616(codegen, expression.expr)
    if isinstance(expression, CVariable):
        storage = next(
            (
                candidate
                for candidate in _cvariable_storage_views_8616(expression)
                if isinstance(candidate, SimStackVariable)
                and isinstance(candidate.base, str)
                and isinstance(candidate.offset, int)
            ),
            None,
        )
        if storage is None:
            return None
        storage_base = storage.base
        storage_offset = (
            machine_bp_offset_for_stack_variable_8616(codegen, storage)
            if storage_base == "bp"
            else storage.offset
        )
        if not isinstance(storage_base, str) or not isinstance(storage_offset, int):
            return None
        return storage_base, storage_offset, 0
    if not isinstance(expression, CBinaryOp) or expression.op not in {"Add", "Sub"}:
        return None
    base = _final_stack_index_identity_8616(codegen, expression.lhs)
    if base is None or not isinstance(expression.rhs, CConstant):
        return None
    amount = expression.rhs.value
    if not isinstance(amount, int):
        return None
    base_name, base_offset, adjustment = base
    return (
        base_name,
        base_offset,
        adjustment + amount if expression.op == "Add" else adjustment - amount,
    )


def _final_indexed_global_stack_copies_8616(
    codegen: object,
    nodes: Iterable[object],
    fact: IndexedGlobalStackAggregateCopyFact8616,
) -> tuple[_FinalIndexedGlobalStackAggregateCopy8616, ...]:
    """Return final whole copies assigned to the exact fact destination."""
    copies: set[_FinalIndexedGlobalStackAggregateCopy8616] = set()
    for node in nodes:
        if (
            not isinstance(node, CAssignment)
            or not isinstance(node.lhs, CVariable)
            or not _stack_storage_matches_8616(
                codegen,
                node.lhs,
                base=fact.destination_base,
                offset=fact.destination_offset,
            )
        ):
            continue
        rhs = _strip_type_casts_8616(node.rhs)
        if not isinstance(rhs, CIndexedVariable) or not isinstance(
            rhs.variable,
            CVariable,
        ):
            continue
        source_storage = next(
            (
                storage
                for storage in _cvariable_storage_views_8616(rhs.variable)
                if isinstance(storage, SimMemoryVariable)
                and isinstance(storage.addr, int)
                and isinstance(storage.size, int)
            ),
            None,
        )
        destination_storage = next(
            (
                storage
                for storage in _cvariable_storage_views_8616(node.lhs)
                if isinstance(storage, SimStackVariable)
                and storage.base == fact.destination_base
                and machine_bp_offset_for_stack_variable_8616(codegen, storage)
                == fact.destination_offset
                and isinstance(storage.size, int)
            ),
            None,
        )
        index_identity = _final_stack_index_identity_8616(codegen, rhs.index)
        if (
            source_storage is None
            or destination_storage is None
            or index_identity is None
        ):
            continue
        try:
            source_type = rhs.type
        except AttributeError:
            source_type = None
        if _resolved_struct_type_8616(source_type) is None:
            try:
                source_type = rhs.variable.type
            except AttributeError:
                source_type = None
        try:
            destination_type = node.lhs.type
        except AttributeError:
            destination_type = None
        source_struct = _resolved_struct_type_8616(source_type)
        destination_struct = _resolved_struct_type_8616(destination_type)
        index_base, index_offset, index_adjustment = index_identity
        copies.add(
            _FinalIndexedGlobalStackAggregateCopy8616(
                source_global_offset=source_storage.addr & 0xFFFF,
                source_global_name=(
                    source_storage.name
                    if isinstance(source_storage.name, str)
                    else ""
                ),
                source_index_base=index_base,
                source_index_offset=index_offset,
                source_index_adjustment=index_adjustment,
                source_width=source_storage.size,
                destination_width=destination_storage.size,
                source_struct_name=_struct_name_8616(source_struct),
                destination_struct_name=_struct_name_8616(destination_struct),
                source_struct_type=source_struct,
                destination_struct_type=destination_struct,
            )
        )
    return tuple(
        sorted(
            copies,
            key=lambda copy: (
                copy.source_global_offset,
                copy.source_global_name,
                copy.source_index_base,
                copy.source_index_offset,
                copy.source_index_adjustment,
                copy.source_width,
                copy.destination_width,
                copy.source_struct_name,
                copy.destination_struct_name,
            ),
        )
    )


def _indexed_global_stack_copy_fact_is_valid_8616(
    fact: IndexedGlobalStackAggregateCopyFact8616,
) -> bool:
    """Return whether one whole-copy fact has exact representable identities."""
    return (
        0 <= fact.source_global_offset <= 0xFFFF
        and fact.source_index_base == "bp"
        and fact.source_index_offset < 0
        and fact.destination_base == "bp"
        and fact.destination_offset < 0
        and fact.width > 0
        and isinstance(fact.struct_type, SimStruct)
        and fact.load_ins_addr >= 0
        and fact.store_ins_addr >= 0
    )


def _indexed_global_stack_copy_issue_8616(
    fact: IndexedGlobalStackAggregateCopyFact8616,
    kind: IndexedGlobalStackAggregateCopyIssueKind8616,
    *,
    evidence_variants: tuple[tuple[int, int, int, int, str], ...] = (),
    actual: tuple[_FinalIndexedGlobalStackAggregateCopy8616, ...] = (),
) -> IndexedGlobalStackAggregateCopyIssue8616:
    """Build one stable whole aggregate-copy validation issue."""
    return IndexedGlobalStackAggregateCopyIssue8616(
        kind=kind,
        source_global_offset=fact.source_global_offset,
        source_index_base=fact.source_index_base,
        source_index_offset=fact.source_index_offset,
        source_index_adjustment=fact.source_index_adjustment,
        destination_base=fact.destination_base,
        destination_offset=fact.destination_offset,
        expected_width=fact.width,
        expected_struct_name=_struct_name_8616(fact.struct_type),
        load_ins_addr=fact.load_ins_addr,
        store_ins_addr=fact.store_ins_addr,
        evidence_variants=evidence_variants,
        actual_copies=tuple(
            (
                copy.source_global_offset,
                copy.source_index_base,
                copy.source_index_offset,
                copy.source_index_adjustment,
                copy.source_width,
                copy.destination_width,
                copy.source_struct_name,
                copy.destination_struct_name,
            )
            for copy in actual
        ),
    )


def _type_width_bytes_8616(type_value: object) -> int:
    """Return a final third-party C type width in bytes, or zero if unavailable."""
    try:
        bits = cast(_SizedType8616, type_value).size
    except (AttributeError, ValueError):
        return 0
    if not isinstance(bits, int) or bits <= 0 or bits % 8:
        return 0
    return bits // 8


def _stack_aggregate_candidate_shapes_8616(
    codegen: object,
    variables: tuple[CVariable, ...],
    base_offset: int,
) -> tuple[tuple[int, int, int], ...]:
    """Return final ``storage/declared/element`` widths at one BP-local base."""
    shapes: set[tuple[int, int, int]] = set()
    for variable in variables:
        stack_views = tuple(
            storage
            for storage in _cvariable_storage_views_8616(variable)
            if isinstance(storage, SimStackVariable)
            and storage.base == "bp"
            and machine_bp_offset_for_stack_variable_8616(codegen, storage)
            == base_offset
            and isinstance(storage.size, int)
            and storage.size > 0
        )
        if not stack_views:
            continue
        try:
            variable_type = variable.type
        except AttributeError:
            variable_type = None
        declared_width = _type_width_bytes_8616(variable_type)
        element_width = 0
        if isinstance(variable_type, SimTypeArray):
            element_width = _type_width_bytes_8616(variable_type.elem_type)
        for storage in stack_views:
            shapes.add((storage.size, declared_width, element_width))
    return tuple(sorted(shapes))


def _stack_aggregate_fact_is_valid_8616(
    fact: StackAggregateObjectFact8616,
) -> bool:
    """Return whether an owned stack-object fact has a representable array shape."""
    return (
        fact.base_offset < 0
        and fact.byte_size > 0
        and fact.element_width in {1, 2, 4}
        and fact.byte_size % fact.element_width == 0
    )

def validate_storage_identities_8616(
    codegen: object,
    root: object,
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> StorageIdentityValidationReport8616:
    """Compare typed global and stack-object facts with final C storage."""
    if query_index is not None:
        query_index.require_root(root)
    raw_global_facts = global_storage_identity_facts_8616(codegen)
    global_facts = _normalized_facts_8616(raw_global_facts)
    raw_stack_facts = stack_aggregate_object_facts_8616(codegen)
    stack_facts = _normalized_stack_aggregate_facts_8616(raw_stack_facts)
    raw_field_facts = stack_aggregate_field_projection_facts_8616(codegen)
    field_facts = _normalized_stack_field_projection_facts_8616(
        raw_field_facts,
    )
    raw_copy_facts = indexed_global_stack_aggregate_copy_facts_8616(codegen)
    copy_facts = _normalized_indexed_global_stack_copy_facts_8616(
        raw_copy_facts,
    )
    named_global_facts = named_global_aggregate_type_facts_8616(codegen)
    query_index = query_index or StructuredAstQueryIndex8616.build(root)
    root_variables = _root_cvariables_8616(root, query_index)
    run = _StorageValidationRun8616(
        codegen=codegen,
        nodes=query_index.nodes,
        root_variables=root_variables,
        declaration_variables=_declaration_cvariables_8616(
            codegen,
            root_variables,
        ),
        named_global_facts=named_global_facts,
    )
    run.global_facts_phase(global_facts)
    run.stack_facts_phase(stack_facts)
    run.field_facts_phase(field_facts)
    run.copy_facts_phase(copy_facts)

    report = StorageIdentityValidationReport8616(
        raw_fact_count=(
            len(raw_global_facts)
            + len(raw_stack_facts)
            + len(raw_field_facts)
            + len(raw_copy_facts)
        ),
        normalized_fact_count=(
            len(global_facts)
            + len(stack_facts)
            + len(field_facts)
            + len(copy_facts)
        ),
        classified_fact_count=run.classified_fact_count,
        materialized_count=run.materialized_count,
        issues=tuple(sorted(run.issues, key=lambda issue: issue.token())),
    )
    if os.environ.get("INERTIA_DEBUG_VALIDATION_STORAGE") == "1":
        log.warning(
            "storage validation copy_facts=%r final_copies=%r "
            "named_global_facts=%r issues=%r counters=%r",
            copy_facts,
            tuple(
                (fact, _final_indexed_global_stack_copies_8616(codegen, run.nodes, fact))
                for fact in copy_facts
            ),
            named_global_facts,
            report.issue_tokens(),
            report.to_dict(),
        )
    return report


@dataclass(slots=True)
class _StorageValidationRun8616:
    """Shared context and issue counters for storage-identity validation."""

    codegen: object
    nodes: object
    root_variables: tuple[CVariable, ...]
    declaration_variables: tuple[CVariable, ...]
    named_global_facts: tuple[object, ...]
    issues: list[StorageValidationIssue8616] = field(default_factory=list)
    classified_fact_count: int = 0
    materialized_count: int = 0

    def global_facts_phase(
        self,
        global_facts: tuple[GlobalStorageIdentityFact8616, ...],
    ) -> None:
        """Compare normalized global facts against final DS globals."""
        conflicting_keys: set[tuple[object, ...]] = set()
        facts_by_evidence: dict[
            tuple[MemSpace, int, int, object], list[GlobalStorageIdentityFact8616]
        ] = {}
        for fact in global_facts:
            facts_by_evidence.setdefault(
                (fact.space, fact.offset, fact.evidence_addr, fact.kind), []
            ).append(fact)
        for evidence_key, evidence_facts in facts_by_evidence.items():
            widths = tuple(sorted({fact.width for fact in evidence_facts}))
            if len(widths) <= 1:
                continue
            conflicting_keys.add(evidence_key)
            self.classified_fact_count += len(evidence_facts)
            representative = min(evidence_facts, key=lambda fact: (fact.width, fact.name))
            self.issues.append(
                StorageIdentityIssue8616(
                    kind=StorageIdentityIssueKind8616.CONFLICTING_EVIDENCE_WIDTH,
                    space=representative.space,
                    offset=representative.offset,
                    expected_width=representative.width,
                    name=representative.name,
                    evidence_addrs=(representative.evidence_addr,),
                    actual_widths=widths,
                )
            )
        for fact in global_facts:
            self._global_fact(fact, conflicting_keys)

    def _global_fact(
        self,
        fact: GlobalStorageIdentityFact8616,
        conflicting_keys: set[tuple[object, ...]],
    ) -> None:
        """Classify one global storage fact against the final globals."""
        evidence_key = (fact.space, fact.offset, fact.evidence_addr, fact.kind)
        if evidence_key in conflicting_keys:
            return
        self.classified_fact_count += 1
        evidence_addrs = (fact.evidence_addr,)
        if fact.space is not MemSpace.DS:
            self.issues.append(
                StorageIdentityIssue8616(
                    kind=StorageIdentityIssueKind8616.UNREPRESENTED_SEGMENT,
                    space=fact.space,
                    offset=fact.offset,
                    expected_width=fact.width,
                    name=fact.name,
                    evidence_addrs=evidence_addrs,
                )
            )
            return

        covering_globals = _covering_global_cvariables_8616(
            self.root_variables,
            fact.offset,
            fact.width,
        )
        actual_widths = _global_storage_candidate_widths_8616(
            self.root_variables,
            fact.offset,
        )
        if covering_globals:
            self.materialized_count += 1
        elif actual_widths:
            self.issues.append(
                StorageIdentityIssue8616(
                    kind=StorageIdentityIssueKind8616.WIDTH_MISMATCH,
                    space=fact.space,
                    offset=fact.offset,
                    expected_width=fact.width,
                    name=fact.name,
                    evidence_addrs=evidence_addrs,
                    actual_widths=actual_widths,
                )
            )
        else:
            self.issues.append(
                StorageIdentityIssue8616(
                    kind=StorageIdentityIssueKind8616.MISSING_GLOBAL,
                    space=fact.space,
                    offset=fact.offset,
                    expected_width=fact.width,
                    name=fact.name,
                    evidence_addrs=evidence_addrs,
                )
            )

        shadow_names = {
            fact.name,
            *_covering_global_names_8616(covering_globals),
        }
        shadow_locations = tuple(
            sorted(
                {
                    location
                    for shadow_name in shadow_names
                    for location in _shadow_locations_8616(
                        self.declaration_variables,
                        shadow_name,
                    )
                }
            )
        )
        if shadow_locations:
            self.issues.append(
                StorageIdentityIssue8616(
                    kind=StorageIdentityIssueKind8616.LOCAL_SHADOW,
                    space=fact.space,
                    offset=fact.offset,
                    expected_width=fact.width,
                    name=fact.name,
                    evidence_addrs=evidence_addrs,
                    shadow_locations=shadow_locations,
                )
            )

    def stack_facts_phase(
        self,
        stack_facts: tuple[StackAggregateObjectFact8616, ...],
    ) -> None:
        """Compare normalized stack-aggregate facts against final locals."""
        conflicting_stack_bases: set[int] = set()
        stack_facts_by_base: dict[int, list[StackAggregateObjectFact8616]] = {}
        for stack_fact in stack_facts:
            stack_facts_by_base.setdefault(stack_fact.base_offset, []).append(stack_fact)
        for base_offset, base_facts in stack_facts_by_base.items():
            shapes = {
                (stack_fact.byte_size, stack_fact.element_width)
                for stack_fact in base_facts
            }
            if len(shapes) <= 1:
                continue
            conflicting_stack_bases.add(base_offset)
            self.classified_fact_count += len(base_facts)
            stack_representative = min(
                base_facts,
                key=lambda fact: (
                    fact.byte_size,
                    fact.element_width,
                    fact.evidence_kind.value,
                    fact.indexed_offsets,
                ),
            )
            self.issues.append(
                StackAggregateObjectIssue8616(
                    kind=StackAggregateObjectIssueKind8616.CONFLICTING_EVIDENCE_SHAPE,
                    base_offset=stack_representative.base_offset,
                    expected_byte_size=stack_representative.byte_size,
                    expected_element_width=stack_representative.element_width,
                    evidence_kind=stack_representative.evidence_kind,
                    indexed_offsets=stack_representative.indexed_offsets,
                    evidence_shapes=tuple(sorted(shapes)),
                )
            )
        for stack_fact in stack_facts:
            self._stack_fact(stack_fact, conflicting_stack_bases)

    def _stack_fact(
        self,
        stack_fact: StackAggregateObjectFact8616,
        conflicting_stack_bases: set[int],
    ) -> None:
        """Classify one stack-aggregate fact against the final locals."""
        if stack_fact.base_offset in conflicting_stack_bases:
            return
        self.classified_fact_count += 1
        if not _stack_aggregate_fact_is_valid_8616(stack_fact):
            self.issues.append(
                StackAggregateObjectIssue8616(
                    kind=StackAggregateObjectIssueKind8616.INVALID_EVIDENCE_SHAPE,
                    base_offset=stack_fact.base_offset,
                    expected_byte_size=stack_fact.byte_size,
                    expected_element_width=stack_fact.element_width,
                    evidence_kind=stack_fact.evidence_kind,
                    indexed_offsets=stack_fact.indexed_offsets,
                )
            )
            return
        actual_shapes = _stack_aggregate_candidate_shapes_8616(
            self.codegen,
            self.root_variables,
            stack_fact.base_offset,
        )
        matching_width_shapes = tuple(
            shape
            for shape in actual_shapes
            if shape[1] == stack_fact.byte_size
        )
        if any(
            shape[2] == stack_fact.element_width
            for shape in matching_width_shapes
        ):
            self.materialized_count += 1
            return
        if not actual_shapes:
            issue_kind = StackAggregateObjectIssueKind8616.MISSING_OBJECT
        elif not matching_width_shapes:
            issue_kind = StackAggregateObjectIssueKind8616.WIDTH_MISMATCH
        else:
            issue_kind = StackAggregateObjectIssueKind8616.ELEMENT_STRIDE_MISMATCH
        self.issues.append(
            StackAggregateObjectIssue8616(
                kind=issue_kind,
                base_offset=stack_fact.base_offset,
                expected_byte_size=stack_fact.byte_size,
                expected_element_width=stack_fact.element_width,
                evidence_kind=stack_fact.evidence_kind,
                indexed_offsets=stack_fact.indexed_offsets,
                actual_shapes=actual_shapes,
            )
        )

    def field_facts_phase(
        self,
        field_facts: tuple[StackAggregateFieldProjectionFact8616, ...],
    ) -> None:
        """Compare normalized field-projection facts against final locals."""
        conflicting_field_identities: set[tuple[str, int, str, int]] = set()
        field_facts_by_identity: dict[
            tuple[str, int, str, int],
            list[StackAggregateFieldProjectionFact8616],
        ] = {}
        for field_fact in field_facts:
            identity = (
                field_fact.source_base,
                field_fact.source_offset,
                field_fact.destination_base,
                field_fact.destination_offset,
            )
            field_facts_by_identity.setdefault(identity, []).append(field_fact)
        for identity, identity_facts in field_facts_by_identity.items():
            field_variants = {
                (
                    fact.field_offset,
                    fact.struct_type,
                    fact.cast_source_type,
                    fact.cast_destination_type,
                )
                for fact in identity_facts
            }
            if len(field_variants) <= 1:
                continue
            conflicting_field_identities.add(identity)
            self.classified_fact_count += len(identity_facts)
            field_representative = min(
                identity_facts,
                key=lambda fact: (
                    fact.field_offset,
                    _struct_name_8616(fact.struct_type),
                ),
            )
            self.issues.append(
                _stack_field_projection_issue_8616(
                    field_representative,
                    StackFieldProjectionIssueKind8616.CONFLICTING_EVIDENCE,
                    evidence_projections=tuple(
                        sorted(
                            {
                                (
                                    fact.field_offset,
                                    _struct_name_8616(fact.struct_type),
                                )
                                for fact in identity_facts
                            }
                        )
                    ),
                )
            )
        for field_fact in field_facts:
            self._field_fact(field_fact, conflicting_field_identities)

    def _field_fact(
        self,
        field_fact: StackAggregateFieldProjectionFact8616,
        conflicting_field_identities: set[tuple[str, int, str, int]],
    ) -> None:
        """Classify one field-projection fact against final locals."""
        identity = (
            field_fact.source_base,
            field_fact.source_offset,
            field_fact.destination_base,
            field_fact.destination_offset,
        )
        if identity in conflicting_field_identities:
            return
        self.classified_fact_count += 1
        if not _stack_field_projection_fact_is_valid_8616(field_fact):
            self.issues.append(
                _stack_field_projection_issue_8616(
                    field_fact,
                    StackFieldProjectionIssueKind8616.INVALID_EVIDENCE,
                )
            )
            return
        actual = _final_stack_field_projections_8616(self.codegen, self.nodes, field_fact)
        if not actual:
            self.issues.append(
                _stack_field_projection_issue_8616(
                    field_fact,
                    StackFieldProjectionIssueKind8616.MISSING_PROJECTION,
                )
            )
            return
        source_matches = tuple(
            projection
            for projection in actual
            if projection.source_base == field_fact.source_base
            and projection.source_offset == field_fact.source_offset
        )
        if not source_matches:
            self.issues.append(
                _stack_field_projection_issue_8616(
                    field_fact,
                    StackFieldProjectionIssueKind8616.SOURCE_IDENTITY_MISMATCH,
                    actual=actual,
                )
            )
            return
        field_matches = tuple(
            projection
            for projection in source_matches
            if projection.field_offset == field_fact.field_offset
        )
        if not field_matches:
            self.issues.append(
                _stack_field_projection_issue_8616(
                    field_fact,
                    StackFieldProjectionIssueKind8616.FIELD_OFFSET_MISMATCH,
                    actual=source_matches,
                )
            )
            return
        if not any(
            projection.struct_type == field_fact.struct_type
            for projection in field_matches
        ):
            self.issues.append(
                _stack_field_projection_issue_8616(
                    field_fact,
                    StackFieldProjectionIssueKind8616.STRUCT_TYPE_MISMATCH,
                    actual=field_matches,
                )
            )
            return
        self.materialized_count += 1

    def copy_facts_phase(
        self,
        copy_facts: tuple[IndexedGlobalStackAggregateCopyFact8616, ...],
    ) -> None:
        """Compare normalized whole-copy facts against final copies."""
        conflicting_copy_evidence: set[tuple[int, int]] = set()
        copy_facts_by_evidence: dict[
            tuple[int, int],
            list[IndexedGlobalStackAggregateCopyFact8616],
        ] = {}
        for copy_fact in copy_facts:
            copy_facts_by_evidence.setdefault(
                (copy_fact.load_ins_addr, copy_fact.store_ins_addr),
                [],
            ).append(copy_fact)
        for evidence_identity, copy_evidence_facts in copy_facts_by_evidence.items():
            copy_variants = {
                (
                    copy_evidence_fact.source_global_offset,
                    copy_evidence_fact.source_index_base,
                    copy_evidence_fact.source_index_offset,
                    copy_evidence_fact.source_index_adjustment,
                    copy_evidence_fact.destination_base,
                    copy_evidence_fact.destination_offset,
                    copy_evidence_fact.width,
                    copy_evidence_fact.struct_type,
                )
                for copy_evidence_fact in copy_evidence_facts
            }
            if len(copy_variants) <= 1:
                continue
            conflicting_copy_evidence.add(evidence_identity)
            self.classified_fact_count += len(copy_evidence_facts)
            copy_representative = min(
                copy_evidence_facts,
                key=lambda copy_evidence_fact: (
                    copy_evidence_fact.source_global_offset,
                    copy_evidence_fact.source_index_offset,
                    copy_evidence_fact.source_index_adjustment,
                    copy_evidence_fact.destination_offset,
                    copy_evidence_fact.width,
                    _struct_name_8616(copy_evidence_fact.struct_type),
                ),
            )
            self.issues.append(
                _indexed_global_stack_copy_issue_8616(
                    copy_representative,
                    IndexedGlobalStackAggregateCopyIssueKind8616.CONFLICTING_EVIDENCE,
                    evidence_variants=tuple(
                        sorted(
                            {
                                (
                                    copy_evidence_fact.source_global_offset,
                                    copy_evidence_fact.source_index_offset,
                                    copy_evidence_fact.source_index_adjustment,
                                    copy_evidence_fact.destination_offset,
                                    _struct_name_8616(copy_evidence_fact.struct_type),
                                )
                                for copy_evidence_fact in copy_evidence_facts
                            }
                        )
                    ),
                )
            )
        for copy_fact in copy_facts:
            self._copy_fact(copy_fact, conflicting_copy_evidence)

    def _copy_fact(
        self,
        copy_fact: IndexedGlobalStackAggregateCopyFact8616,
        conflicting_copy_evidence: set[tuple[int, int]],
    ) -> None:
        """Classify one indexed whole-copy fact against final copies."""
        evidence_identity = (copy_fact.load_ins_addr, copy_fact.store_ins_addr)
        if evidence_identity in conflicting_copy_evidence:
            return
        self.classified_fact_count += 1
        if not _indexed_global_stack_copy_fact_is_valid_8616(copy_fact):
            self.issues.append(
                _indexed_global_stack_copy_issue_8616(
                    copy_fact,
                    IndexedGlobalStackAggregateCopyIssueKind8616.INVALID_EVIDENCE,
                )
            )
            return
        copy_actual = _final_indexed_global_stack_copies_8616(
            self.codegen, self.nodes, copy_fact
        )
        if not copy_actual:
            self.issues.append(
                _indexed_global_stack_copy_issue_8616(
                    copy_fact,
                    IndexedGlobalStackAggregateCopyIssueKind8616.MISSING_COPY,
                )
            )
            return
        copy_source_matches = tuple(
            copy
            for copy in copy_actual
            if copy.source_global_offset == copy_fact.source_global_offset
        )
        if not copy_source_matches:
            self.issues.append(
                _indexed_global_stack_copy_issue_8616(
                    copy_fact,
                    IndexedGlobalStackAggregateCopyIssueKind8616.SOURCE_IDENTITY_MISMATCH,
                    actual=copy_actual,
                )
            )
            return
        copy_index_matches = tuple(
            copy
            for copy in copy_source_matches
            if copy.source_index_base == copy_fact.source_index_base
            and copy.source_index_offset == copy_fact.source_index_offset
            and copy.source_index_adjustment
            == copy_fact.source_index_adjustment
        )
        if not copy_index_matches:
            self.issues.append(
                _indexed_global_stack_copy_issue_8616(
                    copy_fact,
                    IndexedGlobalStackAggregateCopyIssueKind8616.SOURCE_INDEX_MISMATCH,
                    actual=copy_source_matches,
                )
            )
            return
        copy_width_matches = tuple(
            copy
            for copy in copy_index_matches
            if copy.source_width == copy_fact.width
            and copy.destination_width == copy_fact.width
        )
        if not copy_width_matches:
            self.issues.append(
                _indexed_global_stack_copy_issue_8616(
                    copy_fact,
                    IndexedGlobalStackAggregateCopyIssueKind8616.WIDTH_MISMATCH,
                    actual=copy_index_matches,
                )
            )
            return
        if not any(
            (
                copy.source_struct_type == copy_fact.struct_type
                or (
                    copy.source_struct_type is None
                    and _registered_named_global_copy_type_matches_8616(
                        self.codegen,
                        copy_fact,
                        copy,
                        self.named_global_facts,
                    )
                )
            )
            and copy.destination_struct_type == copy_fact.struct_type
            for copy in copy_width_matches
        ):
            self.issues.append(
                _indexed_global_stack_copy_issue_8616(
                    copy_fact,
                    IndexedGlobalStackAggregateCopyIssueKind8616.STRUCT_TYPE_MISMATCH,
                    actual=copy_width_matches,
                )
            )
            return
        self.materialized_count += 1
