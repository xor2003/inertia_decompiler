"""Track the mutable inputs consumed by final tail-validation reports.

Layer: Tail validation.
Responsibility: build in-process generation tokens for final structured-C
validation inputs so unchanged reports can be reused without rerunning every
validator.
Forbidden: semantic recovery, AST mutation, rendered-C inspection, or use as a
persistent/cross-process fingerprint. Opaque third-party identities are valid
only because these tokens never leave the current process.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from inertia.semantics.callsite_summary import (
    caller_return_use_evidence_by_addr_8616,
    callsite_summary_inventory_8616,
)

from inertia.lowering.return_type_evidence import proven_function_return_class_8616

from .status_flag_preservation import (
    packed_status_flag_preservation_evidence_8616,
)
from .tail_validation_generation_atoms import (
    ValidationGenerationAtom8616,
    ValidationGenerationAtomBuilder8616,
    validation_generation_atoms_equal_8616,
)

_CODEGEN_EVIDENCE_FIELDS_8616 = (
    "_inertia_call_output_stack_object_facts_8616",
    "_inertia_callsite_summaries",
    "_inertia_callsite_summary_inventory_8616",
    "_inertia_direct_stack_move_facts_8616",
    "_inertia_function_parameter_width_facts_8616",
    "_inertia_global_storage_identity_facts_8616",
    "_inertia_indexed_global_stack_aggregate_copy_facts_8616",
    "_inertia_loop_branch_guard_facts_8616",
    "_inertia_named_global_aggregate_type_facts_8616",
    "_inertia_near_pointer_argument_facts_8616",
    "_inertia_required_direct_segmented_global_stores_8616",
    "_inertia_segment_state_artifact",
    "_inertia_software_interrupt_input_artifact_8616",
    "_inertia_stack_aggregate_field_projection_facts_8616",
    "_inertia_stack_aggregate_object_facts_8616",
    "_inertia_structuring_switch_loop_exit_return_evidence_8616",
    "_inertia_typed_conditions",
)

_CFUNC_SURFACE_FIELDS_8616 = (
    "addr",
    "arg_list",
    "functy",
    "unified_local_vars",
    "variables_in_use",
)

class _FunctionSurface8616(Protocol):
    """Final function fields read at the third-party codegen boundary."""

    addr: object


class _CodegenSurface8616(Protocol):
    """Dynamic angr codegen surface carrying the final C function."""

    cfunc: _FunctionSurface8616


class _FunctionCollectionSurface8616(Protocol):
    """Minimal angr function collection used for prototype lookup."""

    def get(self, function_addr: int) -> object | None:
        """Return one function by address when present."""
        ...


class _KnowledgeBaseSurface8616(Protocol):
    """Minimal angr knowledge-base surface used by validation."""

    functions: _FunctionCollectionSurface8616


class _ProjectSurface8616(Protocol):
    """Dynamic angr project surface carrying its knowledge base."""

    kb: _KnowledgeBaseSurface8616


@dataclass(frozen=True, slots=True, eq=False)
class TailValidationSummaryInputGeneration8616:
    """In-process identity of all non-observable final-validator inputs.

    Equality preserves native dataclass self identity and field comparison
    order, delegating each atom field to the exact request-local DAG comparator.
    Shared substructure is walked once per unique tuple pair within each field
    instead of once per root path. Hashing stays the frozen-dataclass
    field-tuple hash so separately built equal generations keep coherent
    dictionary keys instead of falling back to object-identity hashing.
    """

    function_surface: ValidationGenerationAtom8616
    codegen_evidence: tuple[tuple[str, ValidationGenerationAtom8616], ...]
    project_evidence: ValidationGenerationAtom8616

    def __eq__(self, other: object) -> bool:
        """Compare same-class generations by exact atom equality per field."""
        if self is other:
            return True
        if (
            not isinstance(other, TailValidationSummaryInputGeneration8616)
            or other.__class__ is not self.__class__
        ):
            return NotImplemented
        return (
            validation_generation_atoms_equal_8616(
                self.function_surface, other.function_surface
            )
            and validation_generation_atoms_equal_8616(
                self.codegen_evidence, other.codegen_evidence
            )
            and validation_generation_atoms_equal_8616(
                self.project_evidence, other.project_evidence
            )
        )

    def __hash__(self) -> int:
        """Hash the field tuple exactly as frozen-dataclass generation did."""
        return hash(
            (
                self.function_surface,
                self.codegen_evidence,
                self.project_evidence,
            )
        )


def _function_surface_generation_8616(
    codegen: object,
    builder: ValidationGenerationAtomBuilder8616,
) -> ValidationGenerationAtom8616:
    """Capture final function signature and declaration containers."""
    try:
        cfunc = cast(_CodegenSurface8616, codegen).cfunc
    except AttributeError:
        return ("missing", "cfunc")
    return tuple(
        (field_name, builder.dynamic_field_atom(cfunc, field_name))
        for field_name in _CFUNC_SURFACE_FIELDS_8616
    )


def _target_prototype_generation_8616(
    project: object,
    codegen: object,
    builder: ValidationGenerationAtomBuilder8616,
) -> ValidationGenerationAtom8616:
    """Capture prototypes consulted by final call-interface validation."""
    summaries = callsite_summary_inventory_8616(codegen)
    target_addresses = tuple(
        sorted(
            {
                summary.target_addr
                for summary in summaries.values()
                if isinstance(summary.target_addr, int)
            }
        )
    )
    try:
        functions = cast(_ProjectSurface8616, project).kb.functions
    except AttributeError:
        return ()
    prototypes: list[ValidationGenerationAtom8616] = []
    for target_addr in target_addresses:
        try:
            function = functions.get(target_addr)
        except AttributeError:
            function = None
        prototypes.append(
            (
                target_addr,
                builder.dynamic_field_atom(function, "prototype")
                if function is not None
                else None,
            )
        )
    return tuple(prototypes)


def tail_validation_summary_input_generation_8616(
    project: object,
    codegen: object,
) -> TailValidationSummaryInputGeneration8616:
    """Return the current typed evidence generation for summary validators."""
    builder = ValidationGenerationAtomBuilder8616()
    codegen_evidence = tuple(
        (
            field_name,
            builder.dynamic_field_atom(codegen, field_name),
        )
        for field_name in _CODEGEN_EVIDENCE_FIELDS_8616
    )
    try:
        raw_function_addr = cast(_CodegenSurface8616, codegen).cfunc.addr
    except AttributeError:
        raw_function_addr = None
    function_addr = (
        raw_function_addr
        if isinstance(raw_function_addr, int) and not isinstance(raw_function_addr, bool)
        else None
    )
    return TailValidationSummaryInputGeneration8616(
        function_surface=_function_surface_generation_8616(codegen, builder),
        codegen_evidence=codegen_evidence,
        project_evidence=(
            (
                "arch",
                builder.dynamic_field_atom(project, "arch"),
            ),
            (
                "caller-return-use",
                builder.atom(
                    caller_return_use_evidence_by_addr_8616(project).get(function_addr)
                    if function_addr is not None
                    else None
                ),
            ),
            (
                "proven-return-class",
                builder.atom(
                    proven_function_return_class_8616(project, function_addr)
                    if function_addr is not None
                    else None
                ),
            ),
            (
                "packed-status-flags",
                builder.atom(
                    packed_status_flag_preservation_evidence_8616(project, codegen)
                ),
            ),
            (
                "target-prototypes",
                _target_prototype_generation_8616(project, codegen, builder),
            ),
        ),
    )
