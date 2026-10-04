"""Bind a proven IR far DX:AX return pair to one structured C expression.

Layer: Types/Lowering.
Responsibility: mutation-free preflight that joins a complete
``prove_stack_argument_far_scaled_return_8616`` result with one codegen
function's canonical stack projections to produce a candidate segmented
pointer return expression, or one typed refusal. The bound expression keeps
guest 16-bit offset wrap through an explicit 16-bit result view and uses the
owned segmented pointer constructor instead of linearized ``(seg << 4) + off``
arithmetic. This module does not infer a pointee family from downstream
dereference width, publish a return type or prototype, or edit the AST.
Consumes alias, widening, and typed facts through retained proof fields only.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeInt, SimTypeShort

from ..c_ast_utils import _clone_c_ast_tree_8616
from ..ir import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRMemoryAccessKind8616,
)
from ..ir.ssa_function import SSAFunctionArtifact
from ..ir.stack_argument_scaled_return import (
    FarScaledReturnFailure8616,
    FarScaledReturnResult8616,
)
from .c_runtime_header import is_lowered_runtime_macro_8616
from .stack_variable_coordinates import stack_cvar_for_machine_bp_range_8616

__all__ = [
    "FarReturnBoundInput8616",
    "FarReturnExpressionBindingFailure8616",
    "FarReturnExpressionBindingResult8616",
    "FarReturnExpressionBindingStats8616",
    "FarReturnExpressionBindingVerdict8616",
    "FarReturnExpressionRole8616",
    "FarReturnRepresentationKind8616",
    "bind_far_return_expression_8616",
]


class _CFunctionBoundary8616(Protocol):
    """Owned fields used from the dynamic angr C-function boundary."""

    addr: object


class _ProjectBoundary8616(Protocol):
    """Owned fields used from the dynamic angr project boundary."""

    _inertia_c_target: object


class _CodegenBoundary8616(Protocol):
    """Owned fields used from the dynamic angr codegen boundary."""

    cfunc: _CFunctionBoundary8616 | None
    project: _ProjectBoundary8616


class _VariableTypeBoundary8616(Protocol):
    """Third-party angr type width field read at the expression boundary."""

    size: object


class FarReturnExpressionBindingVerdict8616(StrEnum):
    """Whether the proven far-return pair bound to one C expression."""

    BOUND = "bound"
    UNKNOWN_REFUSE = "unknown_refuse"


class FarReturnExpressionBindingFailure8616(StrEnum):
    """Stable reasons the far-return expression binding cannot publish."""

    PROOF_INCOMPLETE = "proof_incomplete"
    CODEGEN_SURFACE_UNPROVEN = "codegen_surface_unproven"
    FUNCTION_MISMATCH = "function_mismatch"
    LOGICAL_MEMORY_UNPROVEN = "logical_memory_unproven"
    INPUT_ACCESS_UNPROVEN = "input_access_unproven"
    INPUT_STORAGE_MISMATCH = "input_storage_mismatch"
    INPUT_EXPRESSION_MISSING = "input_expression_missing"
    INPUT_EXPRESSION_MISMATCH = "input_expression_mismatch"
    TARGET_UNKNOWN = "target_unknown"
    REPRESENTATION_MISSING = "representation_missing"


class FarReturnExpressionRole8616(StrEnum):
    """Which proven input word one bound expression fragment carries."""

    OFFSET_BASE = "offset_base"
    SEGMENT = "segment"
    OFFSET_INDEX = "offset_index"


class FarReturnRepresentationKind8616(StrEnum):
    """Precise structured representation that a refusal could not produce."""

    INPUT_ACCESS = "input_access"
    INPUT_STACK_VARIABLE = "input_stack_variable"
    INPUT_WORD_TYPE = "input_word_type"
    SEGMENTED_POINTER_CONSTRUCTOR = "segmented_pointer_constructor"
    CODEGEN_FUNCTION = "codegen_function"


@dataclass(frozen=True, slots=True)
class FarReturnBoundInput8616:
    """One proven IR input word rebound to its canonical stack C variable."""

    role: FarReturnExpressionRole8616
    access_key: IRLogicalMemoryAccessKey8616
    storage: IRAddress
    expression: structured_c.CExpression


@dataclass(frozen=True, slots=True)
class FarReturnExpressionBindingStats8616:
    """Closed five-stage evidence loop for one requested binding."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class FarReturnExpressionBindingResult8616:
    """One bound candidate return expression or a typed atomic refusal."""

    verdict: FarReturnExpressionBindingVerdict8616
    failure: FarReturnExpressionBindingFailure8616 | None
    stats: FarReturnExpressionBindingStats8616
    target: str | None = None
    expression: structured_c.CExpression | None = None
    bound_inputs: tuple[FarReturnBoundInput8616, ...] = ()
    missing_representation: FarReturnRepresentationKind8616 | None = None
    missing_role: FarReturnExpressionRole8616 | None = None
    upstream_failure: FarScaledReturnFailure8616 | None = None

    @property
    def complete(self) -> bool:
        """Require one bound expression covering all three proven inputs."""
        return bool(
            self.verdict is FarReturnExpressionBindingVerdict8616.BOUND
            and self.failure is None
            and self.target in _FAR_RETURN_HELPER_BY_TARGET_8616
            and isinstance(self.expression, structured_c.CFunctionCall)
            and self.expression.callee_target
            == _FAR_RETURN_HELPER_BY_TARGET_8616[self.target]
            and len(self.bound_inputs) == 3
            and {item.role for item in self.bound_inputs}
            == set(FarReturnExpressionRole8616)
            and all(
                isinstance(item.expression, structured_c.CExpression)
                for item in self.bound_inputs
            )
            and self.missing_representation is None
            and self.missing_role is None
            and self.upstream_failure is None
            and self.stats == FarReturnExpressionBindingStats8616(1, 1, 1, 1, 0)
        )


_FAR_RETURN_HELPER_BY_TARGET_8616: dict[str, str] = {
    "portable-flat": "SEG_PTR",
    "msc-dos": "MK_FP",
}


def _refuse_8616(
    failure: FarReturnExpressionBindingFailure8616,
    *,
    normalized: bool = False,
    classified: bool = False,
    missing: FarReturnRepresentationKind8616 | None = None,
    role: FarReturnExpressionRole8616 | None = None,
    upstream: FarScaledReturnFailure8616 | None = None,
) -> FarReturnExpressionBindingResult8616:
    """Keep one failed binding as an atomic refusal with closed counters."""
    return FarReturnExpressionBindingResult8616(
        verdict=FarReturnExpressionBindingVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
        stats=FarReturnExpressionBindingStats8616(
            1, int(normalized), int(classified), 0, 1
        ),
        missing_representation=missing,
        missing_role=role,
        upstream_failure=upstream,
    )


def _codegen_function_addr_8616(codegen: object) -> int | None:
    """Read the exact linear function identity at the codegen boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    cfunc = boundary.cfunc
    if cfunc is None:
        return None
    addr = cfunc.addr
    return addr if isinstance(addr, int) and addr >= 0 else None


def _codegen_c_target_8616(codegen: object) -> str:
    """Read the selected generated-C ABI, defaulting like every consumer."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        target = boundary.project._inertia_c_target
    except AttributeError:
        target = None
    normalized = str(target or "portable-flat").strip().lower()
    return normalized if normalized else "portable-flat"


def _proven_input_access_8616(
    artifact: SSAFunctionArtifact,
    key: IRLogicalMemoryAccessKey8616,
) -> IRLogicalMemoryAccess8616 | None:
    """Bind one upstream proof key to a unique complete logical word read."""
    logical = artifact.logical_memory
    if logical is None or not logical.closed or logical.refusals:
        return None
    matches = tuple(access for access in logical.accesses if access.key == key)
    if len(matches) != 1:
        return None
    access = matches[0]
    if (
        not access.complete
        or access.kind is not IRMemoryAccessKind8616.READ
        or key.function_addr != artifact.function_addr
        or not key.complete
    ):
        return None
    return access


def _stable_bp_word_8616(access: IRLogicalMemoryAccess8616) -> IRAddress | None:
    """Require one proven stable SS:BP two-byte storage identity."""
    address = access.address
    if not (
        address.space is MemSpace.SS
        and address.base == ("bp",)
        and address.size == 2
        and address.status is AddressStatus.STABLE
        and address.segment_origin is SegmentOrigin.PROVEN
    ):
        return None
    return address


def _projected_word_cvar_8616(codegen: object, storage: IRAddress) -> object | None:
    """Return the canonical projected C node for one exact BP word."""
    projected: object | None = stack_cvar_for_machine_bp_range_8616(
        codegen, storage.offset, storage.size
    )
    return projected


def _is_word_variable_8616(cvar: object) -> bool:
    """Accept only a 16-bit integer stack variable as a bound input.

    The IR proof is a sign-insensitive bit-pattern fact, so signedness is not
    discriminated here; a pointer or wider type would change the scaling of
    the returned offset arithmetic and must refuse.
    """
    if not isinstance(cvar, structured_c.CVariable):
        return False
    variable_type = cvar.variable_type
    return bool(
        isinstance(variable_type, (SimTypeInt, SimTypeShort))
        and cast(_VariableTypeBoundary8616, variable_type).size == 16
    )


def _unsigned_word_view_8616(
    codegen: object,
    cvar: structured_c.CVariable,
) -> structured_c.CExpression:
    """Preserve a signed input's 16-bit pattern before C shift or macro use.

    A negative signed left operand makes C left shift undefined. Portable-flat
    ``SEG_PTR`` also widens its segment argument before shifting, so passing a
    signed word without this view would sign-extend a guest segment value.
    """
    variable_type = cast(SimTypeInt, cvar.variable_type)
    cloned = cast(structured_c.CExpression, _clone_c_ast_tree_8616(cvar))
    if variable_type.signed is False:
        return cloned
    return structured_c.CTypeCast(
        None,
        SimTypeShort(False),
        cloned,
        codegen=codegen,
    )


def _bound_offset_expression_8616(
    codegen: object,
    base: structured_c.CVariable,
    index: structured_c.CVariable,
) -> structured_c.CExpression:
    """Build (base + 2 * index) truncated to the proven guest 16-bit offset."""
    scaled = structured_c.CBinaryOp(
        "Shl",
        _unsigned_word_view_8616(codegen, index),
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    total = structured_c.CBinaryOp(
        "Add",
        _unsigned_word_view_8616(codegen, base),
        scaled,
        codegen=codegen,
    )
    # The IR fact proves a 16-bit result; the explicit word view keeps wrap
    # local to the expression instead of relying on callee argument coercion.
    return structured_c.CTypeCast(
        None,
        SimTypeShort(False),
        total,
        codegen=codegen,
    )


def _resolve_proven_accesses_8616(
    artifact: SSAFunctionArtifact,
    proof: FarScaledReturnResult8616,
) -> (
    tuple[tuple[FarReturnExpressionRole8616, IRLogicalMemoryAccess8616], ...]
    | FarReturnExpressionBindingResult8616
):
    """Rebind every retained proof key to a unique complete logical read."""
    proof_offset = proof.offset
    assert proof_offset is not None
    keys = (
        (FarReturnExpressionRole8616.OFFSET_BASE, proof_offset.base_access_key),
        (FarReturnExpressionRole8616.SEGMENT, proof.segment_access_key),
        (FarReturnExpressionRole8616.OFFSET_INDEX, proof_offset.index_access_key),
    )
    if any(key is None for _, key in keys):
        return _refuse_8616(
            FarReturnExpressionBindingFailure8616.INPUT_ACCESS_UNPROVEN,
            missing=FarReturnRepresentationKind8616.INPUT_ACCESS,
        )
    accesses: list[tuple[FarReturnExpressionRole8616, IRLogicalMemoryAccess8616]] = []
    for role, key in keys:
        assert key is not None
        access = _proven_input_access_8616(artifact, key)
        if access is None:
            return _refuse_8616(
                FarReturnExpressionBindingFailure8616.INPUT_ACCESS_UNPROVEN,
                missing=FarReturnRepresentationKind8616.INPUT_ACCESS,
                role=role,
            )
        accesses.append((role, access))
    return tuple(accesses)


def _proven_input_storages_8616(
    accesses: tuple[tuple[FarReturnExpressionRole8616, IRLogicalMemoryAccess8616], ...],
) -> (
    dict[FarReturnExpressionRole8616, IRAddress]
    | FarReturnExpressionBindingResult8616
):
    """Require stable proven SS:BP words in the exact far-pointer layout."""
    storages: dict[FarReturnExpressionRole8616, IRAddress] = {}
    for role, access in accesses:
        storage = _stable_bp_word_8616(access)
        if storage is None:
            return _refuse_8616(
                FarReturnExpressionBindingFailure8616.INPUT_STORAGE_MISMATCH,
                normalized=True,
                missing=FarReturnRepresentationKind8616.INPUT_ACCESS,
                role=role,
            )
        storages[role] = storage
    base = storages[FarReturnExpressionRole8616.OFFSET_BASE]
    segment = storages[FarReturnExpressionRole8616.SEGMENT]
    index = storages[FarReturnExpressionRole8616.OFFSET_INDEX]
    offsets = (base.offset, segment.offset, index.offset)
    adjacent_segment = segment.offset == base.offset + base.size
    if len(set(offsets)) != 3 or not adjacent_segment:
        return _refuse_8616(
            FarReturnExpressionBindingFailure8616.INPUT_STORAGE_MISMATCH,
            normalized=True,
            missing=FarReturnRepresentationKind8616.INPUT_ACCESS,
        )
    return storages


def _bind_input_variables_8616(
    codegen: object,
    accesses: tuple[tuple[FarReturnExpressionRole8616, IRLogicalMemoryAccess8616], ...],
    storages: dict[FarReturnExpressionRole8616, IRAddress],
) -> (
    tuple[
        tuple[FarReturnBoundInput8616, ...],
        dict[FarReturnExpressionRole8616, structured_c.CVariable],
    ]
    | FarReturnExpressionBindingResult8616
):
    """Bind each proven storage to one existing canonical stack variable."""
    bound_inputs: list[FarReturnBoundInput8616] = []
    variables: dict[FarReturnExpressionRole8616, structured_c.CVariable] = {}
    for role, access in accesses:
        storage = storages[role]
        cvar = _projected_word_cvar_8616(codegen, storage)
        if cvar is None:
            return _refuse_8616(
                FarReturnExpressionBindingFailure8616.INPUT_EXPRESSION_MISSING,
                normalized=True,
                missing=FarReturnRepresentationKind8616.INPUT_STACK_VARIABLE,
                role=role,
            )
        if not _is_word_variable_8616(cvar):
            return _refuse_8616(
                FarReturnExpressionBindingFailure8616.INPUT_EXPRESSION_MISMATCH,
                normalized=True,
                missing=FarReturnRepresentationKind8616.INPUT_WORD_TYPE,
                role=role,
            )
        assert isinstance(cvar, structured_c.CVariable)
        bound_inputs.append(
            FarReturnBoundInput8616(role, access.key, storage, cvar)
        )
        variables[role] = cvar
    return tuple(bound_inputs), variables


def _selected_far_return_helper_8616(
    codegen: object,
) -> tuple[str, str] | FarReturnExpressionBindingResult8616:
    """Require the segmented pointer constructor under both C runtimes."""
    target = _codegen_c_target_8616(codegen)
    helper = _FAR_RETURN_HELPER_BY_TARGET_8616.get(target)
    if helper is None:
        return _refuse_8616(
            FarReturnExpressionBindingFailure8616.TARGET_UNKNOWN,
            normalized=True,
            classified=True,
            missing=FarReturnRepresentationKind8616.SEGMENTED_POINTER_CONSTRUCTOR,
        )
    if not all(
        is_lowered_runtime_macro_8616(name)
        for name in _FAR_RETURN_HELPER_BY_TARGET_8616.values()
    ):
        return _refuse_8616(
            FarReturnExpressionBindingFailure8616.REPRESENTATION_MISSING,
            normalized=True,
            classified=True,
            missing=FarReturnRepresentationKind8616.SEGMENTED_POINTER_CONSTRUCTOR,
        )
    return target, helper


def _far_return_call_8616(
    codegen: object,
    proof: FarScaledReturnResult8616,
    accesses: tuple[tuple[FarReturnExpressionRole8616, IRLogicalMemoryAccess8616], ...],
    variables: dict[FarReturnExpressionRole8616, structured_c.CVariable],
    helper: str,
) -> structured_c.CFunctionCall:
    """Construct the segmented pointer candidate with exact provenance tags."""
    offset_expression = _bound_offset_expression_8616(
        codegen,
        variables[FarReturnExpressionRole8616.OFFSET_BASE],
        variables[FarReturnExpressionRole8616.OFFSET_INDEX],
    )
    assert proof.return_instruction_addr is not None
    source_addrs = tuple(
        sorted(
            {
                proof.return_instruction_addr,
                *(access.key.insn_addr for _, access in accesses),
            }
        )
    )
    return structured_c.CFunctionCall(
        helper,
        None,
        [
            _unsigned_word_view_8616(
                codegen, variables[FarReturnExpressionRole8616.SEGMENT]
            ),
            offset_expression,
        ],
        codegen=codegen,
        tags={
            "inertia_source_instruction_addrs": source_addrs,
            "inertia_x86_16_far_return_expression": proof.return_instruction_addr,
        },
    )


def bind_far_return_expression_8616(
    codegen: object,
    artifact: SSAFunctionArtifact,
    proof: FarScaledReturnResult8616,
) -> FarReturnExpressionBindingResult8616:
    """Bind proven DX:AX segment:offset inputs to one C return expression.

    The result is a nonpublishing candidate: it never mutates the codegen AST,
    function prototype, or callsite contracts, and it does not decide a pointee
    family. Callers still owe the atomic contract update and replay.
    """
    if not proof.complete or proof.offset is None:
        return _refuse_8616(
            FarReturnExpressionBindingFailure8616.PROOF_INCOMPLETE,
            upstream=proof.failure,
        )
    function_addr = _codegen_function_addr_8616(codegen)
    if function_addr is None:
        return _refuse_8616(
            FarReturnExpressionBindingFailure8616.CODEGEN_SURFACE_UNPROVEN,
            missing=FarReturnRepresentationKind8616.CODEGEN_FUNCTION,
        )
    if function_addr != artifact.function_addr:
        return _refuse_8616(
            FarReturnExpressionBindingFailure8616.FUNCTION_MISMATCH,
            missing=FarReturnRepresentationKind8616.CODEGEN_FUNCTION,
        )

    logical = artifact.logical_memory
    if logical is None or not logical.closed or logical.refusals:
        return _refuse_8616(
            FarReturnExpressionBindingFailure8616.LOGICAL_MEMORY_UNPROVEN,
            missing=FarReturnRepresentationKind8616.INPUT_ACCESS,
        )

    accesses = _resolve_proven_accesses_8616(artifact, proof)
    if isinstance(accesses, FarReturnExpressionBindingResult8616):
        return accesses
    storages = _proven_input_storages_8616(accesses)
    if isinstance(storages, FarReturnExpressionBindingResult8616):
        return storages
    binding = _bind_input_variables_8616(codegen, accesses, storages)
    if isinstance(binding, FarReturnExpressionBindingResult8616):
        return binding
    bound_inputs, variables = binding
    selected = _selected_far_return_helper_8616(codegen)
    if isinstance(selected, FarReturnExpressionBindingResult8616):
        return selected
    target, helper = selected

    expression = _far_return_call_8616(codegen, proof, accesses, variables, helper)
    result = FarReturnExpressionBindingResult8616(
        verdict=FarReturnExpressionBindingVerdict8616.BOUND,
        failure=None,
        stats=FarReturnExpressionBindingStats8616(1, 1, 1, 1, 0),
        target=target,
        expression=expression,
        bound_inputs=bound_inputs,
    )
    if not result.complete:
        raise RuntimeError("far-return expression binding lost owned evidence")
    return result
