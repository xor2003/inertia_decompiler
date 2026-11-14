# cython: language_level=3, infer_types=True
"""Reconcile generated function headers with binary caller arity evidence.

Layer: Types/Lowering.
Responsibility: accept, refuse, or materialize generated-C function interfaces
from typed caller arity and callee pointer evidence before identity lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimType, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable

from .callee_argument_count_evidence import CalleeArgumentCountEvidence8616, CalleeArgumentCountVerdict8616
from .callee_argument_width_evidence import collect_callee_argument_width_evidence_8616
from .near_pointer_type import near_pointer_type_8616
from .stack_prototype_materialization import materialize_exact_trailing_stack_argument_8616
import dataclasses
import operator


class CalleeArgumentInterfaceDecision8616(StrEnum):
    """Typed decision for one candidate generated-C argument interface."""

    ACCEPT = "accept"
    REFUSE = "refuse"
    MATERIALIZED_ZERO = "materialized-zero"


@dataclasses.dataclass(frozen=True, )
class CalleeArgumentInterfaceResult8616:
    """Evidence, decision, and mutation result for one interface join."""

    evidence: CalleeArgumentCountEvidence8616
    decision: CalleeArgumentInterfaceDecision8616
    changed: cython.bint = False


@dataclasses.dataclass(frozen=True, )
class CalleePointerInterfaceResult8616:
    """Closed evidence counts for pointer-backed C-interface materialization."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    changed: cython.bint = False


class _CFunctionSurface8616(Protocol):
    """angr generated-function fields updated at the dynamic boundary."""

    addr: cython.longlong
    arg_list: Sequence[object] | None
    functy: object


class _CodegenSurface8616(Protocol):
    """angr codegen fields plus owned Inertia evidence metadata."""

    cfunc: _CFunctionSurface8616 | None
    _inertia_authoritative_zero_arg_prototype_8616: cython.bint
    _inertia_callee_argument_count_evidence_8616: CalleeArgumentCountEvidence8616
    _inertia_codegen_decl_refresh_required_8616: cython.bint


class _FunctionManagerSurface8616(Protocol):
    """angr function lookup used at the third-party project boundary."""

    def function(self, *, addr: cython.longlong, create: cython.bint) -> _FunctionSurface8616 | None:
        """Return an existing function without creating a new one."""


class _KnowledgeBaseSurface8616(Protocol):
    """angr knowledge-base surface required by interface lowering."""

    functions: _FunctionManagerSurface8616


class _ProjectSurface8616(Protocol):
    """angr project fields consumed by typed interface lowering."""

    arch: object
    kb: _KnowledgeBaseSurface8616


class _FunctionSurface8616(Protocol):
    """angr function prototype fields updated by typed Lowering."""

    prototype: object
    is_prototype_guessed: cython.bint


class _PointerEvidenceSurface8616(Protocol):
    """Owned binary pointer evidence consumed by interface lowering."""

    @property
    def target_addr(self) -> cython.longlong:
        """Return the binary callee address."""
        ...

    @property
    def raw_fact_count(self) -> cython.longlong:
        """Return the number of collected pointer facts."""
        ...

    @property
    def normalized_fact_count(self) -> cython.longlong:
        """Return the number of normalized pointer facts."""
        ...

    @property
    def classified_fact_count(self) -> cython.longlong:
        """Return the number of classified pointer facts."""
        ...

    @property
    def failure_count(self) -> cython.longlong:
        """Return the number of pointer evidence failures."""
        ...

    @property
    def pointer_stack_offsets(self) -> object:
        """Return proven pointer-bearing callee stack offsets."""
        ...

    @property
    def pointer_argument_indices(self) -> object:
        """Return proven pointer argument indices."""
        ...


@cython.ccall
def materialize_callee_pointer_codegen_interface_8616(
    project: object,
    codegen: object,
    evidence: _PointerEvidenceSurface8616,
) -> CalleePointerInterfaceResult8616:
    """Materialize exact binary-proven BP pointer slots in the active C header."""
    cfunc: object
    argument_index: object
    stack_offset: object
    typed_project = cast(_ProjectSurface8616, project)
    typed_codegen = cast(_CodegenSurface8616, codegen)
    cfunc = typed_codegen.cfunc
    if operator.ne(len(evidence.pointer_argument_indices), len(evidence.pointer_stack_offsets)):
        return CalleePointerInterfaceResult8616(
            evidence.raw_fact_count,
            evidence.normalized_fact_count,
            evidence.classified_fact_count,
            0,
            max(1, evidence.classified_fact_count),
        )
    pairs = tuple(zip(evidence.pointer_argument_indices, evidence.pointer_stack_offsets, strict=True))
    classified_count = evidence.classified_fact_count
    if (
        cfunc is None
        or operator.ne(cfunc.addr, evidence.target_addr)
        or evidence.failure_count
        or operator.ne(len(pairs), classified_count)
    ):
        return CalleePointerInterfaceResult8616(
            evidence.raw_fact_count,
            evidence.normalized_fact_count,
            classified_count,
            0,
            max(1, evidence.failure_count, classified_count),
        )
    arch = typed_project.arch
    pointer_type = near_pointer_type_8616(SimTypeShort(False), arch)
    changed = False
    materialized_count = 0
    for argument_index, stack_offset in pairs:
        arguments = tuple(cfunc.arg_list or ())
        if argument_index < len(arguments):
            argument = arguments[argument_index]
            if (
                not isinstance(argument, CVariable)
                or not isinstance(argument.variable, SimStackVariable)
                or operator.ne(argument.variable.offset, stack_offset)
            ):
                break
            materialized_count += 1
            continue
        if operator.ne(argument_index, len(arguments)) or operator.ne(stack_offset, 4 + 2 * argument_index):
            break
        candidate = CVariable(
            SimStackVariable(
                stack_offset,
                2,
                base="bp",
                name=f"arg_{stack_offset:x}",
                region=cfunc.addr,
            ),
            variable_type=pointer_type,
            codegen=codegen,
        )
        if materialize_exact_trailing_stack_argument_8616(
            project,
            codegen,
            candidate=candidate,
            stack_offset=stack_offset,
            argument_type=pointer_type,
            width=2,
        ) is None:
            break
        changed = True
        materialized_count += 1
    failure_count = evidence.failure_count + classified_count - materialized_count
    result = CalleePointerInterfaceResult8616(
        evidence.raw_fact_count,
        evidence.normalized_fact_count,
        classified_count,
        materialized_count,
        failure_count,
        changed,
    )
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return result


def materialize_callee_pointer_prefix_prototype_8616(
    project: object,
    function: object,
    pointer_argument_indices: Sequence[cython.longlong],
) -> cython.longlong:
    """Materialize callee-proven pointer slots in an existing prototype.

    A short prototype may be extended only when every missing slot belongs to
    a contiguous pointer prefix beginning at ``BP+4``. Existing non-prefix
    slots are never invented or reclassified without their own binary proof.
    """
    index: object
    indices = tuple(pointer_argument_indices)
    if not indices or operator.ne(indices, tuple(sorted(tuple(set(indices))))):
        return 0
    typed_function = cast(_FunctionSurface8616, function)
    prototype = typed_function.prototype
    if not isinstance(prototype, SimTypeFunction):
        return 0
    argument_types: list[SimType] = list(prototype.args or ())
    required_count = indices[-1] + 1
    if required_count > len(argument_types):
        if operator.ne(indices, tuple(range(required_count))):
            return 0
        argument_types.extend(
            SimTypeShort(False) for _ in range(required_count - len(argument_types))
        )
    arch = cast(_ProjectSurface8616, project).arch
    pointer_type = near_pointer_type_8616(SimTypeShort(False), arch)
    for index in indices:
        argument_types[index] = pointer_type
    existing_names = tuple(prototype.arg_names or ())
    argument_names = list(existing_names[: len(argument_types)])
    while len(argument_names) < len(argument_types):
        argument_names.append(f"arg_{4 + 2 * len(argument_names):x}")
    typed_function.prototype = SimTypeFunction(
        argument_types,
        prototype.returnty,
        arg_names=tuple(argument_names),
        variadic=prototype.variadic,
    ).with_arch(arch)
    return len(indices)


@cython.ccall
def _function_for_address_8616(project: object, address: cython.longlong) -> _FunctionSurface8616 | None:
    """Resolve one existing angr function through the third-party boundary."""
    try:
        function = cast(_ProjectSurface8616, project).kb.functions.function(addr=address, create=False)
    except KeyError:
        return None
    return function


@cython.ccall
def _materialize_zero_argument_interface_8616(
    project: object,
    codegen: _CodegenSurface8616,
    cfunc: _CFunctionSurface8616,
) -> cython.bint:
    """Apply a caller-proven zero-argument header without deleting body facts."""
    function: object
    current = cfunc.functy
    return_type = current.returnty if isinstance(current, SimTypeFunction) else SimTypeShort(False)
    prototype = SimTypeFunction([], return_type)
    prototype = prototype.with_arch(cast(_ProjectSurface8616, project).arch)
    changed = bool(cfunc.arg_list)
    if cfunc.arg_list:
        cfunc.arg_list = []
    if operator.ne(cfunc.functy, prototype):
        cfunc.functy = prototype
        changed = True
    function = _function_for_address_8616(project, cfunc.addr)
    if function is not None:
        if operator.ne(function.prototype, prototype):
            function.prototype = prototype
            changed = True
        if function.is_prototype_guessed:
            function.is_prototype_guessed = False
            changed = True
    codegen._inertia_authoritative_zero_arg_prototype_8616 = True
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


@cython.ccall
def reconcile_callee_argument_interface_8616(
    project: object,
    codegen: object,
    *,
    candidate_count: cython.longlong,
) -> CalleeArgumentInterfaceResult8616:
    """Join a candidate header with all available binary caller evidence."""
    cfunc: object
    typed_codegen = cast(_CodegenSurface8616, codegen)
    cfunc = typed_codegen.cfunc
    storage_evidence = collect_callee_argument_width_evidence_8616(
        project, -1 if cfunc is None else cfunc.addr
    )
    evidence = storage_evidence.required_count_evidence
    if cfunc is None:
        return CalleeArgumentInterfaceResult8616(
            evidence,
            CalleeArgumentInterfaceDecision8616.REFUSE,
        )
    typed_codegen._inertia_callee_argument_count_evidence_8616 = evidence
    if evidence.raw_fact_count > 0 and not storage_evidence.closes_census:
        return CalleeArgumentInterfaceResult8616(evidence, CalleeArgumentInterfaceDecision8616.REFUSE)
    if evidence.verdict is not CalleeArgumentCountVerdict8616.CONSISTENT:
        return CalleeArgumentInterfaceResult8616(evidence, CalleeArgumentInterfaceDecision8616.ACCEPT)
    if operator.eq(evidence.argument_count, candidate_count):
        return CalleeArgumentInterfaceResult8616(evidence, CalleeArgumentInterfaceDecision8616.ACCEPT)
    if evidence.argument_count == 0:
        changed = _materialize_zero_argument_interface_8616(project, typed_codegen, cfunc)
        return CalleeArgumentInterfaceResult8616(
            evidence,
            CalleeArgumentInterfaceDecision8616.MATERIALIZED_ZERO,
            changed,
        )
    return CalleeArgumentInterfaceResult8616(evidence, CalleeArgumentInterfaceDecision8616.REFUSE)


__all__ = [
    "CalleeArgumentInterfaceDecision8616",
    "CalleeArgumentInterfaceResult8616",
    "CalleePointerInterfaceResult8616",
    "materialize_callee_pointer_codegen_interface_8616",
    "materialize_callee_pointer_prefix_prototype_8616",
    "reconcile_callee_argument_interface_8616",
]
