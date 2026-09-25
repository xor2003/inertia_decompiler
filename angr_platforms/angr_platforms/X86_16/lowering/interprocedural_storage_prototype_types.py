"""Preflight accepted storage contracts for function-prototype application.

Layer: Types/Lowering.
Responsibility: verify exact C argument storage, join existing pointer pointees,
and build mutation-free prototype application results before transaction commit.
Consumes alias, widening, and typed facts through accepted interprocedural
storage contracts and their ``SimType`` projection. It does not mutate codegen
or function metadata.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeBottom, SimTypeFunction, SimTypePointer
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from .interprocedural_storage_contracts import (
    FunctionStorageContract8616,
    StorageIdentityKind8616,
    StorageSlotContract8616,
    StorageTrialRole8616,
)
from .interprocedural_storage_simtypes import (
    StorageSimTypeFailureKind8616,
    StorageSimTypeVerdict8616,
    storage_contract_return_type_8616,
    storage_slot_simtype_8616,
)
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

__all__ = [
    "FunctionStoragePrototypeApplicationResult8616",
    "FunctionStoragePrototypeApplicationVerdict8616",
    "FunctionStoragePrototypeTypes8616",
    "preflight_storage_prototype_types_8616",
    "storage_prototype_with_types_8616",
]


class FunctionStoragePrototypeApplicationVerdict8616(StrEnum):
    """Typed outcome of applying one published storage contract."""

    CONTRACT_UNAVAILABLE = "contract_unavailable"
    CONTRACT_REFUSED = "contract_refused"
    FUNCTION_UNAVAILABLE = "function_unavailable"
    PROTOTYPE_UNAVAILABLE = "prototype_unavailable"
    ARGUMENT_SHAPE_REFUSED = "argument_shape_refused"
    TYPE_REFUSED = "type_refused"
    APPLIED = "applied"
    UNCHANGED = "unchanged"


@dataclass(frozen=True, slots=True)
class FunctionStoragePrototypeApplicationResult8616:
    """Atomic prototype-application result retained on current codegen."""

    function_addr: int | None
    verdict: FunctionStoragePrototypeApplicationVerdict8616
    prototype: SimTypeFunction | None = None
    type_failures: tuple[StorageSimTypeFailureKind8616, ...] = ()
    changed: bool = False

    @property
    def blocks_legacy_reconciliation(self) -> bool:
        """Return whether fallback width-only mutation would violate atomicity."""
        return self.verdict in {
            FunctionStoragePrototypeApplicationVerdict8616.CONTRACT_REFUSED,
            FunctionStoragePrototypeApplicationVerdict8616.PROTOTYPE_UNAVAILABLE,
            FunctionStoragePrototypeApplicationVerdict8616.ARGUMENT_SHAPE_REFUSED,
            FunctionStoragePrototypeApplicationVerdict8616.TYPE_REFUSED,
        }


@dataclass(frozen=True, slots=True)
class FunctionStoragePrototypeTypes8616:
    """Mutation-free argument and proven-return types for one accepted contract."""

    argument_types: tuple[SimType, ...] | None
    proven_return: SimType | None = None
    failures: tuple[StorageSimTypeFailureKind8616, ...] = ()

    @property
    def accepted(self) -> bool:
        """Return whether every contract-owned type passed preflight."""
        return self.argument_types is not None and not self.failures


def _prototype_arguments_8616(prototype: object) -> tuple[SimType, ...] | None:
    """Return a fully typed argument tuple or refuse a partial prototype."""
    if not isinstance(prototype, SimTypeFunction):
        return None
    arguments = tuple(prototype.args or ())
    return arguments if all(isinstance(item, SimType) for item in arguments) else None


def _pointer_is_informative_8616(pointer_type: SimTypePointer) -> bool:
    """Return whether an existing near pointer carries a non-void pointee."""
    pointee = pointer_type.pts_to
    return not (
        isinstance(pointee, SimTypeBottom)
        and pointee.label in {None, "void"}
    )


def _existing_pointer_candidate_8616(
    candidates: tuple[SimType | None, ...],
    arch: Arch,
) -> tuple[SimType | None, bool]:
    """Join exact-width existing pointees or refuse competing object types."""
    pointers = tuple(
        bound
        for candidate in candidates
        if isinstance(candidate, SimTypePointer)
        and isinstance((bound := candidate.with_arch(arch)), SimTypePointer)
        and bound.size == 16
    )
    informative = tuple(item for item in pointers if _pointer_is_informative_8616(item))
    if informative and any(item != informative[0] for item in informative[1:]):
        return None, False
    return (informative[0] if informative else (pointers[0] if pointers else None)), True


def _slot_matches_cvar_8616(
    slot: StorageSlotContract8616,
    cvar: structured_c.CVariable,
    codegen: object,
) -> bool:
    """Verify one C argument against contiguous machine-BP storage pieces."""
    pieces = slot.pieces
    variable = cvar.variable
    if (
        slot.role is not StorageTrialRole8616.INPUT
        or not pieces
        or not isinstance(variable, SimStackVariable)
    ):
        return False
    first_address = pieces[0].address
    if first_address is None:
        return False
    expected_offset = first_address.offset
    for piece in pieces:
        address = piece.address
        if (
            piece.kind is not StorageIdentityKind8616.STACK
            or not piece.is_exact
            or address is None
            or address.base != ("bp",)
            or address.offset != expected_offset
        ):
            return False
        expected_offset += piece.width
    variable_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return isinstance(variable_offset, int) and variable_offset == first_address.offset


def storage_prototype_with_types_8616(
    original: SimTypeFunction,
    argument_types: tuple[SimType, ...],
    return_type: SimType,
    arch: Arch,
) -> SimTypeFunction:
    """Rebuild one projection while preserving only non-semantic name metadata."""
    names = tuple(original.arg_names or ())
    return SimTypeFunction(
        argument_types,
        return_type,
        arg_names=names if len(names) == len(argument_types) else None,
        variadic=original.variadic,
    ).with_arch(arch)


def _prototype_inputs_aligned_8616(
    cfunc_args: tuple[SimType, ...] | None,
    function_args: tuple[SimType, ...] | None,
    contract: FunctionStorageContract8616,
    cvars: tuple[structured_c.CVariable, ...],
    codegen: object,
) -> bool:
    """Return whether argument counts, logical order, and cvars all align."""
    if cfunc_args is None or function_args is None:
        return False
    expected_indices = tuple(range(len(contract.inputs)))
    return (
        len(cfunc_args) == len(contract.inputs)
        and len(cvars) == len(contract.inputs)
        and tuple(slot.logical_index for slot in contract.inputs) == expected_indices
        and all(
            _slot_matches_cvar_8616(slot, cvar, codegen)
            for slot, cvar in zip(contract.inputs, cvars, strict=True)
        )
    )


def preflight_storage_prototype_types_8616(
    contract: FunctionStorageContract8616,
    cfunc_prototype: SimTypeFunction,
    function_prototype: SimTypeFunction,
    cvars: tuple[structured_c.CVariable, ...],
    arch: Arch,
    codegen: object,
) -> FunctionStoragePrototypeTypes8616:
    """Preflight every parameter and any proven return before mutation."""
    cfunc_args = _prototype_arguments_8616(cfunc_prototype)
    function_args = _prototype_arguments_8616(function_prototype)
    if not _prototype_inputs_aligned_8616(
        cfunc_args, function_args, contract, cvars, codegen
    ):
        return FunctionStoragePrototypeTypes8616(
            None,
            failures=(StorageSimTypeFailureKind8616.INVALID_LOGICAL_ORDER,),
        )
    assert cfunc_args is not None
    assert function_args is not None
    argument_types: list[SimType] = []
    for index, (slot, cvar) in enumerate(zip(contract.inputs, cvars, strict=True)):
        function_arg = function_args[index] if index < len(function_args) else None
        existing, coherent = _existing_pointer_candidate_8616(
            (cvar.variable_type, cfunc_args[index], function_arg),
            arch,
        )
        if not coherent:
            return FunctionStoragePrototypeTypes8616(
                None,
                failures=(StorageSimTypeFailureKind8616.VALUE_CLASS_UNKNOWN,),
            )
        result = storage_slot_simtype_8616(slot, arch, existing_type=existing)
        if not result.accepted or result.sim_type is None:
            return FunctionStoragePrototypeTypes8616(None, failures=result.failures)
        argument_types.append(result.sim_type)
    existing_return, coherent = _existing_pointer_candidate_8616(
        (cfunc_prototype.returnty, function_prototype.returnty),
        arch,
    )
    if not coherent:
        return FunctionStoragePrototypeTypes8616(
            None,
            failures=(StorageSimTypeFailureKind8616.VALUE_CLASS_UNKNOWN,),
        )
    return_result = storage_contract_return_type_8616(
        contract,
        arch,
        existing_type=existing_return,
    )
    if return_result.verdict is StorageSimTypeVerdict8616.REFUSED:
        return FunctionStoragePrototypeTypes8616(None, failures=return_result.failures)
    return FunctionStoragePrototypeTypes8616(
        tuple(argument_types),
        proven_return=return_result.sim_type,
    )
