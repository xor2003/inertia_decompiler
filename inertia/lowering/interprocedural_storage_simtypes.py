"""Map accepted storage slots to architecture-bound angr types.

Layer: Types/Lowering.
Responsibility: provide the single typed projection from proof-bearing input and
output storage contracts to ``SimType`` and C declaration types.  A DX:AX
pointer-class return projects to a far pointer only when an independently
proven pointee family is supplied; the contract's ``pointee_width_bytes`` is
caller-dereference evidence and can never authorize the far pointer alone.
Consumes alias, widening, and typed facts through accepted interprocedural
storage contracts only. It does not mutate function metadata or infer absent
return storage.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from angr.sim_type import (
    SimType,
    SimTypeBottom,
    SimTypeChar,
    SimTypeFunction,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from archinfo import Arch

from .far_pointer_type import SimTypeFarPointer16_8616, far_pointer_type_8616
from .interprocedural_storage_contracts import (
    FunctionStorageContract8616,
    StorageIdentityKind8616,
    StorageSlotContract8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from .near_pointer_type import near_pointer_type_8616

__all__ = [
    "StorageContractReturnTypeResult8616",
    "StorageSimTypeFailureKind8616",
    "StorageSimTypeResult8616",
    "StorageSimTypeVerdict8616",
    "storage_contract_return_type_8616",
    "storage_slot_simtype_8616",
]


class StorageSimTypeVerdict8616(StrEnum):
    """Typed outcome of one storage-contract type projection."""

    ACCEPTED = "accepted"
    UNPROVEN = "unproven"
    REFUSED = "refused"


class StorageSimTypeFailureKind8616(StrEnum):
    """Stable reasons an accepted storage shape cannot become one C type."""

    INVALID_ROLE = "invalid_role"
    INVALID_LOGICAL_ORDER = "invalid_logical_order"
    UNSUPPORTED_WIDTH = "unsupported_width"
    SIGNEDNESS_CLASS_CONFLICT = "signedness_class_conflict"
    VALUE_CLASS_UNKNOWN = "value_class_unknown"
    OUTPUT_ARITY_UNSUPPORTED = "output_arity_unsupported"
    POINTEE_WIDTH_UNKNOWN = "pointee_width_unknown"
    POINTEE_WIDTH_CONFLICT = "pointee_width_conflict"
    POINTER_WIDTH_CONFLICT = "pointer_width_conflict"
    POINTER_ABI_CONFLICT = "pointer_abi_conflict"
    POINTEE_FAMILY_UNPROVEN = "pointee_family_unproven"
    POINTEE_FAMILY_CONFLICT = "pointee_family_conflict"
    POINTER_ARITHMETIC_UNPROVEN = "pointer_arithmetic_unproven"


@dataclass(frozen=True, slots=True)
class StorageSimTypeResult8616:
    """One accepted/refused slot projection with its matching C spelling."""

    verdict: StorageSimTypeVerdict8616
    sim_type: SimType | None = None
    c_type: str | None = None
    failures: tuple[StorageSimTypeFailureKind8616, ...] = ()

    @property
    def accepted(self) -> bool:
        """Return whether the slot has one exact materializable type."""
        return self.verdict is StorageSimTypeVerdict8616.ACCEPTED


@dataclass(frozen=True, slots=True)
class StorageContractReturnTypeResult8616:
    """Projection of zero or one logical output to a function return type."""

    verdict: StorageSimTypeVerdict8616
    sim_type: SimType | None = None
    c_type: str | None = None
    failures: tuple[StorageSimTypeFailureKind8616, ...] = ()

    @property
    def accepted(self) -> bool:
        """Return whether one proven output has an exact return type."""
        return self.verdict is StorageSimTypeVerdict8616.ACCEPTED


def _normalized_pointer_c_type_8616(pointer_type: SimTypePointer) -> str:
    """Render a pointer base type without introducing a declarator name."""
    rendered = cast(str, pointer_type.c_repr(name=None))
    return " ".join(rendered.replace("*", " * ").split())


def _exact_existing_pointer_8616(
    existing_type: SimType | None,
    arch: Arch,
) -> SimTypePointer | None:
    """Retain an existing pointee only when its pointer width is proven near."""
    if not isinstance(existing_type, SimTypePointer):
        return None
    bound = existing_type.with_arch(arch)
    if not isinstance(bound, SimTypePointer) or bound.size != 16:
        return None
    return bound


def _return_pointee_type_8616(
    slot: StorageSlotContract8616,
    arch: Arch,
    existing: SimTypePointer | None,
) -> tuple[SimType | None, StorageSimTypeFailureKind8616 | None]:
    """Select a bit-preserving pointee from exact caller dereference width."""
    width = slot.pointee_width_bytes
    if width is None:
        return None, StorageSimTypeFailureKind8616.POINTEE_WIDTH_UNKNOWN
    constructor = {1: SimTypeChar, 2: SimTypeShort, 4: SimTypeLong}.get(width)
    if constructor is None:
        return None, StorageSimTypeFailureKind8616.UNSUPPORTED_WIDTH
    if existing is not None:
        prior = existing.pts_to
        if not isinstance(prior, SimTypeBottom):
            if prior.size != width * 8:
                return None, StorageSimTypeFailureKind8616.POINTEE_WIDTH_CONFLICT
            return prior, None
    return cast(SimType, constructor(signed=False).with_arch(arch)), None


def _is_dx_ax_return_pair_8616(slot: StorageSlotContract8616) -> bool:
    """Return whether the slot is exactly the DX:AX far-result register pair."""
    pieces = slot.pieces
    if len(pieces) != 2:
        return False
    return all(
        piece.kind is StorageIdentityKind8616.REGISTER
        and piece.is_exact
        and piece.register == register
        and piece.width == width
        for piece, (register, width) in zip(
            pieces, (("ax", 2), ("dx", 2)), strict=True
        )
    )


def _pointee_size_bits_8616(pointee: SimType) -> int | None:
    """Return the declared bit size, treating callable families as unsized."""
    if isinstance(pointee, SimTypeFunction):
        return None
    size = pointee.size
    return size if isinstance(size, int) else None


def _pointee_family_matches_8616(prior: SimType, proven: SimType) -> bool:
    """Require the same structural C family, not merely the same byte size."""
    return bool(prior == proven)


def _far_pointer_return_simtype_8616(
    slot: StorageSlotContract8616,
    arch: Arch,
    existing_type: SimType | None,
    proven_far_pointee: SimType | None,
) -> StorageSimTypeResult8616:
    """Project the proven DX:AX pair to a far pointer from independent proof.

    ``slot.pointee_width_bytes`` is a downstream caller-dereference width; it
    corroborates but never establishes which family the returned segment:offset
    pair points at.  Publication therefore requires ``proven_far_pointee``, an
    independently proven pointee family supplied through the typed contract.
    """
    pointee = None if proven_far_pointee is None else proven_far_pointee.with_arch(arch)
    if pointee is None or isinstance(pointee, SimTypeBottom):
        return StorageSimTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.POINTEE_FAMILY_UNPROVEN,),
        )
    pointee_bits = _pointee_size_bits_8616(pointee)
    if (
        slot.pointee_width_bytes is not None
        and pointee_bits is not None
        and pointee_bits != slot.pointee_width_bytes * 8
    ):
        return StorageSimTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.POINTEE_WIDTH_CONFLICT,),
        )
    if isinstance(existing_type, SimTypePointer):
        bound = existing_type.with_arch(arch)
        if isinstance(bound, SimTypePointer) and bound.size != 32:
            return StorageSimTypeResult8616(
                StorageSimTypeVerdict8616.REFUSED,
                failures=(StorageSimTypeFailureKind8616.POINTER_WIDTH_CONFLICT,),
            )
        if not isinstance(bound, SimTypeFarPointer16_8616):
            return StorageSimTypeResult8616(
                StorageSimTypeVerdict8616.REFUSED,
                failures=(StorageSimTypeFailureKind8616.POINTER_ABI_CONFLICT,),
            )
        prior = bound.pts_to
        if not isinstance(prior, SimTypeBottom):
            if not _pointee_family_matches_8616(prior, pointee):
                return StorageSimTypeResult8616(
                    StorageSimTypeVerdict8616.REFUSED,
                    failures=(StorageSimTypeFailureKind8616.POINTEE_FAMILY_CONFLICT,),
                )
            pointee = prior
    pointer_type = far_pointer_type_8616(pointee, arch)
    return StorageSimTypeResult8616(
        StorageSimTypeVerdict8616.ACCEPTED,
        sim_type=pointer_type,
        c_type=_normalized_pointer_c_type_8616(pointer_type),
    )


def _pointer_slot_simtype_8616(
    slot: StorageSlotContract8616,
    arch: Arch,
    existing_type: SimType | None,
    proven_far_pointee: SimType | None,
) -> StorageSimTypeResult8616:
    """Project an exact pointer slot; a DX:AX result needs independent proof."""
    is_far_result = (
        slot.role is StorageTrialRole8616.RETURN
        and _is_dx_ax_return_pair_8616(slot)
    )
    if slot.width != 2 and not is_far_result:
        return StorageSimTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.UNSUPPORTED_WIDTH,),
        )
    if slot.signedness is not StorageTrialSignedness8616.NOT_APPLICABLE:
        return StorageSimTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.SIGNEDNESS_CLASS_CONFLICT,),
        )
    if is_far_result:
        return _far_pointer_return_simtype_8616(
            slot, arch, existing_type, proven_far_pointee
        )
    pointer_type = _exact_existing_pointer_8616(existing_type, arch)
    if slot.role is StorageTrialRole8616.RETURN:
        pointee, failure = _return_pointee_type_8616(slot, arch, pointer_type)
        if pointee is None:
            return StorageSimTypeResult8616(
                StorageSimTypeVerdict8616.REFUSED,
                failures=(failure,) if failure is not None else (),
            )
        pointer_type = near_pointer_type_8616(pointee, arch)
    elif pointer_type is None:
        pointer_type = near_pointer_type_8616(
            SimTypeBottom(label="void").with_arch(arch), arch,
        )
    return StorageSimTypeResult8616(
        StorageSimTypeVerdict8616.ACCEPTED,
        sim_type=pointer_type,
        c_type=_normalized_pointer_c_type_8616(pointer_type),
    )


def storage_slot_simtype_8616(
    slot: StorageSlotContract8616,
    arch: Arch,
    *,
    existing_type: SimType | None = None,
    proven_far_pointee: SimType | None = None,
) -> StorageSimTypeResult8616:
    """Map one exact logical storage slot to its architecture-bound C type.

    ``proven_far_pointee`` is the independently proven pointee family of a DX:AX
    pointer-class result; it is consumed only by that shape and never inferred
    from the slot's downstream caller-dereference width.
    """
    if slot.role not in {StorageTrialRole8616.INPUT, StorageTrialRole8616.RETURN}:
        return StorageSimTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.INVALID_ROLE,),
        )
    if slot.value_class is StorageTrialValueClass8616.POINTER:
        return _pointer_slot_simtype_8616(
            slot, arch, existing_type, proven_far_pointee
        )
    if slot.value_class is not StorageTrialValueClass8616.VALUE:
        return StorageSimTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.VALUE_CLASS_UNKNOWN,),
        )
    if slot.signedness not in {
        StorageTrialSignedness8616.SIGN_INSENSITIVE,
        StorageTrialSignedness8616.SIGNED,
        StorageTrialSignedness8616.UNSIGNED,
    }:
        return StorageSimTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.SIGNEDNESS_CLASS_CONFLICT,),
        )
    # Equality-only use proves bit width and value class, not source signedness.
    # Unsigned C is the canonical projection that preserves every proven bit.
    signed = slot.signedness is StorageTrialSignedness8616.SIGNED
    constructors = {
        1: SimTypeChar,
        2: SimTypeShort,
        4: SimTypeLong,
    }
    constructor = constructors.get(slot.width)
    if constructor is None:
        return StorageSimTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.UNSUPPORTED_WIDTH,),
        )
    sim_type = cast(SimType, constructor(signed=signed).with_arch(arch))
    base_name = {1: "char", 2: "short", 4: "long"}[slot.width]
    c_type = base_name if signed else f"unsigned {base_name}"
    if signed and slot.width == 1:
        c_type = "signed char"
    return StorageSimTypeResult8616(
        StorageSimTypeVerdict8616.ACCEPTED,
        sim_type=sim_type,
        c_type=c_type,
    )


def storage_contract_return_type_8616(
    contract: FunctionStorageContract8616,
    arch: Arch,
    *,
    existing_type: SimType | None = None,
    proven_far_pointee: SimType | None = None,
) -> StorageContractReturnTypeResult8616:
    """Project exactly one proven output; zero outputs remain explicitly unproven.

    ``proven_far_pointee`` is the independently proven pointee family required
    before a DX:AX pointer-class result can become a far-pointer return type.
    """
    returns = tuple(
        output for output in contract.outputs if output.role is StorageTrialRole8616.RETURN
    )
    if not returns:
        return StorageContractReturnTypeResult8616(
            StorageSimTypeVerdict8616.UNPROVEN,
        )
    if len(returns) != 1:
        return StorageContractReturnTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.OUTPUT_ARITY_UNSUPPORTED,),
        )
    output = returns[0]
    if output.role is not StorageTrialRole8616.RETURN or output.logical_index != 0:
        return StorageContractReturnTypeResult8616(
            StorageSimTypeVerdict8616.REFUSED,
            failures=(StorageSimTypeFailureKind8616.INVALID_LOGICAL_ORDER,),
        )
    result = storage_slot_simtype_8616(
        output,
        arch,
        existing_type=existing_type,
        proven_far_pointee=proven_far_pointee,
    )
    return StorageContractReturnTypeResult8616(
        result.verdict,
        sim_type=result.sim_type,
        c_type=result.c_type,
        failures=result.failures,
    )
