"""Tests for storage-contract ``SimType`` projection and atomic application."""

from __future__ import annotations

import pytest
from angr.sim_type import (
    SimStruct,
    SimTypeBottom,
    SimTypeChar,
    SimTypeFunction,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)
from inertia.lowering.far_pointer_type import (
    SimTypeFarPointer16_8616,
    far_pointer_type_8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    FunctionStorageContract8616,
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageSlotContract8616,
    StorageTrialRole8616,
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from inertia.lowering.interprocedural_storage_simtypes import (
    StorageSimTypeFailureKind8616,
    StorageSimTypeVerdict8616,
    storage_contract_return_type_8616,
    storage_slot_simtype_8616,
)
from inertia.lowering.near_pointer_type import (
    SimTypeNearPointer16_8616,
    near_pointer_type_8616,
)


def _identity(
    width: int,
    *,
    offset: int | None = None,
    register: str | None = None,
) -> StorageIdentity8616:
    if offset is None:
        return StorageIdentity8616(
            kind=StorageIdentityKind8616.REGISTER,
            width=width,
            register=register,
        )
    return StorageIdentity8616(
        kind=StorageIdentityKind8616.STACK,
        width=width,
        address=IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=offset,
            size=width,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
    )


def _slot(
    role: StorageTrialRole8616,
    logical_index: int,
    width: int,
    signedness: StorageTrialSignedness8616,
    value_class: StorageTrialValueClass8616,
    *,
    offset: int | None = None,
    register: str | None = None,
) -> StorageSlotContract8616:
    return StorageSlotContract8616(
        role=role,
        logical_index=logical_index,
        pieces=(_identity(width, offset=offset, register=register),),
        signedness=signedness,
        value_class=value_class,
    )


def _contract(
    *,
    inputs: tuple[StorageSlotContract8616, ...] = (),
    outputs: tuple[StorageSlotContract8616, ...] = (),
) -> FunctionStorageContract8616:
    return FunctionStorageContract8616(
        function_addr=0x2000,
        inputs=inputs,
        outputs=outputs,
        stack_delta=sum(slot.width for slot in inputs),
        callsites=(),
    )


@pytest.mark.parametrize(
    ("width", "signedness", "expected_class", "expected_c", "expected_signed"),
    (
        (1, StorageTrialSignedness8616.SIGNED, SimTypeChar, "signed char", True),
        (1, StorageTrialSignedness8616.UNSIGNED, SimTypeChar, "unsigned char", False),
        (2, StorageTrialSignedness8616.SIGNED, SimTypeShort, "short", True),
        (2, StorageTrialSignedness8616.UNSIGNED, SimTypeShort, "unsigned short", False),
        (4, StorageTrialSignedness8616.SIGNED, SimTypeLong, "long", True),
        (4, StorageTrialSignedness8616.UNSIGNED, SimTypeLong, "unsigned long", False),
    ),
)
def test_scalar_slot_maps_exact_width_and_signedness(
    width,
    signedness,
    expected_class,
    expected_c,
    expected_signed,
) -> None:
    result = storage_slot_simtype_8616(
        _slot(
            StorageTrialRole8616.INPUT,
            0,
            width,
            signedness,
            StorageTrialValueClass8616.VALUE,
            offset=4,
        ),
        Arch86_16(),
    )

    assert result.accepted
    assert isinstance(result.sim_type, expected_class)
    assert isinstance(result.sim_type, (SimTypeChar, SimTypeShort, SimTypeLong))
    assert result.sim_type.signed is expected_signed
    assert result.c_type == expected_c


def test_sign_insensitive_wide_value_uses_canonical_unsigned_projection() -> None:
    """Equality-only evidence preserves bits without claiming source signedness."""
    result = storage_slot_simtype_8616(
        StorageSlotContract8616(
            role=StorageTrialRole8616.RETURN,
            logical_index=0,
            pieces=(
                _identity(2, register="ax"),
                _identity(2, register="dx"),
            ),
            signedness=StorageTrialSignedness8616.SIGN_INSENSITIVE,
            value_class=StorageTrialValueClass8616.VALUE,
        ),
        Arch86_16(),
    )

    assert result.accepted
    assert isinstance(result.sim_type, SimTypeLong)
    assert result.sim_type.signed is False
    assert result.c_type == "unsigned long"


def test_pointer_slot_preserves_proven_near_pointee_type() -> None:
    arch = Arch86_16()
    item_type = SimStruct({}, name="Item").with_arch(arch)
    existing = near_pointer_type_8616(item_type, arch)

    result = storage_slot_simtype_8616(
        _slot(
            StorageTrialRole8616.INPUT,
            0,
            2,
            StorageTrialSignedness8616.NOT_APPLICABLE,
            StorageTrialValueClass8616.POINTER,
            offset=4,
        ),
        arch,
        existing_type=existing,
    )

    assert isinstance(result.sim_type, SimTypeNearPointer16_8616)
    assert result.sim_type.pts_to == item_type
    assert result.c_type == "struct Item *"


def test_near_pointer_supports_angr_recursive_architecture_binding() -> None:
    """Function-type rebinding must pass angr's shared recursive-type memo."""
    arch = Arch86_16()
    prototype = SimTypeFunction(
        [SimTypeNearPointer16_8616(SimTypeChar(False))],
        SimTypeShort(False),
    ).with_arch(arch)

    pointer = prototype.args[0]
    assert isinstance(pointer, SimTypeNearPointer16_8616)
    assert pointer.size == 16
    assert pointer._arch is arch
    assert pointer.pts_to._arch is arch


def test_empty_output_is_unproven_and_multiple_outputs_refuse() -> None:
    arch = Arch86_16()
    empty = storage_contract_return_type_8616(_contract(), arch)
    outputs = tuple(
        _slot(
            StorageTrialRole8616.RETURN,
            index,
            2,
            StorageTrialSignedness8616.UNSIGNED,
            StorageTrialValueClass8616.VALUE,
            register=("ax", "dx")[index],
        )
        for index in range(2)
    )
    multiple = storage_contract_return_type_8616(
        _contract(outputs=outputs),
        arch,
    )

    assert empty.verdict is StorageSimTypeVerdict8616.UNPROVEN
    assert empty.sim_type is None and empty.c_type is None
    assert multiple.verdict is StorageSimTypeVerdict8616.REFUSED
    assert multiple.failures == (
        StorageSimTypeFailureKind8616.OUTPUT_ARITY_UNSUPPORTED,
    )


def test_split_dx_ax_output_maps_to_one_unsigned_long() -> None:
    output = StorageSlotContract8616(
        role=StorageTrialRole8616.RETURN,
        logical_index=0,
        pieces=(_identity(2, register="ax"), _identity(2, register="dx")),
        signedness=StorageTrialSignedness8616.UNSIGNED,
        value_class=StorageTrialValueClass8616.VALUE,
    )

    result = storage_contract_return_type_8616(
        _contract(outputs=(output,)),
        Arch86_16(),
    )

    assert result.accepted
    assert isinstance(result.sim_type, SimTypeLong)
    assert result.sim_type.signed is False
    assert result.c_type == "unsigned long"


def _dx_ax_pointer_return_slot(
    *, pointee_width_bytes: int | None = None
) -> StorageSlotContract8616:
    """Build the proven DX:AX register pair classified as a pointer result."""
    return StorageSlotContract8616(
        role=StorageTrialRole8616.RETURN,
        logical_index=0,
        pieces=(_identity(2, register="ax"), _identity(2, register="dx")),
        signedness=StorageTrialSignedness8616.NOT_APPLICABLE,
        value_class=StorageTrialValueClass8616.POINTER,
        pointee_width_bytes=pointee_width_bytes,
    )


def test_dx_ax_pointer_return_refuses_without_independent_pointee() -> None:
    """Caller-dereference width alone can never authorize a far pointer."""
    projected = storage_contract_return_type_8616(
        _contract(outputs=(_dx_ax_pointer_return_slot(pointee_width_bytes=2),)),
        Arch86_16(),
    )

    assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
    assert projected.failures == (
        StorageSimTypeFailureKind8616.POINTEE_FAMILY_UNPROVEN,
    )
    assert projected.sim_type is None and projected.c_type is None


def test_dx_ax_pointer_return_projects_far_pointer_from_proven_pointee() -> None:
    """An independently proven pointee family publishes the 32-bit far type."""
    arch = Arch86_16()
    pointee = SimTypeShort(False).with_arch(arch)

    projected = storage_contract_return_type_8616(
        _contract(outputs=(_dx_ax_pointer_return_slot(pointee_width_bytes=2),)),
        arch,
        proven_far_pointee=pointee,
    )

    assert projected.accepted
    assert isinstance(projected.sim_type, SimTypeFarPointer16_8616)
    assert projected.sim_type.size == 32
    assert projected.sim_type.pts_to == pointee
    assert projected.sim_type._arch is arch
    assert projected.c_type == "unsigned short *"


def test_dx_ax_pointer_return_refuses_conflicting_dereference_width() -> None:
    """A proven word family cannot publish when callers observed bytes."""
    arch = Arch86_16()

    projected = storage_contract_return_type_8616(
        _contract(outputs=(_dx_ax_pointer_return_slot(pointee_width_bytes=1),)),
        arch,
        proven_far_pointee=SimTypeShort(False).with_arch(arch),
    )

    assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
    assert projected.failures == (
        StorageSimTypeFailureKind8616.POINTEE_WIDTH_CONFLICT,
    )


def test_dx_ax_pointer_return_refuses_empty_pointee_family() -> None:
    """A bottom pointee carries no family proof and must still refuse."""
    arch = Arch86_16()

    projected = storage_contract_return_type_8616(
        _contract(outputs=(_dx_ax_pointer_return_slot(),)),
        arch,
        proven_far_pointee=SimTypeBottom(label="void").with_arch(arch),
    )

    assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
    assert projected.failures == (
        StorageSimTypeFailureKind8616.POINTEE_FAMILY_UNPROVEN,
    )


def test_dx_ax_pointer_return_refuses_existing_near_pointer() -> None:
    """A published near return type contradicts a proven far result."""
    arch = Arch86_16()
    near = near_pointer_type_8616(SimTypeShort(False).with_arch(arch), arch)

    projected = storage_contract_return_type_8616(
        _contract(outputs=(_dx_ax_pointer_return_slot(),)),
        arch,
        existing_type=near,
        proven_far_pointee=SimTypeShort(False).with_arch(arch),
    )

    assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
    assert projected.failures == (
        StorageSimTypeFailureKind8616.POINTER_WIDTH_CONFLICT,
    )


def test_dx_ax_pointer_return_retains_existing_far_pointee() -> None:
    """The same independently proven family retains a concrete far pointee."""
    arch = Arch86_16()
    item_type = SimStruct(
        {"value": SimTypeShort(False).with_arch(arch)}, name="Item"
    ).with_arch(arch)
    existing = far_pointer_type_8616(item_type, arch)

    projected = storage_contract_return_type_8616(
        _contract(outputs=(_dx_ax_pointer_return_slot(),)),
        arch,
        existing_type=existing,
        proven_far_pointee=item_type,
    )

    assert projected.accepted
    assert isinstance(projected.sim_type, SimTypeFarPointer16_8616)
    assert projected.sim_type.pts_to == item_type
    assert projected.c_type == "struct Item *"


def test_dx_ax_pointer_return_refuses_generic_32_bit_pointer() -> None:
    """A generic host-width pointer is not proof of the DOS FAR ABI."""
    arch = Arch86_16()
    arch.bits = 32  # The loaded DOS project uses angr's 32-bit address view.
    pointee = SimTypeShort(False).with_arch(arch)
    generic = SimTypePointer(pointee).with_arch(arch)
    assert generic.size == 32

    projected = storage_contract_return_type_8616(
        _contract(outputs=(_dx_ax_pointer_return_slot(),)),
        arch,
        existing_type=generic,
        proven_far_pointee=pointee,
    )

    assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
    assert projected.sim_type is None
    assert projected.failures == (
        StorageSimTypeFailureKind8616.POINTER_ABI_CONFLICT,
    )


def test_dx_ax_pointer_return_refuses_equal_width_different_pointee_family() -> None:
    """A word-sized struct and a word scalar are distinct C contracts."""
    arch = Arch86_16()
    item_type = SimStruct(
        {"value": SimTypeShort(False).with_arch(arch)}, name="Item"
    ).with_arch(arch)
    existing = far_pointer_type_8616(item_type, arch)

    projected = storage_contract_return_type_8616(
        _contract(outputs=(_dx_ax_pointer_return_slot(),)),
        arch,
        existing_type=existing,
        proven_far_pointee=SimTypeShort(False).with_arch(arch),
    )

    assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
    assert projected.sim_type is None
    assert projected.failures == (
        StorageSimTypeFailureKind8616.POINTEE_FAMILY_CONFLICT,
    )


def test_four_byte_pointer_slot_without_dx_ax_pair_refuses_width() -> None:
    """Far publication requires the exact DX:AX pair, not any 4-byte slot."""
    arch = Arch86_16()
    stack_pair = StorageSlotContract8616(
        role=StorageTrialRole8616.RETURN,
        logical_index=0,
        pieces=(_identity(2, offset=-2), _identity(2, offset=-4)),
        signedness=StorageTrialSignedness8616.NOT_APPLICABLE,
        value_class=StorageTrialValueClass8616.POINTER,
    )
    input_pair = StorageSlotContract8616(
        role=StorageTrialRole8616.INPUT,
        logical_index=0,
        pieces=(_identity(2, offset=6), _identity(2, offset=8)),
        signedness=StorageTrialSignedness8616.NOT_APPLICABLE,
        value_class=StorageTrialValueClass8616.POINTER,
    )

    for slot in (stack_pair, input_pair):
        projected = storage_slot_simtype_8616(
            slot,
            arch,
            proven_far_pointee=SimTypeShort(False).with_arch(arch),
        )
        assert projected.verdict is StorageSimTypeVerdict8616.REFUSED
        assert projected.failures == (
            StorageSimTypeFailureKind8616.UNSUPPORTED_WIDTH,
        )


def test_proven_far_pointee_does_not_alter_near_pointer_return() -> None:
    """The far-pointee input is only consumed by the proven DX:AX shape."""
    arch = Arch86_16()
    slot = StorageSlotContract8616(
        role=StorageTrialRole8616.RETURN,
        logical_index=0,
        pieces=(_identity(2, register="ax"),),
        signedness=StorageTrialSignedness8616.NOT_APPLICABLE,
        value_class=StorageTrialValueClass8616.POINTER,
        pointee_width_bytes=1,
    )

    projected = storage_contract_return_type_8616(
        _contract(outputs=(slot,)),
        arch,
        proven_far_pointee=SimTypeShort(False).with_arch(arch),
    )

    assert projected.accepted
    assert isinstance(projected.sim_type, SimTypeNearPointer16_8616)
    assert projected.c_type == "char *"
