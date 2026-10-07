from types import SimpleNamespace

from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)

from inertia.semantics.binary_call_contracts import (
    binary_call_return_contract_8616,
)
from inertia.semantics.call_contracts import (
    CallContractEvidenceKind8616,
)
from inertia.cli.project_loading import _build_project_from_bytes


def _project(code: bytes) -> object:
    return _build_project_from_bytes(
        code,
        base_addr=0x1000,
        entry_point=0x1000,
    )


def _address(offset: int, size: int = 2) -> IRAddress:
    return IRAddress(
        space=MemSpace.DS,
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def test_binary_contract_proves_masked_ax_and_exact_disjoint_write() -> None:
    code = (
        b"\xe8\x0d\x00"
        b"\xa3\x00\x20"
        b"\x80\xe4\x7f"
        b"\xc3"
        b"\x90\x90\x90\x90\x90\x90"
        b"\xb8\xff\xff\xc3"
    )

    contract = binary_call_return_contract_8616(_project(code), 0x1000)

    assert contract is not None
    assert contract.evidence_kind is CallContractEvidenceKind8616.DECODED_BINARY
    assert contract.value_range.minimum == 0
    assert contract.value_range.maximum == 0x7FFF
    assert contract.exact_memory_writes == (_address(0x2000),)
    assert not contract.preserves_caller_storage
    assert contract.preserves_address(_address(0x2100))
    assert not contract.preserves_address(_address(0x1FFF, 2))


def test_binary_contract_refuses_unmasked_return() -> None:
    assert binary_call_return_contract_8616(
        _project(b"\xb8\xff\xff\xc3"),
        0x1000,
    ) is None


def test_binary_contract_refuses_ax_overwrite_after_mask() -> None:
    assert binary_call_return_contract_8616(
        _project(b"\x80\xe4\x7f\xb8\xff\xff\xc3"),
        0x1000,
    ) is None


def test_binary_contract_refuses_unknown_indexed_memory_write() -> None:
    assert binary_call_return_contract_8616(
        _project(b"\x89\x07\x80\xe4\x7f\xc3"),
        0x1000,
    ) is None


def test_binary_contract_refuses_project_without_loader() -> None:
    assert binary_call_return_contract_8616(SimpleNamespace(), 0x1000) is None
