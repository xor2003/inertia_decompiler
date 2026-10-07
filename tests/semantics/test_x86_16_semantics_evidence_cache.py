from __future__ import annotations

from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.logical_memory_contracts import IRMemoryAccessKind8616

from inertia.semantics.evidence_cache import (
    AccessRecord8616,
    collect_accesses_for_function,
    get_current_function_addr,
    record_access,
)


def test_x86_16_semantics_evidence_cache_tracks_function_context() -> None:
    with collect_accesses_for_function(0x1234):
        assert get_current_function_addr() == 0x1234

    assert get_current_function_addr() is None


def test_x86_16_semantics_evidence_cache_records_function_accesses() -> None:
    addr = IRAddress(
        MemSpace.DS,
        offset=0x1234,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )

    with collect_accesses_for_function(0x2000) as collection:
        record_access(
            0x2000,
            1,
            addr,
            block_addr=0x2000,
            insn_addr=0x2002,
            address_bits=16,
        )

    assert collection.accesses == [
        AccessRecord8616(
            function_addr=0x2000,
            block_addr=0x2000,
            insn_addr=0x2002,
            access_ordinal=0,
            kind=IRMemoryAccessKind8616.WRITE,
            address_bits=16,
            address=addr,
        )
    ]


def test_x86_16_semantics_evidence_cache_refuses_unowned_function_keys() -> None:
    record_access("not-an-int", 1, object())  # type: ignore[arg-type]

    with collect_accesses_for_function(0x2000) as collection:
        record_access(0x2001, 1, object())

    assert collection.accesses == []


def test_x86_16_semantics_evidence_cache_isolates_nested_collections() -> None:
    outer_addr = object()
    inner_addr = object()

    with collect_accesses_for_function(0x1000) as outer:
        record_access(0x1000, 0, outer_addr)
        with collect_accesses_for_function(0x1000) as inner:
            record_access(0x1000, 1, inner_addr)
        record_access(0x1000, 2, outer_addr)

    assert [record.mode for record in outer.accesses] == [0, 2]
    assert [record.mode for record in inner.accesses] == [1]
