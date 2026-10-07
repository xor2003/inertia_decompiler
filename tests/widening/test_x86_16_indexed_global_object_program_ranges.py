from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)

from inertia.alias.indexed_address_program import (
    IndexedAliasFunctionSelection8616,
    build_indexed_alias_program_evidence_8616,
)
from inertia.widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)
from inertia.widening.indexed_global_object_program_range_codec import (
    project_bounded_global_ranges_from_record_8616,
    project_bounded_global_ranges_record_8616,
)
from inertia.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeSourceKind8616,
    recover_program_bounded_global_object_ranges_8616,
)
from inertia.widening.indexed_global_object_ranges import (
    BoundedGlobalObjectRangeFailureKind8616,
)

INDEXED_WORD_LOOP = bytes.fromhex(
    "55 89 e5 83 ec 02 "
    "c7 46 fe 00 00 "
    "83 7e fe 04 "
    "73 0e "
    "8b 5e fe "
    "d1 e3 "
    "8b 87 00 02 "
    "ff 46 fe "
    "eb ec "
    "89 ec 5d c3"
)


def _program(*, include_missing: bool = False) -> tuple[object, object]:
    project = angr.Project(
        io.BytesIO(INDEXED_WORD_LOOP),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    selections = [
        IndexedAliasFunctionSelection8616(
            0x1000,
            SimpleNamespace(
                addr=0x1000,
                block_addrs_set={0x1000, 0x100B, 0x1011, 0x101F},
                info={},
            ),
        )
    ]
    if include_missing:
        selections.append(IndexedAliasFunctionSelection8616(0x1100, None))
    return project, build_indexed_alias_program_evidence_8616(project, selections)


def _layout() -> GlobalObjectLayoutEvidence8616:
    layout = GlobalObjectLayout8616(
        IRAddress(
            MemSpace.DS,
            offset=0x200,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        2,
        (0, 1),
        0x200,
    )
    return GlobalObjectLayoutEvidence8616((layout,), 1, 1, 1, 1)


def test_complete_program_census_materializes_one_exact_extent() -> None:
    _project_value, program = _program()

    result = recover_program_bounded_global_object_ranges_8616(
        program,
        _layout(),
    )

    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    object_range = result.ranges[0]
    assert (object_range.lower_inclusive, object_range.upper_exclusive) == (0, 4)
    assert object_range.element_width == 2
    assert object_range.byte_extent == 8
    assert len(object_range.covered_access_keys) == 1


def test_complete_project_extent_round_trips_for_clean_workers() -> None:
    _project_value, program = _program()
    original = recover_program_bounded_global_object_ranges_8616(program, _layout())

    record = project_bounded_global_ranges_record_8616(original)
    restored = project_bounded_global_ranges_from_record_8616(record)

    assert restored.closed
    assert restored.ranges == original.ranges
    assert restored.refusals == original.refusals
    assert restored.stats == original.stats
    assert restored.layouts == original.layouts
    assert (
        restored.source.kind
        is ProjectBoundedGlobalObjectRangeSourceKind8616.TRANSPORTED_RECORD
    )
    assert project_bounded_global_ranges_record_8616(restored) == record


def test_missing_function_refuses_the_project_extent() -> None:
    _project_value, program = _program(include_missing=True)

    result = recover_program_bounded_global_object_ranges_8616(
        program,
        _layout(),
    )

    assert result.closed
    assert result.ranges == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert (
        result.refusals[0].failure
        is BoundedGlobalObjectRangeFailureKind8616.PROGRAM_CENSUS_INCOMPLETE
    )
