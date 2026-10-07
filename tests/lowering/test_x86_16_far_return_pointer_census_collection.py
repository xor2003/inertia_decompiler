"""Source-free production collection of every paired far-return caller use."""

from __future__ import annotations

import io

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.far_return_pointer_census import (
    FarReturnPointerCensusFailure8616,
    collect_far_return_pointer_census_8616,
)


def _two_far_call_project(
    *, paired_return: bool = True,
) -> tuple[angr.Project, tuple[tuple[int, int], ...]]:
    """Build two independent far CALL and ES:BX uses without a sidecar."""
    call_and_use = bytes.fromhex("9a 30 00 00 01 8e c2 89 c3 26 83 3f 00")
    caller_code = call_and_use + call_and_use + bytes.fromhex("c3")
    callee_code = (
        bytes.fromhex("b8 20 00 ba 01 00 cb")
        if paired_return else bytes.fromhex("b8 20 00 cb")
    )
    image = bytearray(0x30 + len(callee_code))
    image[:len(caller_code)] = caller_code
    image[0x30:] = callee_code
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x1000,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    ranges = ((0x1000, 0x1000 + len(caller_code)), (0x1030, 0x1030 + len(callee_code)))
    return project, ranges


def test_collector_proves_both_far_result_uses_from_binary() -> None:
    project, ranges = _two_far_call_project()

    result = collect_far_return_pointer_census_8616(
        project, 0x1030, ranges,
    )

    assert result.complete
    assert tuple(use.callsite_addr for use in result.uses) == (0x1000, 0x100D)
    assert result.stats.raw_fact_count == result.stats.materialized_count == 2
    assert result.stats.failure_count == 0


def test_collector_refuses_unproven_callee_return_pair() -> None:
    project, ranges = _two_far_call_project(paired_return=False)

    result = collect_far_return_pointer_census_8616(
        project, 0x1030, ranges,
    )

    assert result.failure is FarReturnPointerCensusFailure8616.CALLEE_OUTPUT_NOT_FAR_PAIR
    assert not result.complete


def test_collector_refuses_missing_callee_boundary() -> None:
    project, ranges = _two_far_call_project()

    result = collect_far_return_pointer_census_8616(project, 0x1030, ranges[:1])

    assert result.failure is FarReturnPointerCensusFailure8616.CALLEE_BOUNDARY_UNPROVEN
    assert not result.complete
