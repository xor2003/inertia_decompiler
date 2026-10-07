"""Binary caller bodies must survive an interior optional signature hint."""

from __future__ import annotations

import io
from dataclasses import replace
from typing import Any, cast

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

from inertia.cli import cli_function_discovery as discovery
from inertia.cli import discovery_candidate_ranges as ranges_module
from inertia.cli.lst_extract import LSTMetadata
from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from inertia.semantics.callsite_summary import (
    CallerReturnUseVerdict8616,
    collect_caller_return_use_evidence_8616,
)


def _project_with_signature(*, indirect_exit: bool = False) -> angr.Project:
    """Load a framed conditional caller and callee, without source/debug bounds."""
    # The signature hint is at the conditional return arm, not a function end.
    caller = bytes.fromhex(
        "55 89 e5 85 c0 74 05 b8 04 00 eb 06 e8 11 00 89 46 fe 89 ec 5d c3"
    )
    if indirect_exit:
        caller = caller[:-1] + bytes.fromhex("ff e0")
    callee = bytes.fromhex("55 89 e5 b8 07 00 5d c3")
    image = caller.ljust(0x20, b"\x90") + callee.ljust(0x10, b"\x90") + b"\xc3"
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x1030,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    cast(Any, project)._inertia_lst_metadata = LSTMetadata(
        data_labels={}, code_labels={0x1007: "optional_hint"},
        signature_code_addrs=frozenset({0x1007}),
        source_format="tools.signatures.signature_catalog",
    )
    return project


def test_interior_signature_cannot_truncate_closed_binary_caller() -> None:
    """A complete binary body outranks an interior candidate-window hint."""
    project = _project_with_signature()
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1020)
    assert boundary is not None
    assert {0x1007, 0x100C, 0x100F} <= boundary.reachable_instruction_addrs

    ranges = discovery._pre_entry_source_function_ranges_8616(project, (0x1000, 0x1020))

    assert ranges[:2] == ((0x1000, 0x1020), (0x1016, 0x1030))


def test_caller_census_keeps_call_after_interior_signature() -> None:
    """The original typed collector must see the actual post-hint return use."""
    project = _project_with_signature()
    ranges = discovery._pre_entry_source_function_ranges_8616(project, (0x1000, 0x1020))

    evidence = collect_caller_return_use_evidence_8616(project, 0x1020, ranges)

    assert evidence.verdict is CallerReturnUseVerdict8616.USED
    assert evidence.callsite_addrs == (0x100C,)
    assert (
        evidence.raw_fact_count, evidence.normalized_fact_count,
        evidence.classified_fact_count, evidence.materialized_count,
        evidence.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_open_binary_caller_does_not_authorize_range_expansion() -> None:
    """An unresolved indirect exit must retain the existing conservative hint."""
    project = _project_with_signature(indirect_exit=True)
    assert exact_function_range_boundary_8616(project, 0x1000, 0x1020) is None

    ranges = discovery._pre_entry_source_function_ranges_8616(project, (0x1000, 0x1020))

    assert ranges[0] == (0x1000, 0x1007)


def test_signature_after_return_remains_a_separate_boundary() -> None:
    """Closed reachability must not absorb an unreachable neighboring body."""
    project = _project_with_signature()
    cast(Any, project)._inertia_lst_metadata = LSTMetadata(
        data_labels={}, code_labels={0x1018: "separate_entry"},
        signature_code_addrs=frozenset({0x1018}), source_format="tools.signatures.signature_catalog",
    )

    ranges = discovery._pre_entry_source_function_ranges_8616(project, (0x1000, 0x1020))

    assert ranges[0] == (0x1000, 0x1018)


def test_interior_hint_does_not_erase_next_unreachable_library_boundary() -> None:
    """Discard only proven interior hints, not every hint in the wider window."""
    project = _project_with_signature()
    cast(Any, project)._inertia_lst_metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1007: "interior_hint", 0x1018: "separate_entry"},
        signature_code_addrs=frozenset({0x1007, 0x1018}),
        source_format="tools.signatures.signature_catalog",
    )

    ranges = discovery._pre_entry_source_function_ranges_8616(project, (0x1000, 0x1020))

    assert ranges[0] == (0x1000, 0x1018)


@pytest.mark.parametrize("foreign_project", (True, False))
def test_caller_range_refuses_foreign_or_stale_binary_proof(
    monkeypatch: pytest.MonkeyPatch, foreign_project: bool,
) -> None:
    """Matching addresses alone cannot borrow another owner or range's body."""
    project = _project_with_signature()
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1020)
    assert boundary is not None
    if foreign_project:
        boundary = replace(boundary, project=_project_with_signature())
    else:
        boundary = replace(boundary, size=0x10)
    monkeypatch.setattr(
        ranges_module, "exact_function_range_boundary_8616",
        lambda _project, _start, _end: boundary,
    )

    ranges = discovery._pre_entry_source_function_ranges_8616(project, (0x1000, 0x1020))

    assert ranges[0] == (0x1000, 0x1007)
