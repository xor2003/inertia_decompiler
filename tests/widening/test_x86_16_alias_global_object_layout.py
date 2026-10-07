from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from inertia.lowering.project_global_object_layout import (
    collect_project_global_object_layout_evidence_8616,
)

import inertia.cli.cache as cache_module
import inertia.cli.indexed_alias_program_recovery as indexed_recovery
from inertia.alias.indexed_address_program import (
    IndexedAliasFunctionSelection8616,
    IndexedAliasProgramEvidence8616,
    IndexedAliasProgramFailureKind8616,
    build_indexed_alias_program_evidence_8616,
)
from inertia.widening.global_object_layout import (
    GlobalObjectLayoutFailureKind8616,
    TransportedGlobalObjectLayoutSource8616,
)
from inertia.widening.global_object_layout_codec import (
    global_object_layout_evidence_from_record_8616,
    global_object_layout_evidence_record_8616,
)
from inertia.widening.indexed_global_object_layout import (
    recover_global_object_layout_evidence_8616,
)
from inertia.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeSourceKind8616,
    recover_program_bounded_global_object_ranges_8616,
)
from inertia.cli.discovery_cache_contract import (
    SourceRegionCatalogEvidence8616,
)
from inertia.cli.indexed_alias_program_context import (
    IndexedAliasProgramContextStatus8616,
    prepare_direct_indexed_alias_program_context_8616,
)

BYTE_FIELD_VIEWS = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 88 87 00 02 "
    "8b 5e fe d1 e3 88 a7 01 02 "
    "8b 5e fe d1 e3 88 87 00 03 "
    "8b 5e fe d1 e3 88 a7 01 03 c9 c3"
)
MISMATCHED_INDEX_BYTE_FIELDS = bytes.fromhex(
    "55 89 e5 83 ec 04 c7 46 fe 01 00 c7 46 fc 02 00 "
    "8b 5e fe d1 e3 88 87 00 02 "
    "8b 5e fc d1 e3 88 a7 01 02 c9 c3"
)
GLOBAL_WORD_COPY = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 8b 87 00 02 "
    "8b 5e fe d1 e3 89 87 00 03 c9 c3"
)
TRANSFORMED_GLOBAL_WORD_COPY = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 8b 87 00 02 40 "
    "8b 5e fe d1 e3 89 87 00 03 c9 c3"
)


def _function(function_addr: int) -> object:
    return SimpleNamespace(
        addr=function_addr,
        block_addrs_set={function_addr},
        info={},
    )


def _program(
    field_code: bytes = BYTE_FIELD_VIEWS,
    copy_code: bytes = GLOBAL_WORD_COPY,
    *,
    include_missing: bool = False,
) -> tuple[angr.Project, IndexedAliasProgramEvidence8616]:
    padding = b"\x90" * (0x100 - len(field_code))
    project = angr.Project(
        io.BytesIO(field_code + padding + copy_code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    selections = [
        IndexedAliasFunctionSelection8616(0x1000, _function(0x1000)),
        IndexedAliasFunctionSelection8616(0x1100, _function(0x1100)),
    ]
    if include_missing:
        selections.append(IndexedAliasFunctionSelection8616(0x1080, None))
    return project, build_indexed_alias_program_evidence_8616(project, selections)


def test_real_alias_program_widens_two_layouts_and_exact_copy_family() -> None:
    project, program = _program()

    assert program.closed
    assert program.stats.raw_fact_count == program.stats.materialized_count == 2
    assert program.refusals == ()
    for function_addr in (0x1000, 0x1100):
        registered = registered_function_ssa_artifact_8616(project, function_addr)
        assert registered.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        assert registered.artifact is not None

    result = recover_global_object_layout_evidence_8616(program)

    assert result.closed
    assert tuple(layout.address.offset for layout in result.layouts) == (0x200, 0x300)
    assert tuple(layout.field_offsets for layout in result.layouts) == ((0, 1), (0, 1))
    assert tuple(layout.family_base_offset for layout in result.layouts) == (0x200, 0x200)
    assert result.raw_fact_count == 11
    assert result.materialized_count == 7
    assert result.failure_count == 4
    assert {
        refusal.failure for refusal in result.refusals
    } == {GlobalObjectLayoutFailureKind8616.UPSTREAM_COPY_REFUSAL}
    assert all(function.ranges.closed for function in program.functions)


def test_transformed_copy_does_not_join_proven_layout_families() -> None:
    _project, program = _program(copy_code=TRANSFORMED_GLOBAL_WORD_COPY)

    result = recover_global_object_layout_evidence_8616(program)

    assert result.closed
    assert tuple(layout.address.offset for layout in result.layouts) == (0x200, 0x300)
    assert tuple(layout.family_base_offset for layout in result.layouts) == (0x200, 0x300)
    assert GlobalObjectLayoutFailureKind8616.UPSTREAM_COPY_REFUSAL in {
        refusal.failure for refusal in result.refusals
    }


def test_byte_fields_with_different_alias_identities_do_not_form_layout() -> None:
    _project, program = _program(field_code=MISMATCHED_INDEX_BYTE_FIELDS)

    result = recover_global_object_layout_evidence_8616(program)

    assert result.closed
    assert result.layouts == ()
    failures = {refusal.failure for refusal in result.refusals}
    assert GlobalObjectLayoutFailureKind8616.LAYOUT_NOT_PROVEN in failures
    assert GlobalObjectLayoutFailureKind8616.COPY_ENDPOINT_NOT_LAYOUT in failures


def test_incomplete_alias_program_suppresses_partial_layout_inference() -> None:
    _project, program = _program(include_missing=True)

    assert program.closed
    assert len(program.refusals) == 1
    assert (
        program.refusals[0].failure
        is IndexedAliasProgramFailureKind8616.FUNCTION_MISSING
    )

    result = recover_global_object_layout_evidence_8616(program)

    assert result.closed
    assert result.layouts == ()
    assert result.materialized_count == 0
    assert result.raw_fact_count == result.failure_count
    failures = {refusal.failure for refusal in result.refusals}
    assert GlobalObjectLayoutFailureKind8616.UPSTREAM_FUNCTION_REFUSAL in failures
    assert GlobalObjectLayoutFailureKind8616.PROGRAM_CENSUS_INCOMPLETE in failures


def test_program_refuses_a_conflicting_supplied_function_boundary() -> None:
    project, _program_evidence = _program()

    result = build_indexed_alias_program_evidence_8616(
        project,
        (IndexedAliasFunctionSelection8616(0x1000, _function(0x1001)),),
    )

    assert result.closed
    assert result.functions == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert (
        result.refusals[0].failure
        is IndexedAliasProgramFailureKind8616.FUNCTION_BOUNDARY_CONFLICT
    )


def test_lowering_orchestrator_reuses_typed_alias_program_and_layout_cache() -> None:
    _project, program = _program()
    original = SimpleNamespace(
        _inertia_indexed_alias_program_evidence_8616=program,
    )
    surface = SimpleNamespace(
        _inertia_caller_function_ranges_8616=((0x1000, 0x1050), (0x1100, 0x1150)),
        _inertia_original_project=original,
    )

    first = collect_project_global_object_layout_evidence_8616(surface)
    second = collect_project_global_object_layout_evidence_8616(surface)

    assert first is second
    assert first.closed
    assert tuple(layout.family_base_offset for layout in first.layouts) == (0x200, 0x200)
    assert original._inertia_indexed_alias_program_evidence_8616 is program


def test_closed_widening_evidence_round_trips_for_clean_workers() -> None:
    _project, program = _program()
    original = recover_global_object_layout_evidence_8616(program)

    record = global_object_layout_evidence_record_8616(original)
    restored = global_object_layout_evidence_from_record_8616(record)

    assert restored.closed
    assert restored.layouts == original.layouts
    assert restored.raw_fact_count == original.raw_fact_count
    assert restored.materialized_count == original.materialized_count
    assert restored.failure_count == original.failure_count
    assert all(
        isinstance(refusal.source, TransportedGlobalObjectLayoutSource8616)
        for refusal in restored.refusals
    )
    assert global_object_layout_evidence_record_8616(restored) == record


def test_transported_widening_still_publishes_local_ir_ssa() -> None:
    _evidence_project, program = _program()
    project = angr.Project(
        io.BytesIO(BYTE_FIELD_VIEWS),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    layouts = recover_global_object_layout_evidence_8616(program)
    project._inertia_project_global_object_layout_evidence_8616 = layouts
    project._inertia_project_bounded_global_object_ranges_8616 = (
        recover_program_bounded_global_object_ranges_8616(program, layouts)
    )

    result = prepare_direct_indexed_alias_program_context_8616(
        project,
        project,
        _function(0x1000),
        timeout=1,
        window=0x100,
    )

    assert result.status is IndexedAliasProgramContextStatus8616.REUSED_WIDENING
    assert registered_function_ssa_artifact_8616(
        project,
        0x1000,
    ).verdict is FunctionSSAArtifactVerdict8616.PROVEN


def test_persisted_widening_reuses_complete_layout_across_fresh_projects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    evidence_project, _program_evidence = _program()
    binary_path = tmp_path / "fixture.exe"
    binary_path.write_bytes(BYTE_FIELD_VIEWS + b"\x90" * 0x100 + GLOBAL_WORD_COPY)
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(
        indexed_recovery,
        "isolated_discovery_evidence_project_8616",
        lambda _project: evidence_project,
    )
    recovery_calls: list[int] = []

    def recover_catalog(*_args: object, **_kwargs: object) -> list[tuple[object, object]]:
        recovery_calls.append(1)
        return [(object(), _function(0x1000)), (object(), _function(0x1100))]

    complete_catalog = SourceRegionCatalogEvidence8616(2, 2, 2, 2, 0, ())
    monkeypatch.setattr(indexed_recovery, "_recover_fast_exe_catalog", recover_catalog)
    monkeypatch.setattr(
        indexed_recovery,
        "_source_region_catalog_evidence_8616",
        lambda _project: complete_catalog,
    )

    def direct_project() -> angr.Project:
        return angr.Project(
            io.BytesIO(BYTE_FIELD_VIEWS),
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": 0x1000,
                "entry_point": 0x1000,
            },
            auto_load_libs=False,
        )

    first_project = direct_project()
    first = prepare_direct_indexed_alias_program_context_8616(
        evidence_project,
        first_project,
        _function(0x1000),
        timeout=1,
        window=0x100,
        binary_path=binary_path,
    )
    second_project = direct_project()
    second = prepare_direct_indexed_alias_program_context_8616(
        evidence_project,
        second_project,
        _function(0x1000),
        timeout=1,
        window=0x100,
        binary_path=binary_path,
    )

    assert first.status is IndexedAliasProgramContextStatus8616.PUBLISHED
    assert second.status is IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING
    assert recovery_calls == [1]
    assert first_project._inertia_project_global_object_layout_evidence_8616.closed
    assert second_project._inertia_project_global_object_layout_evidence_8616.closed
    first_ranges = first_project._inertia_project_bounded_global_object_ranges_8616
    second_ranges = second_project._inertia_project_bounded_global_object_ranges_8616
    assert first_ranges.closed
    assert second_ranges.closed
    assert first_ranges.layouts == first_project._inertia_project_global_object_layout_evidence_8616
    assert second_ranges.layouts == second_project._inertia_project_global_object_layout_evidence_8616
    assert (
        first_ranges.source.kind
        is ProjectBoundedGlobalObjectRangeSourceKind8616.LIVE_ALIAS_PROGRAM
    )
    assert (
        second_ranges.source.kind
        is ProjectBoundedGlobalObjectRangeSourceKind8616.TRANSPORTED_RECORD
    )
    assert registered_function_ssa_artifact_8616(
        second_project,
        0x1000,
    ).verdict is FunctionSSAArtifactVerdict8616.PROVEN
