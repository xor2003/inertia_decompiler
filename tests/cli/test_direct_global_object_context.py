from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.global_object_program_requirement import (
    GlobalObjectProgramRequirementEvidence8616,
    GlobalObjectProgramRequirementReason8616,
    GlobalObjectProgramRequirementVerdict8616,
)

import inertia.cli.cache as cache_module
import inertia.cli.direct_global_object_context as direct_context
import inertia.cli.indexed_alias_program_context as indexed_context
from inertia.alias.indexed_address_program import (
    IndexedAliasFunctionSelection8616,
    build_indexed_alias_program_evidence_8616,
)
from inertia.widening.indexed_global_object_layout import (
    recover_global_object_layout_evidence_8616,
)
from inertia.widening.indexed_global_object_program_ranges import (
    recover_program_bounded_global_object_ranges_8616,
)
from inertia.cli.direct_global_object_cache import (
    direct_global_object_cache_key_8616,
    load_direct_global_object_cache_8616,
)
from inertia.cli.function_ir_ssa_cache import (
    FunctionIRSSACacheStats8616,
    FunctionIRSSACatalogResult8616,
)
from inertia.cli.indexed_alias_program_context import (
    IndexedAliasProgramContextStatus8616,
    prepare_direct_indexed_alias_program_context_8616,
)
from inertia.cli.indexed_alias_program_recovery import (
    RecoveredIndexedAliasCatalog8616,
)
from inertia.cli.indexed_global_object_cache import (
    PersistedIndexedGlobalObjectEvidence8616,
    indexed_global_object_cache_key_8616,
    store_indexed_global_object_cache_8616,
)

_CODE = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 88 87 00 02 c9 c3"
)


def _project() -> angr.Project:
    return angr.Project(
        io.BytesIO(_CODE),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )


def _function() -> object:
    return SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})


def _requirement() -> GlobalObjectProgramRequirementEvidence8616:
    return GlobalObjectProgramRequirementEvidence8616(
        verdict=GlobalObjectProgramRequirementVerdict8616.REQUIRED,
        reasons=(GlobalObjectProgramRequirementReason8616.LOCAL_GLOBAL_INDEXED_ACCESS,),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        local_fact_count=1,
        global_pointer_source_count=0,
        stack_pointer_source_count=0,
        pointer_target_addrs=(),
        callsite_addrs=(),
    )


def _empty_ir_ssa_cache() -> FunctionIRSSACatalogResult8616:
    return FunctionIRSSACatalogResult8616((), FunctionIRSSACacheStats8616())


def test_direct_global_cache_miss_rebuilds_only_direct_evidence_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    source_project = _project()
    source_function = _function()
    binary_path = tmp_path / "fixture.exe"
    binary_path.write_bytes(_CODE)

    program = build_indexed_alias_program_evidence_8616(
        source_project,
        (IndexedAliasFunctionSelection8616(0x1000, source_function),),
    )
    layouts = recover_global_object_layout_evidence_8616(program)
    ranges = recover_program_bounded_global_object_ranges_8616(program, layouts)
    indexed_key = indexed_global_object_cache_key_8616(source_project, binary_path)
    direct_key = direct_global_object_cache_key_8616(source_project, binary_path)
    assert indexed_key is not None
    assert direct_key is not None
    store_indexed_global_object_cache_8616(
        indexed_key,
        PersistedIndexedGlobalObjectEvidence8616(layouts, ranges),
    )

    catalog = RecoveredIndexedAliasCatalog8616(
        source_project,
        (source_function,),
        _empty_ir_ssa_cache(),
    )
    catalog_calls: list[int] = []
    collector_calls: list[int] = []

    def recover_catalog(*_args: object, **_kwargs: object) -> RecoveredIndexedAliasCatalog8616:
        catalog_calls.append(1)
        return catalog

    def collect_widths(*_args: object) -> tuple[SimpleNamespace, ...]:
        collector_calls.append(1)
        return (SimpleNamespace(offset=0x0B4C, width=4),)

    monkeypatch.setattr(
        indexed_context,
        "collect_global_object_program_requirement_8616",
        lambda *_args: _requirement(),
    )
    monkeypatch.setattr(
        indexed_context,
        "recover_direct_indexed_alias_catalog_8616",
        recover_catalog,
    )
    monkeypatch.setattr(
        indexed_context,
        "publish_discovered_indexed_alias_program_8616",
        lambda *_args, **_kwargs: pytest.fail("indexed Alias/Widening must not rebuild"),
    )
    monkeypatch.setattr(
        direct_context,
        "collect_project_direct_global_width_evidence_8616",
        collect_widths,
    )

    first_target = _project()
    first = prepare_direct_indexed_alias_program_context_8616(
        source_project,
        first_target,
        _function(),
        timeout=1,
        window=0x100,
        binary_path=binary_path,
    )

    assert first.status is IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING
    assert catalog_calls == [1]
    assert collector_calls == [1]
    assert first_target._inertia_project_direct_global_object_layout_evidence_8616.layouts
    assert load_direct_global_object_cache_8616(direct_key) is not None

    monkeypatch.setattr(
        indexed_context,
        "recover_direct_indexed_alias_catalog_8616",
        lambda *_args, **_kwargs: pytest.fail("direct-global cache hit must avoid recovery"),
    )
    second_target = _project()
    second = prepare_direct_indexed_alias_program_context_8616(
        source_project,
        second_target,
        _function(),
        timeout=1,
        window=0x100,
        binary_path=binary_path,
    )

    assert second.status is IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING
    assert collector_calls == [1]
    assert second_target._inertia_project_direct_global_object_layout_evidence_8616 == (
        first_target._inertia_project_direct_global_object_layout_evidence_8616
    )


def test_direct_global_cache_miss_does_not_block_persisted_widening(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    source_project = _project()
    source_function = _function()
    binary_path = tmp_path / "fixture.exe"
    binary_path.write_bytes(_CODE)
    program = build_indexed_alias_program_evidence_8616(
        source_project,
        (IndexedAliasFunctionSelection8616(0x1000, source_function),),
    )
    layouts = recover_global_object_layout_evidence_8616(program)
    ranges = recover_program_bounded_global_object_ranges_8616(program, layouts)
    indexed_key = indexed_global_object_cache_key_8616(source_project, binary_path)
    assert indexed_key is not None
    store_indexed_global_object_cache_8616(
        indexed_key,
        PersistedIndexedGlobalObjectEvidence8616(layouts, ranges),
    )
    monkeypatch.setattr(
        indexed_context,
        "collect_global_object_program_requirement_8616",
        lambda *_args: _requirement(),
    )
    monkeypatch.setattr(
        indexed_context,
        "recover_direct_indexed_alias_catalog_8616",
        lambda *_args, **_kwargs: None,
    )
    target_project = _project()

    result = prepare_direct_indexed_alias_program_context_8616(
        source_project,
        target_project,
        _function(),
        timeout=1,
        window=0x100,
        binary_path=binary_path,
    )

    assert result.status is IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING
    restored = target_project._inertia_project_global_object_layout_evidence_8616
    assert restored.closed
    assert restored.layouts == layouts.layouts
    assert "_inertia_project_direct_global_object_layout_evidence_8616" not in vars(
        target_project
    )
