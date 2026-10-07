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
import inertia.cli.indexed_alias_program_context as indexed_context
import inertia.cli.indexed_alias_program_recovery as indexed_recovery
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
from inertia.cli.cache_source_manifest import (
    FUNCTION_IR_SSA_CACHE_SOURCE_FILES,
    INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES,
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

_INDEXED_GLOBAL_CODE = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 88 87 00 02 c9 c3"
)


def _project(code: bytes) -> angr.Project:
    return angr.Project(
        io.BytesIO(code),
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


def _required_callsites() -> GlobalObjectProgramRequirementEvidence8616:
    return GlobalObjectProgramRequirementEvidence8616(
        verdict=GlobalObjectProgramRequirementVerdict8616.REQUIRED,
        reasons=(
            GlobalObjectProgramRequirementReason8616.LOCAL_GLOBAL_INDEXED_ACCESS,
        ),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        local_fact_count=1,
        global_pointer_source_count=0,
        stack_pointer_source_count=0,
        pointer_target_addrs=(0x1100,),
        callsite_addrs=(0x1008,),
    )


def _empty_ir_ssa_cache() -> FunctionIRSSACatalogResult8616:
    return FunctionIRSSACatalogResult8616((), FunctionIRSSACacheStats8616())


def test_indexed_alias_cache_scope_uses_exact_artifact_owners() -> None:
    import inertia.alias.indexed_address_program as indexed_address_program_module
    import inertia.frontend.x86_16.frontend_indirect_jump_targets as indirect_targets_module
    import inertia.frontend.x86_16.load_dos_mz as load_dos_mz_module
    import inertia.lowering.analysis_helpers as analysis_helpers_module
    import inertia.widening.global_object_layout as global_object_layout_module

    indexed_paths = set(INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES)
    relative_paths = {
        path.relative_to(Path(__file__).resolve().parents[2]).as_posix()
        for path in indexed_paths
    }

    assert set(FUNCTION_IR_SSA_CACHE_SOURCE_FILES) <= indexed_paths
    assert {
        Path(analysis_helpers_module.__file__).parent / "analysis_helpers.py",
        Path(indirect_targets_module.__file__).parent / "frontend_indirect_jump_targets.py",
        Path(load_dos_mz_module.__file__).parent / "load_dos_mz.py",
        Path(indexed_address_program_module.__file__).parent / "indexed_address_program.py",
        Path(global_object_layout_module.__file__).parent / "global_object_layout.py",
    } <= indexed_paths
    assert {
        "inertia/semantics/callsite_summary.py",
        "inertia/postprocess/decompiler_postprocess_stage.py",
        "inertia/lowering/register_local_declarations.py",
        "inertia/structuring/condition_lowering.py",
    }.isdisjoint(relative_paths)
    assert all(path.is_file() and path.suffix == ".py" for path in indexed_paths)


def test_callsite_cache_miss_reuses_persisted_alias_widening(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    source_project = _project(_INDEXED_GLOBAL_CODE)
    source_function = _function()
    program = build_indexed_alias_program_evidence_8616(
        source_project,
        (IndexedAliasFunctionSelection8616(0x1000, source_function),),
    )
    layouts = recover_global_object_layout_evidence_8616(program)
    ranges = recover_program_bounded_global_object_ranges_8616(program, layouts)
    binary_path = tmp_path / "fixture.exe"
    binary_path.write_bytes(_INDEXED_GLOBAL_CODE)
    cache_key = indexed_global_object_cache_key_8616(source_project, binary_path)
    assert cache_key is not None
    store_indexed_global_object_cache_8616(
        cache_key,
        PersistedIndexedGlobalObjectEvidence8616(layouts, ranges),
    )

    target_project = _project(_INDEXED_GLOBAL_CODE)
    recovered_catalog = RecoveredIndexedAliasCatalog8616(
        source_project,
        (source_function,),
        _empty_ir_ssa_cache(),
    )
    recovery_calls: list[int] = []
    callsite_steps: list[str] = []

    def recover_catalog(*_args: object, **_kwargs: object) -> RecoveredIndexedAliasCatalog8616:
        recovery_calls.append(1)
        return recovered_catalog

    monkeypatch.setattr(
        indexed_context,
        "collect_global_object_program_requirement_8616",
        lambda *_args: _required_callsites(),
    )
    monkeypatch.setattr(
        indexed_context,
        "attach_available_program_callsite_evidence_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        indexed_context,
        "recover_direct_indexed_alias_catalog_8616",
        recover_catalog,
    )
    monkeypatch.setattr(
        indexed_context,
        "publish_discovered_indexed_alias_program_8616",
        lambda *_args, **_kwargs: pytest.fail("Alias/Widening must not rebuild"),
    )
    monkeypatch.setattr(
        indexed_recovery,
        "attach_program_callsite_caller_ranges_8616",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        indexed_recovery,
        "collect_complete_project_callee_callsites_8616",
        lambda *_args: callsite_steps.append("collect"),
    )
    callsite_evidence = object()
    monkeypatch.setattr(
        indexed_recovery,
        "program_callsite_evidence_from_project_8616",
        lambda *_args: callsite_evidence,
    )
    monkeypatch.setattr(
        indexed_recovery,
        "attach_program_callsite_evidence_8616",
        lambda *_args: callsite_steps.append("attach"),
    )
    monkeypatch.setattr(
        indexed_recovery,
        "store_program_callsite_cache_8616",
        lambda *_args: callsite_steps.append("store"),
    )

    result = prepare_direct_indexed_alias_program_context_8616(
        source_project,
        target_project,
        _function(),
        timeout=1,
        window=0x100,
        binary_path=binary_path,
    )

    assert result.status is IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING
    assert recovery_calls == [1]
    assert callsite_steps == ["collect", "attach", "store"]
    restored_layouts = target_project._inertia_project_global_object_layout_evidence_8616
    restored_ranges = target_project._inertia_project_bounded_global_object_ranges_8616
    assert restored_layouts.closed
    assert restored_layouts.layouts == layouts.layouts
    assert restored_ranges.closed
    assert restored_ranges.layouts == restored_layouts


def test_failed_callsite_recovery_does_not_publish_partial_alias_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    source_project = _project(_INDEXED_GLOBAL_CODE)
    source_function = _function()
    program = build_indexed_alias_program_evidence_8616(
        source_project,
        (IndexedAliasFunctionSelection8616(0x1000, source_function),),
    )
    layouts = recover_global_object_layout_evidence_8616(program)
    ranges = recover_program_bounded_global_object_ranges_8616(program, layouts)
    binary_path = tmp_path / "fixture.exe"
    binary_path.write_bytes(_INDEXED_GLOBAL_CODE)
    cache_key = indexed_global_object_cache_key_8616(source_project, binary_path)
    assert cache_key is not None
    store_indexed_global_object_cache_8616(
        cache_key,
        PersistedIndexedGlobalObjectEvidence8616(layouts, ranges),
    )

    target_project = _project(_INDEXED_GLOBAL_CODE)
    monkeypatch.setattr(
        indexed_context,
        "collect_global_object_program_requirement_8616",
        lambda *_args: _required_callsites(),
    )
    monkeypatch.setattr(
        indexed_context,
        "attach_available_program_callsite_evidence_8616",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        indexed_context,
        "recover_direct_indexed_alias_catalog_8616",
        lambda *_args, **_kwargs: RecoveredIndexedAliasCatalog8616(
            source_project,
            (source_function,),
            _empty_ir_ssa_cache(),
        ),
    )
    monkeypatch.setattr(
        indexed_context,
        "publish_recovered_program_callsites_8616",
        lambda *_args, **_kwargs: False,
    )

    result = prepare_direct_indexed_alias_program_context_8616(
        source_project,
        target_project,
        _function(),
        timeout=1,
        window=0x100,
        binary_path=binary_path,
    )

    assert result.status is IndexedAliasProgramContextStatus8616.DISCOVERY_INCOMPLETE
    assert "_inertia_project_global_object_layout_evidence_8616" not in vars(
        target_project
    )
    assert "_inertia_project_bounded_global_object_ranges_8616" not in vars(
        target_project
    )
