"""Own source-component scopes for persistent decompiler caches.

Layer: CLI/fallback/reporting.
Responsibility: identify implementation files that can change discovery-only
artifacts separately from files that can change final generated C.
Forbidden: weakening final decompilation cache invalidation or classifying
semantic output as discovery-only.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from .function_ir_ssa_source_scope import (
    function_ir_ssa_cache_source_files_8616,
)

_ROOT = Path(__file__).resolve().parents[1]

_DISCOVERY_INERTIA_NAMES_8616 = frozenset(
    {
        "cache.py",
        "cache_io.py",
        "cache_lock.py",
        "cache_runtime_contract.py",
        "cache_source_manifest.py",
        "cli.py",
        "cli_arg_parser.py",
        "catalog_policy.py",
        "external_unpacker_cache.py",
        "cli_core.py",
        "cli_function_discovery.py",
        "disassembly_helpers.py",
        "discovery_cache_contract.py",
        "discovery_evidence_project.py",
        "discovery_candidate_ranges.py",
        "project_loading.py",
        "rizin_discovery.py",
        "rizin_evidence.py",
        "runtime_support.py",
        "sidecar_cache.py",
        "sidecar_metadata.py",
        "binary_signature_metadata.py",
        "metadata_evidence.py",
        "sidecar_parsers.py",
        "sidecar_policy.py",
        "slice_recovery.py",
        "source_sidecar.py",
        "work_items.py",
        "x86_16_exact_slice.py",
    }
)

_DISCOVERY_X86_16_ROOT_EXCLUDED_PREFIXES_8616 = (
    "alias_",
    "decompiler_",
    "postprocess_",
    "recompilable_",
    "structuring_",
    "tail_validation",
    "type_",
    "validation_",
    "widening_",
)

_DISCOVERY_X86_16_DEPENDENCY_DIRS_8616 = (
    "ir",
    "semantics",
)

_RECOVERY_PIPELINE_DEPENDENCY_NAMES_8616 = (
    "contracts.py",
    "errors.py",
)

_INDEXED_ALIAS_PROGRAM_INERTIA_NAMES_8616 = (
    *_DISCOVERY_INERTIA_NAMES_8616,
    "indexed_alias_program_context.py",
    "direct_indexed_alias_local_cache.py",
    "indexed_alias_program_parallel.py",
    "indexed_alias_program_publication.py",
    "indexed_alias_program_recovery.py",
    "indexed_global_object_cache.py",
    "project_evidence_transport.py",
)

_INDEXED_ALIAS_PROGRAM_X86_16_DEPENDENCY_DIRS_8616 = (
    "ir",
)

_INDEXED_ALIAS_PROGRAM_DISCOVERY_PATHS_8616 = (
    "analysis_helpers.py",
    "annotations.py",
    "calling_convention_compat.py",
    "cod_analysis_image.py",
    "cod_extract.py",
    "codeview_nb00.py",
    "codeview_nb02_nb04.py",
    "compat.py",
    "exact_region_diagnostics.py",
    "exepack.py",
    "flair_extract.py",
    "frontend_function_boundary_index.py",
    "frontend_function_instructions.py",
    "frontend_indirect_jump_targets.py",
    "function_evidence_inventory.py",
    "helper_abi.py",
    "load_dos_mz.py",
    "load_dos_ne.py",
    "lst_extract.py",
    "mz_image.py",
    "ne_exe_parse.py",
    "packed_mz.py",
    "pklite.py",
    "segment_program_layout.py",
    "segment_program_layout_codec.py",
    "segment_program_layout_contract.py",
    "simos_86_16.py",
    "synthetic_call_stub_evidence.py",
    "turbo_debug_tdinfo.py",
)

_INDEXED_ALIAS_PROGRAM_ALIAS_NAMES_8616 = (
    "alias_model_impl.py",
    "domains.py",
    "indexed_address_access_classification.py",
    "indexed_address_access_contracts.py",
    "indexed_address_contracts.py",
    "indexed_address_copy_contracts.py",
    "indexed_address_copy_projection.py",
    "indexed_address_program.py",
    "indexed_address_projection.py",
    "indexed_address_range_contracts.py",
    "indexed_address_range_projection.py",
    "storage_fact_join.py",
)

_INDEXED_ALIAS_PROGRAM_WIDENING_NAMES_8616 = (
    "global_object_layout.py",
    "global_object_layout_codec.py",
    "indexed_global_object_layout.py",
    "indexed_global_object_program_range_codec.py",
    "indexed_global_object_program_ranges.py",
    "indexed_global_object_range_layouts.py",
    "indexed_global_object_range_solver.py",
    "indexed_global_object_ranges.py",
)

_PROGRAM_CALLSITE_INERTIA_NAMES_8616 = (
    *_DISCOVERY_INERTIA_NAMES_8616,
    "indexed_alias_program_context.py",
    "indexed_alias_program_parallel.py",
    "program_callsite_cache.py",
)

_PROGRAM_CALLSITE_LOWERING_NAMES_8616 = (
    "callee_callsite_codec.py",
    "callee_callsite_contracts.py",
    "callee_range_callsite_facts.py",
    "project_callee_callsite_collection.py",
)

_PROGRAM_CALLSITE_ALIAS_NAMES_8616 = (
    "callsite_stack_merge.py",
    "domains.py",
    "partial_register_address_break.py",
    "register_reaching_source.py",
)

_DIRECT_GLOBAL_OBJECT_INERTIA_NAMES_8616 = (
    "direct_global_object_cache.py",
    "direct_global_object_context.py",
    "indexed_alias_program_context.py",
    "indexed_alias_program_recovery.py",
    "project_evidence_transport.py",
)

_DIRECT_GLOBAL_OBJECT_LOWERING_NAMES_8616 = (
    "project_global_object_layout.py",
    "real_mode_linear.py",
    "segmented_global_loads.py",
)

_DIRECT_GLOBAL_OBJECT_STRUCTURING_NAMES_8616 = (
    "simple_loop_recovery.py",
)

_DIRECT_GLOBAL_OBJECT_WIDENING_NAMES_8616 = (
    "direct_global_object_layout_codec.py",
    "global_object_layout.py",
)


class RecoveryCacheSourceScope8616(StrEnum):
    """Implementation surface that owns one recovery-cache artifact."""

    FULL_DECOMPILATION = "full-decompilation"
    DIRECT_GLOBAL_OBJECT = "direct-global-object"
    FUNCTION_IR_SSA = "function-ir-ssa"
    FUNCTION_DISCOVERY = "function-discovery"
    INDEXED_ALIAS_PROGRAM = "indexed-alias-program"
    PROGRAM_CALLSITE = "program-callsite"


def _function_discovery_cache_source_files_8616() -> tuple[Path, ...]:
    """Return the conservative frontend/discovery implementation surface."""
    inertia_root = _ROOT / "inertia_decompiler"
    x86_root = _ROOT / "angr_platforms" / "angr_platforms" / "X86_16"
    discovered = {
        inertia_root / name
        for name in _DISCOVERY_INERTIA_NAMES_8616
    }
    discovered.update(
        path
        for path in x86_root.glob("*.py")
        if not path.name.startswith(
            _DISCOVERY_X86_16_ROOT_EXCLUDED_PREFIXES_8616
        )
    )
    discovered.update(
        path
        for directory_name in _DISCOVERY_X86_16_DEPENDENCY_DIRS_8616
        for path in (x86_root / directory_name).rglob("*.py")
    )
    discovered.update(
        x86_root / "pipeline" / name
        for name in _RECOVERY_PIPELINE_DEPENDENCY_NAMES_8616
    )
    discovered.update(
        {
            _ROOT / "omf_pat.py",
            _ROOT / "signature_catalog.py",
        }
    )
    return tuple(sorted(path for path in discovered if path.is_file()))


FUNCTION_DISCOVERY_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _function_discovery_cache_source_files_8616()
)


FUNCTION_IR_SSA_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    function_ir_ssa_cache_source_files_8616(_ROOT)
)


def _indexed_alias_program_cache_source_files_8616() -> tuple[Path, ...]:
    """Return discovery plus the Alias/Widening program implementation surface."""
    inertia_root = _ROOT / "inertia_decompiler"
    x86_root = _ROOT / "angr_platforms" / "angr_platforms" / "X86_16"
    discovered = {
        inertia_root / name
        for name in _INDEXED_ALIAS_PROGRAM_INERTIA_NAMES_8616
    }
    discovered.update(FUNCTION_IR_SSA_CACHE_SOURCE_FILES)
    discovered.update(
        x86_root / path
        for path in _INDEXED_ALIAS_PROGRAM_DISCOVERY_PATHS_8616
    )
    discovered.update(
        path
        for directory_name in _INDEXED_ALIAS_PROGRAM_X86_16_DEPENDENCY_DIRS_8616
        for path in (x86_root / directory_name).rglob("*.py")
    )
    discovered.update(
        x86_root / "alias" / name
        for name in _INDEXED_ALIAS_PROGRAM_ALIAS_NAMES_8616
    )
    discovered.update(
        x86_root / "widening" / name
        for name in _INDEXED_ALIAS_PROGRAM_WIDENING_NAMES_8616
    )
    discovered.update({_ROOT / "omf_pat.py", _ROOT / "signature_catalog.py"})
    return tuple(sorted(path for path in discovered if path.is_file()))


INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _indexed_alias_program_cache_source_files_8616()
)


def _program_callsite_cache_source_files_8616() -> tuple[Path, ...]:
    """Return exact discovery and callsite-summary artifact owners."""
    inertia_root = _ROOT / "inertia_decompiler"
    x86_root = _ROOT / "angr_platforms" / "angr_platforms" / "X86_16"
    discovered = {
        inertia_root / name
        for name in _PROGRAM_CALLSITE_INERTIA_NAMES_8616
    }
    discovered.update(FUNCTION_DISCOVERY_CACHE_SOURCE_FILES)
    discovered.update(
        x86_root / "alias" / name
        for name in _PROGRAM_CALLSITE_ALIAS_NAMES_8616
    )
    discovered.update(
        x86_root / "lowering" / name
        for name in _PROGRAM_CALLSITE_LOWERING_NAMES_8616
    )
    return tuple(sorted(path for path in discovered if path.is_file()))


PROGRAM_CALLSITE_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _program_callsite_cache_source_files_8616()
)


def _direct_global_object_cache_source_files_8616() -> tuple[Path, ...]:
    """Return discovery plus exact direct-global Lowering/Widening owners."""
    inertia_root = _ROOT / "inertia_decompiler"
    x86_root = _ROOT / "angr_platforms" / "angr_platforms" / "X86_16"
    discovered = set(FUNCTION_DISCOVERY_CACHE_SOURCE_FILES)
    discovered.update(
        inertia_root / name for name in _DIRECT_GLOBAL_OBJECT_INERTIA_NAMES_8616
    )
    discovered.update(
        x86_root / "lowering" / name
        for name in _DIRECT_GLOBAL_OBJECT_LOWERING_NAMES_8616
    )
    discovered.update(
        x86_root / "structuring" / name
        for name in _DIRECT_GLOBAL_OBJECT_STRUCTURING_NAMES_8616
    )
    discovered.update(
        x86_root / "widening" / name
        for name in _DIRECT_GLOBAL_OBJECT_WIDENING_NAMES_8616
    )
    return tuple(sorted(path for path in discovered if path.is_file()))


DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _direct_global_object_cache_source_files_8616()
)
