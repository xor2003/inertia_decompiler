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
    frontend_cache_source_files_8616,
    function_ir_ssa_cache_source_files_8616,
)

_ROOT = Path(__file__).resolve().parents[2]

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

_DISCOVERY_X86_16_ROOT_INERTIA_NAMES_8616 = (
    "acceptance_scorecard.py",
    "borland_mangling.py",
    "cod_comment_emitter.py",
    "cod_source_rewrites.py",
    "codeview_nb00.py",
    "codeview_nb02_nb04.py",
    "corpus_recovery_artifact.py",
    "corpus_scan.py",
    "correctness_goals.py",
    "exact_region_diagnostics.py",
    "fast_tracer.py",
    "flair_extract.py",
    "layer_module_status.py",
    "lst_extract.py",
    "milestone_report.py",
    "readability_goals.py",
    "readability_set.py",
    "recovery_artifact_cache.py",
    "recovery_artifact_manifest.py",
    "recovery_artifact_writer.py",
    "recovery_artifacts.py",
    "recovery_instruction_coverage.py",
    "recovery_manifest.py",
    "runtime_trace_refinement.py",
    "structured_function_helpers.py",
    "targeted_recovery_artifact.py",
    "turbo_debug_tdinfo.py",
)

_DISCOVERY_X86_16_ROOT_LOWERING_NAMES_8616 = (
    "analysis_helpers.py",
    "annotations.py",
    "c_ast_utils.py",
    "calling_convention_seed_cache.py",
    "callsite_pointer_values.py",
    "codegen_metadata.py",
    "segmented_memory_reasoning.py",
    "string_instruction_lowering.py",
    "structured_tags.py",
)

_DISCOVERY_X86_16_ROOT_STRUCTURING_NAMES_8616 = (
    "condition_call_effects.py",
    "condition_trace.py",
    "confidence_and_assumptions.py",
    "confidence_evidence.py",
    "ir_confidence_markers.py",
    "ir_readiness.py",
    "ir_recovery_summary.py",
    "string_codegen_override.py",
)

_DISCOVERY_X86_16_ROOT_POSTPROCESS_NAMES_8616 = (
    "callsite_stack_metadata.py",
    "codegen_parentheses.py",
)

_DISCOVERY_X86_16_ROOT_VALIDATION_NAMES_8616 = (
    "recovery_confidence.py",
)

_RECOVERY_PIPELINE_DEPENDENCY_NAMES_8616 = (
    "contracts.py",
    "errors.py",
)

_INDEXED_ALIAS_PROGRAM_INERTIA_NAMES_8616 = (
    *_DISCOVERY_INERTIA_NAMES_8616,
    "codeview_nb00.py",
    "codeview_nb02_nb04.py",
    "exact_region_diagnostics.py",
    "flair_extract.py",
    "lst_extract.py",
    "turbo_debug_tdinfo.py",
    "indexed_alias_program_context.py",
    "direct_indexed_alias_local_cache.py",
    "indexed_alias_program_parallel.py",
    "indexed_alias_program_publication.py",
    "indexed_alias_program_recovery.py",
    "indexed_global_object_cache.py",
    "project_evidence_transport.py",
)

_INDEXED_ALIAS_PROGRAM_DISCOVERY_PATHS_8616 = (
    "calling_convention_compat.py",
    "cod_analysis_image.py",
    "cod_extract.py",
    "compat.py",
    "exepack.py",
    "frontend_function_boundary_index.py",
    "frontend_function_instructions.py",
    "frontend_indirect_jump_targets.py",
    "load_dos_mz.py",
    "load_dos_ne.py",
    "mz_image.py",
    "ne_exe_parse.py",
    "packed_mz.py",
    "pklite.py",
    "simos_86_16.py",
    "synthetic_call_stub_evidence.py",
)

_INDEXED_ALIAS_PROGRAM_SEMANTICS_NAMES_8616 = (
    "function_evidence_inventory.py",
    "helper_abi.py",
    "segment_program_layout.py",
    "segment_program_layout_codec.py",
    "segment_program_layout_contract.py",
)

_INDEXED_ALIAS_PROGRAM_LOWERING_NAMES_8616 = (
    "analysis_helpers.py",
    "annotations.py",
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
    from inertia import ir, lowering, pipeline, postprocess, semantics, structuring, validation
    from inertia.frontend import x86_16

    inertia_root = _ROOT / "inertia" / "cli"
    x86_root = Path(x86_16.__file__).parent
    sources = {
        *(inertia_root / name for name in _DISCOVERY_INERTIA_NAMES_8616),
        *(inertia_root / name for name in _DISCOVERY_X86_16_ROOT_INERTIA_NAMES_8616),
        *(
        path
        for path in x86_root.glob("*.py")
        if not path.name.startswith(
            _DISCOVERY_X86_16_ROOT_EXCLUDED_PREFIXES_8616
        )
        ),
        *Path(ir.__file__).parent.glob("*.py"),
        *Path(semantics.__file__).parent.rglob("*.py"),
        *(
        Path(pipeline.__file__).parent / name
        for name in _RECOVERY_PIPELINE_DEPENDENCY_NAMES_8616
        ),
        *(
        Path(lowering.__file__).parent / name
        for name in _DISCOVERY_X86_16_ROOT_LOWERING_NAMES_8616
        ),
        *(
        Path(structuring.__file__).parent / name
        for name in _DISCOVERY_X86_16_ROOT_STRUCTURING_NAMES_8616
        ),
        *(
        Path(postprocess.__file__).parent / name
        for name in _DISCOVERY_X86_16_ROOT_POSTPROCESS_NAMES_8616
        ),
        *(
        Path(validation.__file__).parent / name
        for name in _DISCOVERY_X86_16_ROOT_VALIDATION_NAMES_8616
        ),
        _ROOT / "tools/signatures/omf_pat.py",
        _ROOT / "tools/signatures/signature_catalog.py",
        *frontend_cache_source_files_8616(_ROOT),
    }
    return tuple(sorted(path for path in sources if path.is_file()))


FUNCTION_DISCOVERY_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _function_discovery_cache_source_files_8616()
)


FUNCTION_IR_SSA_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    function_ir_ssa_cache_source_files_8616(_ROOT)
)


def _indexed_alias_program_cache_source_files_8616() -> tuple[Path, ...]:
    """Return discovery plus the Alias/Widening program implementation surface."""
    from inertia import alias, ir, lowering, semantics, widening
    from inertia.frontend import x86_16

    inertia_root = _ROOT / "inertia" / "cli"
    x86_root = Path(x86_16.__file__).parent
    sources = {
        *(inertia_root / name for name in _INDEXED_ALIAS_PROGRAM_INERTIA_NAMES_8616),
        *FUNCTION_IR_SSA_CACHE_SOURCE_FILES,
        *(
        x86_root / path
        for path in _INDEXED_ALIAS_PROGRAM_DISCOVERY_PATHS_8616
        ),
        *(
        Path(semantics.__file__).parent / name
        for name in _INDEXED_ALIAS_PROGRAM_SEMANTICS_NAMES_8616
        ),
        *(
        Path(lowering.__file__).parent / name
        for name in _INDEXED_ALIAS_PROGRAM_LOWERING_NAMES_8616
        ),
        *Path(ir.__file__).parent.glob("*.py"),
        *(
        Path(alias.__file__).parent / name
        for name in _INDEXED_ALIAS_PROGRAM_ALIAS_NAMES_8616
        ),
        *(
        Path(widening.__file__).parent / name
        for name in _INDEXED_ALIAS_PROGRAM_WIDENING_NAMES_8616
        ),
        _ROOT / "tools/signatures/omf_pat.py", _ROOT / "tools/signatures/signature_catalog.py",
    }
    return tuple(sorted(path for path in sources if path.is_file()))


INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _indexed_alias_program_cache_source_files_8616()
)


def _program_callsite_cache_source_files_8616() -> tuple[Path, ...]:
    """Return exact discovery and callsite-summary artifact owners."""
    from inertia import alias, lowering

    inertia_root = _ROOT / "inertia" / "cli"
    sources = {
        *(inertia_root / name for name in _PROGRAM_CALLSITE_INERTIA_NAMES_8616),
        *FUNCTION_DISCOVERY_CACHE_SOURCE_FILES,
        *(
        Path(alias.__file__).parent / name
        for name in _PROGRAM_CALLSITE_ALIAS_NAMES_8616
        ),
        *(
        Path(lowering.__file__).parent / name
        for name in _PROGRAM_CALLSITE_LOWERING_NAMES_8616
        ),
    }
    return tuple(sorted(path for path in sources if path.is_file()))


PROGRAM_CALLSITE_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _program_callsite_cache_source_files_8616()
)


def _direct_global_object_cache_source_files_8616() -> tuple[Path, ...]:
    """Return discovery plus exact direct-global Lowering/Widening owners."""
    from inertia import lowering, structuring, widening

    inertia_root = _ROOT / "inertia" / "cli"
    sources = {
        *FUNCTION_DISCOVERY_CACHE_SOURCE_FILES,
        *(
        inertia_root / name for name in _DIRECT_GLOBAL_OBJECT_INERTIA_NAMES_8616
        ),
        *(
        Path(lowering.__file__).parent / name
        for name in _DIRECT_GLOBAL_OBJECT_LOWERING_NAMES_8616
        ),
        *(
        Path(structuring.__file__).parent / name
        for name in _DIRECT_GLOBAL_OBJECT_STRUCTURING_NAMES_8616
        ),
        *(
        Path(widening.__file__).parent / name
        for name in _DIRECT_GLOBAL_OBJECT_WIDENING_NAMES_8616
        ),
    }
    return tuple(sorted(path for path in sources if path.is_file()))


DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _direct_global_object_cache_source_files_8616()
)
