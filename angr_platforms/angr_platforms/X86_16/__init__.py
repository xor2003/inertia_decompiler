"""Public package surface for the 16-bit x86 platform support.

Layer: Frontend/runtime package surface.
Responsibility: owns package initialization and public imports for X86_16.
"""

from __future__ import annotations

from .lifter_backend_selection import VEX_BACKEND

try:
    import pyvex_compat

    pyvex_compat.apply_pyvex_runtime_compatibility()
except Exception:
    pass

from collections.abc import Callable
from importlib import import_module
from typing import TYPE_CHECKING

__all__ = [
    "COD_SOURCE_REWRITE_REGISTRY",
    "VEX_BACKEND",
    "CODSourceRewriteStatusKind",
    "DecompilerPostprocessPassInventoryItem",
    "DecompilerPostprocessPassInventoryViolation",
    "DecompilerPostprocessPassKind8616",
    "DecompilerPostprocessPassMigrationStatus8616",
    "DecompilerPostprocessPassSpec",
    "DecompilerStructuringPassSpec",
    "X86_16TailValidationSummary",
    "X86_16ValidationCacheDescriptor",
    "address_ir",
    "alias_domains",
    "alias_model",
    "alias_state",
    "alias_transfer",
    "annotations",
    "apply_cod_source_rewrites",
    "apply_x86_16_bootstrap",
    "apply_x86_16_calling_convention_compatibility",
    "apply_x86_16_compatibility",
    "apply_x86_16_decompiler_postprocess",
    "apply_x86_16_decompiler_return_compatibility",
    "apply_x86_16_metadata_annotations",
    "apply_x86_16_stack_compatibility",
    "arch_86_16",
    "bootstrap",
    "build_x86_16_tail_validation_aggregate",
    "build_x86_16_tail_validation_cached_result",
    "build_x86_16_tail_validation_surface",
    "build_x86_16_tail_validation_verdict",
    "build_x86_16_validation_cache_descriptor",
    "calling_convention_compat",
    "callsite_summary",
    "check_x86_16_tail_validation_surface_consistency",
    "cod_extract",
    "cod_source_rewrite_description",
    "cod_source_rewrite_names",
    "cod_source_rewrite_summary",
    "cod_source_rewrites",
    "collect_x86_16_tail_validation_summary",
    "compare_x86_16_tail_validation_summaries",
    "compat",
    "corpus_recovery_artifact",
    "corpus_scan",
    "correctness_goals",
    "decompiler_postprocess",
    "decompiler_postprocess_calls",
    "decompiler_postprocess_flags",
    "decompiler_postprocess_globals",
    "decompiler_postprocess_inventory",
    "decompiler_postprocess_simplify",
    "decompiler_postprocess_stage",
    "decompiler_postprocess_utils",
    "decompiler_return_compat",
    "decompiler_structuring_stage",
    "describe_x86_16_alias_recovery_api",
    "describe_x86_16_cod_known_objects",
    "describe_x86_16_correctness_goals",
    "describe_x86_16_decode_width_matrix",
    "describe_x86_16_decompiler_postprocess_inventory_8616",
    "describe_x86_16_decompiler_postprocess_stage",
    "describe_x86_16_decompiler_structuring_stage",
    "describe_x86_16_instruction_metadata_surface",
    "describe_x86_16_interrupt_api_surface",
    "describe_x86_16_interrupt_core_surface",
    "describe_x86_16_interrupt_lowering_boundary",
    "describe_x86_16_mixed_width_extension_surface",
    "describe_x86_16_mixed_width_instruction_surface",
    "describe_x86_16_object_recovery_focus",
    "describe_x86_16_projection_cleanup_rules",
    "describe_x86_16_readability_goals",
    "describe_x86_16_recovery_confidence_axes",
    "describe_x86_16_recovery_layers",
    "describe_x86_16_source_backed_rewrite_debt",
    "describe_x86_16_source_backed_rewrite_status",
    "describe_x86_16_tail_validation_scope",
    "describe_x86_16_validation_triage",
    "describe_x86_16_widening_pipeline",
    "extract_x86_16_tail_validation_snapshot",
    "fingerprint_x86_16_tail_validation_boundary",
    "format_x86_16_tail_validation_diff",
    "function_effect_summary",
    "function_summary",
    "get_cod_source_rewrite_spec",
    "lift_86_16",
    "load_dos_mz",
    "load_dos_ne",
    "milestone_report",
    "patch_dirty",
    "persist_x86_16_tail_validation_snapshot",
    "rank_readability_goal_queue",
    "readability_goals",
    "readability_set",
    "recompilable_subset",
    "recovery_artifact_cache",
    "recovery_artifact_manifest",
    "recovery_artifact_writer",
    "recovery_artifacts",
    "recovery_confidence",
    "recovery_manifest",
    "render_x86_16_tail_validation_console_summary",
    "resolve_x86_16_validation_cached_artifact",
    "rewrite_cod_source_stage",
    "simos_86_16",
    "stack_compat",
    "structuring_cross_entry",
    "structuring_grouped_graph_builder",
    "structuring_grouped_pass",
    "structuring_grouped_units",
    "summarize_readability_focus",
    "summarize_x86_16_function_effects",
    "summarize_x86_16_tail_validation_records",
    "tail_validation",
    "targeted_recovery_artifact",
    "typehoon_compat",
    "validate_x86_16_decompiler_postprocess_inventory_8616",
    "validation_manifest",
    "widening_alias",
    "widening_model",
    "x86_16_tail_validation_snapshot_passed",
]

from . import (
    address_ir,
    alias_domains,
    alias_model,
    alias_state,
    alias_transfer,
    arch_86_16,
    calling_convention_compat,
    callsite_summary,
    cod_extract,
    cod_source_rewrites,
    compat,
    corpus_recovery_artifact,
    corpus_scan,
    correctness_goals,
    decompiler_postprocess,
    decompiler_postprocess_calls,
    decompiler_postprocess_flags,
    decompiler_postprocess_globals,
    decompiler_postprocess_simplify,
    decompiler_postprocess_utils,
    decompiler_return_compat,
    function_effect_summary,
    function_summary,
    lift_86_16,
    load_dos_mz,
    load_dos_ne,
    milestone_report,
    patch_dirty,
    readability_goals,
    readability_set,
    recompilable_subset,
    recovery_artifact_cache,
    recovery_artifact_manifest,
    recovery_artifact_writer,
    recovery_artifacts,
    recovery_confidence,
    recovery_manifest,
    simos_86_16,
    stack_compat,
    structuring_cross_entry,
    structuring_grouped_graph_builder,
    structuring_grouped_pass,
    structuring_grouped_units,
    tail_validation,
    targeted_recovery_artifact,
    typehoon_compat,
    validation_manifest,
    widening_alias,
    widening_model,
)
from . import (
    annotations as _annotations,  # noqa: F401  # keep package module export
)
from .addressing_helpers import (
    describe_x86_16_decode_width_matrix,
    describe_x86_16_mixed_width_extension_surface,
    describe_x86_16_mixed_width_instruction_surface,
)
from .alias.alias_model_impl import describe_x86_16_alias_recovery_api
from .analysis_helpers import (
    describe_x86_16_interrupt_api_surface,
    describe_x86_16_interrupt_core_surface,
    describe_x86_16_interrupt_lowering_boundary,
)
from .annotations import apply_x86_16_metadata_annotations
from .calling_convention_compat import apply_x86_16_calling_convention_compatibility
from .cod_known_objects import describe_x86_16_cod_known_objects
from .cod_source_rewrites import (
    COD_SOURCE_REWRITE_REGISTRY,
    CODSourceRewriteStatusKind,
    apply_cod_source_rewrites,
    cod_source_rewrite_description,
    cod_source_rewrite_names,
    cod_source_rewrite_summary,
    describe_x86_16_source_backed_rewrite_debt,
    describe_x86_16_source_backed_rewrite_status,
    get_cod_source_rewrite_spec,
    rewrite_cod_source_stage,
)
from .compat import apply_x86_16_compatibility
from .correctness_goals import describe_x86_16_correctness_goals
from .decompiler_postprocess_simplify import describe_x86_16_projection_cleanup_rules
from .decompiler_return_compat import apply_x86_16_decompiler_return_compatibility
from .function_effect_summary import summarize_x86_16_function_effects
from .instruction import describe_x86_16_instruction_metadata_surface
from .milestone_report import render_x86_16_tail_validation_console_summary
from .readability_goals import (
    describe_x86_16_readability_goals,
    rank_readability_goal_queue,
    summarize_readability_focus,
)
from .recovery_confidence import describe_x86_16_recovery_confidence_axes
from .recovery_manifest import describe_x86_16_object_recovery_focus, describe_x86_16_recovery_layers
from .stack_compat import apply_x86_16_stack_compatibility
from .tail_validation import (
    X86_16TailValidationSummary,
    X86_16ValidationCacheDescriptor,
    build_x86_16_tail_validation_aggregate,
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_surface,
    build_x86_16_tail_validation_verdict,
    build_x86_16_validation_cache_descriptor,
    check_x86_16_tail_validation_surface_consistency,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    describe_x86_16_tail_validation_scope,
    extract_x86_16_tail_validation_snapshot,
    fingerprint_x86_16_tail_validation_boundary,
    format_x86_16_tail_validation_diff,
    persist_x86_16_tail_validation_snapshot,
    resolve_x86_16_validation_cached_artifact,
    summarize_x86_16_tail_validation_records,
    x86_16_tail_validation_snapshot_passed,
)
from .validation_manifest import describe_x86_16_validation_triage
from .widening.stack_widening import describe_x86_16_widening_pipeline

if TYPE_CHECKING:
    from . import (
        bootstrap,
        decompiler_postprocess_inventory,
        decompiler_postprocess_stage,
        decompiler_structuring_stage,
    )
    from .bootstrap import apply_x86_16_bootstrap
    from .decompiler_postprocess_inventory import (
        DecompilerPostprocessPassInventoryItem,
        DecompilerPostprocessPassInventoryViolation,
        DecompilerPostprocessPassKind8616,
        DecompilerPostprocessPassMigrationStatus8616,
        describe_x86_16_decompiler_postprocess_inventory_8616,
        validate_x86_16_decompiler_postprocess_inventory_8616,
    )
    from .decompiler_postprocess_stage import (
        DecompilerPostprocessPassSpec,
        apply_x86_16_decompiler_postprocess,
        describe_x86_16_decompiler_postprocess_stage,
    )
    from .decompiler_structuring_stage import (
        DecompilerStructuringPassSpec,
        describe_x86_16_decompiler_structuring_stage,
    )

_LazyExportLoader = Callable[[], object]


def _load_bootstrap_module() -> object:
    return import_module(".bootstrap", __name__)


def _load_apply_x86_16_bootstrap() -> object:
    from .bootstrap import apply_x86_16_bootstrap

    return apply_x86_16_bootstrap


def _load_decompiler_postprocess_inventory_module() -> object:
    return import_module(".decompiler_postprocess_inventory", __name__)


def _load_decompiler_postprocess_stage_module() -> object:
    return import_module(".decompiler_postprocess_stage", __name__)


def _load_decompiler_structuring_stage_module() -> object:
    return import_module(".decompiler_structuring_stage", __name__)


def _load_decompiler_postprocess_pass_inventory_item() -> object:
    from .decompiler_postprocess_inventory import DecompilerPostprocessPassInventoryItem

    return DecompilerPostprocessPassInventoryItem


def _load_decompiler_postprocess_pass_kind_8616() -> object:
    from .decompiler_postprocess_inventory import DecompilerPostprocessPassKind8616

    return DecompilerPostprocessPassKind8616


def _load_decompiler_postprocess_pass_migration_status_8616() -> object:
    from .decompiler_postprocess_inventory import DecompilerPostprocessPassMigrationStatus8616

    return DecompilerPostprocessPassMigrationStatus8616


def _load_decompiler_postprocess_pass_inventory_violation() -> object:
    from .decompiler_postprocess_inventory import DecompilerPostprocessPassInventoryViolation

    return DecompilerPostprocessPassInventoryViolation


def _load_decompiler_postprocess_pass_spec() -> object:
    from .decompiler_postprocess_stage import DecompilerPostprocessPassSpec

    return DecompilerPostprocessPassSpec


def _load_apply_x86_16_decompiler_postprocess() -> object:
    from .decompiler_postprocess_stage import apply_x86_16_decompiler_postprocess

    return apply_x86_16_decompiler_postprocess


def _load_describe_x86_16_decompiler_postprocess_inventory_8616() -> object:
    from .decompiler_postprocess_inventory import describe_x86_16_decompiler_postprocess_inventory_8616

    return describe_x86_16_decompiler_postprocess_inventory_8616


def _load_validate_x86_16_decompiler_postprocess_inventory_8616() -> object:
    from .decompiler_postprocess_inventory import validate_x86_16_decompiler_postprocess_inventory_8616

    return validate_x86_16_decompiler_postprocess_inventory_8616


def _load_describe_x86_16_decompiler_postprocess_stage() -> object:
    from .decompiler_postprocess_stage import describe_x86_16_decompiler_postprocess_stage

    return describe_x86_16_decompiler_postprocess_stage


def _load_decompiler_structuring_pass_spec() -> object:
    from .decompiler_structuring_stage import DecompilerStructuringPassSpec

    return DecompilerStructuringPassSpec


def _load_apply_x86_16_decompiler_structuring() -> object:
    from .decompiler_structuring_stage import apply_x86_16_decompiler_structuring

    return apply_x86_16_decompiler_structuring


def _load_describe_x86_16_decompiler_structuring_stage() -> object:
    from .decompiler_structuring_stage import describe_x86_16_decompiler_structuring_stage

    return describe_x86_16_decompiler_structuring_stage


_LAZY_EXPORTS: dict[str, _LazyExportLoader] = {
    "bootstrap": _load_bootstrap_module,
    "apply_x86_16_bootstrap": _load_apply_x86_16_bootstrap,
    "decompiler_postprocess_inventory": _load_decompiler_postprocess_inventory_module,
    "decompiler_postprocess_stage": _load_decompiler_postprocess_stage_module,
    "DecompilerPostprocessPassInventoryItem": _load_decompiler_postprocess_pass_inventory_item,
    "DecompilerPostprocessPassKind8616": _load_decompiler_postprocess_pass_kind_8616,
    "DecompilerPostprocessPassMigrationStatus8616": _load_decompiler_postprocess_pass_migration_status_8616,
    "DecompilerPostprocessPassInventoryViolation": _load_decompiler_postprocess_pass_inventory_violation,
    "DecompilerPostprocessPassSpec": _load_decompiler_postprocess_pass_spec,
    "apply_x86_16_decompiler_postprocess": _load_apply_x86_16_decompiler_postprocess,
    "describe_x86_16_decompiler_postprocess_inventory_8616": (
        _load_describe_x86_16_decompiler_postprocess_inventory_8616
    ),
    "validate_x86_16_decompiler_postprocess_inventory_8616": (
        _load_validate_x86_16_decompiler_postprocess_inventory_8616
    ),
    "describe_x86_16_decompiler_postprocess_stage": _load_describe_x86_16_decompiler_postprocess_stage,
    "decompiler_structuring_stage": _load_decompiler_structuring_stage_module,
    "DecompilerStructuringPassSpec": _load_decompiler_structuring_pass_spec,
    "apply_x86_16_decompiler_structuring": _load_apply_x86_16_decompiler_structuring,
    "describe_x86_16_decompiler_structuring_stage": _load_describe_x86_16_decompiler_structuring_stage,
}


def __getattr__(name: str) -> object:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    value = target()
    globals()[name] = value
    return value


try:
    _bootstrap = __getattr__("apply_x86_16_bootstrap")
    if callable(_bootstrap):
        _bootstrap()
except Exception:
    pass

# Do not wrap Clinic._make_callsites with SIGALRM-based timeouts here.
# Raising out of Clinic causes angr resilience to drop decompilation results
# and return an empty codegen, which is worse than a slow but honest decompile.
