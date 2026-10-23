"""Canonical public API surface for the 16-bit x86 platform support.

Layer: Frontend/runtime package surface.
Responsibility: owns the public imports, lazy exports, and startup bootstrap
for the X86_16 platform surface. The historical ``inertia.frontend.x86_16.public_api``
package remains a thin facade re-exporting this surface.
"""

from __future__ import annotations as _future_annotations

lazy import inertia.cli.corpus_recovery_artifact as corpus_recovery_artifact
lazy import inertia.cli.corpus_scan as corpus_scan
lazy import inertia.cli.targeted_recovery_artifact as targeted_recovery_artifact
lazy import inertia.frontend.x86_16.bootstrap as bootstrap
lazy import inertia.postprocess.decompiler_postprocess_inventory as decompiler_postprocess_inventory
lazy import inertia.postprocess.decompiler_postprocess_stage as decompiler_postprocess_stage
lazy import inertia.structuring.decompiler_structuring_stage as decompiler_structuring_stage
lazy from inertia.postprocess.decompiler_postprocess_inventory import (
    DecompilerPostprocessPassInventoryItem as DecompilerPostprocessPassInventoryItem,
)
lazy from inertia.postprocess.decompiler_postprocess_inventory import (
    DecompilerPostprocessPassInventoryViolation as DecompilerPostprocessPassInventoryViolation,
)
lazy from inertia.postprocess.decompiler_postprocess_inventory import (
    DecompilerPostprocessPassKind8616 as DecompilerPostprocessPassKind8616,
)
lazy from inertia.postprocess.decompiler_postprocess_inventory import (
    DecompilerPostprocessPassMigrationStatus8616 as DecompilerPostprocessPassMigrationStatus8616,
)
lazy from inertia.postprocess.decompiler_postprocess_inventory import (
    describe_x86_16_decompiler_postprocess_inventory_8616 as describe_x86_16_decompiler_postprocess_inventory_8616,
)
lazy from inertia.postprocess.decompiler_postprocess_inventory import (
    validate_x86_16_decompiler_postprocess_inventory_8616 as validate_x86_16_decompiler_postprocess_inventory_8616,
)
lazy from inertia.postprocess.decompiler_postprocess_stage import (
    DecompilerPostprocessPassSpec as DecompilerPostprocessPassSpec,
)
lazy from inertia.postprocess.decompiler_postprocess_stage import (
    apply_x86_16_decompiler_postprocess as apply_x86_16_decompiler_postprocess,
)
lazy from inertia.postprocess.decompiler_postprocess_stage import (
    describe_x86_16_decompiler_postprocess_stage as describe_x86_16_decompiler_postprocess_stage,
)
lazy from inertia.structuring.decompiler_structuring_stage import (
    DecompilerStructuringPassSpec as DecompilerStructuringPassSpec,
)
lazy from inertia.structuring.decompiler_structuring_stage import (
    apply_x86_16_decompiler_structuring as apply_x86_16_decompiler_structuring,
)
lazy from inertia.structuring.decompiler_structuring_stage import (
    describe_x86_16_decompiler_structuring_stage as describe_x86_16_decompiler_structuring_stage,
)

from . import (
    arch_86_16,
    calling_convention_compat,
    cod_extract,
    compat,
    decompiler_return_compat,
    lift_86_16,
    load_dos_mz,
    load_dos_ne,
    patch_dirty,
    simos_86_16,
    stack_compat,
    typehoon_compat,
)
from .addressing_helpers import (
    describe_x86_16_decode_width_matrix,
    describe_x86_16_mixed_width_extension_surface,
    describe_x86_16_mixed_width_instruction_surface,
)
from .calling_convention_compat import apply_x86_16_calling_convention_compatibility
from .cod_known_objects import describe_x86_16_cod_known_objects
from .compat import apply_x86_16_compatibility
from .decompiler_return_compat import apply_x86_16_decompiler_return_compatibility
from .instruction import describe_x86_16_instruction_metadata_surface
from .lifter_backend_selection import VEX_BACKEND
from .stack_compat import apply_x86_16_stack_compatibility
lazy from .bootstrap import apply_x86_16_bootstrap as apply_x86_16_bootstrap

try:
    import pyvex_compat

    pyvex_compat.apply_pyvex_runtime_compatibility()
except Exception:
    pass

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

import inertia.lowering.annotations as annotations
from inertia.alias import alias_model
from inertia.alias import domains as alias_domains
from inertia.alias import state as alias_state
from inertia.alias import transfer as alias_transfer
from inertia.alias.alias_model_impl import describe_x86_16_alias_recovery_api
from inertia.cli import (
    cod_source_rewrites,
    correctness_goals,
    milestone_report,
    readability_goals,
    readability_set,
    recompilable_subset,
    recovery_artifact_cache,
    recovery_artifact_manifest,
    recovery_artifact_writer,
    recovery_artifacts,
    recovery_manifest,
)
from inertia.cli.cod_source_rewrites import (
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
from inertia.cli.correctness_goals import describe_x86_16_correctness_goals
from inertia.cli.milestone_report import render_x86_16_tail_validation_console_summary
from inertia.cli.readability_goals import (
    describe_x86_16_readability_goals,
    rank_readability_goal_queue,
    summarize_readability_focus,
)
from inertia.cli.recovery_manifest import (
    describe_x86_16_object_recovery_focus,
    describe_x86_16_recovery_layers,
)
from inertia.ir import address_ir_8616 as address_ir
from inertia.lowering.analysis_helpers import (
    describe_x86_16_interrupt_api_surface,
    describe_x86_16_interrupt_core_surface,
    describe_x86_16_interrupt_lowering_boundary,
)
from inertia.lowering.annotations import apply_x86_16_metadata_annotations
from inertia.postprocess import (
    decompiler_postprocess,
    decompiler_postprocess_calls,
    decompiler_postprocess_globals,
    decompiler_postprocess_simplify,
    decompiler_postprocess_utils,
)
from inertia.postprocess import flags_cleanup as decompiler_postprocess_flags
from inertia.postprocess.decompiler_postprocess_simplify import describe_x86_16_projection_cleanup_rules
from inertia.semantics import callsite_summary, function_effect_summary, function_summary
from inertia.semantics.function_effect_summary import summarize_x86_16_function_effects
from inertia.structuring import (
    structuring_cross_entry,
    structuring_grouped_graph_builder,
    structuring_grouped_pass,
    structuring_grouped_units,
)
from inertia.validation import recovery_confidence, tail_validation, validation_manifest
from inertia.validation.recovery_confidence import describe_x86_16_recovery_confidence_axes
from inertia.validation.tail_validation import (
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
from inertia.validation.validation_manifest import describe_x86_16_validation_triage
from inertia.widening import register_widening as widening_alias
from inertia.widening import widening_model
from inertia.widening.stack_widening import describe_x86_16_widening_pipeline

try:
    _bootstrap = apply_x86_16_bootstrap
    if callable(_bootstrap):
        _bootstrap()
except Exception:
    pass

# Do not wrap Clinic._make_callsites with SIGALRM-based timeouts here.
# Raising out of Clinic causes angr resilience to drop decompilation results
# and return an empty codegen, which is worse than a slow but honest decompile.
