"""Layer: CLI/fallback/reporting.

Responsibility: expose the command entrypoint and compatibility imports.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import sys
from importlib import import_module
from types import ModuleType
from typing import cast

# Native PEP 810 lazy exports; every name binds its canonical module owner.
lazy from angr.analyses.decompiler.structured_codegen import (
    c as structured_c,
)
lazy from angr.sim_type import (
    SimTypeChar as SimTypeChar,
)
lazy from angr.sim_type import (
    SimTypePointer as SimTypePointer,
)
lazy from angr.sim_type import (
    SimTypeShort as SimTypeShort,
)
lazy from angr.sim_variable import (
    SimMemoryVariable as SimMemoryVariable,
)
lazy from angr.sim_variable import (
    SimRegisterVariable as SimRegisterVariable,
)
lazy from angr.sim_variable import (
    SimStackVariable as SimStackVariable,
)

from .architecture_runtime_guard import (
    DecompilerArchitectureGuardError,
    assert_decompiler_architecture_clean,
)

try:
    assert_decompiler_architecture_clean()
except DecompilerArchitectureGuardError as ex:
    print(str(ex), file=sys.stderr)
    raise SystemExit(3) from ex

lazy import inertia.widening.register_widening as _register_widening_8616
lazy from inertia.cli.cache import (
    _CACHE_NON_SEMANTIC_ENVIRONMENT_NAMES as _CACHE_NON_SEMANTIC_ENVIRONMENT_NAMES,
)
lazy from inertia.cli.cache import (
    _CACHE_NON_SEMANTIC_ENVIRONMENT_PREFIXES as _CACHE_NON_SEMANTIC_ENVIRONMENT_PREFIXES,
)
lazy from inertia.cli.cache import (
    _PRODUCTION_DECOMPILER_SOURCE_FILES as _PRODUCTION_DECOMPILER_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    _ROOT as _ROOT,
)
lazy from inertia.cli.cache import (
    BASE_DECOMPILATION_CACHE_SOURCE_FILES as BASE_DECOMPILATION_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    BASE_RECOVERY_CACHE_SOURCE_FILES as BASE_RECOVERY_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    DECOMPILATION_CACHE_DIR as DECOMPILATION_CACHE_DIR,
)
lazy from inertia.cli.cache import (
    DECOMPILATION_CACHE_SCHEMA as DECOMPILATION_CACHE_SCHEMA,
)
lazy from inertia.cli.cache import (
    DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES as DIRECT_GLOBAL_OBJECT_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    FUNCTION_DISCOVERY_CACHE_SOURCE_FILES as FUNCTION_DISCOVERY_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    FUNCTION_IR_SSA_CACHE_SOURCE_FILES as FUNCTION_IR_SSA_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES as INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    PROGRAM_CALLSITE_CACHE_SOURCE_FILES as PROGRAM_CALLSITE_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    RECOVERY_CACHE_SOURCE_FILES as RECOVERY_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    SIDECAR_METADATA_CACHE_SOURCE_FILES as SIDECAR_METADATA_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cache import (
    _cache_content_fingerprint as _cache_content_fingerprint,
)
lazy from inertia.cli.cache import (
    _cache_file_fingerprint as _cache_file_fingerprint,
)
lazy from inertia.cli.cache import (
    _cache_json_path as _cache_json_path,
)
lazy from inertia.cli.cache import (
    _cache_runtime_environment as _cache_runtime_environment,
)
lazy from inertia.cli.cache import (
    _cache_sha256_bytes as _cache_sha256_bytes,
)
lazy from inertia.cli.cache import (
    _cache_sha256_file as _cache_sha256_file,
)
lazy from inertia.cli.cache import (
    _cache_sidecar_fingerprints as _cache_sidecar_fingerprints,
)
lazy from inertia.cli.cache import (
    _case_insensitive_sibling_path as _case_insensitive_sibling_path,
)
lazy from inertia.cli.cache import (
    _function_decompilation_cache_key as _function_decompilation_cache_key,
)
lazy from inertia.cli.cache import (
    _production_decompiler_source_files as _production_decompiler_source_files,
)
lazy from inertia.cli.cache import (
    _sidecar_metadata_cache_key as _sidecar_metadata_cache_key,
)
lazy from inertia.cli.cache import (
    cache_content_fingerprint_8616 as cache_content_fingerprint_8616,
)
lazy from inertia.cli.cache import (
    cache_file_digest_8616 as cache_file_digest_8616,
)
lazy from inertia.cli.cache import (
    cache_file_fingerprint_8616 as cache_file_fingerprint_8616,
)
lazy from inertia.cli.cache import (
    cache_path_lock as cache_path_lock,
)
lazy from inertia.cli.cache import (
    cache_runtime_contract_8616 as cache_runtime_contract_8616,
)
lazy from inertia.cli.cache import (
    contextmanager as contextmanager,
)
lazy from inertia.cli.cache import (
    deark_cache_identity as deark_cache_identity,
)
lazy from inertia.cli.cache import (
    inertia as inertia,
)
lazy from inertia.cli.cache import (
    is_non_semantic_cache_environment_name as is_non_semantic_cache_environment_name,
)
lazy from inertia.cli.cache import (
    load_cache_json_path as load_cache_json_path,
)
lazy from inertia.cli.cache import (
    lru_cache as lru_cache,
)
lazy from inertia.cli.cache import (
    store_cache_json_path as store_cache_json_path,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _AST_REWRITE_LOGGER as _AST_REWRITE_LOGGER,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _CHILD_LIST_ATTRS as _CHILD_LIST_ATTRS,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _CHILD_SCALAR_ATTRS as _CHILD_SCALAR_ATTRS,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _CLI_AST_LEAF_TYPES_8616 as _CLI_AST_LEAF_TYPES_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _CLI_AST_NON_CHILD_ATTRS_8616 as _CLI_AST_NON_CHILD_ATTRS_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _COD_GLOBAL_ARM_CONTINUE_8616 as _COD_GLOBAL_ARM_CONTINUE_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _CONST_FOLD_OPS_8616 as _CONST_FOLD_OPS_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _SEGMENT_REG_DESIRED_NAMES_8616 as _SEGMENT_REG_DESIRED_NAMES_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _SIMPLIFY_NO_MATCH_8616 as _SIMPLIFY_NO_MATCH_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    AliasState as AliasState,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    AngrProjectValue as AngrProjectValue,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    CSemanticCast8616 as CSemanticCast8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    DomainKey as DomainKey,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    Hashable as Hashable,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    StructuredAstValue as StructuredAstValue,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    StructuredCodegenValue as StructuredCodegenValue,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _access_trait_field_name as _access_trait_field_name,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _access_trait_member_candidates as _access_trait_member_candidates,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _access_trait_profile_for_key as _access_trait_profile_for_key,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _access_trait_variable_key as _access_trait_variable_key,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _AccessTraitRewriteDecision as _AccessTraitRewriteDecision,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _addr_exprs_are_byte_pair as _addr_exprs_are_byte_pair,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _addr_exprs_are_same as _addr_exprs_are_same,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _adjacent_pair_proof_ok_8616 as _adjacent_pair_proof_ok_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _adjacent_pair_reg_vars_8616 as _adjacent_pair_reg_vars_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _adjacent_pair_scaled_high_8616 as _adjacent_pair_scaled_high_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _algebraic_identity_transform_8616 as _algebraic_identity_transform_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _algebraic_pointer_shr_arm_8616 as _algebraic_pointer_shr_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _analyze_widening_expr as _analyze_widening_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _apply_generic_unified_name_for_param_slot as _apply_generic_unified_name_for_param_slot,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _apply_global_type_and_size_8616 as _apply_global_type_and_size_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _arch_register_var_name_8616 as _arch_register_var_name_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _attach_cod_callee_names as _attach_cod_callee_names,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _attach_register_names_in_use_8616 as _attach_register_names_in_use_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _attach_register_names_unified_8616 as _attach_register_names_unified_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _attach_segment_names_in_use_8616 as _attach_segment_names_in_use_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _attach_segment_names_unified_8616 as _attach_segment_names_unified_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _BinarySimplifyCtx8616 as _BinarySimplifyCtx8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _boolean_not_operand_arm_8616 as _boolean_not_operand_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _build_access_trait_evidence_profiles as _build_access_trait_evidence_profiles,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _build_cod_normalized_bp_alias_map as _build_cod_normalized_bp_alias_map,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _build_cod_positive_bp_alias_map as _build_cod_positive_bp_alias_map,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _c_constant_value as _c_constant_value,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _canonicalize_stack_cvar_expr as _canonicalize_stack_cvar_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cite_is_negation as _cite_is_negation,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _classify_segmented_addr_expr as _classify_segmented_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _classify_segmented_dereference as _classify_segmented_dereference,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_access_object_hints as _cli_access_object_hints,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_access_profiles as _cli_access_profiles,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_access_rewrite_artifact as _cli_access_rewrite_artifact,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_access_trait_rewrite as _cli_access_trait_rewrite,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_access_traits as _cli_access_traits,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_cod_global_statements as _cli_cod_global_statements,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_cod_globals as _cli_cod_globals,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_dead_local_prune as _cli_dead_local_prune,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_far_pointer_stack as _cli_far_pointer_stack,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_helper_modeling as _cli_helper_modeling,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_linear_aliases as _cli_linear_aliases,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_linear_recurrence as _cli_linear_recurrence,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_linear_recurrence_rules as _cli_linear_recurrence_rules,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_local_prune as _cli_local_prune,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_local_rewrites as _cli_local_rewrites,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_memory_prune as _cli_memory_prune,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_mkfp_simplify as _cli_mkfp_simplify,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_segmented as _cli_segmented,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_segmented_compare as _cli_segmented_compare,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_segmented_elision as _cli_segmented_elision,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_segmented_load_coalesce as _cli_segmented_load_coalesce,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_segmented_lowering as _cli_segmented_lowering,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_segmented_store_coalesce as _cli_segmented_store_coalesce,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_stack_byte_offsets as _cli_stack_byte_offsets,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_stack_coalesce as _cli_stack_coalesce,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_stack_cvars as _cli_stack_cvars,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_stack_locals as _cli_stack_locals,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_word_global_helpers as _cli_word_global_helpers,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cli_word_loads as _cli_word_loads,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _clone_c_value_container_8616 as _clone_c_value_container_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _clone_c_value_slot_names_8616 as _clone_c_value_slot_names_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _clone_c_value_slots_8616 as _clone_c_value_slots_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _clone_structured_c_value as _clone_structured_c_value,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _coalesce_direct_ss_local_word_statements as _coalesce_direct_ss_local_word_statements,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _coalesce_segmented_word_store_statements as _coalesce_segmented_word_store_statements,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cod_global_deref_arm_8616 as _cod_global_deref_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cod_global_seg_deref_arm_8616 as _cod_global_seg_deref_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cod_global_var_arm_8616 as _cod_global_var_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cod_named_global_cvar_8616 as _cod_named_global_cvar_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _cod_stack_alias_for_disp as _cod_stack_alias_for_disp,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _CODSourceRewriteSpec as _CODSourceRewriteSpec,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _collect_cod_name_ownership as _collect_cod_name_ownership,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _collect_protected_deref_expr_ids as _collect_protected_deref_expr_ids,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _collect_staging_wrapper_summary as _collect_staging_wrapper_summary,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _compat_callback as _compat_callback,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _CopyAliasState as _CopyAliasState,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _derived_stack_high_byte_follows_cvar as _derived_stack_high_byte_follows_cvar,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _derived_stack_high_byte_follows_slot as _derived_stack_high_byte_follows_slot,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _desired_global_type_spec_8616 as _desired_global_type_spec_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _dos_helper_declarations as _dos_helper_declarations,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _dup_word_increment_base_8616 as _dup_word_increment_base_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _emit_c_node_children_8616 as _emit_c_node_children_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _extract_child_zero_flag_source_8616 as _extract_child_zero_flag_source_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _extract_dereference_addr_expr as _extract_dereference_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _extract_linear_widening_delta_8616 as _extract_linear_widening_delta_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _extract_mul_zero_flag_source_8616 as _extract_mul_zero_flag_source_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _extract_same_zero_compare_expr as _extract_same_zero_compare_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _extract_zero_flag_source_expr as _extract_zero_flag_source_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _flatten_c_add_terms as _flatten_c_add_terms,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _fold_linear_delta_parts_8616 as _fold_linear_delta_parts_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _get_or_seed_inertia_alias_state as _get_or_seed_inertia_alias_state,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _global_load_addr as _global_load_addr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _global_memory_addr as _global_memory_addr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _high_byte_const_and_arm_8616 as _high_byte_const_and_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _high_byte_const_shr_arm_8616 as _high_byte_const_shr_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _high_byte_preserving_scale_arm_8616 as _high_byte_preserving_scale_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _high_byte_store_addr as _high_byte_store_addr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _int21_call_replacements as _int21_call_replacements,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _interrupt_call_replacement_map as _interrupt_call_replacement_map,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _interrupt_helper_declarations as _interrupt_helper_declarations,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _invert_comparison_op as _invert_comparison_op,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _invert_interval_guard_if_safe as _invert_interval_guard_if_safe,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _is_c_constant_int as _is_c_constant_int,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _is_generic_var_name_8616 as _is_generic_var_name_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _is_linear_register_temp_var as _is_linear_register_temp_var,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _is_stable_byte_register_8616 as _is_stable_byte_register_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _is_staging_local_name as _is_staging_local_name,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _iter_c_node_children_8616 as _iter_c_node_children_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _known_helper_declarations as _known_helper_declarations,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _linear_delta_or_base_8616 as _linear_delta_or_base_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_collect_temp_aliases_8616 as _lst_collect_temp_aliases_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_data_label as _lst_data_label,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_deref_arm_8616 as _lst_deref_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_deref_segment_terms_8616 as _lst_deref_segment_terms_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_is_linear_temp_8616 as _lst_is_linear_temp_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_make_data_var_8616 as _lst_make_data_var_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_resolved_constant_value_8616 as _lst_resolved_constant_value_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_temp_alias_value_8616 as _lst_temp_alias_value_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _lst_var_arm_8616 as _lst_var_arm_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _make_inverted_comparison as _make_inverted_comparison,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _make_unique_identifier as _make_unique_identifier,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _make_word_dereference_from_addr_expr as _make_word_dereference_from_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_byte_load_addr_expr as _match_byte_load_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_byte_store_addr_expr as _match_byte_store_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_duplicate_word_base_expr as _match_duplicate_word_base_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_duplicate_word_increment_shift_expr as _match_duplicate_word_increment_shift_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_high_byte_preserving_widening_8616 as _match_high_byte_preserving_widening_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_high_byte_projection_base as _match_high_byte_projection_base,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_high_byte_projection_constant as _match_high_byte_projection_constant,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_high_byte_projection_expr as _match_high_byte_projection_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_real_mode_linear_expr as _match_real_mode_linear_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_scaled_high_byte as _match_scaled_high_byte,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_segment_register_based_dereference as _match_segment_register_based_dereference,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_segmented_dereference as _match_segmented_dereference,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_shift_right_8_expr as _match_shift_right_8_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_shifted_high_byte_addr_expr as _match_shifted_high_byte_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_ss_local_plus_const as _match_ss_local_plus_const,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_ss_stack_reference as _match_ss_stack_reference,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_stack_cvar_and_offset as _match_stack_cvar_and_offset,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_word_dereference_addr_expr as _match_word_dereference_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_word_pair_low_addr_expr as _match_word_pair_low_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _match_word_rhs_from_byte_pair as _match_word_rhs_from_byte_pair,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _materialize_stack_cvar_at_offset as _materialize_stack_cvar_at_offset,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _normalize_16bit_signed_offset as _normalize_16bit_signed_offset,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _normalize_bp_disp as _normalize_bp_disp,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _normalize_byte_register_node_types_8616 as _normalize_byte_register_node_types_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _normalize_in_use_byte_register_types_8616 as _normalize_in_use_byte_register_types_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _normalize_unified_byte_register_types_8616 as _normalize_unified_byte_register_types_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _ordered_stack_identity_nodes as _ordered_stack_identity_nodes,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _ordered_stack_identity_variables as _ordered_stack_identity_variables,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _project_rewrite_cache as _project_rewrite_cache,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _promote_direct_stack_cvariable as _promote_direct_stack_cvariable,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _prune_unused_linear_register_declarations as _prune_unused_linear_register_declarations,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _push_iterable_children_8616 as _push_iterable_children_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _remove_unused_staging_vars_from_maps as _remove_unused_staging_vars_from_maps,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _rename_in_use_global_symbols_8616 as _rename_in_use_global_symbols_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _rename_register_variable_8616 as _rename_register_variable_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _rename_unified_global_locals_8616 as _rename_unified_global_locals_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _replace_c_children as _replace_c_children,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _replace_condition_pairs as _replace_condition_pairs,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _replace_list_child_attrs as _replace_list_child_attrs,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _replace_one_list_attr_8616 as _replace_one_list_attr_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _replace_scalar_child_attrs as _replace_scalar_child_attrs,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _resolve_alias_collision_name as _resolve_alias_collision_name,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _resolve_dirty_virtual_expr_8616 as _resolve_dirty_virtual_expr_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _resolve_stack_cvar_at_offset as _resolve_stack_cvar_at_offset,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _resolve_stack_cvar_from_addr_expr as _resolve_stack_cvar_from_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _restore_not_shift_zero_flag_source as _restore_not_shift_zero_flag_source,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _retune_cextern_global_types_8616 as _retune_cextern_global_types_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _retune_in_use_global_types_8616 as _retune_in_use_global_types_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _retune_unified_global_types_8616 as _retune_unified_global_types_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _rewrite_cod_proc_from_source as _rewrite_cod_proc_from_source,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _rewrite_staging_statements as _rewrite_staging_statements,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_c_dirty_expr_8616 as _same_c_dirty_expr_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_c_expr_payload_8616 as _same_c_expr_payload_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_c_expression as _same_c_expression,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_c_function_call_8616 as _same_c_function_call_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_c_storage as _same_c_storage,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_c_variable_8616 as _same_c_variable_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_expression_list as _same_expression_list,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_stack_slot_identity as _same_stack_slot_identity,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _same_stack_slot_identity_var as _same_stack_slot_identity_var,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _sanitize_cod_identifier as _sanitize_cod_identifier,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _seed_adjacent_byte_pair_aliases as _seed_adjacent_byte_pair_aliases,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _seed_alias_state_from_registers_8616 as _seed_alias_state_from_registers_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _segment_reg_name as _segment_reg_name,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _segment_register_var_name_8616 as _segment_register_var_name_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _SegmentedAccess as _SegmentedAccess,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _set_c_variable_type_8616 as _set_c_variable_type_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _should_attach_access_trait_names as _should_attach_access_trait_names,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _simplify_boolean_expr as _simplify_boolean_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _simplify_zero_flag_comparison as _simplify_zero_flag_comparison,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _simplify_zero_mul_or_expr as _simplify_zero_mul_or_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _split_expr_const_offset as _split_expr_const_offset,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _stack_cvar_base_8616 as _stack_cvar_base_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _stack_cvar_binary_8616 as _stack_cvar_binary_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _stack_cvar_indexed_8616 as _stack_cvar_indexed_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _stack_object_name as _stack_object_name,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _stack_slot_identity_can_join as _stack_slot_identity_can_join,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _stack_slot_identity_can_join_var as _stack_slot_identity_can_join_var,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _stack_slot_identity_for_variable as _stack_slot_identity_for_variable,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _stack_type_for_size as _stack_type_for_size,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _StackPointerAliasState as _StackPointerAliasState,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _staging_used_variable_ids_8616 as _staging_used_variable_ids_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _storage_domain_for_expr as _storage_domain_for_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _storage_size_from_type_bits as _storage_size_from_type_bits,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _strip_segment_scale_from_addr_expr as _strip_segment_scale_from_addr_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _structured_codegen_node as _structured_codegen_node,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _structured_codegen_node_8616 as _structured_codegen_node_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _structured_slot_names_8616 as _structured_slot_names_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _structured_slot_names_for_type_8616 as _structured_slot_names_for_type_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _StructuredSimplifyRun8616 as _StructuredSimplifyRun8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _synthetic_global_entry as _synthetic_global_entry,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _synthetic_word_global_variable as _synthetic_word_global_variable,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _transform_condition_pairs_8616 as _transform_condition_pairs_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _unwrap_c_casts as _unwrap_c_casts,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _WideningMatch as _WideningMatch,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _word_from_adjacent_memory_bytes as _word_from_adjacent_memory_bytes,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _word_from_byte_pair_addr_match as _word_from_byte_pair_addr_match,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _word_from_constant_byte_pair as _word_from_constant_byte_pair,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _word_from_pair_low_addr as _word_from_pair_low_addr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _word_from_shifted_high_expr as _word_from_shifted_high_expr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    _word_from_widening_shift_match as _word_from_widening_shift_match,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    collect_dos_int21_calls as collect_dos_int21_calls,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    collect_interrupt_service_calls as collect_interrupt_service_calls,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    dos_helper_declarations as dos_helper_declarations,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    flatten_bitwise_terms_8616 as flatten_bitwise_terms_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    interrupt_helper_declarations_8616 as interrupt_helper_declarations_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    interrupt_service_addr as interrupt_service_addr,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    interrupt_service_name as interrupt_service_name,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    is_identity_semantic_variable_cast_8616 as is_identity_semantic_variable_cast_8616,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    preferred_known_helper_signature_decl as preferred_known_helper_signature_decl,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    register_pair_name as register_pair_name,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    render_dos_int21_call as render_dos_int21_call,
)
lazy from inertia.cli.cli_c_ast_rewrites import (
    render_interrupt_call as render_interrupt_call,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _BOOL_ELSE_LINE_RE_8616 as _BOOL_ELSE_LINE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _BOOL_IF_LINE_RE_8616 as _BOOL_IF_LINE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _BYTE_WALK_LOOP_RE_8616 as _BYTE_WALK_LOOP_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _C89_DECL_RE_8616 as _C89_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _C89_HEADER_RE_8616 as _C89_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _COD_LINE_HEADER_RE_8616 as _COD_LINE_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _DECL_FUNCTION_SIG_RE_8616 as _DECL_FUNCTION_SIG_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _DECL_SKIP_TOKENS_8616 as _DECL_SKIP_TOKENS_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _DECL_STMT_RE_8616 as _DECL_STMT_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _DECL_TYPE_TAG_RE_8616 as _DECL_TYPE_TAG_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _DECL_TYPEDEF_ALIAS_RE_8616 as _DECL_TYPEDEF_ALIAS_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _DIRECT_SS_STACK_EXPR_RE_8616 as _DIRECT_SS_STACK_EXPR_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _DIRECT_SS_STACK_STORE_RE_8616 as _DIRECT_SS_STACK_STORE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _EXTERN_DECL_RE_8616 as _EXTERN_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _EXTERN_TYPE_RANK_8616 as _EXTERN_TYPE_RANK_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FALLTHROUGH_ANY_RETURN_RE_8616 as _FALLTHROUGH_ANY_RETURN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FALLTHROUGH_EMPTY_HELPERS_8616 as _FALLTHROUGH_EMPTY_HELPERS_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FALLTHROUGH_HEADER_RE_8616 as _FALLTHROUGH_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FALLTHROUGH_TERMINAL_RETURN_RE_8616 as _FALLTHROUGH_TERMINAL_RETURN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FRAG_ASSIGN_RE_8616 as _FRAG_ASSIGN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FRAG_CARRIER_RHS_RE_8616 as _FRAG_CARRIER_RHS_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FRAG_DECL_RE_8616 as _FRAG_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FRAG_IDENT_RE_8616 as _FRAG_IDENT_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _FRAG_LHS_ASSIGN_RE_8616 as _FRAG_LHS_ASSIGN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _GENERIC_FUNC_PTR_DECL_RE_8616 as _GENERIC_FUNC_PTR_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _GENERIC_HEADER_RE_8616 as _GENERIC_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _GENERIC_LOCAL_NAME_RE_8616 as _GENERIC_LOCAL_NAME_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _GENERIC_PLAIN_DECL_RE_8616 as _GENERIC_PLAIN_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _GENERIC_STACK_NAME_RE_8616 as _GENERIC_STACK_NAME_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _GENERIC_USE_RE_8616 as _GENERIC_USE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _GLOBAL_DECL_INFERENCE_RESERVED_IDENTIFIERS_8616 as _GLOBAL_DECL_INFERENCE_RESERVED_IDENTIFIERS_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _INCDEC_FOR_HIGH_RE_8616 as _INCDEC_FOR_HIGH_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _INCDEC_HIGH_RE_8616 as _INCDEC_HIGH_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _INCDEC_INC_RE_8616 as _INCDEC_INC_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _INCDEC_LOAD_RE_8616 as _INCDEC_LOAD_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _INCDEC_LOCAL_DECL_RE_8616 as _INCDEC_LOCAL_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _INCDEC_WORD_RE_8616 as _INCDEC_WORD_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _INDEXED_SS_LOCAL_EXPR_RE_8616 as _INDEXED_SS_LOCAL_EXPR_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _OPAQUE_BASE_TYPES_8616 as _OPAQUE_BASE_TYPES_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _OPAQUE_HEADER_RE_8616 as _OPAQUE_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _OPAQUE_POINTER_TYPE_RE_8616 as _OPAQUE_POINTER_TYPE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _OPAQUE_PROTOTYPE_RE_8616 as _OPAQUE_PROTOTYPE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _PLAIN_STACK_STORE_RE_8616 as _PLAIN_STACK_STORE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _PROTOTYPE_CALL_RE_8616 as _PROTOTYPE_CALL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _PROTOTYPE_DECL_RE_8616 as _PROTOTYPE_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SEG_OFF_HEADER_RE_8616 as _SEG_OFF_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SEGMENTED_BYTE_PAIR_LOAD_RE_8616 as _SEGMENTED_BYTE_PAIR_LOAD_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SHADOW_DECL_RE_8616 as _SHADOW_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SHADOW_FUNC_PTR_RE_8616 as _SHADOW_FUNC_PTR_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SHADOW_HEADER_RE_8616 as _SHADOW_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SIGNATURE_CONTROL_NAMES_8616 as _SIGNATURE_CONTROL_NAMES_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SIGNATURE_TYPE_KEYWORDS_8616 as _SIGNATURE_TYPE_KEYWORDS_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SPURIOUS_DECL_RE_8616 as _SPURIOUS_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SPURIOUS_HEADER_RE_8616 as _SPURIOUS_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _SS_STACK_STORE_RE_8616 as _SS_STACK_STORE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_ALIAS_BASE_RE_8616 as _STACK_ALIAS_BASE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_ALIAS_CHAIN_RE_8616 as _STACK_ALIAS_CHAIN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_BYTE_PAIR_LOAD_RE_8616 as _STACK_BYTE_PAIR_LOAD_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_FAR_POINTER_STORE_RE_8616 as _STACK_FAR_POINTER_STORE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_HIGH_STORE_RE_8616 as _STACK_HIGH_STORE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_HIGH_STORE_UNCAST_RE_8616 as _STACK_HIGH_STORE_UNCAST_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_LOW_STORE_RE_8616 as _STACK_LOW_STORE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_LOW_STORE_UNCAST_RE_8616 as _STACK_LOW_STORE_UNCAST_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_POINTER_STORE_RE_8616 as _STACK_POINTER_STORE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STACK_RAW_LINEAR_POINTER_STORE_RE_8616 as _STACK_RAW_LINEAR_POINTER_STORE_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STAGING_ASSIGN_RE_8616 as _STAGING_ASSIGN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STAGING_DECL_RE_8616 as _STAGING_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STAGING_GENERIC_ASSIGN_RE_8616 as _STAGING_GENERIC_ASSIGN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STAGING_IDENT_RE_8616 as _STAGING_IDENT_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STAGING_NAME_PATTERN_8616 as _STAGING_NAME_PATTERN_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STAGING_NAME_RE_8616 as _STAGING_NAME_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STAGING_RAW_REGISTER_FRAG_RE_8616 as _STAGING_RAW_REGISTER_FRAG_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _STAGING_SELF_ADDR_RE_8616 as _STAGING_SELF_ADDR_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _UNUSED_LOCAL_DECL_RE_8616 as _UNUSED_LOCAL_DECL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _UNUSED_LOCAL_HEADER_RE_8616 as _UNUSED_LOCAL_HEADER_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _UNUSED_LOCAL_IDENT_RE_8616 as _UNUSED_LOCAL_IDENT_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _UNUSED_LOCAL_SKIP_PREFIXES_8616 as _UNUSED_LOCAL_SKIP_PREFIXES_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _UNUSED_LOCAL_SYNTHETIC_RE_8616 as _UNUSED_LOCAL_SYNTHETIC_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _VOID_BARE_RETURN_RE_8616 as _VOID_BARE_RETURN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _VOID_HEADER_START_RE_8616 as _VOID_HEADER_START_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _VOID_RETURN_RE_8616 as _VOID_RETURN_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _VOID_SIDE_EFFECT_CALL_RE_8616 as _VOID_SIDE_EFFECT_CALL_RE_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _alias_replacements_from_metadata_8616 as _alias_replacements_from_metadata_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _align_function_header_with_cod_source_decl_text as _align_function_header_with_cod_source_decl_text,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _align_unknown_call_names_from_cod_evidence_text as _align_unknown_call_names_from_cod_evidence_text,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _annotate_bp_comment_line_8616 as _annotate_bp_comment_line_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _annotate_cod_lines_with_aliases_8616 as _annotate_cod_lines_with_aliases_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _annotated_bp_arg_names_8616 as _annotated_bp_arg_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _apply_alias_replacements_8616 as _apply_alias_replacements_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _apply_int21_helper_replacements_8616 as _apply_int21_helper_replacements_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _apply_interrupt_replacements_8616 as _apply_interrupt_replacements_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _apply_local_return_type_to_header_8616 as _apply_local_return_type_to_header_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _apply_spurious_renames_8616 as _apply_spurious_renames_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _apply_wrapper_calls_8616 as _apply_wrapper_calls_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _arg_has_pointer_evidence_8616 as _arg_has_pointer_evidence_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _arg_name_used_in_body_8616 as _arg_name_used_in_body_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _body_identifier_counts_8616 as _body_identifier_counts_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _c89_collect_decl_entries_8616 as _c89_collect_decl_entries_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _c89_hoist_plan_8616 as _c89_hoist_plan_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _c89_insertion_index_8616 as _c89_insertion_index_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _canonicalize_suffixed_helper_calls_8616 as _canonicalize_suffixed_helper_calls_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _classify_staging_assignment_rhs_effect_8616 as _classify_staging_assignment_rhs_effect_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _cod_decls_finish_8616 as _cod_decls_finish_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _codegen_prototype_parts_8616 as _codegen_prototype_parts_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _codegen_signature_authoritative_8616 as _codegen_signature_authoritative_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_cod_materialized_decls_8616 as _collect_cod_materialized_decls_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_declared_and_defined_function_names as _collect_declared_and_defined_function_names,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_declared_global_names_8616 as _collect_declared_global_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_declared_identifiers_8616 as _collect_declared_identifiers_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_declared_identifiers_line_8616 as _collect_declared_identifiers_line_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_direct_calls_and_observed_arity as _collect_direct_calls_and_observed_arity,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_function_parameter_names_8616 as _collect_function_parameter_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_global_usage_candidates_from_body_8616 as _collect_global_usage_candidates_from_body_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_header_arg_aliases_8616 as _collect_header_arg_aliases_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_local_decl_entries as _collect_local_decl_entries,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_member_access_names_8616 as _collect_member_access_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _collect_void_function_names_from_c_text_8616 as _collect_void_function_names_from_c_text_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _comma_tail_names_8616 as _comma_tail_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _compile_function_header_pattern_8616 as _compile_function_header_pattern_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _contains_void_function_definition_text as _contains_void_function_definition_text,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _decl_arg_name_8616 as _decl_arg_name_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _declared_generic_local_name_8616 as _declared_generic_local_name_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _declared_names_for_synthetic_globals_8616 as _declared_names_for_synthetic_globals_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _dynamic_text_attr as _dynamic_text_attr,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _ensure_main_returns_zero as _ensure_main_returns_zero,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _extern_decl_rewrite_8616 as _extern_decl_rewrite_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _extern_decl_winners_8616 as _extern_decl_winners_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _extract_function_header_args_8616 as _extract_function_header_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _extract_reserved_arg_names as _extract_reserved_arg_names,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _fallthrough_header_match_8616 as _fallthrough_header_match_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _fallthrough_return_candidates_8616 as _fallthrough_return_candidates_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _fallthrough_terminal_index_8616 as _fallthrough_terminal_index_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _fallthrough_terminal_result_8616 as _fallthrough_terminal_result_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _finalize_cod_annotation_text_8616 as _finalize_cod_annotation_text_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _find_block_end as _find_block_end,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _find_body_end_index_8616 as _find_body_end_index_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _find_body_span_8616 as _find_body_span_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _find_first_function_insert_index as _find_first_function_insert_index,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _find_function_body_bounds as _find_function_body_bounds,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _find_function_body_open_8616 as _find_function_body_open_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _find_function_brace_index as _find_function_brace_index,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _find_header_index_8616 as _find_header_index_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _first_function_insert_index_8616 as _first_function_insert_index_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _format_bp_disp as _format_bp_disp,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _frag_carrier_line_dropped_8616 as _frag_carrier_line_dropped_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _frag_declared_names_8616 as _frag_declared_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _frag_live_assigns_reads_8616 as _frag_live_assigns_reads_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _frag_read_usage_8616 as _frag_read_usage_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _func_header_match_8616 as _func_header_match_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _function_definition_args_text_8616 as _function_definition_args_text_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _gb_array_name_needs_scalar_8616 as _gb_array_name_needs_scalar_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _gb_array_scalar_use_res_8616 as _gb_array_scalar_use_res_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _generic_block_body_end_8616 as _generic_block_body_end_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _generic_block_brace_index_8616 as _generic_block_brace_index_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _generic_declared_names_8616 as _generic_declared_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _generic_used_names_8616 as _generic_used_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _global_binop_candidates_8616 as _global_binop_candidates_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _global_call_arg_candidates_8616 as _global_call_arg_candidates_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _has_decl_or_def_in_text as _has_decl_or_def_in_text,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _has_open_brace_in_lookahead as _has_open_brace_in_lookahead,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _helper_literal_mappings_8616 as _helper_literal_mappings_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _hoist_c89_decls_block_8616 as _hoist_c89_decls_block_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _immutable_pointer_names_8616 as _immutable_pointer_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _infer_decl_for_global_8616 as _infer_decl_for_global_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _interrupt_wrapper_call_text as _interrupt_wrapper_call_text,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _is_known_compiler_temp_8616 as _is_known_compiler_temp_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _is_plausible_simple_return_type_8616 as _is_plausible_simple_return_type_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _is_portable_main_argument_list as _is_portable_main_argument_list,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _is_strict_c_identifier_8616 as _is_strict_c_identifier_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _join_lines_like_input_8616 as _join_lines_like_input_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _join_with_original_trailing_newline as _join_with_original_trailing_newline,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _linear_addr_to_mk_fp_8616 as _linear_addr_to_mk_fp_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _LocalDeclEntry8616 as _LocalDeclEntry8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _LocalDeclKind8616 as _LocalDeclKind8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _materialize_generic_locals_block_8616 as _materialize_generic_locals_block_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _msc_signed_arg_text_8616 as _msc_signed_arg_text_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _name_has_known_binding_8616 as _name_has_known_binding_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _name_in_text_8616 as _name_in_text_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _norm_incdec_expr_8616 as _norm_incdec_expr_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _normalize_duplicate_generic_hex_global_names_8616 as _normalize_duplicate_generic_hex_global_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _normalize_existing_decl_names_8616 as _normalize_existing_decl_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _normalize_main_header_args as _normalize_main_header_args,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _normalize_mk_fp_segment_names as _normalize_mk_fp_segment_names,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _normalize_nonportable_main_void_call_returns as _normalize_nonportable_main_void_call_returns,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _normalize_signature_args_8616 as _normalize_signature_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _normalize_symbol_name_text as _normalize_symbol_name_text,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _opaque_collect_args_types_8616 as _opaque_collect_args_types_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _opaque_known_types_8616 as _opaque_known_types_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _opaque_needed_pointer_types_8616 as _opaque_needed_pointer_types_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _parameter_names_from_args_text_8616 as _parameter_names_from_args_text_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _prototype_declared_arity_8616 as _prototype_declared_arity_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _prototype_for_direct_call as _prototype_for_direct_call,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _prototype_score_8616 as _prototype_score_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _prune_shadow_decls_in_body_8616 as _prune_shadow_decls_in_body_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _prune_unused_locals_block_8616 as _prune_unused_locals_block_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _PruneConflictingPrototypesRun8616 as _PruneConflictingPrototypesRun8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _PruneVoidReturnsRun8616 as _PruneVoidReturnsRun8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _remove_missing_arg_decls_8616 as _remove_missing_arg_decls_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rename_identifiers_in_body_8616 as _rename_identifiers_in_body_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _renamed_arg_mismatch_probe_8616 as _renamed_arg_mismatch_probe_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _repair_empty_if_else_gaps_8616 as _repair_empty_if_else_gaps_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _repair_missing_cod_function_header_text as _repair_missing_cod_function_header_text,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _repair_missing_fallthrough_returns as _repair_missing_fallthrough_returns,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _replace_decl_arg_name_8616 as _replace_decl_arg_name_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _replace_header_and_join_8616 as _replace_header_and_join_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _restore_codegen_header_for_unmaterialized_source_args_8616 as _restore_codegen_header_for_unmaterialized_source_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _return_only_helper_decl_8616 as _return_only_helper_decl_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_byte_walk_loop_8616 as _rewrite_byte_walk_loop_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_cod_arg_decl_8616 as _rewrite_cod_arg_decl_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_cod_header_8616 as _rewrite_cod_header_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_cod_header_arg_parts_8616 as _rewrite_cod_header_arg_parts_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_cod_header_args_line_8616 as _rewrite_cod_header_args_line_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_direct_ss_stack_expr_8616 as _rewrite_direct_ss_stack_expr_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_indexed_ss_local_expr_8616 as _rewrite_indexed_ss_local_expr_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_or_prune_duplicate_locals as _rewrite_or_prune_duplicate_locals,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_single_stack_pointer_line_8616 as _rewrite_single_stack_pointer_line_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_stack_pointer_load_patterns_8616 as _rewrite_stack_pointer_load_patterns_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _rewrite_stack_pointer_store_lines_8616 as _rewrite_stack_pointer_store_lines_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _safe_finditer_8616 as _safe_finditer_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _seg_off_rewritten_args_8616 as _seg_off_rewritten_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _shadow_body_end_8616 as _shadow_body_end_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _shadow_function_arg_names_8616 as _shadow_function_arg_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _signature_arg_names_8616 as _signature_arg_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _signature_split_args_8616 as _signature_split_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _signature_split_decl_name_8616 as _signature_split_decl_name_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _simplify_condition_line as _simplify_condition_line,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _simplify_negated_condition as _simplify_negated_condition,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _simplify_negated_zero_one_ternary_condition_8616 as _simplify_negated_zero_one_ternary_condition_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _simplify_x86_16_conditions as _simplify_x86_16_conditions,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _simplify_x86_16_stack_references as _simplify_x86_16_stack_references,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _simplify_x86_16_wrapped_stack_offsets as _simplify_x86_16_wrapped_stack_offsets,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _sorted_metadata_stack_aliases as _sorted_metadata_stack_aliases,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _source_args_from_cod_source_lines as _source_args_from_cod_source_lines,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _source_decl_args_text_8616 as _source_decl_args_text_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _source_decl_has_custom_ptr_8616 as _source_decl_has_custom_ptr_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _source_function_prototype_decls_from_cod_source_lines as _source_function_prototype_decls_from_cod_source_lines,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _source_header_args_unmaterialized_8616 as _source_header_args_unmaterialized_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_args_8616 as _split_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_c_signature_args_8616 as _split_c_signature_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_for_header_8616 as _split_for_header_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_function_args_preserving_nesting as _split_function_args_preserving_nesting,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_incdec_word_pattern_8616 as _split_incdec_word_pattern_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_simple_assignment_conditions as _split_simple_assignment_conditions,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_source_decl_args_8616 as _split_source_decl_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_top_level_binary as _split_top_level_binary,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_top_level_call_args_8616 as _split_top_level_call_args_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _split_top_level_ternary_8616 as _split_top_level_ternary_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _spurious_declared_names_8616 as _spurious_declared_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _spurious_rename_map_8616 as _spurious_rename_map_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _stack_norm_far_offset_8616 as _stack_norm_far_offset_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _stack_norm_rhs_8616 as _stack_norm_rhs_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _stack_rhs_base_8616 as _stack_rhs_base_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _StackAliasResolver8616 as _StackAliasResolver8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _StackPointerLineCtx8616 as _StackPointerLineCtx8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _StagingAssignmentRhsEffect8616 as _StagingAssignmentRhsEffect8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _StagingPrunePass8616 as _StagingPrunePass8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _strip_comments_and_strings_8616 as _strip_comments_and_strings_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _strip_comments_for_global_decl_inference_8616 as _strip_comments_for_global_decl_inference_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _strip_single_outer_parens_8616 as _strip_single_outer_parens_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _synthetic_global_declarations_8616 as _synthetic_global_declarations_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _synthetic_name_width_map_8616 as _synthetic_name_width_map_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _unmaterialized_source_arg_probe_8616 as _unmaterialized_source_arg_probe_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _unused_local_block_span_8616 as _unused_local_block_span_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _unused_local_decl_names_8616 as _unused_local_decl_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _unused_locals_removal_8616 as _unused_locals_removal_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _update_bracket_depths_8616 as _update_bracket_depths_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _used_global_names_8616 as _used_global_names_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    _used_global_names_per_line_8616 as _used_global_names_per_line_8616,
)
lazy from inertia.cli.cli_c_text_postprocess import (
    runtime_gp_word_symbols_8616 as runtime_gp_word_symbols_8616,
)
lazy from inertia.cli.cli_core import (
    _ANALYSIS_TIMEOUT_FORCE_THREAD_LANES_ENV_8616 as _ANALYSIS_TIMEOUT_FORCE_THREAD_LANES_ENV_8616,
)
lazy from inertia.cli.cli_core import (
    _ARCHITECTURE_GUARD_STATUS_8616 as _ARCHITECTURE_GUARD_STATUS_8616,
)
lazy from inertia.cli.cli_core import (
    _C_ASSIGN_RE_8616 as _C_ASSIGN_RE_8616,
)
lazy from inertia.cli.cli_core import (
    _C_IDENT_RE as _C_IDENT_RE,
)
lazy from inertia.cli.cli_core import (
    _C_IDENT_RE_8616 as _C_IDENT_RE_8616,
)
lazy from inertia.cli.cli_core import (
    _CALL_TOKEN_RE as _CALL_TOKEN_RE,
)
lazy from inertia.cli.cli_core import (
    _DEFAULT_FUNCTION_TIMEOUT_CAP as _DEFAULT_FUNCTION_TIMEOUT_CAP,
)
lazy from inertia.cli.cli_core import (
    _DIRECT_ADDR_FORCE_THREAD_LANE_ENV_8616 as _DIRECT_ADDR_FORCE_THREAD_LANE_ENV_8616,
)
lazy from inertia.cli.cli_core import (
    _FORCE_SERIAL_FUNCTION_DECOMP_ENV as _FORCE_SERIAL_FUNCTION_DECOMP_ENV,
)
lazy from inertia.cli.cli_core import (
    _NON_EXECUTABLE_CALL_NAMES_8616 as _NON_EXECUTABLE_CALL_NAMES_8616,
)
lazy from inertia.cli.cli_core import (
    _RECOMPILE_RESULT_CACHE_8616 as _RECOMPILE_RESULT_CACHE_8616,
)
lazy from inertia.cli.cli_core import (
    _RECOMPILE_RESULT_CACHE_LOCK_8616 as _RECOMPILE_RESULT_CACHE_LOCK_8616,
)
lazy from inertia.cli.cli_core import (
    _SEG_DS_ACCESS_RE_8616 as _SEG_DS_ACCESS_RE_8616,
)
lazy from inertia.cli.cli_core import (
    _SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616 as _SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616,
)
lazy from inertia.cli.cli_core import (
    _SERIAL_CLEAN_WORKER_RESULT_ENV_8616 as _SERIAL_CLEAN_WORKER_RESULT_ENV_8616,
)
lazy from inertia.cli.cli_core import (
    _SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616 as _SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
)
lazy from inertia.cli.cli_core import (
    _TRUTHY_ENV_VALUES_8616 as _TRUTHY_ENV_VALUES_8616,
)
lazy from inertia.cli.cli_core import (
    _X86_16_EXACT_REGION_PADDING_SCAN_LIMIT as _X86_16_EXACT_REGION_PADDING_SCAN_LIMIT,
)
lazy from inertia.cli.cli_core import (
    ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV as ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV,
)
lazy from inertia.cli.cli_core import (
    DECOMPILATION_CACHE_SOURCE_FILES as DECOMPILATION_CACHE_SOURCE_FILES,
)
lazy from inertia.cli.cli_core import (
    FIRST_COMPLETED as FIRST_COMPLETED,
)
lazy from inertia.cli.cli_core import (
    PARALLEL_CLEAN_WORKER_TIMEOUT_CAP as PARALLEL_CLEAN_WORKER_TIMEOUT_CAP,
)
lazy from inertia.cli.cli_core import (
    AcceptedPayloadIntegrity8616 as AcceptedPayloadIntegrity8616,
)
lazy from inertia.cli.cli_core import (
    AcceptedPayloadIntegrityVerdict8616 as AcceptedPayloadIntegrityVerdict8616,
)
lazy from inertia.cli.cli_core import (
    Any as Any,
)
lazy from inertia.cli.cli_core import (
    BatchCOutputStatus8616 as BatchCOutputStatus8616,
)
lazy from inertia.cli.cli_core import (
    CAcceptanceResult8616 as CAcceptanceResult8616,
)
lazy from inertia.cli.cli_core import (
    CallerReturnUseEvidence8616 as CallerReturnUseEvidence8616,
)
lazy from inertia.cli.cli_core import (
    CliArguments as CliArguments,
)
lazy from inertia.cli.cli_core import (
    CliTerminalStatus as CliTerminalStatus,
)
lazy from inertia.cli.cli_core import (
    CODProcMetadata as CODProcMetadata,
)
lazy from inertia.cli.cli_core import (
    DaemonThreadPoolExecutor as DaemonThreadPoolExecutor,
)
lazy from inertia.cli.cli_core import (
    DeclaredDiscoveryStatus8616 as DeclaredDiscoveryStatus8616,
)
lazy from inertia.cli.cli_core import (
    DeclaredFunctionDiscovery8616 as DeclaredFunctionDiscovery8616,
)
lazy from inertia.cli.cli_core import (
    DirectAddrCanonicalization8616 as DirectAddrCanonicalization8616,
)
lazy from inertia.cli.cli_core import (
    DirectClinicPolicy8616 as DirectClinicPolicy8616,
)
lazy from inertia.cli.cli_core import (
    DirectRequestCacheArtifact8616 as DirectRequestCacheArtifact8616,
)
lazy from inertia.cli.cli_core import (
    DirectRequestCacheInputs8616 as DirectRequestCacheInputs8616,
)
lazy from inertia.cli.cli_core import (
    DirectRequestCacheLookup8616 as DirectRequestCacheLookup8616,
)
lazy from inertia.cli.cli_core import (
    DirectRequestCacheVerdict8616 as DirectRequestCacheVerdict8616,
)
lazy from inertia.cli.cli_core import (
    DisplayCatalogCachePolicy8616 as DisplayCatalogCachePolicy8616,
)
lazy from inertia.cli.cli_core import (
    Enum as Enum,
)
lazy from inertia.cli.cli_core import (
    FailureFamilySnapshot as FailureFamilySnapshot,
)
lazy from inertia.cli.cli_core import (
    FailureFamilyState as FailureFamilyState,
)
lazy from inertia.cli.cli_core import (
    FunctionWorkerMode8616 as FunctionWorkerMode8616,
)
lazy from inertia.cli.cli_core import (
    FunctionWorkExecutionOrigin8616 as FunctionWorkExecutionOrigin8616,
)
lazy from inertia.cli.cli_core import (
    FunctionWorkItem as FunctionWorkItem,
)
lazy from inertia.cli.cli_core import (
    FunctionWorkResult as FunctionWorkResult,
)
lazy from inertia.cli.cli_core import (
    FuturesTimeoutError as FuturesTimeoutError,
)
lazy from inertia.cli.cli_core import (
    Iterable as Iterable,
)
lazy from inertia.cli.cli_core import (
    Iterator as Iterator,
)
lazy from inertia.cli.cli_core import (
    LSTMetadata as LSTMetadata,
)
lazy from inertia.cli.cli_core import (
    Mapping as Mapping,
)
lazy from inertia.cli.cli_core import (
    NonOptimizedSliceOutcome as NonOptimizedSliceOutcome,
)
lazy from inertia.cli.cli_core import (
    PackedExecutableRefusedError as PackedExecutableRefusedError,
)
lazy from inertia.cli.cli_core import (
    Path as Path,
)
lazy from inertia.cli.cli_core import (
    PipelineHardError as PipelineHardError,
)
lazy from inertia.cli.cli_core import (
    RecompileCheckResult as RecompileCheckResult,
)
lazy from inertia.cli.cli_core import (
    RizinDiscoveryResult as RizinDiscoveryResult,
)
lazy from inertia.cli.cli_core import (
    RizinDiscoveryStatus as RizinDiscoveryStatus,
)
lazy from inertia.cli.cli_core import (
    RizinEvidence as RizinEvidence,
)
lazy from inertia.cli.cli_core import (
    RizinEvidenceStatus as RizinEvidenceStatus,
)
lazy from inertia.cli.cli_core import (
    ScalarInterface8616 as ScalarInterface8616,
)
lazy from inertia.cli.cli_core import (
    SegmentProgramFunctionEvidence8616 as SegmentProgramFunctionEvidence8616,
)
lazy from inertia.cli.cli_core import (
    Sequence as Sequence,
)
lazy from inertia.cli.cli_core import (
    SerialWorkerCacheLookup8616 as SerialWorkerCacheLookup8616,
)
lazy from inertia.cli.cli_core import (
    SerialWorkerCacheVerdict8616 as SerialWorkerCacheVerdict8616,
)
lazy from inertia.cli.cli_core import (
    Sized as Sized,
)
lazy from inertia.cli.cli_core import (
    SliceRecoveryAttemptOutcome as SliceRecoveryAttemptOutcome,
)
lazy from inertia.cli.cli_core import (
    TerminalDecompileFailure8616 as TerminalDecompileFailure8616,
)
lazy from inertia.cli.cli_core import (
    WorkItemStatus as WorkItemStatus,
)
lazy from inertia.cli.cli_core import (
    _accept_function_work_result_for_emission_8616 as _accept_function_work_result_for_emission_8616,
)
lazy from inertia.cli.cli_core import (
    _accept_generated_c_for_emission_8616 as _accept_generated_c_for_emission_8616,
)
lazy from inertia.cli.cli_core import (
    _accept_string_fallback_8616 as _accept_string_fallback_8616,
)
lazy from inertia.cli.cli_core import (
    _acceptance_result_8616 as _acceptance_result_8616,
)
lazy from inertia.cli.cli_core import (
    _acceptance_run_8616 as _acceptance_run_8616,
)
lazy from inertia.cli.cli_core import (
    _acceptance_tail_snapshot_admitted_8616 as _acceptance_tail_snapshot_admitted_8616,
)
lazy from inertia.cli.cli_core import (
    _AdaptivePerByteTimeoutModel as _AdaptivePerByteTimeoutModel,
)
lazy from inertia.cli.cli_core import (
    _analysis_timeout_lane_allows_fork as _analysis_timeout_lane_allows_fork,
)
lazy from inertia.cli.cli_core import (
    _analysis_timeout_use_fork_8616 as _analysis_timeout_use_fork_8616,
)
lazy from inertia.cli.cli_core import (
    _AnalysisTimeout as _AnalysisTimeout,
)
lazy from inertia.cli.cli_core import (
    _AngrFunction as _AngrFunction,
)
lazy from inertia.cli.cli_core import (
    _apply_binary_specific_annotations as _apply_binary_specific_annotations,
)
lazy from inertia.cli.cli_core import (
    _apply_function_annotations_for_active_and_original_8616 as _apply_function_annotations_for_active_and_original_8616,
)
lazy from inertia.cli.cli_core import (
    _apply_memory_limit as _apply_memory_limit,
)
lazy from inertia.cli.cli_core import (
    _argument_was_explicit as _argument_was_explicit,
)
lazy from inertia.cli.cli_core import (
    _auto_rizin_enabled_for_binary_8616 as _auto_rizin_enabled_for_binary_8616,
)
lazy from inertia.cli.cli_core import (
    _batch_exit_code_8616 as _batch_exit_code_8616,
)
lazy from inertia.cli.cli_core import (
    _batch_function_decompile_timeout_8616 as _batch_function_decompile_timeout_8616,
)
lazy from inertia.cli.cli_core import (
    _BatchCliContext8616 as _BatchCliContext8616,
)
lazy from inertia.cli.cli_core import (
    _binary_evidence_recovery_snapshot_8616 as _binary_evidence_recovery_snapshot_8616,
)
lazy from inertia.cli.cli_core import (
    _bounded_non_optimized_timeout as _bounded_non_optimized_timeout,
)
lazy from inertia.cli.cli_core import (
    _build_project as _build_project,
)
lazy from inertia.cli.cli_core import (
    _build_project_cached as _build_project_cached,
)
lazy from inertia.cli.cli_core import (
    _build_project_from_bytes as _build_project_from_bytes,
)
lazy from inertia.cli.cli_core import (
    _cache_bypass_8616 as _cache_bypass_8616,
)
lazy from inertia.cli.cli_core import (
    _cache_key_lock as _cache_key_lock,
)
lazy from inertia.cli.cli_core import (
    _cache_source_digest as _cache_source_digest,
)
lazy from inertia.cli.cli_core import (
    _cacheable_direct_result_8616 as _cacheable_direct_result_8616,
)
lazy from inertia.cli.cli_core import (
    _cached_function_work_result_8616 as _cached_function_work_result_8616,
)
lazy from inertia.cli.cli_core import (
    _cached_payload_acceptance_bypass_reason_8616 as _cached_payload_acceptance_bypass_reason_8616,
)
lazy from inertia.cli.cli_core import (
    _cached_tail_snapshot_8616 as _cached_tail_snapshot_8616,
)
lazy from inertia.cli.cli_core import (
    _call_text_parse_until_8616 as _call_text_parse_until_8616,
)
lazy from inertia.cli.cli_core import (
    _call_text_skip_string_8616 as _call_text_skip_string_8616,
)
lazy from inertia.cli.cli_core import (
    _call_text_skip_ws_8616 as _call_text_skip_ws_8616,
)
lazy from inertia.cli.cli_core import (
    _canonicalize_direct_addr_from_sidecar_padding_8616 as _canonicalize_direct_addr_from_sidecar_padding_8616,
)
lazy from inertia.cli.cli_core import (
    _canonicalize_sidecar_work_offset_8616 as _canonicalize_sidecar_work_offset_8616,
)
lazy from inertia.cli.cli_core import (
    _capture_thread_output as _capture_thread_output,
)
lazy from inertia.cli.cli_core import (
    _catalog_address_cache_key_8616 as _catalog_address_cache_key_8616,
)
lazy from inertia.cli.cli_core import (
    _catalog_address_cache_storable_8616 as _catalog_address_cache_storable_8616,
)
lazy from inertia.cli.cli_core import (
    _choose_function_parallelism as _choose_function_parallelism,
)
lazy from inertia.cli.cli_core import (
    _clinic_policy_needs_callsite_count_8616 as _clinic_policy_needs_callsite_count_8616,
)
lazy from inertia.cli.cli_core import (
    _coalesce_redundant_split_global_incdec_text as _coalesce_redundant_split_global_incdec_text,
)
lazy from inertia.cli.cli_core import (
    _collect_recompilation_payloads_8616 as _collect_recompilation_payloads_8616,
)
lazy from inertia.cli.cli_core import (
    _collect_rizin_library_offsets_8616 as _collect_rizin_library_offsets_8616,
)
lazy from inertia.cli.cli_core import (
    _complete_serial_clean_worker_result_8616 as _complete_serial_clean_worker_result_8616,
)
lazy from inertia.cli.cli_core import (
    _configure_cli_telemetry_8616 as _configure_cli_telemetry_8616,
)
lazy from inertia.cli.cli_core import (
    _configure_display_catalog_cache_policy_8616 as _configure_display_catalog_cache_policy_8616,
)
lazy from inertia.cli.cli_core import (
    _copy_function_project_tv_attrs_8616 as _copy_function_project_tv_attrs_8616,
)
lazy from inertia.cli.cli_core import (
    _count_unresolved_ds_linear_macro_hits_8616 as _count_unresolved_ds_linear_macro_hits_8616,
)
lazy from inertia.cli.cli_core import (
    _dead_setup_counters_8616 as _dead_setup_counters_8616,
)
lazy from inertia.cli.cli_core import (
    _declared_call_dependency_retained_8616 as _declared_call_dependency_retained_8616,
)
lazy from inertia.cli.cli_core import (
    _decompile_for_work_item_8616 as _decompile_for_work_item_8616,
)
lazy from inertia.cli.cli_core import (
    _decompile_function_with_stats as _decompile_function_with_stats,
)
lazy from inertia.cli.cli_core import (
    _DecompileRunTuple8616 as _DecompileRunTuple8616,
)
lazy from inertia.cli.cli_core import (
    _dedupe_duplicate_local_declarations_text as _dedupe_duplicate_local_declarations_text,
)
lazy from inertia.cli.cli_core import (
    _default_exe_showcase_cap as _default_exe_showcase_cap,
)
lazy from inertia.cli.cli_core import (
    _default_recovery_timeout as _default_recovery_timeout,
)
lazy from inertia.cli.cli_core import (
    _describe_exception as _describe_exception,
)
lazy from inertia.cli.cli_core import (
    _direct_addr_project_local_fallback_addr_8616 as _direct_addr_project_local_fallback_addr_8616,
)
lazy from inertia.cli.cli_core import (
    _direct_addr_robust_retry_enabled_8616 as _direct_addr_robust_retry_enabled_8616,
)
lazy from inertia.cli.cli_core import (
    _direct_addr_should_skip_heavy_validation_fallbacks_8616 as _direct_addr_should_skip_heavy_validation_fallbacks_8616,
)
lazy from inertia.cli.cli_core import (
    _direct_addr_use_fork_lane_8616 as _direct_addr_use_fork_lane_8616,
)
lazy from inertia.cli.cli_core import (
    _direct_addr_validation_retry_count_8616 as _direct_addr_validation_retry_count_8616,
)
lazy from inertia.cli.cli_core import (
    _direct_addr_wall_clock_budget as _direct_addr_wall_clock_budget,
)
lazy from inertia.cli.cli_core import (
    _direct_addr_work_requires_parent_lock_8616 as _direct_addr_work_requires_parent_lock_8616,
)
lazy from inertia.cli.cli_core import (
    _direct_clinic_policy_8616 as _direct_clinic_policy_8616,
)
lazy from inertia.cli.cli_core import (
    _direct_request_cache_artifact_for_result_8616 as _direct_request_cache_artifact_for_result_8616,
)
lazy from inertia.cli.cli_core import (
    _direct_timeout_failure_stage_from_payload as _direct_timeout_failure_stage_from_payload,
)
lazy from inertia.cli.cli_core import (
    _DirectAddrCliContext8616 as _DirectAddrCliContext8616,
)
lazy from inertia.cli.cli_core import (
    _DirectAddrCliRun8616 as _DirectAddrCliRun8616,
)
lazy from inertia.cli.cli_core import (
    _DirectDecompileJobResult8616 as _DirectDecompileJobResult8616,
)
lazy from inertia.cli.cli_core import (
    _discover_ranked_binary_offsets as _discover_ranked_binary_offsets,
)
lazy from inertia.cli.cli_core import (
    _dump_validation_failed_payload_8616 as _dump_validation_failed_payload_8616,
)
lazy from inertia.cli.cli_core import (
    _dump_validation_failed_payload_if_requested_8616 as _dump_validation_failed_payload_if_requested_8616,
)
lazy from inertia.cli.cli_core import (
    _effective_decompile_timeout_8616 as _effective_decompile_timeout_8616,
)
lazy from inertia.cli.cli_core import (
    _emission_result_state_8616 as _emission_result_state_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_asm_fallback_block_8616 as _emit_asm_fallback_block_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_conditional_result_8616 as _emit_conditional_result_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_direct_cache_hit_8616 as _emit_direct_cache_hit_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_failed_timeout_acceptance_hints_8616 as _emit_failed_timeout_acceptance_hints_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_function_result as _emit_function_result,
)
lazy from inertia.cli.cli_core import (
    _emit_function_result_fallback_lanes_8616 as _emit_function_result_fallback_lanes_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_function_result_light_fallback_8616 as _emit_function_result_light_fallback_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_function_timing_summary as _emit_function_timing_summary,
)
lazy from inertia.cli.cli_core import (
    _emit_light_asm_fallback_tail_8616 as _emit_light_asm_fallback_tail_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_light_nonopt_unavailable_8616 as _emit_light_nonopt_unavailable_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_nonopt_acceptance_8616 as _emit_nonopt_acceptance_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_ok_result_8616 as _emit_ok_result_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_optional_source_sidecar_c_block as _emit_optional_source_sidecar_c_block,
)
lazy from inertia.cli.cli_core import (
    _emit_partial_payload_block_8616 as _emit_partial_payload_block_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_pending_batch_results_8616 as _emit_pending_batch_results_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_retry_gate_candidate_8616 as _emit_retry_gate_candidate_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_sidecar_slice_tail_validation_snapshot_8616 as _emit_sidecar_slice_tail_validation_snapshot_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_string_fallback_block_8616 as _emit_string_fallback_block_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_string_or_asm_fallback_8616 as _emit_string_or_asm_fallback_8616,
)
lazy from inertia.cli.cli_core import (
    _emit_tail_validation_console_summary as _emit_tail_validation_console_summary,
)
lazy from inertia.cli.cli_core import (
    _emit_tail_validation_for_function_run_or_uncollected as _emit_tail_validation_for_function_run_or_uncollected,
)
lazy from inertia.cli.cli_core import (
    _emit_tail_validation_snapshot_or_uncollected as _emit_tail_validation_snapshot_or_uncollected,
)
lazy from inertia.cli.cli_core import (
    _emit_timeout_and_exit as _emit_timeout_and_exit,
)
lazy from inertia.cli.cli_core import (
    _enforce_function_timeout_cap as _enforce_function_timeout_cap,
)
lazy from inertia.cli.cli_core import (
    _ensure_runtime_architecture_guard_8616 as _ensure_runtime_architecture_guard_8616,
)
lazy from inertia.cli.cli_core import (
    _env_truthy_8616 as _env_truthy_8616,
)
lazy from inertia.cli.cli_core import (
    _exe_addr_none_batch_gate_8616 as _exe_addr_none_batch_gate_8616,
)
lazy from inertia.cli.cli_core import (
    _exe_unlabeled_batch_gate_8616 as _exe_unlabeled_batch_gate_8616,
)
lazy from inertia.cli.cli_core import (
    _expanded_exe_discovery_limit as _expanded_exe_discovery_limit,
)
lazy from inertia.cli.cli_core import (
    _extract_emitted_function_name_8616 as _extract_emitted_function_name_8616,
)
lazy from inertia.cli.cli_core import (
    _extract_function_body_text_8616 as _extract_function_body_text_8616,
)
lazy from inertia.cli.cli_core import (
    _extract_x86_16_tail_validation_snapshot as _extract_x86_16_tail_validation_snapshot,
)
lazy from inertia.cli.cli_core import (
    _finalization_timeout_floor_8616 as _finalization_timeout_floor_8616,
)
lazy from inertia.cli.cli_core import (
    _finalize_acceptance_lanes_8616 as _finalize_acceptance_lanes_8616,
)
lazy from inertia.cli.cli_core import (
    _finalize_work_result_8616 as _finalize_work_result_8616,
)
lazy from inertia.cli.cli_core import (
    _finish_batch_cli_8616 as _finish_batch_cli_8616,
)
lazy from inertia.cli.cli_core import (
    _fork_unavailable_reason as _fork_unavailable_reason,
)
lazy from inertia.cli.cli_core import (
    _format_asm_range as _format_asm_range,
)
lazy from inertia.cli.cli_core import (
    _format_first_block_asm as _format_first_block_asm,
)
lazy from inertia.cli.cli_core import (
    _format_sidecar_function_catalog as _format_sidecar_function_catalog,
)
lazy from inertia.cli.cli_core import (
    _format_tail_validation_diagnostic as _format_tail_validation_diagnostic,
)
lazy from inertia.cli.cli_core import (
    _fresh_primary_function_work_item_8616 as _fresh_primary_function_work_item_8616,
)
lazy from inertia.cli.cli_core import (
    _fresh_sidecar_retry_work_item_8616 as _fresh_sidecar_retry_work_item_8616,
)
lazy from inertia.cli.cli_core import (
    _function_attempt_display_status as _function_attempt_display_status,
)
lazy from inertia.cli.cli_core import (
    _function_binary_exact_region_8616 as _function_binary_exact_region_8616,
)
lazy from inertia.cli.cli_core import (
    _function_complexity as _function_complexity,
)
lazy from inertia.cli.cli_core import (
    _function_discovery_code_labels as _function_discovery_code_labels,
)
lazy from inertia.cli.cli_core import (
    _function_recovery_detail as _function_recovery_detail,
)
lazy from inertia.cli.cli_core import (
    _function_work_cache_lookup as _function_work_cache_lookup,
)
lazy from inertia.cli.cli_core import (
    _function_work_item_recovery_addr_8616 as _function_work_item_recovery_addr_8616,
)
lazy from inertia.cli.cli_core import (
    _function_work_result_for_fork_ipc as _function_work_result_for_fork_ipc,
)
lazy from inertia.cli.cli_core import (
    _FunctionCfgPair8616 as _FunctionCfgPair8616,
)
lazy from inertia.cli.cli_core import (
    _has_local_sidecar_evidence_8616 as _has_local_sidecar_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    _helper_model_tail_snapshot_8616 as _helper_model_tail_snapshot_8616,
)
lazy from inertia.cli.cli_core import (
    _helper_name as _helper_name,
)
lazy from inertia.cli.cli_core import (
    _hoist_c89_local_declarations_text as _hoist_c89_local_declarations_text,
)
lazy from inertia.cli.cli_core import (
    _hydrate_serial_clean_worker_evidence_8616 as _hydrate_serial_clean_worker_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    _import_scalar_interface_8616 as _import_scalar_interface_8616,
)
lazy from inertia.cli.cli_core import (
    _infer_linear_disassembly_window as _infer_linear_disassembly_window,
)
lazy from inertia.cli.cli_core import (
    _inherit_tail_validation_runtime_policy as _inherit_tail_validation_runtime_policy,
)
lazy from inertia.cli.cli_core import (
    _interesting_functions as _interesting_functions,
)
lazy from inertia.cli.cli_core import (
    _is_structured_codegen_node_8616 as _is_structured_codegen_node_8616,
)
lazy from inertia.cli.cli_core import (
    _isolated_project_lane_8616 as _isolated_project_lane_8616,
)
lazy from inertia.cli.cli_core import (
    _isolated_project_recovery_target_8616 as _isolated_project_recovery_target_8616,
)
lazy from inertia.cli.cli_core import (
    _iter_c_child_nodes_8616 as _iter_c_child_nodes_8616,
)
lazy from inertia.cli.cli_core import (
    _iter_c_nodes as _iter_c_nodes,
)
lazy from inertia.cli.cli_core import (
    _known_nonopt_fallback_8616 as _known_nonopt_fallback_8616,
)
lazy from inertia.cli.cli_core import (
    _library_ranked_task_gate_8616 as _library_ranked_task_gate_8616,
)
lazy from inertia.cli.cli_core import (
    _line_has_call_token_8616 as _line_has_call_token_8616,
)
lazy from inertia.cli.cli_core import (
    _linked_proc_addr_from_metadata_8616 as _linked_proc_addr_from_metadata_8616,
)
lazy from inertia.cli.cli_core import (
    _load_cache_json as _load_cache_json,
)
lazy from inertia.cli.cli_core import (
    _load_catalog_address_cache as _load_catalog_address_cache,
)
lazy from inertia.cli.cli_core import (
    _load_lst_metadata as _load_lst_metadata,
)
lazy from inertia.cli.cli_core import (
    _lookup_persistent_recovery_timeout as _lookup_persistent_recovery_timeout,
)
lazy from inertia.cli.cli_core import (
    _lower_process_priority as _lower_process_priority,
)
lazy from inertia.cli.cli_core import (
    _lst_code_label as _lst_code_label,
)
lazy from inertia.cli.cli_core import (
    _lst_code_region as _lst_code_region,
)
lazy from inertia.cli.cli_core import (
    _MainCliRun8616 as _MainCliRun8616,
)
lazy from inertia.cli.cli_core import (
    _MainProjectSetup8616 as _MainProjectSetup8616,
)
lazy from inertia.cli.cli_core import (
    _make_placeholder_function as _make_placeholder_function,
)
lazy from inertia.cli.cli_core import (
    _mark_tail_validation_failed_with_blocker_8616 as _mark_tail_validation_failed_with_blocker_8616,
)
lazy from inertia.cli.cli_core import (
    _materialize_missing_direct_call_prototypes_text as _materialize_missing_direct_call_prototypes_text,
)
lazy from inertia.cli.cli_core import (
    _materialize_missing_generic_local_declarations_text as _materialize_missing_generic_local_declarations_text,
)
lazy from inertia.cli.cli_core import (
    _materialize_missing_segment_macro_locals_text as _materialize_missing_segment_macro_locals_text,
)
lazy from inertia.cli.cli_core import (
    _materialize_missing_synthetic_global_declarations_text as _materialize_missing_synthetic_global_declarations_text,
)
lazy from inertia.cli.cli_core import (
    _materialize_opaque_pointer_typedefs_text as _materialize_opaque_pointer_typedefs_text,
)
lazy from inertia.cli.cli_core import (
    _materialize_stack_base_placeholder_declaration_text as _materialize_stack_base_placeholder_declaration_text,
)
lazy from inertia.cli.cli_core import (
    _maybe_return_known_helper_result_8616 as _maybe_return_known_helper_result_8616,
)
lazy from inertia.cli.cli_core import (
    _merged_or_rizin_offsets_8616 as _merged_or_rizin_offsets_8616,
)
lazy from inertia.cli.cli_core import (
    _non_optimized_slice_failure_detail as _non_optimized_slice_failure_detail,
)
lazy from inertia.cli.cli_core import (
    _non_optimized_slice_rendered as _non_optimized_slice_rendered,
)
lazy from inertia.cli.cli_core import (
    _non_probe_call_count_for_fallback_rank_8616 as _non_probe_call_count_for_fallback_rank_8616,
)
lazy from inertia.cli.cli_core import (
    _nonopt_slice_gate_8616 as _nonopt_slice_gate_8616,
)
lazy from inertia.cli.cli_core import (
    _normalize_accepted_payload_8616 as _normalize_accepted_payload_8616,
)
lazy from inertia.cli.cli_core import (
    _normalize_anonymous_call_targets as _normalize_anonymous_call_targets,
)
lazy from inertia.cli.cli_core import (
    _normalize_boolean_conditions as _normalize_boolean_conditions,
)
lazy from inertia.cli.cli_core import (
    _normalize_function_signature_arg_names as _normalize_function_signature_arg_names,
)
lazy from inertia.cli.cli_core import (
    _normalize_gcc_checked_payload_8616 as _normalize_gcc_checked_payload_8616,
)
lazy from inertia.cli.cli_core import (
    _normalize_scalar_gb_array_declarations_text as _normalize_scalar_gb_array_declarations_text,
)
lazy from inertia.cli.cli_core import (
    _normalize_seg_offset_void_pointer_args_text as _normalize_seg_offset_void_pointer_args_text,
)
lazy from inertia.cli.cli_core import (
    _normalize_unsupported_computed_goto_text as _normalize_unsupported_computed_goto_text,
)
lazy from inertia.cli.cli_core import (
    _ok_cached_function_result_tuple_8616 as _ok_cached_function_result_tuple_8616,
)
lazy from inertia.cli.cli_core import (
    _OkEmitOutcome8616 as _OkEmitOutcome8616,
)
lazy from inertia.cli.cli_core import (
    _ordered_call_names_from_text_8616 as _ordered_call_names_from_text_8616,
)
lazy from inertia.cli.cli_core import (
    _parse_env_timeout_cap as _parse_env_timeout_cap,
)
lazy from inertia.cli.cli_core import (
    _parse_int as _parse_int,
)
lazy from inertia.cli.cli_core import (
    _partial_result_report_8616 as _partial_result_report_8616,
)
lazy from inertia.cli.cli_core import (
    _PartialResultReport8616 as _PartialResultReport8616,
)
lazy from inertia.cli.cli_core import (
    _payload_needs_helper_retry_8616 as _payload_needs_helper_retry_8616,
)
lazy from inertia.cli.cli_core import (
    _pointer_param_names_8616 as _pointer_param_names_8616,
)
lazy from inertia.cli.cli_core import (
    _prefer_low_memory_path as _prefer_low_memory_path,
)
lazy from inertia.cli.cli_core import (
    _prepare_main_cli_args_8616 as _prepare_main_cli_args_8616,
)
lazy from inertia.cli.cli_core import (
    _prepare_main_project_8616 as _prepare_main_project_8616,
)
lazy from inertia.cli.cli_core import (
    _prepare_ranked_binary_preview_items as _prepare_ranked_binary_preview_items,
)
lazy from inertia.cli.cli_core import (
    _preserve_source_label_for_recovered_function_8616 as _preserve_source_label_for_recovered_function_8616,
)
lazy from inertia.cli.cli_core import (
    _print_asm_fallback_text as _print_asm_fallback_text,
)
lazy from inertia.cli.cli_core import (
    _print_diagnostic_text as _print_diagnostic_text,
)
lazy from inertia.cli.cli_core import (
    _print_function_attempt_status as _print_function_attempt_status,
)
lazy from inertia.cli.cli_core import (
    _print_rizin_fallback_diagnostics_8616 as _print_rizin_fallback_diagnostics_8616,
)
lazy from inertia.cli.cli_core import (
    _print_stop_on_first_failure_8616 as _print_stop_on_first_failure_8616,
)
lazy from inertia.cli.cli_core import (
    _proc_cod_image_lane_8616 as _proc_cod_image_lane_8616,
)
lazy from inertia.cli.cli_core import (
    _proc_linked_binary_lane_8616 as _proc_linked_binary_lane_8616,
)
lazy from inertia.cli.cli_core import (
    _prune_invalid_simple_function_prototypes_text as _prune_invalid_simple_function_prototypes_text,
)
lazy from inertia.cli.cli_core import (
    _prune_parameter_shadow_declarations_text as _prune_parameter_shadow_declarations_text,
)
lazy from inertia.cli.cli_core import (
    _prune_standalone_memory_helper_reads_text as _prune_standalone_memory_helper_reads_text,
)
lazy from inertia.cli.cli_core import (
    _prune_undefined_fragment_carrier_assignments_text as _prune_undefined_fragment_carrier_assignments_text,
)
lazy from inertia.cli.cli_core import (
    _prune_unused_local_declarations_text as _prune_unused_local_declarations_text,
)
lazy from inertia.cli.cli_core import (
    _prune_void_call_assignments_text as _prune_void_call_assignments_text,
)
lazy from inertia.cli.cli_core import (
    _rank_exe_function_seeds as _rank_exe_function_seeds,
)
lazy from inertia.cli.cli_core import (
    _rank_function_cfg_pairs_for_display as _rank_function_cfg_pairs_for_display,
)
lazy from inertia.cli.cli_core import (
    _rank_labeled_function_entries_cached as _rank_labeled_function_entries_cached,
)
lazy from inertia.cli.cli_core import (
    _read_serial_clean_worker_evidence_8616 as _read_serial_clean_worker_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    _read_serial_clean_worker_result_8616 as _read_serial_clean_worker_result_8616,
)
lazy from inertia.cli.cli_core import (
    _recompile_gate_fail_detail_8616 as _recompile_gate_fail_detail_8616,
)
lazy from inertia.cli.cli_core import (
    _record_retry_success_8616 as _record_retry_success_8616,
)
lazy from inertia.cli.cli_core import (
    _recover_binary_evidence_c_8616 as _recover_binary_evidence_c_8616,
)
lazy from inertia.cli.cli_core import (
    _recover_cached_function_pairs as _recover_cached_function_pairs,
)
lazy from inertia.cli.cli_core import (
    _recover_candidate_function_pair as _recover_candidate_function_pair,
)
lazy from inertia.cli.cli_core import (
    _recover_cfg as _recover_cfg,
)
lazy from inertia.cli.cli_core import (
    _recover_direct_addr_function as _recover_direct_addr_function,
)
lazy from inertia.cli.cli_core import (
    _recover_fast_exe_catalog as _recover_fast_exe_catalog,
)
lazy from inertia.cli.cli_core import (
    _recover_fast_seed_functions as _recover_fast_seed_functions,
)
lazy from inertia.cli.cli_core import (
    _recover_lst_function as _recover_lst_function,
)
lazy from inertia.cli.cli_core import (
    _recover_partial_cfg as _recover_partial_cfg,
)
lazy from inertia.cli.cli_core import (
    _recover_ranked_binary_function as _recover_ranked_binary_function,
)
lazy from inertia.cli.cli_core import (
    _recover_seeded_exe_functions as _recover_seeded_exe_functions,
)
lazy from inertia.cli.cli_core import (
    _recovered_evidence_acceptance_8616 as _recovered_evidence_acceptance_8616,
)
lazy from inertia.cli.cli_core import (
    _recovery_code_labels as _recovery_code_labels,
)
lazy from inertia.cli.cli_core import (
    _recovery_evidence_line as _recovery_evidence_line,
)
lazy from inertia.cli.cli_core import (
    _remember_fallback_tail_validation as _remember_fallback_tail_validation,
)
lazy from inertia.cli.cli_core import (
    _report_declared_call_consumptions_8616 as _report_declared_call_consumptions_8616,
)
lazy from inertia.cli.cli_core import (
    _resolve_cod_path_8616 as _resolve_cod_path_8616,
)
lazy from inertia.cli.cli_core import (
    _resolve_x86_16_function_start as _resolve_x86_16_function_start,
)
lazy from inertia.cli.cli_core import (
    _retain_emission_result_8616 as _retain_emission_result_8616,
)
lazy from inertia.cli.cli_core import (
    _retry_clean_process_fallback_8616 as _retry_clean_process_fallback_8616,
)
lazy from inertia.cli.cli_core import (
    _retry_function_tail_validation_snapshot_8616 as _retry_function_tail_validation_snapshot_8616,
)
lazy from inertia.cli.cli_core import (
    _retry_gate_allows_candidate_8616 as _retry_gate_allows_candidate_8616,
)
lazy from inertia.cli.cli_core import (
    _retry_timeout_for_failed_result_8616 as _retry_timeout_for_failed_result_8616,
)
lazy from inertia.cli.cli_core import (
    _retry_work_item_8616 as _retry_work_item_8616,
)
lazy from inertia.cli.cli_core import (
    _rizin_offsets_status_8616 as _rizin_offsets_status_8616,
)
lazy from inertia.cli.cli_core import (
    _run_canonicalized_direct_clean_worker_8616 as _run_canonicalized_direct_clean_worker_8616,
)
lazy from inertia.cli.cli_core import (
    _run_direct_addr_cli_8616 as _run_direct_addr_cli_8616,
)
lazy from inertia.cli.cli_core import (
    _run_function_work_item as _run_function_work_item,
)
lazy from inertia.cli.cli_core import (
    _run_function_work_item_uncached as _run_function_work_item_uncached,
)
lazy from inertia.cli.cli_core import (
    _run_local_work_8616 as _run_local_work_8616,
)
lazy from inertia.cli.cli_core import (
    _run_main_cli_8616 as _run_main_cli_8616,
)
lazy from inertia.cli.cli_core import (
    _run_nonopt_slice_lane_8616 as _run_nonopt_slice_lane_8616,
)
lazy from inertia.cli.cli_core import (
    _run_serial_batch_cli_8616 as _run_serial_batch_cli_8616,
)
lazy from inertia.cli.cli_core import (
    _run_serial_clean_process_work_item_8616 as _run_serial_clean_process_work_item_8616,
)
lazy from inertia.cli.cli_core import (
    _run_serial_function_8616 as _run_serial_function_8616,
)
lazy from inertia.cli.cli_core import (
    _run_with_timeout_in_daemon_thread as _run_with_timeout_in_daemon_thread,
)
lazy from inertia.cli.cli_core import (
    _run_with_timeout_in_fork as _run_with_timeout_in_fork,
)
lazy from inertia.cli.cli_core import (
    _safe_function_callsite_count_8616 as _safe_function_callsite_count_8616,
)
lazy from inertia.cli.cli_core import (
    _sanitize_direct_timeout_stage_token as _sanitize_direct_timeout_stage_token,
)
lazy from inertia.cli.cli_core import (
    _seeded_supplement_needed_8616 as _seeded_supplement_needed_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_clean_cache_hit_result_8616 as _serial_clean_cache_hit_result_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_clean_worker_command_8616 as _serial_clean_worker_command_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_clean_worker_debug_output_8616 as _serial_clean_worker_debug_output_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_clean_worker_failure_8616 as _serial_clean_worker_failure_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_clean_worker_outer_timeout_8616 as _serial_clean_worker_outer_timeout_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_clean_worker_window_8616 as _serial_clean_worker_window_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_decompile_active_item_8616 as _serial_decompile_active_item_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_emit_result_8616 as _serial_emit_result_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_local_recover_timeout_8616 as _serial_local_recover_timeout_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_missing_result_lane_8616 as _serial_missing_result_lane_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_no_cfg_error_outcome_8616 as _serial_no_cfg_error_outcome_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_post_result_8616 as _serial_post_result_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_recover_call_8616 as _serial_recover_call_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_recover_function_8616 as _serial_recover_function_8616,
)
lazy from inertia.cli.cli_core import (
    _serial_stub_rerank_and_item_8616 as _serial_stub_rerank_and_item_8616,
)
lazy from inertia.cli.cli_core import (
    _SerialFunctionOutcome8616 as _SerialFunctionOutcome8616,
)
lazy from inertia.cli.cli_core import (
    _set_tail_validation_runtime_enabled as _set_tail_validation_runtime_enabled,
)
lazy from inertia.cli.cli_core import (
    _sha256_text_8616 as _sha256_text_8616,
)
lazy from inertia.cli.cli_core import (
    _should_force_serial_supplemental_decompilation as _should_force_serial_supplemental_decompilation,
)
lazy from inertia.cli.cli_core import (
    _sidecar_slice_fallback_8616 as _sidecar_slice_fallback_8616,
)
lazy from inertia.cli.cli_core import (
    _signature_matched_code_addrs as _signature_matched_code_addrs,
)
lazy from inertia.cli.cli_core import (
    _source_region_catalog_evidence_8616 as _source_region_catalog_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    _stdout_is_interactive as _stdout_is_interactive,
)
lazy from inertia.cli.cli_core import (
    _store_cache_json as _store_cache_json,
)
lazy from inertia.cli.cli_core import (
    _store_catalog_address_cache as _store_catalog_address_cache,
)
lazy from inertia.cli.cli_core import (
    _store_direct_request_result_8616 as _store_direct_request_result_8616,
)
lazy from inertia.cli.cli_core import (
    _string_intrinsic_candidate_8616 as _string_intrinsic_candidate_8616,
)
lazy from inertia.cli.cli_core import (
    _strip_comment_blocks_8616 as _strip_comment_blocks_8616,
)
lazy from inertia.cli.cli_core import (
    _strip_register_fragment_suffixes_text as _strip_register_fragment_suffixes_text,
)
lazy from inertia.cli.cli_core import (
    _StructuredCNode8616 as _StructuredCNode8616,
)
lazy from inertia.cli.cli_core import (
    _supplement_cached_seeded_recovery as _supplement_cached_seeded_recovery,
)
lazy from inertia.cli.cli_core import (
    _supplement_function_cfg_pairs_with_ranked_preview as _supplement_function_cfg_pairs_with_ranked_preview,
)
lazy from inertia.cli.cli_core import (
    _supplement_function_cfg_pairs_with_seeded_recovery as _supplement_function_cfg_pairs_with_seeded_recovery,
)
lazy from inertia.cli.cli_core import (
    _supplement_functions_from_prologue_scan as _supplement_functions_from_prologue_scan,
)
lazy from inertia.cli.cli_core import (
    _SyntheticGlobals8616 as _SyntheticGlobals8616,
)
lazy from inertia.cli.cli_core import (
    _tail_snapshot_missing_stages_8616 as _tail_snapshot_missing_stages_8616,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_display_status as _tail_validation_display_status,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_enabled_for_run as _tail_validation_enabled_for_run,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_fallback_allows_project_snapshot as _tail_validation_fallback_allows_project_snapshot,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_passes_lenient as _tail_validation_passes_lenient,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_runtime_enabled as _tail_validation_runtime_enabled,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_snapshot_for_fallback as _tail_validation_snapshot_for_fallback,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_snapshot_for_function_run as _tail_validation_snapshot_for_function_run,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_snapshot_from_result_8616 as _tail_validation_snapshot_from_result_8616,
)
lazy from inertia.cli.cli_core import (
    _tail_validation_stage_detail_8616 as _tail_validation_stage_detail_8616,
)
lazy from inertia.cli.cli_core import (
    _temporary_clinic_policy_8616 as _temporary_clinic_policy_8616,
)
lazy from inertia.cli.cli_core import (
    _TimeoutDelayPrinter8616 as _TimeoutDelayPrinter8616,
)
lazy from inertia.cli.cli_core import (
    _timestamped_print as _timestamped_print,
)
lazy from inertia.cli.cli_core import (
    _timing_output_enabled as _timing_output_enabled,
)
lazy from inertia.cli.cli_core import (
    _toolchain_identity_fail_detail_8616 as _toolchain_identity_fail_detail_8616,
)
lazy from inertia.cli.cli_core import (
    _transfer_caller_return_use_evidence_8616 as _transfer_caller_return_use_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    _trivial_sidecar_fallback_8616 as _trivial_sidecar_fallback_8616,
)
lazy from inertia.cli.cli_core import (
    _try_decompile_non_optimized_known_function as _try_decompile_non_optimized_known_function,
)
lazy from inertia.cli.cli_core import (
    _try_decompile_non_optimized_slice as _try_decompile_non_optimized_slice,
)
lazy from inertia.cli.cli_core import (
    _try_decompile_sidecar_slice as _try_decompile_sidecar_slice,
)
lazy from inertia.cli.cli_core import (
    _try_emit_known_runtime_helper_c as _try_emit_known_runtime_helper_c,
)
lazy from inertia.cli.cli_core import (
    _try_emit_retry_recovered_candidate_8616 as _try_emit_retry_recovered_candidate_8616,
)
lazy from inertia.cli.cli_core import (
    _try_emit_string_intrinsic_c as _try_emit_string_intrinsic_c,
)
lazy from inertia.cli.cli_core import (
    _try_emit_trivial_sidecar_c as _try_emit_trivial_sidecar_c,
)
lazy from inertia.cli.cli_core import (
    _unreachable_calls_after_return_violation_8616 as _unreachable_calls_after_return_violation_8616,
)
lazy from inertia.cli.cli_core import (
    _validated_generated_c_acceptance_8616 as _validated_generated_c_acceptance_8616,
)
lazy from inertia.cli.cli_core import (
    _validation_fail_8616 as _validation_fail_8616,
)
lazy from inertia.cli.cli_core import (
    _validation_failed_retry_gate_8616 as _validation_failed_retry_gate_8616,
)
lazy from inertia.cli.cli_core import (
    _visible_code_labels as _visible_code_labels,
)
lazy from inertia.cli.cli_core import (
    _wants_rizin_8616 as _wants_rizin_8616,
)
lazy from inertia.cli.cli_core import (
    _with_scalar_interface_8616 as _with_scalar_interface_8616,
)
lazy from inertia.cli.cli_core import (
    _work_item_status_8616 as _work_item_status_8616,
)
lazy from inertia.cli.cli_core import (
    _worker_scalar_interface_8616 as _worker_scalar_interface_8616,
)
lazy from inertia.cli.cli_core import (
    _WorkRunCtx8616 as _WorkRunCtx8616,
)
lazy from inertia.cli.cli_core import (
    _write_final_function_result_8616 as _write_final_function_result_8616,
)
lazy from inertia.cli.cli_core import (
    _write_serial_clean_worker_evidence_8616 as _write_serial_clean_worker_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    _write_serial_clean_worker_result_8616 as _write_serial_clean_worker_result_8616,
)
lazy from inertia.cli.cli_core import (
    _x86_16_complexity_timeout_8616 as _x86_16_complexity_timeout_8616,
)
lazy from inertia.cli.cli_core import (
    admit_declared_external_call_files_8616 as admit_declared_external_call_files_8616,
)
lazy from inertia.cli.cli_core import (
    allows_heavy_fallbacks_for_run as allows_heavy_fallbacks_for_run,
)
lazy from inertia.cli.cli_core import (
    angr as angr,
)
lazy from inertia.cli.cli_core import (
    annotate_current_span as annotate_current_span,
)
lazy from inertia.cli.cli_core import (
    annotate_function as annotate_function,
)
lazy from inertia.cli.cli_core import (
    assess_decompiled_c_text as assess_decompiled_c_text,
)
lazy from inertia.cli.cli_core import (
    assess_final_generated_c_text as assess_final_generated_c_text,
)
lazy from inertia.cli.cli_core import (
    attach_direct_target_argument_evidence_context_8616 as attach_direct_target_argument_evidence_context_8616,
)
lazy from inertia.cli.cli_core import (
    attach_lst_metadata_to_project as attach_lst_metadata_to_project,
)
lazy from inertia.cli.cli_core import (
    attach_project_argument_evidence_ranges_8616 as attach_project_argument_evidence_ranges_8616,
)
lazy from inertia.cli.cli_core import (
    attach_scalar_interface_8616 as attach_scalar_interface_8616,
)
lazy from inertia.cli.cli_core import (
    attach_segment_program_layout_8616 as attach_segment_program_layout_8616,
)
lazy from inertia.cli.cli_core import (
    build_batch_c_output_8616 as build_batch_c_output_8616,
)
lazy from inertia.cli.cli_core import (
    build_cod_analysis_image_8616 as build_cod_analysis_image_8616,
)
lazy from inertia.cli.cli_core import (
    build_direct_request_cache_key_8616 as build_direct_request_cache_key_8616,
)
lazy from inertia.cli.cli_core import (
    build_failure_family_snapshot as build_failure_family_snapshot,
)
lazy from inertia.cli.cli_core import (
    build_parallel_clean_worker_timeout_model as build_parallel_clean_worker_timeout_model,
)
lazy from inertia.cli.cli_core import (
    caller_return_use_evidence_by_addr_8616 as caller_return_use_evidence_by_addr_8616,
)
lazy from inertia.cli.cli_core import (
    check_c_recompiles_8616 as check_c_recompiles_8616,
)
lazy from inertia.cli.cli_core import (
    clean_process_override_8616 as clean_process_override_8616,
)
lazy from inertia.cli.cli_core import (
    collect_neighbor_call_targets as collect_neighbor_call_targets,
)
lazy from inertia.cli.cli_core import (
    collect_rizin_evidence as collect_rizin_evidence,
)
lazy from inertia.cli.cli_core import (
    conditional_tail_snapshot_8616 as conditional_tail_snapshot_8616,
)
lazy from inertia.cli.cli_core import (
    configure_telemetry_from_env as configure_telemetry_from_env,
)
lazy from inertia.cli.cli_core import (
    copy as copy,
)
lazy from inertia.cli.cli_core import (
    dataclass as dataclass,
)
lazy from inertia.cli.cli_core import (
    declared_call_diagnostic_lines_8616 as declared_call_diagnostic_lines_8616,
)
lazy from inertia.cli.cli_core import (
    declared_call_receipts_current_8616 as declared_call_receipts_current_8616,
)
lazy from inertia.cli.cli_core import (
    declared_input_path_8616 as declared_input_path_8616,
)
lazy from inertia.cli.cli_core import (
    default_signature_catalog_path as default_signature_catalog_path,
)
lazy from inertia.cli.cli_core import (
    dependency_ordered_function_work_8616 as dependency_ordered_function_work_8616,
)
lazy from inertia.cli.cli_core import (
    describe_non_optimized_unavailable as describe_non_optimized_unavailable,
)
lazy from inertia.cli.cli_core import (
    direct_request_cache_enabled_8616 as direct_request_cache_enabled_8616,
)
lazy from inertia.cli.cli_core import (
    discover_declared_function_closure_8616 as discover_declared_function_closure_8616,
)
lazy from inertia.cli.cli_core import (
    discover_rizin_function_entries as discover_rizin_function_entries,
)
lazy from inertia.cli.cli_core import (
    emit_compact_summary as emit_compact_summary,
)
lazy from inertia.cli.cli_core import (
    emit_file_decompilation_summary as emit_file_decompilation_summary,
)
lazy from inertia.cli.cli_core import (
    emit_terminal_status as emit_terminal_status,
)
lazy from inertia.cli.cli_core import (
    extract_cod_function_entries as extract_cod_function_entries,
)
lazy from inertia.cli.cli_core import (
    extract_cod_proc_metadata as extract_cod_proc_metadata,
)
lazy from inertia.cli.cli_core import (
    extract_simple_cod_logic_entries as extract_simple_cod_logic_entries,
)
lazy from inertia.cli.cli_core import (
    extract_small_two_arg_cod_logic_entries as extract_small_two_arg_cod_logic_entries,
)
lazy from inertia.cli.cli_core import (
    field as field,
)
lazy from inertia.cli.cli_core import (
    filter_code_labels_for_library_policy as filter_code_labels_for_library_policy,
)
lazy from inertia.cli.cli_core import (
    function_decompilation_cache_key_8616 as function_decompilation_cache_key_8616,
)
lazy from inertia.cli.cli_core import (
    function_original_addr as function_original_addr,
)
lazy from inertia.cli.cli_core import (
    has_only_binary_signatures as has_only_binary_signatures,
)
lazy from inertia.cli.cli_core import (
    hashlib as hashlib,
)
lazy from inertia.cli.cli_core import (
    infer_cod_logic_start as infer_cod_logic_start,
)
lazy from inertia.cli.cli_core import (
    is_library_like_function_name as is_library_like_function_name,
)
lazy from inertia.cli.cli_core import (
    is_x86_16_stack_probe_name_8616 as is_x86_16_stack_probe_name_8616,
)
lazy from inertia.cli.cli_core import (
    json as json,
)
lazy from inertia.cli.cli_core import (
    load_binary_signature_metadata as load_binary_signature_metadata,
)
lazy from inertia.cli.cli_core import (
    load_direct_request_cache_8616 as load_direct_request_cache_8616,
)
lazy from inertia.cli.cli_core import (
    load_serial_worker_cache_8616 as load_serial_worker_cache_8616,
)
lazy from inertia.cli.cli_core import (
    logging as logging,
)
lazy from inertia.cli.cli_core import (
    main as main,
)
lazy from inertia.cli.cli_core import (
    mark_function_original_addr as mark_function_original_addr,
)
lazy from inertia.cli.cli_core import (
    metadata_has_precise_code_regions as metadata_has_precise_code_regions,
)
lazy from inertia.cli.cli_core import (
    normalize_unresolved_c_text as normalize_unresolved_c_text,
)
lazy from inertia.cli.cli_core import (
    parse_cli_arguments as parse_cli_arguments,
)
lazy from inertia.cli.cli_core import (
    prepare_direct_indexed_alias_program_context_8616 as prepare_direct_indexed_alias_program_context_8616,
)
lazy from inertia.cli.cli_core import (
    print as print,
)
lazy from inertia.cli.cli_core import (
    prioritize_clean_function_work_8616 as prioritize_clean_function_work_8616,
)
lazy from inertia.cli.cli_core import (
    publish_discovered_indexed_alias_program_8616 as publish_discovered_indexed_alias_program_8616,
)
lazy from inertia.cli.cli_core import (
    re as re,
)
lazy from inertia.cli.cli_core import (
    read_terminal_status as read_terminal_status,
)
lazy from inertia.cli.cli_core import (
    record_cod_module_caller_return_use_evidence_8616 as record_cod_module_caller_return_use_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    record_direct_target_caller_return_use_evidence_8616 as record_direct_target_caller_return_use_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    record_synthetic_call_stubs_8616 as record_synthetic_call_stubs_8616,
)
lazy from inertia.cli.cli_core import (
    recover_32bit_compare_c_8616 as recover_32bit_compare_c_8616,
)
lazy from inertia.cli.cli_core import (
    recover_counted_stack_loop_c_8616 as recover_counted_stack_loop_c_8616,
)
lazy from inertia.cli.cli_core import (
    relabel_generated_function_definition as relabel_generated_function_definition,
)
lazy from inertia.cli.cli_core import (
    render_c_runtime_header_8616 as render_c_runtime_header_8616,
)
lazy from inertia.cli.cli_core import (
    render_direct_request_tail_snapshot_diagnostic_8616 as render_direct_request_tail_snapshot_diagnostic_8616,
)
lazy from inertia.cli.cli_core import (
    replace as replace,
)
lazy from inertia.cli.cli_core import (
    requires_isolated_function_decompilation as requires_isolated_function_decompilation,
)
lazy from inertia.cli.cli_core import (
    retry_timeout_after_failed_attempt as retry_timeout_after_failed_attempt,
)
lazy from inertia.cli.cli_core import (
    run_captured_subprocess_tree as run_captured_subprocess_tree,
)
lazy from inertia.cli.cli_core import (
    scalar_interface_for_result_8616 as scalar_interface_for_result_8616,
)
lazy from inertia.cli.cli_core import (
    scalar_interface_from_record_8616 as scalar_interface_from_record_8616,
)
lazy from inertia.cli.cli_core import (
    segment_program_function_evidence_for_function_8616 as segment_program_function_evidence_for_function_8616,
)
lazy from inertia.cli.cli_core import (
    segment_program_function_evidence_from_record_8616 as segment_program_function_evidence_from_record_8616,
)
lazy from inertia.cli.cli_core import (
    segment_program_function_evidence_matches_item_8616 as segment_program_function_evidence_matches_item_8616,
)
lazy from inertia.cli.cli_core import (
    select_function_worker_policy_8616 as select_function_worker_policy_8616,
)
lazy from inertia.cli.cli_core import (
    serial_worker_cache_inputs_8616 as serial_worker_cache_inputs_8616,
)
lazy from inertia.cli.cli_core import (
    sidecar_verdict_closes_non_optimized_lane as sidecar_verdict_closes_non_optimized_lane,
)
lazy from inertia.cli.cli_core import (
    span as span,
)
lazy from inertia.cli.cli_core import (
    store_direct_request_cache_8616 as store_direct_request_cache_8616,
)
lazy from inertia.cli.cli_core import (
    store_serial_worker_cache_8616 as store_serial_worker_cache_8616,
)
lazy from inertia.cli.cli_core import (
    subprocess as subprocess,
)
lazy from inertia.cli.cli_core import (
    tempfile as tempfile,
)
lazy from inertia.cli.cli_core import (
    threading as threading,
)
lazy from inertia.cli.cli_core import (
    time as time,
)
lazy from inertia.cli.cli_core import (
    trace_function as trace_function,
)
lazy from inertia.cli.cli_core import (
    transfer_project_evidence_8616 as transfer_project_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    typing as typing,
)
lazy from inertia.cli.cli_core import (
    verify_function_work_result_payload_integrity_8616 as verify_function_work_result_payload_integrity_8616,
)
lazy from inertia.cli.cli_core import (
    wait as wait,
)
lazy from inertia.cli.cli_core import (
    with_segment_program_function_evidence_8616 as with_segment_program_function_evidence_8616,
)
lazy from inertia.cli.cli_core import (
    write_conditional_function_c_8616 as write_conditional_function_c_8616,
)
lazy from inertia.cli.cli_core import (
    write_generated_function_c as write_generated_function_c,
)
lazy from inertia.cli.cli_core import (
    write_generated_translation_unit_c as write_generated_translation_unit_c,
)
lazy from inertia.cli.cli_core import (
    x86_16_tail_validation_snapshot_passed as x86_16_tail_validation_snapshot_passed,
)
lazy from inertia.cli.cli_decompilation import (
    _CALL_EXPRESSION_NAME_RE_8616 as _CALL_EXPRESSION_NAME_RE_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _CALLSITE_DECL_NAME_RE_8616 as _CALLSITE_DECL_NAME_RE_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _CALLSITE_DEFN_NAME_RE_8616 as _CALLSITE_DEFN_NAME_RE_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _CALLSITE_NON_DECLARATION_PREFIXES_8616 as _CALLSITE_NON_DECLARATION_PREFIXES_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _IMPLICIT_STACK_PLACEHOLDER_RE_8616 as _IMPLICIT_STACK_PLACEHOLDER_RE_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _LAYER_DUMP_MUTEX as _LAYER_DUMP_MUTEX,
)
lazy from inertia.cli.cli_decompilation import (
    _LAYER_DUMP_STATE_ATTR as _LAYER_DUMP_STATE_ATTR,
)
lazy from inertia.cli.cli_decompilation import (
    _REPLACEMENT_RECOMPILE_CACHE_8616 as _REPLACEMENT_RECOMPILE_CACHE_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _REPLACEMENT_RECOMPILE_CACHE_LOCK_8616 as _REPLACEMENT_RECOMPILE_CACHE_LOCK_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _SEMANTIC_CODEGEN_HELPER_NAMES_8616 as _SEMANTIC_CODEGEN_HELPER_NAMES_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _STACK_PROBE_CALL_TARGET_CACHE_8616 as _STACK_PROBE_CALL_TARGET_CACHE_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _STACK_SLOT_DECL_RE_8616 as _STACK_SLOT_DECL_RE_8616,
)
lazy from inertia.cli.cli_decompilation import (
    DECOMPILATION_PREP_LOCK as DECOMPILATION_PREP_LOCK,
)
lazy from inertia.cli.cli_decompilation import (
    CallLossGuardedDceResult8616 as CallLossGuardedDceResult8616,
)
lazy from inertia.cli.cli_decompilation import (
    CallsitePrototypeSeedDecision8616 as CallsitePrototypeSeedDecision8616,
)
lazy from inertia.cli.cli_decompilation import (
    CliCallInventory8616 as CliCallInventory8616,
)
lazy from inertia.cli.cli_decompilation import (
    CodegenRenderAuthority8616 as CodegenRenderAuthority8616,
)
lazy from inertia.cli.cli_decompilation import (
    CompilerHelperEvidence8616 as CompilerHelperEvidence8616,
)
lazy from inertia.cli.cli_decompilation import (
    Counter as Counter,
)
lazy from inertia.cli.cli_decompilation import (
    DirectAddrStageBundleInput as DirectAddrStageBundleInput,
)
lazy from inertia.cli.cli_decompilation import (
    DirectStackMoveSourceKind8616 as DirectStackMoveSourceKind8616,
)
lazy from inertia.cli.cli_decompilation import (
    GlobalDeclarationArrayExtent8616 as GlobalDeclarationArrayExtent8616,
)
lazy from inertia.cli.cli_decompilation import (
    PickledCfuncSnapshot8616 as PickledCfuncSnapshot8616,
)
lazy from inertia.cli.cli_decompilation import (
    RenderRefreshPreservationDecision8616 as RenderRefreshPreservationDecision8616,
)
lazy from inertia.cli.cli_decompilation import (
    RenderRefreshPreservationEvidence8616 as RenderRefreshPreservationEvidence8616,
)
lazy from inertia.cli.cli_decompilation import (
    RenderRefreshSemanticReplayEvidence8616 as RenderRefreshSemanticReplayEvidence8616,
)
lazy from inertia.cli.cli_decompilation import (
    SegmentedGlobalLoadStats8616 as SegmentedGlobalLoadStats8616,
)
lazy from inertia.cli.cli_decompilation import (
    StrEnum as StrEnum,
)
lazy from inertia.cli.cli_decompilation import (
    TrustedCoreSnapshot8616 as TrustedCoreSnapshot8616,
)
lazy from inertia.cli.cli_decompilation import (
    TypedDict as TypedDict,
)
lazy from inertia.cli.cli_decompilation import (
    ValidatedPayloadReplacementDecision8616 as ValidatedPayloadReplacementDecision8616,
)
lazy from inertia.cli.cli_decompilation import (
    ValidatedPayloadReplacementEvidence8616 as ValidatedPayloadReplacementEvidence8616,
)
lazy from inertia.cli.cli_decompilation import (
    X86_16TailValidationSummary as X86_16TailValidationSummary,
)
lazy from inertia.cli.cli_decompilation import (
    _annotate_cod_proc_output as _annotate_cod_proc_output,
)
lazy from inertia.cli.cli_decompilation import (
    _apply_known_cod_object_annotations as _apply_known_cod_object_annotations,
)
lazy from inertia.cli.cli_decompilation import (
    _apply_known_helper_signatures as _apply_known_helper_signatures,
)
lazy from inertia.cli.cli_decompilation import (
    _apply_stub_returning_flags_8616 as _apply_stub_returning_flags_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _apply_validated_payload_replacement_8616 as _apply_validated_payload_replacement_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_access_trait_field_names as _attach_access_trait_field_names,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_cod_global_declaration_names as _attach_cod_global_declaration_names,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_cod_global_declaration_types as _attach_cod_global_declaration_types,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_cod_global_names as _attach_cod_global_names,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_cod_variable_names as _attach_cod_variable_names,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_dos_pseudo_callees as _attach_dos_pseudo_callees,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_interrupt_wrapper_callees as _attach_interrupt_wrapper_callees,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_lst_data_names as _attach_lst_data_names,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_pointer_member_names as _attach_pointer_member_names,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_project_context_to_function_8616 as _attach_project_context_to_function_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_register_names as _attach_register_names,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_segment_register_names as _attach_segment_register_names,
)
lazy from inertia.cli.cli_decompilation import (
    _attach_ss_stack_variables as _attach_ss_stack_variables,
)
lazy from inertia.cli.cli_decompilation import (
    _best_recovered_decls_8616 as _best_recovered_decls_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _bind_codegen_render_variable_types_8616 as _bind_codegen_render_variable_types_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _bind_unified_local_vars_8616 as _bind_unified_local_vars_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _bind_variables_in_use_8616 as _bind_variables_in_use_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _block_profile_for_addr_8616 as _block_profile_for_addr_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _c_ast_cycle_path_8616 as _c_ast_cycle_path_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _cached_block_profiles_8616 as _cached_block_profiles_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _cached_function_profile_8616 as _cached_function_profile_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _call_name_matches_target_evidence_8616 as _call_name_matches_target_evidence_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _call_node_is_proven_stack_probe_8616 as _call_node_is_proven_stack_probe_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _call_node_stack_probe_candidates_8616 as _call_node_stack_probe_candidates_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _call_semantics_retry_evidence_8616 as _call_semantics_retry_evidence_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _callee_names_equivalent_8616 as _callee_names_equivalent_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _callsite_addr_points_to_call_insn_8616 as _callsite_addr_points_to_call_insn_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _callsite_decl_score_8616 as _callsite_decl_score_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _callsite_declaration_match_8616 as _callsite_declaration_match_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _candidate_expected_global_names_8616 as _candidate_expected_global_names_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _candidate_is_filtered_8616 as _candidate_is_filtered_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _candidate_original_target_8616 as _candidate_original_target_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _canonicalize_stack_cvars as _canonicalize_stack_cvars,
)
lazy from inertia.cli.cli_decompilation import (
    _capstone_direct_target_8616 as _capstone_direct_target_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _choose_preferred_candidate_8616 as _choose_preferred_candidate_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _clear_codegen_render_refresh_8616 as _clear_codegen_render_refresh_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _coalesce_cod_word_global_loads as _coalesce_cod_word_global_loads,
)
lazy from inertia.cli.cli_decompilation import (
    _coalesce_cod_word_global_statements as _coalesce_cod_word_global_statements,
)
lazy from inertia.cli.cli_decompilation import (
    _coalesce_far_pointer_stack_expressions as _coalesce_far_pointer_stack_expressions,
)
lazy from inertia.cli.cli_decompilation import (
    _coalesce_linear_recurrence_statements as _coalesce_linear_recurrence_statements,
)
lazy from inertia.cli.cli_decompilation import (
    _coalesce_segmented_word_load_expressions as _coalesce_segmented_word_load_expressions,
)
lazy from inertia.cli.cli_decompilation import (
    _cod_signature_and_stack_alias_score_8616 as _cod_signature_and_stack_alias_score_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _cod_window_for_stage_bundle_8616 as _cod_window_for_stage_bundle_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _codegen_has_semantic_materialization_8616 as _codegen_has_semantic_materialization_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _codegen_requires_render_refresh_8616 as _codegen_requires_render_refresh_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _collapse_annotated_stack_aliases_text as _collapse_annotated_stack_aliases_text,
)
lazy from inertia.cli.cli_decompilation import (
    _collapse_duplicate_type_keywords_text as _collapse_duplicate_type_keywords_text,
)
lazy from inertia.cli.cli_decompilation import (
    _collect_access_traits as _collect_access_traits,
)
lazy from inertia.cli.cli_decompilation import (
    _collect_callsite_direct_calls_8616 as _collect_callsite_direct_calls_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _collect_direct_calls_8616 as _collect_direct_calls_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _collect_existing_decls_8616 as _collect_existing_decls_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _collect_render_refresh_tail_summary_8616 as _collect_render_refresh_tail_summary_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _commentless_c_text_8616 as _commentless_c_text_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _compiler_helper_name_at_addr_8616 as _compiler_helper_name_at_addr_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _compute_candidate_targets_8616 as _compute_candidate_targets_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _count_switch_case_segment_carriers_8616 as _count_switch_case_segment_carriers_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _create_or_update_direct_call_stub_8616 as _create_or_update_direct_call_stub_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _dead_code_elimination_8616 as _dead_code_elimination_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _dead_code_elimination_after_flag_prune_8616 as _dead_code_elimination_after_flag_prune_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _debug_dump_calls_8616 as _debug_dump_calls_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _debug_dump_rewrite_pass_lines_8616 as _debug_dump_rewrite_pass_lines_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _decompile_function as _decompile_function,
)
lazy from inertia.cli.cli_decompilation import (
    _DecompileRun8616 as _DecompileRun8616,
)
lazy from inertia.cli.cli_decompilation import (
    _dedupe_adjacent_prototype_lines as _dedupe_adjacent_prototype_lines,
)
lazy from inertia.cli.cli_decompilation import (
    _dedupe_codegen_variable_names_8616 as _dedupe_codegen_variable_names_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _dedupe_conflicting_extern_variable_declarations_text as _dedupe_conflicting_extern_variable_declarations_text,
)
lazy from inertia.cli.cli_decompilation import (
    _direct_call_stub_filter_regions as _direct_call_stub_filter_regions,
)
lazy from inertia.cli.cli_decompilation import (
    _direct_stack_materialization_evidence_offsets_8616 as _direct_stack_materialization_evidence_offsets_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _direct_stub_name_8616 as _direct_stub_name_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _elide_redundant_segment_pointer_dereferences as _elide_redundant_segment_pointer_dereferences,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_ast_replacement_stats_8616 as _emit_ast_replacement_stats_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_c_stage_trace as _emit_c_stage_trace,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_direct_addr_stage_bundle_8616 as _emit_direct_addr_stage_bundle_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_grouped_structuring_stats_8616 as _emit_grouped_structuring_stats_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_pre_codegen_seqnode_probe_stats_8616 as _emit_pre_codegen_seqnode_probe_stats_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_seqnode_replacement_stats_8616 as _emit_seqnode_replacement_stats_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_single_function_context_metric as _emit_single_function_context_metric,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_start_debug_8616 as _emit_start_debug_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_switch_graph_debug_8616 as _emit_switch_graph_debug_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_switch_lowering_status_stats_8616 as _emit_switch_lowering_status_stats_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_switch_safety_payload_8616 as _emit_switch_safety_payload_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emit_typed_edge_switch_replacement_safety_stats_8616 as _emit_typed_edge_switch_replacement_safety_stats_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _emitted_loop_count_8616 as _emitted_loop_count_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _evidence_recovery_has_better_source_abi_8616 as _evidence_recovery_has_better_source_abi_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _expected_call_arity_deficit_8616 as _expected_call_arity_deficit_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _expected_call_arity_score_8616 as _expected_call_arity_score_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _expected_call_presence_score_8616 as _expected_call_presence_score_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _expected_loop_count_from_cod_metadata_8616 as _expected_loop_count_from_cod_metadata_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _expected_loop_presence_score_8616 as _expected_loop_presence_score_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _extract_cod_metadata_for_function_8616 as _extract_cod_metadata_for_function_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _filter_recovered_decls_8616 as _filter_recovered_decls_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _final_c_unreachable_after_return_penalty_8616 as _final_c_unreachable_after_return_penalty_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _finalize_callsite_arguments_after_noncall_regen_8616 as _finalize_callsite_arguments_after_noncall_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _finalize_regenerated_noncall_ast_8616 as _finalize_regenerated_noncall_ast_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _finalize_typed_call_interfaces_before_render_8616 as _finalize_typed_call_interfaces_before_render_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _finalize_typed_interfaces_and_projections_before_render_8616 as _finalize_typed_interfaces_and_projections_before_render_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _first_function_header_parts_8616 as _first_function_header_parts_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _forced_corpus_templates_enabled as _forced_corpus_templates_enabled,
)
lazy from inertia.cli.cli_decompilation import (
    _forced_function_template as _forced_function_template,
)
lazy from inertia.cli.cli_decompilation import (
    _format_known_helper_calls as _format_known_helper_calls,
)
lazy from inertia.cli.cli_decompilation import (
    _format_minimal_codegen_output as _format_minimal_codegen_output,
)
lazy from inertia.cli.cli_decompilation import (
    _function_block_profile_cache_8616 as _function_block_profile_cache_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _function_decompilation_profile as _function_decompilation_profile,
)
lazy from inertia.cli.cli_decompilation import (
    _function_header_arg_count_8616 as _function_header_arg_count_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _function_name_at_addr_8616 as _function_name_at_addr_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _function_named_addr_8616 as _function_named_addr_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _get_layer_dump_state as _get_layer_dump_state,
)
lazy from inertia.cli.cli_decompilation import (
    _global_decl_insert_index_8616 as _global_decl_insert_index_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _global_declaration_coverage_score_8616 as _global_declaration_coverage_score_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _global_declaration_name_has_standalone_use_8616 as _global_declaration_name_has_standalone_use_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _global_extern_declarations_8616 as _global_extern_declarations_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_ail_narrowing as _guard_angr_ail_narrowing,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_analysis_hard_failure_passthrough as _guard_angr_analysis_hard_failure_passthrough,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_basepointeroffset_codegen_support as _guard_angr_basepointeroffset_codegen_support,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_clinic_stage_markers as _guard_angr_clinic_stage_markers,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_fast_post_ssa_8616 as _guard_angr_fast_post_ssa_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_peephole_expr_bitwidth_assertion as _guard_angr_peephole_expr_bitwidth_assertion,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_pre_codegen_seqnode_probe as _guard_angr_pre_codegen_seqnode_probe,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_structurer_codegen_timing as _guard_angr_structurer_codegen_timing,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_structuring_codegen_internal_timing as _guard_angr_structuring_codegen_internal_timing,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_structuring_seqnode_stage_probe as _guard_angr_structuring_seqnode_stage_probe,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_tail_validation_collection_timing as _guard_angr_tail_validation_collection_timing,
)
lazy from inertia.cli.cli_decompilation import (
    _guard_angr_variable_recovery_binop_sub_size_mismatch as _guard_angr_variable_recovery_binop_sub_size_mismatch,
)
lazy from inertia.cli.cli_decompilation import (
    _has_global_declaration_8616 as _has_global_declaration_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _has_synthetic_split_signature_args_8616 as _has_synthetic_split_signature_args_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _helper_overrides_generic_name_8616 as _helper_overrides_generic_name_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _implicit_placeholder_artifact_count_8616 as _implicit_placeholder_artifact_count_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _is_compiler_stack_probe_call_insn_8616 as _is_compiler_stack_probe_call_insn_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _is_compiler_stack_probe_call_target_8616 as _is_compiler_stack_probe_call_target_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _is_known_noreturn_name_8616 as _is_known_noreturn_name_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _is_stack_probe_name_8616 as _is_stack_probe_name_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _iter_c_nodes_deep as _iter_c_nodes_deep,
)
lazy from inertia.cli.cli_decompilation import (
    _iter_c_nodes_deep_8616 as _iter_c_nodes_deep_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _iter_capstone_direct_calls_8616 as _iter_capstone_direct_calls_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _iter_linear_region_direct_calls_8616 as _iter_linear_region_direct_calls_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _label_at_addr_8616 as _label_at_addr_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _latest_layer_dump_text_8616 as _latest_layer_dump_text_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _layer_dump_accepts_label as _layer_dump_accepts_label,
)
lazy from inertia.cli.cli_decompilation import (
    _layer_dump_enabled as _layer_dump_enabled,
)
lazy from inertia.cli.cli_decompilation import (
    _layer_dump_filter as _layer_dump_filter,
)
lazy from inertia.cli.cli_decompilation import (
    _layer_dump_root as _layer_dump_root,
)
lazy from inertia.cli.cli_decompilation import (
    _LayerDumpState as _LayerDumpState,
)
lazy from inertia.cli.cli_decompilation import (
    _LayerDumpStatus as _LayerDumpStatus,
)
lazy from inertia.cli.cli_decompilation import (
    _linear_region_code_8616 as _linear_region_code_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _lower_interrupt_wrapper_result_reads as _lower_interrupt_wrapper_result_reads,
)
lazy from inertia.cli.cli_decompilation import (
    _materialize_annotated_cod_declarations_text as _materialize_annotated_cod_declarations_text,
)
lazy from inertia.cli.cli_decompilation import (
    _materialize_codegen_global_externs_text_8616 as _materialize_codegen_global_externs_text_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _materialize_missing_g_hex_externs_text as _materialize_missing_g_hex_externs_text,
)
lazy from inertia.cli.cli_decompilation import (
    _materialize_missing_register_local_declarations as _materialize_missing_register_local_declarations,
)
lazy from inertia.cli.cli_decompilation import (
    _materialize_missing_stack_local_declarations as _materialize_missing_stack_local_declarations,
)
lazy from inertia.cli.cli_decompilation import (
    _materialize_missing_terminal_ax_return_8616 as _materialize_missing_terminal_ax_return_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _maybe_debug_callsite_returning_8616 as _maybe_debug_callsite_returning_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _maybe_debug_function_blocks_8616 as _maybe_debug_function_blocks_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _maybe_debug_function_graph_8616 as _maybe_debug_function_graph_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _maybe_normalize_function_8616 as _maybe_normalize_function_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _merge_direct_call_8616 as _merge_direct_call_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _merge_x86_16_annotations_8616 as _merge_x86_16_annotations_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _missing_expected_calls_from_cod_metadata_8616 as _missing_expected_calls_from_cod_metadata_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _non_probe_executable_call_count_8616 as _non_probe_executable_call_count_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_concat_zero_text as _normalize_concat_zero_text,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_integer_dereference_stores_text as _normalize_integer_dereference_stores_text,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_msc_signed_int_function_signature_text as _normalize_msc_signed_int_function_signature_text,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_portable_flat_main_signature_text as _normalize_portable_flat_main_signature_text,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_scalar_assigned_extern_arrays_text as _normalize_scalar_assigned_extern_arrays_text,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_scalar_byte_register_types as _normalize_scalar_byte_register_types,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_shift_add_precedence_in_assignments as _normalize_shift_add_precedence_in_assignments,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_signed_char_function_signature_text as _normalize_signed_char_function_signature_text,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_spurious_duplicate_local_suffixes as _normalize_spurious_duplicate_local_suffixes,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_stack_identifiers_before_render_8616 as _normalize_stack_identifiers_before_render_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_text_payload_8616 as _normalize_text_payload_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _normalize_unary_not_shift_precedence_text as _normalize_unary_not_shift_precedence_text,
)
lazy from inertia.cli.cli_decompilation import (
    _ordered_original_target_candidates_8616 as _ordered_original_target_candidates_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _original_callee_name_8616 as _original_callee_name_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _original_callee_name_for_target_8616 as _original_callee_name_for_target_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _parse_direct_call_target_8616 as _parse_direct_call_target_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _partial_timeout_payload_is_validated_8616 as _partial_timeout_payload_is_validated_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _pipeline_hard_error_context_8616 as _pipeline_hard_error_context_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _postprocess_regenerated_text_available_8616 as _postprocess_regenerated_text_available_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _prefer_cached_render_when_regen_empty_8616 as _prefer_cached_render_when_regen_empty_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _prefer_richer_cached_render_8616 as _prefer_richer_cached_render_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _preferred_decompiler_options as _preferred_decompiler_options,
)
lazy from inertia.cli.cli_decompilation import (
    _preferred_expr_collapse_depth as _preferred_expr_collapse_depth,
)
lazy from inertia.cli.cli_decompilation import (
    _prepare_function_for_decompilation as _prepare_function_for_decompilation,
)
lazy from inertia.cli.cli_decompilation import (
    _prepend_recovered_callsite_prototypes_8616 as _prepend_recovered_callsite_prototypes_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _preserve_source_label_for_same_addr_function_8616 as _preserve_source_label_for_same_addr_function_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _profile_call_counts_8616 as _profile_call_counts_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _profile_call_sites_8616 as _profile_call_sites_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _profile_int_8616 as _profile_int_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_dead_local_assignments as _prune_dead_local_assignments,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_dead_stack_base_assignments_text as _prune_dead_stack_base_assignments_text,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_existing_decl_lines_8616 as _prune_existing_decl_lines_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_non_lvalue_arithmetic_assignments as _prune_non_lvalue_arithmetic_assignments,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_tiny_wrapper_staging_locals as _prune_tiny_wrapper_staging_locals,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_trailing_generic_return_text as _prune_trailing_generic_return_text,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_unused_local_declarations as _prune_unused_local_declarations,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_unused_staging_assignments as _prune_unused_staging_assignments,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_unused_unnamed_memory_declarations as _prune_unused_unnamed_memory_declarations,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_void_function_return_values as _prune_void_function_return_values,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_void_function_return_values_text as _prune_void_function_return_values_text,
)
lazy from inertia.cli.cli_decompilation import (
    _prune_weaker_conflicting_prototypes_text as _prune_weaker_conflicting_prototypes_text,
)
lazy from inertia.cli.cli_decompilation import (
    _raw_asm_for_stage_bundle_8616 as _raw_asm_for_stage_bundle_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _record_direct_callsite_target_8616 as _record_direct_callsite_target_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _record_layer_dump as _record_layer_dump,
)
lazy from inertia.cli.cli_decompilation import (
    _recorded_block_complexity_8616 as _recorded_block_complexity_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _recover_canonical_for_loops_after_regen_8616 as _recover_canonical_for_loops_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _regenerate_codegen_text_safely as _regenerate_codegen_text_safely,
)
lazy from inertia.cli.cli_decompilation import (
    _regeneration_introduced_arg_local_split_8616 as _regeneration_introduced_arg_local_split_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _RegenRunCtx8616 as _RegenRunCtx8616,
)
lazy from inertia.cli.cli_decompilation import (
    _register_direct_call_target_function_stubs as _register_direct_call_target_function_stubs,
)
lazy from inertia.cli.cli_decompilation import (
    _rehydrate_missing_evidenced_calls_on_live_codegen_8616 as _rehydrate_missing_evidenced_calls_on_live_codegen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _render_candidate_score_8616 as _render_candidate_score_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _render_refresh_candidate_strictly_improves_quality_8616 as _render_refresh_candidate_strictly_improves_quality_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _render_refresh_lost_stack_writes_are_validated_materialization_8616 as _render_refresh_lost_stack_writes_are_validated_materialization_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _render_refresh_lost_stack_writes_have_direct_stack_evidence_8616 as _render_refresh_lost_stack_writes_have_direct_stack_evidence_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _render_refresh_preservation_evidence_8616 as _render_refresh_preservation_evidence_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _render_refresh_replay_preserves_live_out_8616 as _render_refresh_replay_preserves_live_out_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _render_text_usable_8616 as _render_text_usable_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _repair_missing_cnode_codegen_metadata_8616 as _repair_missing_cnode_codegen_metadata_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_bound_callsite_argument_consumer_8616 as _replay_bound_callsite_argument_consumer_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_call_return_selector_lowering_after_regen_8616 as _replay_call_return_selector_lowering_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_direct_stack_mov_after_regen_8616 as _replay_direct_stack_mov_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_direct_stack_semantics_after_regen_8616 as _replay_direct_stack_semantics_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_direct_stack_updates_after_regen_8616 as _replay_direct_stack_updates_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_final_codegen_projections_after_regen_8616 as _replay_final_codegen_projections_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_indexed_segmented_global_lowering_after_regen_8616 as _replay_indexed_segmented_global_lowering_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_named_segmented_global_lowering_after_regen_8616 as _replay_named_segmented_global_lowering_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_runtime_segment_lowering_after_regen_8616 as _replay_runtime_segment_lowering_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_seqnode_case_segments_8616 as _replay_seqnode_case_segments_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _replay_stack_address_lowering_after_regen_8616 as _replay_stack_address_lowering_after_regen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _reserved_8616_frame_slot_key as _reserved_8616_frame_slot_key,
)
lazy from inertia.cli.cli_decompilation import (
    _rewrite_known_helper_signature_text as _rewrite_known_helper_signature_text,
)
lazy from inertia.cli.cli_decompilation import (
    _rewrite_ss_stack_byte_offsets as _rewrite_ss_stack_byte_offsets,
)
lazy from inertia.cli.cli_decompilation import (
    _run_typed_widening_pass as _run_typed_widening_pass,
)
lazy from inertia.cli.cli_decompilation import (
    _safe_path_component as _safe_path_component,
)
lazy from inertia.cli.cli_decompilation import (
    _sanitize_mangled_autonames_text as _sanitize_mangled_autonames_text,
)
lazy from inertia.cli.cli_decompilation import (
    _seed_callsite_prototype_and_trace_8616 as _seed_callsite_prototype_and_trace_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _seed_direct_callee_prototype_from_original_project_8616 as _seed_direct_callee_prototype_from_original_project_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _select_evidence_recovered_c_8616 as _select_evidence_recovered_c_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _should_refuse_legacy_cli_rewrite_8616 as _should_refuse_legacy_cli_rewrite_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _sidecar_cod_metadata_for_function as _sidecar_cod_metadata_for_function,
)
lazy from inertia.cli.cli_decompilation import (
    _sidecar_enclosing_label_8616 as _sidecar_enclosing_label_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _simplify_basic_algebraic_identities as _simplify_basic_algebraic_identities,
)
lazy from inertia.cli.cli_decompilation import (
    _simplify_nested_mk_fp_calls as _simplify_nested_mk_fp_calls,
)
lazy from inertia.cli.cli_decompilation import (
    _simplify_structured_c_expressions as _simplify_structured_c_expressions,
)
lazy from inertia.cli.cli_decompilation import (
    _simplify_structured_expressions_8616 as _simplify_structured_expressions_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _simplify_x86_16_stack_byte_pointers as _simplify_x86_16_stack_byte_pointers,
)
lazy from inertia.cli.cli_decompilation import (
    _single_function_context_measuring_enabled as _single_function_context_measuring_enabled,
)
lazy from inertia.cli.cli_decompilation import (
    _snapshot_codegen_text as _snapshot_codegen_text,
)
lazy from inertia.cli.cli_decompilation import (
    _stabilize_regenerated_noncall_ast_8616 as _stabilize_regenerated_noncall_ast_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _stack_probe_target_evidence_8616 as _stack_probe_target_evidence_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _stack_slot_key_offset_8616 as _stack_slot_key_offset_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _stack_slot_write_effects_from_c_text_8616 as _stack_slot_write_effects_from_c_text_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _strip_global_decl_lines_8616 as _strip_global_decl_lines_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _stub_candidates_for_direct_call_8616 as _stub_candidates_for_direct_call_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _switch_call_name_8616 as _switch_call_name_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _switch_case_bodies_8616 as _switch_case_bodies_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _switch_constant_value_8616 as _switch_constant_value_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _switch_is_segment_register_expr_8616 as _switch_is_segment_register_expr_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _switch_node_has_unresolved_linear_segment_8616 as _switch_node_has_unresolved_linear_segment_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _switch_segment_carrier_signature_8616 as _switch_segment_carrier_signature_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _switch_strip_casts_8616 as _switch_strip_casts_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _sync_function_info_8616 as _sync_function_info_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _sync_function_name_8616 as _sync_function_name_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _sync_recovered_function_metadata_from_kb_8616 as _sync_recovered_function_metadata_from_kb_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _tail_validation_snapshot_complete_for_cli_rewrite_8616 as _tail_validation_snapshot_complete_for_cli_rewrite_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _tail_validation_snapshot_failed_for_cli_rewrite_8616 as _tail_validation_snapshot_failed_for_cli_rewrite_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _typed_switch_seqnode_case_segment_quality_8616 as _typed_switch_seqnode_case_segment_quality_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _under_recovered_call_heavy_codegen_8616 as _under_recovered_call_heavy_codegen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _validated_payload_cache_tail_validation_passed_8616 as _validated_payload_cache_tail_validation_passed_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _validated_payload_replacement_evidence_8616 as _validated_payload_replacement_evidence_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _validated_payload_replacement_recompiles_8616 as _validated_payload_replacement_recompiles_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _validated_replacement_gate_8616 as _validated_replacement_gate_8616,
)
lazy from inertia.cli.cli_decompilation import (
    _validated_rewrite_refusal_needs_render_refresh_8616 as _validated_rewrite_refusal_needs_render_refresh_8616,
)
lazy from inertia.cli.cli_decompilation import (
    active_status_flag_lift_context_8616 as active_status_flag_lift_context_8616,
)
lazy from inertia.cli.cli_decompilation import (
    active_structuring_function_8616 as active_structuring_function_8616,
)
lazy from inertia.cli.cli_decompilation import (
    advance_failure_family_state as advance_failure_family_state,
)
lazy from inertia.cli.cli_decompilation import (
    apply_runtime_segment_lowering_8616 as apply_runtime_segment_lowering_8616,
)
lazy from inertia.cli.cli_decompilation import (
    apply_x86_16_metadata_annotations as apply_x86_16_metadata_annotations,
)
lazy from inertia.cli.cli_decompilation import (
    apply_x86_16_segmented_memory_reasoning as apply_x86_16_segmented_memory_reasoning,
)
lazy from inertia.cli.cli_decompilation import (
    assert_exact_instruction_coverage_8616 as assert_exact_instruction_coverage_8616,
)
lazy from inertia.cli.cli_decompilation import (
    assert_final_c_quality_8616 as assert_final_c_quality_8616,
)
lazy from inertia.cli.cli_decompilation import (
    assert_pipeline_contracts_8616 as assert_pipeline_contracts_8616,
)
lazy from inertia.cli.cli_decompilation import (
    attach_cod_stack_alias_annotations_8616 as attach_cod_stack_alias_annotations_8616,
)
lazy from inertia.cli.cli_decompilation import (
    build_typed_stack_probe_return_facts_8616 as build_typed_stack_probe_return_facts_8616,
)
lazy from inertia.cli.cli_decompilation import (
    callsite_stack_probe_evidence_8616 as callsite_stack_probe_evidence_8616,
)
lazy from inertia.cli.cli_decompilation import (
    codegen_render_authority_8616 as codegen_render_authority_8616,
)
lazy from inertia.cli.cli_decompilation import (
    collect_exact_instruction_coverage_8616 as collect_exact_instruction_coverage_8616,
)
lazy from inertia.cli.cli_decompilation import (
    collect_x86_16_tail_validation_summary as collect_x86_16_tail_validation_summary,
)
lazy from inertia.cli.cli_decompilation import (
    compare_x86_16_tail_validation_summaries as compare_x86_16_tail_validation_summaries,
)
lazy from inertia.cli.cli_decompilation import (
    emit_msc51_diagnostic as emit_msc51_diagnostic,
)
lazy from inertia.cli.cli_decompilation import (
    enforce_x86_16_clinic_options_8616 as enforce_x86_16_clinic_options_8616,
)
lazy from inertia.cli.cli_decompilation import (
    final_c_has_unreachable_call_after_return_8616 as final_c_has_unreachable_call_after_return_8616,
)
lazy from inertia.cli.cli_decompilation import (
    finalize_late_ast_cleanup_8616 as finalize_late_ast_cleanup_8616,
)
lazy from inertia.cli.cli_decompilation import (
    finalize_post_switch_cleanup_after_seqnode_replacement_8616 as finalize_post_switch_cleanup_after_seqnode_replacement_8616,
)
lazy from inertia.cli.cli_decompilation import (
    finalize_seqnode_switch_replay_after_replacement_8616 as finalize_seqnode_switch_replay_after_replacement_8616,
)
lazy from inertia.cli.cli_decompilation import (
    finalize_shared_call_occurrences_8616 as finalize_shared_call_occurrences_8616,
)
lazy from inertia.cli.cli_decompilation import (
    finalize_typed_edge_switch_replacement_if_enabled_8616 as finalize_typed_edge_switch_replacement_if_enabled_8616,
)
lazy from inertia.cli.cli_decompilation import (
    format_stack_probe_fact_stats_8616 as format_stack_probe_fact_stats_8616,
)
lazy from inertia.cli.cli_decompilation import (
    function_knowledge_base_8616 as function_knowledge_base_8616,
)
lazy from inertia.cli.cli_decompilation import (
    get_codegen_sequence_attr as get_codegen_sequence_attr,
)
lazy from inertia.cli.cli_decompilation import (
    gp_runtime_replaced_declaration_names_8616 as gp_runtime_replaced_declaration_names_8616,
)
lazy from inertia.cli.cli_decompilation import (
    hook_x86_16_compiler_helper_at_8616 as hook_x86_16_compiler_helper_at_8616,
)
lazy from inertia.cli.cli_decompilation import (
    identify_x86_16_compiler_helper_at_8616 as identify_x86_16_compiler_helper_at_8616,
)
lazy from inertia.cli.cli_decompilation import (
    is_near_pointer_argument_helper_call_8616 as is_near_pointer_argument_helper_call_8616,
)
lazy from inertia.cli.cli_decompilation import (
    is_x86_16_stack_probe_evidence_kind_8616 as is_x86_16_stack_probe_evidence_kind_8616,
)
lazy from inertia.cli.cli_decompilation import (
    known_cod_object_spec as known_cod_object_spec,
)
lazy from inertia.cli.cli_decompilation import (
    lower_stable_ss_linear_stack_dereferences_8616 as lower_stable_ss_linear_stack_dereferences_8616,
)
lazy from inertia.cli.cli_decompilation import (
    lower_stack_accesses_from_alias_facts_8616 as lower_stack_accesses_from_alias_facts_8616,
)
lazy from inertia.cli.cli_decompilation import (
    materialize_callsite_prototype_declarations_8616 as materialize_callsite_prototype_declarations_8616,
)
lazy from inertia.cli.cli_decompilation import (
    materialize_compare_register_global_carriers_8616 as materialize_compare_register_global_carriers_8616,
)
lazy from inertia.cli.cli_decompilation import (
    materialize_direct_global_symbol_stores_8616 as materialize_direct_global_symbol_stores_8616,
)
lazy from inertia.cli.cli_decompilation import (
    materialize_direct_stack_mov_instructions_8616 as materialize_direct_stack_mov_instructions_8616,
)
lazy from inertia.cli.cli_decompilation import (
    materialize_function_pointer_parameters_8616 as materialize_function_pointer_parameters_8616,
)
lazy from inertia.cli.cli_decompilation import (
    materialize_indexed_segmented_global_loads_8616 as materialize_indexed_segmented_global_loads_8616,
)
lazy from inertia.cli.cli_decompilation import (
    materialize_named_segmented_global_loads_8616 as materialize_named_segmented_global_loads_8616,
)
lazy from inertia.cli.cli_decompilation import (
    materialize_terminal_register_return_type_8616 as materialize_terminal_register_return_type_8616,
)
lazy from inertia.cli.cli_decompilation import (
    native_import_request_8616 as native_import_request_8616,
)
lazy from inertia.cli.cli_decompilation import (
    normalize_callee_name_8616 as normalize_callee_name_8616,
)
lazy from inertia.cli.cli_decompilation import (
    pickled_trusted_cfunc_8616 as pickled_trusted_cfunc_8616,
)
lazy from inertia.cli.cli_decompilation import (
    project_gp_runtime_declarations_8616 as project_gp_runtime_declarations_8616,
)
lazy from inertia.cli.cli_decompilation import (
    prune_redundant_loop_break_carriers_after_lowering_8616 as prune_redundant_loop_break_carriers_after_lowering_8616,
)
lazy from inertia.cli.cli_decompilation import (
    reapply_proven_named_global_aggregate_types_8616 as reapply_proven_named_global_aggregate_types_8616,
)
lazy from inertia.cli.cli_decompilation import (
    reapply_proven_stack_aggregate_field_projections_8616 as reapply_proven_stack_aggregate_field_projections_8616,
)
lazy from inertia.cli.cli_decompilation import (
    reapply_proven_stack_aggregate_types_8616 as reapply_proven_stack_aggregate_types_8616,
)
lazy from inertia.cli.cli_decompilation import (
    reapply_stack_aggregate_object_facts_8616 as reapply_stack_aggregate_object_facts_8616,
)
lazy from inertia.cli.cli_decompilation import (
    reconcile_exact_stack_argument_prototype_8616 as reconcile_exact_stack_argument_prototype_8616,
)
lazy from inertia.cli.cli_decompilation import (
    reconcile_registered_named_global_aggregate_declarations_8616 as reconcile_registered_named_global_aggregate_declarations_8616,
)
lazy from inertia.cli.cli_decompilation import (
    record_failure_family_retry_stop as record_failure_family_retry_stop,
)
lazy from inertia.cli.cli_decompilation import (
    record_typed_edge_switch_replacement_diagnostics_8616 as record_typed_edge_switch_replacement_diagnostics_8616,
)
lazy from inertia.cli.cli_decompilation import (
    recover_structuring_canonical_for_loops_8616 as recover_structuring_canonical_for_loops_8616,
)
lazy from inertia.cli.cli_decompilation import (
    refresh_x86_16_final_semantic_validation_8616 as refresh_x86_16_final_semantic_validation_8616,
)
lazy from inertia.cli.cli_decompilation import (
    remember_failure_family_candidate as remember_failure_family_candidate,
)
lazy from inertia.cli.cli_decompilation import (
    repair_cfunctioncall_render_targets_8616 as repair_cfunctioncall_render_targets_8616,
)
lazy from inertia.cli.cli_decompilation import (
    repair_empty_counted_loop_body_from_evidence_8616 as repair_empty_counted_loop_body_from_evidence_8616,
)
lazy from inertia.cli.cli_decompilation import (
    replay_callsite_stack_arguments_after_regeneration_8616 as replay_callsite_stack_arguments_after_regeneration_8616,
)
lazy from inertia.cli.cli_decompilation import (
    replay_codegen_structured_condition_segment_provenance_8616 as replay_codegen_structured_condition_segment_provenance_8616,
)
lazy from inertia.cli.cli_decompilation import (
    require_codegen_render_integrity_8616 as require_codegen_render_integrity_8616,
)
lazy from inertia.cli.cli_decompilation import (
    rollback_final_semantic_drift_8616 as rollback_final_semantic_drift_8616,
)
lazy from inertia.cli.cli_decompilation import (
    run_callsite_stack_fact_materialization_8616 as run_callsite_stack_fact_materialization_8616,
)
lazy from inertia.cli.cli_decompilation import (
    run_direct_instruction_materialization_8616 as run_direct_instruction_materialization_8616,
)
lazy from inertia.cli.cli_decompilation import (
    run_segment_global_materialization_8616 as run_segment_global_materialization_8616,
)
lazy from inertia.cli.cli_decompilation import (
    run_stack_lowering_pass_8616 as run_stack_lowering_pass_8616,
)
lazy from inertia.cli.cli_decompilation import (
    runtime_segment_name_for_variable_8616 as runtime_segment_name_for_variable_8616,
)
lazy from inertia.cli.cli_decompilation import (
    sanitize_direct_call_sites_8616 as sanitize_direct_call_sites_8616,
)
lazy from inertia.cli.cli_decompilation import (
    seed_physical_callsite_prototype_8616 as seed_physical_callsite_prototype_8616,
)
lazy from inertia.cli.cli_decompilation import (
    seed_wide_stack_prototype_from_binary_address_8616 as seed_wide_stack_prototype_from_binary_address_8616,
)
lazy from inertia.cli.cli_decompilation import (
    seqnode_switch_replacement_changed_for_codegen_8616 as seqnode_switch_replacement_changed_for_codegen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    snapshot_stack_local_candidates_8616 as snapshot_stack_local_candidates_8616,
)
lazy from inertia.cli.cli_decompilation import (
    snapshot_trusted_cfunc_8616 as snapshot_trusted_cfunc_8616,
)
lazy from inertia.cli.cli_decompilation import (
    traceback as traceback,
)
lazy from inertia.cli.cli_decompilation import (
    transfer_semantic_alias_facts_to_codegen_8616 as transfer_semantic_alias_facts_to_codegen_8616,
)
lazy from inertia.cli.cli_decompilation import (
    unpickle_trusted_cfunc_8616 as unpickle_trusted_cfunc_8616,
)
lazy from inertia.cli.cli_decompilation import (
    weakref as weakref,
)
lazy from inertia.cli.cli_decompilation import (
    write_direct_addr_stage_bundle as write_direct_addr_stage_bundle,
)
lazy from inertia.cli.cli_decompilation import (
    x86_16_tail_validation_result_passed as x86_16_tail_validation_result_passed,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _RUNTIME_HELPER_ENTRIES_8616 as _RUNTIME_HELPER_ENTRIES_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _RUNTIME_HELPER_TAIL2_8616 as _RUNTIME_HELPER_TAIL2_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _RUNTIME_HELPER_TAIL_8616 as _RUNTIME_HELPER_TAIL_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _SIDECAR_SLICE_DECOMPILE_TIMEOUT_CAP_8616 as _SIDECAR_SLICE_DECOMPILE_TIMEOUT_CAP_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _SIDECAR_SLICE_MAX_INSTRUCTION_BYTES_8616 as _SIDECAR_SLICE_MAX_INSTRUCTION_BYTES_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _SIDECAR_SLICE_RUNNER_TIMEOUT_CAP_8616 as _SIDECAR_SLICE_RUNNER_TIMEOUT_CAP_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    BoundedSliceVerdict as BoundedSliceVerdict,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    Protocol as Protocol,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    SliceRecoverCallable as SliceRecoverCallable,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    SliceRecoveryAttemptTrace as SliceRecoveryAttemptTrace,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _call_decompile_function_with_stats as _call_decompile_function_with_stats,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _cli_string_timeout_fallback as _cli_string_timeout_fallback,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _DecompileFunctionWithStats as _DecompileFunctionWithStats,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _is_blob_only_input as _is_blob_only_input,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _mark_helper_fallback_tail_validation_passed as _mark_helper_fallback_tail_validation_passed,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _NonOptimizedSliceFallback8616 as _NonOptimizedSliceFallback8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _runtime_helper_match_8616 as _runtime_helper_match_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _RuntimeHelperEmitter8616 as _RuntimeHelperEmitter8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _RuntimeHelperTail2_8616 as _RuntimeHelperTail2_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _RuntimeHelperTail8616 as _RuntimeHelperTail8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _SidecarCfgBlockBoundary8616 as _SidecarCfgBlockBoundary8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _SidecarCfgCapstoneBoundary8616 as _SidecarCfgCapstoneBoundary8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _SidecarCfgInstructionBoundary8616 as _SidecarCfgInstructionBoundary8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _SidecarFunctionBoundary8616 as _SidecarFunctionBoundary8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _SidecarSliceFallback8616 as _SidecarSliceFallback8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _try_emit_known_runtime_helper_c_tail2_8616 as _try_emit_known_runtime_helper_c_tail2_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    _try_emit_known_runtime_helper_c_tail_8616 as _try_emit_known_runtime_helper_c_tail_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    bounded_non_optimized_attempt_timeout as bounded_non_optimized_attempt_timeout,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    build_default_slice_recovery_attempts as build_default_slice_recovery_attempts,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    collect_bounded_linear_instruction_inventory_8616 as collect_bounded_linear_instruction_inventory_8616,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    functools as functools,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    logger as logger,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    non_optimized_slice_codegen_policy as non_optimized_slice_codegen_policy,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    run_bounded_slice_recovery as run_bounded_slice_recovery,
)
lazy from inertia.cli.cli_fallback_decompilation import (
    runtime_checkable as runtime_checkable,
)
lazy from inertia.cli.cli_function_discovery import (
    _BINARY_EXACT_REGION_INFO_KEY_8616 as _BINARY_EXACT_REGION_INFO_KEY_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _DEFAULT_PICK_FUNCTION_LEAN as _DEFAULT_PICK_FUNCTION_LEAN,
)
lazy from inertia.cli.cli_function_discovery import (
    _DISPLAY_CATALOG_CACHE_POLICY_SCHEMA_8616 as _DISPLAY_CATALOG_CACHE_POLICY_SCHEMA_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _PROVEN_CALL_RECEIPT_INFO_KEY_8616 as _PROVEN_CALL_RECEIPT_INFO_KEY_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _SEED_PRIORITY_RULES_8616 as _SEED_PRIORITY_RULES_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    DEFAULT_CATALOG_TIMEOUT as DEFAULT_CATALOG_TIMEOUT,
)
lazy from inertia.cli.cli_function_discovery import (
    DOS_SERVICE_BASE_ADDR as DOS_SERVICE_BASE_ADDR,
)
lazy from inertia.cli.cli_function_discovery import (
    CallerReturnUseVerdict8616 as CallerReturnUseVerdict8616,
)
lazy from inertia.cli.cli_function_discovery import (
    Literal as Literal,
)
lazy from inertia.cli.cli_function_discovery import (
    MutableMapping as MutableMapping,
)
lazy from inertia.cli.cli_function_discovery import (
    ProvenCallExtensionReceipt8616 as ProvenCallExtensionReceipt8616,
)
lazy from inertia.cli.cli_function_discovery import (
    RecoveryCacheSourceScope8616 as RecoveryCacheSourceScope8616,
)
lazy from inertia.cli.cli_function_discovery import (
    Self as Self,
)
lazy from inertia.cli.cli_function_discovery import (
    SourceRegionCatalogEvidence8616 as SourceRegionCatalogEvidence8616,
)
lazy from inertia.cli.cli_function_discovery import (
    X86ExactSlicePlan as X86ExactSlicePlan,
)
lazy from inertia.cli.cli_function_discovery import (
    _addr_in_ranges as _addr_in_ranges,
)
lazy from inertia.cli.cli_function_discovery import (
    _adjust_region_past_padding_8616 as _adjust_region_past_padding_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _adjust_region_to_inner_prologue_8616 as _adjust_region_to_inner_prologue_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _analysis_timeout as _analysis_timeout,
)
lazy from inertia.cli.cli_function_discovery import (
    _AngrBlock as _AngrBlock,
)
lazy from inertia.cli.cli_function_discovery import (
    _AngrCfg as _AngrCfg,
)
lazy from inertia.cli.cli_function_discovery import (
    _AngrObject as _AngrObject,
)
lazy from inertia.cli.cli_function_discovery import (
    _attach_proven_call_receipt_8616 as _attach_proven_call_receipt_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _best_region_function_candidate as _best_region_function_candidate,
)
lazy from inertia.cli.cli_function_discovery import (
    _binary_padding_entry_aliases_8616 as _binary_padding_entry_aliases_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _block_overlap_count_8616 as _block_overlap_count_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _block_ranges_for_overlap_8616 as _block_ranges_for_overlap_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _block_unique_covered_bytes_8616 as _block_unique_covered_bytes_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _build_rebased_slice_project_8616 as _build_rebased_slice_project_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _bytes_uniform_8616 as _bytes_uniform_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _cache_key_object as _cache_key_object,
)
lazy from inertia.cli.cli_function_discovery import (
    _caller_target_aliases_for_lst_function_8616 as _caller_target_aliases_for_lst_function_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _candidate_recovery_cache_key as _candidate_recovery_cache_key,
)
lazy from inertia.cli.cli_function_discovery import (
    _candidate_recovery_regions as _candidate_recovery_regions,
)
lazy from inertia.cli.cli_function_discovery import (
    _CandidateRecoveryCacheValue as _CandidateRecoveryCacheValue,
)
lazy from inertia.cli.cli_function_discovery import (
    _CandidateRecoveryCtx8616 as _CandidateRecoveryCtx8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _cap_stitched_blocks_to_leaders_8616 as _cap_stitched_blocks_to_leaders_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _clip_repair_blocks_at_leaders_8616 as _clip_repair_blocks_at_leaders_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _collect_block_8616 as _collect_block_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _collect_caller_return_use_for_entry_aliases_8616 as _collect_caller_return_use_for_entry_aliases_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _collect_direct_callee_return_use_evidence_8616 as _collect_direct_callee_return_use_evidence_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _collect_neighbor_targets_for_seed_ranking as _collect_neighbor_targets_for_seed_ranking,
)
lazy from inertia.cli.cli_function_discovery import (
    _collect_ranked_seed_state_8616 as _collect_ranked_seed_state_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _collect_stitched_blocks_and_edges_8616 as _collect_stitched_blocks_and_edges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _collect_supplement_pairs_8616 as _collect_supplement_pairs_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _collect_terminal_next_targets_8616 as _collect_terminal_next_targets_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _commit_exact_region_function_to_kb_8616 as _commit_exact_region_function_to_kb_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _commit_region_to_manager_8616 as _commit_region_to_manager_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _compute_gap_ranges_8616 as _compute_gap_ranges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _consider_metadata_and_tracer_seeds_8616 as _consider_metadata_and_tracer_seeds_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _consider_tracer_targets_8616 as _consider_tracer_targets_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _count_region_local_functions as _count_region_local_functions,
)
lazy from inertia.cli.cli_function_discovery import (
    _debug_graph_repair_finish_8616 as _debug_graph_repair_finish_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _derive_lst_exact_region_8616 as _derive_lst_exact_region_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _direct_addr_candidate_8616 as _direct_addr_candidate_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _direct_addr_fallback_8616 as _direct_addr_fallback_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _direct_recovery_inventory_count as _direct_recovery_inventory_count,
)
lazy from inertia.cli.cli_function_discovery import (
    _discover_graph_repair_region_8616 as _discover_graph_repair_region_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _display_catalog_cache_policy_8616 as _display_catalog_cache_policy_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _DisplayRankState8616 as _DisplayRankState8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _dynamic_attr as _dynamic_attr,
)
lazy from inertia.cli.cli_function_discovery import (
    _ensure_repair_block_node_8616 as _ensure_repair_block_node_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _entry_linear_caller_range_8616 as _entry_linear_caller_range_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _entry_window_seed_targets as _entry_window_seed_targets,
)
lazy from inertia.cli.cli_function_discovery import (
    _env_flag_enabled_8616 as _env_flag_enabled_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _escalate_truncated_lst_pair_8616 as _escalate_truncated_lst_pair_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _exact_region_recovery_looks_truncated as _exact_region_recovery_looks_truncated,
)
lazy from inertia.cli.cli_function_discovery import (
    _exe_seed_context_8616 as _exe_seed_context_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _ExeSeedCtx8616 as _ExeSeedCtx8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _extend_and_validate_exact_region_8616 as _extend_and_validate_exact_region_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _extend_candidate_pair_for_proven_calls_8616 as _extend_candidate_pair_for_proven_calls_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _extend_cfg_86_16_8616 as _extend_cfg_86_16_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _extended_terminator_region_8616 as _extended_terminator_region_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _fallback_entry_function as _fallback_entry_function,
)
lazy from inertia.cli.cli_function_discovery import (
    _filter_noncode_labeled_entries as _filter_noncode_labeled_entries,
)
lazy from inertia.cli.cli_function_discovery import (
    _final_seed_priority_8616 as _final_seed_priority_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _final_seed_priority_decision_8616 as _final_seed_priority_decision_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _finalize_candidate_pair_8616 as _finalize_candidate_pair_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _finalize_seeded_recovery_8616 as _finalize_seeded_recovery_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _function_block_overlap_count_8616 as _function_block_overlap_count_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _function_cfg_pair_object as _function_cfg_pair_object,
)
lazy from inertia.cli.cli_function_discovery import (
    _function_complexity_local as _function_complexity_local,
)
lazy from inertia.cli.cli_function_discovery import (
    _function_covered_ranges as _function_covered_ranges,
)
lazy from inertia.cli.cli_function_discovery import (
    _function_recovery_score as _function_recovery_score,
)
lazy from inertia.cli.cli_function_discovery import (
    _function_recovery_truncated as _function_recovery_truncated,
)
lazy from inertia.cli.cli_function_discovery import (
    _function_skip_reason as _function_skip_reason,
)
lazy from inertia.cli.cli_function_discovery import (
    _FunctionCfgPair as _FunctionCfgPair,
)
lazy from inertia.cli.cli_function_discovery import (
    _graph_repair_block_addrs_8616 as _graph_repair_block_addrs_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _graph_repair_entry_addr_8616 as _graph_repair_entry_addr_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _graph_repair_scan_bounds_8616 as _graph_repair_scan_bounds_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _GraphRepairDiscovery8616 as _GraphRepairDiscovery8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _GraphRepairScanBounds8616 as _GraphRepairScanBounds8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _infer_x86_16_linear_region as _infer_x86_16_linear_region,
)
lazy from inertia.cli.cli_function_discovery import (
    _inject_prologue_seed_targets_8616 as _inject_prologue_seed_targets_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _install_repair_edges_8616 as _install_repair_edges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _install_repair_return_sites_8616 as _install_repair_return_sites_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _is_library_seed_8616 as _is_library_seed_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _is_plausible_code_seed as _is_plausible_code_seed,
)
lazy from inertia.cli.cli_function_discovery import (
    _is_return_mnemonic_8616 as _is_return_mnemonic_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _is_zero_filled_region as _is_zero_filled_region,
)
lazy from inertia.cli.cli_function_discovery import (
    _labeled_entry_bucket_8616 as _labeled_entry_bucket_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _labeled_entry_bucket_early_8616 as _labeled_entry_bucket_early_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _linear_function_seed_targets as _linear_function_seed_targets,
)
lazy from inertia.cli.cli_function_discovery import (
    _linear_seed_target_8616 as _linear_seed_target_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _load_main_object_code_8616 as _load_main_object_code_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _load_seed_ranking_cache as _load_seed_ranking_cache,
)
lazy from inertia.cli.cli_function_discovery import (
    _load_seeded_recovery_from_cache as _load_seeded_recovery_from_cache,
)
lazy from inertia.cli.cli_function_discovery import (
    _looks_like_86_16_frame_prologue_8616 as _looks_like_86_16_frame_prologue_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _looks_like_x86_16_entry_byte as _looks_like_x86_16_entry_byte,
)
lazy from inertia.cli.cli_function_discovery import (
    _looks_like_x86_16_function_prologue as _looks_like_x86_16_function_prologue,
)
lazy from inertia.cli.cli_function_discovery import (
    _lookup_candidate_recovery_cache as _lookup_candidate_recovery_cache,
)
lazy from inertia.cli.cli_function_discovery import (
    _lst_recovery_regions_8616 as _lst_recovery_regions_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _lst_region_by_label_name_8616 as _lst_region_by_label_name_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _mark_function_binary_exact_region_8616 as _mark_function_binary_exact_region_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _mark_function_recovery_truncated as _mark_function_recovery_truncated,
)
lazy from inertia.cli.cli_function_discovery import (
    _mark_stitched_return_sites_8616 as _mark_stitched_return_sites_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _mark_x86_16_stitched_recovery_8616 as _mark_x86_16_stitched_recovery_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _maybe_extend_x86_16_exact_region_terminator as _maybe_extend_x86_16_exact_region_terminator,
)
lazy from inertia.cli.cli_function_discovery import (
    _merge_scan_windows as _merge_scan_windows,
)
lazy from inertia.cli.cli_function_discovery import (
    _merge_supplement_pairs_8616 as _merge_supplement_pairs_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _metadata_code_windows as _metadata_code_windows,
)
lazy from inertia.cli.cli_function_discovery import (
    _mz_segment_windows as _mz_segment_windows,
)
lazy from inertia.cli.cli_function_discovery import (
    _needs_pre_entry_body_supplement as _needs_pre_entry_body_supplement,
)
lazy from inertia.cli.cli_function_discovery import (
    _normalize_and_merge_ranges_8616 as _normalize_and_merge_ranges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _normalized_x86_16_recovery_window as _normalized_x86_16_recovery_window,
)
lazy from inertia.cli.cli_function_discovery import (
    _persistent_recovery_attempt_cache_key as _persistent_recovery_attempt_cache_key,
)
lazy from inertia.cli.cli_function_discovery import (
    _pick_function as _pick_function,
)
lazy from inertia.cli.cli_function_discovery import (
    _pick_function_lean as _pick_function_lean,
)
lazy from inertia.cli.cli_function_discovery import (
    _pick_lst_fallback_pair_8616 as _pick_lst_fallback_pair_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _pop_pending_seed_addr_8616 as _pop_pending_seed_addr_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _pre_entry_source_function_ranges_8616 as _pre_entry_source_function_ranges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _preserve_candidate_function_info_8616 as _preserve_candidate_function_info_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _prioritized_pre_entry_follow_on_targets as _prioritized_pre_entry_follow_on_targets,
)
lazy from inertia.cli.cli_function_discovery import (
    _process_seeded_addr_8616 as _process_seeded_addr_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _project_region_on_recovered_8616 as _project_region_on_recovered_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _prologue_rank_entry_8616 as _prologue_rank_entry_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _prologue_scan_context_8616 as _prologue_scan_context_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _PrologueScanCtx8616 as _PrologueScanCtx8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _promote_region_function_8616 as _promote_region_function_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _queue_follow_on_targets_8616 as _queue_follow_on_targets_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _queue_new_seed_targets_8616 as _queue_new_seed_targets_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _rank_gap_scan_candidate_addrs as _rank_gap_scan_candidate_addrs,
)
lazy from inertia.cli.cli_function_discovery import (
    _rank_hidden_sidecar_pairs_for_display_throughput as _rank_hidden_sidecar_pairs_for_display_throughput,
)
lazy from inertia.cli.cli_function_discovery import (
    _rank_labeled_function_entries as _rank_labeled_function_entries,
)
lazy from inertia.cli.cli_function_discovery import (
    _rank_pre_entry_source_function_seeds_8616 as _rank_pre_entry_source_function_seeds_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _rank_prologue_scan_candidate_addrs as _rank_prologue_scan_candidate_addrs,
)
lazy from inertia.cli.cli_function_discovery import (
    _RankedBinaryPreviewItem as _RankedBinaryPreviewItem,
)
lazy from inertia.cli.cli_function_discovery import (
    _rebase_addr_on_sidecar_start_8616 as _rebase_addr_on_sidecar_start_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _rebuild_function_transition_graph_8616 as _rebuild_function_transition_graph_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recompute_stitched_edges_8616 as _recompute_stitched_edges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_caller_return_use_evidence_8616 as _record_caller_return_use_evidence_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_far_call_seed_8616 as _record_far_call_seed_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_follow_on_targets_8616 as _record_follow_on_targets_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_gap_scan_candidates_8616 as _record_gap_scan_candidates_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_near_transfer_seed_8616 as _record_near_transfer_seed_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_post_return_candidate_8616 as _record_post_return_candidate_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_rebased_slice_evidence_8616 as _record_rebased_slice_evidence_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_recovered_block_targets_8616 as _record_recovered_block_targets_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_recovered_pair_8616 as _record_recovered_pair_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _record_source_region_caller_evidence_8616 as _record_source_region_caller_evidence_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_blob_entry_function as _recover_blob_entry_function,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_cached_pair_once_8616 as _recover_cached_pair_once_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_candidate_with_timeout as _recover_candidate_with_timeout,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_direct_addr_bounded_8616 as _recover_direct_addr_bounded_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_hidden_sidecar_display_pairs as _recover_hidden_sidecar_display_pairs,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_lst_bounded_pair_8616 as _recover_lst_bounded_pair_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_once_with_cache_8616 as _recover_once_with_cache_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_pair_in_project_8616 as _recover_pair_in_project_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_pre_entry_source_catalog_8616 as _recover_pre_entry_source_catalog_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_prologue_candidate_8616 as _recover_prologue_candidate_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_rebased_slice_func_8616 as _recover_rebased_slice_func_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_richer_bounded_pair_8616 as _recover_richer_bounded_pair_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_small_unbounded_pair_8616 as _recover_small_unbounded_pair_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_source_seed_attempts_8616 as _recover_source_seed_attempts_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_source_seed_once_8616 as _recover_source_seed_once_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_source_seed_pass_8616 as _recover_source_seed_pass_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recover_target_cfg_8616 as _recover_target_cfg_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _recovery_cache_key as _recovery_cache_key,
)
lazy from inertia.cli.cli_function_discovery import (
    _recovery_score_good_enough as _recovery_score_good_enough,
)
lazy from inertia.cli.cli_function_discovery import (
    _region_terminator_reached_8616 as _region_terminator_reached_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _relocation_seed_targets as _relocation_seed_targets,
)
lazy from inertia.cli.cli_function_discovery import (
    _repair_leader_addrs_8616 as _repair_leader_addrs_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _repair_node_extent_8616 as _repair_node_extent_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _repair_recovered_entry_function_8616 as _repair_recovered_entry_function_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _repair_x86_16_function_graph_8616 as _repair_x86_16_function_graph_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _report_cached_recovery_8616 as _report_cached_recovery_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _report_region_split_diagnostics_8616 as _report_region_split_diagnostics_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _rerank_seed_candidates_8616 as _rerank_seed_candidates_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _reset_function_graph_state_8616 as _reset_function_graph_state_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _resolve_x86_16_call_target as _resolve_x86_16_call_target,
)
lazy from inertia.cli.cli_function_discovery import (
    _retry_exact_region_pairs_8616 as _retry_exact_region_pairs_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _richest_bounded_recovery_region as _richest_bounded_recovery_region,
)
lazy from inertia.cli.cli_function_discovery import (
    _scan_candidate_regions_8616 as _scan_candidate_regions_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _scan_gap_for_candidates_8616 as _scan_gap_for_candidates_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _scan_opcode_seed_targets_8616 as _scan_opcode_seed_targets_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _scan_prologue_candidates_8616 as _scan_prologue_candidates_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _scan_repair_block_8616 as _scan_repair_block_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _seed_graph_repair_node_cache_8616 as _seed_graph_repair_node_cache_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _seed_ranking_cache_key as _seed_ranking_cache_key,
)
lazy from inertia.cli.cli_function_discovery import (
    _seed_ranking_metadata_context as _seed_ranking_metadata_context,
)
lazy from inertia.cli.cli_function_discovery import (
    _seed_scan_windows as _seed_scan_windows,
)
lazy from inertia.cli.cli_function_discovery import (
    _SeedCandidateState8616 as _SeedCandidateState8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _seeded_image_context_8616 as _seeded_image_context_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _seeded_recovery_empty_result as _seeded_recovery_empty_result,
)
lazy from inertia.cli.cli_function_discovery import (
    _SeededExeCtx8616 as _SeededExeCtx8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _SeededRecoveryResult as _SeededRecoveryResult,
)
lazy from inertia.cli.cli_function_discovery import (
    _SeededRecoveryState8616 as _SeededRecoveryState8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _SeedEvidence8616 as _SeedEvidence8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _SeedTrace16 as _SeedTrace16,
)
lazy from inertia.cli.cli_function_discovery import (
    _select_sidecar_showcase_entries as _select_sidecar_showcase_entries,
)
lazy from inertia.cli.cli_function_discovery import (
    _should_replace_exact_region_candidate_8616 as _should_replace_exact_region_candidate_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _should_replace_function_with_stitched_graph_8616 as _should_replace_function_with_stitched_graph_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _sidecar_label_addr_8616 as _sidecar_label_addr_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _sidecar_label_ranking_cache_key as _sidecar_label_ranking_cache_key,
)
lazy from inertia.cli.cli_function_discovery import (
    _SidecarShowcaseState8616 as _SidecarShowcaseState8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _stitch_best_lst_func_8616 as _stitch_best_lst_func_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _stitch_candidate_pair_8616 as _stitch_candidate_pair_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _stitch_x86_16_exact_function_8616 as _stitch_x86_16_exact_function_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _store_candidate_recovery_cache as _store_candidate_recovery_cache,
)
lazy from inertia.cli.cli_function_discovery import (
    _store_catalog_address_cache_addrs_8616 as _store_catalog_address_cache_addrs_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _store_recovery_cache_value_8616 as _store_recovery_cache_value_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _tiny_region_has_terminator_8616 as _tiny_region_has_terminator_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _tiny_showcase_bucket_8616 as _tiny_showcase_bucket_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _track_ah_value_8616 as _track_ah_value_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _try_fast_entry_recovery_8616 as _try_fast_entry_recovery_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _try_lean_lst_windows_8616 as _try_lean_lst_windows_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _try_narrow_entry_recovery_8616 as _try_narrow_entry_recovery_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _try_partial_cfg_window_8616 as _try_partial_cfg_window_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _try_rebased_exact_region_recovery_8616 as _try_rebased_exact_region_recovery_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _try_recover_direct_addr_from_sidecar_label as _try_recover_direct_addr_from_sidecar_label,
)
lazy from inertia.cli.cli_function_discovery import (
    _try_recover_direct_addr_from_sidecar_region as _try_recover_direct_addr_from_sidecar_region,
)
lazy from inertia.cli.cli_function_discovery import (
    _try_sidecar_direct_lanes_8616 as _try_sidecar_direct_lanes_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _verified_library_seed_ranges_8616 as _verified_library_seed_ranges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _x86_16_block_successors_from_capstone_8616 as _x86_16_block_successors_from_capstone_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _x86_16_exact_region_has_terminator as _x86_16_exact_region_has_terminator,
)
lazy from inertia.cli.cli_function_discovery import (
    _x86_16_fast_recovery_windows as _x86_16_fast_recovery_windows,
)
lazy from inertia.cli.cli_function_discovery import (
    _x86_16_image_end_exclusive_8616 as _x86_16_image_end_exclusive_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _x86_16_image_relative_extent_8616 as _x86_16_image_relative_extent_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    _x86_16_recovery_windows as _x86_16_recovery_windows,
)
lazy from inertia.cli.cli_function_discovery import (
    _x86_16_region_image_end_8616 as _x86_16_region_image_end_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    bounded_entry_function_boundary_8616 as bounded_entry_function_boundary_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    build_exact_region_diagnostics_8616 as build_exact_region_diagnostics_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    builtins as builtins,
)
lazy from inertia.cli.cli_function_discovery import (
    caller_return_use_program_scope_8616 as caller_return_use_program_scope_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    classify_region_split_8616 as classify_region_split_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    collect_caller_return_use_evidence_8616 as collect_caller_return_use_evidence_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    collect_constant_indirect_jump_edges_8616 as collect_constant_indirect_jump_edges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    display_catalog_cache_payload_from_record_8616 as display_catalog_cache_payload_from_record_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    display_catalog_cache_record_8616 as display_catalog_cache_record_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    enforce_covered_transition_sources_8616 as enforce_covered_transition_sources_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    extend_cfg_for_far_calls as extend_cfg_for_far_calls,
)
lazy from inertia.cli.cli_function_discovery import (
    extend_cfg_for_neighbor_calls as extend_cfg_for_neighbor_calls,
)
lazy from inertia.cli.cli_function_discovery import (
    extend_cfg_for_proven_calls_8616 as extend_cfg_for_proven_calls_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    format_exact_region_diagnostics_8616 as format_exact_region_diagnostics_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    importlib as importlib,
)
lazy from inertia.cli.cli_function_discovery import (
    infer_com_region as infer_com_region,
)
lazy from inertia.cli.cli_function_discovery import (
    isolated_discovery_evidence_project_8616 as isolated_discovery_evidence_project_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    patch_interrupt_service_call_sites as patch_interrupt_service_call_sites,
)
lazy from inertia.cli.cli_function_discovery import (
    plan_x86_16_exact_slice as plan_x86_16_exact_slice,
)
lazy from inertia.cli.cli_function_discovery import (
    pre_entry_caller_ranges_8616 as pre_entry_caller_ranges_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    pre_entry_candidate_ranges as pre_entry_candidate_ranges,
)
lazy from inertia.cli.cli_function_discovery import (
    record_caller_return_use_evidence_8616 as record_caller_return_use_evidence_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    seed_calling_conventions as seed_calling_conventions,
)
lazy from inertia.cli.cli_function_discovery import (
    source_region_catalog_evidence_comment_8616 as source_region_catalog_evidence_comment_8616,
)
lazy from inertia.cli.cli_function_discovery import (
    trace_16bit_seed_candidates as trace_16bit_seed_candidates,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _X_WORD_TO_HALVES as _X_WORD_TO_HALVES,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    InterruptCall as InterruptCall,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    InterruptWrapperCall as InterruptWrapperCall,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    InterruptWrapperFieldAccess as InterruptWrapperFieldAccess,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    RegisterState as RegisterState,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _CFunctionLike as _CFunctionLike,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _CodegenLike as _CodegenLike,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _copy_register_state as _copy_register_state,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _dos_pseudo_functions as _dos_pseudo_functions,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _FunctionLike as _FunctionLike,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_arg_slots as _interrupt_wrapper_arg_slots,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_call_kind as _interrupt_wrapper_call_kind,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_call_signature as _interrupt_wrapper_call_signature,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_callee_name as _interrupt_wrapper_callee_name,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_dos_version_replacement as _interrupt_wrapper_dos_version_replacement,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_field_access_summary as _interrupt_wrapper_field_access_summary,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_field_path as _interrupt_wrapper_field_path,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_field_role as _interrupt_wrapper_field_role,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_helper_args as _interrupt_wrapper_helper_args,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_helper_call_expr as _interrupt_wrapper_helper_call_expr,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_high_byte_extract as _interrupt_wrapper_high_byte_extract,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_int10_call as _interrupt_wrapper_int10_call,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_int21_call as _interrupt_wrapper_int21_call,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_low_byte_extract as _interrupt_wrapper_low_byte_extract,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_mirror_register_write as _interrupt_wrapper_mirror_register_write,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_record_register_write as _interrupt_wrapper_record_register_write,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_register_state_value as _interrupt_wrapper_register_state_value,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_result_expr_replacement as _interrupt_wrapper_result_expr_replacement,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_result_extract_expr as _interrupt_wrapper_result_extract_expr,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_result_helper_expr as _interrupt_wrapper_result_helper_expr,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _interrupt_wrapper_result_replacement as _interrupt_wrapper_result_replacement,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _normalize_interrupt_wrapper_name as _normalize_interrupt_wrapper_name,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _unbound_c_call_nodes as _unbound_c_call_nodes,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _visit_wrapper_assignment as _visit_wrapper_assignment,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _visit_wrapper_call_stmt as _visit_wrapper_call_stmt,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _visit_wrapper_expr_stmt as _visit_wrapper_expr_stmt,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _visit_wrapper_result_node as _visit_wrapper_result_node,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    _visit_wrapper_statements as _visit_wrapper_statements,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    collect_interrupt_wrapper_calls as collect_interrupt_wrapper_calls,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    collect_interrupt_wrapper_field_accesses as collect_interrupt_wrapper_field_accesses,
)
lazy from inertia.cli.cli_interrupt_modeling import (
    structured_codegen as structured_codegen,
)
lazy from inertia.cli.disassembly_helpers import (
    _CapstoneInstructionLike as _CapstoneInstructionLike,
)
lazy from inertia.cli.disassembly_helpers import (
    _linear_disassembly as _linear_disassembly,
)
lazy from inertia.cli.disassembly_helpers import (
    _LoaderMainObjectLike as _LoaderMainObjectLike,
)
lazy from inertia.cli.disassembly_helpers import (
    _probe_lift_break as _probe_lift_break,
)
lazy from inertia.cli.disassembly_helpers import (
    _ProjectLoaderLike as _ProjectLoaderLike,
)
lazy from inertia.cli.project_loading import (
    _IDA_BASE_ADDRESS_RE as _IDA_BASE_ADDRESS_RE,
)
lazy from inertia.cli.project_loading import (
    _TRACE_FUNCTION as _TRACE_FUNCTION,
)
lazy from inertia.cli.project_loading import (
    Arch86_16 as Arch86_16,
)
lazy from inertia.cli.project_loading import (
    MzStaticIntakeRequest8616 as MzStaticIntakeRequest8616,
)
lazy from inertia.cli.project_loading import (
    PackedMZError as PackedMZError,
)
lazy from inertia.cli.project_loading import (
    PackerDetection as PackerDetection,
)
lazy from inertia.cli.project_loading import (
    PackerType as PackerType,
)
lazy from inertia.cli.project_loading import (
    UnpackedMZImage as UnpackedMZImage,
)
lazy from inertia.cli.project_loading import (
    _build_project_cached_impl as _build_project_cached_impl,
)
lazy from inertia.cli.project_loading import (
    _debug_print as _debug_print,
)
lazy from inertia.cli.project_loading import (
    _decoded_packed_stream as _decoded_packed_stream,
)
lazy from inertia.cli.project_loading import (
    _defer_mz_static_invocation_8616 as _defer_mz_static_invocation_8616,
)
lazy from inertia.cli.project_loading import (
    _detect_packed_mz_executable as _detect_packed_mz_executable,
)
lazy from inertia.cli.project_loading import (
    _detect_packed_mz_executable_cached as _detect_packed_mz_executable_cached,
)
lazy from inertia.cli.project_loading import (
    _finalize_x86_16_project as _finalize_x86_16_project,
)
lazy from inertia.cli.project_loading import (
    _find_sidecar_file as _find_sidecar_file,
)
lazy from inertia.cli.project_loading import (
    _find_sidecar_file_cached as _find_sidecar_file_cached,
)
lazy from inertia.cli.project_loading import (
    _looks_like_ne_executable as _looks_like_ne_executable,
)
lazy from inertia.cli.project_loading import (
    _looks_like_ne_executable_cached as _looks_like_ne_executable_cached,
)
lazy from inertia.cli.project_loading import (
    _mark_packed_project as _mark_packed_project,
)
lazy from inertia.cli.project_loading import (
    _MzStaticRequestMarker as _MzStaticRequestMarker,
)
lazy from inertia.cli.project_loading import (
    _PackedProjectMarker as _PackedProjectMarker,
)
lazy from inertia.cli.project_loading import (
    _probe_ida_base_linear as _probe_ida_base_linear,
)
lazy from inertia.cli.project_loading import (
    _probe_ida_base_linear_cached as _probe_ida_base_linear_cached,
)
lazy from inertia.cli.project_loading import (
    _project_source as _project_source,
)
lazy from inertia.cli.project_loading import (
    build_declared_project_8616 as build_declared_project_8616,
)
lazy from inertia.cli.project_loading import (
    detect_packer as detect_packer,
)
lazy from inertia.cli.project_loading import (
    hook_x86_16_known_compiler_helpers_8616 as hook_x86_16_known_compiler_helpers_8616,
)
lazy from inertia.cli.project_loading import (
    io as io,
)
lazy from inertia.cli.project_loading import (
    unpack_exepack as unpack_exepack,
)
lazy from inertia.cli.project_loading import (
    unpack_lzexe_091 as unpack_lzexe_091,
)
lazy from inertia.cli.project_loading import (
    unpack_pklite as unpack_pklite,
)
lazy from inertia.cli.runtime_support import (
    _CURRENT_PROJECT as _CURRENT_PROJECT,
)
lazy from inertia.cli.runtime_support import (
    _FORMAT_FIRST_BLOCK_ASM as _FORMAT_FIRST_BLOCK_ASM,
)
lazy from inertia.cli.runtime_support import (
    _REAL_STDERR as _REAL_STDERR,
)
lazy from inertia.cli.runtime_support import (
    _REAL_STDOUT as _REAL_STDOUT,
)
lazy from inertia.cli.runtime_support import (
    _SEQNODE_PREFERRED_TYPES_8616 as _SEQNODE_PREFERRED_TYPES_8616,
)
lazy from inertia.cli.runtime_support import (
    _THREAD_STDERR as _THREAD_STDERR,
)
lazy from inertia.cli.runtime_support import (
    _THREAD_STDOUT as _THREAD_STDOUT,
)
lazy from inertia.cli.runtime_support import (
    DEFAULT_FREE_RAM_BUDGET_FRACTION as DEFAULT_FREE_RAM_BUDGET_FRACTION,
)
lazy from inertia.cli.runtime_support import (
    DEFAULT_WORKER_MEMORY_FLOOR_MB as DEFAULT_WORKER_MEMORY_FLOOR_MB,
)
lazy from inertia.cli.runtime_support import (
    FORCE_SERIAL_FUNCTION_DECOMP_ENV as FORCE_SERIAL_FUNCTION_DECOMP_ENV,
)
lazy from inertia.cli.runtime_support import (
    LAST_STEP_TIME as LAST_STEP_TIME,
)
lazy from inertia.cli.runtime_support import (
    PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT as PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT,
)
lazy from inertia.cli.runtime_support import (
    START_TIME as START_TIME,
)
lazy from inertia.cli.runtime_support import (
    AnalysisTimeout as AnalysisTimeout,
)
lazy from inertia.cli.runtime_support import (
    AngrPatchSurface as AngrPatchSurface,
)
lazy from inertia.cli.runtime_support import (
    AngrProjectSurface as AngrProjectSurface,
)
lazy from inertia.cli.runtime_support import (
    ConditionEdgeEvidence as ConditionEdgeEvidence,
)
lazy from inertia.cli.runtime_support import (
    DynamicRecord as DynamicRecord,
)
lazy from inertia.cli.runtime_support import (
    JumpkindLoggingHandler as JumpkindLoggingHandler,
)
lazy from inertia.cli.runtime_support import (
    PreforkJobPool as PreforkJobPool,
)
lazy from inertia.cli.runtime_support import (
    ThreadBoundTextIO as ThreadBoundTextIO,
)
lazy from inertia.cli.runtime_support import (
    ThreadPoolExecutor as ThreadPoolExecutor,
)
lazy from inertia.cli.runtime_support import (
    _accumulate_branch_split_ids_8616 as _accumulate_branch_split_ids_8616,
)
lazy from inertia.cli.runtime_support import (
    _accumulate_branch_subtree_ids_8616 as _accumulate_branch_subtree_ids_8616,
)
lazy from inertia.cli.runtime_support import (
    _ambiguous_mapping_samples_8616 as _ambiguous_mapping_samples_8616,
)
lazy from inertia.cli.runtime_support import (
    _append_int_values_8616 as _append_int_values_8616,
)
lazy from inertia.cli.runtime_support import (
    _block_has_pathologically_complex_expr as _block_has_pathologically_complex_expr,
)
lazy from inertia.cli.runtime_support import (
    _bounded_stage_guard_8616 as _bounded_stage_guard_8616,
)
lazy from inertia.cli.runtime_support import (
    _build_grouped_switch_artifacts_from_source_graph_8616 as _build_grouped_switch_artifacts_from_source_graph_8616,
)
lazy from inertia.cli.runtime_support import (
    _clinic_peephole_capped_8616 as _clinic_peephole_capped_8616,
)
lazy from inertia.cli.runtime_support import (
    _clinic_skip_complex_expr_gate_8616 as _clinic_skip_complex_expr_gate_8616,
)
lazy from inertia.cli.runtime_support import (
    _clinic_stage_guard_8616 as _clinic_stage_guard_8616,
)
lazy from inertia.cli.runtime_support import (
    _ClinicGuardState8616 as _ClinicGuardState8616,
)
lazy from inertia.cli.runtime_support import (
    _collect_loop_exit_nodes_8616 as _collect_loop_exit_nodes_8616,
)
lazy from inertia.cli.runtime_support import (
    _common_int_path_8616 as _common_int_path_8616,
)
lazy from inertia.cli.runtime_support import (
    _common_prefix_len_8616 as _common_prefix_len_8616,
)
lazy from inertia.cli.runtime_support import (
    _condition_ir_payload_8616 as _condition_ir_payload_8616,
)
lazy from inertia.cli.runtime_support import (
    _condition_operand_payload_8616 as _condition_operand_payload_8616,
)
lazy from inertia.cli.runtime_support import (
    _converged_recover_variables_8616 as _converged_recover_variables_8616,
)
lazy from inertia.cli.runtime_support import (
    _daemon_thread_result_8616 as _daemon_thread_result_8616,
)
lazy from inertia.cli.runtime_support import (
    _debug_clinic_flags_8616 as _debug_clinic_flags_8616,
)
lazy from inertia.cli.runtime_support import (
    _debug_skip_complex_block_8616 as _debug_skip_complex_block_8616,
)
lazy from inertia.cli.runtime_support import (
    _default_case_region_ids_by_default_8616 as _default_case_region_ids_by_default_8616,
)
lazy from inertia.cli.runtime_support import (
    _disambiguated_default_mappings_8616 as _disambiguated_default_mappings_8616,
)
lazy from inertia.cli.runtime_support import (
    _dynamic_record as _dynamic_record,
)
lazy from inertia.cli.runtime_support import (
    _enable_thread_stack_dump_8616 as _enable_thread_stack_dump_8616,
)
lazy from inertia.cli.runtime_support import (
    _exact_region_match_8616 as _exact_region_match_8616,
)
lazy from inertia.cli.runtime_support import (
    _expanded_path_samples_8616 as _expanded_path_samples_8616,
)
lazy from inertia.cli.runtime_support import (
    _expanded_region_mappings_8616 as _expanded_region_mappings_8616,
)
lazy from inertia.cli.runtime_support import (
    _expanded_root_body_shape_status_8616 as _expanded_root_body_shape_status_8616,
)
lazy from inertia.cli.runtime_support import (
    _expanded_root_geometry_8616 as _expanded_root_geometry_8616,
)
lazy from inertia.cli.runtime_support import (
    _expanded_root_normalized_body_from_summary_8616 as _expanded_root_normalized_body_from_summary_8616,
)
lazy from inertia.cli.runtime_support import (
    _expanded_root_switch_fields_8616 as _expanded_root_switch_fields_8616,
)
lazy from inertia.cli.runtime_support import (
    _expanded_root_verdict_8616 as _expanded_root_verdict_8616,
)
lazy from inertia.cli.runtime_support import (
    _expr_child_nodes as _expr_child_nodes,
)
lazy from inertia.cli.runtime_support import (
    _expr_tree_node_count as _expr_tree_node_count,
)
lazy from inertia.cli.runtime_support import (
    _external_default_owner_paths_8616 as _external_default_owner_paths_8616,
)
lazy from inertia.cli.runtime_support import (
    _fast_block_peephole_8616 as _fast_block_peephole_8616,
)
lazy from inertia.cli.runtime_support import (
    _faulthandler_output_file as _faulthandler_output_file,
)
lazy from inertia.cli.runtime_support import (
    _FuturesTimeoutError as _FuturesTimeoutError,
)
lazy from inertia.cli.runtime_support import (
    _graphregion_node_at_path_8616 as _graphregion_node_at_path_8616,
)
lazy from inertia.cli.runtime_support import (
    _graphregion_owner_node_summary_8616 as _graphregion_owner_node_summary_8616,
)
lazy from inertia.cli.runtime_support import (
    _graphregion_subtree_summaries_8616 as _graphregion_subtree_summaries_8616,
)
lazy from inertia.cli.runtime_support import (
    _graphregion_switch_artifact_mapping_8616 as _graphregion_switch_artifact_mapping_8616,
)
lazy from inertia.cli.runtime_support import (
    _graphregion_switch_artifact_mappings_8616 as _graphregion_switch_artifact_mappings_8616,
)
lazy from inertia.cli.runtime_support import (
    _guarded_compute_propagation_8616 as _guarded_compute_propagation_8616,
)
lazy from inertia.cli.runtime_support import (
    _guarded_peephole_handle_expr_8616 as _guarded_peephole_handle_expr_8616,
)
lazy from inertia.cli.runtime_support import (
    _guarded_peephole_optimize_8616 as _guarded_peephole_optimize_8616,
)
lazy from inertia.cli.runtime_support import (
    _guarded_peephole_optimize_exprs_8616 as _guarded_peephole_optimize_exprs_8616,
)
lazy from inertia.cli.runtime_support import (
    _guarded_simplify_block_8616 as _guarded_simplify_block_8616,
)
lazy from inertia.cli.runtime_support import (
    _install_bounded_lowering_guards_8616 as _install_bounded_lowering_guards_8616,
)
lazy from inertia.cli.runtime_support import (
    _int_path_tuple as _int_path_tuple,
)
lazy from inertia.cli.runtime_support import (
    _loop_exit_default_relation_8616 as _loop_exit_default_relation_8616,
)
lazy from inertia.cli.runtime_support import (
    _loop_exit_default_status_8616 as _loop_exit_default_status_8616,
)
lazy from inertia.cli.runtime_support import (
    _loop_internal_switch_mapping_8616 as _loop_internal_switch_mapping_8616,
)
lazy from inertia.cli.runtime_support import (
    _loop_preserving_switch_plan_8616 as _loop_preserving_switch_plan_8616,
)
lazy from inertia.cli.runtime_support import (
    _map_graphregion_stage_records_8616 as _map_graphregion_stage_records_8616,
)
lazy from inertia.cli.runtime_support import (
    _map_seqnode_stage_records_8616 as _map_seqnode_stage_records_8616,
)
lazy from inertia.cli.runtime_support import (
    _materialize_loop_break_default_switch_8616 as _materialize_loop_break_default_switch_8616,
)
lazy from inertia.cli.runtime_support import (
    _maybe_materialize_pre_codegen_typed_switch_8616 as _maybe_materialize_pre_codegen_typed_switch_8616,
)
lazy from inertia.cli.runtime_support import (
    _NoPropagationResult8616 as _NoPropagationResult8616,
)
lazy from inertia.cli.runtime_support import (
    _normalize_replacement_bits_8616 as _normalize_replacement_bits_8616,
)
lazy from inertia.cli.runtime_support import (
    _peephole_rewrite_loop_8616 as _peephole_rewrite_loop_8616,
)
lazy from inertia.cli.runtime_support import (
    _PeepholeBlockBoundary8616 as _PeepholeBlockBoundary8616,
)
lazy from inertia.cli.runtime_support import (
    _pre_codegen_condition_evidence_8616 as _pre_codegen_condition_evidence_8616,
)
lazy from inertia.cli.runtime_support import (
    _pre_codegen_grouped_switch_artifacts_8616 as _pre_codegen_grouped_switch_artifacts_8616,
)
lazy from inertia.cli.runtime_support import (
    _pre_codegen_stage_mappings_8616 as _pre_codegen_stage_mappings_8616,
)
lazy from inertia.cli.runtime_support import (
    _pre_codegen_switch_replacement_probe_8616 as _pre_codegen_switch_replacement_probe_8616,
)
lazy from inertia.cli.runtime_support import (
    _pre_recursive_switch_materialization_readiness_8616 as _pre_recursive_switch_materialization_readiness_8616,
)
lazy from inertia.cli.runtime_support import (
    _preferred_exact_region_summary_8616 as _preferred_exact_region_summary_8616,
)
lazy from inertia.cli.runtime_support import (
    _project_current_function_context as _project_current_function_context,
)
lazy from inertia.cli.runtime_support import (
    _project_current_function_context_suffix as _project_current_function_context_suffix,
)
lazy from inertia.cli.runtime_support import (
    _record_graphregion_stage_probe_8616 as _record_graphregion_stage_probe_8616,
)
lazy from inertia.cli.runtime_support import (
    _record_paths as _record_paths,
)
lazy from inertia.cli.runtime_support import (
    _record_pre_codegen_seqnode_probe_8616 as _record_pre_codegen_seqnode_probe_8616,
)
lazy from inertia.cli.runtime_support import (
    _record_seqnode_stage_probe_8616 as _record_seqnode_stage_probe_8616,
)
lazy from inertia.cli.runtime_support import (
    _region_containing_summaries_8616 as _region_containing_summaries_8616,
)
lazy from inertia.cli.runtime_support import (
    _region_missing_result_8616 as _region_missing_result_8616,
)
lazy from inertia.cli.runtime_support import (
    _resolve_ambiguous_default_mapping_8616 as _resolve_ambiguous_default_mapping_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_attr_children_8616 as _seqnode_attr_children_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_candidate_payload_8616 as _seqnode_candidate_payload_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_cases_children_8616 as _seqnode_cases_children_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_children_8616 as _seqnode_children_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_map_region_id_8616 as _seqnode_map_region_id_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_materialization_owner_blocker_8616 as _seqnode_materialization_owner_blocker_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_node_at_path_8616 as _seqnode_node_at_path_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_owner_node_summary_8616 as _seqnode_owner_node_summary_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_probe_summary_8616 as _seqnode_probe_summary_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_subtree_summaries_8616 as _seqnode_subtree_summaries_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_switch_artifact_mapping_8616 as _seqnode_switch_artifact_mapping_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_switch_artifact_mappings_8616 as _seqnode_switch_artifact_mappings_8616,
)
lazy from inertia.cli.runtime_support import (
    _seqnode_target_addr_8616 as _seqnode_target_addr_8616,
)
lazy from inertia.cli.runtime_support import (
    _stmt_expr_children as _stmt_expr_children,
)
lazy from inertia.cli.runtime_support import (
    _switch_mapping_status_8616 as _switch_mapping_status_8616,
)
lazy from inertia.cli.runtime_support import (
    _threads_queues as _threads_queues,
)
lazy from inertia.cli.runtime_support import (
    _ThreadStreamState as _ThreadStreamState,
)
lazy from inertia.cli.runtime_support import (
    _timed_stage_guard_8616 as _timed_stage_guard_8616,
)
lazy from inertia.cli.runtime_support import (
    _worker as _worker,
)
lazy from inertia.cli.runtime_support import (
    analysis_timeout as analysis_timeout,
)
lazy from inertia.cli.runtime_support import (
    apply_memory_limit as apply_memory_limit,
)
lazy from inertia.cli.runtime_support import (
    build_guarded_handle_binop_mul_8616 as build_guarded_handle_binop_mul_8616,
)
lazy from inertia.cli.runtime_support import (
    build_guarded_handle_binop_sub_8616 as build_guarded_handle_binop_sub_8616,
)
lazy from inertia.cli.runtime_support import (
    capture_thread_output as capture_thread_output,
)
lazy from inertia.cli.runtime_support import (
    choose_function_parallelism as choose_function_parallelism,
)
lazy from inertia.cli.runtime_support import (
    datetime as datetime,
)
lazy from inertia.cli.runtime_support import (
    default_exe_showcase_cap as default_exe_showcase_cap,
)
lazy from inertia.cli.runtime_support import (
    emit_timeout_and_exit as emit_timeout_and_exit,
)
lazy from inertia.cli.runtime_support import (
    enable_line_buffered_stdio as enable_line_buffered_stdio,
)
lazy from inertia.cli.runtime_support import (
    faulthandler as faulthandler,
)
lazy from inertia.cli.runtime_support import (
    format_address as format_address,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_ail_narrowing as guard_angr_ail_narrowing,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_basepointeroffset_codegen_support as guard_angr_basepointeroffset_codegen_support,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_clinic_stage_markers as guard_angr_clinic_stage_markers,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_fast_post_ssa_8616 as guard_angr_fast_post_ssa_8616,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_peephole_expr_bitwidth_assertion as guard_angr_peephole_expr_bitwidth_assertion,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_pre_codegen_seqnode_probe as guard_angr_pre_codegen_seqnode_probe,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_structurer_codegen_timing as guard_angr_structurer_codegen_timing,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_structuring_codegen_internal_timing as guard_angr_structuring_codegen_internal_timing,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_structuring_seqnode_stage_probe as guard_angr_structuring_seqnode_stage_probe,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_tail_validation_collection_timing as guard_angr_tail_validation_collection_timing,
)
lazy from inertia.cli.runtime_support import (
    guard_angr_variable_recovery_binop_sub_size_mismatch as guard_angr_variable_recovery_binop_sub_size_mismatch,
)
lazy from inertia.cli.runtime_support import (
    install_angr_basepointeroffset_codegen_guard as install_angr_basepointeroffset_codegen_guard,
)
lazy from inertia.cli.runtime_support import (
    install_angr_peephole_expr_bitwidth_guard as install_angr_peephole_expr_bitwidth_guard,
)
lazy from inertia.cli.runtime_support import (
    install_angr_pre_codegen_seqnode_probe_guard as install_angr_pre_codegen_seqnode_probe_guard,
)
lazy from inertia.cli.runtime_support import (
    install_angr_structuring_seqnode_stage_probe_guard as install_angr_structuring_seqnode_stage_probe_guard,
)
lazy from inertia.cli.runtime_support import (
    install_angr_variable_recovery_binop_sub_size_guard as install_angr_variable_recovery_binop_sub_size_guard,
)
lazy from inertia.cli.runtime_support import (
    install_jumpkind_logging_context as install_jumpkind_logging_context,
)
lazy from inertia.cli.runtime_support import (
    log_step as log_step,
)
lazy from inertia.cli.runtime_support import (
    lower_process_priority as lower_process_priority,
)
lazy from inertia.cli.runtime_support import (
    memory_available_mb as memory_available_mb,
)
lazy from inertia.cli.runtime_support import (
    normalize_codegen_node_tags_8616 as normalize_codegen_node_tags_8616,
)
lazy from inertia.cli.runtime_support import (
    prefer_low_memory_path as prefer_low_memory_path,
)
lazy from inertia.cli.runtime_support import (
    resource as resource,
)
lazy from inertia.cli.runtime_support import (
    run_with_timeout_in_daemon_thread as run_with_timeout_in_daemon_thread,
)
lazy from inertia.cli.runtime_support import (
    run_with_timeout_in_fork as run_with_timeout_in_fork,
)
lazy from inertia.cli.runtime_support import (
    should_force_serial_supplemental_decompilation as should_force_serial_supplemental_decompilation,
)
lazy from inertia.cli.runtime_support import (
    timing_output_enabled as timing_output_enabled,
)
lazy from inertia.cli.sidecar_metadata import (
    CODListingMetadata as CODListingMetadata,
)
lazy from inertia.cli.sidecar_metadata import (
    DebugEnumMemberEvidence as DebugEnumMemberEvidence,
)
lazy from inertia.cli.sidecar_metadata import (
    DebugSymbolEvidence as DebugSymbolEvidence,
)
lazy from inertia.cli.sidecar_metadata import (
    DebugTypeDescriptorEvidence as DebugTypeDescriptorEvidence,
)
lazy from inertia.cli.sidecar_metadata import (
    DebugTypeMemberEvidence as DebugTypeMemberEvidence,
)
lazy from inertia.cli.sidecar_metadata import (
    DebugTypeReferenceEvidence as DebugTypeReferenceEvidence,
)
lazy from inertia.cli.sidecar_metadata import (
    _attach_debug_evidence_attrs as _attach_debug_evidence_attrs,
)
lazy from inertia.cli.sidecar_metadata import (
    _attrs_from_mapping as _attrs_from_mapping,
)
lazy from inertia.cli.sidecar_metadata import (
    _codeview_type_members_to_evidence as _codeview_type_members_to_evidence,
)
lazy from inertia.cli.sidecar_metadata import (
    _detect_flair_metadata as _detect_flair_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    _dynamic_int_attr as _dynamic_int_attr,
)
lazy from inertia.cli.sidecar_metadata import (
    _dynamic_mapping_attr as _dynamic_mapping_attr,
)
lazy from inertia.cli.sidecar_metadata import (
    _find_sibling_sidecar as _find_sibling_sidecar,
)
lazy from inertia.cli.sidecar_metadata import (
    _find_sibling_sidecar_cached as _find_sibling_sidecar_cached,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_cod_listing_sidecar_8616 as _load_cod_listing_sidecar_8616,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_cod_mzre_flair_sidecars as _load_cod_mzre_flair_sidecars,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_codeview_or_ne_metadata as _load_codeview_or_ne_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_flair_sidecar_8616 as _load_flair_sidecar_8616,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_ida_map_sidecar as _load_ida_map_sidecar,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_idc_inc_sidecars as _load_idc_inc_sidecars,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_lst_sidecar as _load_lst_sidecar,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_mzre_map_sidecar_8616 as _load_mzre_map_sidecar_8616,
)
lazy from inertia.cli.sidecar_metadata import (
    _load_tdinfo_sidecar as _load_tdinfo_sidecar,
)
lazy from inertia.cli.sidecar_metadata import (
    _lst_label_fallback_region_8616 as _lst_label_fallback_region_8616,
)
lazy from inertia.cli.sidecar_metadata import (
    _lst_metadata_has_evidence_8616 as _lst_metadata_has_evidence_8616,
)
lazy from inertia.cli.sidecar_metadata import (
    _merge_cod_label_entry_8616 as _merge_cod_label_entry_8616,
)
lazy from inertia.cli.sidecar_metadata import (
    _merge_ida_lst_proc_metadata_8616 as _merge_ida_lst_proc_metadata_8616,
)
lazy from inertia.cli.sidecar_metadata import (
    _merge_lst_metadata_8616 as _merge_lst_metadata_8616,
)
lazy from inertia.cli.sidecar_metadata import (
    _nb00_publics_to_symbol_evidence as _nb00_publics_to_symbol_evidence,
)
lazy from inertia.cli.sidecar_metadata import (
    _nb0204_procedure_ranges as _nb0204_procedure_ranges,
)
lazy from inertia.cli.sidecar_metadata import (
    _nb0204_symbols_to_evidence as _nb0204_symbols_to_evidence,
)
lazy from inertia.cli.sidecar_metadata import (
    _parse_cod_sidecar_metadata as _parse_cod_sidecar_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    _parse_ida_lst_proc_metadata as _parse_ida_lst_proc_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    _parse_ida_lst_proc_ranges as _parse_ida_lst_proc_ranges,
)
lazy from inertia.cli.sidecar_metadata import (
    _parse_ida_map_metadata as _parse_ida_map_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    _parse_idc_metadata as _parse_idc_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    _parse_inc_struct_names as _parse_inc_struct_names,
)
lazy from inertia.cli.sidecar_metadata import (
    _parse_mzre_map_metadata as _parse_mzre_map_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    _parse_ne_exe_metadata as _parse_ne_exe_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    _ProjectLike as _ProjectLike,
)
lazy from inertia.cli.sidecar_metadata import (
    _reconcile_cod_listing_with_codeview as _reconcile_cod_listing_with_codeview,
)
lazy from inertia.cli.sidecar_metadata import (
    _synthesize_code_ranges as _synthesize_code_ranges,
)
lazy from inertia.cli.sidecar_metadata import (
    _tdinfo_symbols_to_evidence as _tdinfo_symbols_to_evidence,
)
lazy from inertia.cli.sidecar_metadata import (
    apply_cached_sidecar_metadata as apply_cached_sidecar_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    emit_sidecar_metadata_debug as emit_sidecar_metadata_debug,
)
lazy from inertia.cli.sidecar_metadata import (
    extract_lst_metadata as extract_lst_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    load_cached_sidecar_metadata as load_cached_sidecar_metadata,
)
lazy from inertia.cli.sidecar_metadata import (
    parse_codeview_nb00 as parse_codeview_nb00,
)
lazy from inertia.cli.sidecar_metadata import (
    parse_codeview_nb0204 as parse_codeview_nb0204,
)
lazy from inertia.cli.sidecar_metadata import (
    parse_tdinfo_exe as parse_tdinfo_exe,
)
lazy from inertia.cli.sidecar_metadata import (
    store_cached_sidecar_metadata as store_cached_sidecar_metadata,
)
lazy from inertia.cli.sidecar_parsers import (
    _CONTROL_FLOW_LABEL_TOKENS as _CONTROL_FLOW_LABEL_TOKENS,
)
lazy from inertia.cli.sidecar_parsers import (
    _IDA_LST_ADDR_RE as _IDA_LST_ADDR_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _IDA_LST_ENDP_RE as _IDA_LST_ENDP_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _IDA_LST_PROC_RE as _IDA_LST_PROC_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _IDA_MAP_CODE_CLASSES as _IDA_MAP_CODE_CLASSES,
)
lazy from inertia.cli.sidecar_parsers import (
    _IDA_MAP_DATA_CLASSES as _IDA_MAP_DATA_CLASSES,
)
lazy from inertia.cli.sidecar_parsers import (
    _IDA_MAP_PUBLIC_RE as _IDA_MAP_PUBLIC_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _IDA_MAP_SEGMENT_RE as _IDA_MAP_SEGMENT_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _IDC_SET_NAME_RE as _IDC_SET_NAME_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _INC_STRUCT_RE as _INC_STRUCT_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _MZRE_ROUTINE_RE as _MZRE_ROUTINE_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _MZRE_SEGMENT_RE as _MZRE_SEGMENT_RE,
)
lazy from inertia.cli.sidecar_parsers import (
    _NON_FUNCTION_CODE_PREFIXES as _NON_FUNCTION_CODE_PREFIXES,
)
lazy from inertia.cli.sidecar_parsers import (
    CachedPatRegexSpec as CachedPatRegexSpec,
)
lazy from inertia.cli.sidecar_parsers import (
    FlairStartupPattern as FlairStartupPattern,
)
lazy from inertia.cli.sidecar_parsers import (
    LocalPatMatchResult as LocalPatMatchResult,
)
lazy from inertia.cli.sidecar_parsers import (
    _accumulate_base_candidates_8616 as _accumulate_base_candidates_8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _AngrMemoryLoader8616 as _AngrMemoryLoader8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _cod_entry_pattern_8616 as _cod_entry_pattern_8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _label_looks_like_code as _label_looks_like_code,
)
lazy from inertia.cli.sidecar_parsers import (
    _label_looks_like_function as _label_looks_like_function,
)
lazy from inertia.cli.sidecar_parsers import (
    _load_flair_startup_pat_modules as _load_flair_startup_pat_modules,
)
lazy from inertia.cli.sidecar_parsers import (
    _match_flair_startup_pat_functions as _match_flair_startup_pat_functions,
)
lazy from inertia.cli.sidecar_parsers import (
    _memory_matches_cod_pattern_8616 as _memory_matches_cod_pattern_8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _merge_signature_catalog_8616 as _merge_signature_catalog_8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _merge_startup_flair_evidence_8616 as _merge_startup_flair_evidence_8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _parse_codeview_nb00_metadata as _parse_codeview_nb00_metadata,
)
lazy from inertia.cli.sidecar_parsers import (
    _parse_codeview_nb0204_metadata as _parse_codeview_nb0204_metadata,
)
lazy from inertia.cli.sidecar_parsers import (
    _ranges_overlap_or_touch as _ranges_overlap_or_touch,
)
lazy from inertia.cli.sidecar_parsers import (
    _reconcile_cod_label_8616 as _reconcile_cod_label_8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _remember_compiler_8616 as _remember_compiler_8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _scan_cod_base_deltas_8616 as _scan_cod_base_deltas_8616,
)
lazy from inertia.cli.sidecar_parsers import (
    _startup_pat_cache_dir as _startup_pat_cache_dir,
)
lazy from inertia.cli.sidecar_parsers import (
    bisect_right as bisect_right,
)
lazy from inertia.cli.sidecar_parsers import (
    extract_cod_listing_metadata as extract_cod_listing_metadata,
)
lazy from inertia.cli.sidecar_parsers import (
    flair_signature_root as flair_signature_root,
)
lazy from inertia.cli.sidecar_parsers import (
    load_cached_pat_regex_specs as load_cached_pat_regex_specs,
)
lazy from inertia.cli.sidecar_parsers import (
    match_flair_startup_entry as match_flair_startup_entry,
)
lazy from inertia.cli.sidecar_parsers import (
    match_pat_modules as match_pat_modules,
)
lazy from inertia.cli.sidecar_parsers import (
    match_signature_catalog as match_signature_catalog,
)
lazy from inertia.cli.sidecar_parsers import (
    parse_codeview_nb0204_bytes as parse_codeview_nb0204_bytes,
)
lazy from inertia.cli.sidecar_parsers import (
    parse_ne_exe as parse_ne_exe,
)
lazy from inertia.cli.sidecar_parsers import (
    registered_pat_architecture as registered_pat_architecture,
)
lazy from inertia.cli.sidecar_parsers import (
    struct as struct,
)
lazy from inertia.cli.tail_validation import (
    _TAIL_VALIDATION_STABLE_STATUSES as _TAIL_VALIDATION_STABLE_STATUSES,
)
lazy from inertia.cli.tail_validation import (
    ROOT as ROOT,
)
lazy from inertia.cli.tail_validation import (
    TAIL_VALIDATION_CONSOLE_CACHE_DIR as TAIL_VALIDATION_CONSOLE_CACHE_DIR,
)
lazy from inertia.cli.tail_validation import (
    TAIL_VALIDATION_DETAIL_CACHE_DIR as TAIL_VALIDATION_DETAIL_CACHE_DIR,
)
lazy from inertia.cli.tail_validation import (
    TAIL_VALIDATION_ENABLE_ENV as TAIL_VALIDATION_ENABLE_ENV,
)
lazy from inertia.cli.tail_validation import (
    TAIL_VALIDATION_FALLBACK_PROJECT_SNAPSHOT_KINDS as TAIL_VALIDATION_FALLBACK_PROJECT_SNAPSHOT_KINDS,
)
lazy from inertia.cli.tail_validation import (
    TAIL_VALIDATION_METADATA_ENV as TAIL_VALIDATION_METADATA_ENV,
)
lazy from inertia.cli.tail_validation import (
    TAIL_VALIDATION_METADATA_PREFIX as TAIL_VALIDATION_METADATA_PREFIX,
)
lazy from inertia.cli.tail_validation import (
    TAIL_VALIDATION_STDERR_PREFIX as TAIL_VALIDATION_STDERR_PREFIX,
)
lazy from inertia.cli.tail_validation import (
    TailValidationAcceptanceSeverity as TailValidationAcceptanceSeverity,
)
lazy from inertia.cli.tail_validation import (
    TailValidationDisplayStatus as TailValidationDisplayStatus,
)
lazy from inertia.cli.tail_validation import (
    TailValidationResultStatus as TailValidationResultStatus,
)
lazy from inertia.cli.tail_validation import (
    _append_stage_diagnostic_lines_8616 as _append_stage_diagnostic_lines_8616,
)
lazy from inertia.cli.tail_validation import (
    _as_int as _as_int,
)
lazy from inertia.cli.tail_validation import (
    _as_iterable as _as_iterable,
)
lazy from inertia.cli.tail_validation import (
    _as_mapping as _as_mapping,
)
lazy from inertia.cli.tail_validation import (
    _as_string_tuple as _as_string_tuple,
)
lazy from inertia.cli.tail_validation import (
    _attach_tail_record_counts_8616 as _attach_tail_record_counts_8616,
)
lazy from inertia.cli.tail_validation import (
    _collect_failed_stages_8616 as _collect_failed_stages_8616,
)
lazy from inertia.cli.tail_validation import (
    _compute_cfg_hash_from_result as _compute_cfg_hash_from_result,
)
lazy from inertia.cli.tail_validation import (
    _dynamic_cli_attr as _dynamic_cli_attr,
)
lazy from inertia.cli.tail_validation import (
    _has_acceptance_validation_failure as _has_acceptance_validation_failure,
)
lazy from inertia.cli.tail_validation import (
    _missing_snapshot_tail_record_8616 as _missing_snapshot_tail_record_8616,
)
lazy from inertia.cli.tail_validation import (
    _tail_record_identity_8616 as _tail_record_identity_8616,
)
lazy from inertia.cli.tail_validation import (
    build_x86_16_tail_validation_aggregate as build_x86_16_tail_validation_aggregate,
)
lazy from inertia.cli.tail_validation import (
    cache_x86_16_tail_validation_detail_artifact as cache_x86_16_tail_validation_detail_artifact,
)
lazy from inertia.cli.tail_validation import (
    collect_tail_validation_records as collect_tail_validation_records,
)
lazy from inertia.cli.tail_validation import (
    emit_tail_validation_console_summary as emit_tail_validation_console_summary,
)
lazy from inertia.cli.tail_validation import (
    emit_tail_validation_surface_summary as emit_tail_validation_surface_summary,
)
lazy from inertia.cli.tail_validation import (
    extract_x86_16_tail_validation_snapshot as extract_x86_16_tail_validation_snapshot,
)
lazy from inertia.cli.tail_validation import (
    format_tail_validation_diagnostic as format_tail_validation_diagnostic,
)
lazy from inertia.cli.tail_validation import (
    inherit_tail_validation_runtime_policy as inherit_tail_validation_runtime_policy,
)
lazy from inertia.cli.tail_validation import (
    parse_env_bool as parse_env_bool,
)
lazy from inertia.cli.tail_validation import (
    render_x86_16_tail_validation_console_summary as render_x86_16_tail_validation_console_summary,
)
lazy from inertia.cli.tail_validation import (
    set_tail_validation_runtime_enabled as set_tail_validation_runtime_enabled,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_cache_label as tail_validation_cache_label,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_console_cache_path as tail_validation_console_cache_path,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_detail_cache_path as tail_validation_detail_cache_path,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_display_status as tail_validation_display_status,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_enabled_for_run as tail_validation_enabled_for_run,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_fallback_allows_project_snapshot as tail_validation_fallback_allows_project_snapshot,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_record_for_result as tail_validation_record_for_result,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_runtime_enabled as tail_validation_runtime_enabled,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_snapshot_for_fallback as tail_validation_snapshot_for_fallback,
)
lazy from inertia.cli.tail_validation import (
    tail_validation_snapshot_for_function_run as tail_validation_snapshot_for_function_run,
)
lazy from inertia.cli.work_items import (
    FunctionDecompileResult as FunctionDecompileResult,
)
lazy from inertia.cli.work_items import (
    FunctionDecompileTask as FunctionDecompileTask,
)
lazy from inertia.cli.work_items import (
    TailValidationDisplayOutcome as TailValidationDisplayOutcome,
)
lazy from inertia.cli.work_items import (
    _diagnostic_print as _diagnostic_print,
)
lazy from inertia.cli.work_items import (
    _tail_validation_to_item_status as _tail_validation_to_item_status,
)
lazy from inertia.cli.work_items import (
    _visible_source_format as _visible_source_format,
)
lazy from inertia.cli.work_items import (
    _work_item_status_display as _work_item_status_display,
)
lazy from inertia.cli.work_items import (
    emit_tail_validation_for_function_run_or_uncollected as emit_tail_validation_for_function_run_or_uncollected,
)
lazy from inertia.cli.work_items import (
    emit_tail_validation_snapshot_or_uncollected as emit_tail_validation_snapshot_or_uncollected,
)
lazy from inertia.cli.work_items import (
    function_attempt_display_status as function_attempt_display_status,
)
lazy from inertia.cli.work_items import (
    lst_metadata_content_digest_8616 as lst_metadata_content_digest_8616,
)
lazy from inertia.cli.work_items import (
    normalize_tail_validation_status as normalize_tail_validation_status,
)
lazy from inertia.cli.work_items import (
    print_function_attempt_status as print_function_attempt_status,
)
lazy from inertia.cli.work_items import (
    recovery_evidence_line as recovery_evidence_line,
)
lazy from inertia.frontend.x86_16.cod_extract import (
    join_cod_entries_with_synthetic_globals as join_cod_entries_with_synthetic_globals,
)
lazy from inertia.lowering.access_profiles import (
    AccessTraitEvidenceProfile as AccessTraitEvidenceProfile,
)
lazy from inertia.lowering.access_profiles import (
    AccessTraitEvidenceProfile as _AccessTraitEvidenceProfile,
)
lazy from inertia.lowering.access_profiles import (
    AccessTraitInductionVar as AccessTraitInductionVar,
)
lazy from inertia.lowering.access_profiles import (
    AccessTraitRewriteDecision as AccessTraitRewriteDecision,
)
lazy from inertia.lowering.access_profiles import (
    AccessTraitStrideEvidence as AccessTraitStrideEvidence,
)
lazy from inertia.lowering.access_profiles import (
    AccessTraitStrideEvidence as _AccessTraitStrideEvidence,
)
lazy from inertia.lowering.access_profiles import (
    InductionSummary as InductionSummary,
)
lazy from inertia.lowering.access_profiles import (
    NamingCandidate as NamingCandidate,
)
lazy from inertia.lowering.access_profiles import (
    _add_access_trait_bucket_8616 as _add_access_trait_bucket_8616,
)
lazy from inertia.lowering.access_profiles import (
    _add_access_trait_structured_bucket_8616 as _add_access_trait_structured_bucket_8616,
)
lazy from inertia.lowering.access_profiles import (
    _decoded_bucket_candidate_8616 as _decoded_bucket_candidate_8616,
)
lazy from inertia.lowering.access_profiles import (
    _raw_profile_entry_8616 as _raw_profile_entry_8616,
)
lazy from inertia.lowering.access_profiles import (
    access_trait_member_candidates as access_trait_member_candidates,
)
lazy from inertia.lowering.access_profiles import (
    access_trait_profile_for_key as access_trait_profile_for_key,
)
lazy from inertia.lowering.access_profiles import (
    build_access_trait_evidence_profiles as build_access_trait_evidence_profiles,
)
lazy from inertia.lowering.access_profiles import (
    infer_induction_summary as infer_induction_summary,
)
lazy from inertia.lowering.access_profiles import (
    infer_induction_variable as infer_induction_variable,
)
lazy from inertia.semantics.alias_query import (
    describe_alias_storage as describe_alias_storage,
)
lazy from inertia.widening.register_widening import (
    can_join_adjacent_register_slices as can_join_adjacent_register_slices,
)
lazy from inertia.widening.register_widening import (
    join_adjacent_register_slices as join_adjacent_register_slices,
)
lazy from inertia.widening.widening_model import (
    analyze_adjacent_storage_slices as analyze_adjacent_storage_slices,
)


def _normalized_high_slice_expr(current_high_expr: object) -> object:
    """Unwrap one Mul/Shl high-byte scale wrapper into its inner view."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

    from .cli_c_ast_rewrites import _c_constant_value, _unwrap_c_casts

    if isinstance(current_high_expr, CBinaryOp) and current_high_expr.op in {"Mul", "Shl"}:
        for maybe_inner, maybe_scale in (
            (current_high_expr.lhs, current_high_expr.rhs),
            (current_high_expr.rhs, current_high_expr.lhs),
        ):
            scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
            if scale not in {8, 0x100}:
                continue
            return _unwrap_c_casts(maybe_inner)
    return current_high_expr


def _joinable_register_pair_proof(analysis: object) -> object | None:
    """Return the widening proof when its register-pair versions agree."""
    # Dynamic codegen boundary: widening proof shape comes from X86_16 analysis helpers.
    proof = getattr(analysis, "proof", None)
    if proof is None:
        return None
    # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
    if getattr(proof, "register_pair", None) is None:
        return None
    # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
    if getattr(proof, "left_version", None) is None or getattr(proof, "right_version", None) is None:
        return None
    # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
    if getattr(proof, "left_version", None) != getattr(proof, "right_version", None):
        return None
    # Dynamic boundary: proof is an analysis-owned object read through getattr.
    return cast(object, proof)


def _match_adjacent_register_pair_impl(
    low_expr: object,
    high_expr: object,
    codegen: object,
) -> object | None:
    """Join two proven adjacent byte slices into one widened expression."""
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimRegisterVariable

    from inertia.widening.widening_model import analyze_adjacent_storage_slices

    from .cli_c_ast_rewrites import _get_or_seed_inertia_alias_state

    current_low_expr = low_expr
    current_high_expr = _normalized_high_slice_expr(high_expr)
    if not isinstance(current_low_expr, CVariable) or not isinstance(current_high_expr, CVariable):
        return None
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    low_var = getattr(current_low_expr, "variable", None)
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    high_var = getattr(current_high_expr, "variable", None)
    if not isinstance(low_var, SimRegisterVariable) or not isinstance(high_var, SimRegisterVariable):
        return None
    # Dynamic codegen boundary: SimRegisterVariable slice size comes from angr variable metadata.
    if getattr(low_var, "size", None) != 1 or getattr(high_var, "size", None) != 1:
        return None
    alias_state = _get_or_seed_inertia_alias_state(codegen)
    if alias_state is None:
        return None
    analysis = analyze_adjacent_storage_slices(current_low_expr, current_high_expr, alias_state=alias_state)
    if not analysis.ok:
        return None
    proof = _joinable_register_pair_proof(analysis)
    if proof is None:
        return None
    if not _register_widening_8616.can_join_adjacent_register_slices(
        current_low_expr, current_high_expr, alias_state=alias_state, proof=proof
    ):
        return None
    return _register_widening_8616.join_adjacent_register_slices(
        current_low_expr, current_high_expr, codegen, alias_state=alias_state, proof=proof
    )


def _match_adjacent_register_pair_var_expr(low_expr: object, high_expr: object, codegen: object) -> object | None:
    # Compatibility surface for legacy tests and callers importing from decompile/cli.
    return _match_adjacent_register_pair_impl(low_expr, high_expr, codegen)


_CLI_COMPAT_OWNER_MODULES: tuple[str, ...] = (
    "inertia.cli.cli_core",
    "inertia.cli.cli_function_discovery",
    "inertia.cli.cli_decompilation",
    "inertia.cli.cli_fallback_decompilation",
    "inertia.cli.cli_c_ast_rewrites",
    "inertia.cli.cli_c_text_postprocess",
    "inertia.cli.cli_interrupt_modeling",
    "inertia.cli.cache",
    "inertia.lowering.access_profiles",
    "inertia.cli.non_optimized_fallback",
    "inertia.cli.disassembly_helpers",
    "inertia.cli.project_loading",
    "inertia.cli.runtime_support",
    "inertia.cli.sidecar_metadata",
    "inertia.cli.sidecar_parsers",
    "inertia.cli.tail_validation",
    "inertia.cli.work_items",
)


class _CompatModule(ModuleType):
    """Legacy monkeypatch write-through for the native lazy facade.

    This is a compatibility mutation contract, not lazy import resolution:
    assigning a known compatibility export eagerly loads every canonical
    owner and mirrors the value wherever that owner already defines the
    name, so later native lazy reads observe the override.
    """

    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        """Mirror a known compatibility export write into every canonical owner."""
        known = name in self.__dict__
        ModuleType.__setattr__(self, name, value)
        if not known or name.startswith("__") or name == "main":
            return
        for owner_name in _CLI_COMPAT_OWNER_MODULES:
            if name == "_recovery_code_labels" and owner_name.endswith("sidecar_metadata"):
                continue
            owner = import_module(owner_name)
            if name in owner.__dict__:
                ModuleType.__setattr__(owner, name, value)


_THIS_MODULE = sys.modules[__name__]
_THIS_MODULE.__class__ = _CompatModule


__all__: tuple[str, ...] = (
    "SimMemoryVariable",
    "SimRegisterVariable",
    "SimStackVariable",
    "SimTypePointer",
    "SimTypeShort",
    "_AccessTraitEvidenceProfile",
    "_AccessTraitStrideEvidence",
    "_addr_exprs_are_byte_pair",
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_classify_segmented_addr_expr",
    "_coalesce_cod_word_global_loads",
    "_coalesce_direct_ss_local_word_statements",
    "_coalesce_far_pointer_stack_expressions",
    "_coalesce_linear_recurrence_statements",
    "_coalesce_segmented_word_load_expressions",
    "_coalesce_segmented_word_store_statements",
    "_linear_disassembly",
    "_make_word_dereference_from_addr_expr",
    "_match_adjacent_register_pair_var_expr",
    "_match_byte_load_addr_expr",
    "_match_byte_store_addr_expr",
    "_match_duplicate_word_increment_shift_expr",
    "_match_shift_right_8_expr",
    "_match_shifted_high_byte_addr_expr",
    "_match_ss_local_plus_const",
    "_match_word_rhs_from_byte_pair",
    "_materialize_missing_stack_local_declarations",
    "_probe_lift_break",
    "_resolve_stack_cvar_from_addr_expr",
    "_rewrite_ss_stack_byte_offsets",
    "_same_c_expression",
    "_seed_adjacent_byte_pair_aliases",
    "_simplify_x86_16_conditions",
    "_simplify_x86_16_stack_byte_pointers",
    "_stack_slot_identity_can_join",
    "analyze_adjacent_storage_slices",
    "can_join_adjacent_register_slices",
    "describe_alias_storage",
    "join_adjacent_register_slices",
    "main",
    "structured_c",
)


if __name__ == "__main__":
    raise SystemExit(main())
