# AUTO-GENERATED split from cli_runtime_shared.py
"""Layer: CLI/fallback/reporting.

Responsibility: coordinate legacy AST cleanup helpers around already-recovered facts.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
Required Lowering conversions survive unless Lowering proves identity against
the emitted declaration; copies retain their class, types and evidence tags.
Dynamic attribute boundary: getattr/setattr use here is limited to third-party
angr/codegen compatibility objects and optional diagnostic metadata.
"""

from __future__ import annotations

import contextlib
import copy
import logging
import re
from collections.abc import Callable, Iterable, Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimVariable
from angr_platforms.X86_16.alias.alias_model_impl import (
    _CopyAliasState,
    _derived_stack_high_byte_follows_slot,
    _stack_slot_identity_for_variable,
    _StackPointerAliasState,
)
from angr_platforms.X86_16.alias.state import AliasState
from angr_platforms.X86_16.alias_domains import DomainKey, register_pair_name
from angr_platforms.X86_16.analysis_helpers import (
    collect_dos_int21_calls,
    collect_interrupt_service_calls,
    dos_helper_declarations,
    interrupt_service_addr,
    interrupt_service_name,
    preferred_known_helper_signature_decl,
    render_dos_int21_call,
    render_interrupt_call,
)
from angr_platforms.X86_16.annotations import _normalize_bp_disp
from angr_platforms.X86_16.c_ast_utils import _structured_codegen_node_8616
from angr_platforms.X86_16.cod_extract import CODProcMetadata
from angr_platforms.X86_16.cod_source_rewrites import rewrite_cod_proc_from_source as _rewrite_cod_proc_from_source
from angr_platforms.X86_16.lowering.c_runtime_header import (
    interrupt_helper_declarations_8616,
)
from angr_platforms.X86_16.lowering.segmented_lowering import _SegmentedAccess
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616, is_identity_semantic_variable_cast_8616
from angr_platforms.X86_16.lst_extract import LSTMetadata
from angr_platforms.X86_16.postprocess.bitwise_terms import flatten_bitwise_terms_8616
from angr_platforms.X86_16.semantics.alias_query import (
    _storage_domain_for_expr,
    describe_alias_storage,
)
from angr_platforms.X86_16.widening.register_widening import (
    can_join_adjacent_register_slices,
    join_adjacent_register_slices,
)
from angr_platforms.X86_16.widening_model import analyze_adjacent_storage_slices

from inertia_decompiler import cli_access_object_hints as _cli_access_object_hints
from inertia_decompiler import cli_access_profiles as _cli_access_profiles
from inertia_decompiler import cli_access_rewrite_artifact as _cli_access_rewrite_artifact
from inertia_decompiler import cli_access_trait_rewrite as _cli_access_trait_rewrite
from inertia_decompiler import cli_access_traits as _cli_access_traits
from inertia_decompiler import cli_cod_global_statements as _cli_cod_global_statements
from inertia_decompiler import cli_cod_globals as _cli_cod_globals
from inertia_decompiler import cli_dead_local_prune as _cli_dead_local_prune
from inertia_decompiler import cli_far_pointer_stack as _cli_far_pointer_stack
from inertia_decompiler import cli_helper_modeling as _cli_helper_modeling
from inertia_decompiler import cli_linear_aliases as _cli_linear_aliases
from inertia_decompiler import cli_linear_recurrence as _cli_linear_recurrence
from inertia_decompiler import cli_linear_recurrence_rules as _cli_linear_recurrence_rules
from inertia_decompiler import cli_local_prune as _cli_local_prune
from inertia_decompiler import cli_local_rewrites as _cli_local_rewrites
from inertia_decompiler import cli_memory_prune as _cli_memory_prune
from inertia_decompiler import cli_mkfp_simplify as _cli_mkfp_simplify
from inertia_decompiler import cli_segmented as _cli_segmented
from inertia_decompiler import cli_segmented_compare as _cli_segmented_compare
from inertia_decompiler import cli_segmented_elision as _cli_segmented_elision
from inertia_decompiler import cli_segmented_load_coalesce as _cli_segmented_load_coalesce
from inertia_decompiler import cli_segmented_lowering as _cli_segmented_lowering
from inertia_decompiler import cli_segmented_store_coalesce as _cli_segmented_store_coalesce
from inertia_decompiler import cli_stack_byte_offsets as _cli_stack_byte_offsets
from inertia_decompiler import cli_stack_coalesce as _cli_stack_coalesce
from inertia_decompiler import cli_stack_cvars as _cli_stack_cvars
from inertia_decompiler import cli_stack_locals as _cli_stack_locals
from inertia_decompiler import cli_word_global_helpers as _cli_word_global_helpers
from inertia_decompiler import cli_word_loads as _cli_word_loads
from inertia_decompiler.cli_access_profiles import AccessTraitStrideEvidence as _AccessTraitStrideEvidence
from inertia_decompiler.cli_output import (
    _timestamped_print,
)
from inertia_decompiler.sidecar_metadata import (
    _lst_data_label,
)

# angr's structured-C node classes and attributes vary across supported
# versions. Keep that third-party dynamism explicit and confined to this AST
# compatibility module; owned CLI state and evidence contracts remain concrete.
type StructuredAstValue = Any
type StructuredCodegenValue = Any
type AngrProjectValue = Any

type _AccessTraitEvidenceProfile = _cli_access_profiles.AccessTraitEvidenceProfile


def _compat_callback(callback: Callable[..., object]) -> StructuredAstValue:
    """Adapt a callable across version-varying split-helper protocols."""
    return callback


print: Callable[..., None] = _timestamped_print
__all__ = [
    "_AccessTraitRewriteDecision",
    "_CODSourceRewriteSpec",
    "_WideningMatch",
    "_access_trait_field_name",
    "_access_trait_member_candidates",
    "_access_trait_profile_for_key",
    "_access_trait_variable_key",
    "_addr_exprs_are_byte_pair",
    "_addr_exprs_are_same",
    "_analyze_widening_expr",
    "_attach_access_trait_field_names",
    "_attach_cod_callee_names",
    "_attach_cod_global_declaration_names",
    "_attach_cod_global_declaration_types",
    "_attach_cod_global_names",
    "_attach_cod_variable_names",
    "_attach_lst_data_names",
    "_attach_pointer_member_names",
    "_attach_register_names",
    "_attach_segment_register_names",
    "_attach_ss_stack_variables",
    "_build_access_trait_evidence_profiles",
    "_build_cod_positive_bp_alias_map",
    "_c_constant_value",
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_cite_is_negation",
    "_classify_segmented_addr_expr",
    "_classify_segmented_dereference",
    "_clone_structured_c_value",
    "_coalesce_cod_word_global_loads",
    "_coalesce_cod_word_global_statements",
    "_coalesce_direct_ss_local_word_statements",
    "_coalesce_far_pointer_stack_expressions",
    "_coalesce_linear_recurrence_statements",
    "_coalesce_segmented_word_load_expressions",
    "_coalesce_segmented_word_store_statements",
    "_cod_stack_alias_for_disp",
    "_collect_access_traits",
    "_dedupe_codegen_variable_names_8616",
    "_dos_helper_declarations",
    "_elide_redundant_segment_pointer_dereferences",
    "_extract_dereference_addr_expr",
    "_extract_same_zero_compare_expr",
    "_extract_zero_flag_source_expr",
    "_flatten_c_add_terms",
    "_get_or_seed_inertia_alias_state",
    "_global_load_addr",
    "_global_memory_addr",
    "_high_byte_store_addr",
    "_int21_call_replacements",
    "_interrupt_call_replacement_map",
    "_interrupt_helper_declarations",
    "_invert_comparison_op",
    "_invert_interval_guard_if_safe",
    "_is_c_constant_int",
    "_is_staging_local_name",
    "_iter_c_nodes_deep",
    "_known_helper_declarations",
    "_make_inverted_comparison",
    "_make_unique_identifier",
    "_make_word_dereference_from_addr_expr",
    "_match_adjacent_register_pair_var_expr",
    "_match_byte_load_addr_expr",
    "_match_byte_store_addr_expr",
    "_match_duplicate_word_base_expr",
    "_match_duplicate_word_increment_shift_expr",
    "_match_high_byte_projection_base",
    "_match_high_byte_projection_constant",
    "_match_high_byte_projection_expr",
    "_match_real_mode_linear_expr",
    "_match_scaled_high_byte",
    "_match_segment_register_based_dereference",
    "_match_segmented_dereference",
    "_match_shift_right_8_expr",
    "_match_shifted_high_byte_addr_expr",
    "_match_ss_local_plus_const",
    "_match_ss_stack_reference",
    "_match_stack_cvar_and_offset",
    "_match_word_dereference_addr_expr",
    "_match_word_pair_low_addr_expr",
    "_match_word_rhs_from_byte_pair",
    "_materialize_missing_register_local_declarations",
    "_materialize_missing_stack_local_declarations",
    "_materialize_stack_cvar_at_offset",
    "_normalize_16bit_signed_offset",
    "_normalize_scalar_byte_register_types",
    "_project_rewrite_cache",
    "_promote_direct_stack_cvariable",
    "_prune_dead_local_assignments",
    "_prune_tiny_wrapper_staging_locals",
    "_prune_unused_linear_register_declarations",
    "_prune_unused_local_declarations",
    "_prune_unused_unnamed_memory_declarations",
    "_prune_void_function_return_values",
    "_replace_c_children",
    "_resolve_dirty_virtual_expr_8616",
    "_resolve_stack_cvar_at_offset",
    "_resolve_stack_cvar_from_addr_expr",
    "_rewrite_ss_stack_byte_offsets",
    "_run_typed_widening_pass",
    "_same_c_expression",
    "_same_c_storage",
    "_same_expression_list",
    "_same_stack_slot_identity",
    "_sanitize_cod_identifier",
    "_seed_adjacent_byte_pair_aliases",
    "_segment_reg_name",
    "_should_attach_access_trait_names",
    "_simplify_basic_algebraic_identities",
    "_simplify_boolean_expr",
    "_simplify_nested_mk_fp_calls",
    "_simplify_structured_c_expressions",
    "_simplify_zero_flag_comparison",
    "_simplify_zero_mul_or_expr",
    "_split_expr_const_offset",
    "_stack_object_name",
    "_stack_slot_identity_can_join",
    "_stack_type_for_size",
    "_strip_segment_scale_from_addr_expr",
    "_structured_codegen_node",
    "_synthetic_global_entry",
    "_synthetic_word_global_variable",
    "_unwrap_c_casts",
]


def _helper_name(project: AngrProjectValue, addr: int) -> str | None:
    proc = project.hooked_by(addr)
    if proc is None:
        return None
    name = getattr(proc, "INT_NAME", None)
    if isinstance(name, str) and name:
        return name
    name = getattr(proc, "display_name", None)
    if isinstance(name, str) and name:
        return name
    return cast(str, proc.__class__.__name__)


def _attach_cod_callee_names(
    project: AngrProjectValue, codegen: StructuredCodegenValue, cod_metadata: CODProcMetadata | None
) -> bool:
    return False


def _build_cod_positive_bp_alias_map(bp_disps: list[int], cod_metadata: CODProcMetadata | None) -> dict[int, str]:
    def _impl() -> dict[int, str]:
        if cod_metadata is None:
            return {}
        cast_aliases = cod_metadata.stack_aliases

        meta_positive = sorted((disp, name) for disp, name in cast_aliases.items() if isinstance(disp, int) and isinstance(name, str) and disp > 0)
        if not meta_positive:
            return {}

        var_positive = sorted(disp for disp in bp_disps if disp > 0)
        if not var_positive:
            return {}

        alias_map: dict[int, str] = {}
        for disp in var_positive:
            direct = cast_aliases.get(disp)
            if direct is not None:
                alias_map[disp] = direct

        unmatched_var_positive = [disp for disp in var_positive if disp not in alias_map]
        unused_meta_positive = [item for item in meta_positive if item[1] not in alias_map.values()]
        if len(unmatched_var_positive) <= len(unused_meta_positive):
            for disp, (_, name) in zip(unmatched_var_positive, unused_meta_positive, strict=False):
                alias_map[disp] = name

        return alias_map

    return _impl()


def _cod_stack_alias_for_disp(
    disp: int,
    cod_metadata: CODProcMetadata | None,
    *,
    argument_aliases: dict[int, str] | None = None,
    positive_aliases: dict[int, str] | None = None,
    normalized_aliases: dict[int, str] | None = None,
) -> str | None:
    """Resolve a bp-relative disp to a COD alias by source priority."""

    if cod_metadata is None:
        return None
    cast_aliases = cod_metadata.stack_aliases

    alias_sources: list[dict[int, str] | None] = [argument_aliases]
    if disp < 0:
        alias_sources.append(cast_aliases)
    alias_sources.append(normalized_aliases)
    if disp > 0:
        alias_sources.append(positive_aliases)
    alias_sources.append(cast_aliases)
    for source in alias_sources:
        if source is not None:
            alias = source.get(disp)
            if alias is not None:
                return alias
    return None


def _build_cod_normalized_bp_alias_map(cod_metadata: CODProcMetadata | None) -> dict[int, str]:
    if cod_metadata is None:
        return {}
    aliases = cod_metadata.stack_aliases
    normalized: dict[int, str] = {}
    for bp_disp, alias in aliases.items():
        if isinstance(bp_disp, int) and isinstance(alias, str) and alias:
            normalized.setdefault(_normalize_bp_disp(bp_disp), alias)
    return normalized


def _collect_cod_name_ownership(codegen: StructuredCodegenValue) -> tuple[set[str], dict[str, int]]:
    def _impl() -> tuple[set[str], dict[str, int]]:
        used_names: set[str] = set()
        name_owner_offsets: dict[str, int] = {}
        variables_in_use = getattr(codegen.cfunc, "variables_in_use", {})
        for variable, cvar in variables_in_use.items():
            if _stack_slot_identity_for_variable(variable) is None:
                continue
            current_name = getattr(variable, "name", None)
            if isinstance(current_name, str) and current_name:
                offset = getattr(variable, "offset", None)
                if not isinstance(offset, int) or offset not in {0, 2}:
                    used_names.add(current_name)
                    name_owner_offsets[current_name] = offset if isinstance(offset, int) else 0
            unified = getattr(cvar, "unified_variable", None)
            unified_name = getattr(unified, "name", None)
            if isinstance(unified_name, str) and unified_name:
                offset = getattr(variable, "offset", None)
                if not isinstance(offset, int) or offset not in {0, 2}:
                    used_names.add(unified_name)
                    name_owner_offsets[unified_name] = offset if isinstance(offset, int) else 0
        return used_names, name_owner_offsets

    return _impl()


def _ordered_stack_identity_variables(codegen: StructuredCodegenValue) -> list[tuple[object, object]]:
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", {})
    return sorted(
        [
            (variable, cvar)
            for variable, cvar in variables_in_use.items()
            if _stack_slot_identity_for_variable(variable) is not None
        ],
        key=lambda item: (
            0 if isinstance(getattr(item[0], "offset", None), int) and getattr(item[0], "offset", 0) > 0 else 1,
            getattr(item[0], "offset", 0) if isinstance(getattr(item[0], "offset", 0), int) else 0,
            -getattr(item[0], "size", 0) if isinstance(getattr(item[0], "size", 0), int) else 0,
            getattr(item[0], "name", "") or "",
        )
    )


def _ordered_stack_identity_nodes(codegen: StructuredCodegenValue) -> list[tuple[object, object]]:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return []
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        variables_in_use = {}
        cfunc.variables_in_use = variables_in_use

    nodes: dict[tuple[object, object, object], tuple[object, object]] = {}
    for variable, cvar in variables_in_use.items():
        if _stack_slot_identity_for_variable(variable) is None:
            continue
        nodes[
            (
                getattr(variable, "offset", None),
                getattr(variable, "size", None),
                getattr(variable, "base", None),
            )
        ] = (variable, cvar)

    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    for node in _iter_c_nodes_deep(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = node.variable
        if not isinstance(variable, SimStackVariable):
            continue
        if _stack_slot_identity_for_variable(variable) is None:
            continue
        key = (
            variable.offset,
            variable.size,
            variable.base,
        )
        nodes.setdefault(key, (variable, node))
        if variable not in variables_in_use:
            variables_in_use[variable] = node

    return sorted(
        nodes.values(),
        key=lambda item: (
            0 if isinstance(getattr(item[0], "offset", None), int) and getattr(item[0], "offset", 0) > 0 else 1,
            getattr(item[0], "offset", 0) if isinstance(getattr(item[0], "offset", 0), int) else 0,
            -getattr(item[0], "size", 0) if isinstance(getattr(item[0], "size", 0), int) else 0,
            getattr(item[0], "name", "") or "",
        ),
    )


def _apply_generic_unified_name_for_param_slot(
    variable: StructuredAstValue, cvar: StructuredAstValue, cod_metadata: CODProcMetadata | None
) -> bool:
    def _impl() -> bool:
        disp = getattr(variable, "offset", None)
        if not (isinstance(disp, int) and disp in {0, 2}):
            return False
        if cod_metadata is not None and disp in cod_metadata.stack_aliases:
            return False
        changed = False
        unified = getattr(cvar, "unified_variable", None)
        unified_name = getattr(unified, "name", None)
        if isinstance(unified_name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", unified_name):
            if getattr(variable, "name", None) != unified_name:
                variable.name = unified_name
                changed = True
            if unified is not None and getattr(unified, "name", None) != unified_name:
                unified.name = unified_name
                changed = True
            if getattr(cvar, "name", None) != unified_name:
                try:
                    cvar.name = unified_name
                except Exception:
                    pass
                else:
                    changed = True
        return changed

    return _impl()


def _resolve_alias_collision_name(
    alias: str,
    disp: int | None,
    used_names: set[str],
    name_owner_offsets: dict[str, int],
) -> str:
    if alias not in used_names:
        used_names.add(alias)
        name_owner_offsets[alias] = disp if isinstance(disp, int) else 0
        return alias
    owner_offset = name_owner_offsets.get(alias)
    if owner_offset == disp:
        used_names.add(alias)
        name_owner_offsets[alias] = disp if isinstance(disp, int) else 0
        return alias
    if isinstance(disp, int) and disp > 2 and owner_offset in {0, 2}:
        used_names.add(alias)
        name_owner_offsets[alias] = disp
        return alias
    alias = _make_unique_identifier(alias, used_names)
    name_owner_offsets[alias] = disp if isinstance(disp, int) else 0
    return alias


def _attach_cod_variable_names(codegen: StructuredCodegenValue, cod_metadata: CODProcMetadata | None) -> bool:
    return False


def _synthetic_global_entry(
    synthetic_globals: dict[int, tuple[str, int]] | None, addr: int | None
) -> tuple[str, int] | None:
    if not synthetic_globals or not isinstance(addr, int):
        return None
    entry = synthetic_globals.get(addr)
    if entry is None:
        return None
    if isinstance(entry, tuple):
        return entry
    return entry, 1


def _sanitize_cod_identifier(name: str) -> str:
    name = name.lstrip("_")
    if name.startswith("$") and "_" in name:
        name = name.rsplit("_", 1)[-1]
    name = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not name:
        return "data"
    if name[0].isdigit():
        return f"g_{name}"
    return name


def _seed_alias_state_from_registers_8616(alias_state: AliasState, cfunc: structured_c.CFunction) -> bool:
    """Seed register-domain aliases from cfunc variables; return seeded."""

    seeded = False
    for variable in getattr(cfunc, "variables_in_use", {}):
        if not isinstance(variable, SimRegisterVariable):
            continue
        pair_name = register_pair_name(variable.name)
        if pair_name is None:
            reg = variable.reg
            size = variable.size or 0
            if isinstance(reg, int) and size in {1, 2}:
                pair_names = ("ax", "cx", "dx", "bx")
                pair_index = reg // 2
                if 0 <= pair_index < len(pair_names):
                    pair_name = pair_names[pair_index]
        if pair_name is None:
            continue
        alias_state.bump_domain(DomainKey("reg", pair_name.upper()))
        seeded = True
    return seeded


def _get_or_seed_inertia_alias_state(codegen: StructuredCodegenValue) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        alias_state = getattr(codegen, "_inertia_alias_state", None)
        if alias_state is None:
            alias_state = getattr(getattr(codegen, "cfunc", None), "_inertia_alias_state", None)
        if alias_state is not None:
            return alias_state

        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return None

        alias_state = AliasState()
        seeded = _seed_alias_state_from_registers_8616(alias_state, cfunc)

        if not seeded:
            return None
        codegen._inertia_alias_state = alias_state
        with contextlib.suppress(AttributeError):
            cfunc._inertia_alias_state = alias_state
        return alias_state

    return _impl()


def _make_unique_identifier(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _structured_codegen_node(value: StructuredAstValue) -> bool:
    """Consume the shared AST boundary, including owned semantic node subclasses."""
    return bool(_structured_codegen_node_8616(value))


def _class_slot_names_8616(value: StructuredAstValue) -> list[str]:
    """Collect public non-codegen slot names across the class hierarchy."""

    attrs: list[str] = []
    for cls in type(value).mro():
        slots = getattr(cls, "__slots__", ())
        if not slots:
            continue
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if isinstance(slot, str) and not slot.startswith("_") and slot != "codegen":
                attrs.append(slot)
    return attrs


def _structured_slot_names_8616(value: StructuredAstValue) -> tuple[str, ...]:
    def _impl() -> tuple[str, ...]:
        if type(value) is object:
            return ()
        attrs = _class_slot_names_8616(value)

        if hasattr(value, "__dict__"):
            attrs.extend(
                attr
                for attr in value.__dict__
                if isinstance(attr, str) and not attr.startswith("_") and attr != "codegen"
            )

        # Preserve deterministic traversal order and avoid duplicates when
        # inherited slots repeat between classes.
        seen = set()
        ordered: list[str] = []
        for attr in attrs:
            if attr in seen:
                continue
            seen.add(attr)
            ordered.append(attr)
        return tuple(ordered)

    return _impl()


def _push_iterable_children_8616(current: StructuredAstValue, stack: list[StructuredAstValue]) -> None:
    """Push container/iterable children into the DFS stack."""

    if isinstance(current, (str, bytes)):
        return
    if isinstance(current, dict):
        with contextlib.suppress(Exception):
            stack.extend(tuple(current.values()))
        return
    if isinstance(current, (list, tuple, set)):
        with contextlib.suppress(Exception):
            stack.extend(tuple(current))
        return
    if hasattr(current, "__iter__"):
        with contextlib.suppress(Exception):
            stack.extend(tuple(current))


def _iter_c_node_children_8616(value: StructuredAstValue, seen_values: set[int] | None = None) -> tuple[StructuredAstValue, ...]:
    def _impl() -> tuple[StructuredAstValue, ...]:
        nonlocal seen_values
        if seen_values is None:
            seen_values = set()

        collected: list[StructuredAstValue] = []
        stack = [value]
        while stack:
            current = stack.pop()
            try:
                current_id = id(current)
            except Exception:
                continue
            if current_id in seen_values:
                continue
            seen_values.add(current_id)

            if _structured_codegen_node(current):
                collected.append(current)
                continue

            _push_iterable_children_8616(current, stack)

        return tuple(collected)

    return _impl()


def _c_constant_value(node: StructuredAstValue) -> int | None:
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _normalize_16bit_signed_offset(offset: object) -> int:
    if not isinstance(offset, int):
        raise TypeError("segmented address offset must be an integer")
    wrapped = offset & 0xFFFF
    if wrapped >= 0x8000:
        return wrapped - 0x10000
    return wrapped


def _storage_size_from_type_bits(bits: object, project: AngrProjectValue) -> int:
    """Return a concrete byte size from an optional angr type width."""
    byte_width = getattr(project.arch, "byte_width", 8)
    if not isinstance(bits, int) or bits <= 0 or not isinstance(byte_width, int) or byte_width <= 0:
        return 1
    return max(bits // byte_width, 1)


def _project_rewrite_cache(project: AngrProjectValue) -> MutableMapping[str, MutableMapping[int, object]]:
    cache = getattr(project, "_inertia_rewrite_cache", None)
    if cache is None:
        cache = {}
        project._inertia_rewrite_cache = cache
    return cast(MutableMapping[str, MutableMapping[int, object]], cache)


class _CODSourceRewriteSpec:
    """Describe one legacy COD-backed source rewrite specification."""

    name: str
    header_regex: str
    rewritten: str
    required_lines: tuple[str, ...] = ()

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        """Apply this rewrite through the quarantined legacy source boundary."""
        return str(
            _rewrite_cod_proc_from_source(
            c_text,
            metadata,
            header_regex=self.header_regex,
            rewritten=self.rewritten,
            required_lines=self.required_lines,
        )
        )


def _segment_reg_name(node: StructuredAstValue, project: AngrProjectValue) -> str | None:
    return cast(
        str | None,
        _cli_segmented._segment_reg_name(node, project, project_rewrite_cache=_project_rewrite_cache),
    )


def _classify_segmented_addr_expr(node: StructuredAstValue, project: AngrProjectValue) -> _SegmentedAccess | None:
    return _cli_segmented._classify_segmented_addr_expr(
        node,
        project,
        project_rewrite_cache=_project_rewrite_cache,
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        match_stack_cvar_and_offset=_match_stack_cvar_and_offset,
        normalize_16bit_signed_offset=_normalize_16bit_signed_offset,
        stack_slot_identity_for_variable=_stack_slot_identity_for_variable,
    )


def _classify_segmented_dereference(node: StructuredAstValue, project: AngrProjectValue) -> _SegmentedAccess | None:
    return _cli_segmented._classify_segmented_dereference(
        node,
        project,
        project_rewrite_cache=_project_rewrite_cache,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
    )


def _match_real_mode_linear_expr(node: StructuredAstValue, project: AngrProjectValue) -> tuple[str | None, int | None]:
    return cast(
        tuple[str | None, int | None],
        _cli_segmented._match_real_mode_linear_expr(
            node,
            project,
            project_rewrite_cache=_project_rewrite_cache,
            classify_segmented_addr_expr=_classify_segmented_addr_expr,
        ),
    )


def _match_segmented_dereference(node: StructuredAstValue, project: AngrProjectValue) -> tuple[str | None, int | None]:
    return cast(
        tuple[str | None, int | None],
        _cli_segmented._match_segmented_dereference(
            node,
            project,
            project_rewrite_cache=_compat_callback(_project_rewrite_cache),
            classify_segmented_dereference=_compat_callback(_classify_segmented_dereference),
        ),
    )


def _match_segment_register_based_dereference(
    node: StructuredAstValue, project: AngrProjectValue
) -> StructuredAstValue:
    return _cli_segmented_lowering._match_segment_register_based_dereference(
        node,
        project,
        classify_segmented_dereference=_compat_callback(_classify_segmented_dereference),
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        segment_reg_name=_segment_reg_name,
    )


def _strip_segment_scale_from_addr_expr(addr_expr: StructuredAstValue, project: AngrProjectValue) -> StructuredAstValue:
    return _cli_segmented_lowering._strip_segment_scale_from_addr_expr(
        addr_expr,
        project,
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        segment_reg_name=_segment_reg_name,
    )


def _match_ss_stack_reference(node: StructuredAstValue, project: AngrProjectValue) -> StructuredAstValue:
    return _cli_segmented_lowering._match_ss_stack_reference(
        node,
        project,
        project_rewrite_cache=_project_rewrite_cache,
        classify_segmented_dereference=_classify_segmented_dereference,
    )


def _flatten_c_add_terms(node: StructuredAstValue, seen: set[int] | None = None) -> StructuredAstValue:
    if seen is None:
        seen = set()
    key = id(node)
    if key in seen:
        return [node]
    seen.add(key)
    if isinstance(node, structured_c.CTypeCast):
        return _flatten_c_add_terms(node.expr, seen)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_c_add_terms(node.lhs, seen) + _flatten_c_add_terms(node.rhs, seen)
    return [node]


def _resolve_dirty_virtual_expr_8616(node: StructuredAstValue) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        dirty = getattr(node, "dirty", None)
        if dirty is None:
            return None
        varid = getattr(dirty, "varid", None)
        if not isinstance(varid, int):
            return None
        codegen = getattr(node, "codegen", None)
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            return None

        target_name = f"vvar_{varid}"
        matches = []
        for stmt in _iter_c_nodes_deep(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs = stmt.lhs
            if not isinstance(lhs, structured_c.CVariable):
                continue
            lhs_name = lhs.name or getattr(lhs.variable, "name", None)
            if lhs_name != target_name:
                continue
            matches.append(stmt.rhs)
            if len(matches) > 1:
                return None
        return matches[0] if len(matches) == 1 else None

    return _impl()


def _stack_cvar_base_8616(variable: object, node: StructuredAstValue) -> StructuredAstValue:
    """Return (node, 0) when the variable is a stack slot."""

    if isinstance(variable, SimStackVariable) and _stack_slot_identity_for_variable(variable) is not None:
        return node, 0
    return None


def _stack_cvar_binary_8616(node: StructuredAstValue, seen: set[int]) -> StructuredAstValue:
    """Match ``base +/- const`` over a stack cvar."""

    lhs = _match_stack_cvar_and_offset(node.lhs, seen)
    rhs = _match_stack_cvar_and_offset(node.rhs, seen)
    lhs_const = _c_constant_value(_unwrap_c_casts(node.lhs))
    rhs_const = _c_constant_value(_unwrap_c_casts(node.rhs))

    if lhs is not None and rhs_const is not None:
        base, offset = lhs
        return base, _normalize_16bit_signed_offset(offset + (rhs_const if node.op == "Add" else -rhs_const))
    if rhs is not None and lhs_const is not None:
        base, offset = rhs
        return base, _normalize_16bit_signed_offset(offset + lhs_const)
    return None


def _stack_cvar_indexed_8616(node: StructuredAstValue, seen: set[int]) -> StructuredAstValue:
    """Match an indexed stack cvar plus constant offset."""

    base = _match_stack_cvar_and_offset(node.variable, seen)
    index = _c_constant_value(_unwrap_c_casts(node.index))
    if base is None or index is None:
        return None
    base_cvar, offset = base
    return base_cvar, _normalize_16bit_signed_offset(offset + index)


def _match_stack_cvar_and_offset(node: StructuredAstValue, _seen: set[int] | None = None) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        nonlocal _seen, node
        if _seen is None:
            _seen = set()
        node = _unwrap_c_casts(node)
        key = id(node)
        if key in _seen:
            return None
        _seen.add(key)

        resolved_dirty = _resolve_dirty_virtual_expr_8616(node)
        if resolved_dirty is not None:
            return _match_stack_cvar_and_offset(resolved_dirty, _seen)

        if isinstance(node, structured_c.CVariable):
            return _stack_cvar_base_8616(node.variable, node)

        if isinstance(node, structured_c.CIndexedVariable):
            return _stack_cvar_indexed_8616(node, _seen)

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
            operand = _unwrap_c_casts(node.operand)
            if isinstance(operand, structured_c.CVariable):
                return _stack_cvar_base_8616(operand.variable, operand)
            return None

        if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
            return _stack_cvar_binary_8616(node, _seen)

        return None

    return _impl()


def _match_ss_local_plus_const(node: StructuredAstValue, project: AngrProjectValue) -> StructuredAstValue:
    cache = _project_rewrite_cache(project).setdefault("ss_local_plus_const", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = _classify_segmented_dereference(node, project)
    if classified is None or classified.kind != "stack" or classified.cvar is None:
        cache[key] = None
        return None
    extra_offset = _normalize_16bit_signed_offset(classified.extra_offset)
    result = (classified.cvar, extra_offset)
    cache[key] = (classified.cvar, extra_offset)
    return result


_CHILD_SCALAR_ATTRS = (
    "lhs",
    "rhs",
    "expr",
    "operand",
    "addr",
    "data",
    "guard",
    "condition",
    "cond",
    "initializer",
    "iterator",
    "body",
    "iffalse",
    "iftrue",
    "callee_target",
    "else_node",
    "retval",
)
_CHILD_LIST_ATTRS = ("args", "operands", "statements")


def _replace_scalar_child_attrs(
    current: StructuredAstValue,
    transform: StructuredAstValue,
    node_stack: list[object],
    *,
    should_process_child: Callable[[StructuredAstValue, str], bool] | None = None,
) -> bool:
    changed = False
    for attr in _CHILD_SCALAR_ATTRS:
        if not hasattr(current, attr):
            continue
        if callable(should_process_child) and not should_process_child(current, attr):
            continue
        try:
            value = getattr(current, attr)
        except Exception:
            _AST_REWRITE_LOGGER.warning(
                "cli_c_ast_rewrites._replace_c_children: failed to read node attribute %s on %r",
                attr,
                current,
                exc_info=True,
            )
            continue
        if not _structured_codegen_node(value):
            continue
        new_value = transform(value)
        if new_value is not value:
            setattr(current, attr, new_value)
            changed = True
            continue
        node_stack.append(value)
    return changed


def _replace_one_list_attr_8616(
    current: StructuredAstValue,
    attr: str,
    transform: StructuredAstValue,
    node_stack: list[object],
) -> bool:
    """Transform items of one list attr; return whether it changed."""

    try:
        items = getattr(current, attr)
    except Exception:
        _AST_REWRITE_LOGGER.debug(
            "cli_c_ast_rewrites._replace_c_children: failed to read iterable node attribute %s on %r",
            attr,
            current,
            exc_info=True,
        )
        return False
    if not items:
        return False
    new_items = []
    list_changed = False
    for item in items:
        if not _structured_codegen_node(item):
            new_items.append(item)
            continue
        new_item = transform(item)
        if new_item is not item:
            list_changed = True
        if new_item is item and _structured_codegen_node(new_item):
            node_stack.append(new_item)
        new_items.append(new_item)
    if list_changed:
        setattr(current, attr, new_items)
    return list_changed


def _replace_list_child_attrs(
    current: StructuredAstValue,
    transform: StructuredAstValue,
    node_stack: list[object],
    *,
    should_process_child: Callable[[StructuredAstValue, str], bool] | None = None,
) -> bool:
    def _impl() -> bool:
        changed = False
        for attr in _CHILD_LIST_ATTRS:
            if not hasattr(current, attr):
                continue
            if callable(should_process_child) and not should_process_child(current, attr):
                continue
            if _replace_one_list_attr_8616(current, attr, transform, node_stack):
                changed = True
        return changed

    return _impl()


def _transform_condition_pairs_8616(
    pairs: Iterable[tuple[object, object]], transform: StructuredAstValue, node_stack: list[object]
) -> tuple[list[object], bool]:
    """Transform each (cond, body) pair; return (new_pairs, changed)."""

    new_pairs: list[object] = []
    pair_changed = False
    for cond, body in pairs:
        new_cond = transform(cond) if _structured_codegen_node(cond) else cond
        new_body = transform(body) if _structured_codegen_node(body) else body
        if new_cond is not cond or new_body is not body:
            pair_changed = True
        if new_cond is cond and _structured_codegen_node(new_cond):
            node_stack.append(new_cond)
        if new_body is body and _structured_codegen_node(new_body):
            node_stack.append(new_body)
        new_pairs.append((new_cond, new_body))
    return new_pairs, pair_changed


def _replace_condition_pairs(
    current: StructuredAstValue,
    transform: StructuredAstValue,
    node_stack: list[object],
    *,
    should_process_child: Callable[[StructuredAstValue, str], bool] | None = None,
) -> bool:
    def _impl() -> bool:
        if callable(should_process_child) and not should_process_child(current, "condition_and_nodes"):
            return False
        if not hasattr(current, "condition_and_nodes"):
            return False
        try:
            pairs = current.condition_and_nodes
        except Exception:
            _AST_REWRITE_LOGGER.debug(
                "cli_c_ast_rewrites._replace_c_children: failed to read condition_and_nodes on %r",
                current,
                exc_info=True,
            )
            return False
        if not pairs:
            return False
        new_pairs, pair_changed = _transform_condition_pairs_8616(pairs, transform, node_stack)
        if not pair_changed:
            return False
        current.condition_and_nodes = new_pairs
        return True

    return _impl()


def _replace_c_children(
    node: StructuredAstValue,
    transform: StructuredAstValue,
    seen: set[int] | None = None,
    *,
    should_process_child: Callable[[StructuredAstValue, str], bool] | None = None,
) -> bool:
    if seen is None:
        seen = set()
    if not _structured_codegen_node(node):
        return False

    node_stack: list[object] = [node]
    changed = False
    while node_stack:
        current = node_stack.pop()
        if not _structured_codegen_node(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        scalar_changed = _replace_scalar_child_attrs(
            current,
            transform,
            node_stack,
            should_process_child=should_process_child,
        )
        list_changed = _replace_list_child_attrs(
            current,
            transform,
            node_stack,
            should_process_child=should_process_child,
        )
        pair_changed = _replace_condition_pairs(
            current,
            transform,
            node_stack,
            should_process_child=should_process_child,
        )
        changed = changed or scalar_changed or list_changed or pair_changed

    return changed


def _iter_c_nodes_deep(node: StructuredAstValue, seen: set[int] | None = None) -> StructuredAstValue:
    if seen is None:
        seen = set()
    if not _structured_codegen_node(node):
        return
    # Iterative walk avoids recursion overflow on degenerate structured-IR inputs.
    node_stack = [node]
    while node_stack:
        current = node_stack.pop()
        if not _structured_codegen_node(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        for attr in _structured_slot_names_8616(current):
            try:
                value = getattr(current, attr)
            except Exception:
                continue
            for item in _iter_c_node_children_8616(value, set()):
                if _structured_codegen_node(item):
                    node_stack.append(item)


def _same_c_function_call_8616(
    lhs: StructuredAstValue, rhs: StructuredAstValue, seen_pairs: set[tuple[int, int]]
) -> bool:
    """Compare callee identity and args of two function calls."""

    if lhs.callee_target != getattr(rhs, "callee_target", None):
        return False
    if lhs.callee_func != getattr(rhs, "callee_func", None):
        return False
    lhs_args = list(lhs.args or ())
    rhs_args = list(getattr(rhs, "args", ()) or ())
    if len(lhs_args) != len(rhs_args):
        return False
    return all(
        _same_c_expression(larg, rarg, seen_pairs)
        for larg, rarg in zip(lhs_args, rhs_args, strict=False)
    )


def _same_c_dirty_expr_8616(lhs: StructuredAstValue, rhs: StructuredAstValue) -> bool:
    """Compare dirty-expression payloads by their identifying fields."""

    lhs_dirty = getattr(lhs, "dirty", None)
    rhs_dirty = getattr(rhs, "dirty", None)
    for attr in ("varid", "idx", "reg_offset", "reg", "bits"):
        lhs_value = getattr(lhs_dirty, attr, None)
        rhs_value = getattr(rhs_dirty, attr, None)
        if lhs_value is not None or rhs_value is not None:
            return lhs_value == rhs_value
    return getattr(lhs, "idx", None) == getattr(rhs, "idx", None)


def _same_c_variable_8616(lhs: StructuredAstValue, rhs: StructuredAstValue) -> bool:
    """Compare variables by register/stack/memory identity."""

    lvar = lhs.variable
    rvar = getattr(rhs, "variable", None)
    if type(lvar) is not type(rvar):
        return False
    if isinstance(lvar, SimRegisterVariable):
        return bool(lvar.reg == getattr(rvar, "reg", None))
    if isinstance(lvar, SimStackVariable):
        return bool(
            lvar.base == getattr(rvar, "base", None)
            and lvar.offset == getattr(rvar, "offset", None)
            and lvar.size == getattr(rvar, "size", None)
        )
    if isinstance(lvar, SimMemoryVariable):
        return bool(lvar.addr == getattr(rvar, "addr", None) and lvar.size == getattr(rvar, "size", None))
    return lvar == rvar


def _same_c_expression(
    lhs: StructuredAstValue, rhs: StructuredAstValue, seen_pairs: set[tuple[int, int]] | None = None
) -> bool:
    """Compare two C expressions structurally with cycle protection."""

    if type(lhs) is not type(rhs):
        return False
    if seen_pairs is None:
        seen_pairs = set()
    pair = (id(lhs), id(rhs))
    if pair in seen_pairs:
        return True
    seen_pairs.add(pair)
    return _same_c_expr_payload_8616(lhs, rhs, seen_pairs)


def _same_c_expr_payload_8616(
    lhs: StructuredAstValue, rhs: StructuredAstValue, seen_pairs: set[tuple[int, int]]
) -> bool:
    """Compare same-typed expression payloads by node kind."""

    if isinstance(lhs, structured_c.CConstant):
        return bool(lhs.value == rhs.value)

    if isinstance(lhs, structured_c.CTypeCast):
        return _same_c_expression(lhs.expr, rhs.expr, seen_pairs)

    if isinstance(lhs, structured_c.CUnaryOp):
        return lhs.op == rhs.op and _same_c_expression(lhs.operand, rhs.operand, seen_pairs)

    if isinstance(lhs, structured_c.CBinaryOp):
        return (
            lhs.op == rhs.op
            and _same_c_expression(lhs.lhs, rhs.lhs, seen_pairs)
            and _same_c_expression(lhs.rhs, rhs.rhs, seen_pairs)
        )

    if isinstance(lhs, structured_c.CFunctionCall):
        return _same_c_function_call_8616(lhs, rhs, seen_pairs)

    if type(lhs).__name__ == "CDirtyExpression":
        return _same_c_dirty_expr_8616(lhs, rhs)

    if isinstance(lhs, structured_c.CVariable):
        return _same_c_variable_8616(lhs, rhs)

    return lhs is rhs

def _same_c_storage(lhs: StructuredAstValue, rhs: StructuredAstValue) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False

    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    if type(lvar) is not type(rvar):
        return False

    if isinstance(lvar, SimRegisterVariable):
        return bool(lvar.reg == getattr(rvar, "reg", None))
    if isinstance(lvar, SimStackVariable):
        return bool(
            lvar.base == getattr(rvar, "base", None)
            and lvar.offset == getattr(rvar, "offset", None)
        )
    if isinstance(lvar, SimMemoryVariable):
        return bool(lvar.addr == getattr(rvar, "addr", None))
    return lvar == rvar


def _same_stack_slot_identity_var(lhs_var: StructuredAstValue, rhs_var: StructuredAstValue) -> bool:
    lhs_identity = _stack_slot_identity_for_variable(lhs_var)
    rhs_identity = _stack_slot_identity_for_variable(rhs_var)
    return bool(lhs_identity is not None and rhs_identity is not None and lhs_identity == rhs_identity)


def _stack_slot_identity_can_join_var(lhs_var: StructuredAstValue, rhs_var: StructuredAstValue) -> bool:
    lhs_identity = _stack_slot_identity_for_variable(lhs_var)
    rhs_identity = _stack_slot_identity_for_variable(rhs_var)
    if lhs_identity is None or rhs_identity is None:
        return False
    return bool(lhs_identity.can_join(rhs_identity))


def _same_stack_slot_identity(lhs: StructuredAstValue, rhs: StructuredAstValue) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    return _same_stack_slot_identity_var(lvar, rvar)


def _stack_slot_identity_can_join(lhs: StructuredAstValue, rhs: StructuredAstValue) -> bool:
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lvar = getattr(lhs, "variable", None)
    rvar = getattr(rhs, "variable", None)
    return _stack_slot_identity_can_join_var(lvar, rvar)


def _derived_stack_high_byte_follows_cvar(
    address_base: StructuredAstValue,
    address_byte_offset: int,
    low_byte: StructuredAstValue,
) -> bool:
    """Adapt structured CVariables to the Alias-owned derived-byte proof."""
    if not isinstance(address_base, structured_c.CVariable) or not isinstance(low_byte, structured_c.CVariable):
        return False
    return bool(
        _derived_stack_high_byte_follows_slot(
            address_base.variable,
            address_byte_offset,
            low_byte.variable,
        )
    )


def _is_c_constant_int(node: StructuredAstValue, value: int) -> bool:
    return isinstance(node, structured_c.CConstant) and isinstance(node.value, int) and node.value == value


def _cite_is_negation(node: StructuredAstValue) -> bool:
    return type(node).__name__ == "CITE" and _is_c_constant_int(node.iftrue, 0) and _is_c_constant_int(node.iffalse, 1)


def _invert_comparison_op(op: str) -> str | None:
    return {
        "==": "!=",
        "!=": "==",
        ">": "<=",
        "<": ">=",
        ">=": "<",
        "<=": ">",
    }.get(op)


def _make_inverted_comparison(node: StructuredAstValue, codegen: StructuredCodegenValue) -> StructuredAstValue:
    if not isinstance(node, structured_c.CBinaryOp):
        return None
    inverted = _invert_comparison_op(node.op)
    if inverted is None:
        return None
    return structured_c.CBinaryOp(
        inverted,
        node.lhs,
        node.rhs,
        type=node.type,
        codegen=codegen,
        tags=node.tags,
    )


def _invert_interval_guard_if_safe(node: StructuredAstValue, codegen: StructuredCodegenValue) -> StructuredAstValue:
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "LogicalAnd":
        return None

    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)
    if not isinstance(lhs, structured_c.CBinaryOp) or not isinstance(rhs, structured_c.CBinaryOp):
        return None

    if lhs.op not in {">", ">=", "CmpGT", "CmpGE"}:
        return None
    if rhs.op not in {"<", "<=", "CmpLT", "CmpLE"}:
        return None
    if not _same_c_expression(lhs.rhs, rhs.rhs):
        return None

    inverted_lhs = _make_inverted_comparison(lhs, codegen)
    inverted_rhs = _make_inverted_comparison(rhs, codegen)
    if inverted_lhs is None or inverted_rhs is None:
        return None
    return structured_c.CBinaryOp(
        "LogicalAnd",
        inverted_lhs,
        inverted_rhs,
        codegen=codegen,
        tags=getattr(node, "tags", None),
    )


def _extract_same_zero_compare_expr(node: StructuredAstValue) -> StructuredAstValue:
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "CmpEQ":
        return None

    if _is_c_constant_int(node.rhs, 0):
        return node.lhs
    if _is_c_constant_int(node.lhs, 0):
        return node.rhs
    return None


def _extract_mul_zero_flag_source_8616(node: StructuredAstValue) -> StructuredAstValue:
    """Match ``x*64`` forms carrying same-zero compare sources."""

    pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
    for maybe_logic, maybe_scale in pairs:
        if not _is_c_constant_int(maybe_scale, 64):
            continue
        source_expr = _extract_same_zero_compare_expr(maybe_logic)
        if source_expr is not None:
            return source_expr
        if not isinstance(maybe_logic, structured_c.CBinaryOp) or maybe_logic.op != "LogicalAnd":
            continue
        lhs_expr = _extract_same_zero_compare_expr(maybe_logic.lhs)
        rhs_expr = _extract_same_zero_compare_expr(maybe_logic.rhs)
        if lhs_expr is not None and rhs_expr is not None and _same_c_expression(lhs_expr, rhs_expr):
            return lhs_expr
    return None


def _extract_child_zero_flag_source_8616(node: StructuredAstValue, attrs: tuple[str, ...]) -> StructuredAstValue:
    """Recurse into the first structured child attr carrying a flag source."""

    for attr in attrs:
        child = getattr(node, attr, None)
        if _structured_codegen_node(child):
            extracted = _extract_zero_flag_source_expr(child)
            if extracted is not None:
                return extracted
    return None


def _extract_zero_flag_source_expr(node: StructuredAstValue) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        if isinstance(node, structured_c.CBinaryOp):
            if node.op == "Mul":
                extracted = _extract_mul_zero_flag_source_8616(node)
                if extracted is not None:
                    return extracted
            return _extract_child_zero_flag_source_8616(node, ("lhs", "rhs"))

        if isinstance(node, structured_c.CUnaryOp):
            return _extract_child_zero_flag_source_8616(node, ("operand",))

        if isinstance(node, structured_c.CTypeCast):
            return _extract_child_zero_flag_source_8616(node, ("expr",))

        return None

    return _impl()


def _simplify_zero_flag_comparison(node: object, codegen: StructuredCodegenValue) -> object:
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return node

    if _is_c_constant_int(node.rhs, 0):
        expr = node.lhs
    elif _is_c_constant_int(node.lhs, 0):
        expr = node.rhs
    else:
        return node

    source_expr = _extract_zero_flag_source_expr(expr)
    if source_expr is None:
        return node
    source_expr = _restore_not_shift_zero_flag_source(source_expr, codegen)

    if node.op == "CmpEQ":
        return source_expr

    if not isinstance(source_expr, structured_c.CExpression):
        return node
    return structured_c.CUnaryOp("Not", source_expr, codegen=codegen)


def _restore_not_shift_zero_flag_source(source_expr: object, codegen: StructuredCodegenValue) -> object:
    source_expr = _unwrap_c_casts(source_expr)
    if not isinstance(source_expr, structured_c.CBinaryOp) or source_expr.op not in {"Shr", "Sar"}:
        return source_expr
    lhs = _unwrap_c_casts(getattr(source_expr, "lhs", None))
    if not isinstance(lhs, structured_c.CUnaryOp) or lhs.op != "Not":
        return source_expr
    restored_shift = structured_c.CBinaryOp(
        source_expr.op,
        getattr(lhs, "operand", None),
        getattr(source_expr, "rhs", None),
        codegen=codegen,
        tags=getattr(source_expr, "tags", None),
    )
    return structured_c.CUnaryOp(
        "Not",
        restored_shift,
        codegen=codegen,
        tags=getattr(lhs, "tags", None) or getattr(source_expr, "tags", None),
    )


def _match_high_byte_projection_base(expr: StructuredAstValue) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        nonlocal expr
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
            return None
        if _c_constant_value(_unwrap_c_casts(expr.rhs)) != 8:
            return None
        inner = _unwrap_c_casts(expr.lhs)
        if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Or":
            return None
        for maybe_const, maybe_other in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
            const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
            other = _unwrap_c_casts(maybe_other)
            if const_value is None or const_value & 0xFF:
                continue
            if isinstance(other, structured_c.CBinaryOp) and other.op == "And":
                lhs_mask = _c_constant_value(_unwrap_c_casts(other.lhs))
                rhs_mask = _c_constant_value(_unwrap_c_casts(other.rhs))
                if lhs_mask == 0xFF or rhs_mask == 0xFF:
                    return other
        return None

    return _impl()


def _adjacent_pair_scaled_high_8616(high_expr: StructuredAstValue) -> StructuredAstValue:
    """Unwrap ``x*8``/``x*0x100``/``x<<8`` scale on the high expr."""

    if isinstance(high_expr, structured_c.CBinaryOp) and high_expr.op in {"Mul", "Shl"}:
        for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
            scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
            if scale not in {8, 0x100}:
                continue
            return _unwrap_c_casts(maybe_inner)
    return high_expr


def _adjacent_pair_reg_vars_8616(low_expr: StructuredAstValue, high_expr: StructuredAstValue) -> bool:
    """Return whether both exprs are size-1 register variables."""

    if not isinstance(low_expr, structured_c.CVariable) or not isinstance(high_expr, structured_c.CVariable):
        return False
    low_var = getattr(low_expr, "variable", None)
    high_var = getattr(high_expr, "variable", None)
    if not isinstance(low_var, SimRegisterVariable) or not isinstance(high_var, SimRegisterVariable):
        return False
    return getattr(low_var, "size", None) == 1 and getattr(high_var, "size", None) == 1


def _adjacent_pair_proof_ok_8616(analysis: object) -> bool:
    """Validate the adjacent-slices analysis proof fields."""

    proof = getattr(analysis, "proof", None)
    if proof is None:
        return False
    if getattr(proof, "register_pair", None) is None:
        return False
    if getattr(proof, "left_version", None) is None or getattr(proof, "right_version", None) is None:
        return False
    return getattr(proof, "left_version", None) == getattr(proof, "right_version", None)


def _match_adjacent_register_pair_var_expr(
    low_expr: StructuredAstValue, high_expr: StructuredAstValue, codegen: StructuredCodegenValue
) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        nonlocal high_expr
        high_expr = _adjacent_pair_scaled_high_8616(high_expr)
        if not _adjacent_pair_reg_vars_8616(low_expr, high_expr):
            return None
        alias_state = _get_or_seed_inertia_alias_state(codegen)
        if alias_state is None:
            return None
        analysis = analyze_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
        if not analysis.ok or not _adjacent_pair_proof_ok_8616(analysis):
            return None
        proof = analysis.proof
        if not can_join_adjacent_register_slices(low_expr, high_expr, alias_state=alias_state, proof=proof):
            return None
        return join_adjacent_register_slices(low_expr, high_expr, codegen, alias_state=alias_state, proof=proof)

    return _impl()


def _match_high_byte_projection_expr(expr: StructuredAstValue) -> StructuredAstValue:
    expr = _unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
        return None
    if _c_constant_value(_unwrap_c_casts(expr.rhs)) != 8:
        return None
    inner = _unwrap_c_casts(expr.lhs)
    if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "And":
        return None
    lhs_mask = _c_constant_value(_unwrap_c_casts(inner.lhs))
    rhs_mask = _c_constant_value(_unwrap_c_casts(inner.rhs))
    if lhs_mask == 0xFF00 or rhs_mask == 0xFF00:
        return expr
    return None


def _high_byte_const_and_arm_8616(node: StructuredAstValue) -> StructuredAstValue:
    """Unwrap ``x & 0xFF`` and recurse for the high-byte constant."""

    for maybe_inner, maybe_mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _c_constant_value(_unwrap_c_casts(maybe_mask)) == 0xFF:
            inner_val = _match_high_byte_projection_constant(maybe_inner)
            if inner_val is not None:
                return inner_val
    return None


def _high_byte_const_shr_arm_8616(node: StructuredAstValue) -> StructuredAstValue:
    """Match ``(const | (y & 0xFF)) >> 8`` to its projected byte constant."""

    shift = _c_constant_value(_unwrap_c_casts(node.rhs))
    inner = _unwrap_c_casts(node.lhs)
    if shift != 8 or not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Or":
        return None
    for maybe_const, maybe_other in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
        const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
        other = _unwrap_c_casts(maybe_other)
        if const_value is None or const_value & 0xFF:
            continue
        if isinstance(other, structured_c.CBinaryOp) and other.op == "And":
            lhs_mask = _c_constant_value(_unwrap_c_casts(other.lhs))
            rhs_mask = _c_constant_value(_unwrap_c_casts(other.rhs))
            if lhs_mask == 0xFF or rhs_mask == 0xFF:
                return (const_value >> 8) & 0xFF
    return None


def _match_high_byte_projection_constant(node: StructuredAstValue) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        nonlocal node
        node = _unwrap_c_casts(node)
        if isinstance(node, structured_c.CBinaryOp) and node.op == "And":
            inner_val = _high_byte_const_and_arm_8616(node)
            if inner_val is not None:
                return inner_val
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
            return None
        return _high_byte_const_shr_arm_8616(node)

    return _impl()


def _boolean_not_operand_arm_8616(node: StructuredAstValue, codegen: StructuredCodegenValue) -> StructuredAstValue:
    """Simplify ``Not operand`` shapes; None means no rewrite."""

    operand = _unwrap_c_casts(node.operand)
    if isinstance(operand, structured_c.CUnaryOp) and operand.op == "Not":
        return operand.operand
    if isinstance(operand, structured_c.CBinaryOp) and operand.op == "And":
        return structured_c.CBinaryOp(
            "CmpEQ",
            operand,
            structured_c.CConstant(
                0,
                operand.type or SimTypeShort(False),
                codegen=codegen,
            ),
            codegen=codegen,
            tags=node.tags,
        )
    if isinstance(operand, structured_c.CBinaryOp) and operand.op == "Sub":
        lhs_const = _c_constant_value(_unwrap_c_casts(operand.lhs))
        rhs_const = _c_constant_value(_unwrap_c_casts(operand.rhs))
        if rhs_const is not None:
            return structured_c.CBinaryOp(
                "CmpEQ",
                operand.lhs,
                structured_c.CConstant(
                    rhs_const,
                    getattr(operand.rhs, "type", None) or operand.type or SimTypeShort(False),
                    codegen=codegen,
                ),
                codegen=codegen,
                tags=node.tags,
            )
        if lhs_const is not None:
            return structured_c.CBinaryOp(
                "CmpEQ",
                operand.rhs,
                structured_c.CConstant(
                    lhs_const,
                    getattr(operand.lhs, "type", None) or operand.type or SimTypeShort(False),
                    codegen=codegen,
                ),
                codegen=codegen,
                tags=node.tags,
            )
    if isinstance(operand, structured_c.CBinaryOp):
        return _make_inverted_comparison(operand, codegen)
    return None


def _simplify_boolean_expr(node: StructuredAstValue, codegen: StructuredCodegenValue) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Not":
            rewritten = _boolean_not_operand_arm_8616(node, codegen)
            if rewritten is not None:
                return rewritten

        simplified = _simplify_zero_flag_comparison(node, codegen)
        if simplified is not node:
            return simplified

        if (
            isinstance(node, structured_c.CUnaryOp)
            and node.op == "Not"
            and isinstance(node.operand, structured_c.CITE)
            and _cite_is_negation(node.operand)
        ):
            inverted = _make_inverted_comparison(node.operand.cond, codegen)
            return inverted if inverted is not None else node.operand.cond

        interval_guard = _invert_interval_guard_if_safe(node, codegen)
        if interval_guard is not None:
            return interval_guard

        if isinstance(node, structured_c.CITE) and _cite_is_negation(node):
            cond = node.cond
            inverted = _make_inverted_comparison(cond, codegen)
            if inverted is not None:
                return inverted

        return node

    return _impl()


def _simplify_zero_mul_or_expr(node: StructuredAstValue, codegen: StructuredCodegenValue) -> StructuredAstValue:
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return node

    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)

    def is_zero_mul(expr: StructuredAstValue) -> StructuredAstValue:
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Mul":
            return False
        return _c_constant_value(_unwrap_c_casts(expr.lhs)) == 0 or _c_constant_value(_unwrap_c_casts(expr.rhs)) == 0

    if _c_constant_value(lhs) == 0:
        return node.rhs
    if _c_constant_value(rhs) == 0:
        return node.lhs
    if is_zero_mul(lhs):
        return node.rhs
    if is_zero_mul(rhs):
        return node.lhs
    return node


def _algebraic_pointer_shr_arm_8616(node: StructuredAstValue, codegen: StructuredCodegenValue) -> StructuredAstValue:
    """Cast ``&x >> 8`` pointer shifts to an explicit integer projection."""

    lhs_raw = _unwrap_c_casts(node.lhs)
    if not isinstance(lhs_raw, structured_c.CUnaryOp) or lhs_raw.op not in {"Reference", "AddressOf"}:
        return None
    cast_lhs = structured_c.CTypeCast(
        None,
        SimTypeShort(False),
        node.lhs,
        codegen=codegen,
    )
    return structured_c.CBinaryOp(
        "Shr",
        cast_lhs,
        node.rhs,
        codegen=codegen,
        tags=node.tags,
    )


def _algebraic_identity_transform_8616(node: StructuredAstValue, codegen: StructuredCodegenValue) -> StructuredAstValue:
    """Rewrite basic Xor/Sub/Add/Or/Shr identity arms on one node."""

    if not isinstance(node, structured_c.CBinaryOp):
        return node

    lhs = _unwrap_c_casts(node.lhs)
    rhs = _unwrap_c_casts(node.rhs)

    if node.op == "Xor" and _same_c_expression(lhs, rhs):
        type_ = (
            node.type
            or getattr(node.lhs, "type", None)
            or getattr(node.rhs, "type", None)
            or SimTypeShort(False)
        )
        return structured_c.CConstant(0, type_, codegen=codegen)

    if node.op == "Sub" and _c_constant_value(rhs) == 0:
        return node.lhs

    if node.op in {"Add", "Or"}:
        if _c_constant_value(lhs) == 0:
            return node.rhs
        if _c_constant_value(rhs) == 0:
            return node.lhs

    # MS C (16-bit) rejects shifting raw pointer expressions (e.g. &x >> 8).
    # In the 16-bit pipeline these are high-byte projections of offset-like
    # values, so make the integer projection explicit at the AST layer.
    if node.op == "Shr" and _c_constant_value(rhs) == 8:
        rewritten = _algebraic_pointer_shr_arm_8616(node, codegen)
        if rewritten is not None:
            return rewritten

    high_byte_constant = _match_high_byte_projection_constant(node)
    if high_byte_constant is not None:
        type_ = (
            node.type
            or getattr(node.lhs, "type", None)
            or getattr(node.rhs, "type", None)
            or SimTypeChar()
        )
        return structured_c.CConstant(high_byte_constant, type_, codegen=codegen)

    return node


def _simplify_basic_algebraic_identities(codegen: StructuredCodegenValue) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node: StructuredAstValue) -> StructuredAstValue:
        return _algebraic_identity_transform_8616(node, codegen)

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True

    if _replace_c_children(root, transform):
        changed = True

    return changed


def _collect_protected_deref_expr_ids(root: StructuredAstValue) -> set[int]:
    protected_ids: set[int] = set()

    def _protect_addr_expr_nodes(expr: StructuredAstValue) -> None:
        if not _structured_codegen_node(expr):
            return
        for protected_node in _iter_c_nodes_deep(expr):
            protected_ids.add(id(protected_node))

    for walk_node in _iter_c_nodes_deep(root):
        if not isinstance(walk_node, structured_c.CUnaryOp) or walk_node.op != "Dereference":
            if isinstance(walk_node, structured_c.CFunctionCall):
                callee_target = walk_node.callee_target
                callee_func = walk_node.callee_func
                callee_name = callee_target if isinstance(callee_target, str) else getattr(callee_func, "name", None)
                if isinstance(callee_name, str) and callee_name in {
                    "SEG_PTR",
                    "SEG_U8",
                    "SEG_U16",
                    "SEG_U32",
                    "MEM_U8",
                    "MEM_U16",
                    "MEM_U32",
                }:
                    args = tuple(walk_node.args or ())
                    if len(args) >= 2:
                        _protect_addr_expr_nodes(args[1])
            continue
        _protect_addr_expr_nodes(_extract_dereference_addr_expr(walk_node))
    return protected_ids


def _is_linear_register_temp_var(cvar: StructuredAstValue) -> bool:
    return (
        isinstance(cvar, structured_c.CVariable)
        and isinstance(getattr(cvar, "name", None), str)
        and re.fullmatch(
            r"(?:v\d+|vvar_\d+|ir_\d+)",
            getattr(cvar, "name", ""),
        )
        is not None
    )


_SIMPLIFY_NO_MATCH_8616: object = object()

_CONST_FOLD_OPS_8616: Mapping[str, Callable[[int, int], int]] = {
    "Add": lambda lhs, rhs: lhs + rhs,
    "Sub": lambda lhs, rhs: lhs - rhs,
    "Mul": lambda lhs, rhs: lhs * rhs,
    "And": lambda lhs, rhs: lhs & rhs,
    "Or": lambda lhs, rhs: lhs | rhs,
    "Xor": lambda lhs, rhs: lhs ^ rhs,
    "Shl": lambda lhs, rhs: lhs << rhs,
    "Shr": lambda lhs, rhs: lhs >> rhs,
}


@dataclass
class _BinarySimplifyCtx8616:
    """Resolved operand context shared by the binary transform arms."""

    node: StructuredAstValue
    lhs: StructuredAstValue
    rhs: StructuredAstValue
    resolved: StructuredAstValue
    resolved_contains_dereference: bool
    storage_backed_source: bool



@dataclass
class _StructuredSimplifyRun8616:
    """Run state for the legacy structured-C simplification passes.

    Fields preserve the state the original nested implementation kept in
    closure variables: alias maps are rebuilt on every pass while the
    caches persist across the fixed-point iterations.
    """

    codegen: StructuredCodegenValue
    cfunc: Any = None
    protected_dereference_addr_expr_ids: set[int] = field(default_factory=set)
    variable_use_counts: dict[int, int] = field(default_factory=dict)
    high_byte_aliases: dict[int, int] = field(default_factory=dict)
    shift_extract_aliases: dict[int, tuple[object, int]] = field(default_factory=dict)
    mask_shift_aliases: dict[int, tuple[object, int, int]] = field(default_factory=dict)
    copy_aliases: dict[int, _CopyAliasState] = field(default_factory=dict)
    linear_aliases: dict[int, object] = field(default_factory=dict)
    dereference_backed_linear_temps: set[int] = field(default_factory=set)
    memory_backed_linear_temps: set[int] = field(default_factory=set)
    far_pointer_aliases: dict[int, object] = field(default_factory=dict)
    adjacent_byte_pair_cache: dict[tuple[int, int], object] = field(default_factory=dict)
    word_plus_minus_one_cache: dict[int, object] = field(default_factory=dict)

    @classmethod
    def build_8616(cls, codegen: StructuredCodegenValue) -> _StructuredSimplifyRun8616 | None:
        """Return a run only when the codegen exposes structured statements."""
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None or getattr(cfunc, "statements", None) is None:
            return None
        return cls(codegen=codegen, cfunc=cfunc)

    def __post_init__(self) -> None:
        """Seed protected-expression ids, use counts, and linear aliases."""
        self.protected_dereference_addr_expr_ids = _collect_protected_deref_expr_ids(getattr(self.cfunc, "statements", None))
        for walk_node in _iter_c_nodes_deep(self.cfunc.statements):
            if not isinstance(walk_node, structured_c.CVariable):
                continue
            variable = walk_node.variable
            if variable is not None:
                self.variable_use_counts[id(variable)] = self.variable_use_counts.get(id(variable), 0) + 1
        self._seed_linear_aliases_8616()

    def _seed_linear_aliases_8616(self) -> None:
        """Resolve linear word-delta temporaries to a fixed point before passes."""
        for _ in range(3):
            changed = False
            for walk_node in _iter_c_nodes_deep(self.codegen.cfunc.statements):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
                    walk_node.lhs, structured_c.CVariable
                ):
                    continue
                if not _is_linear_register_temp_var(walk_node.lhs):
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op not in {"Add", "Sub"}:
                    continue
                resolved_rhs = self._resolve_copy_alias_expr(rhs)
                linear_rhs = self._match_linear_word_delta_expr(resolved_rhs)
                if linear_rhs is None:
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                key = id(lhs_var)
                if self.linear_aliases.get(key) != linear_rhs:
                    self.linear_aliases[key] = linear_rhs
                    changed = True
            if not changed:
                break

    def run_8616(self) -> bool:
        """Run the fixed-point transform and dead-init pruning passes."""
        root = self.codegen.cfunc.statements
        changed = False
        for _ in range(3):
            iter_changed = False
            self.high_byte_aliases = self._collect_high_byte_temp_constants(root)
            self.shift_extract_aliases = self._collect_shift_extract_aliases(root)
            self.mask_shift_aliases = self._collect_mask_shift_aliases(root)
            self.copy_aliases = self._collect_copy_aliases(root)
            self.dereference_backed_linear_temps = self._collect_dereference_backed_linear_temps(root)
            self.memory_backed_linear_temps = self._collect_memory_backed_linear_temps(root)
            self.far_pointer_aliases = self._collect_far_pointer_stack_aliases(root)
            new_root = self.transform(root)
            if new_root is not root:
                self.codegen.cfunc.statements = new_root
                root = new_root
                iter_changed = True
            if _replace_c_children(root, self.transform):
                iter_changed = True
            if self.prune_dead_stack_address_inits(root):
                iter_changed = True
            changed |= iter_changed
            if not iter_changed:
                break
        return changed

    def _collect_high_byte_temp_constants(self, node: StructuredAstValue) -> StructuredAstValue:
        aliases: dict[int, int] = {}
        for walk_node in _iter_c_nodes_deep(node):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
                walk_node.lhs, structured_c.CVariable
            ):
                continue
            if not _is_linear_register_temp_var(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Or":
                continue
            for maybe_const, _maybe_other in ((rhs.lhs, rhs.rhs), (rhs.rhs, rhs.lhs)):
                const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
                if const_value is None or const_value & 0xFF:
                    continue
                aliases[id(getattr(walk_node.lhs, "variable", None))] = const_value >> 8
                break
        return aliases

    def _collect_shift_extract_aliases(self, node: StructuredAstValue) -> StructuredAstValue:
        aliases: dict[int, tuple[object, int]] = {}
        for walk_node in _iter_c_nodes_deep(node):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
                walk_node.lhs, structured_c.CVariable
            ):
                continue
            if not _is_linear_register_temp_var(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Shr":
                continue
            shift = _c_constant_value(_unwrap_c_casts(rhs.rhs))
            base = _unwrap_c_casts(rhs.lhs)
            if shift is None or not isinstance(shift, int):
                continue
            if not isinstance(base, structured_c.CBinaryOp) or base.op != "And":
                continue
            mask_lhs = _c_constant_value(_unwrap_c_casts(base.lhs))
            mask_rhs = _c_constant_value(_unwrap_c_casts(base.rhs))
            inner = None
            if mask_lhs == 0xFF00:
                inner = base.rhs
            elif mask_rhs == 0xFF00:
                inner = base.lhs
            if inner is None:
                continue
            aliases[id(getattr(walk_node.lhs, "variable", None))] = (inner, shift)
        return aliases

    def _mask_shift_alias_for_assignment_8616(
        self, walk_node: StructuredAstValue, aliases: dict[int, tuple[object, int, int]]
    ) -> tuple[int, tuple[object, int, int]] | None:
        """Match one assignment against the mask/shift alias forms."""
        if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
            walk_node.lhs, structured_c.CVariable
        ):
            return None
        if not _is_linear_register_temp_var(walk_node.lhs):
            return None
        lhs_var = getattr(walk_node.lhs, "variable", None)
        if lhs_var is None:
            return None
        rhs = _unwrap_c_casts(walk_node.rhs)
        alias = self._mask_shift_alias_for_rhs_8616(rhs, aliases)
        if alias is None:
            return None
        return id(lhs_var), alias

    def _mask_shift_alias_for_rhs_8616(
        self, rhs: StructuredAstValue, aliases: dict[int, tuple[object, int, int]]
    ) -> tuple[object, int, int] | None:
        """Match an assignment rhs against the mask or shift alias forms."""
        if isinstance(rhs, structured_c.CBinaryOp) and rhs.op == "And":
            lhs_const = _c_constant_value(_unwrap_c_casts(rhs.lhs))
            rhs_const = _c_constant_value(_unwrap_c_casts(rhs.rhs))
            if lhs_const is not None:
                return rhs.rhs, lhs_const, 0
            if rhs_const is not None:
                return rhs.lhs, rhs_const, 0
            return None
        if not isinstance(rhs, structured_c.CBinaryOp) or rhs.op != "Shr":
            return None
        shift = _c_constant_value(_unwrap_c_casts(rhs.rhs))
        shifted = _unwrap_c_casts(rhs.lhs)
        if not isinstance(shifted, structured_c.CVariable) or not isinstance(shift, int):
            return None
        parent = aliases.get(id(shifted.variable))
        if parent is None:
            return None
        base_expr, mask, base_shift = parent
        return base_expr, mask, base_shift + shift

    def _collect_mask_shift_aliases(self, node: StructuredAstValue) -> StructuredAstValue:
        aliases: dict[int, tuple[object, int, int]] = {}
        for _ in range(4):
            changed = False
            for walk_node in _iter_c_nodes_deep(node):
                match = self._mask_shift_alias_for_assignment_8616(walk_node, aliases)
                if match is None:
                    continue
                key, alias = match
                if aliases.get(key) != alias:
                    aliases[key] = alias
                    changed = True
            if not changed:
                break
        return aliases

    def _copy_alias_state_for_assignment_8616(
        self, walk_node: StructuredAstValue, aliases: dict[int, _CopyAliasState]
    ) -> tuple[int, _CopyAliasState] | None:
        """Match one assignment against the copy-alias form."""
        if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
            walk_node.lhs, structured_c.CVariable
        ):
            return None
        if not _is_linear_register_temp_var(walk_node.lhs):
            return None
        rhs = _unwrap_c_casts(walk_node.rhs)
        if not isinstance(rhs, structured_c.CVariable):
            return None
        lhs_var = getattr(walk_node.lhs, "variable", None)
        rhs_var = rhs.variable
        if lhs_var is None or rhs_var is None:
            return None
        rhs_domain = _storage_domain_for_expr(rhs)
        if rhs_domain.is_mixed():
            return None
        parent_state = aliases.get(id(rhs_var))
        rhs_state = _CopyAliasState(
            rhs_domain,
            parent_state.expr if parent_state is not None else rhs,
            needs_synthesis=parent_state.needs_synthesis if parent_state is not None else False,
        )
        return id(lhs_var), rhs_state

    def _collect_copy_aliases(self, node: StructuredAstValue) -> StructuredAstValue:
        aliases: dict[int, _CopyAliasState] = {}
        for _ in range(3):
            changed = False
            for walk_node in _iter_c_nodes_deep(node):
                match = self._copy_alias_state_for_assignment_8616(walk_node, aliases)
                if match is None:
                    continue
                key, rhs_state = match
                current = aliases.get(key)
                if current is None:
                    aliases[key] = rhs_state
                    changed = True
                    continue
                merged = current.merge(rhs_state)
                if merged != current:
                    aliases[key] = merged
                    changed = True
            if not changed:
                break
        return aliases

    def _extract_linear_delta(self, expr: object) -> tuple[object | None, int]:
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
            return None, int(expr.value)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
            return expr, 0

        left_base, left_delta = self._extract_linear_delta(expr.lhs)
        right_base, right_delta = self._extract_linear_delta(expr.rhs)
        if left_base is not None and right_base is not None:
            if _same_c_expression(left_base, right_base) and expr.op == "Add":
                return left_base, left_delta + right_delta
            return expr, 0
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Or":
            duplicate_word_base = _match_duplicate_word_base_expr(expr, self._resolve_copy_alias_expr)
            if duplicate_word_base is not None:
                return duplicate_word_base, 0
        return self._combine_linear_delta_8616(expr, left_base, left_delta, right_base, right_delta)

    def _combine_linear_delta_8616(
        self,
        expr: structured_c.CBinaryOp,
        left_base: StructuredAstValue,
        left_delta: int,
        right_base: StructuredAstValue,
        right_delta: int,
    ) -> tuple[object | None, int]:
        """Combine the operand deltas for the Add/Sub linear form."""
        if left_base is not None:
            if expr.op == "Add":
                return left_base, left_delta + right_delta
            return left_base, left_delta - right_delta
        if right_base is not None:
            if expr.op == "Add":
                return right_base, left_delta + right_delta
            return expr, 0
        if expr.op == "Add":
            return None, left_delta + right_delta
        return None, left_delta - right_delta

    def _fold_simple_add_constants(self, node: StructuredAstValue) -> StructuredAstValue:
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
            return node


        terms = self._collect_add_terms(node)
        if len(terms) > 8:
            return node
        const_total = 0
        const_type = None
        base_terms = []
        for term in terms:
            const_value = _c_constant_value(term)
            if const_value is not None:
                const_total += const_value
                const_type = const_type or getattr(term, "type", None)
                continue
            base_terms.append(term)

        if len(base_terms) != 1 or not terms:
            return node

        base_expr = base_terms[0]
        if const_total == 0:
            return base_expr

        if const_type is None:
            const_type = getattr(base_expr, "type", None) or getattr(node, "type", None) or SimTypeShort(False)
        return structured_c.CBinaryOp(
            "Add" if const_total > 0 else "Sub",
            base_expr,
            structured_c.CConstant(
                const_total if const_total > 0 else -const_total,
                const_type,
                codegen=getattr(node, "codegen", None),
            ),
            codegen=getattr(node, "codegen", None),
        )

    def _collect_add_terms(self, expr: StructuredAstValue) -> StructuredAstValue:
        terms = []
        stack = [_unwrap_c_casts(expr)]
        seen: set[int] = set()
        while stack:
            current = _unwrap_c_casts(stack.pop())
            key = id(current)
            if key in seen:
                terms.append(current)
                continue
            seen.add(key)
            if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
                stack.append(current.rhs)
                stack.append(current.lhs)
            else:
                terms.append(current)
        return terms

    def _build_linear_expr(self, 
        base_expr: StructuredAstValue, delta: StructuredAstValue, codegen: StructuredCodegenValue
    ) -> StructuredAstValue:
        if delta == 0:
            return base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        return structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )

    def _normalize_protected_add_constant_tail(self, node: StructuredAstValue) -> StructuredAstValue:
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
            return node
        lhs = _unwrap_c_casts(node.lhs)
        rhs = _unwrap_c_casts(node.rhs)
        if isinstance(lhs, structured_c.CBinaryOp) and lhs.op == "Add":
            lhs_lhs = _unwrap_c_casts(lhs.lhs)
            lhs_rhs = _unwrap_c_casts(lhs.rhs)
            if (
                _c_constant_value(lhs_rhs) is not None
                and _c_constant_value(rhs) is None
                and isinstance(rhs, structured_c.CBinaryOp)
            ):
                return structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp("Add", lhs_lhs, rhs, codegen=self.codegen),
                    lhs_rhs,
                    codegen=self.codegen,
                )
        return node

    def _alias_storage_key(self, expr: StructuredAstValue) -> StructuredAstValue:
        facts = describe_alias_storage(expr)
        return facts.identity

    def _chase_copy_alias_8616(self, current: StructuredAstValue, seen: set[int]) -> StructuredAstValue:
        """Follow inlinable copy aliases, cloning each inlined expression."""
        while isinstance(current, structured_c.CVariable):
            variable = getattr(current, "variable", None)
            if variable is None:
                break
            key = id(variable)
            if key in seen:
                break
            seen.add(key)
            alias = self.copy_aliases.get(key)
            if alias is None:
                storage_key = self._alias_storage_key(current)
                if storage_key is not None:
                    alias = self.copy_aliases.get(storage_key)
            if alias is None or not alias.can_inline():
                break
            # Inline a structural copy so later child rewrites do not mutate the
            # original statement that defined the alias.
            current = _unwrap_c_casts(_clone_structured_c_value(alias.expr))
        return current

    def _resolve_copy_alias_expr(self, node: StructuredAstValue, seen: set[int] | None = None) -> StructuredAstValue:
        current = _unwrap_c_casts(node)
        if seen is None:
            seen = set()
        current_key = id(current)
        if current_key in seen:
            return current
        seen.add(current_key)
        current = self._chase_copy_alias_8616(current, seen)
        if isinstance(current, structured_c.CTypeCast):
            inner = self._resolve_copy_alias_expr(current.expr, seen)
            if inner is not current.expr:
                # Preserve Lowering's conversion class, types and evidence.
                replacement = copy.copy(current)
                replacement.expr = inner
                return replacement
            return current
        if isinstance(current, structured_c.CUnaryOp):
            operand = self._resolve_copy_alias_expr(current.operand, seen)
            if operand is not current.operand:
                return structured_c.CUnaryOp(current.op, operand, codegen=current.codegen)
            return current
        if isinstance(current, structured_c.CBinaryOp):
            lhs = self._resolve_copy_alias_expr(current.lhs, seen)
            rhs = self._resolve_copy_alias_expr(current.rhs, seen)
            if lhs is not current.lhs or rhs is not current.rhs:
                return structured_c.CBinaryOp(current.op, lhs, rhs, codegen=current.codegen)
        return current

    def _expr_is_safe_inline_candidate(self, expr: StructuredAstValue) -> StructuredAstValue:
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return self._expr_is_safe_inline_candidate(expr.expr)
        if isinstance(expr, structured_c.CUnaryOp):
            return expr.op in {"Neg", "Not"} and self._expr_is_safe_inline_candidate(expr.operand)
        if isinstance(expr, structured_c.CBinaryOp):
            if expr.op not in {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr"}:
                return False
            return self._expr_is_safe_inline_candidate(expr.lhs) and self._expr_is_safe_inline_candidate(expr.rhs)
        return False

    def _expr_is_copy_alias_candidate(self, expr: StructuredAstValue) -> StructuredAstValue:
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, (structured_c.CConstant, structured_c.CVariable)):
            return True
        if isinstance(expr, structured_c.CTypeCast):
            return self._expr_is_copy_alias_candidate(expr.expr)
        return False

    def _expr_contains_dereference(self, expr: StructuredAstValue) -> bool:
        for walk_node in _iter_c_nodes_deep(expr):
            if isinstance(walk_node, structured_c.CUnaryOp) and walk_node.op == "Dereference":
                return True
        return False

    def _collect_dereference_backed_linear_temps(self, node: StructuredAstValue) -> StructuredAstValue:
        aliases: set[int] = set()
        for _ in range(4):
            changed = False
            for walk_node in _iter_c_nodes_deep(node):
                key = self._linear_temp_assignment_key_8616(walk_node)
                if key is None or key in aliases:
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                if self._expr_contains_dereference(rhs):
                    aliases.add(key)
                    changed = True
                    continue
                if not isinstance(rhs, structured_c.CVariable):
                    continue
                rhs_var = rhs.variable
                if rhs_var is not None and id(rhs_var) in aliases:
                    aliases.add(key)
                    changed = True
            if not changed:
                break
        return aliases

    def _linear_temp_assignment_key_8616(self, walk_node: StructuredAstValue) -> int | None:
        """Return the lhs variable key for a linear register temp assignment."""
        if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
            walk_node.lhs, structured_c.CVariable
        ):
            return None
        if not _is_linear_register_temp_var(walk_node.lhs):
            return None
        lhs_var = getattr(walk_node.lhs, "variable", None)
        if lhs_var is None:
            return None
        return id(lhs_var)

    def _collect_memory_backed_linear_temps(self, node: StructuredAstValue) -> StructuredAstValue:
        aliases: set[int] = set()
        for _ in range(4):
            changed = False
            for walk_node in _iter_c_nodes_deep(node):
                if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
                    walk_node.lhs, structured_c.CVariable
                ):
                    continue
                if not _is_linear_register_temp_var(walk_node.lhs):
                    continue
                lhs_var = getattr(walk_node.lhs, "variable", None)
                if lhs_var is None:
                    continue
                key = id(lhs_var)
                if key in aliases:
                    continue
                rhs = _unwrap_c_casts(walk_node.rhs)
                rhs_var = getattr(rhs, "variable", None) if isinstance(rhs, structured_c.CVariable) else None
                if isinstance(rhs_var, SimMemoryVariable):
                    aliases.add(key)
                    changed = True
                    continue
                if rhs_var is not None and id(rhs_var) in aliases:
                    aliases.add(key)
                    changed = True
            if not changed:
                break
        return aliases

    def _expr_uses_dereference_backed_temp(self, expr: StructuredAstValue, backed_ids: set[int]) -> bool:
        if not backed_ids:
            return False
        for walk_node in _iter_c_nodes_deep(expr):
            if not isinstance(walk_node, structured_c.CVariable):
                continue
            variable = walk_node.variable
            if variable is not None and id(variable) in backed_ids:
                return True
        return False

    def _expr_uses_memory_backed_temp(self, expr: StructuredAstValue, backed_ids: set[int]) -> bool:
        if not backed_ids:
            return False
        for walk_node in _iter_c_nodes_deep(expr):
            if not isinstance(walk_node, structured_c.CVariable):
                continue
            variable = walk_node.variable
            if variable is not None and id(variable) in backed_ids:
                return True
        return False

    def _stack_name_root(self, name: str | None) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        match = re.fullmatch(r"(?P<root>.*?)(?:_(?P<suffix>\d+))?", name)
        if match is None:
            return name
        suffix = match.group("suffix")
        root = match.group("root")
        if suffix is None:
            return root
        return root if root else name

    def _far_pointer_alias_groups_8616(
        self, node: StructuredAstValue
    ) -> dict[str, dict[str, list[tuple[structured_c.CVariable, object]]]]:
        """Group stack assignments into zero inits and candidate sources per root."""
        groups: dict[str, dict[str, list[tuple[structured_c.CVariable, object]]]] = {}
        for walk_node in _iter_c_nodes_deep(node):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
                walk_node.lhs, structured_c.CVariable
            ):
                continue
            lhs_var = getattr(walk_node.lhs, "variable", None)
            if not isinstance(lhs_var, SimStackVariable):
                continue
            root = self._stack_name_root(lhs_var.name)
            if root is None:
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            if _c_constant_value(rhs) is None and not self._expr_is_safe_inline_candidate(rhs):
                continue
            if self._expr_contains_generated_temp(rhs):
                continue
            bucket = groups.setdefault(root, {"zero": [], "source": []})
            if _c_constant_value(rhs) == 0:
                bucket["zero"].append((walk_node.lhs, rhs))
            else:
                bucket["source"].append((walk_node.lhs, rhs))
        return groups

    def _far_pointer_source_expr_8616(
        self, root: str, sources: list[tuple[structured_c.CVariable, object]]
    ) -> StructuredAstValue:
        """Pick the best-scoring source expression that does not self-reference."""
        for cvar, rhs in sorted(sources, key=lambda item: self._source_score(item[0], item[1])):
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            if self._stack_name_root(variable.name) != root:
                continue
            if self._expr_mentions_stack_root(rhs, root):
                continue
            return rhs
        return None

    def _collect_far_pointer_stack_aliases(self, node: StructuredAstValue) -> StructuredAstValue:
        groups = self._far_pointer_alias_groups_8616(node)
        aliases: dict[int, object] = {}
        for root, parts in groups.items():
            if not parts["zero"] or not parts["source"]:
                continue
            source_expr = self._far_pointer_source_expr_8616(root, parts["source"])
            if source_expr is None:
                continue
            for cvar, _rhs in parts["zero"]:
                variable = getattr(cvar, "variable", None)
                if not isinstance(variable, SimStackVariable):
                    continue
                aliases[id(variable)] = source_expr
        return aliases

    def _expr_contains_generated_temp(self, expr: StructuredAstValue) -> bool:
        for walk in _iter_c_nodes_deep(expr):
            if not isinstance(walk, structured_c.CVariable):
                continue
            name = walk.name
            if isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name):
                return True
        return False

    def _expr_mentions_stack_root(self, expr: StructuredAstValue, root: str) -> bool:
        for walk in _iter_c_nodes_deep(expr):
            if not isinstance(walk, structured_c.CVariable):
                continue
            variable = walk.variable
            if not isinstance(variable, SimStackVariable):
                continue
            if self._stack_name_root(variable.name) == root:
                return True
        return False

    def _source_score(self, _cvar: StructuredAstValue, expr: StructuredAstValue) -> tuple[int, int, int]:
        expr = _unwrap_c_casts(expr)
        variable = getattr(expr, "variable", None)
        name = getattr(variable, "name", None) or getattr(expr, "name", None)
        generic_name = isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None
        if isinstance(variable, SimStackVariable):
            return (0 if not generic_name else 2, variable.offset, variable.size)
        if isinstance(variable, SimMemoryVariable):
            return (0 if not generic_name else 2, variable.addr, variable.size)
        if isinstance(variable, SimRegisterVariable):
            return (3 if generic_name else 1, variable.reg, variable.size)
        if isinstance(expr, structured_c.CConstant):
            return (4, int(expr.value) if isinstance(expr.value, int) else 0, 0)
        return (4, 0, 0)

    def _match_adjacent_byte_pair_var_expr(self, 
        low_expr: StructuredAstValue, high_expr: StructuredAstValue
    ) -> StructuredAstValue:
        key = (id(low_expr), id(high_expr))
        if key in self.adjacent_byte_pair_cache:
            cached = self.adjacent_byte_pair_cache[key]
            return None if cached is _SIMPLIFY_NO_MATCH_8616 else cached
        low_expr = self._resolve_copy_alias_expr(low_expr)
        high_expr = self._resolve_copy_alias_expr(high_expr)

        if isinstance(high_expr, structured_c.CBinaryOp) and high_expr.op in {"Mul", "Shl"}:
            for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
                if scale not in {8, 0x100}:
                    continue
                high_expr = self._resolve_copy_alias_expr(maybe_inner)
                break

        low_var = getattr(low_expr, "variable", None) if isinstance(low_expr, structured_c.CVariable) else None
        high_var = getattr(high_expr, "variable", None) if isinstance(high_expr, structured_c.CVariable) else None
        if not isinstance(low_var, SimMemoryVariable) or not isinstance(high_var, SimMemoryVariable):
            self.adjacent_byte_pair_cache[key] = _SIMPLIFY_NO_MATCH_8616
            return None
        # Global/object recovery owns DS/ES data-space objects. The structured
        # simplifier must not synthesize a bare word object from adjacent byte
        # globals here, because that late semantic jump can corrupt split byte
        # store sequences into unresolved address-valued stores.
        self.adjacent_byte_pair_cache[key] = _SIMPLIFY_NO_MATCH_8616
        return None

    def _match_word_plus_minus_one_expr(self, node: StructuredAstValue) -> StructuredAstValue:
        key = id(node)
        if key in self.word_plus_minus_one_cache:
            cached = self.word_plus_minus_one_cache[key]
            return None if cached is _SIMPLIFY_NO_MATCH_8616 else cached
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            self.word_plus_minus_one_cache[key] = _SIMPLIFY_NO_MATCH_8616
            return None




        for masked_expr, delta_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            base_expr = self._match_masked_high_word(masked_expr)
            duplicate_word_base = None
            if base_expr is None:
                duplicate_word_base = self._match_duplicate_word_base(masked_expr)
                base_expr = duplicate_word_base
                if base_expr is None:
                    continue
            result = self._word_plus_delta_result_8616(node, base_expr, duplicate_word_base, delta_expr)
            if result is not None:
                return result

        self.word_plus_minus_one_cache[key] = _SIMPLIFY_NO_MATCH_8616
        return None

    def _word_plus_delta_result_8616(
        self,
        node: structured_c.CBinaryOp,
        base_expr: StructuredAstValue,
        duplicate_word_base: StructuredAstValue,
        delta_expr: StructuredAstValue,
    ) -> StructuredAstValue:
        """Match the delta operand of the masked-word plus/minus-one form."""
        delta_expr = _unwrap_c_casts(delta_expr)
        constant_delta = _c_constant_value(delta_expr)
        if node.op == "Add" and isinstance(constant_delta, int):
            return structured_c.CBinaryOp(
                "Add",
                base_expr,
                structured_c.CConstant(constant_delta, SimTypeShort(False), codegen=self.codegen),
                codegen=self.codegen,
            )
        if not isinstance(delta_expr, structured_c.CBinaryOp) or delta_expr.op not in {"Add", "Sub"}:
            return None
        low_expr, const_expr = delta_expr.lhs, delta_expr.rhs
        if duplicate_word_base is not None and _c_constant_value(_unwrap_c_casts(const_expr)) == 1:
            return structured_c.CBinaryOp(
                "Add" if delta_expr.op == "Add" else "Sub",
                base_expr,
                structured_c.CConstant(1, SimTypeShort(False), codegen=self.codegen),
                codegen=self.codegen,
            )
        if (
            _c_constant_value(_unwrap_c_casts(low_expr)) is None
            and _c_constant_value(_unwrap_c_casts(const_expr)) is None
        ):
            return None
        if (
            _same_c_expression(self._strip_byte_cast(low_expr), base_expr)
            and _c_constant_value(_unwrap_c_casts(const_expr)) == 1
        ):
            return structured_c.CBinaryOp(
                "Add" if delta_expr.op == "Add" else "Sub",
                base_expr,
                structured_c.CConstant(1, SimTypeShort(False), codegen=self.codegen),
                codegen=self.codegen,
            )
        if (
            _same_c_expression(self._strip_byte_cast(const_expr), base_expr)
            and _c_constant_value(_unwrap_c_casts(low_expr)) == 1
        ):
            return structured_c.CBinaryOp(
                "Add" if delta_expr.op == "Add" else "Sub",
                base_expr,
                structured_c.CConstant(1, SimTypeShort(False), codegen=self.codegen),
                codegen=self.codegen,
            )
        return None

    def _strip_byte_cast(self, expr: StructuredAstValue) -> StructuredAstValue:
        expr = _unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CTypeCast):
            type_ = expr.type
            if getattr(type_, "size", None) == 8:
                return _unwrap_c_casts(expr.expr)
        return expr

    def _match_masked_high_word(self, expr: StructuredAstValue) -> StructuredAstValue:
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "And":
            return None
        for maybe_word, maybe_mask in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_mask)) != 0xFF00:
                continue
            return _unwrap_c_casts(maybe_word)
        return None

    def _match_duplicate_word_base(self, expr: StructuredAstValue) -> StructuredAstValue:
        expr = _unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
            return None
        for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            low_expr = self._resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
            high_expr = _unwrap_c_casts(maybe_high)
            if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
                continue
            for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                    continue
                inner_expr = self._resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))
                if _same_c_expression(low_expr, inner_expr):
                    return low_expr
        return None

    def _analyze_current_widening_expr(self, node: StructuredAstValue) -> StructuredAstValue:
        """Analyze current operands, including temporary resolved expressions."""
        # Resolved nodes can be discarded between calls and their IDs reused.
        # The mutable AST and alias maps also preclude pass-wide memoization.
        return _analyze_widening_expr(
            node,
            self._resolve_copy_alias_expr,
            _match_high_byte_projection_base,
        )

    def _match_linear_word_delta_expr(self, node: StructuredAstValue) -> StructuredAstValue:
        analysis = self._analyze_current_widening_expr(node)
        if analysis is None or analysis.kind != "linear":
            return None
        if analysis.delta == 0:
            return analysis.base_expr
        delta = analysis.delta
        base_expr = analysis.base_expr
        op = "Add" if delta > 0 else "Sub"
        magnitude = delta if delta > 0 else -delta
        return structured_c.CBinaryOp(
            op,
            base_expr,
            structured_c.CConstant(magnitude, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )

    def _match_high_byte_preserving_word_expr(self, node: StructuredAstValue) -> StructuredAstValue:
        analysis = self._analyze_current_widening_expr(node)
        if analysis is None or analysis.kind != "high_byte_preserving":
            return None
        return structured_c.CBinaryOp(
            "Add",
            analysis.base_expr,
            structured_c.CConstant(analysis.delta, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )

    def _memory_backed_widening_base(self, node: StructuredAstValue) -> bool:
        if self._expr_uses_dereference_backed_temp(node, self.dereference_backed_linear_temps):
            return True
        analysis = self._analyze_current_widening_expr(node)
        if analysis is None:
            return False
        base_expr = self._resolve_copy_alias_expr(_unwrap_c_casts(analysis.base_expr))
        if isinstance(base_expr, structured_c.CVariable) and isinstance(
            getattr(base_expr, "variable", None), SimMemoryVariable
        ):
            return True
        return isinstance(base_expr, structured_c.CUnaryOp) and base_expr.op == "Dereference"

    def _make_mk_fp(self, segment_expr: StructuredAstValue, offset_expr: StructuredAstValue) -> StructuredAstValue:
        return structured_c.CFunctionCall("MK_FP", None, [segment_expr, offset_expr], codegen=self.codegen)

    def _is_dead_stack_address_init(self, stmt: StructuredAstValue) -> bool:
        if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
            return False
        lhs_var = getattr(stmt.lhs, "variable", None)
        if not isinstance(lhs_var, SimStackVariable) or _stack_slot_identity_for_variable(lhs_var) is None:
            return False
        if self.variable_use_counts.get(id(lhs_var), 0) != 1:
            return False
        rhs = stmt.rhs
        if not isinstance(rhs, structured_c.CUnaryOp) or rhs.op != "Reference":
            return False
        operand = rhs.operand
        if not isinstance(operand, structured_c.CVariable):
            return False
        ref_var = operand.variable
        return isinstance(ref_var, SimStackVariable) and _stack_slot_identity_for_variable(ref_var) is not None

    def _is_redundant_self_copy(self, stmt: StructuredAstValue) -> bool:
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = _unwrap_c_casts(stmt.lhs)
        rhs = _unwrap_c_casts(stmt.rhs)
        if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
            return False
        lhs_var = getattr(lhs, "variable", None)
        rhs_var = getattr(rhs, "variable", None)
        if lhs_var is None or rhs_var is None or lhs_var is not rhs_var:
            return False
        return _is_linear_register_temp_var(lhs)

    def _rewrite_and_over_or(self, node: StructuredAstValue) -> StructuredAstValue:
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "And":
            return None
        for or_expr, const_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            or_expr = _unwrap_c_casts(or_expr)
            const_value = _c_constant_value(_unwrap_c_casts(const_expr))
            if const_value is None or not isinstance(or_expr, structured_c.CBinaryOp) or or_expr.op != "Or":
                continue
            for and_expr, inner_const_expr in ((or_expr.lhs, or_expr.rhs), (or_expr.rhs, or_expr.lhs)):
                inner_const = _c_constant_value(_unwrap_c_casts(inner_const_expr))
                if inner_const is None or not isinstance(and_expr, structured_c.CBinaryOp) or and_expr.op != "And":
                    continue
                for inner_base, inner_mask_expr in ((and_expr.lhs, and_expr.rhs), (and_expr.rhs, and_expr.lhs)):
                    inner_mask = _c_constant_value(_unwrap_c_casts(inner_mask_expr))
                    if inner_mask is None:
                        continue
                    left = structured_c.CBinaryOp(
                        "And",
                        _unwrap_c_casts(inner_base),
                        structured_c.CConstant(const_value, SimTypeShort(False), codegen=self.codegen),
                        codegen=self.codegen,
                    )
                    right_const = inner_const & const_value
                    if right_const == 0:
                        return left
                    right = structured_c.CConstant(right_const, SimTypeShort(False), codegen=self.codegen)
                    return structured_c.CBinaryOp("Or", left, right, codegen=self.codegen)
        return None

    def transform(self, node: StructuredAstValue) -> StructuredAstValue:
        result = self._transform_typecast_8616(node)
        if result is not None:
            return result
        if isinstance(node, structured_c.CBinaryOp):
            result = self._transform_binary_8616(node)
            if result is not None:
                return result
        result = self._transform_tail_8616(node)
        if result is not None:
            return result
        return node


    def _binary_ctx_8616(self, node: structured_c.CBinaryOp) -> _BinarySimplifyCtx8616 | None:
        """Resolve copy aliases in the operands and snapshot the arm context."""
        memory_backed_source = self._expr_uses_memory_backed_temp(node, self.memory_backed_linear_temps)
        if memory_backed_source:
            lhs = _unwrap_c_casts(node.lhs)
            rhs = _unwrap_c_casts(node.rhs)
        else:
            lhs = self._resolve_copy_alias_expr(_unwrap_c_casts(node.lhs))
            rhs = self._resolve_copy_alias_expr(_unwrap_c_casts(node.rhs))
        try:
            resolved = structured_c.CBinaryOp(node.op, lhs, rhs, tags=node.tags, codegen=self.codegen)
        except ValueError:
            # Keep original node when angr cannot resolve operand sizes for
            # transient synthetic types lacking arch context.
            return None
        return _BinarySimplifyCtx8616(
            node=node,
            lhs=lhs,
            rhs=rhs,
            resolved=resolved,
            resolved_contains_dereference=self._expr_contains_dereference(resolved),
            storage_backed_source=(
                self._expr_uses_dereference_backed_temp(node, self.dereference_backed_linear_temps)
                or memory_backed_source
            ),
        )

    def _run_binary_arms_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        """Run the binary rewrite arms in their original order."""
        for arm in (
            self._arm_widened_byte_pair_8616,
            self._arm_far_pointer_mkfp_8616,
            self._arm_word_delta_8616,
            self._arm_addsub_linear_8616,
            self._arm_const_fold_8616,
        ):
            result = arm(ctx)
            if result is not None:
                return result
        rewritten_and = self._rewrite_and_over_or(ctx.node)
        if rewritten_and is not None:
            return rewritten_and
        for arm in (
            self._arm_bitwise_terms_8616,
            self._arm_zero_identity_8616,
            self._arm_addsub_fold_8616,
            self._arm_same_expr_8616,
            self._arm_mul_8616,
            self._arm_and_8616,
        ):
            result = arm(ctx)
            if result is not None:
                return result
        simplified_or = _simplify_zero_mul_or_expr(ctx.node, self.codegen)
        if simplified_or is not ctx.node:
            return simplified_or
        return self._arm_shr_8616(ctx)

    def _transform_binary_8616(self, node: StructuredAstValue) -> StructuredAstValue:
        if id(node) in self.protected_dereference_addr_expr_ids:
            return self._normalize_protected_add_constant_tail(node)
        ctx = self._binary_ctx_8616(node)
        if ctx is None:
            return node
        result = self._run_binary_arms_8616(ctx)
        if result is not None:
            return result
        if ctx.lhs is not ctx.node.lhs or ctx.rhs is not ctx.node.rhs:
            return ctx.resolved
        return None


    def _arm_widened_byte_pair_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op in {"Add", "Or"} and not ctx.storage_backed_source:
            widened = self._match_adjacent_byte_pair_var_expr(ctx.lhs, ctx.rhs)
            if widened is None:
                widened = self._match_adjacent_byte_pair_var_expr(ctx.rhs, ctx.lhs)
            if widened is not None:
                return widened
            widened = _match_adjacent_register_pair_var_expr(ctx.lhs, ctx.rhs, self.codegen)
            if widened is None:
                widened = _match_adjacent_register_pair_var_expr(ctx.rhs, ctx.lhs, self.codegen)
            if widened is not None:
                return widened
        return None


    def _arm_far_pointer_mkfp_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op == "Add":
            if isinstance(ctx.lhs, structured_c.CVariable) and isinstance(
                getattr(ctx.lhs, "variable", None), SimStackVariable
            ) and _c_constant_value(ctx.rhs) is not None:
                alias_expr = self.far_pointer_aliases.get(id(ctx.lhs.variable))
                if alias_expr is not None:
                    return self._make_mk_fp(alias_expr, ctx.rhs)
            if isinstance(ctx.rhs, structured_c.CVariable) and isinstance(
                getattr(ctx.rhs, "variable", None), SimStackVariable
            ) and _c_constant_value(ctx.lhs) is not None:
                alias_expr = self.far_pointer_aliases.get(id(ctx.rhs.variable))
                if alias_expr is not None:
                    return self._make_mk_fp(alias_expr, ctx.lhs)
        return None


    def _arm_word_delta_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if (
            ctx.node.op in {"Add", "Or"}
            and not ctx.resolved_contains_dereference
            and not ctx.storage_backed_source
            and not self._memory_backed_widening_base(ctx.node)
        ):
            delta = self._match_word_plus_minus_one_expr(ctx.node)
            if delta is not None:
                return delta
            linear = self._match_linear_word_delta_expr(ctx.node)
            if linear is not None:
                return linear
            high_update = self._match_high_byte_preserving_word_expr(ctx.node)
            if high_update is not None:
                return high_update
        return None


    def _arm_addsub_linear_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op in {"Add", "Sub"}:  # noqa: SIM102
            if not ctx.resolved_contains_dereference and not ctx.storage_backed_source:  # noqa: SIM102
                if not self._memory_backed_widening_base(ctx.resolved):
                    linear = self._match_linear_word_delta_expr(ctx.resolved)
                    if linear is not None:
                        return linear
        return None


    def _arm_const_fold_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if isinstance(ctx.lhs, structured_c.CConstant) and isinstance(ctx.rhs, structured_c.CConstant):  # noqa: SIM102
            if isinstance(ctx.lhs.value, int) and isinstance(ctx.rhs.value, int):
                op_fn = _CONST_FOLD_OPS_8616.get(ctx.node.op)
                result = op_fn(ctx.lhs.value, ctx.rhs.value) if op_fn is not None else None
                if result is not None:
                    type_ = (
                        ctx.node.type
                        or getattr(ctx.node.lhs, "type", None)
                        or getattr(ctx.node.rhs, "type", None)
                        or SimTypeShort(False)
                    )
                    return structured_c.CConstant(result, type_, codegen=self.codegen)
        return None


    def _fold_bitwise_term_values_8616(
        self, ctx: _BinarySimplifyCtx8616, terms: list[StructuredAstValue]
    ) -> tuple[int | None, object, list[StructuredAstValue]]:
        """Fold constant operands of a flattened And/Or term list."""
        const_value = None
        const_type = None
        non_constants = []
        for term in terms:
            value = _c_constant_value(term)
            if value is None:
                non_constants.append(term)
                continue
            const_type = getattr(term, "type", None) or const_type
            if const_value is None:
                const_value = value
            elif ctx.node.op == "And":
                const_value &= value
            else:
                const_value |= value
        return const_value, const_type, non_constants

    def _arm_bitwise_terms_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op in {"And", "Or"}:
            terms = flatten_bitwise_terms_8616(ctx.node, ctx.node.op, _unwrap_c_casts)
            const_value, const_type, non_constants = self._fold_bitwise_term_values_8616(ctx, terms)
            if len(terms) > 2 or len(non_constants) != len(terms):
                rebuilt_terms = list(non_constants)
                if const_value is not None:  # noqa: SIM102
                    if not ((ctx.node.op == "And" and const_value == -1) or (ctx.node.op == "Or" and const_value == 0)):
                        rebuilt_terms.append(
                            structured_c.CConstant(
                                const_value,
                                const_type or ctx.node.type or SimTypeShort(False),
                                codegen=self.codegen,
                            )
                        )
                if not rebuilt_terms:
                    type_ = (
                        ctx.node.type
                        or getattr(ctx.node.lhs, "type", None)
                        or getattr(ctx.node.rhs, "type", None)
                        or SimTypeShort(False)
                    )
                    return structured_c.CConstant(
                        const_value if const_value is not None else 0, type_, codegen=self.codegen
                    )
                rebuilt_result: object = rebuilt_terms[0]
                for term in rebuilt_terms[1:]:
                    rebuilt_result = structured_c.CBinaryOp(ctx.node.op, rebuilt_result, term, codegen=self.codegen)
                return rebuilt_result
        return None


    def _arm_zero_identity_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op in {"Add", "Or", "Xor"}:
            if _c_constant_value(ctx.lhs) == 0:
                return ctx.node.rhs
            if _c_constant_value(ctx.rhs) == 0:
                return ctx.node.lhs
        if ctx.node.op == "Sub" and _c_constant_value(ctx.rhs) == 0:
            return ctx.node.lhs
        return None


    def _arm_addsub_fold_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op == "Add":
            folded = self._fold_simple_add_constants(ctx.node)
            if folded is not ctx.node:
                return folded
        if ctx.node.op == "Sub":
            base_expr, delta = self._extract_linear_delta(ctx.node)
            if base_expr is not None:
                rebuilt = self._build_linear_expr(base_expr, delta, self.codegen)
                if not _same_c_expression(rebuilt, ctx.node):
                    return rebuilt
        return None


    def _arm_same_expr_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op in {"And", "Or"} and _same_c_expression(ctx.lhs, ctx.rhs):
            return ctx.lhs
        if ctx.node.op == "Xor" and _same_c_expression(ctx.lhs, ctx.rhs):
            type_ = (
                ctx.node.type
                or getattr(ctx.node.lhs, "type", None)
                or getattr(ctx.node.rhs, "type", None)
            )
            if type_ is not None:
                return structured_c.CConstant(0, type_, codegen=self.codegen)
        return None


    def _mul_scaled_high_byte_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        """Match a high-byte projection scaled by a constant operand."""
        for maybe_inner, maybe_other in ((ctx.lhs, ctx.rhs), (ctx.rhs, ctx.lhs)):
            if _c_constant_value(maybe_other) is None:
                continue
            inner = _unwrap_c_casts(maybe_inner)
            if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "And":
                continue
            if _c_constant_value(_unwrap_c_casts(inner.rhs)) != 0xFF:
                continue
            shifted = _match_high_byte_projection_expr(inner.lhs)
            if shifted is None:
                continue
            return structured_c.CBinaryOp(
                "Mul",
                shifted,
                maybe_other,
                codegen=self.codegen,
            )
        return None

    def _arm_mul_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op == "Mul":
            scaled = self._mul_scaled_high_byte_8616(ctx)
            if scaled is not None:
                return scaled
            if _c_constant_value(ctx.lhs) == 0 or _c_constant_value(ctx.rhs) == 0:
                type_ = (
                    ctx.node.type
                    or getattr(ctx.node.lhs, "type", None)
                    or getattr(ctx.node.rhs, "type", None)
                )
                if type_ is not None:
                    return structured_c.CConstant(0, type_, codegen=self.codegen)
            if _c_constant_value(ctx.lhs) == 1:
                return ctx.node.rhs
            if _c_constant_value(ctx.rhs) == 1:
                return ctx.node.lhs
        return None


    def _masked_high_byte_identity_8616(
        self, maybe_inner: StructuredAstValue, maybe_mask: StructuredAstValue
    ) -> StructuredAstValue:
        """Return the operand itself when it is already a masked high byte."""
        if _c_constant_value(maybe_mask) != 0xFF:
            return None
        if isinstance(maybe_inner, structured_c.CVariable):
            variable = maybe_inner.variable
            if variable is not None:
                var_key = id(variable)
                if (
                    var_key in self.high_byte_aliases
                    or var_key in self.shift_extract_aliases
                    or var_key in self.mask_shift_aliases
                ):
                    return maybe_inner
            return None
        if (
            isinstance(maybe_inner, structured_c.CBinaryOp)
            and maybe_inner.op == "Shr"
            and _is_c_constant_int(_unwrap_c_casts(maybe_inner.rhs), 8)
            and isinstance(_unwrap_c_casts(maybe_inner.lhs), structured_c.CBinaryOp)
            and _unwrap_c_casts(maybe_inner.lhs).op == "And"
        ):
            return maybe_inner
        return None

    def _arm_and_mask_pair_8616(
        self, ctx: _BinarySimplifyCtx8616, maybe_inner: StructuredAstValue, maybe_mask: StructuredAstValue
    ) -> StructuredAstValue:
        masked_var = self._masked_high_byte_identity_8616(maybe_inner, maybe_mask)
        if masked_var is not None:
            return masked_var
        if _c_constant_value(maybe_mask) != 0xFF:
            return None
        projection = _match_high_byte_projection_expr(maybe_inner)
        if projection is not None:
            return projection
        const_high = _match_high_byte_projection_constant(maybe_inner)
        if const_high is not None:
            type_ = (
                ctx.node.type
                or getattr(ctx.node.lhs, "type", None)
                or getattr(ctx.node.rhs, "type", None)
                or SimTypeShort(False)
            )
            return structured_c.CConstant(const_high, type_, codegen=self.codegen)
        if isinstance(maybe_inner, structured_c.CVariable):
            alias = self.mask_shift_aliases.get(id(maybe_inner.variable))
            if alias is not None:
                base_expr, mask, total_shift = alias
                if mask == 0xFF00:
                    return self._shifted_masked_result_8616(base_expr, total_shift)
        return self._shr_alias_result_8616(maybe_inner)

    def _shifted_masked_result_8616(self, base_expr: StructuredAstValue, total_shift: int) -> StructuredAstValue:
        """Build the Shr (optionally 0xFF-masked) result for a shift alias."""
        simplified = structured_c.CBinaryOp(
            "Shr",
            base_expr,
            structured_c.CConstant(total_shift, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )
        base_type = getattr(getattr(base_expr, "type", None), "size", None)
        if total_shift == 8 and base_type == 16:
            return simplified
        return structured_c.CBinaryOp(
            "And",
            simplified,
            structured_c.CConstant(0xFF, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )

    def _shr_alias_result_8616(self, maybe_inner: StructuredAstValue) -> StructuredAstValue:
        """Compose a nested Shr alias into a single masked shift."""
        inner = _unwrap_c_casts(maybe_inner)
        if not isinstance(inner, structured_c.CBinaryOp) or inner.op != "Shr":
            return None
        shift = _c_constant_value(_unwrap_c_casts(inner.rhs))
        shifted = _unwrap_c_casts(inner.lhs)
        if not isinstance(shifted, structured_c.CVariable):
            return None
        shift_alias = self.shift_extract_aliases.get(id(shifted.variable))
        if shift_alias is None or not isinstance(shift, int):
            return None
        base_expr, base_shift = shift_alias
        return self._shifted_masked_result_8616(base_expr, base_shift + shift)


    def _arm_and_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op == "And":
            if _c_constant_value(ctx.lhs) == 0 or _c_constant_value(ctx.rhs) == 0:
                type_ = (
                    ctx.node.type
                    or getattr(ctx.node.lhs, "type", None)
                    or getattr(ctx.node.rhs, "type", None)
                )
                if type_ is not None:
                    return structured_c.CConstant(0, type_, codegen=self.codegen)
            for maybe_inner, maybe_mask in ((ctx.lhs, ctx.rhs), (ctx.rhs, ctx.lhs)):
                result = self._arm_and_mask_pair_8616(ctx, maybe_inner, maybe_mask)
                if result is not None:
                    return result
        return None


    def _arm_shr_8616(self, ctx: _BinarySimplifyCtx8616) -> StructuredAstValue:
        if ctx.node.op == "Shr":
            if isinstance(ctx.lhs, structured_c.CBinaryOp) and ctx.lhs.op == "Shr":
                inner_shift = _c_constant_value(_unwrap_c_casts(ctx.lhs.rhs))
                outer_shift = _c_constant_value(ctx.rhs)
                if isinstance(inner_shift, int) and isinstance(outer_shift, int):
                    return structured_c.CBinaryOp(
                        "Shr",
                        ctx.lhs.lhs,
                        structured_c.CConstant(inner_shift + outer_shift, SimTypeShort(False), codegen=self.codegen),
                        codegen=self.codegen,
                    )
            if _is_c_constant_int(ctx.rhs, 8) and isinstance(ctx.lhs, structured_c.CVariable):
                high_alias = self.high_byte_aliases.get(id(ctx.lhs.variable))
                if high_alias is not None:
                    type_ = (
                        ctx.node.type
                        or getattr(ctx.node.lhs, "type", None)
                        or getattr(ctx.node.rhs, "type", None)
                        or SimTypeShort(False)
                    )
                    return structured_c.CConstant(high_alias, type_, codegen=self.codegen)
        return None


    def _transform_typecast_8616(self, node: StructuredAstValue) -> StructuredAstValue:
        if isinstance(node, structured_c.CTypeCast):
            target_type = node.type
            rendered = str(target_type) if target_type is not None else ""
            if "[" in rendered and isinstance(node.expr, structured_c.CVariable):
                return node.expr
            if "[" in rendered and not isinstance(node.expr, structured_c.CConstant):
                return node.expr
        return None


    def _transform_tail_8616(self, node: StructuredAstValue) -> StructuredAstValue:
        simplified = _simplify_boolean_expr(node, self.codegen)
        if simplified is not node:
            return simplified
        if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":  # noqa: SIM102
            if _same_c_expression(node.lhs, node.rhs):
                type_ = node.type or getattr(node.lhs, "type", None)
                if type_ is not None:
                    return structured_c.CConstant(0, type_, codegen=self.codegen)
        if isinstance(node, structured_c.CAssignment) and self._is_redundant_self_copy(node):
            constant_type = (
                getattr(node, "type", None)
                or getattr(node.lhs, "type", None)
                or getattr(node.rhs, "type", None)
            )
            if constant_type is None:
                return node
            return structured_c.CConstant(
                0,
                constant_type,
                codegen=self.codegen,
            )
        return None



    def _prune_dead_inits_in_statements_8616(self, node: structured_c.CStatements) -> bool:
        """Drop proven dead stack-address inits from one statement list."""
        changed = False
        new_statements = []
        for stmt in node.statements:
            if self._is_dead_stack_address_init(stmt):
                changed = True
                continue
            if self._is_redundant_self_copy(stmt):
                changed = True
                continue
            if self.prune_dead_stack_address_inits(stmt):
                changed = True
            new_statements.append(stmt)
        if changed or new_statements != node.statements:
            node.statements = new_statements
        return changed

    def prune_dead_stack_address_inits(self, node: StructuredAstValue) -> bool:
        changed = False
        if isinstance(node, structured_c.CStatements):
            return self._prune_dead_inits_in_statements_8616(node)
        if isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                if self.prune_dead_stack_address_inits(body):
                    changed = True
            if node.else_node is not None and self.prune_dead_stack_address_inits(node.else_node):
                changed = True
        return changed


def _simplify_structured_c_expressions(codegen: StructuredCodegenValue) -> bool:
    """Apply legacy cleanup without reusing analyses of discarded expressions."""
    run = _StructuredSimplifyRun8616.build_8616(codegen)
    if run is None:
        return False
    return run.run_8616()


def _unwrap_c_casts(node: StructuredAstValue) -> StructuredAstValue:
    """Skip cosmetic casts without discarding required machine conversions."""
    while isinstance(node, structured_c.CTypeCast):
        if isinstance(node, CSemanticCast8616) and not is_identity_semantic_variable_cast_8616(node):
            break
        node = node.expr
    return node


def _match_shift_right_8_expr(node: StructuredAstValue) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        nonlocal node
        node = _unwrap_c_casts(node)
        if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
            return None
        lhs = _unwrap_c_casts(node.lhs)
        rhs = _unwrap_c_casts(node.rhs)
        if _is_c_constant_int(rhs, 8):
            if (
                isinstance(lhs, structured_c.CBinaryOp)
                and lhs.op == "And"
                and _is_c_constant_int(_unwrap_c_casts(lhs.rhs), 0xFF)
            ):
                or_expr = _unwrap_c_casts(lhs.lhs)
                if isinstance(or_expr, structured_c.CBinaryOp) and or_expr.op == "Or":
                    for _maybe_masked, maybe_const in ((or_expr.lhs, or_expr.rhs), (or_expr.rhs, or_expr.lhs)):
                        const_value = _c_constant_value(_unwrap_c_casts(maybe_const))
                        if not isinstance(const_value, int):
                            continue
                        if const_value & 0xFF00 == const_value and const_value & 0xFF == 0:
                            return structured_c.CConstant(
                                (const_value >> 8) & 0xFF, SimTypeChar(), codegen=getattr(node, "codegen", None)
                            )
            return lhs
        if _is_c_constant_int(lhs, 8):
            return rhs
        return None

    return _impl()


def _dup_word_increment_base_8616(
    expr: StructuredAstValue, resolve_copy_alias_expr: StructuredAstValue
) -> StructuredAstValue:
    """Match ``low | inner*0x100`` where low and inner are the same value."""

    expr = _unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
        return None
    for maybe_low, maybe_high in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
        low_expr = resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
        high_expr = _unwrap_c_casts(maybe_high)
        if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
            continue
        for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                continue
            if _same_c_expression(low_expr, resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))):
                return low_expr
    return None


def _match_duplicate_word_increment_shift_expr(
    node: StructuredAstValue, resolve_copy_alias_expr: StructuredAstValue, codegen: StructuredCodegenValue
) -> StructuredAstValue:
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
        return None
    if _c_constant_value(_unwrap_c_casts(node.rhs)) != 8:
        return None

    lhs = _unwrap_c_casts(node.lhs)
    if not isinstance(lhs, structured_c.CBinaryOp) or lhs.op not in {"Add", "Sub"}:
        return None

    for maybe_word, maybe_const in ((lhs.lhs, lhs.rhs), (lhs.rhs, lhs.lhs)):
        if _c_constant_value(_unwrap_c_casts(maybe_const)) != 1:
            continue
        base_expr = _dup_word_increment_base_8616(maybe_word, resolve_copy_alias_expr)
        if base_expr is None:
            continue
        return structured_c.CBinaryOp(
            "Add" if lhs.op == "Add" else "Sub",
            base_expr,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    return None


def _match_duplicate_word_base_expr(
    node: StructuredAstValue, resolve_copy_alias_expr: StructuredAstValue
) -> StructuredAstValue:
    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None

    for maybe_low, maybe_high in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_expr = resolve_copy_alias_expr(_unwrap_c_casts(maybe_low))
        high_expr = _unwrap_c_casts(maybe_high)
        if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Mul", "Shl"}:
            continue
        for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
                continue
            if _same_c_expression(low_expr, resolve_copy_alias_expr(_unwrap_c_casts(maybe_inner))):
                return low_expr

    return None


_COD_GLOBAL_ARM_CONTINUE_8616: StructuredAstValue = object()


def _cod_named_global_cvar_8616(
    created: dict[tuple[int, int], structured_c.CVariable],
    linear: int,
    symbol: tuple[str, int],
    node_type: object,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
) -> StructuredAstValue:
    """Build or reuse a named synthetic-global CVariable for a linear addr."""

    if node_type is None:
        return None
    bits = getattr(node_type, "size", None)
    size = _storage_size_from_type_bits(bits, project)
    key = (linear, size)
    existing = created.get(key)
    if existing is not None:
        return existing
    name, _width = symbol
    name = _sanitize_cod_identifier(name)
    cvar = structured_c.CVariable(
        SimMemoryVariable(linear, size, name=name, region=codegen.cfunc.addr),
        variable_type=node_type,
        codegen=codegen,
    )
    created[key] = cvar
    return cvar


def _cod_global_var_arm_8616(
    node: StructuredAstValue,
    created: dict[tuple[int, int], structured_c.CVariable],
    synthetic_globals: dict[int, tuple[str, int]],
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
) -> StructuredAstValue:
    """Name a direct SimMemoryVariable global; continue-sentinel if unmatched."""

    variable = node.variable
    if not isinstance(variable, SimMemoryVariable):
        return _COD_GLOBAL_ARM_CONTINUE_8616
    linear = variable.addr
    if not isinstance(linear, int):
        return node
    symbol = _synthetic_global_entry(synthetic_globals, linear)
    if symbol is None:
        return _COD_GLOBAL_ARM_CONTINUE_8616
    cvar = _cod_named_global_cvar_8616(created, linear, symbol, node.variable_type, project, codegen)
    return cvar if cvar is not None else node


def _cod_global_deref_arm_8616(
    node: StructuredAstValue,
    created: dict[tuple[int, int], structured_c.CVariable],
    synthetic_globals: dict[int, tuple[str, int]],
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
) -> StructuredAstValue:
    """Name a const-address Dereference global; continue-sentinel if unmatched."""

    addr_expr = _extract_dereference_addr_expr(node)
    addr_value = _c_constant_value(_unwrap_c_casts(addr_expr)) if addr_expr is not None else None
    if not isinstance(addr_value, int):
        return node
    symbol = _synthetic_global_entry(synthetic_globals, addr_value)
    if symbol is None:
        return _COD_GLOBAL_ARM_CONTINUE_8616
    cvar = _cod_named_global_cvar_8616(created, addr_value, symbol, node.type, project, codegen)
    return cvar if cvar is not None else node


def _cod_global_seg_deref_arm_8616(
    node: StructuredAstValue,
    created: dict[tuple[int, int], structured_c.CVariable],
    synthetic_globals: dict[int, tuple[str, int]],
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
) -> StructuredAstValue:
    """Name a segmented-dereference DS global; node when unmatched."""

    seg_name, linear = _match_segmented_dereference(node, project)
    if not isinstance(linear, int):
        return node
    symbol = _synthetic_global_entry(synthetic_globals, linear)
    if seg_name != "ds" or symbol is None:
        return node
    cvar = _cod_named_global_cvar_8616(created, linear, symbol, getattr(node, "type", None), project, codegen)
    return cvar if cvar is not None else node


def _attach_cod_global_names(
    project: AngrProjectValue, codegen: StructuredCodegenValue, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}

    def transform(node: StructuredAstValue) -> StructuredAstValue:
        if isinstance(node, structured_c.CVariable):
            arm_result = _cod_global_var_arm_8616(node, created, synthetic_globals, project, codegen)
            if arm_result is not _COD_GLOBAL_ARM_CONTINUE_8616:
                return arm_result

        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            arm_result = _cod_global_deref_arm_8616(node, created, synthetic_globals, project, codegen)
            if arm_result is not _COD_GLOBAL_ARM_CONTINUE_8616:
                return arm_result

        return _cod_global_seg_deref_arm_8616(node, created, synthetic_globals, project, codegen)

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed


def _rename_in_use_global_symbols_8616(
    variables_in_use: Mapping[SimVariable, structured_c.CVariable], synthetic_globals: dict[int, tuple[str, int]]
) -> bool:
    """Rename in-use SimMemoryVariable globals to their synthetic names."""

    changed = False
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        symbol = _synthetic_global_entry(synthetic_globals, variable.addr)
        if symbol is None:
            continue
        raw_name, _width = symbol
        name = _sanitize_cod_identifier(raw_name)
        if variable.name != name:
            variable.name = name
            changed = True
        if getattr(cvar, "name", None) != name:
            cvar.name = name
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != name:
            unified.name = name
            changed = True
    return changed


def _rename_unified_global_locals_8616(
    unified_locals: MutableMapping[SimVariable, set[tuple[structured_c.CVariable, object]]], synthetic_globals: dict[int, tuple[str, int]]
) -> bool:
    """Rename unified-local SimMemoryVariable globals to synthetic names."""

    changed = False
    for variable, cvar_and_vartypes in list(unified_locals.items()):
        if not isinstance(variable, SimMemoryVariable):
            continue
        symbol = _synthetic_global_entry(synthetic_globals, variable.addr)
        if symbol is None:
            continue
        raw_name, _width = symbol
        name = _sanitize_cod_identifier(raw_name)
        new_entries = set()
        for cvariable, vartype in cvar_and_vartypes:
            if getattr(cvariable, "name", None) != name:
                cvariable.name = name
                changed = True
            new_entries.add((cvariable, vartype))
        if new_entries != cvar_and_vartypes:
            unified_locals[variable] = new_entries
            changed = True
    return changed


def _attach_cod_global_declaration_names(
    codegen: StructuredCodegenValue, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    def _impl() -> bool:
        if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
            return False

        changed = _rename_in_use_global_symbols_8616(
            getattr(codegen.cfunc, "variables_in_use", {}), synthetic_globals
        )

        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict) and _rename_unified_global_locals_8616(
            unified_locals, synthetic_globals
        ):
            changed = True

        return changed

    return _impl()


def _desired_global_type_spec_8616(
    variable: StructuredAstValue,
    synthetic_globals: dict[int, tuple[str, int]],
    short_type: StructuredAstValue,
    char_type: StructuredAstValue,
) -> tuple[object | None, int | None, str | None]:
    """Map a global variable to (type, size, name) from synthetic metadata."""

    symbol = _synthetic_global_entry(synthetic_globals, getattr(variable, "addr", None))
    if symbol is None:
        return None, None, None
    _raw_name, width = symbol
    if width == 1:
        return char_type, 1, None
    if width >= 2:
        return short_type, 2, None
    return None, None, None


def _apply_global_type_and_size_8616(
    variable: StructuredAstValue,
    cvar: StructuredAstValue,
    new_type: StructuredAstValue,
    new_size: StructuredAstValue,
) -> bool:
    """Apply a desired type/size to a variable and its cvar/unified pair."""

    local_changed = False
    if new_size is not None and getattr(variable, "size", None) != new_size:
        variable.size = new_size
        local_changed = True
    if getattr(cvar, "variable_type", None) != new_type:
        cvar.variable_type = new_type
        local_changed = True
    unified = getattr(cvar, "unified_variable", None)
    if unified is not None and new_size is not None and getattr(unified, "size", None) != new_size:
        with contextlib.suppress(Exception):
            unified.size = new_size
            local_changed = True
    return local_changed


def _retune_in_use_global_types_8616(
    variables_in_use: Mapping[SimVariable, structured_c.CVariable],
    synthetic_globals: dict[int, tuple[str, int]],
    short_type: StructuredAstValue,
    char_type: StructuredAstValue,
) -> bool:
    """Retune types/sizes (and names) of in-use global variables."""

    changed = False
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        new_type, new_size, target_name = _desired_global_type_spec_8616(
            variable, synthetic_globals, short_type, char_type
        )
        if new_type is None:
            continue
        changed = _apply_global_type_and_size_8616(variable, cvar, new_type, new_size) or changed
        unified = getattr(cvar, "unified_variable", None)
        if target_name is not None:
            if variable.name != target_name:
                variable.name = target_name
                changed = True
            if getattr(cvar, "name", None) != target_name:
                cvar.name = target_name
                changed = True
            if unified is not None and getattr(unified, "name", None) != target_name:
                unified.name = target_name
                changed = True
    return changed


def _retune_cextern_global_types_8616(
    cexterns: Iterable[structured_c.CVariable],
    synthetic_globals: dict[int, tuple[str, int]],
    short_type: StructuredAstValue,
    char_type: StructuredAstValue,
) -> bool:
    """Retune types/sizes on cextern global variables."""

    changed = False
    for cextern in cexterns:
        variable = getattr(cextern, "variable", None)
        if not isinstance(variable, SimMemoryVariable):
            continue
        new_type, new_size, _ = _desired_global_type_spec_8616(
            variable, synthetic_globals, short_type, char_type
        )
        if new_type is None:
            continue
        if new_size is not None and variable.size != new_size:
            variable.size = new_size
            changed = True
        if getattr(cextern, "variable_type", None) != new_type:
            cextern.variable_type = new_type
            changed = True
    return changed


def _retune_unified_global_types_8616(
    unified_locals: MutableMapping[SimVariable, set[tuple[structured_c.CVariable, object]]],
    synthetic_globals: dict[int, tuple[str, int]],
    short_type: StructuredAstValue,
    char_type: StructuredAstValue,
) -> bool:
    """Retune types/sizes on unified-local global variables."""

    changed = False
    for variable, cvar_and_vartypes in list(unified_locals.items()):
        if not isinstance(variable, SimMemoryVariable):
            continue
        new_type, new_size, _ = _desired_global_type_spec_8616(
            variable, synthetic_globals, short_type, char_type
        )
        if new_type is None:
            continue
        if new_size is not None and variable.size != new_size:
            variable.size = new_size
            changed = True
        new_entries = {(cvariable, new_type) for cvariable, _vartype in cvar_and_vartypes}
        if new_entries != cvar_and_vartypes:
            unified_locals[variable] = new_entries
            changed = True
    return changed


def _attach_cod_global_declaration_types(
    codegen: StructuredCodegenValue, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    """Apply scalar storage widths; aggregate typing is owned by Lowering."""

    def _impl() -> bool:
        if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
            return False

        short_type = SimTypeShort(False)
        char_type = SimTypeChar(False)
        changed = False

        changed = _retune_in_use_global_types_8616(
            getattr(codegen.cfunc, "variables_in_use", {}), synthetic_globals, short_type, char_type
        )

        cexterns = getattr(codegen, "cexterns", ()) or ()
        if _retune_cextern_global_types_8616(cexterns, synthetic_globals, short_type, char_type):
            changed = True

        unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict) and _retune_unified_global_types_8616(
            unified_locals, synthetic_globals, short_type, char_type
        ):
            changed = True

        return changed

    return _impl()


def _access_trait_field_name(offset: int, size: int) -> str:
    return f"field_{offset:x}"


def _stack_object_name(offset: int) -> str:
    if offset >= 0:
        return f"arg_{offset:x}"
    return f"local_{-offset:x}"


def _access_trait_variable_key(variable: StructuredAstValue) -> tuple[object, ...] | None:
    if isinstance(variable, SimRegisterVariable):
        return ("reg", variable.reg)
    if isinstance(variable, SimStackVariable):
        identity = _stack_slot_identity_for_variable(variable)
        if identity is None:
            return None
        return ("stack", identity.base, variable.offset, variable.region)
    if isinstance(variable, SimMemoryVariable):
        return ("mem", variable.addr)
    return None


def _access_trait_profile_for_key(
    evidence_profiles: Mapping[tuple[object, ...], _AccessTraitEvidenceProfile],
    base_key: tuple[object, ...],
) -> _AccessTraitEvidenceProfile | None:
    return cast(_AccessTraitEvidenceProfile | None, _cli_access_profiles.access_trait_profile_for_key(evidence_profiles, base_key))  # type: ignore[redundant-cast]


@dataclass(frozen=True)
class _WideningMatch:
    kind: str
    base_expr: object
    delta: int = 0


@dataclass(frozen=True)
class _AccessTraitRewriteDecision:
    base_key: tuple[object, ...]
    profile: _AccessTraitEvidenceProfile

    def _inner(self) -> _cli_access_profiles.AccessTraitRewriteDecision:
        return _cli_access_profiles.AccessTraitRewriteDecision(self.base_key, self.profile)

    def should_rename_stack(self) -> bool:
        """Return whether stable evidence permits stack-object renaming."""
        return bool(self._inner().should_rename_stack())

    def preferred_kind(self) -> str | None:
        """Return the preferred recovered object kind, when evidence is stable."""
        result = self._inner().preferred_kind()
        return result if isinstance(result, str) else None

    def candidate_field_names(self) -> tuple[str, ...]:
        """Return deterministic field-name candidates from access evidence."""
        result = self._inner().candidate_field_names(_access_trait_field_name)
        return tuple(result) if isinstance(result, tuple) else ()


def _build_access_trait_evidence_profiles(
    traits: dict[str, dict[tuple[object, ...], object]],
) -> dict[tuple[object, ...], _AccessTraitEvidenceProfile]:
    return cast(  # type: ignore[redundant-cast]
        dict[tuple[object, ...], _AccessTraitEvidenceProfile],
        _cli_access_profiles.build_access_trait_evidence_profiles(traits),
    )


def _linear_delta_or_base_8616(
    base: StructuredAstValue, resolve_copy_alias_expr: StructuredAstValue
) -> tuple[StructuredAstValue, bool]:
    """Resolve an Or-shaped duplicate-word base; ok=False ⇒ abort the fold."""

    if isinstance(base, structured_c.CBinaryOp) and base.op == "Or":
        duplicate_word_base = _match_duplicate_word_base_expr(base, resolve_copy_alias_expr)
        if duplicate_word_base is None:
            return None, False
        return duplicate_word_base, True
    return base, True


def _extract_linear_widening_delta_8616(
    expr: StructuredAstValue,
    resolve_copy_alias_expr: StructuredAstValue,
    seen: set[int] | None = None,
    depth: int = 0,
) -> StructuredAstValue:
    """Extract ``base +/- const`` structure into (base, delta)."""

    if depth > 64:
        return expr, 0
    expr = resolve_copy_alias_expr(_unwrap_c_casts(expr))
    if seen is None:
        seen = set()
    key = id(expr)
    if key in seen:
        return expr, 0
    seen.add(key)
    if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
        return None, int(expr.value)
    if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Or":
        duplicate_word_base = _match_duplicate_word_base_expr(expr, resolve_copy_alias_expr)
        if duplicate_word_base is not None:
            return duplicate_word_base, 0
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op not in {"Add", "Sub"}:
        return expr, 0

    left_base, left_delta = _extract_linear_widening_delta_8616(
        expr.lhs, resolve_copy_alias_expr, seen, depth + 1
    )
    right_base, right_delta = _extract_linear_widening_delta_8616(
        expr.rhs, resolve_copy_alias_expr, seen, depth + 1
    )
    left_base, left_ok = _linear_delta_or_base_8616(left_base, resolve_copy_alias_expr)
    if not left_ok:
        return expr, 0
    right_base, right_ok = _linear_delta_or_base_8616(right_base, resolve_copy_alias_expr)
    if not right_ok:
        return expr, 0
    return _fold_linear_delta_parts_8616(expr, left_base, left_delta, right_base, right_delta)


def _fold_linear_delta_parts_8616(
    expr: StructuredAstValue,
    left_base: StructuredAstValue,
    left_delta: int,
    right_base: StructuredAstValue,
    right_delta: int,
) -> StructuredAstValue:
    """Fold (base, delta) pairs across an Add/Sub node."""

    if left_base is not None and right_base is not None:
        if _same_c_expression(left_base, right_base) and expr.op == "Add":
            return left_base, left_delta + right_delta
        return expr, 0
    if left_base is not None:
        if expr.op == "Add":
            return left_base, left_delta + right_delta
        return left_base, left_delta - right_delta
    if right_base is not None:
        if expr.op == "Add":
            return right_base, left_delta + right_delta
        return expr, 0
    if expr.op == "Add":
        return None, left_delta + right_delta
    return None, left_delta - right_delta


def _high_byte_preserving_scale_arm_8616(
    high_expr: StructuredAstValue,
    base_expr: StructuredAstValue,
    match_high_byte_projection_base: StructuredAstValue,
) -> StructuredAstValue:
    """Match the ``(base +/- 1) * 0x100`` scale side of the widening."""

    for maybe_delta, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
        if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 0x100:
            continue
        delta_expr = _unwrap_c_casts(maybe_delta)
        if not isinstance(delta_expr, structured_c.CBinaryOp) or delta_expr.op not in {"Add", "Sub"}:
            continue

        for maybe_inner, maybe_const in ((delta_expr.lhs, delta_expr.rhs), (delta_expr.rhs, delta_expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_const)) != 1:
                continue
            if match_high_byte_projection_base(maybe_inner) is None:
                continue
            if not _same_c_expression(_unwrap_c_casts(maybe_inner), base_expr):
                continue
            return _WideningMatch("high_byte_preserving", base_expr, 0x100)
    return None


def _match_high_byte_preserving_widening_8616(
    node: StructuredAstValue, match_high_byte_projection_base: StructuredAstValue
) -> StructuredAstValue:
    """Match ``(base & 255) | ((base +/- 1) * 0x100)`` widening shapes."""

    for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_expr = _unwrap_c_casts(low_expr)
        high_expr = _unwrap_c_casts(high_expr)
        if not isinstance(low_expr, structured_c.CBinaryOp) or low_expr.op != "And":
            continue

        base_expr = None
        for maybe_word, maybe_mask in ((low_expr.lhs, low_expr.rhs), (low_expr.rhs, low_expr.lhs)):
            if _c_constant_value(_unwrap_c_casts(maybe_mask)) != 255:
                continue
            base_expr = _unwrap_c_casts(maybe_word)
            break
        if base_expr is None:
            continue

        if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op != "Mul":
            continue

        matched = _high_byte_preserving_scale_arm_8616(high_expr, base_expr, match_high_byte_projection_base)
        if matched is not None:
            return matched

    return None


def _analyze_widening_expr(
    node: StructuredAstValue,
    resolve_copy_alias_expr: StructuredAstValue,
    match_high_byte_projection_base: StructuredAstValue,
) -> StructuredAstValue:
    """Classify an expression as a linear or high-byte-preserving widening."""

    node = resolve_copy_alias_expr(_unwrap_c_casts(node))

    base_expr, delta = _extract_linear_widening_delta_8616(node, resolve_copy_alias_expr)
    if base_expr is not None and isinstance(delta, int) and delta != 0:
        return _WideningMatch("linear", base_expr, delta)

    node = _unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
        return None

    return _match_high_byte_preserving_widening_8616(node, match_high_byte_projection_base)

def _access_trait_member_candidates(
    traits: dict[str, dict[tuple[object, ...], int]],
) -> dict[tuple[object, ...], list[tuple[int, int, int]]]:
    compatible_traits = cast(dict[str, dict[tuple[object, ...], object]], traits)
    return cast(  # type: ignore[redundant-cast]
        dict[tuple[object, ...], list[tuple[int, int, int]]],
        _cli_access_profiles.access_trait_member_candidates(compatible_traits),
    )


def _should_attach_access_trait_names(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_access_trait_rewrite._should_attach_access_trait_names(
        codegen,
        has_access_rewrite_artifact=lambda current_codegen: _cli_access_rewrite_artifact.has_access_rewrite_artifact(
            getattr(current_codegen, "project", None),
            getattr(getattr(current_codegen, "cfunc", None), "addr", None),
            build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            build_stable_access_object_hints=lambda traits: _cli_access_object_hints._build_stable_access_object_hints(
                traits,
                build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            ),
        ),
    )
    )


def _attach_access_trait_field_names(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_access_trait_rewrite._attach_access_trait_field_names(
        project,
        codegen,
        should_attach_access_trait_names=_should_attach_access_trait_names,
        load_access_rewrite_artifact=lambda current_project, function_addr: (
            _cli_access_rewrite_artifact.load_access_rewrite_artifact(
                current_project,
                function_addr if isinstance(function_addr, int) else None,
                build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
                build_stable_access_object_hints=lambda traits: (
                    _cli_access_object_hints._build_stable_access_object_hints(
                        traits,
                        build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
                    )
                ),
            )
        ),
        stable_access_object_hint_for_key=_cli_access_object_hints._stable_access_object_hint_for_key,
        access_trait_variable_key=_access_trait_variable_key,
        stack_object_name=_stack_object_name,
        access_trait_field_name=_access_trait_field_name,
        replace_c_children=_replace_c_children,
    ))


def _attach_pointer_member_names(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_access_trait_rewrite._attach_pointer_member_names(
        project,
        codegen,
        should_attach_access_trait_names=_should_attach_access_trait_names,
        load_access_rewrite_artifact=lambda current_project, function_addr: (
            _cli_access_rewrite_artifact.load_access_rewrite_artifact(
                current_project,
                function_addr if isinstance(function_addr, int) else None,
                build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
                build_stable_access_object_hints=lambda traits: (
                    _cli_access_object_hints._build_stable_access_object_hints(
                        traits,
                        build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
                    )
                ),
            )
        ),
        stable_access_object_hint_for_key=_cli_access_object_hints._stable_access_object_hint_for_key,
        access_trait_variable_key=_access_trait_variable_key,
        access_trait_field_name=_access_trait_field_name,
        replace_c_children=_replace_c_children,
    ))


def _lst_is_linear_temp_8616(cvar: StructuredAstValue) -> bool:
    """Return whether the cvar is a linear ``vN`` temp."""

    return (
        isinstance(cvar, structured_c.CVariable)
        and isinstance(getattr(cvar, "name", None), str)
        and re.fullmatch(r"v\d+", getattr(cvar, "name", "")) is not None
    )


def _lst_temp_alias_value_8616(rhs: StructuredAstValue, aliases: dict[int, int]) -> int | None:
    """Resolve an assignment rhs to a constant through aliases."""

    if isinstance(rhs, structured_c.CConstant) and isinstance(rhs.value, int):
        return rhs.value
    if isinstance(rhs, structured_c.CVariable):
        return aliases.get(id(rhs.variable))
    return None


def _lst_collect_temp_aliases_8616(statements: StructuredAstValue) -> dict[int, int]:
    """Collect constant aliases for linear temps over a fixed point."""

    aliases: dict[int, int] = {}
    for _ in range(3):
        changed = False
        for walk_node in _iter_c_nodes_deep(statements):
            if not isinstance(walk_node, structured_c.CAssignment) or not isinstance(
                walk_node.lhs, structured_c.CVariable
            ):
                continue
            if not _lst_is_linear_temp_8616(walk_node.lhs):
                continue
            rhs = _unwrap_c_casts(walk_node.rhs)
            value = _lst_temp_alias_value_8616(rhs, aliases)
            if value is None:
                continue
            lhs_var = getattr(walk_node.lhs, "variable", None)
            if lhs_var is None:
                continue
            key = id(lhs_var)
            if aliases.get(key) != value:
                aliases[key] = value
                changed = True
        if not changed:
            break
    return aliases


def _lst_resolved_constant_value_8616(
    node: StructuredAstValue, temp_const_aliases: dict[int, int], seen_nodes: set[int] | None = None
) -> int | None:
    """Resolve a node to a constant through temp aliases and Add/Sub folds."""

    node = _unwrap_c_casts(node)
    if seen_nodes is None:
        seen_nodes = set()
    key = id(node)
    if key in seen_nodes:
        return None
    seen_nodes.add(key)
    constant = _c_constant_value(node)
    if constant is not None:
        return constant
    if isinstance(node, structured_c.CVariable):
        variable = node.variable
        if variable is not None:
            return temp_const_aliases.get(id(variable))
    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs = _lst_resolved_constant_value_8616(node.lhs, temp_const_aliases, seen_nodes)
        rhs = _lst_resolved_constant_value_8616(node.rhs, temp_const_aliases, seen_nodes)
        if lhs is not None and rhs is not None:
            return lhs + rhs if node.op == "Add" else lhs - rhs
    return None


def _lst_make_data_var_8616(
    created: dict[tuple[int, int], structured_c.CVariable],
    offset: int,
    size: int,
    label: str,
    codegen: StructuredCodegenValue,
) -> StructuredAstValue:
    """Build or reuse a named data CVariable for an offset."""

    key = (offset, size)
    existing = created.get(key)
    if existing is not None:
        return existing
    cvar = structured_c.CVariable(
        SimMemoryVariable(offset, size, name=_sanitize_cod_identifier(label), region=codegen.cfunc.addr),
        variable_type=SimTypeChar(False) if size == 1 else SimTypeShort(False),
        codegen=codegen,
    )
    created[key] = cvar
    return cvar


def _lst_deref_segment_terms_8616(
    operand: StructuredAstValue,
    temp_const_aliases: dict[int, int],
    project: AngrProjectValue,
) -> tuple[str | None, int, list[object]]:
    """Fold seg*16 + const terms into (seg_name, linear, other_terms)."""

    seg_name = None
    linear = 0
    saw_segment = False
    other_terms: list[object] = []
    for term in _flatten_c_add_terms(operand):
        inner = _unwrap_c_casts(term)
        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if _c_constant_value(_unwrap_c_casts(maybe_scale)) != 16:
                    continue
                name = _segment_reg_name(_unwrap_c_casts(maybe_seg), project)
                if name is not None:
                    seg_name = name
                    saw_segment = True
                    break
            if saw_segment:
                continue

        const_value = _lst_resolved_constant_value_8616(inner, temp_const_aliases)
        if const_value is not None:
            linear += const_value
            continue

        other_terms.append(inner)
    return seg_name, linear, other_terms


def _lst_deref_arm_8616(
    node: StructuredAstValue,
    created: dict[tuple[int, int], structured_c.CVariable],
    temp_const_aliases: dict[int, int],
    lst_metadata: LSTMetadata,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
) -> StructuredAstValue:
    """Name a ``ds:linear`` dereference to its LST data label."""

    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        operand = operand.expr

    seg_name, linear, other_terms = _lst_deref_segment_terms_8616(operand, temp_const_aliases, project)

    if seg_name == "ds" and not other_terms:
        label = _lst_data_label(lst_metadata, linear)
        if label is not None:
            type_ = node.type
            if type_ is not None:
                bits = getattr(type_, "size", None)
                size = _storage_size_from_type_bits(bits, project)
                return _lst_make_data_var_8616(created, linear, size, label, codegen)
    return node


def _lst_var_arm_8616(
    node: StructuredAstValue,
    created: dict[tuple[int, int], structured_c.CVariable],
    lst_metadata: LSTMetadata,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
) -> StructuredAstValue:
    """Name a SimMemoryVariable to its LST data label."""

    variable = node.variable
    if isinstance(variable, SimMemoryVariable):
        addr = variable.addr
        label = lst_metadata.data_labels.get(addr) if isinstance(addr, int) else None
        if label is not None and isinstance(addr, int):
            type_ = node.variable_type
            bits = getattr(type_, "size", None)
            size = _storage_size_from_type_bits(bits, project)
            return _lst_make_data_var_8616(created, addr, size, label, codegen)
    return node


def _attach_lst_data_names(
    project: AngrProjectValue, codegen: StructuredCodegenValue, lst_metadata: LSTMetadata | None
) -> bool:
    """Attach LST data labels to memory variables and ds dereferences."""

    if lst_metadata is None or getattr(codegen, "cfunc", None) is None:
        return False

    created: dict[tuple[int, int], structured_c.CVariable] = {}
    temp_const_aliases = _lst_collect_temp_aliases_8616(codegen.cfunc.statements)

    def transform(node: StructuredAstValue) -> StructuredAstValue:
        if isinstance(node, structured_c.CVariable):
            return _lst_var_arm_8616(node, created, lst_metadata, project, codegen)
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            return _lst_deref_arm_8616(node, created, temp_const_aliases, lst_metadata, project, codegen)
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if _replace_c_children(root, transform):
        changed = True
    return changed

def _is_stable_byte_register_8616(expr: StructuredAstValue) -> bool:
    """Check the alias-storage domain is a proven 8-bit register."""

    facts = describe_alias_storage(expr)
    domain = facts.domain
    return (
        domain.space == "register"
        and domain.width == 8
        and not domain.is_unknown()
        and not domain.is_mixed()
        and not facts.needs_synthesis()
        and facts.identity is not None
    )


def _set_c_variable_type_8616(node: StructuredAstValue, type_: StructuredAstValue) -> bool:
    """Set ``node.variable_type`` when it differs; False on failure."""

    if not hasattr(node, "variable_type"):
        return False
    if getattr(node, "variable_type", None) == type_:
        return False
    try:
        node.variable_type = type_
    except Exception:
        return False
    return True


def _normalize_in_use_byte_register_types_8616(
    variables_in_use: Mapping[SimVariable, structured_c.CVariable], target_type: StructuredAstValue
) -> bool:
    """Retype in-use stable byte-register variables."""

    changed = False
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimRegisterVariable):
            continue
        if variable.size != 1:
            continue
        if not _is_stable_byte_register_8616(cvar):
            continue
        current_type = getattr(cvar, "variable_type", None)
        if current_type != target_type and _set_c_variable_type_8616(cvar, target_type):
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and _set_c_variable_type_8616(unified, target_type):
            changed = True
    return changed


def _normalize_unified_byte_register_types_8616(
    unified_locals: MutableMapping[SimVariable, set[tuple[structured_c.CVariable, object]]], target_type: StructuredAstValue
) -> bool:
    """Retype stable byte-register entries in the unified-local map."""

    changed = False
    for variable, cvar_and_vartypes in list(unified_locals.items()):
        if not isinstance(variable, SimRegisterVariable):
            continue
        if variable.size != 1:
            continue
        new_entries = {
            (
                cvariable,
                target_type if _is_stable_byte_register_8616(cvariable) else vartype,
            )
            for cvariable, vartype in cvar_and_vartypes
        }
        if new_entries != cvar_and_vartypes:
            unified_locals[variable] = new_entries
            changed = True
    return changed


def _normalize_byte_register_node_types_8616(
    statements: StructuredAstValue, target_type: StructuredAstValue
) -> bool:
    """Retype stable byte-register CVariable nodes in the body."""

    changed = False
    for node in _iter_c_nodes_deep(statements):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = node.variable
        if not isinstance(variable, SimRegisterVariable):
            continue
        if variable.size != 1:
            continue
        if not _is_stable_byte_register_8616(node):
            continue
        if node.variable_type != target_type:
            changed = _set_c_variable_type_8616(node, target_type) or changed
        unified = node.unified_variable
        if unified is not None and hasattr(unified, "variable_type") and _set_c_variable_type_8616(
            unified, target_type
        ):
            changed = True
    return changed


def _normalize_scalar_byte_register_types(codegen: StructuredCodegenValue) -> bool:
    """Normalize proven stable 8-bit register variables to char type."""

    if getattr(codegen, "cfunc", None) is None:
        return False

    target_type = SimTypeChar(False)
    changed = _normalize_in_use_byte_register_types_8616(
        getattr(codegen.cfunc, "variables_in_use", {}), target_type
    )

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict) and _normalize_unified_byte_register_types_8616(
        unified_locals, target_type
    ):
        changed = True

    if _normalize_byte_register_node_types_8616(getattr(codegen.cfunc, "statements", None), target_type):
        changed = True

    return changed

_SEGMENT_REG_DESIRED_NAMES_8616 = {"cs", "ds", "es", "ss", "fs", "gs"}


def _segment_register_var_name_8616(
    variable: StructuredAstValue, project: AngrProjectValue | None
) -> str | None:
    """Resolve a segment-register name from the arch map or variable name."""

    if not isinstance(variable, SimRegisterVariable):
        return None
    if project is not None:
        reg = variable.reg
        name = project.arch.register_names.get(reg) if isinstance(reg, int) else None
        if isinstance(name, str) and name in _SEGMENT_REG_DESIRED_NAMES_8616:
            return name
    name = variable.name
    if isinstance(name, str) and name in _SEGMENT_REG_DESIRED_NAMES_8616:
        return name
    return None


def _attach_segment_names_in_use_8616(
    variables_in_use: Mapping[SimVariable, structured_c.CVariable], project: AngrProjectValue | None
) -> bool:
    """Attach segment names to in-use register variables."""

    changed = False
    for variable, cvar in variables_in_use.items():
        name = _segment_register_var_name_8616(variable, project)
        if name is None:
            continue
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "name", None) != name:
            unified.name = name
            changed = True
    return changed


def _attach_segment_names_unified_8616(
    unified_locals: MutableMapping[SimVariable, set[tuple[structured_c.CVariable, object]]], project: AngrProjectValue | None
) -> bool:
    """Attach segment names to unified-local register variables."""

    changed = False
    for variable, cvar_and_vartypes in list(unified_locals.items()):
        name = _segment_register_var_name_8616(variable, project)
        if name is None:
            continue
        new_entries = set()
        for cvariable, vartype in cvar_and_vartypes:
            new_entries.add((cvariable, vartype))
        if new_entries != cvar_and_vartypes:
            unified_locals[variable] = new_entries
            changed = True
    return changed


def _attach_segment_register_names(codegen: StructuredCodegenValue, project: AngrProjectValue = None) -> bool:
    """Attach canonical segment-register names to matching variables."""

    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = _attach_segment_names_in_use_8616(
        getattr(codegen.cfunc, "variables_in_use", {}), project
    )

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict) and _attach_segment_names_unified_8616(unified_locals, project):
        changed = True

    return changed

def _is_generic_var_name_8616(name: object) -> bool:
    """Return whether the name is a generated temp identifier."""

    return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+|ir_\d+)", name) is not None


def _arch_register_var_name_8616(
    variable: StructuredAstValue,
    register_names: Mapping[int, object],
    registers: Mapping[object, tuple[int, int]],
) -> str | None:
    """Resolve a register variable to its arch register name."""

    if not isinstance(variable, SimRegisterVariable):
        return None
    reg = variable.reg
    size = variable.size
    if isinstance(reg, int) and isinstance(size, int):
        for name, (offset, reg_size) in registers.items():
            if isinstance(name, str) and offset == reg and reg_size == size:
                return name
    name = register_names.get(reg)
    if not isinstance(name, str) or not name:
        return None
    return name


def _rename_register_variable_8616(variable: StructuredAstValue, cvar: StructuredAstValue, name: str) -> bool:
    """Rename a register variable/cvar/unified triple; return changed."""

    changed = False
    if getattr(variable, "name", None) != name:
        variable.name = name
        changed = True
    if getattr(cvar, "name", None) != name:
        try:
            cvar.name = name
        except Exception:
            pass
        else:
            changed = True
    unified = getattr(cvar, "unified_variable", None)
    if unified is not None and getattr(unified, "name", None) != name:
        unified.name = name
        changed = True
    return changed


def _attach_register_names_in_use_8616(
    variables_in_use: Mapping[SimVariable, structured_c.CVariable],
    register_names: Mapping[int, object],
    registers: Mapping[object, tuple[int, int]],
) -> bool:
    """Rename in-use register variables that still carry temp names."""

    changed = False
    for variable, cvar in variables_in_use.items():
        name = _arch_register_var_name_8616(variable, register_names, registers)
        if name is None:
            continue
        if not any(
            _is_generic_var_name_8616(candidate)
            for candidate in (
                getattr(variable, "name", None),
                getattr(cvar, "name", None),
                getattr(getattr(cvar, "unified_variable", None), "name", None),
            )
        ):
            continue
        if _rename_register_variable_8616(variable, cvar, name):
            changed = True
    return changed


def _attach_register_names_unified_8616(
    unified_locals: MutableMapping[SimVariable, set[tuple[structured_c.CVariable, object]]],
    register_names: Mapping[int, object],
    registers: Mapping[object, tuple[int, int]],
) -> bool:
    """Rename unified-local register variables carrying temp names."""

    changed = False
    for variable, cvar_and_vartypes in list(unified_locals.items()):
        name = _arch_register_var_name_8616(variable, register_names, registers)
        if name is None:
            continue
        if not any(
            _is_generic_var_name_8616(candidate)
            for candidate in (
                getattr(variable, "name", None),
                *(getattr(cvar, "name", None) for cvar, _vartype in cvar_and_vartypes),
            )
        ):
            continue
        for cvar, _vartype in cvar_and_vartypes:
            if _rename_register_variable_8616(variable, cvar, name):
                changed = True
    return changed


def _attach_register_names(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    """Attach arch register names to register variables with temp names."""

    if getattr(codegen, "cfunc", None) is None:
        return False

    register_names = getattr(getattr(project, "arch", None), "register_names", None)
    registers = getattr(getattr(project, "arch", None), "registers", None)
    if not isinstance(register_names, dict):
        return False
    if not isinstance(registers, dict):
        registers = {}

    changed = _attach_register_names_in_use_8616(
        getattr(codegen.cfunc, "variables_in_use", {}), register_names, registers
    )

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict) and _attach_register_names_unified_8616(
        unified_locals, register_names, registers
    ):
        changed = True

    return changed

def _elide_redundant_segment_pointer_dereferences(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_segmented_elision._elide_redundant_segment_pointer_dereferences(
            project,
            codegen,
            iter_c_nodes_deep=_iter_c_nodes_deep,
            classify_segmented_dereference=_compat_callback(_classify_segmented_dereference),
            flatten_c_add_terms=_flatten_c_add_terms,
            unwrap_c_casts=_unwrap_c_casts,
            c_constant_value=_c_constant_value,
            segment_reg_name=_segment_reg_name,
            match_segment_register_based_dereference=_match_segment_register_based_dereference,
            strip_segment_scale_from_addr_expr=_strip_segment_scale_from_addr_expr,
            same_c_storage=_same_c_storage,
            replace_c_children=_replace_c_children,
        ),
    )


def _collect_access_traits(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_access_traits._collect_access_traits(
            project,
            codegen,
            iter_c_nodes_deep=_iter_c_nodes_deep,
            unwrap_c_casts=_unwrap_c_casts,
            c_constant_value=_c_constant_value,
            classify_segmented_dereference=_compat_callback(_classify_segmented_dereference),
            stack_slot_identity_for_variable=_compat_callback(_stack_slot_identity_for_variable),
            access_trait_variable_key=_access_trait_variable_key,
            AccessTraitStrideEvidence=_AccessTraitStrideEvidence,
        ),
    )


def _prune_unused_unnamed_memory_declarations(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_memory_prune._prune_unused_unnamed_memory_declarations(
            codegen,
            iter_c_nodes_deep=_iter_c_nodes_deep,
        ),
    )


def _prune_unused_linear_register_declarations(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_local_prune._prune_unused_linear_register_declarations(
            codegen,
            iter_c_nodes_deep=_iter_c_nodes_deep,
        ),
    )


def _prune_unused_local_declarations(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_local_prune._prune_unused_local_declarations(
            codegen,
            iter_c_nodes_deep=_iter_c_nodes_deep,
            describe_alias_storage=_compat_callback(describe_alias_storage),
        ),
    )


def _prune_dead_local_assignments(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_dead_local_prune._prune_dead_local_assignments(
            codegen,
            structured_codegen_node=_structured_codegen_node,
            iter_c_nodes_deep=_iter_c_nodes_deep,
            unwrap_c_casts=_unwrap_c_casts,
            describe_alias_storage=_compat_callback(describe_alias_storage),
        ),
    )


def _materialize_missing_stack_local_declarations(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_local_rewrites._materialize_missing_stack_local_declarations(
            codegen,
            stack_slot_identity_for_variable=_compat_callback(_stack_slot_identity_for_variable),
            stack_type_for_size=_stack_type_for_size,
            replace_c_children=_replace_c_children,
            iter_c_nodes_deep=_iter_c_nodes_deep,
        ),
    )


def _dedupe_codegen_variable_names_8616(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_local_rewrites._dedupe_codegen_variable_names_8616(
            codegen,
            make_unique_identifier=_make_unique_identifier,
        ),
    )


def _materialize_missing_register_local_declarations(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_local_rewrites._materialize_missing_register_local_declarations(
            codegen,
            stack_slot_identity_for_variable=_compat_callback(_stack_slot_identity_for_variable),
            stack_type_for_size=_stack_type_for_size,
            structured_codegen_node=_structured_codegen_node,
            iter_c_nodes_deep=_iter_c_nodes_deep,
        ),
    )


def _prune_void_function_return_values(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_local_rewrites._prune_void_function_return_values(
            codegen,
            iter_c_nodes_deep=_iter_c_nodes_deep,
        ),
    )


def _coalesce_far_pointer_stack_expressions(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_far_pointer_stack._coalesce_far_pointer_stack_expressions(
            project,
            codegen,
            unwrap_c_casts=_unwrap_c_casts,
            segment_reg_name=_segment_reg_name,
            iter_c_nodes_deep=_iter_c_nodes_deep,
            resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
            build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            build_stable_access_object_hints=lambda traits: _cli_access_object_hints._build_stable_access_object_hints(
                traits,
                build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            ),
            access_trait_variable_key=_access_trait_variable_key,
            replace_c_children=_replace_c_children,
            describe_alias_storage=_compat_callback(describe_alias_storage),
        ),
    )


def _simplify_nested_mk_fp_calls(codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_mkfp_simplify._simplify_nested_mk_fp_calls(
            codegen,
            unwrap_c_casts=_unwrap_c_casts,
            c_constant_value=_c_constant_value,
            replace_c_children=_replace_c_children,
        ),
    )


def _attach_ss_stack_variables(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_stack_locals._attach_ss_stack_variables(
            project,
            codegen,
            match_ss_stack_reference=_match_ss_stack_reference,
            resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
            replace_c_children=_replace_c_children,
            stack_slot_identity_for_variable=_compat_callback(_stack_slot_identity_for_variable),
        ),
    )


def _rewrite_ss_stack_byte_offsets(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_stack_byte_offsets._rewrite_ss_stack_byte_offsets(
            project,
            codegen,
            unwrap_c_casts=_unwrap_c_casts,
            iter_c_nodes_deep=_iter_c_nodes_deep,
            replace_c_children=_replace_c_children,
            c_constant_value=_c_constant_value,
            flatten_c_add_terms=_flatten_c_add_terms,
            classify_segmented_dereference=_classify_segmented_dereference,
            strip_segment_scale_from_addr_expr=_strip_segment_scale_from_addr_expr,
            resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
            promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
            stack_type_for_size=_stack_type_for_size,
            materialize_stack_cvar_at_offset=_materialize_stack_cvar_at_offset,
            stack_slot_identity_for_variable=_compat_callback(_stack_slot_identity_for_variable),
            stack_pointer_alias_state=_compat_callback(_StackPointerAliasState),
        ),
    )


def _promote_direct_stack_cvariable(
    codegen: StructuredCodegenValue, cvar: StructuredAstValue, size: int, type_: StructuredAstValue
) -> bool:
    return cast(bool, _cli_stack_locals._promote_direct_stack_cvariable(codegen, cvar, size, type_))  # type: ignore[redundant-cast]


def _stack_type_for_size(size: int) -> StructuredAstValue:
    return _cli_stack_locals._stack_type_for_size(size)


def _resolve_stack_cvar_at_offset(
    codegen: StructuredCodegenValue, offset: int, *, preferred_size: int | None = None
) -> StructuredAstValue:
    return _cli_stack_cvars._resolve_stack_cvar_at_offset(
        codegen,
        offset,
        stack_slot_identity_for_variable=_compat_callback(_stack_slot_identity_for_variable),
        preferred_size=preferred_size,
    )


def _materialize_stack_cvar_at_offset(
    codegen: StructuredCodegenValue, offset: int, size: int = 2
) -> StructuredAstValue:
    return _cli_stack_cvars._materialize_stack_cvar_at_offset(
        codegen,
        offset,
        size,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        stack_type_for_size=_stack_type_for_size,
    )


def _canonicalize_stack_cvar_expr(
    expr: StructuredAstValue,
    codegen: StructuredCodegenValue,
    active_expr_ids: set[int] | None = None,
    analysis_context: dict[str, object] | None = None,
) -> StructuredAstValue:
    return _cli_stack_cvars._canonicalize_stack_cvar_expr(
        expr,
        codegen,
        unwrap_c_casts=_unwrap_c_casts,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        materialize_stack_cvar_at_offset=_materialize_stack_cvar_at_offset,
        active_expr_ids=active_expr_ids,
        analysis_context=analysis_context,
    )


def _canonicalize_stack_cvars(codegen: StructuredCodegenValue) -> bool:
    return cast(
        bool,
        _cli_stack_cvars._canonicalize_stack_cvars(
        codegen,
        replace_c_children=_replace_c_children,
        canonicalize_stack_cvar_expr=_canonicalize_stack_cvar_expr,
        ),
    )


def _resolve_stack_cvar_from_addr_expr(
    project: AngrProjectValue, codegen: StructuredCodegenValue, addr_expr: StructuredAstValue
) -> StructuredAstValue:
    return _cli_stack_cvars._resolve_stack_cvar_from_addr_expr(
        project,
        codegen,
        addr_expr,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        materialize_stack_cvar_at_offset=_materialize_stack_cvar_at_offset,
        stack_type_for_size=_stack_type_for_size,
    )


def _coalesce_direct_ss_local_word_statements(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(
        bool,
        _cli_stack_coalesce._coalesce_direct_ss_local_word_statements(
        project,
        codegen,
        match_ss_local_plus_const=_match_ss_local_plus_const,
        match_shift_right_8_expr=_match_shift_right_8_expr,
        stack_slot_identity_can_join=_stack_slot_identity_can_join,
        derived_stack_high_byte_follows_slot=_derived_stack_high_byte_follows_cvar,
        same_c_expression=_same_c_expression,
        unwrap_c_casts=_unwrap_c_casts,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        stack_type_for_size=_stack_type_for_size,
        match_byte_store_addr_expr=_match_byte_store_addr_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
        resolve_stack_cvar_from_addr_expr=_resolve_stack_cvar_from_addr_expr,
        canonicalize_stack_cvar_expr=_canonicalize_stack_cvar_expr,
        ),
    )


def _seed_adjacent_byte_pair_aliases(project: AngrProjectValue, codegen: StructuredCodegenValue) -> dict[int, object]:
    return cast(  # type: ignore[redundant-cast]
        dict[int, object],
        _cli_linear_aliases._seed_adjacent_byte_pair_aliases(
        project,
        codegen,
        structured_codegen_node=_structured_codegen_node,
        unwrap_c_casts=_unwrap_c_casts,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
        make_word_dereference_from_addr_expr=_make_word_dereference_from_addr_expr,
        ),
    )


def _coalesce_linear_recurrence_statements(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_linear_recurrence._coalesce_linear_recurrence_statements(
            project,
            codegen,
            unwrap_c_casts=_unwrap_c_casts,
            structured_codegen_node=_structured_codegen_node,
            iter_c_nodes_deep=_iter_c_nodes_deep,
            same_c_expression=_same_c_expression,
            c_constant_value=_c_constant_value,
            canonicalize_stack_cvar_expr=_canonicalize_stack_cvar_expr,
            seed_adjacent_byte_pair_aliases=_compat_callback(_seed_adjacent_byte_pair_aliases),
            describe_alias_storage=describe_alias_storage,
            analyze_widening_expr=_analyze_widening_expr,
            match_high_byte_projection_base=_match_high_byte_projection_base,
        match_duplicate_word_base_expr=_match_duplicate_word_base_expr,
        match_duplicate_word_increment_shift_expr=_match_duplicate_word_increment_shift_expr,
        same_stack_slot_identity_var=_same_stack_slot_identity_var,
        rules=_cli_linear_recurrence_rules,
        ),
    )


def _coalesce_segmented_word_store_statements(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(
        bool,
        _cli_segmented_store_coalesce._coalesce_segmented_word_store_statements(
        project,
        codegen,
        match_ss_local_plus_const=_match_ss_local_plus_const,
        match_word_rhs_from_byte_pair=_match_word_rhs_from_byte_pair,
        promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
        stack_type_for_size=_stack_type_for_size,
        stack_slot_identity_can_join=_stack_slot_identity_can_join,
        canonicalize_stack_cvar_expr=_canonicalize_stack_cvar_expr,
        match_byte_store_addr_expr=_match_byte_store_addr_expr,
        match_shift_right_8_expr=_match_shift_right_8_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
        resolve_stack_cvar_from_addr_expr=_resolve_stack_cvar_from_addr_expr,
        make_word_dereference_from_addr_expr=_make_word_dereference_from_addr_expr,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        describe_alias_storage=describe_alias_storage,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
        same_c_expression=_same_c_expression,
        ),
    )


def _run_typed_widening_pass(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(
        bool,
        _cli_segmented_store_coalesce.run_typed_widening_pass_8616(
        project,
        codegen,
        coalesce_direct_ss_local_word_statements=_coalesce_direct_ss_local_word_statements,
        coalesce_segmented_word_store_statements=_coalesce_segmented_word_store_statements,
        promote_stack_slots_from_instruction_widths=lambda current_project, current_codegen: (
                _cli_segmented_store_coalesce.promote_stack_slots_from_instruction_widths_8616(
                    current_project,
                    current_codegen,
                    resolve_stack_cvar_at_offset=_resolve_stack_cvar_at_offset,
                    promote_direct_stack_cvariable=_promote_direct_stack_cvariable,
                    stack_type_for_size=_stack_type_for_size,
                )
        ),
        ),
    )


def _global_memory_addr(node: StructuredAstValue) -> int | None:
    return cast(int | None, _cli_word_loads._global_memory_addr(node))


def _global_load_addr(node: StructuredAstValue, project: AngrProjectValue) -> int | None:
    return cast(int | None, _cli_word_loads._global_load_addr(node, project))


def _match_scaled_high_byte(node: StructuredAstValue, project: AngrProjectValue) -> int | None:
    return cast(
        int | None,
        _cli_word_loads._match_scaled_high_byte(
        node,
        project,
        c_constant_value=_c_constant_value,
        global_load_addr=_global_load_addr,
        ),
    )


def _extract_dereference_addr_expr(node: StructuredAstValue) -> StructuredAstValue:
    return _cli_word_loads._extract_dereference_addr_expr(node)


def _match_byte_load_addr_expr(node: StructuredAstValue) -> StructuredAstValue:
    return _cli_word_loads._match_byte_load_addr_expr(
        node,
        unwrap_c_casts=_unwrap_c_casts,
    )


def _match_byte_store_addr_expr(node: StructuredAstValue) -> StructuredAstValue:
    return _cli_word_loads._match_byte_store_addr_expr(node)


def _match_shifted_high_byte_addr_expr(node: StructuredAstValue) -> StructuredAstValue:
    return _cli_word_loads._match_shifted_high_byte_addr_expr(
        node,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
    )


def _match_word_pair_low_addr_expr(node: StructuredAstValue, project: AngrProjectValue) -> StructuredAstValue:
    return _cli_word_loads._match_word_pair_low_addr_expr(
        node,
        project,
        unwrap_c_casts=_unwrap_c_casts,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
        match_shifted_high_byte_addr_expr=_match_shifted_high_byte_addr_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
    )


def _split_expr_const_offset(node: StructuredAstValue) -> StructuredAstValue:
    return _cli_segmented_compare._split_expr_const_offset(
        node,
        flatten_c_add_terms=_flatten_c_add_terms,
        unwrap_c_casts=_unwrap_c_casts,
        c_constant_value=_c_constant_value,
    )


def _same_expression_list(lhs_terms: StructuredAstValue, rhs_terms: StructuredAstValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_segmented_compare._same_expression_list(
        lhs_terms,
        rhs_terms,
        same_c_expression=_same_c_expression,
        ),
    )


def _addr_exprs_are_same(
    low_addr_expr: StructuredAstValue, high_addr_expr: StructuredAstValue, project: AngrProjectValue
) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_segmented_compare._addr_exprs_are_same(
        low_addr_expr,
        high_addr_expr,
        project,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        same_c_expression=_same_c_expression,
        split_expr_const_offset=_split_expr_const_offset,
        same_expression_list=_same_expression_list,
        ),
    )


def _addr_exprs_are_byte_pair(
    low_addr_expr: StructuredAstValue, high_addr_expr: StructuredAstValue, project: AngrProjectValue = None
) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_segmented_compare._addr_exprs_are_byte_pair(
        low_addr_expr,
        high_addr_expr,
        project,
        classify_segmented_addr_expr=_classify_segmented_addr_expr,
        stack_slot_identity_can_join_var=_stack_slot_identity_can_join_var,
        split_expr_const_offset=_split_expr_const_offset,
        same_expression_list=_same_expression_list,
        ),
    )


def _make_word_dereference_from_addr_expr(
    codegen: StructuredCodegenValue, project: AngrProjectValue, addr_expr: StructuredAstValue
) -> StructuredAstValue:
    return _cli_word_loads._make_word_dereference_from_addr_expr(codegen, project, addr_expr)


def _match_word_dereference_addr_expr(node: StructuredAstValue) -> StructuredAstValue:
    return _cli_word_loads._match_word_dereference_addr_expr(node)


def _word_from_constant_byte_pair(
    low_unwrapped: StructuredAstValue, high_unwrapped: StructuredAstValue, codegen: StructuredCodegenValue
) -> StructuredAstValue:
    if not (
        isinstance(low_unwrapped, structured_c.CConstant)
        and isinstance(low_unwrapped.value, int)
        and isinstance(high_unwrapped, structured_c.CConstant)
        and isinstance(high_unwrapped.value, int)
    ):
        return None
    return _canonicalize_stack_cvar_expr(
        structured_c.CConstant(
            (low_unwrapped.value & 0xFF) | ((high_unwrapped.value & 0xFF) << 8),
            SimTypeShort(False),
            codegen=codegen,
        ),
        codegen,
    )


def _word_from_adjacent_memory_bytes(
    low_unwrapped: StructuredAstValue, high_unwrapped: StructuredAstValue, codegen: StructuredCodegenValue
) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        low_mem_addr = _global_memory_addr(low_unwrapped)
        high_mem_addr = _global_memory_addr(high_unwrapped)
        if not (
            isinstance(low_unwrapped, structured_c.CVariable)
            and isinstance(high_unwrapped, structured_c.CVariable)
            and isinstance(getattr(low_unwrapped, "variable", None), SimMemoryVariable)
            and isinstance(getattr(high_unwrapped, "variable", None), SimMemoryVariable)
            and low_mem_addr is not None
            and high_mem_addr == low_mem_addr + 1
        ):
            return None
        if not analyze_adjacent_storage_slices(low_unwrapped, high_unwrapped).ok:
            return None
        low_var = getattr(low_unwrapped, "variable", None)
        name = getattr(low_var, "name", None) if isinstance(low_var, SimMemoryVariable) else None
        if not isinstance(name, str) or not name or re.fullmatch(r"(?:v\d+|vvar_\d+)", name):
            return None
        return _canonicalize_stack_cvar_expr(
            structured_c.CVariable(
                SimMemoryVariable(low_mem_addr, 2, name=_sanitize_cod_identifier(name), region=codegen.cfunc.addr),
                variable_type=SimTypeShort(False),
                codegen=codegen,
            ),
            codegen,
        )

    return _impl()


def _word_from_shifted_high_expr(
    low_rhs: StructuredAstValue,
    high_rhs: StructuredAstValue,
    low_unwrapped: StructuredAstValue,
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
) -> StructuredAstValue:
    def _safe_type_size(node: StructuredAstValue) -> int | None:
        try:
            return getattr(getattr(node, "type", None), "size", None)
        except ValueError:
            return None

    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is None:
        return None
    shifted_source = _unwrap_c_casts(shifted_source)
    low_bits = _safe_type_size(low_unwrapped)
    if _same_c_expression(_unwrap_c_casts(low_rhs), shifted_source) and (
        isinstance(low_unwrapped, (structured_c.CVariable, structured_c.CConstant)) or low_bits == 16
    ):
        return _canonicalize_stack_cvar_expr(low_rhs, codegen)
    low_addr_expr = _match_byte_load_addr_expr(low_unwrapped)
    word_addr_expr = _match_word_dereference_addr_expr(shifted_source)
    if (
        low_addr_expr is not None
        and word_addr_expr is not None
        and _addr_exprs_are_same(low_addr_expr, word_addr_expr, project)
    ):
        return _canonicalize_stack_cvar_expr(shifted_source, codegen)
    return None


def _word_from_pair_low_addr(
    low_unwrapped: StructuredAstValue,
    high_rhs: StructuredAstValue,
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
) -> StructuredAstValue:
    low_pair_addr = _match_word_pair_low_addr_expr(low_unwrapped, project)
    if low_pair_addr is None:
        return None
    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is None:
        return None
    word_addr_expr = _match_word_dereference_addr_expr(_unwrap_c_casts(shifted_source))
    if word_addr_expr is None or not _addr_exprs_are_same(low_pair_addr, word_addr_expr, project):
        return None
    return _canonicalize_stack_cvar_expr(
        _make_word_dereference_from_addr_expr(codegen, project, low_pair_addr),
        codegen,
    )


def _word_from_byte_pair_addr_match(
    low_unwrapped: StructuredAstValue,
    high_rhs: StructuredAstValue,
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
) -> StructuredAstValue:
    low_addr_expr = _match_byte_load_addr_expr(low_unwrapped)
    high_addr_expr = _match_shifted_high_byte_addr_expr(high_rhs)
    if low_addr_expr is None or high_addr_expr is None:
        return None
    if not _addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
        return None
    return _canonicalize_stack_cvar_expr(
        _make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
        codegen,
    )


def _word_from_widening_shift_match(
    low_rhs: StructuredAstValue, high_rhs: StructuredAstValue, codegen: StructuredCodegenValue
) -> StructuredAstValue:
    shifted_source = _match_shift_right_8_expr(high_rhs)
    if shifted_source is None:
        return None
    shifted_source = _unwrap_c_casts(shifted_source)
    low_expr = _unwrap_c_casts(low_rhs)
    analysis = _analyze_widening_expr(shifted_source, lambda expr: expr, lambda expr: expr)
    if analysis is not None and analysis.kind == "linear" and analysis.delta in {1, -1}:  # noqa: SIM102
        if _same_c_expression(low_expr, analysis.base_expr):
            return _canonicalize_stack_cvar_expr(shifted_source, codegen)
    if _same_c_expression(low_expr, shifted_source):
        return _canonicalize_stack_cvar_expr(shifted_source, codegen)
    return None


def _match_word_rhs_from_byte_pair(
    low_rhs: StructuredAstValue,
    high_rhs: StructuredAstValue,
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
) -> StructuredAstValue:
    low_unwrapped = _unwrap_c_casts(low_rhs)
    high_unwrapped = _unwrap_c_casts(high_rhs)
    result = _word_from_constant_byte_pair(low_unwrapped, high_unwrapped, codegen)
    if result is not None:
        return result
    result = _word_from_adjacent_memory_bytes(low_unwrapped, high_unwrapped, codegen)
    if result is not None:
        return result
    result = _word_from_shifted_high_expr(low_rhs, high_rhs, low_unwrapped, codegen, project)
    if result is not None:
        return result
    result = _word_from_pair_low_addr(low_unwrapped, high_rhs, codegen, project)
    if result is not None:
        return result
    result = _word_from_byte_pair_addr_match(low_unwrapped, high_rhs, codegen, project)
    if result is not None:
        return result
    result = _word_from_widening_shift_match(low_rhs, high_rhs, codegen)
    if result is not None:
        return result
    return None


def _high_byte_store_addr(node: StructuredAstValue, project: AngrProjectValue) -> int | None:
    return cast(
        int | None,
        _cli_word_loads._high_byte_store_addr(
        node,
        project,
        classify_segmented_dereference=_classify_segmented_dereference,
        ),
    )


def _synthetic_word_global_variable(
    codegen: StructuredCodegenValue,
    synthetic_globals: dict[int, tuple[str, int]] | None,
    addr: int,
    created: dict[int, structured_c.CVariable] | None = None,
) -> StructuredAstValue:
    return _cli_word_global_helpers._synthetic_word_global_variable(
        codegen,
        synthetic_globals,
        addr,
        synthetic_global_entry=_synthetic_global_entry,
        sanitize_cod_identifier=_sanitize_cod_identifier,
        created=created,
    )


def _coalesce_cod_word_global_loads(
    project: AngrProjectValue, codegen: StructuredCodegenValue, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_cod_globals._coalesce_cod_word_global_loads(
        project,
        codegen,
            synthetic_globals,
            collect_access_traits=_collect_access_traits,
            build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            build_stable_access_object_hints=lambda traits: _cli_access_object_hints._build_stable_access_object_hints(
                traits,
                build_access_trait_evidence_profiles=_build_access_trait_evidence_profiles,
            ),
        global_load_addr=_global_load_addr,
        match_scaled_high_byte=_match_scaled_high_byte,
        synthetic_word_global_variable=_compat_callback(_synthetic_word_global_variable),
        replace_c_children=_replace_c_children,
        ),
    )


def _coalesce_segmented_word_load_expressions(project: AngrProjectValue, codegen: StructuredCodegenValue) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_segmented_load_coalesce._coalesce_segmented_word_load_expressions(
        project,
        codegen,
        unwrap_c_casts=_unwrap_c_casts,
        iter_c_nodes_deep=_iter_c_nodes_deep,
        replace_c_children=_replace_c_children,
        structured_codegen_node=_structured_codegen_node,
        match_byte_load_addr_expr=_match_byte_load_addr_expr,
        match_shifted_high_byte_addr_expr=_match_shifted_high_byte_addr_expr,
        addr_exprs_are_byte_pair=_addr_exprs_are_byte_pair,
        classify_segmented_addr_expr=_compat_callback(_classify_segmented_addr_expr),
        resolve_stack_cvar_from_addr_expr=_resolve_stack_cvar_from_addr_expr,
        make_word_dereference_from_addr_expr=_make_word_dereference_from_addr_expr,
        describe_alias_storage=_compat_callback(describe_alias_storage),
        ),
    )


def _coalesce_cod_word_global_statements(
    project: AngrProjectValue, codegen: StructuredCodegenValue, synthetic_globals: dict[int, tuple[str, int]] | None
) -> bool:
    return cast(  # type: ignore[redundant-cast]
        bool,
        _cli_cod_global_statements._coalesce_cod_word_global_statements(
        project,
        codegen,
        synthetic_globals,
        global_memory_addr=_global_memory_addr,
        high_byte_store_addr=_high_byte_store_addr,
        synthetic_word_global_variable=_compat_callback(_synthetic_word_global_variable),
        ),
    )


def _int21_call_replacements(
    project: AngrProjectValue, function: StructuredAstValue, api_style: str, binary_path: Path | None
) -> list[str]:
    return cast(  # type: ignore[redundant-cast]
        list[str],
        _cli_helper_modeling._int21_call_replacements(
        project,
        function,
        api_style,
        binary_path,
        collect_dos_int21_calls=collect_dos_int21_calls,
        render_dos_int21_call=_compat_callback(render_dos_int21_call),
        ),
    )


def _interrupt_call_replacement_map(
    project: AngrProjectValue, function: StructuredAstValue, api_style: str, binary_path: Path | None
) -> dict[str, tuple[str, ...]]:
    return cast(  # type: ignore[redundant-cast]
        dict[str, tuple[str, ...]],
        _cli_helper_modeling._interrupt_call_replacement_map(
        project,
        function,
        api_style,
        binary_path,
        collect_interrupt_service_calls=collect_interrupt_service_calls,
        render_interrupt_call=_compat_callback(render_interrupt_call),
        helper_name=_helper_name,
        interrupt_service_addr=_compat_callback(interrupt_service_addr),
        interrupt_service_name=_compat_callback(interrupt_service_name),
        ),
    )


def _dos_helper_declarations(function: StructuredAstValue, api_style: str, binary_path: Path | None) -> list[str]:
    return cast(  # type: ignore[redundant-cast]
        list[str],
        _cli_helper_modeling._dos_helper_declarations(
        function,
        api_style,
        binary_path,
        collect_dos_int21_calls=collect_dos_int21_calls,
        dos_helper_declarations=_compat_callback(dos_helper_declarations),
        ),
    )


def _interrupt_helper_declarations(function: StructuredAstValue, api_style: str, binary_path: Path | None) -> list[str]:
    return cast(  # type: ignore[redundant-cast]
        list[str],
        _cli_helper_modeling._interrupt_helper_declarations(
        function,
        api_style,
        binary_path,
        collect_interrupt_service_calls=collect_interrupt_service_calls,
        interrupt_service_declarations=_compat_callback(interrupt_helper_declarations_8616),
        ),
    )


def _known_helper_declarations(cod_metadata: CODProcMetadata | None) -> list[str]:
    return cast(  # type: ignore[redundant-cast]
        list[str],
        _cli_helper_modeling._known_helper_declarations(
        cod_metadata,
        preferred_known_helper_signature_decl=preferred_known_helper_signature_decl,
        ),
    )


def _is_staging_local_name(name: str | None) -> bool:
    return isinstance(name, str) and re.fullmatch(r"s_[0-9a-fA-F]+", name) is not None


def _clone_c_value_container_8616(value: StructuredAstValue, memo: dict[int, object]) -> StructuredAstValue:
    """Deep-clone list/tuple/dict containers elementwise."""

    if isinstance(value, list):
        return [_clone_structured_c_value(item, memo) for item in value]
    if isinstance(value, tuple):
        return tuple(_clone_structured_c_value(item, memo) for item in value)
    if isinstance(value, dict):
        return {
            _clone_structured_c_value(key, memo): _clone_structured_c_value(item, memo)
            for key, item in value.items()
        }
    return value


def _clone_c_value_slot_names_8616(value: StructuredAstValue) -> list[str]:
    """Ordered unique __slots__ names across the class hierarchy."""

    slot_names: list[str] = []
    for cls in type(value).__mro__:
        slots = getattr(cls, "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        slot_names.extend(slots)
    return list(dict.fromkeys(slot_names))


def _clone_c_value_slots_8616(value: StructuredAstValue, clone: object, memo: dict[int, object]) -> None:
    """Deep-clone slot attributes onto the shallow copy."""

    for attr in _clone_c_value_slot_names_8616(value):
        if attr == "codegen" or not hasattr(value, attr):
            continue
        try:
            child = getattr(value, attr)
        except Exception:
            continue
        cloned_child = _clone_structured_c_value(child, memo)
        if cloned_child is not child:
            try:
                setattr(clone, attr, cloned_child)
            except Exception:
                continue


def _clone_structured_c_value(value: StructuredAstValue, memo: dict[int, object] | None = None) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        nonlocal memo
        if memo is None:
            memo = {}

        if not _structured_codegen_node(value):
            return _clone_c_value_container_8616(value, memo)

        value_id = id(value)
        if value_id in memo:
            return memo[value_id]

        clone = copy.copy(value)
        memo[value_id] = clone
        _clone_c_value_slots_8616(value, clone, memo)
        return clone

    return _impl()


def _collect_staging_wrapper_summary(statements: list[object]) -> tuple[int, dict[int, object], set[int], bool]:
    def _impl() -> tuple[int, dict[int, object], set[int], bool]:
        call_count = 0
        staging_replacements: dict[int, object] = {}
        staging_variable_ids: set[int] = set()
        non_staging_logic = False
        for stmt in statements:
            if (isinstance(stmt, structured_c.CExpressionStatement) and isinstance(
                stmt.expr, structured_c.CFunctionCall
            )) or isinstance(stmt, structured_c.CFunctionCall):
                call_count += 1
            if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
                if not (
                    isinstance(stmt, (structured_c.CFunctionCall, structured_c.CReturn))
                    or (
                        isinstance(stmt, structured_c.CExpressionStatement)
                        and isinstance(getattr(stmt, "expr", None), structured_c.CFunctionCall)
                    )
                ):
                    non_staging_logic = True
                continue
            variable = getattr(stmt.lhs, "variable", None)
            if not _is_staging_local_name(getattr(variable, "name", None)):
                continue
            staging_variable_ids.add(id(variable))
            staging_replacements[id(variable)] = _clone_structured_c_value(stmt.rhs)
        return call_count, staging_replacements, staging_variable_ids, non_staging_logic

    return _impl()


def _rewrite_staging_statements(
    statements: list[object], staging_replacements: dict[int, object], staging_variable_ids: set[int]
) -> tuple[list[object], bool]:
    changed = False

    def transform(node: StructuredAstValue) -> StructuredAstValue:
        if isinstance(node, structured_c.CVariable):
            variable = node.variable
            replacement = staging_replacements.get(id(variable))
            if replacement is not None:
                return replacement
        return node

    new_statements = []
    for stmt in statements:
        if isinstance(stmt, structured_c.CAssignment) and isinstance(stmt.lhs, structured_c.CVariable):
            variable = getattr(stmt.lhs, "variable", None)
            if id(variable) in staging_variable_ids:
                changed = True
                continue
        if _structured_codegen_node(stmt) and _replace_c_children(stmt, transform):
            changed = True
        new_statements.append(stmt)
    return new_statements, changed


def _remove_unused_staging_vars_from_maps(
    codegen: StructuredCodegenValue, staging_variable_ids: set[int], used_variables: set[int]
) -> bool:
    changed = False
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if id(variable) in staging_variable_ids and id(variable) not in used_variables:
                del variables_in_use[variable]
                changed = True
    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable in list(unified_locals):
            if id(variable) in staging_variable_ids and id(variable) not in used_variables:
                del unified_locals[variable]
                changed = True
    return changed


def _staging_used_variable_ids_8616(root: StructuredAstValue) -> set[int]:
    """Collect ids of all variables (and unified vars) referenced in the body."""

    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = node.variable
        if variable is not None:
            used_variables.add(id(variable))
        unified = node.unified_variable
        if unified is not None:
            used_variables.add(id(unified))
    return used_variables


def _prune_tiny_wrapper_staging_locals(codegen: StructuredCodegenValue) -> bool:
    def _impl() -> bool:
        if getattr(codegen, "cfunc", None) is None:
            return False
        root = getattr(codegen.cfunc, "statements", None)
        if not isinstance(root, structured_c.CStatements):
            return False

        statements = list(root.statements)
        if not statements:
            return False
        if any(isinstance(stmt, (structured_c.CIfElse, structured_c.CWhileLoop)) for stmt in statements):
            return False

        call_count, staging_replacements, staging_variable_ids, non_staging_logic = _collect_staging_wrapper_summary(
            statements
        )

        if call_count != 1 or not staging_replacements or non_staging_logic:
            return False

        new_statements, changed = _rewrite_staging_statements(statements, staging_replacements, staging_variable_ids)

        if len(new_statements) != len(statements):
            root.statements = new_statements

        used_variables = _staging_used_variable_ids_8616(root)
        changed = _remove_unused_staging_vars_from_maps(codegen, staging_variable_ids, used_variables) or changed
        return changed

    return _impl()


# Missing symbols during split:
# - _SegmentedAccess
# - _SegmentAssociationState
_AST_REWRITE_LOGGER = logging.getLogger(__name__)
