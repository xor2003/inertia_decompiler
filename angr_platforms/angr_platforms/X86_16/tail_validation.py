"""Layer: Tail Validation.

Responsibility: compare recovered behavior against observed effects and report honest deltas.
Forbidden: semantic recovery from source, COD, assembly, or rendered C text.
Dynamic boundary: this module reads third-party angr/codegen C AST attributes
through getattr/setattr when validating observed behavior.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, MutableMapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, cast

from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CDirtyExpression,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeBottom
from angr.sim_variable import SimMemoryVariable

from inertia_decompiler.telemetry import span

from .c_ast_utils import _iter_c_nodes_deep_8616
from .call_target_identity import (
    normalize_x86_16_call_target_addr_8616,
    normalize_x86_16_direct_call_target_8616,
)
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_summary import (
    CallsiteSummary8616,
    callsite_summary_inventory_8616,
    structured_callsite_addr_8616,
    summarize_x86_16_callsite,
)
from .compiler_helpers import is_x86_16_stack_probe_helper_at_8616
from .decompiler_postprocess_flags import _split_ordering_if_chain_replacement_condition_8616
from .ir.condition_ir import (
    _INVERTED_COMPARISON_OPS_8616,
    _split_fingerprint_args_8616,
    _split_fingerprint_call_8616,
    canonicalize_condition_storage_fingerprint_8616,
    invert_condition_fingerprint_string_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from .ir.core import SegmentOrigin
from .ir.segment_state import SegmentStateArtifact, SegmentValueKind8616
from .lowering.call_output_stack_objects import CallOutputStackObjectFact8616
from .lowering.indexed_global_evidence import IndexedSegmentedGlobalEvidence8616
from .lowering.real_mode_linear import DirectStackMoveFact8616
from .lowering.return_type_evidence import function_result_is_proven_unobserved_8616
from .lowering.segmented_global_loads import (
    DwordGlobalZeroTestEvidence8616,
    IndexedGlobalReadCarrierMaterializationRecord8616,
)
from .lowering.stack_function_coordinates import final_c_function_machine_bp_offset_8616
from .pipeline.errors import PipelineHardError
from .pipeline.structured_ast_query_index import StructuredAstQueryIndex8616
from .structuring.canonical_for_loops import canonical_loop_validation_shape_8616
from .structuring.indexed_stack_ranges import (
    IndexedStackReadProof8616,
    collect_indexed_stack_read_proofs_8616,
)
from .structuring.loop_break_jcc import (
    LoopHeaderDuplicateGuardRemovalFact8616,
    loop_branch_guard_facts_8616,
)
from .structuring.return_chains import (
    ExpressionFingerprintCallbacks8616,
    identical_assignment_arm_condition_8616,
)
from .structuring.shared_loop_exit import shared_exit_fingerprint_8616
from .structuring.shared_loop_exit_publication import shared_loop_exit_report_8616
from .tail_validation_condition_context import build_x86_16_contextual_condition_fingerprints
from .tail_validation_fingerprint import (
    TAIL_VALIDATION_FINGERPRINT_VERSION,
    _c_constant_int_value,
    _call_target_name,
    _collect_direct_capstone_callsite_addrs_8616,
    _expr_fingerprint,
    _function_for_call_context_8616,
    _indexed_global_write_location_fingerprints_8616,
    _is_runtime_segment_helper_call_8616,
    _is_structured_c_intrinsic_call_8616,
    _location_fingerprint,
    _resolve_call_symbol_addr_8616,
    _target_abi_type_size_bytes_8616,
    _wrap_not_fingerprint,
    build_x86_16_contextual_call_fingerprints,
)
from .tail_validation_generation import (
    TailValidationSummaryInputGeneration8616,
    tail_validation_summary_input_generation_8616,
)
from .tail_validation_routing import build_tail_validation_family_routing
from .tail_validation_selector_returns import (
    collect_selector_return_fingerprints_8616,
    compact_selector_return_fingerprint_8616,
)
from .tail_validation_stack_policy import StackObservedLocations8616, include_x86_16_tail_validation_stack_write
from .validation.entry_stack_ranges import entry_stack_ranges_from_codegen_8616
from .validation.status_flag_preservation import packed_status_flag_preservation_evidence_8616
from .validation_branch_conditions import validate_materialized_branch_conditions_8616
from .validation_call_multiplicity import (
    CallsiteMultiplicityValidationReport8616,
    validate_required_callsite_multiplicity_8616,
)
from .validation_calls import (
    CallArgumentClassValidationReport8616,
    CallInterfaceValidationReport8616,
    FunctionParameterValidationReport8616,
    FunctionReturnClassValidationReport8616,
    RequiredCallsiteValidationReport8616,
    build_required_call_validation_surface_8616,
    validate_call_argument_classes_8616,
    validate_call_interfaces_8616,
    validate_function_parameters_8616,
    validate_function_return_class_8616,
    validate_required_callsites_8616,
)
from .validation_condition_identity import condition_ir_semantic_fingerprint_8616
from .validation_condition_storage_views import condition_storage_views_match_8616
from .validation_control_flow import (
    ControlFlowValidationReport8616,
    validate_structured_control_flow_8616,
)
from .validation_control_flow_obligations import (
    switch_exit_obligations_from_codegen_8616,
    validate_switch_exit_obligations_8616,
)
from .validation_dataflow import (
    DefUseCallOutputDefinition8616,
    DefUseValidationReport8616,
    validate_structured_def_use_8616,
)
from .validation_interrupt_calls import (
    SoftwareInterruptValidationReport8616,
    validate_software_interrupt_inputs_8616,
)
from .validation_observable_compaction import (
    compact_normalized_validation_observable_8616,
)
from .validation_pointer_parameter_output_contracts import (
    PointerParameterOutputValidationReport8616,
)
from .validation_pointer_parameter_outputs import (
    validate_pointer_parameter_outputs_8616,
)
from .validation_required_memory_effects import (
    RequiredMemoryEffectValidationReport8616,
    validate_required_memory_effects_8616,
)
from .validation_semantic_failures import (
    TailSemanticFailureScope8616,
    collect_tail_semantic_failures_8616,
    format_tail_semantic_failures_8616,
    normalize_tail_semantic_failures_8616,
)
from .validation_storage import (
    StorageIdentityValidationReport8616,
    validate_storage_identities_8616,
)

type StructuredAstValue = Any
type TailValidationValue = Any

_TAIL_VALIDATION_EXPRESSION_CALLBACKS_8616 = ExpressionFingerprintCallbacks8616(
    expr_fingerprint=_expr_fingerprint,
    iter_c_nodes_deep=_iter_c_nodes_deep_8616,
)


def _boundary_tuple_8616(value: StructuredAstValue) -> tuple[StructuredAstValue, ...]:
    """Convert a dynamic angr/codegen iterable to a tuple without changing semantics."""
    return tuple(cast(Iterable[StructuredAstValue], value))


def _boundary_list_8616(value: StructuredAstValue) -> list[StructuredAstValue]:
    """Convert a dynamic angr/codegen iterable to a list without changing semantics."""
    return list(cast(Iterable[StructuredAstValue], value))


def _boundary_set_8616(value: StructuredAstValue) -> set[StructuredAstValue]:
    """Convert a dynamic angr/codegen iterable to a set without changing semantics."""
    return set(cast(Iterable[StructuredAstValue], value))


__all__ = [
    "X86_16TailValidationSummary",
    "X86_16ValidationCacheDescriptor",
    "annotate_x86_16_tail_validation_surface_with_baseline",
    "build_x86_16_tail_validation_aggregate",
    "build_x86_16_tail_validation_baseline",
    "build_x86_16_tail_validation_cached_result",
    "build_x86_16_tail_validation_surface",
    "build_x86_16_tail_validation_verdict",
    "build_x86_16_validation_cache_descriptor",
    "callsite_consumed_stack_store_prune_delta_8616",
    "callsite_far_pointer_remnant_prune_delta_8616",
    "callsite_helper_control_target_delta_8616",
    "callsite_mixed_helper_stack_control_delta_8616",
    "callsite_resolved_indirect_helper_control_delta_8616",
    "callsite_resolved_indirect_helper_stack_delta_8616",
    "callsite_stack_arg_slot_alias_condition_delta_8616",
    "callsite_stack_precision_control_delta_8616",
    "canonicalize_tail_validation_summary_field_values_8616",
    "check_x86_16_tail_validation_surface_consistency",
    "collect_x86_16_tail_validation_summary",
    "compare_x86_16_tail_validation_baseline",
    "compare_x86_16_tail_validation_summaries",
    "conditional_continue_guard_repair_delta_8616",
    "describe_x86_16_tail_validation_scope",
    "direct_stack_move_function_pointer_prune_delta_8616",
    "direct_stack_move_idiv_remainder_aux_delta_8616",
    "dword_global_zero_test_precision_delta_8616",
    "exit_goto_repair_delta_8616",
    "extract_x86_16_tail_validation_snapshot",
    "fingerprint_x86_16_tail_validation_boundary",
    "format_x86_16_tail_validation_diff",
    "indexed_global_read_carrier_precision_delta_8616",
    "indexed_segmented_global_precision_delta_8616",
    "loop_exit_return_guard_repair_delta_8616",
    "loop_header_duplicate_guard_removal_delta_8616",
    "name_only_helper_annotation_delta_8616",
    "persist_x86_16_tail_validation_snapshot",
    "refresh_x86_16_final_semantic_validation_8616",
    "resolve_x86_16_validation_cached_artifact",
    "segmented_stack_slot_size_precision_delta_8616",
    "summarize_x86_16_tail_validation_records",
    "switch_loop_exit_return_repair_delta_8616",
    "validation_delta_removes_stack_or_control_effects_8616",
    "validation_delta_touched_fields_8616",
    "validation_stack_offsets_in_token_8616",
    "validation_stack_write_delta_offsets_are_evidenced_8616",
    "validation_without_delta_fields_8616",
    "void_tail_call_guard_materialization_delta_8616",
    "x86_16_tail_validation_snapshot_passed",
]

_TAIL_VALIDATION_MODES = {"coarse", "live_out"}
_TAIL_VALIDATION_AGGREGATE_CACHE: dict[str, dict[str, TailValidationValue]] = {}
_TAIL_VALIDATION_OBSERVABLE_FIELDS = (
    "helper_calls",
    "register_writes",
    "stack_writes",
    "exposed_stack_values",
    "global_writes",
    "segmented_writes",
    "returns",
    "conditions",
    "control_flow_effects",
)
_TAIL_VALIDATION_SEMANTIC_FAILURE_FIELDS = (
    "def_use_issues",
    "missing_required_calls",
    "callsite_multiplicity_issues",
    "call_interface_issues",
    "call_argument_class_issues",
    "function_parameter_issues",
    "function_return_class_issues",
    "control_flow_issues",
    "storage_identity_issues",
)
_MISSING_CALLSITE_FINGERPRINT_PREFIX_8616 = "missing-callsite:"
_COMPACT_OBSERVABLE_FIELDS_8616 = {"conditions", "control_flow_effects"}
_TAIL_VALIDATION_COMPARISON_VERSION_8616 = 15
_STACK_ARG_ALIAS_TOKEN_RE_8616 = re.compile(
    r"stack_arg:(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::size(?P<size>\d+))?(?::bp[+-]0x[0-9a-fA-F]+)?"
)
_SEGMENTED_STACK_SLOT_SIZE_TOKEN_RE_8616 = re.compile(r"stack_slot:SS:BP(?P<offset>[+-]0x[0-9a-fA-F]+):size[0-9]+")
_LEGACY_STACK_LOCATION_TOKEN_RE_8616 = re.compile(r"(?P<prefix>^|[:,])stack:(?P<offset>[+-]0x[0-9a-fA-F]+)")
_STACK_OFFSET_TOKEN_RE_8616 = re.compile(r"BP(?P<sign>[+-])0x(?P<value>[0-9a-fA-F]+)")
_LOOP_BODY_WRITE_EFFECT_PREFIXES_8616 = (
    "while-body-writes:",
    "dowhile-body-writes:",
    "for-body-writes:",
)
_CONTROL_FLOW_WRITE_LOCATION_MARKERS_8616 = (
    "stack_slot:",
    "stack:",
    "ds_global:",
    "global:",
    "deref:",
    "reg:",
)


def conditional_continue_guard_repair_delta_8616(
    materialized_count: int,
    validation: Mapping[str, TailValidationValue],
) -> bool:
    """Accept only validation deltas introduced by proven conditional-continue guard repair."""
    if materialized_count <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added", ()) or ())
            or _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
    }
    if not touched_fields or touched_fields - {"conditions", "control_flow_effects"}:
        return False
    saw_removed_ifbreak = False
    for field_name in touched_fields:
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, Mapping):
            return False
        if _boundary_tuple_8616(field_delta.get("added", ()) or ()):
            return False
        removed = _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        if not removed:
            return False
        if field_name == "control_flow_effects":
            if any(not isinstance(item, str) or not item.startswith("ifbreak:") for item in removed):
                return False
            saw_removed_ifbreak = True
        elif field_name == "conditions":
            if any(not isinstance(item, str) or not item.startswith("Cmp") for item in removed):
                return False
    return saw_removed_ifbreak


def loop_header_duplicate_guard_removal_delta_8616(
    facts: Sequence[LoopHeaderDuplicateGuardRemovalFact8616],
    validation: Mapping[str, TailValidationValue],
) -> bool:
    """Accept only exact redundant break removals proven by loop-header JCC facts."""
    if not facts:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added", ()) or ())
            or _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
    }
    if touched_fields != {"control_flow_effects"}:
        return False
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, Mapping):
        return False
    if _boundary_tuple_8616(control_delta.get("added", ()) or ()):
        return False
    removed_controls = _boundary_tuple_8616(
        control_delta.get("removed", ()) or ()
    )
    if not removed_controls:
        return False

    evidenced_guards: set[str] = set()
    for fact in facts:
        removed_guard = normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(
                fact.removed_guard_fingerprint
            )
        )
        retained_loop = normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(
                fact.retained_loop_fingerprint
            )
        )
        inverted_guard = invert_condition_fingerprint_string_8616(
            removed_guard
        )
        if inverted_guard is None:
            return False
        normalized_inverted_guard = normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(inverted_guard)
        )
        if normalized_inverted_guard != retained_loop:
            return False
        evidenced_guards.add(removed_guard)

    removed_guards: set[str] = set()
    for control in removed_controls:
        if not isinstance(control, str) or not control.startswith("ifbreak:"):
            return False
        removed_guards.add(
            normalize_condition_fingerprint_algebraic_8616(
                normalize_condition_fingerprint_string_8616(
                    control[len("ifbreak:") :]
                )
            )
        )
    return bool(removed_guards) and removed_guards <= evidenced_guards


def loop_exit_return_guard_repair_delta_8616(
    materialized_count: int,
    validation: Mapping[str, TailValidationValue],
) -> bool:
    """Accept a proven loop ``if (cond) return;`` to ``if (cond) break;`` rewrite.

    The Structuring pass preserves the condition and changes only the control
    shape and the empty return statement.  Requiring a one-to-one condition
    fingerprint match prevents this validator from accepting arbitrary return
    deletion or branch changes merely because a loop-repair pass ran.
    """
    if materialized_count <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added", ()) or ())
            or _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
    }
    if touched_fields != {"returns", "control_flow_effects"}:
        return False

    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, Mapping):
        return False
    if _boundary_tuple_8616(returns_delta.get("added", ()) or ()):
        return False
    removed_returns = _boundary_tuple_8616(returns_delta.get("removed", ()) or ())
    # Empty CReturn nodes are represented as ``none`` by the compact fixture
    # boundary and as ``return`` by the live angr tail fingerprint.
    if not removed_returns or any(item not in {"none", "return"} for item in removed_returns):
        return False

    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, Mapping):
        return False
    added = _boundary_tuple_8616(control_delta.get("added", ()) or ())
    removed = _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    if not added:
        return False
    added_conditions = {
        item[len("ifbreak:") :]
        for item in added
        if isinstance(item, str) and item.startswith("ifbreak:")
    }
    removed_conditions = {
        item[len("if:") :]
        for item in removed
        if isinstance(item, str) and item.startswith("if:")
    }
    removed_non_guards = tuple(
        item for item in removed if not (isinstance(item, str) and item.startswith("if:"))
    )
    return (
        len(added_conditions) == len(added)
        and len(removed_conditions) == len(removed) - len(removed_non_guards)
        and added_conditions == removed_conditions
        and all(item == "return" for item in removed_non_guards)
        and len(removed_non_guards) <= 1
    )


def switch_loop_exit_return_repair_delta_8616(
    materialized_count: int,
    validation: Mapping[str, TailValidationValue],
) -> bool:
    """Accept only validation deltas introduced by proven switch-loop exit-return repair."""
    if materialized_count <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added", ()) or ())
            or _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
    }
    if not touched_fields or touched_fields - {"returns", "control_flow_effects"}:
        return False
    returns_delta = delta.get("returns")
    if isinstance(returns_delta, Mapping):
        added_returns = _boundary_tuple_8616(returns_delta.get("added", ()) or ())
        removed_returns = _boundary_tuple_8616(returns_delta.get("removed", ()) or ())
        if removed_returns and not _switch_loop_exit_return_replacement_delta_8616(
            added_returns,
            removed_returns,
            touched_fields,
        ):
            return False
        if not removed_returns and added_returns not in ((), ("none",)):
            return False
    elif "returns" in touched_fields:
        return False
    if touched_fields == {"returns"}:
        return True
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, Mapping):
        return False
    added_control = _boundary_tuple_8616(control_delta.get("added", ()) or ())
    removed_control = _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    if removed_control:
        return False
    return bool(added_control) and all(
        isinstance(token, str) and token.startswith("case:const:") for token in added_control
    )


def _switch_loop_exit_return_replacement_delta_8616(
    added_returns: tuple[TailValidationValue, ...],
    removed_returns: tuple[TailValidationValue, ...],
    touched_fields: set[str],
) -> bool:
    """Return whether a return delta is an allowed switch-loop void-tail replacement."""
    if not touched_fields or touched_fields - {"returns", "control_flow_effects"}:
        return False
    if added_returns != ("none",):
        return False
    if not removed_returns:
        return False
    return all(isinstance(token, str) and re.fullmatch(r"Add\(reg:ax,const:-\d+\)", token) for token in removed_returns)


def exit_goto_repair_delta_8616(validation: Mapping[str, TailValidationValue]) -> bool:
    """Accept only the validation delta produced by replacing one exit goto with return."""
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    control_flow_delta = delta.get("control_flow_effects")
    returns_delta = delta.get("returns")
    control_flow_added = (
        _boundary_tuple_8616(control_flow_delta.get("added", ()) or ())
        if isinstance(control_flow_delta, Mapping)
        else ()
    )
    control_flow_removed = (
        _boundary_tuple_8616(control_flow_delta.get("removed", ()) or ())
        if isinstance(control_flow_delta, Mapping)
        else ()
    )
    returns_added = (
        _boundary_tuple_8616(returns_delta.get("added", ()) or ()) if isinstance(returns_delta, Mapping) else ()
    )
    returns_removed = (
        _boundary_tuple_8616(returns_delta.get("removed", ()) or ()) if isinstance(returns_delta, Mapping) else ()
    )

    return (
        isinstance(control_flow_delta, Mapping)
        and isinstance(returns_delta, Mapping)
        and returns_added == ("none",)
        and returns_removed == ()
        and len(control_flow_added) == 1
        and len(control_flow_removed) == 1
        and control_flow_added == ("return",)
        and isinstance(control_flow_removed[0], str)
        and control_flow_removed[0].startswith("goto:")
    )


def segmented_stack_slot_size_precision_delta_8616(validation: Mapping[str, TailValidationValue]) -> bool:
    """Accept only segmented-write deltas that change proven stack-slot size spelling."""
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added", ()) or ())
            or _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
    }
    if touched_fields != {"segmented_writes"}:
        return False
    segmented_delta = delta.get("segmented_writes")
    if not isinstance(segmented_delta, Mapping):
        return False
    raw_added = _boundary_tuple_8616(segmented_delta.get("added", ()) or ())
    raw_removed = _boundary_tuple_8616(segmented_delta.get("removed", ()) or ())
    added = tuple(item for item in raw_added if isinstance(item, str))
    removed = tuple(item for item in raw_removed if isinstance(item, str))
    if not added or not removed:
        return False
    if len(added) != len(raw_added) or len(removed) != len(raw_removed):
        return False
    if not all(item.startswith("deref:") and "stack_slot:SS:BP" in item for item in added + removed):
        return False
    normalized_added = {_normalize_segmented_stack_slot_size_token_8616(item) for item in added}
    normalized_removed = {_normalize_segmented_stack_slot_size_token_8616(item) for item in removed}
    return normalized_added == normalized_removed


def name_only_helper_annotation_delta_8616(validation: Mapping[str, TailValidationValue]) -> bool:
    """Accept only helper-call removals that replace address helpers with equivalent names."""
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added", ()) or ())
            or _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
    }
    if touched_fields != {"helper_calls"}:
        return False
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, Mapping):
        return False
    added = _boundary_tuple_8616(helper_delta.get("added", ()) or ())
    removed = _boundary_tuple_8616(helper_delta.get("removed", ()) or ())
    return (
        not added
        and bool(removed)
        and all(isinstance(token, str) and token.startswith("name:addr:") for token in removed)
    )


def direct_stack_move_idiv_remainder_aux_delta_8616(validation: Mapping[str, TailValidationValue]) -> bool:
    """Accept only helper/register churn from signed-idiv remainder stack-move materialization."""
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added", ()) or ())
            or _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
    }
    if not touched_fields or touched_fields - {"helper_calls", "register_writes"}:
        return False
    helper_delta = delta.get("helper_calls")
    if isinstance(helper_delta, Mapping):
        helper_tokens = _boundary_tuple_8616(helper_delta.get("added", ()) or ()) + _boundary_tuple_8616(
            helper_delta.get("removed", ()) or ()
        )
        if not helper_tokens or any(not _helper_token_is_insert_artifact_8616(token) for token in helper_tokens):
            return False
    elif "helper_calls" in touched_fields:
        return False
    register_delta = delta.get("register_writes")
    if isinstance(register_delta, Mapping):
        reg_tokens = _boundary_tuple_8616(register_delta.get("added", ()) or ()) + _boundary_tuple_8616(
            register_delta.get("removed", ()) or ()
        )
        if not reg_tokens or any(token != "reg:ax" for token in reg_tokens):
            return False
    elif "register_writes" in touched_fields:
        return False
    return True


def direct_stack_move_function_pointer_prune_delta_8616(
    validation: Mapping[str, TailValidationValue],
    evidence_offsets: Collection[int],
    *,
    has_prune_evidence: bool,
) -> bool:
    """Accept direct-stack move deltas that only prune evidenced function-pointer stores."""
    if not has_prune_evidence:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = _validation_delta_touched_fields_from_mapping_8616(delta)
    if touched_fields != {"stack_writes"}:
        return False
    evidence_offset_set = set(evidence_offsets)
    if not evidence_offset_set:
        return False
    stack_delta = delta.get("stack_writes")
    if not isinstance(stack_delta, Mapping):
        return False
    if _boundary_tuple_8616(stack_delta.get("added") or ()):
        return False
    removed_stack = _boundary_tuple_8616(stack_delta.get("removed") or ())
    if not removed_stack:
        return False
    return _stack_write_delta_offsets_are_evidenced_8616(stack_delta, evidence_offset_set)


def validation_stack_offsets_in_token_8616(token: str) -> frozenset[int]:
    """Return BP-relative stack offsets mentioned in a validation token."""
    offsets: set[int] = set()
    for match in _STACK_OFFSET_TOKEN_RE_8616.finditer(token):
        value = int(match.group("value"), 16)
        offsets.add(-value if match.group("sign") == "-" else value)
    return frozenset(offsets)


def validation_stack_write_delta_offsets_are_evidenced_8616(
    validation: Mapping[str, TailValidationValue],
    evidence_offsets: Collection[int],
) -> bool:
    """Return whether a validation stack-write delta is covered by evidence offsets."""
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    stack_delta = delta.get("stack_writes")
    if not isinstance(stack_delta, Mapping):
        return True
    return _stack_write_delta_offsets_are_evidenced_8616(stack_delta, evidence_offsets)


def validation_without_delta_fields_8616(
    validation: Mapping[str, TailValidationValue],
    fields: Collection[str],
) -> dict[str, TailValidationValue]:
    """Return validation payload copy with selected delta fields removed."""
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return dict(validation)
    stripped = dict(validation)
    stripped["delta"] = {key: value for key, value in delta.items() if key not in set(fields)}
    return stripped


def validation_delta_removes_stack_or_control_effects_8616(validation: Mapping[str, TailValidationValue]) -> bool:
    """Return whether a validation delta removes stack writes or control effects."""
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    for field_name in ("stack_writes", "control_flow_effects"):
        field_delta = delta.get(field_name)
        if isinstance(field_delta, Mapping) and _boundary_tuple_8616(field_delta.get("removed") or ()):
            return True
    return False


def _stack_write_delta_offsets_are_evidenced_8616(
    stack_delta: Mapping[str, TailValidationValue],
    evidence_offsets: Collection[int],
) -> bool:
    """Return whether stack-write delta offsets are covered by evidence."""
    touched_offsets: set[int] = set()
    for token in _boundary_tuple_8616(stack_delta.get("added") or ()) + _boundary_tuple_8616(
        stack_delta.get("removed") or ()
    ):
        if not isinstance(token, str):
            return False
        touched_offsets.update(validation_stack_offsets_in_token_8616(token))
    return not touched_offsets or touched_offsets <= set(evidence_offsets)


def _helper_token_is_insert_artifact_8616(token: TailValidationValue) -> bool:
    """Return whether a helper-call token names the compiler insert artifact."""
    if not isinstance(token, str):
        return False
    return token in {"name:_INSERT", "name:__INSERT", "_INSERT", "__INSERT"} or token.endswith("._INSERT")


def callsite_stack_precision_control_delta_8616(control_delta: Mapping[str, TailValidationValue]) -> bool:
    """Accept only callsite control-flow deltas from stack-write precision token expansion."""
    added_control = _boundary_tuple_8616(control_delta.get("added", ()) or ())
    removed_control = _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    if len(added_control) != len(removed_control):
        return False
    for added_token, removed_token in zip(added_control, removed_control, strict=False):
        added_is_hash = isinstance(added_token, str) and added_token.startswith("control_flow_effects:sha256:")
        removed_is_hash = isinstance(removed_token, str) and removed_token.startswith("control_flow_effects:sha256:")
        if added_is_hash and removed_is_hash:
            continue
        if removed_is_hash and _is_stack_only_control_flow_write_precision_token_8616(added_token):
            continue
        return False
    return True


def callsite_resolved_indirect_helper_control_delta_8616(control_delta: Mapping[str, TailValidationValue]) -> bool:
    """Accept only callsite control-flow deltas that replace indirect helper names with resolved names."""
    added_control = _boundary_tuple_8616(control_delta.get("added", ()) or ())
    removed_control = _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    if not added_control or not removed_control:
        return False
    if any(isinstance(token, str) and token.startswith("control_flow_effects:sha256:") for token in added_control):
        return False
    removed_nonhash = tuple(
        token
        for token in removed_control
        if not (isinstance(token, str) and token.startswith("control_flow_effects:sha256:"))
    )
    if len(added_control) != len(removed_nonhash):
        return False

    def _normalize(token: TailValidationValue) -> str | None:
        if not isinstance(token, str):
            return None
        normalized = re.sub(r"name:addr:0x[0-9a-fA-F]+", "name:<resolved>", token)
        return normalized.replace("name:<indirect>", "name:<resolved>")

    added = Counter(normalized for normalized in (_normalize(token) for token in added_control) if normalized)
    removed = Counter(normalized for normalized in (_normalize(token) for token in removed_nonhash) if normalized)
    if not added or added != removed:
        return False
    return all(isinstance(token, str) and "name:addr:0x" in token for token in added_control) and all(
        isinstance(token, str) and "name:<indirect>" in token for token in removed_nonhash
    )


def _is_stack_only_control_flow_write_precision_token_8616(token: TailValidationValue) -> bool:
    """Return whether a control-flow token only expands stack-based SS writes."""
    if not isinstance(token, str):
        return False
    if not token.startswith(("while-body-writes:", "for-body-writes:", "do-while-body-writes:", "if-body-writes:")):
        return False
    if "global:" in token:
        return False
    for reg_match in re.finditer(r"reg:([a-z0-9]+)", token):
        if reg_match.group(1) not in {"sp", "ss"}:
            return False
    deref_count = token.count("deref:")
    return deref_count > 0 and deref_count == token.count("deref:Add(Mul(reg:ss,const:16)")


def callsite_helper_control_target_delta_8616(
    delta: Mapping[str, TailValidationValue], target_evidence: Collection[int]
) -> bool:
    """Accept callsite helper/control deltas that only correct resolved target addresses."""
    touched_fields = {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added") or ())
            or _boundary_tuple_8616(field_delta.get("removed") or ())
        )
    }
    if touched_fields != {"helper_calls", "control_flow_effects"}:
        return False

    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, Mapping):
        return False
    helper_added = _boundary_tuple_8616(helper_delta.get("added") or ())
    helper_removed = _boundary_tuple_8616(helper_delta.get("removed") or ())
    if not helper_added or len(helper_added) != len(helper_removed):
        return False
    added_targets = {_helper_call_addr_token_8616(token) for token in helper_added}
    if any(not isinstance(target, int) for target in added_targets):
        return False
    if any(_helper_call_addr_token_8616(token) is None for token in helper_removed):
        return False
    added_targets_int = {target for target in added_targets if isinstance(target, int)}
    target_set = set(target_evidence)
    if not target_set or not added_targets_int or not added_targets_int.issubset(target_set):
        return False

    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, Mapping):
        return False
    added_control = _boundary_tuple_8616(control_delta.get("added") or ())
    removed_control = _boundary_tuple_8616(control_delta.get("removed") or ())
    if not added_control or not removed_control:
        return False
    normalized_added = Counter(
        normalized
        for token in added_control
        for normalized in (_canonicalize_control_call_targets_for_compare_8616(token),)
        if normalized is not None
    )
    normalized_removed = Counter(
        normalized
        for token in removed_control
        for normalized in (_canonicalize_control_call_targets_for_compare_8616(token),)
        if normalized is not None
    )
    return normalized_added == normalized_removed


def callsite_consumed_stack_store_prune_delta_8616(pruned_count: int, delta: Mapping[str, TailValidationValue]) -> bool:
    """Accept only consumed call-argument stack-store prune validation deltas."""
    if pruned_count <= 0:
        return False
    touched_fields = _validation_delta_touched_fields_from_mapping_8616(delta)
    if touched_fields not in ({"stack_writes"}, {"stack_writes", "control_flow_effects"}):
        return False
    stack_delta = delta.get("stack_writes")
    if not isinstance(stack_delta, Mapping) or _boundary_tuple_8616(stack_delta.get("added") or ()):
        return False
    removed_stack = _boundary_tuple_8616(stack_delta.get("removed") or ())
    if not removed_stack or len(removed_stack) > pruned_count:
        return False
    if not all(_is_local_stack_slot_write_token_8616(token) for token in removed_stack):
        return False
    if "control_flow_effects" not in touched_fields:
        return True
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, Mapping) or _boundary_tuple_8616(control_delta.get("added") or ()):
        return False
    return _control_delta_removes_stack_body_write_8616(control_delta, set(removed_stack))


def callsite_far_pointer_remnant_prune_delta_8616(pruned_count: int, delta: Mapping[str, TailValidationValue]) -> bool:
    """Accept only far-pointer high-byte remnant prune validation deltas."""
    if pruned_count <= 0:
        return False
    touched_fields = _validation_delta_touched_fields_from_mapping_8616(delta)
    if not touched_fields or touched_fields - {"stack_writes", "control_flow_effects"}:
        return False
    stack_delta = delta.get("stack_writes")
    if isinstance(stack_delta, Mapping):
        added_stack = _boundary_tuple_8616(stack_delta.get("added") or ())
        removed_stack = _boundary_tuple_8616(stack_delta.get("removed") or ())
        if added_stack:
            return False
        if removed_stack and not all(_is_stack_slot_write_token_8616(token) for token in removed_stack):
            return False
    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, Mapping):
        added_control = _boundary_tuple_8616(control_delta.get("added") or ())
        removed_control = _boundary_tuple_8616(control_delta.get("removed") or ())
        normalized_added = Counter(
            normalized
            for normalized in (_strip_stack_slot_write_fragments_8616(token) for token in added_control)
            if isinstance(normalized, str)
        )
        normalized_removed = Counter(
            normalized
            for normalized in (_strip_stack_slot_write_fragments_8616(token) for token in removed_control)
            if isinstance(normalized, str)
        )
        if normalized_added != normalized_removed:
            return False
    return True


def callsite_resolved_indirect_helper_stack_delta_8616(delta: Mapping[str, TailValidationValue]) -> bool:
    """Accept deltas from replacing indirect helpers with resolved call targets."""
    touched_fields = _validation_delta_touched_fields_from_mapping_8616(delta)
    if not touched_fields or touched_fields - {
        "helper_calls",
        "stack_writes",
        "segmented_writes",
        "control_flow_effects",
    }:
        return False
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, Mapping):
        return False
    helper_added = _boundary_tuple_8616(helper_delta.get("added") or ())
    helper_removed = _boundary_tuple_8616(helper_delta.get("removed") or ())
    if not helper_added or len(helper_added) != len(helper_removed):
        return False
    if not all(isinstance(token, str) and token == "name:<indirect>" for token in helper_removed):
        return False
    if not all(_helper_call_addr_token_8616(token) is not None for token in helper_added):
        return False

    stack_delta = delta.get("stack_writes")
    if isinstance(stack_delta, Mapping):
        added_stack = _boundary_tuple_8616(stack_delta.get("added") or ())
        removed_stack = _boundary_tuple_8616(stack_delta.get("removed") or ())
        if removed_stack:
            return False
        if added_stack and not all(_is_local_stack_slot_write_token_8616(token) for token in added_stack):
            return False

    segmented_delta = delta.get("segmented_writes")
    if isinstance(segmented_delta, Mapping):
        added_segmented = _boundary_tuple_8616(segmented_delta.get("added") or ())
        removed_segmented = _boundary_tuple_8616(segmented_delta.get("removed") or ())
        if added_segmented:
            return False
        if removed_segmented and not all(
            _is_outgoing_ss_sp_segmented_write_token_8616(token) for token in removed_segmented
        ):
            return False

    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, Mapping):
        return callsite_stack_precision_control_delta_8616(
            control_delta
        ) or callsite_resolved_indirect_helper_control_delta_8616(control_delta)
    return True


def callsite_mixed_helper_stack_control_delta_8616(
    delta: Mapping[str, TailValidationValue],
    target_evidence: Collection[int],
    pruned_stack_tokens: Collection[str],
) -> bool:
    """Accept mixed helper/stack/control deltas backed by callsite evidence."""
    touched_fields = _validation_delta_touched_fields_from_mapping_8616(delta)
    if touched_fields != {"helper_calls", "stack_writes", "control_flow_effects"}:
        return False

    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, Mapping):
        return False
    helper_added = _boundary_tuple_8616(helper_delta.get("added") or ())
    helper_removed = _boundary_tuple_8616(helper_delta.get("removed") or ())
    if not helper_added or not helper_removed:
        return False
    if not all(_helper_call_addr_token_8616(token) is not None for token in helper_added):
        return False
    if not all(
        isinstance(token, str) and (token == "name:<indirect>" or _helper_call_addr_token_8616(token) is not None)
        for token in helper_removed
    ):
        return False
    added_targets = {_helper_call_addr_token_8616(token) for token in helper_added}
    if any(not isinstance(target, int) for target in added_targets):
        return False
    added_targets_int = {target for target in added_targets if isinstance(target, int)}
    target_set = set(target_evidence)
    has_indirect_removed = any(token == "name:<indirect>" for token in helper_removed)
    if not has_indirect_removed and (
        not target_set or not added_targets_int or not added_targets_int.issubset(target_set)
    ):
        return False

    stack_delta = delta.get("stack_writes")
    if not isinstance(stack_delta, Mapping):
        return False
    if _boundary_tuple_8616(stack_delta.get("added") or ()):
        return False
    removed_stack = _boundary_tuple_8616(stack_delta.get("removed") or ())
    if not removed_stack or not all(_is_local_stack_slot_write_token_8616(token) for token in removed_stack):
        return False
    pruned_stack_set = set(pruned_stack_tokens)
    if not pruned_stack_set or not set(removed_stack).issubset(pruned_stack_set):
        return False

    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, Mapping):
        return False
    if _control_delta_removes_stack_body_write_8616(control_delta, set(removed_stack)):
        return False
    added_control = _boundary_tuple_8616(control_delta.get("added") or ())
    removed_control = _boundary_tuple_8616(control_delta.get("removed") or ())
    if not added_control or not removed_control:
        return False
    allowed_prefixes = (
        "if-body-calls:",
        "if-else-body-calls:",
        "while-body-calls:",
        "dowhile-body-calls:",
        "do-while-body-calls:",
        "if-body-writes:",
        "while-body-writes:",
        "dowhile-body-writes:",
        "do-while-body-writes:",
    )
    if not all(isinstance(token, str) and token.startswith(allowed_prefixes) for token in added_control):
        return False
    if not all(isinstance(token, str) and token.startswith(allowed_prefixes) for token in removed_control):
        return False
    if not any("name:addr:" in token for token in added_control):
        return False
    return any("name:<indirect>" in token for token in removed_control) or (
        not has_indirect_removed and bool(target_set) and any("name:addr:" in token for token in removed_control)
    )


def callsite_stack_arg_slot_alias_condition_delta_8616(
    delta: Mapping[str, TailValidationValue], aliases: Mapping[tuple[str, int | None], str]
) -> bool:
    """Accept condition/control deltas that only rename stack args to slots."""
    touched_fields = _validation_delta_touched_fields_from_mapping_8616(delta)
    if not touched_fields or touched_fields - {"conditions", "control_flow_effects"}:
        return False
    if not aliases:
        return False
    for field_name in ("conditions", "control_flow_effects"):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, Mapping):
            continue
        added = _boundary_tuple_8616(field_delta.get("added") or ())
        removed = _boundary_tuple_8616(field_delta.get("removed") or ())
        normalized_added = Counter(
            token
            for token in (_canonicalize_stack_arg_alias_token_8616(value, aliases) for value in added)
            if isinstance(token, str)
        )
        normalized_removed = Counter(
            token
            for token in (_canonicalize_stack_arg_alias_token_8616(value, aliases) for value in removed)
            if isinstance(token, str)
        )
        if normalized_added != normalized_removed:
            return False
    return True


def _canonicalize_stack_arg_alias_token_8616(
    token: TailValidationValue, aliases: Mapping[tuple[str, int | None], str]
) -> str | None:
    """Replace stack-argument names with evidenced stack-slot fingerprints."""
    if not isinstance(token, str) or not aliases:
        return token if isinstance(token, str) else None

    def _replace(match: re.Match[str]) -> str:
        name = match.group("name")
        raw_size = match.group("size")
        size = int(raw_size) if isinstance(raw_size, str) and raw_size else None
        replacement = aliases.get((name, size)) or aliases.get((name, None))
        return replacement if isinstance(replacement, str) else match.group(0)

    return _STACK_ARG_ALIAS_TOKEN_RE_8616.sub(_replace, token)


def validation_delta_touched_fields_8616(delta: Mapping[str, TailValidationValue]) -> set[str]:
    """Return validation fields that contain added or removed token deltas."""
    return {
        field_name
        for field_name, field_delta in delta.items()
        if isinstance(field_delta, Mapping)
        and (
            _boundary_tuple_8616(field_delta.get("added") or ())
            or _boundary_tuple_8616(field_delta.get("removed") or ())
        )
    }


def _validation_delta_touched_fields_from_mapping_8616(delta: Mapping[str, TailValidationValue]) -> set[str]:
    """Compatibility helper for internal validation delta-field checks."""
    return validation_delta_touched_fields_8616(delta)


_STACK_SLOT_WRITE_TOKEN_RE_8616 = re.compile(r"stack_slot:SS:BP[+-]0x[0-9a-fA-F]+:size\d+")
_CONTROL_BODY_WRITE_PREFIXES_8616 = (
    "while-body-writes:",
    "do-while-body-writes:",
    "dowhile-body-writes:",
    "for-body-writes:",
)


def _is_local_stack_slot_write_token_8616(token: TailValidationValue) -> bool:
    """Return whether a token describes a local SS:BP stack-slot write."""
    return (
        isinstance(token, str)
        and token.startswith("stack_slot:SS:BP-")
        and _STACK_SLOT_WRITE_TOKEN_RE_8616.fullmatch(token) is not None
    )


def _is_stack_slot_write_token_8616(token: TailValidationValue) -> bool:
    """Return whether a token describes any SS:BP stack-slot write."""
    return isinstance(token, str) and _STACK_SLOT_WRITE_TOKEN_RE_8616.fullmatch(token) is not None


def _is_outgoing_ss_sp_segmented_write_token_8616(token: TailValidationValue) -> bool:
    """Return whether a token describes an outgoing SS:SP segmented write."""
    return (
        isinstance(token, str)
        and token.startswith("deref:Add(Mul(reg:ss,const:16),")
        and "reg:sp" in token
        and "global:" not in token
        and "reg:bp" not in token
    )


def _strip_stack_slot_write_fragments_8616(token: TailValidationValue) -> str | None:
    """Remove stack-slot write fragments from a control-flow token."""
    if not isinstance(token, str):
        return None
    stripped = _STACK_SLOT_WRITE_TOKEN_RE_8616.sub("", token)
    stripped = re.sub(r",+", ",", stripped).strip(",")
    return stripped


def _control_delta_removes_stack_body_write_8616(
    control_delta: Mapping[str, TailValidationValue], removed_stack_tokens: Collection[str]
) -> bool:
    """Return whether a control-flow delta removes a body-write for a stack token."""
    if not removed_stack_tokens:
        return False
    removed_control = _boundary_tuple_8616(control_delta.get("removed") or ())
    for token in removed_control:
        if not isinstance(token, str) or not token.startswith(_CONTROL_BODY_WRITE_PREFIXES_8616):
            continue
        if any(stack_token in token for stack_token in removed_stack_tokens):
            return True
    return False


_CALL_TARGET_TOKEN_RE_8616 = re.compile(r"\b(?:name:)?addr:0x[0-9a-fA-F]+\b")


def _canonicalize_control_call_targets_for_compare_8616(token: TailValidationValue) -> str | None:
    """Normalize resolved control-flow call target tokens for validation comparison."""
    if not isinstance(token, str) or not token:
        return None
    return _CALL_TARGET_TOKEN_RE_8616.sub("addr:*", token)


def _helper_call_addr_token_8616(token: TailValidationValue) -> int | None:
    """Return the resolved helper-call address encoded in a validation token."""
    if not isinstance(token, str):
        return None
    prefix = "name:addr:" if token.startswith("name:addr:") else "addr:" if token.startswith("addr:") else None
    if prefix is None:
        return None
    value = token[len(prefix) :]
    with contextlib.suppress(ValueError):
        return int(value, 0)
    return None


def _helper_call_fingerprint_targets_stack_probe_8616(project: TailValidationValue, fingerprint: str | None) -> bool:
    """Return whether a helper-call fingerprint resolves to a compiler stack probe."""
    addr = _helper_call_addr_token_8616(fingerprint)
    return _target_addr_is_stack_probe_helper_8616(project, addr)


def _normalize_segmented_stack_slot_size_token_8616(token: str) -> str:
    """Erase only stack-slot size suffixes when comparing segmented-write tokens."""
    return _SEGMENTED_STACK_SLOT_SIZE_TOKEN_RE_8616.sub(
        lambda match: f"stack_slot:SS:BP{match.group('offset')}:size*",
        token,
    )


def void_tail_call_guard_materialization_delta_8616(
    materialized_count: int,
    validation: Mapping[str, TailValidationValue],
) -> bool:
    """Accept only validation deltas introduced by proven void-tail-call guard materialization."""
    if materialized_count <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    for field in (
        "helper_calls",
        "register_writes",
        "stack_writes",
        "global_writes",
        "segmented_writes",
        "returns",
        "conditions",
    ):
        field_delta = delta.get(field)
        if not isinstance(field_delta, Mapping):
            continue
        if _boundary_tuple_8616(field_delta.get("added", ()) or ()) or _boundary_tuple_8616(
            field_delta.get("removed", ()) or ()
        ):
            return False
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, Mapping):
        return False
    added = _boundary_tuple_8616(control_delta.get("added", ()) or ())
    removed = _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    return bool(added) and not removed and all(str(item).startswith("if-body-calls:") for item in added)


_LOCAL_STACK_ABI_INT_WIDTH_TOKEN_RE_8616 = re.compile(
    r"stack_slot:SS:BP(?P<offset>-(?:0x[0-9a-fA-F]+|\d+)):size(?:2|4)"
)
_EMBEDDED_NAME_ADDR_HELPER_CALL_TOKEN_RE_8616 = re.compile(r"(?P<prefix>^|[:,])name:(?P<addr>addr:0x[0-9a-fA-F]+)")


@dataclass(frozen=True, slots=True)
class X86_16TailValidationSummary:
    """Immutable observable effects collected for one tail-validation stage."""

    helper_calls: tuple[str, ...]
    register_writes: tuple[str, ...]
    stack_writes: tuple[str, ...]
    global_writes: tuple[str, ...]
    segmented_writes: tuple[str, ...]
    returns: tuple[str, ...]
    conditions: tuple[str, ...]
    control_flow_effects: tuple[str, ...]
    def_use_issues: tuple[str, ...] = ()
    missing_required_calls: tuple[str, ...] = ()
    control_flow_issues: tuple[str, ...] = ()
    call_interface_issues: tuple[str, ...] = ()
    call_argument_class_issues: tuple[str, ...] = ()
    function_parameter_issues: tuple[str, ...] = ()
    function_return_class_issues: tuple[str, ...] = ()
    storage_identity_issues: tuple[str, ...] = ()
    callsite_multiplicity_issues: tuple[str, ...] = ()
    exposed_stack_values: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, tuple[str, ...]]:
        """Return a serializable mapping of summary fields to fingerprints."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class X86_16FinalSemanticValidationReport8616:
    """Final-AST semantic guards evaluated after every output mutation."""

    def_use: DefUseValidationReport8616
    required_calls: RequiredCallsiteValidationReport8616
    callsite_multiplicity: CallsiteMultiplicityValidationReport8616
    call_interfaces: CallInterfaceValidationReport8616
    call_argument_classes: CallArgumentClassValidationReport8616
    function_parameters: FunctionParameterValidationReport8616
    function_return_class: FunctionReturnClassValidationReport8616
    control_flow: ControlFlowValidationReport8616
    storage_identities: StorageIdentityValidationReport8616
    required_memory_effects: RequiredMemoryEffectValidationReport8616
    pointer_parameter_outputs: PointerParameterOutputValidationReport8616
    software_interrupt_inputs: SoftwareInterruptValidationReport8616

    @property
    def passed(self) -> bool:
        """Return whether all absolute final semantic guards passed."""
        return bool(
            self.def_use.passed
            and self.required_calls.passed
            and self.callsite_multiplicity.passed
            and self.call_interfaces.passed
            and self.call_argument_classes.passed
            and self.function_parameters.passed
            and self.function_return_class.passed
            and self.control_flow.passed
            and self.storage_identities.passed
            and self.required_memory_effects.passed
            and self.pointer_parameter_outputs.passed
            and self.software_interrupt_inputs.passed
        )

    def semantic_failures(self) -> dict[str, tuple[str, ...]]:
        """Return typed failure families for the canonical tail snapshot."""
        failures: dict[str, tuple[str, ...]] = {}
        if self.def_use.issues:
            failures["def_use"] = self.def_use.issue_tokens()
        if self.required_calls.missing_calls:
            failures["required_calls"] = self.required_calls.missing_calls
        if self.callsite_multiplicity.issues:
            failures["callsite_multiplicity"] = self.callsite_multiplicity.issue_tokens()
        if self.call_interfaces.issues:
            failures["call_interfaces"] = self.call_interfaces.issue_tokens()
        if self.call_argument_classes.issues:
            failures["call_argument_classes"] = self.call_argument_classes.issue_tokens()
        if self.function_parameters.issues:
            failures["function_parameters"] = self.function_parameters.issue_tokens()
        if self.function_return_class.issues:
            failures["function_return_class"] = self.function_return_class.issue_tokens()
        if self.control_flow.issues:
            failures["control_flow"] = self.control_flow.issue_tokens()
        if self.storage_identities.issues:
            failures["storage_identities"] = self.storage_identities.issue_tokens()
        if self.required_memory_effects.issues:
            failures["required_memory_effects"] = self.required_memory_effects.issue_tokens()
        if self.pointer_parameter_outputs.issues:
            failures["pointer_parameter_outputs"] = (
                self.pointer_parameter_outputs.issue_tokens()
            )
        if self.software_interrupt_inputs.issues:
            failures["software_interrupt_inputs"] = self.software_interrupt_inputs.issue_tokens()
        return failures

    def evidence_counts(self) -> dict[str, dict[str, int]]:
        """Return closed-loop evidence counters for each final guard."""
        return {
            "def_use": {
                "raw_fact_count": self.def_use.raw_fact_count,
                "normalized_fact_count": self.def_use.normalized_fact_count,
                "classified_fact_count": self.def_use.classified_fact_count,
                "materialized_count": self.def_use.materialized_count,
                "failure_count": self.def_use.failure_count,
            },
            "required_calls": {
                "raw_fact_count": self.required_calls.raw_fact_count,
                "normalized_fact_count": self.required_calls.normalized_fact_count,
                "classified_fact_count": self.required_calls.classified_fact_count,
                "materialized_count": self.required_calls.materialized_count,
                "failure_count": self.required_calls.failure_count,
            },
            "callsite_multiplicity": {
                "raw_fact_count": self.callsite_multiplicity.raw_fact_count,
                "normalized_fact_count": self.callsite_multiplicity.normalized_fact_count,
                "classified_fact_count": self.callsite_multiplicity.classified_fact_count,
                "materialized_count": self.callsite_multiplicity.materialized_count,
                "failure_count": self.callsite_multiplicity.failure_count,
            },
            "call_interfaces": {
                "raw_fact_count": self.call_interfaces.raw_fact_count,
                "normalized_fact_count": self.call_interfaces.normalized_fact_count,
                "classified_fact_count": self.call_interfaces.classified_fact_count,
                "materialized_count": self.call_interfaces.materialized_count,
                "failure_count": self.call_interfaces.failure_count,
            },
            "call_argument_classes": {
                "raw_fact_count": self.call_argument_classes.raw_fact_count,
                "normalized_fact_count": self.call_argument_classes.normalized_fact_count,
                "classified_fact_count": self.call_argument_classes.classified_fact_count,
                "materialized_count": self.call_argument_classes.materialized_count,
                "failure_count": self.call_argument_classes.failure_count,
            },
            "function_parameters": {
                "raw_fact_count": self.function_parameters.raw_fact_count,
                "normalized_fact_count": self.function_parameters.normalized_fact_count,
                "classified_fact_count": self.function_parameters.classified_fact_count,
                "materialized_count": self.function_parameters.materialized_count,
                "failure_count": self.function_parameters.failure_count,
            },
            "function_return_class": {
                "raw_fact_count": self.function_return_class.raw_fact_count,
                "normalized_fact_count": self.function_return_class.normalized_fact_count,
                "classified_fact_count": self.function_return_class.classified_fact_count,
                "materialized_count": self.function_return_class.materialized_count,
                "failure_count": self.function_return_class.failure_count,
            },
            "control_flow": {
                "raw_fact_count": self.control_flow.raw_fact_count,
                "normalized_fact_count": self.control_flow.normalized_fact_count,
                "classified_fact_count": self.control_flow.classified_fact_count,
                "materialized_count": self.control_flow.materialized_count,
                "failure_count": self.control_flow.failure_count,
            },
            "storage_identities": {
                "raw_fact_count": self.storage_identities.raw_fact_count,
                "normalized_fact_count": self.storage_identities.normalized_fact_count,
                "classified_fact_count": self.storage_identities.classified_fact_count,
                "materialized_count": self.storage_identities.materialized_count,
                "failure_count": self.storage_identities.failure_count,
            },
            "required_memory_effects": {
                "raw_fact_count": self.required_memory_effects.raw_fact_count,
                "normalized_fact_count": self.required_memory_effects.normalized_fact_count,
                "classified_fact_count": self.required_memory_effects.classified_fact_count,
                "materialized_count": self.required_memory_effects.materialized_count,
                "failure_count": self.required_memory_effects.failure_count,
            },
            "pointer_parameter_outputs": {
                "raw_fact_count": self.pointer_parameter_outputs.raw_fact_count,
                "normalized_fact_count": self.pointer_parameter_outputs.normalized_fact_count,
                "classified_fact_count": self.pointer_parameter_outputs.classified_fact_count,
                "materialized_count": self.pointer_parameter_outputs.materialized_count,
                "failure_count": self.pointer_parameter_outputs.failure_count,
            },
            "software_interrupt_inputs": {
                "raw_fact_count": self.software_interrupt_inputs.raw_fact_count,
                "normalized_fact_count": self.software_interrupt_inputs.normalized_fact_count,
                "classified_fact_count": self.software_interrupt_inputs.classified_fact_count,
                "materialized_count": self.software_interrupt_inputs.materialized_count,
                "failure_count": self.software_interrupt_inputs.failure_count,
            },
        }


@dataclass(frozen=True, slots=True)
class X86_16ValidationCacheDescriptor:
    """Stable identity for a validation cache namespace and payload."""

    namespace: str
    fingerprint: str
    cache_key: str


@dataclass(frozen=True, slots=True)
class _TailValidationBoundaryContext8616:
    """One-shot facts shared from boundary fingerprinting into summary collection."""

    mode: str
    root_id: int
    boundary_fingerprint: str
    summary_input_generation: TailValidationSummaryInputGeneration8616
    contextual_call_fingerprints: dict[int, str]
    contextual_call_summaries: dict[int, TailValidationValue]
    contextual_condition_fingerprints: dict[int, str]


def build_x86_16_validation_cache_descriptor(
    namespace: str, payload: TailValidationValue
) -> X86_16ValidationCacheDescriptor:
    """Build a deterministic cache descriptor for validation payload data."""
    fingerprint = _json_fingerprint({"namespace": namespace, "payload": payload})
    return X86_16ValidationCacheDescriptor(
        namespace=namespace,
        fingerprint=fingerprint,
        cache_key=f"{namespace}:{fingerprint}",
    )


def resolve_x86_16_validation_cached_artifact[T](
    *,
    cache: MutableMapping[str, TailValidationValue] | None,
    descriptor: X86_16ValidationCacheDescriptor,
    build: Callable[[], T],
    clone_on_hit: Callable[[T], T] | None = None,
    store_value: Callable[[T], TailValidationValue] | None = None,
) -> dict[str, TailValidationValue]:
    """Return a cached validation artifact or build and persist a fresh value."""
    if cache is not None:
        cached = cache.get(descriptor.cache_key)
        if cached is not None:
            value = clone_on_hit(cached) if clone_on_hit is not None else cached
            return {
                "cache_key": descriptor.cache_key,
                "cache_hit": True,
                "fingerprint": descriptor.fingerprint,
                "value": value,
            }

    value = build()
    if cache is not None:
        cache[descriptor.cache_key] = store_value(value) if store_value is not None else value
    return {
        "cache_key": descriptor.cache_key,
        "cache_hit": False,
        "fingerprint": descriptor.fingerprint,
        "value": value,
    }


def _codegen_root(codegen: TailValidationValue) -> TailValidationValue | None:
    """Return the canonical lowered C AST before legacy angr root aliases."""
    cfunc = getattr(codegen, "cfunc", None)
    # Structuring and Lowering replace ``statements`` while angr may retain the
    # pre-lowering tree in ``body``. Validation must observe the tree that will
    # be rendered and consumed by subsequent pipeline stages.
    for attr in ("statements", "body", "stmt"):
        value = getattr(cfunc, attr, None)
        if value is not None:
            return value
    return cfunc


def _sorted_unique(values: set[str]) -> tuple[str, ...]:
    return tuple(sorted(values))


def _compact_tail_validation_observable_8616(field_name: str, value: str) -> str:
    """Bound validation diagnostics for huge exact fingerprints.

    Large raw flag expressions can be thousands of characters long. Validation
    only needs stable equality/inequality for those exact forms, so use a digest
    token for oversized condition/control-flow fingerprints. This is
    conservative: equal long expressions stay equal; changed long expressions
    still differ; no semantic rewrite is inferred from the digest.
    """
    if field_name not in _COMPACT_OBSERVABLE_FIELDS_8616 or not isinstance(value, str):
        return value
    if field_name == "control_flow_effects":
        compact_selector = compact_selector_return_fingerprint_8616(
            value,
            canonicalize_condition=_canonicalize_condition_fingerprint_for_compare_8616,
            compact_observable=compact_normalized_validation_observable_8616,
        )
        if compact_selector is not None:
            return compact_selector
        value = _canonical_control_flow_effect_for_compare_8616(value)
    else:
        value = _canonicalize_condition_fingerprint_for_compare_8616(value)
    compacted = compact_normalized_validation_observable_8616(field_name, value)
    if compacted == value:
        return value
    if field_name == "control_flow_effects":
        for prefix in ("if:", "ifbreak:", "while:", "dowhile:", "for:"):
            if not value.startswith(prefix):
                continue
            condition = value[len(prefix) :]
            compact_condition = compact_normalized_validation_observable_8616(
                "conditions",
                condition,
            )
            if compact_condition != condition:
                return f"{prefix}{compact_condition}"
        write_split = _split_control_flow_loop_body_write_effect_8616(value)
        if write_split is not None:
            prefix, locations = write_split
            prefix_digest = hashlib.sha256(prefix.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]
            return (
                f"{field_name}:sha256:{prefix_digest}:len:{len(prefix)}:"
                f"loop-body-writes:{','.join(locations)}"
            )
    return compacted


def _compact_tail_validation_observables_8616(field_name: str, values: set[str]) -> set[str]:
    if field_name not in _COMPACT_OBSERVABLE_FIELDS_8616:
        return values
    return {_compact_tail_validation_observable_8616(field_name, value) for value in values}


def _json_fingerprint(payload: TailValidationValue) -> str:
    def _json_default(value: TailValidationValue) -> str:
        # Validation cache fingerprinting must never crash on rich AST objects.
        # Keep fallback deterministic and side-effect free.
        return f"<{type(value).__name__}>"

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=_json_default)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _clear_tail_validation_expr_fingerprint_cache_8616(project: TailValidationValue) -> None:
    """Clear fingerprint values and their retained AST identity guards."""
    with contextlib.suppress(Exception):
        project._inertia_tail_validation_expr_fingerprint_cache_8616 = {}
        project._inertia_tail_validation_expr_fingerprint_cache_nodes_8616 = {}


def canonicalize_tail_validation_summary_field_values_8616(
    field_name: str,
    values: set[str],
) -> set[str]:
    """Canonicalize condition/control-flow fingerprint strings for comparison.

    Delegates condition semantics to the IR-layer owners:
    1. ``normalize_condition_fingerprint_string_8616`` inverts ``Not(CmpEQ(...))`` → ``CmpNE(...)``
    2. ``normalize_condition_fingerprint_algebraic_8616`` canonicalizes
       ``CmpEQ(Sub(x,const:c),const:0)`` → ``CmpEQ(x,const:c)``
    3. ``canonicalize_condition_storage_fingerprint_8616`` supplies canonical
       typed storage identities such as ``ds_global`` and ``stack_slot``.

    These are validation-only; they do not mutate IR or feed results back into recovery.
    """
    if field_name == "helper_calls":
        return {
            _canonicalize_stack_arg_storage_fingerprint_8616(
                _canonicalize_helper_call_fingerprint_for_compare_8616(value)
            )
            for value in values
        }
    if field_name == "segmented_writes":
        return {
            _canonicalize_stack_arg_storage_fingerprint_8616(
                _canonicalize_segmented_write_fingerprint_for_compare_8616(value)
            )
            for value in values
        }
    if field_name == "control_flow_effects":
        return {_canonical_control_flow_effect_for_compare_8616(str(value)) for value in values}
    if field_name == "returns":
        return {
            _canonicalize_stack_arg_storage_fingerprint_8616(
                normalize_condition_fingerprint_algebraic_8616(value)
            )
            for value in values
        }
    if field_name != "conditions":
        return {_canonicalize_stack_arg_storage_fingerprint_8616(value) for value in values}
    normalized: set[str] = set()
    for value in values:
        value = _compact_tail_validation_observable_8616(field_name, value)
        if value.startswith(f"{field_name}:sha256:"):
            normalized.add(value)
            continue
        normalized.add(_canonicalize_condition_fingerprint_for_compare_8616(value))
    return normalized


def _canonicalize_stack_arg_storage_fingerprint_8616(value: str) -> str:
    def _replace_legacy_stack(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}stack_slot:SS:BP{match.group('offset')}:size2"

    value = canonicalize_condition_storage_fingerprint_8616(value)
    return _LEGACY_STACK_LOCATION_TOKEN_RE_8616.sub(_replace_legacy_stack, value)


def _canonicalize_embedded_helper_call_tokens_for_compare_8616(value: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{match.group('addr').lower()}"

    return _EMBEDDED_NAME_ADDR_HELPER_CALL_TOKEN_RE_8616.sub(_replace, value)


def _canonicalize_global_word_pair_condition_fingerprint_8616(value: str) -> str:
    """Fold adjacent byte views after Condition IR has canonicalized DS storage."""

    def _ds_global_offset(fingerprint: str) -> int | None:
        match = re.fullmatch(r"ds_global:(0x[0-9a-fA-F]+|\d+)", fingerprint)
        if match is None:
            return None
        return int(match.group(1), 0)

    def _const_value(fingerprint: str) -> int | None:
        match = re.fullmatch(r"const:(0x[0-9a-fA-F]+|\d+)", fingerprint)
        if match is None:
            return None
        return int(match.group(1), 0)

    def _scaled_ds_global_byte_offset(fingerprint: str) -> int | None:
        call = _split_fingerprint_call_8616(fingerprint)
        if call is None:
            return None
        op, args_str = call
        args = _split_fingerprint_args_8616(args_str)
        if len(args) != 2:
            return None
        if op == "Shl" and _const_value(args[1]) == 8:
            return _ds_global_offset(args[0])
        if op == "Mul":
            if _const_value(args[0]) == 0x100:
                return _ds_global_offset(args[1])
            if _const_value(args[1]) == 0x100:
                return _ds_global_offset(args[0])
        return None

    def _flatten_or_args(fingerprint: str) -> list[str]:
        call = _split_fingerprint_call_8616(fingerprint)
        if call is None:
            return [fingerprint]
        op, args_str = call
        args = _split_fingerprint_args_8616(args_str)
        if op != "Or":
            return [fingerprint]
        flattened: list[str] = []
        for arg in args:
            flattened.extend(_flatten_or_args(arg))
        return flattened

    def _adjacent_word_pair_base(fingerprint: str) -> str | None:
        parts = _flatten_or_args(fingerprint)
        if len(parts) != 2:
            return None
        offsets = sorted(
            offset
            for part in parts
            if isinstance((offset := _ds_global_offset(part)), int)
        )
        if len(offsets) == 2 and offsets[1] == offsets[0] + 2:
            return f"ds_global:{offsets[0]:#x}"
        return None

    def _normalize_expr(fingerprint: str) -> str:
        call = _split_fingerprint_call_8616(fingerprint)
        if call is None:
            return fingerprint
        op, args_str = call
        args = _split_fingerprint_args_8616(args_str)
        normalized_args = [_normalize_expr(arg) for arg in args]
        if op == "And" and len(normalized_args) == 2:
            left_const = _const_value(normalized_args[0])
            right_const = _const_value(normalized_args[1])
            left_offset = _ds_global_offset(normalized_args[0])
            right_offset = _ds_global_offset(normalized_args[1])
            if isinstance(left_offset, int) and right_const == 0xFFFF:
                return f"ds_global:{left_offset:#x}"
            if isinstance(right_offset, int) and left_const == 0xFFFF:
                return f"ds_global:{right_offset:#x}"
        if op in {"CmpEQ", "CmpNE"} and len(normalized_args) == 2:
            for candidate, zero in (
                (normalized_args[0], normalized_args[1]),
                (normalized_args[1], normalized_args[0]),
            ):
                pair_base = _adjacent_word_pair_base(candidate)
                if pair_base is not None and _const_value(zero) == 0:
                    return f"{op}({pair_base},const:0)"
        if op == "Or":
            deduped_args = tuple(dict.fromkeys(arg for item in normalized_args for arg in _flatten_or_args(item)))
            if len(deduped_args) == 1:
                return deduped_args[0]
            if deduped_args != tuple(normalized_args):
                return f"Or({','.join(deduped_args)})"
        if op == "Shr" and len(normalized_args) == 2:
            base_offset = _ds_global_offset(normalized_args[0])
            if isinstance(base_offset, int) and _const_value(normalized_args[1]) == 16:
                return f"ds_global:{base_offset + 2:#x}"
        if op == "Or" and len(normalized_args) == 2:
            low_offset = _ds_global_offset(normalized_args[0])
            high_offset = _scaled_ds_global_byte_offset(normalized_args[1])
            if not isinstance(low_offset, int) or not isinstance(high_offset, int):
                low_offset = _ds_global_offset(normalized_args[1])
                high_offset = _scaled_ds_global_byte_offset(normalized_args[0])
            if isinstance(low_offset, int) and high_offset == low_offset + 1:
                return f"ds_global:{low_offset:#x}"
        return f"{op}({','.join(normalized_args)})"

    return _normalize_expr(value)


def _canonicalize_condition_fingerprint_for_compare_8616(value: str) -> str:
    """Normalize one condition through the Condition IR storage owner."""
    normalized = normalize_condition_fingerprint_string_8616(value)
    normalized = normalize_condition_fingerprint_algebraic_8616(normalized)
    normalized = canonicalize_condition_storage_fingerprint_8616(normalized)
    normalized = _canonicalize_global_word_pair_condition_fingerprint_8616(normalized)
    return _canonicalize_stack_arg_storage_fingerprint_8616(normalized)


def _canonicalize_final_branch_condition_fingerprint_8616(value: str) -> str:
    """Normalize exact storage-view equivalences for final branch validation."""
    return _canonicalize_condition_fingerprint_for_compare_8616(value)


def _canonicalize_helper_call_fingerprint_for_compare_8616(value: str) -> str:
    if not isinstance(value, str):
        return value
    match = re.fullmatch(r"name:(addr:0x[0-9a-fA-F]+)", value)
    if match is None:
        return value
    return match.group(1).lower()


def _const_fingerprint_value_8616(value: str) -> int | None:
    if not isinstance(value, str) or not value.startswith("const:"):
        return None
    try:
        return int(value[len("const:") :], 0)
    except ValueError:
        return None


def _canonicalize_additive_fingerprint_for_compare_8616(value: str) -> str:
    def _canonicalize_expr(expr: str) -> str:
        call = _split_fingerprint_call_8616(expr)
        if call is None:
            return expr
        op, args_text = call
        args = _split_fingerprint_args_8616(args_text)
        if op == "Shl" and len(args) == 2:
            shift = _const_fingerprint_value_8616(args[1])
            if isinstance(shift, int) and 0 <= shift <= 31:
                return f"Mul({_canonicalize_expr(args[0])},const:{1 << shift})"
        if op == "Reference" and len(args) == 1 and args[0].startswith("stack_slot:"):
            return _canonicalize_expr(args[0])
        if op in {"Add", "Sub"}:
            terms: list[tuple[int, str]] = []

            def _flatten(term: str, sign: int) -> None:
                inner = _split_fingerprint_call_8616(term)
                if inner is None:
                    terms.append((sign, term))
                    return
                inner_op, inner_args_text = inner
                inner_args = _split_fingerprint_args_8616(inner_args_text)
                if inner_op == "Add":
                    for inner_arg in inner_args:
                        _flatten(inner_arg, sign)
                    return
                if inner_op == "Sub" and len(inner_args) == 2:
                    _flatten(inner_args[0], sign)
                    _flatten(inner_args[1], -sign)
                    return
                terms.append((sign, _canonicalize_expr(term)))

            for idx, arg in enumerate(args):
                _flatten(arg, -1 if op == "Sub" and idx > 0 else 1)

            const_total = 0
            parts: list[str] = []
            for sign, term in terms:
                const_value = _const_fingerprint_value_8616(term)
                if isinstance(const_value, int):
                    const_total += sign * const_value
                    continue
                parts.append(term if sign > 0 else f"Neg({term})")
            if const_total or not parts:
                parts.append(f"const:{const_total}")
            return f"Add({','.join(parts)})"
        return f"{op}({','.join(_canonicalize_expr(arg) for arg in args)})"

    return _canonicalize_expr(value)


def _canonicalize_linear_ds_deref_condition_fingerprint_8616(value: str) -> str:
    """Compatibility wrapper for the Condition IR storage owner."""
    return canonicalize_condition_storage_fingerprint_8616(value)


def _canonicalize_segmented_write_fingerprint_for_compare_8616(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("deref:"):
        return value
    return "deref:" + _canonicalize_additive_fingerprint_for_compare_8616(value[len("deref:") :])


def _canonicalize_summary_field_counter_8616(field_name: str, values: Sequence[str]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for value in values:
        if field_name == "helper_calls":
            value = _canonicalize_helper_call_fingerprint_for_compare_8616(value)
        elif field_name == "segmented_writes":
            value = _canonicalize_segmented_write_fingerprint_for_compare_8616(value)
        elif field_name == "returns":
            value = normalize_condition_fingerprint_algebraic_8616(value)
        value = _canonicalize_stack_arg_storage_fingerprint_8616(str(value))
        counter[str(value)] += 1
    return counter


def _counter_delta_items_8616(left: Counter[str], right: Counter[str]) -> tuple[str, ...]:
    items: list[str] = []
    for value in sorted(left):
        count = int(left[value] or 0) - int(right.get(value, 0) or 0)
        if count > 0:
            items.extend([value] * count)
    return tuple(items)


def _missing_callsite_fingerprints_8616(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        str(value)
        for value in values
        if isinstance(value, str) and value.startswith(_MISSING_CALLSITE_FINGERPRINT_PREFIX_8616)
    )


def _summary_is_stack_probe_helper_8616(
    summary: Mapping[str, TailValidationValue] | CallsiteSummary8616 | None,
) -> bool:
    """Return whether a callsite summary represents a compiler stack probe."""
    return bool(_summary_attr_8616(summary, "stack_probe_helper"))


def _is_stack_probe_helper_name_8616(name: str | None) -> bool:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return normalized.lower().lstrip("_") in {"anchkstk", "analloca_probe"}


def _project_function_name_for_addr_8616(project: TailValidationValue, addr: int) -> str | None:
    # Dynamic angr/codegen compatibility boundary.
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        if candidate_project is None:
            continue
        # Dynamic angr/codegen compatibility boundary.
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        # Dynamic angr/codegen compatibility boundary.
        lookup = getattr(functions, "function", None)
        if callable(lookup):
            with contextlib.suppress(Exception):
                function = lookup(addr=addr, create=False)
                # Dynamic angr/codegen compatibility boundary.
                name = getattr(function, "name", None)
                if isinstance(name, str) and name:
                    return name
        # Dynamic angr/codegen compatibility boundary.
        label = getattr(getattr(candidate_project, "kb", None), "labels", {}).get(addr)
        if isinstance(label, str) and label:
            return label
        # Dynamic angr/codegen compatibility boundary.
        metadata = getattr(candidate_project, "_inertia_lst_metadata", None)
        # Dynamic angr/codegen compatibility boundary.
        code_labels = getattr(metadata, "code_labels", None)
        if isinstance(code_labels, Mapping):
            label = code_labels.get(addr)
            if isinstance(label, str) and label:
                return label
    return None


def _target_addr_is_stack_probe_helper_8616(project: TailValidationValue, target_addr: int | None) -> bool:
    if not isinstance(target_addr, int):
        return False
    normalized = _normalized_call_target_addr_8616(project, target_addr)
    candidates = [target_addr]
    if isinstance(normalized, int) and normalized != target_addr:
        candidates.append(normalized)
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    if isinstance(linked_base, int):
        rebased_low = linked_base + (int(target_addr) & 0xFFFF)
        if rebased_low not in candidates:
            candidates.append(rebased_low)
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        if candidate_project is None:
            continue
        for addr in candidates:
            if is_x86_16_stack_probe_helper_at_8616(candidate_project, addr):
                return True
    return any(
        _is_stack_probe_helper_name_8616(_project_function_name_for_addr_8616(project, addr)) for addr in candidates
    )


def _call_node_is_stack_probe_helper_8616(
    project: TailValidationValue, node: TailValidationValue, summary: TailValidationValue
) -> bool:
    if _summary_is_stack_probe_helper_8616(summary):
        return True
    target_addr = _call_summary_target_addr_8616(project, summary)
    if _target_addr_is_stack_probe_helper_8616(project, target_addr):
        return True
    call_name = _call_target_name(node, project)
    if _is_stack_probe_helper_name_8616(call_name):
        return True
    if isinstance(call_name, str) and call_name.startswith("addr:"):
        with contextlib.suppress(ValueError):
            return _target_addr_is_stack_probe_helper_8616(project, int(call_name[5:], 0))
    return False


def _callsite_expected_fingerprint_8616(
    function: TailValidationValue,
    project: TailValidationValue,
    callsite_addr: int,
    summary_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> str | None:
    summary = (
        summary_inventory.get(callsite_addr)
        if summary_inventory is not None
        else summarize_x86_16_callsite(function, callsite_addr)
    )
    if _summary_is_stack_probe_helper_8616(summary):
        return None
    target_addr = _call_summary_target_addr_8616(project, summary)
    if _target_addr_is_stack_probe_helper_8616(project, target_addr):
        return None
    if isinstance(target_addr, int):
        return f"addr:{target_addr:#x}"
    return f"callsite:{callsite_addr:#x}"


def _function_callsite_addrs_for_validation_8616(function: TailValidationValue) -> tuple[int, ...]:
    """Return callsite addresses from dynamic angr function metadata."""
    # Dynamic boundary: angr Function may expose get_call_sites as a method.
    callsite_addrs = _boundary_tuple_8616(sorted(getattr(function, "get_call_sites", list)() or ()))
    if callsite_addrs:
        return callsite_addrs
    return tuple(
        addr
        for addr in _collect_direct_capstone_callsite_addrs_8616(function)
        if isinstance(addr, int)
    )


def _append_missing_contextual_callsite_fingerprints_8616(
    root: TailValidationValue,
    project: TailValidationValue,
    helper_calls: list[str],
    summary_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> None:
    """Append missing contextual callsite fingerprints to helper-call tokens."""
    function = _function_for_call_context_8616(root, project)
    if function is None:
        return
    expected: list[str] = []
    for callsite_addr in _function_callsite_addrs_for_validation_8616(function):
        fingerprint = _callsite_expected_fingerprint_8616(
            function,
            project,
            callsite_addr,
            summary_inventory,
        )
        if fingerprint is not None:
            expected.append(_normalize_helper_call_fingerprint_8616(project, fingerprint) or fingerprint)
    if not expected:
        return
    observed: Counter[str] = Counter()
    for fingerprint in helper_calls:
        normalized_fingerprint = _normalize_helper_call_fingerprint_8616(project, fingerprint) or fingerprint
        observed[_canonicalize_helper_call_fingerprint_for_compare_8616(normalized_fingerprint)] += 1
    for fingerprint in expected:
        normalized = _canonicalize_helper_call_fingerprint_for_compare_8616(fingerprint)
        if observed.get(normalized, 0) > 0:
            observed[normalized] -= 1
            continue
        helper_calls.append(f"{_MISSING_CALLSITE_FINGERPRINT_PREFIX_8616}{fingerprint}")


def _invert_condition_fingerprint_8616(
    node: TailValidationValue, project: TailValidationValue, contextual_condition_fingerprints: Mapping[int, str]
) -> str | None:
    contextual = contextual_condition_fingerprints.get(id(node))
    if contextual is not None:
        inverted_contextual = invert_condition_fingerprint_string_8616(contextual)
        if inverted_contextual is not None:
            return str(inverted_contextual)
    if isinstance(node, CBinaryOp):
        inverted_op = _INVERTED_COMPARISON_OPS_8616.get(node.op)
        if inverted_op is not None:
            lhs = _expr_fingerprint(node.lhs, project)
            rhs = _expr_fingerprint(node.rhs, project)
            return f"{inverted_op}({lhs},{rhs})"
    if isinstance(node, CUnaryOp) and node.op == "Not":
            return str(contextual_condition_fingerprints.get(id(node.operand), _expr_fingerprint(node.operand, project)))
    fingerprint = contextual or _expr_fingerprint(node, project)
    return str(_wrap_not_fingerprint(fingerprint))


def _extract_loop_break_guard_normalization_8616(
    loop: TailValidationValue, project: TailValidationValue, contextual_condition_fingerprints: Mapping[int, str]
) -> tuple[str, set[int]] | None:
    def _impl() -> tuple[str, set[int]] | None:
        condition = getattr(loop, "condition", None)
        if _c_constant_int_value(condition) != 1:
            return None

        body = getattr(loop, "body", None)
        statements = _boundary_tuple_8616(getattr(body, "statements", ()) or ())
        if not statements:
            return None

        guard_index = 0
        while guard_index < len(statements) and isinstance(statements[guard_index], CAssignment):
            guard_index += 1
        if guard_index >= len(statements):
            return None

        guard_stmt = statements[guard_index]
        break_cond = None
        suppressed_node_ids = {id(guard_stmt)}

        def _is_void_loop_exit_stmt_8616(stmt: TailValidationValue) -> bool:
            if isinstance(stmt, CBreak):
                return True
            return bool(isinstance(stmt, CReturn) and getattr(stmt, "retval", None) is None)

        if isinstance(guard_stmt, CIfBreak):
            break_cond = guard_stmt.condition
        elif isinstance(guard_stmt, CIfElse):
            branches = _boundary_tuple_8616(guard_stmt.condition_and_nodes or ())
            else_node = guard_stmt.else_node
            else_statements = (
                _boundary_tuple_8616(getattr(else_node, "statements", ()) or ()) if else_node is not None else ()
            )
            if len(branches) < 1 or else_statements:
                return None
            break_cond = branches[0][0]
            for _branch_cond, branch_node in branches:
                branch_statements = _boundary_tuple_8616(getattr(branch_node, "statements", ()) or ())
                if len(branch_statements) != 1 or not _is_void_loop_exit_stmt_8616(branch_statements[0]):
                    return None
                suppressed_node_ids.add(id(branch_statements[0]))
        else:
            return None

        if break_cond is None:
            return None
        normalized = _invert_condition_fingerprint_8616(break_cond, project, contextual_condition_fingerprints)
        if normalized is None:
            return None
        if guard_index > 0:
            contextual_fingerprint = contextual_condition_fingerprints.get(id(break_cond))
            if contextual_fingerprint is None:
                return None
            prefix_assignments = statements[:guard_index]
            prefix_has_call = any(
                isinstance(child, CFunctionCall)
                for stmt in prefix_assignments
                for child in _iter_c_nodes_deep_8616(getattr(stmt, "rhs", None))
            )
            if prefix_has_call and "call:" not in contextual_fingerprint:
                return None
        return normalized, suppressed_node_ids

    return _impl()


def _do_while_post_body_condition_fingerprint_8616(
    loop: TailValidationValue,
    project: TailValidationValue,
) -> str | None:
    """Fingerprint a proven affine do-while guard in its post-body state."""
    if not isinstance(loop, CDoWhileLoop) or not isinstance(loop.condition, CBinaryOp):
        return None
    statements = _boundary_tuple_8616(getattr(loop.body, "statements", ()) or ())
    if not statements:
        return None
    iterator = statements[-1]
    if (
        not isinstance(iterator, CAssignment)
        or not isinstance(iterator.lhs, CVariable)
        or not isinstance(iterator.rhs, CBinaryOp)
        or iterator.rhs.op not in {"Add", "Sub"}
        or not isinstance(iterator.rhs.lhs, CVariable)
        or not isinstance(iterator.rhs.rhs, CConstant)
    ):
        return None
    target = _expr_fingerprint(iterator.lhs, project)
    if _expr_fingerprint(iterator.rhs.lhs, project) != target:
        return None
    replacement = _expr_fingerprint(iterator.rhs, project)
    occurrence_count = 0

    def _fingerprint(node: TailValidationValue) -> str:
        """Substitute the proven iterator update at its unique guard use."""
        nonlocal occurrence_count
        if isinstance(node, CVariable) and _expr_fingerprint(node, project) == target:
            occurrence_count += 1
            return replacement
        if isinstance(node, CBinaryOp):
            return f"{node.op}({_fingerprint(node.lhs)},{_fingerprint(node.rhs)})"
        return _expr_fingerprint(node, project)

    fingerprint = _fingerprint(loop.condition)
    return fingerprint if occurrence_count == 1 else None


def _normalized_if_chain_condition_8616(
    pairs: Sequence[tuple[TailValidationValue, TailValidationValue]], idx: int, codegen: TailValidationValue
) -> TailValidationValue | None:
    if idx <= 0 or idx >= len(pairs):
        return None
    prev_cond, _prev_body = pairs[idx - 1]
    curr_cond, _curr_body = pairs[idx]
    return _split_ordering_if_chain_replacement_condition_8616(prev_cond, curr_cond, codegen)


def _normalized_call_target_addr_8616(project: TailValidationValue, target_addr: int | None) -> int | None:
    """Return canonical call identity through the shared traits owner."""
    normalized = normalize_x86_16_call_target_addr_8616(project, target_addr)
    return normalized if isinstance(normalized, int) else None


def _call_summary_target_addr_8616(
    project: TailValidationValue,
    summary: Mapping[str, TailValidationValue] | CallsiteSummary8616 | None,
) -> int | None:
    """Return the normalized target address from a direct or wrapped callsite summary."""
    return _normalized_call_target_addr_8616(project, _summary_attr_8616(summary, "target_addr"))


def _active_validation_function_8616(project: TailValidationValue) -> TailValidationValue | None:
    # Dynamic angr/codegen compatibility boundary.
    codegen = getattr(project, "_inertia_tail_validation_active_codegen", None)
    if codegen is None:
        return None
    for candidate in (
        # Dynamic angr/codegen compatibility boundary.
        getattr(codegen, "_inertia_current_function_8616", None),
        # Dynamic angr/codegen compatibility boundary.
        getattr(codegen, "_func", None),
        # Dynamic angr/codegen compatibility boundary.
        getattr(codegen, "cfunc", None),
    ):
        if candidate is not None:
            return candidate
    return None


def _active_callsite_target_fingerprint_8616(project: TailValidationValue, callsite_addr: int) -> str | None:
    function = _active_validation_function_8616(project)
    if function is None:
        return None
    if callsite_addr not in _function_callsite_addrs_for_validation_8616(function):
        return None
    try:
        summary = summarize_x86_16_callsite(function, callsite_addr)
    except Exception:
        return None
    if _summary_is_stack_probe_helper_8616(summary):
        return None
    target_addr = _call_summary_target_addr_8616(project, summary)
    if _target_addr_is_stack_probe_helper_8616(project, target_addr):
        return None
    if isinstance(target_addr, int):
        return f"addr:{target_addr:#x}"
    return None


def _call_summary_callsite_addr_8616(
    summary: Mapping[str, TailValidationValue] | CallsiteSummary8616 | None,
) -> int | None:
    if isinstance(summary, Mapping):
        callsite_addr = summary.get("callsite_addr")
    elif isinstance(summary, CallsiteSummary8616):
        callsite_addr = summary.callsite_addr
    else:
        callsite_addr = None
    return callsite_addr if isinstance(callsite_addr, int) else None


def _known_function_entry_addr_8616(project: TailValidationValue, addr: int) -> bool:
    """Return whether an address is a known function entry, not a callsite token."""
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    if not callable(lookup):
        return False
    candidates = [addr]
    normalized = _normalized_call_target_addr_8616(project, addr)
    if isinstance(normalized, int) and normalized not in candidates:
        candidates.append(normalized)
    for candidate in candidates:
        with contextlib.suppress(Exception):
            function = lookup(addr=candidate, create=False)
            if getattr(function, "addr", None) == candidate:
                return True
    return False


def _normalize_helper_call_fingerprint_8616(project: TailValidationValue, token: str | None) -> str | None:
    def _impl() -> str | None:
        if not isinstance(token, str) or not token:
            return token
        if token.startswith("addr:"):
            raw = token[5:]
            try:
                value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 0)
            except ValueError:
                return token
            if _known_function_entry_addr_8616(project, value):
                normalized = _normalized_call_target_addr_8616(project, value)
                return f"addr:{normalized:#x}" if isinstance(normalized, int) else token
            callsite_target = _active_callsite_target_fingerprint_8616(project, value)
            if isinstance(callsite_target, str) and callsite_target:
                return callsite_target
            normalized = _normalized_call_target_addr_8616(project, value)
            return f"addr:{normalized:#x}" if isinstance(normalized, int) else token
        if token.startswith("name:addr:"):
            raw = token[10:]
            try:
                value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 0)
            except ValueError:
                return token
            normalized = _normalized_call_target_addr_8616(project, value)
            return f"name:addr:{normalized:#x}" if isinstance(normalized, int) else token
        if token.startswith("name:"):
            raw_name = token[5:]
            resolved_addr = _resolve_call_symbol_addr_8616(project, raw_name)
            if isinstance(resolved_addr, int):
                normalized = _normalized_call_target_addr_8616(project, resolved_addr)
                return f"addr:{normalized:#x}" if isinstance(normalized, int) else f"addr:{resolved_addr:#x}"
        if token.startswith("codcall:"):
            raw_name = token[8:]
            resolved_addr = _resolve_call_symbol_addr_8616(project, raw_name)
            if isinstance(resolved_addr, int):
                normalized = _normalized_call_target_addr_8616(project, resolved_addr)
                return f"addr:{normalized:#x}" if isinstance(normalized, int) else f"addr:{resolved_addr:#x}"
        return token

    return _impl()


def _is_void_return_type_8616(return_type: TailValidationValue) -> bool:
    return isinstance(return_type, SimTypeBottom) and getattr(return_type, "label", None) == "void"


def _active_codegen_return_value_is_unobserved_8616(project: TailValidationValue) -> bool:
    """Return whether the active function's result is outside the live-out surface."""
    codegen = getattr(project, "_inertia_tail_validation_active_codegen", None)
    if codegen is None:
        return False
    cfunc = getattr(codegen, "cfunc", None)
    for candidate in (
        getattr(cfunc, "prototype", None),
        getattr(cfunc, "functy", None),
        getattr(getattr(codegen, "_func", None), "prototype", None),
        getattr(getattr(codegen, "_inertia_current_function_8616", None), "prototype", None),
    ):
        if _is_void_return_type_8616(getattr(candidate, "returnty", None)):
            return True
    candidate_functions = [
        getattr(codegen, "_inertia_current_function_8616", None),
        getattr(codegen, "_func", None),
    ]
    cfunc_addr = getattr(cfunc, "addr", None)
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if isinstance(cfunc_addr, int) and functions is not None:
        with contextlib.suppress(Exception):
            candidate_functions.append(functions.function(addr=cfunc_addr, create=False))
    if isinstance(cfunc_addr, int) and function_result_is_proven_unobserved_8616(project, cfunc_addr):
        return True
    for candidate_function in candidate_functions:
        if _function_has_void_return_evidence_8616(candidate_function):
            return True
    return False


def _function_has_void_return_evidence_8616(function: TailValidationValue) -> bool:
    if function is None:
        return False
    if getattr(function, "returning", None) is False:
        return True
    prototype = getattr(function, "prototype", None)
    # Dynamic angr/codegen compatibility boundary.
    return _is_void_return_type_8616(getattr(prototype, "returnty", None))


def _call_effect_fingerprint_8616(
    node: TailValidationValue,
    project: TailValidationValue,
    *,
    contextual_call_summaries: Mapping[int, TailValidationValue],
    contextual_call_fingerprints: Mapping[int, str],
) -> str:
    summary = contextual_call_summaries.get(id(node))
    target_addr = _call_summary_target_addr_8616(project, summary)
    call_fingerprint = (
        f"addr:{target_addr:#x}" if isinstance(target_addr, int) else contextual_call_fingerprints.get(id(node))
    )
    if call_fingerprint is None:
        call_name = _call_target_name(node, project)
        if isinstance(call_name, str) and call_name:
            call_fingerprint = f"name:{call_name}"
    return _normalize_helper_call_fingerprint_8616(project, call_fingerprint) or "<unknown-call>"


def _expected_helper_call_counts_for_validation_8616(
    root: TailValidationValue,
    project: TailValidationValue,
    summary_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> Counter[str]:
    function = _function_for_call_context_8616(root, project)
    if function is None:
        return Counter()
    counts: Counter[str] = Counter()
    for callsite_addr in _function_callsite_addrs_for_validation_8616(function):
        fingerprint = _callsite_expected_fingerprint_8616(
            function,
            project,
            callsite_addr,
            summary_inventory,
        )
        normalized = _normalize_helper_call_fingerprint_8616(project, fingerprint)
        if isinstance(normalized, str) and normalized:
            counts[_canonicalize_helper_call_fingerprint_for_compare_8616(normalized)] += 1
    return counts


def _cap_helper_call_fingerprints_to_expected_8616(
    project: TailValidationValue,
    fingerprints: Sequence[str],
    expected_counts: Counter[str],
) -> tuple[str, ...]:
    if not expected_counts:
        return tuple(fingerprints)
    observed: Counter[str] = Counter()
    capped: list[str] = []
    for fingerprint in fingerprints:
        normalized = _normalize_helper_call_fingerprint_8616(project, fingerprint)
        key = _canonicalize_helper_call_fingerprint_for_compare_8616(str(normalized or fingerprint))
        expected_count = expected_counts.get(key)
        if expected_count:
            if observed[key] >= expected_count:
                continue
            observed[key] += 1
        capped.append(fingerprint)
    return tuple(capped)


def _helper_call_fingerprints_satisfy_expected_8616(
    project: TailValidationValue,
    fingerprints: Sequence[str],
    expected_counts: Counter[str],
) -> bool:
    if not expected_counts:
        return False
    observed: Counter[str] = Counter()
    for fingerprint in fingerprints:
        normalized = _normalize_helper_call_fingerprint_8616(project, fingerprint)
        key = _canonicalize_helper_call_fingerprint_for_compare_8616(str(normalized or fingerprint))
        observed[key] += 1
    return all(observed.get(key, 0) >= count for key, count in expected_counts.items())


def _collapse_mixed_addr_name_addr_duplicates_8616(fingerprints: Sequence[str]) -> tuple[str, ...]:
    by_key: dict[str, str] = {}
    order: list[str] = []
    for fingerprint in fingerprints:
        key = _canonicalize_helper_call_fingerprint_for_compare_8616(str(fingerprint))
        previous = by_key.get(key)
        if previous is None:
            by_key[key] = fingerprint
            order.append(key)
            continue
        if str(previous).startswith("name:addr:") and not str(fingerprint).startswith("name:addr:"):
            by_key[key] = fingerprint
    return tuple(by_key[key] for key in order)


def _node_callsite_addr_8616(node: TailValidationValue) -> int | None:
    """Return a callsite address from dynamic angr C AST node metadata."""
    # Dynamic boundary: angr C AST nodes expose optional tag/address attributes.
    tags = getattr(node, "tags", None)
    if isinstance(tags, dict):
        for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
            value = tags.get(key)
            if isinstance(value, int):
                return value
    # Dynamic boundary: not every third-party C AST node has a tags dict.
    value = getattr(node, "addr", None)
    return value if isinstance(value, int) else None


def _call_identity_callsite_addr_8616(node: TailValidationValue, summary: TailValidationValue) -> int | None:
    summary_callsite_addr = _call_summary_callsite_addr_8616(summary)
    if isinstance(summary_callsite_addr, int):
        return summary_callsite_addr
    return _node_callsite_addr_8616(node)


def _candidate_target_addrs_from_call_8616(project: TailValidationValue, node: TailValidationValue) -> tuple[int, ...]:
    """Return candidate target addresses from dynamic angr call node metadata."""
    addrs: list[int] = []
    # Dynamic boundary: angr C AST call nodes expose optional callee metadata.
    callee_func = getattr(node, "callee_func", None)
    callee_addr = getattr(callee_func, "addr", None)
    if isinstance(callee_addr, int):
        addrs.append(callee_addr)
    for target in (
        getattr(node, "callee_target", None),
        getattr(callee_func, "name", None),
    ):
        if not isinstance(target, str):
            continue
        resolved_addr = _resolve_call_symbol_addr_8616(project, target)
        if isinstance(resolved_addr, int):
            addrs.append(resolved_addr)
        match = re.search(r"0x([0-9a-fA-F]+)", target)
        if match is None:
            continue
        try:
            addrs.append(int(match.group(1), 16))
        except ValueError:
            continue
    ordered: list[int] = []
    for addr in addrs:
        if addr not in ordered:
            ordered.append(addr)
    return tuple(ordered)


def _call_node_matches_summary_8616(
    project: TailValidationValue, node: TailValidationValue, summary: TailValidationValue
) -> bool:
    if node is None or summary is None:
        return False
    target_addr = _call_summary_target_addr_8616(project, summary)
    if not isinstance(target_addr, int):
        return False
    if _target_addr_is_stack_probe_helper_8616(project, target_addr) and _call_node_has_nonprobe_target_evidence_8616(
        project, node
    ):
        return False
    return target_addr in {
        _normalized_call_target_addr_8616(project, candidate_addr)
        for candidate_addr in _candidate_target_addrs_from_call_8616(project, node)
        if isinstance(candidate_addr, int)
    }


def _call_node_has_nonprobe_target_evidence_8616(project: TailValidationValue, node: TailValidationValue) -> bool:
    """Return whether a C call node already points at a concrete non-stack-probe target."""
    for candidate_addr in _candidate_target_addrs_from_call_8616(project, node):
        normalized = _normalized_call_target_addr_8616(project, candidate_addr)
        addr = normalized if isinstance(normalized, int) else candidate_addr
        if not _target_addr_is_stack_probe_helper_8616(project, addr):
            return True
    return False


def _ordered_contextual_call_pairs_8616(
    root: TailValidationValue,
    project: TailValidationValue,
    summary_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> list[tuple[CFunctionCall, int]]:
    def _impl() -> list[tuple[CFunctionCall, int]]:
        function = _function_for_call_context_8616(root, project)
        if function is None:
            return []
        callsite_addrs = _boundary_tuple_8616(sorted(getattr(function, "get_call_sites", list)() or ()))
        if not callsite_addrs:
            callsite_addrs = _collect_direct_capstone_callsite_addrs_8616(function)
        call_nodes = list(_iter_observable_call_nodes_for_validation_8616(root))
        if not callsite_addrs or not call_nodes:
            return []

        nodes_by_callsite: dict[int, list[CFunctionCall]] = {}
        remaining_nodes: list[CFunctionCall] = []
        for node in call_nodes:
            callsite_addr = _node_callsite_addr_8616(node)
            if isinstance(callsite_addr, int):
                nodes_by_callsite.setdefault(callsite_addr, []).append(node)
            else:
                remaining_nodes.append(node)

        ordered_pairs: list[tuple[CFunctionCall, int]] = []
        used_node_ids: set[int] = set()
        unmatched_callsites: list[int] = []
        for callsite_addr in callsite_addrs:
            matched_nodes = nodes_by_callsite.get(callsite_addr)
            if matched_nodes:
                node = matched_nodes.pop(0)
                ordered_pairs.append((node, callsite_addr))
                used_node_ids.add(id(node))
            else:
                unmatched_callsites.append(callsite_addr)

        remaining_nodes.extend(
            node for node in call_nodes if id(node) not in used_node_ids and node not in remaining_nodes
        )
        available_nodes = list(remaining_nodes)
        for callsite_addr in unmatched_callsites:
            summary = (
                summary_inventory.get(callsite_addr)
                if summary_inventory is not None
                else summarize_x86_16_callsite(function, callsite_addr)
            )
            matched_index = None
            if summary is not None:
                for idx, node in enumerate(available_nodes):
                    if _call_node_matches_summary_8616(project, node, summary):
                        matched_index = idx
                        break
            if matched_index is None:
                continue
            node = available_nodes.pop(matched_index)
            ordered_pairs.append((node, callsite_addr))
        return ordered_pairs

    return _impl()


def _node_boundary_fingerprint(
    node: TailValidationValue,
    project: TailValidationValue,
    contextual_call_fingerprints: Mapping[int, str] | None = None,
    contextual_call_summaries: Mapping[int, TailValidationValue] | None = None,
) -> TailValidationValue:
    if node is not None:
        # Dynamic angr/codegen compatibility boundary.
        cache = getattr(project, "_inertia_tail_validation_boundary_node_cache_8616", None)
        if isinstance(cache, dict):
            cache_key = (id(node), id(contextual_call_fingerprints), id(contextual_call_summaries))
            cached = cache.get(cache_key)
            if cached is not None:
                return cached

    def _impl() -> TailValidationValue:
        if node is None:
            return None
        contextual_condition_fingerprints = getattr(
            project, "_inertia_tail_validation_contextual_condition_fingerprints", None
        )
        if isinstance(contextual_condition_fingerprints, Mapping):
            condition_fingerprint = contextual_condition_fingerprints.get(id(node))
            if isinstance(condition_fingerprint, str):
                return ("condition", condition_fingerprint)
        if isinstance(node, CConstant):
            return ("const", node.value)
        if isinstance(node, CVariable):
            return ("var", _location_fingerprint(node, project))
        if isinstance(node, CTypeCast):
            return (
                "cast",
                _node_boundary_fingerprint(
                    node.expr,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                ),
            )
        if isinstance(node, CUnaryOp):
            return (
                "unary",
                node.op,
                _node_boundary_fingerprint(
                    node.operand,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                ),
            )
        if isinstance(node, CBinaryOp):
            return (
                "binary",
                node.op,
                _node_boundary_fingerprint(
                    node.lhs,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                ),
                _node_boundary_fingerprint(
                    node.rhs,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                ),
            )
        if isinstance(node, CFunctionCall):
            return _call_node_boundary_fingerprint_8616(
                node,
                project,
                contextual_call_fingerprints=contextual_call_fingerprints,
                contextual_call_summaries=contextual_call_summaries,
            )
        if isinstance(node, CAssignment):
            return (
                "assign",
                _node_boundary_fingerprint(
                    node.lhs,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                ),
                _node_boundary_fingerprint(
                    node.rhs,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                ),
            )
        if isinstance(node, CReturn):
            return (
                "return",
                _node_boundary_fingerprint(
                    node.retval,
                    project,
                    contextual_call_fingerprints,
                    contextual_call_summaries,
                ),
            )
        structured_fp = _structured_node_boundary_fingerprint_8616(
            node,
            project,
            contextual_call_fingerprints=contextual_call_fingerprints,
            contextual_call_summaries=contextual_call_summaries,
        )
        if structured_fp is not None:
            return structured_fp
        if isinstance(node, CGoto):
            return ("goto", node.target, node.target_idx)
        if isinstance(node, CBreak):
            return ("break",)
        if isinstance(node, CContinue):
            return ("continue",)
        if type(node).__name__ == "CStatements":
            return (
                "statements",
                _boundary_tuple_8616(
                    _node_boundary_fingerprint(
                        stmt,
                        project,
                        contextual_call_fingerprints,
                        contextual_call_summaries,
                    )
                    for stmt in (getattr(node, "statements", ()) or ())
                ),
            )

        fields = []
        for attr in (
            "condition",
            "cond",
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "lhs",
            "rhs",
            "expr",
            "operand",
            "retval",
        ):
            if hasattr(node, attr):
                fields.append((attr, _node_boundary_fingerprint(getattr(node, attr, None), project)))
        return (type(node).__name__, tuple(fields))

    result = _impl()
    if node is not None:
        # Dynamic angr/codegen compatibility boundary.
        cache = getattr(project, "_inertia_tail_validation_boundary_node_cache_8616", None)
        if isinstance(cache, dict):
            cache[(id(node), id(contextual_call_fingerprints), id(contextual_call_summaries))] = result
    return result


def _condition_node_boundary_fingerprint_8616(
    node: TailValidationValue,
    project: TailValidationValue,
    contextual_call_fingerprints: Mapping[int, str] | None,
    contextual_call_summaries: Mapping[int, TailValidationValue] | None,
) -> TailValidationValue:
    """Fingerprint a control-flow condition through the canonical expression surface."""
    # Dynamic angr/codegen compatibility boundary.
    contextual_condition_fingerprints = getattr(
        project,
        "_inertia_tail_validation_contextual_condition_fingerprints",
        None,
    )
    if isinstance(contextual_condition_fingerprints, Mapping):
        condition_fingerprint = contextual_condition_fingerprints.get(id(node))
        if isinstance(condition_fingerprint, str):
            return ("condition", condition_fingerprint)
    if isinstance(node, CBinaryOp):
        return ("condition", _expr_fingerprint(node, project))
    return _node_boundary_fingerprint(node, project, contextual_call_fingerprints, contextual_call_summaries)


def _call_node_boundary_fingerprint_8616(
    node: TailValidationValue,
    project: TailValidationValue,
    *,
    contextual_call_fingerprints: Mapping[int, str] | None,
    contextual_call_summaries: Mapping[int, TailValidationValue] | None,
) -> tuple[TailValidationValue, ...]:
    if _is_runtime_segment_helper_call_8616(node):
        return ("expr", _expr_fingerprint(node, project))
    call_fingerprint = None
    if isinstance(contextual_call_fingerprints, Mapping):
        call_fingerprint = contextual_call_fingerprints.get(id(node))
    if call_fingerprint is None and isinstance(contextual_call_summaries, Mapping):
        summary = contextual_call_summaries.get(id(node))
        target_addr = _call_summary_target_addr_8616(project, summary)
        if isinstance(target_addr, int):
            call_fingerprint = f"addr:{target_addr:#x}"
    return (
        "call",
        call_fingerprint or _call_target_name(node, project),
        _boundary_tuple_8616(
            _node_boundary_fingerprint(
                arg,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            )
            for arg in (getattr(node, "args", ()) or ())
        ),
    )


def _structured_node_boundary_fingerprint_8616(
    node: TailValidationValue,
    project: TailValidationValue,
    *,
    contextual_call_fingerprints: Mapping[int, str] | None,
    contextual_call_summaries: Mapping[int, TailValidationValue] | None,
) -> TailValidationValue:
    def _impl() -> TailValidationValue:
        if isinstance(node, CIfElse):
            return (
                "ifelse",
                _boundary_tuple_8616(
                    (
                        _condition_node_boundary_fingerprint_8616(
                            cond, project, contextual_call_fingerprints, contextual_call_summaries
                        ),
                        _node_boundary_fingerprint(
                            body, project, contextual_call_fingerprints, contextual_call_summaries
                        ),
                    )
                    for cond, body in (node.condition_and_nodes or ())
                ),
                _node_boundary_fingerprint(
                    node.else_node, project, contextual_call_fingerprints, contextual_call_summaries
                ),
            )
        if isinstance(node, CIfBreak):
            return (
                "ifbreak",
                _condition_node_boundary_fingerprint_8616(
                    node.condition, project, contextual_call_fingerprints, contextual_call_summaries
                ),
            )
        if isinstance(node, CWhileLoop):
            return (
                "while",
                _condition_node_boundary_fingerprint_8616(
                    node.condition, project, contextual_call_fingerprints, contextual_call_summaries
                ),
                _node_boundary_fingerprint(
                    node.body, project, contextual_call_fingerprints, contextual_call_summaries
                ),
            )
        if isinstance(node, CDoWhileLoop):
            return (
                "dowhile",
                _condition_node_boundary_fingerprint_8616(
                    node.condition, project, contextual_call_fingerprints, contextual_call_summaries
                ),
                _node_boundary_fingerprint(
                    node.body, project, contextual_call_fingerprints, contextual_call_summaries
                ),
            )
        if isinstance(node, CForLoop):
            return (
                "for",
                _node_boundary_fingerprint(
                    node.initializer, project, contextual_call_fingerprints, contextual_call_summaries
                ),
                _condition_node_boundary_fingerprint_8616(
                    node.condition, project, contextual_call_fingerprints, contextual_call_summaries
                ),
                _node_boundary_fingerprint(
                    node.iterator, project, contextual_call_fingerprints, contextual_call_summaries
                ),
                _node_boundary_fingerprint(
                    node.body, project, contextual_call_fingerprints, contextual_call_summaries
                ),
            )
        if isinstance(node, CSwitchCase):
            case_items = _boundary_tuple_8616(
                (
                    _switch_case_fingerprint(case_value, project),
                    _node_boundary_fingerprint(
                        case_body, project, contextual_call_fingerprints, contextual_call_summaries
                    ),
                )
                for case_value, case_body in sorted(
                    # Dynamic angr/codegen compatibility boundary.
                    _switch_case_items_8616(node.cases),
                    key=lambda item: _switch_case_fingerprint(item[0], project),
                )
            )
            return (
                "switch",
                _node_boundary_fingerprint(
                    node.switch, project, contextual_call_fingerprints, contextual_call_summaries
                ),
                case_items,
                _node_boundary_fingerprint(
                    node.default, project, contextual_call_fingerprints, contextual_call_summaries
                ),
            )
        return None

    return _impl()


def _tail_validation_summary_cache_store(codegen: TailValidationValue) -> dict[str, TailValidationValue]:
    cache = getattr(codegen, "_inertia_tail_validation_summary_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        codegen._inertia_tail_validation_summary_cache = cache
    stats = cache.setdefault("stats", {"hits": 0, "misses": 0})
    if not isinstance(stats, dict):
        cache["stats"] = {"hits": 0, "misses": 0}
    cache.setdefault("entries", {})
    cache.setdefault("boundary_entries", {})
    return cache


def _consume_tail_validation_boundary_context_8616(
    codegen: TailValidationValue,
    *,
    mode: str,
    boundary_fingerprint: str,
    root: TailValidationValue,
) -> _TailValidationBoundaryContext8616 | None:
    """Return matching boundary facts once, then clear them from codegen."""
    # Dynamic angr/codegen compatibility boundary.
    context = getattr(codegen, "_inertia_tail_validation_boundary_context_8616", None)
    if not isinstance(context, _TailValidationBoundaryContext8616):
        return None
    with contextlib.suppress(Exception):
        delattr(codegen, "_inertia_tail_validation_boundary_context_8616")
    if context.mode != mode or context.boundary_fingerprint != boundary_fingerprint or context.root_id != id(root):
        return None
    return context


def _clone_tail_validation_aggregate_payload(
    value: Mapping[str, TailValidationValue],
) -> dict[str, TailValidationValue]:
    surface = value.get("surface")
    return {
        "summary": dict(value["summary"]),
        "surface": dict(surface) if isinstance(surface, Mapping) else None,
    }


def _records_with_uncollected_placeholders(
    records: Sequence[Mapping[str, TailValidationValue]],
    *,
    scanned: int,
) -> list[Mapping[str, TailValidationValue]]:
    normalized = [record for record in records if isinstance(record, Mapping)]
    missing_records = max(0, int(scanned or 0) - len(normalized))
    if missing_records <= 0:
        return normalized
    return normalized + [{} for _ in range(missing_records)]


def _tail_validation_validation_cache_store(owner: TailValidationValue) -> MutableMapping[str, TailValidationValue]:
    if owner is None:
        return {}
    if isinstance(owner, MutableMapping):
        cache = owner.setdefault("_x86_16_tail_validation_cache", {})
        if not isinstance(cache, MutableMapping):
            cache = {}
            owner["_x86_16_tail_validation_cache"] = cache
        cache.setdefault("comparisons", {})
        return cast(MutableMapping[str, TailValidationValue], cache)
    return {}


def _tail_validation_records_fingerprint(records: Sequence[Mapping[str, TailValidationValue]], *, scanned: int) -> str:
    payload = {
        "scanned": int(scanned or 0),
        "records": [
            {
                "cod_file": record.get("cod_file"),
                "proc_name": record.get("proc_name"),
                "proc_kind": record.get("proc_kind"),
                "structuring": record.get("structuring"),
                "postprocess": record.get("postprocess"),
                "tail_validation_uncollected": record.get("tail_validation_uncollected"),
                "exit_kind": record.get("exit_kind"),
                "exit_detail": record.get("exit_detail"),
            }
            for record in records
        ],
    }
    return build_x86_16_validation_cache_descriptor("tail_validation.aggregate.records", payload).fingerprint


def _tail_validation_changed_observable_fields(entry: Mapping[str, TailValidationValue]) -> tuple[str, ...]:
    def _impl() -> tuple[str, ...]:
        delta = entry.get("delta")
        changed_fields: list[str] = []
        if isinstance(delta, Mapping):
            for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
                field_delta = delta.get(field_name)
                if not isinstance(field_delta, Mapping):
                    continue
                added = field_delta.get("added", ()) or ()
                removed = field_delta.get("removed", ()) or ()
                if added or removed:
                    changed_fields.append(field_name)
            if changed_fields:
                return tuple(changed_fields)

        text_parts = []
        for key in ("summary_text", "verdict"):
            value = entry.get(key)
            if isinstance(value, str):
                text_parts.append(value)
        combined = " ".join(text_parts)
        return tuple(field_name for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS if f"{field_name}:" in combined)

    return _impl()


def _tail_validation_changed_families(entry: Mapping[str, TailValidationValue]) -> tuple[str, ...]:
    def _impl() -> tuple[str, ...]:
        fields = set(_tail_validation_changed_observable_fields(entry))
        families: list[str] = []
        if "helper_calls" in fields:
            families.append("helper call delta")
        if "register_writes" in fields:
            families.append("live-out register delta")
        if "stack_writes" in fields:
            families.append("stack write delta")
        if {"global_writes", "segmented_writes"} <= fields:
            families.append("segmented/global write delta")
        else:
            if "global_writes" in fields:
                families.append("global write delta")
            if "segmented_writes" in fields:
                families.append("segmented write delta")
        if "returns" in fields:
            families.append("return delta")
        if "conditions" in fields or "control_flow_effects" in fields:
            families.append("control-flow/guard delta")
        if not families:
            families.append("unclassified observable delta")
        return tuple(families)

    return _impl()


def _tail_validation_changed_family_summary(
    changed_functions: Sequence[Mapping[str, TailValidationValue]],
) -> list[dict[str, TailValidationValue]]:
    def _impl() -> list[dict[str, TailValidationValue]]:
        rows: dict[str, dict[str, TailValidationValue]] = {}
        for item in changed_functions:
            if not isinstance(item, Mapping):
                continue
            stage = item.get("stage")
            function_key = (item.get("cod_file"), item.get("proc_name"), item.get("proc_kind"))
            function_label = {
                "cod_file": item.get("cod_file"),
                "proc_name": item.get("proc_name"),
                "proc_kind": item.get("proc_kind"),
            }
            families = item.get("families")
            if not isinstance(families, Sequence) or isinstance(families, (str, bytes)):
                families = ("unclassified observable delta",)
            for family in families:
                if not isinstance(family, str) or not family:
                    continue
                row = rows.setdefault(
                    family,
                    {
                        "family": family,
                        "count": 0,
                        "stages": set(),
                        "functions": set(),
                        "examples": [],
                    },
                )
                row["count"] += 1
                if isinstance(stage, str) and stage:
                    row["stages"].add(stage)
                row["functions"].add(function_key)
                if len(row["examples"]) < 5 and function_label not in row["examples"]:
                    row["examples"].append(function_label)

        summarized = []
        for row in rows.values():
            summarized.append(
                {
                    "family": row["family"],
                    "count": row["count"],
                    "function_count": len(row["functions"]),
                    "stages": tuple(sorted(row["stages"])),
                    "examples": tuple(row["examples"]),
                }
            )
        return sorted(summarized, key=lambda item: (-int(item["count"]), item["family"]))

    return _impl()


def _tail_validation_sort_value(value: TailValidationValue) -> str:
    return value if isinstance(value, str) else ""


def _tail_validation_function_sort_key(item: Mapping[str, TailValidationValue]) -> tuple[str, str, str, str]:
    return (
        "" if isinstance(item.get("cod_file"), str) else "~",
        _tail_validation_sort_value(item.get("cod_file")),
        _tail_validation_sort_value(item.get("proc_name")),
        _tail_validation_sort_value(item.get("proc_kind")),
    )


def _tail_validation_stage_status(entry: TailValidationValue) -> str:
    if not isinstance(entry, Mapping):
        return "uncollected"
    status = entry.get("status")
    if isinstance(status, str) and status:
        normalized = status.lower()
        if normalized in {"stable", "passed"}:
            return "passed"
        if normalized in {"changed", "uncollected"}:
            return normalized
        if normalized == "failed":
            return "changed"
        if normalized == "unknown":
            return "unknown"
        return "uncollected"
    if "changed" not in entry:
        return "unknown"
    return "changed" if bool(entry.get("changed", False)) else "passed"


def _tail_validation_record_proc_name(record: Mapping[str, TailValidationValue]) -> TailValidationValue:
    proc_name = record.get("proc_name")
    if proc_name:
        return proc_name
    return record.get("function_name")


def _tail_validation_function_accounting(
    records: Sequence[Mapping[str, TailValidationValue]],
) -> dict[str, TailValidationValue]:
    def _impl() -> dict[str, TailValidationValue]:
        rows: list[dict[str, TailValidationValue]] = []
        status_counts: Counter[str] = Counter()
        for record in records:
            proc_name = _tail_validation_record_proc_name(record)
            stage_statuses = {
                stage: _tail_validation_stage_status(record.get(stage)) for stage in ("structuring", "postprocess")
            }
            if "changed" in stage_statuses.values():
                status = "changed"
            elif "unknown" in stage_statuses.values():
                status = "unknown"
            elif "uncollected" in stage_statuses.values():
                status = "uncollected"
            else:
                status = "passed"
            status_counts[status] += 1
            rows.append(
                {
                    "cod_file": record.get("cod_file"),
                    "proc_name": proc_name,
                    "proc_kind": record.get("proc_kind"),
                    "status": status,
                    "stage_statuses": dict(sorted(stage_statuses.items())),
                    "exit_kind": record.get("exit_kind"),
                    "exit_detail": record.get("exit_detail"),
                    "tail_validation_uncollected": bool(record.get("tail_validation_uncollected", False)),
                }
            )
        rows.sort(key=_tail_validation_function_sort_key)
        return {
            "function_status_counts": dict(sorted(status_counts.items())),
            "function_statuses": rows,
            "passed_functions": [row for row in rows if row["status"] == "passed"],
            "changed_functions": [row for row in rows if row["status"] == "changed"],
            "unknown_functions": [row for row in rows if row["status"] == "unknown"],
            "uncollected_functions": [row for row in rows if row["status"] == "uncollected"],
        }

    return _impl()


def _tail_validation_stage_summary(
    records: Sequence[Mapping[str, TailValidationValue]], stage: str
) -> dict[str, TailValidationValue]:
    def _impl() -> dict[str, TailValidationValue]:
        stable_count = 0
        changed_count = 0
        unknown_count = 0
        missing_count = 0
        mode_counter: Counter[str] = Counter()
        verdict_counter: Counter[str] = Counter()
        changed_functions: list[dict[str, TailValidationValue]] = []

        for record in records:
            entry = record.get(stage)
            if not isinstance(entry, Mapping):
                missing_count += 1
                continue
            if "changed" not in entry:
                unknown_count += 1
                continue
            changed = bool(entry.get("changed", False))
            mode = entry.get("mode")
            verdict = entry.get("verdict")
            if isinstance(mode, str) and mode:
                mode_counter[mode] += 1
            if changed:
                changed_count += 1
                if isinstance(verdict, str) and verdict:
                    verdict_counter[verdict] += 1
                families = _tail_validation_changed_families(entry)
                changed_functions.append(
                    {
                        "cod_file": record.get("cod_file"),
                        "proc_name": _tail_validation_record_proc_name(record),
                        "proc_kind": record.get("proc_kind"),
                        "stage": stage,
                        "verdict": verdict,
                        "families": families,
                    }
                )
            else:
                stable_count += 1

        changed_functions.sort(
            key=lambda item: (
                "" if isinstance(item.get("cod_file"), str) else "~",
                item.get("cod_file"),
                item.get("proc_name"),
                item.get("proc_kind"),
            )
        )
        top_verdicts = [
            {"verdict": verdict, "count": count}
            for verdict, count in sorted(verdict_counter.items(), key=lambda item: (-item[1], item[0]))
        ]
        return {
            "stable_count": stable_count,
            "changed_count": changed_count,
            "unknown_count": unknown_count,
            "missing_count": missing_count,
            "coverage_count": stable_count + changed_count + unknown_count,
            "mode_counts": dict(sorted(mode_counter.items())),
            "top_verdicts": top_verdicts,
            "changed_functions": changed_functions,
            "changed_families": _tail_validation_changed_family_summary(changed_functions),
        }

    return _impl()


def _switch_case_fingerprint(case_value: TailValidationValue, project: TailValidationValue) -> str:
    if isinstance(case_value, int):
        return f"const:{case_value}"
    if isinstance(case_value, (tuple, list)):
        return "[" + ",".join(_switch_case_fingerprint(item, project) for item in case_value) + "]"
    return str(_expr_fingerprint(case_value, project))


def _switch_case_items_8616(cases: TailValidationValue) -> tuple[tuple[TailValidationValue, TailValidationValue], ...]:
    if isinstance(cases, dict):
        return tuple(cases.items())
    if isinstance(cases, (list, tuple)):
        return tuple(
            (case_value, case_body)
            for item in cases
            if isinstance(item, (list, tuple)) and len(item) == 2
            for case_value, case_body in (item,)
        )
    return ()


def fingerprint_x86_16_tail_validation_boundary(
    project: TailValidationValue, codegen: TailValidationValue, *, mode: str = "live_out"
) -> str:
    """Fingerprint the structured-codegen boundary used for validation caching."""
    if mode not in _TAIL_VALIDATION_MODES:
        raise ValueError(f"Unsupported x86-16 tail validation mode: {mode}")
    # C codegen mutates AST nodes in place between validation boundaries. The
    # expression fingerprint cache is keyed by object identity, so a boundary
    # fingerprint must start from a clean cache just like summary collection.
    _clear_tail_validation_expr_fingerprint_cache_8616(project)
    with contextlib.suppress(Exception):
        codegen._inertia_jcc_register_exprs_by_ins_addr_8616 = None
    root = _codegen_root(codegen)
    previous_active_codegen = getattr(project, "_inertia_tail_validation_active_codegen", None)
    project._inertia_tail_validation_active_codegen = codegen
    # Dynamic angr/codegen compatibility boundary.
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    summary_inventory = callsite_summary_inventory_8616(codegen) or None
    with span("x86_16.tail_validation.boundary.contextual_calls", function=func_addr):
        contextual_call_fingerprints = build_x86_16_contextual_call_fingerprints(
            root,
            project,
            summary_inventory=summary_inventory,
        )
    with span("x86_16.tail_validation.boundary.call_summaries", function=func_addr):
        contextual_call_summaries = _build_contextual_call_summary_map(
            root,
            project,
            summary_inventory,
        )
    with span("x86_16.tail_validation.boundary.contextual_conditions", function=func_addr):
        contextual_condition_fingerprints = build_x86_16_contextual_condition_fingerprints(root, project)
    previous_condition_fingerprints = getattr(
        project,
        "_inertia_tail_validation_contextual_condition_fingerprints",
        None,
    )
    # Dynamic angr/codegen compatibility boundary.
    previous_node_cache = getattr(project, "_inertia_tail_validation_boundary_node_cache_8616", None)
    # Dynamic angr/codegen compatibility boundary.
    previous_snapshot_expr_cache = getattr(
        project,
        "_inertia_tail_validation_snapshot_expr_cache_enabled_8616",
        None,
    )
    project._inertia_tail_validation_contextual_condition_fingerprints = contextual_condition_fingerprints
    project._inertia_tail_validation_boundary_node_cache_8616 = {}
    project._inertia_tail_validation_snapshot_expr_cache_enabled_8616 = True
    try:
        with span("x86_16.tail_validation.boundary.root_fingerprint", function=func_addr):
            root_fingerprint = _node_boundary_fingerprint(
                root,
                project,
                contextual_call_fingerprints,
                contextual_call_summaries,
            )
        payload = {
            # Dynamic angr/codegen compatibility boundary.
            "arch": getattr(getattr(project, "arch", None), "name", None),
            "mode": mode,
            "fingerprint_version": TAIL_VALIDATION_FINGERPRINT_VERSION,
            "root": root_fingerprint,
        }
        descriptor = build_x86_16_validation_cache_descriptor("tail_validation.boundary", payload)
        codegen._inertia_tail_validation_boundary_context_8616 = _TailValidationBoundaryContext8616(
            mode=mode,
            root_id=id(root),
            boundary_fingerprint=descriptor.fingerprint,
            summary_input_generation=tail_validation_summary_input_generation_8616(
                project,
                codegen,
            ),
            contextual_call_fingerprints=contextual_call_fingerprints,
            contextual_call_summaries=contextual_call_summaries,
            contextual_condition_fingerprints=contextual_condition_fingerprints,
        )
    finally:
        if previous_condition_fingerprints is None:
            with contextlib.suppress(Exception):
                delattr(project, "_inertia_tail_validation_contextual_condition_fingerprints")
        else:
            project._inertia_tail_validation_contextual_condition_fingerprints = previous_condition_fingerprints
        if previous_node_cache is None:
            with contextlib.suppress(Exception):
                delattr(project, "_inertia_tail_validation_boundary_node_cache_8616")
        else:
            project._inertia_tail_validation_boundary_node_cache_8616 = previous_node_cache
        if previous_snapshot_expr_cache is None:
            with contextlib.suppress(Exception):
                delattr(project, "_inertia_tail_validation_snapshot_expr_cache_enabled_8616")
        else:
            project._inertia_tail_validation_snapshot_expr_cache_enabled_8616 = previous_snapshot_expr_cache
        if previous_active_codegen is None:
            with contextlib.suppress(Exception):
                delattr(project, "_inertia_tail_validation_active_codegen")
        else:
            project._inertia_tail_validation_active_codegen = previous_active_codegen
    with span("x86_16.tail_validation.boundary.descriptor", function=func_addr):
        return descriptor.fingerprint


def extract_x86_16_tail_validation_snapshot(
    function_info: Mapping[str, TailValidationValue] | None,
) -> dict[str, TailValidationValue]:
    """Extract persisted structuring/postprocess validation stage snapshots."""

    def _impl() -> dict[str, TailValidationValue]:
        stages: dict[str, TailValidationValue] = {}
        if not isinstance(function_info, Mapping):
            return stages
        validation_info = function_info.get("x86_16_tail_validation")
        if not isinstance(validation_info, Mapping):
            return stages
        for stage in ("structuring", "postprocess"):
            entry = validation_info.get(stage)
            if not isinstance(entry, Mapping):
                continue
            status = entry.get("status")
            if not (isinstance(status, str) and status):
                if "changed" in entry:
                    status = "changed" if bool(entry.get("changed", False)) else "stable"
                else:
                    # No "changed" field and no explicit status means the entry
                    # was persisted without classification metadata and should be
                    # treated as unknown rather than silently forcing uncollected.
                    status = "unknown"
            changed_value = bool(entry.get("changed", False))
            if not isinstance(entry.get("changed"), bool) and "changed" not in entry:
                changed_value = False
            stages[stage] = {
                "changed": changed_value,
                "status": status,
                "mode": entry.get("mode"),
                "verdict": entry.get("verdict"),
                "summary_text": entry.get("summary_text"),
            }
            delta = entry.get("delta")
            if isinstance(delta, Mapping):
                stages[stage]["delta"] = dict(delta)
            semantic_failures = normalize_tail_semantic_failures_8616(entry.get("semantic_failures"))
            if semantic_failures:
                stages[stage]["semantic_failures"] = semantic_failures
        return stages

    return _impl()


def x86_16_tail_validation_result_passed(validation: Mapping[str, TailValidationValue] | None) -> bool:
    """Return whether one validation stage is explicitly stable or passed."""
    if not isinstance(validation, Mapping):
        return False
    status = validation.get("status")
    if isinstance(status, str) and status:
        return status.lower() in {"stable", "passed"}
    if "changed" in validation:
        return not bool(validation.get("changed", False))
    return False


def x86_16_tail_validation_snapshot_passed(
    snapshot: Mapping[str, TailValidationValue] | None,
    *,
    expected_stages: Sequence[str] = ("structuring", "postprocess"),
) -> bool:
    """Return whether all expected validation stages in a snapshot passed."""

    def _impl() -> bool:
        if not isinstance(snapshot, Mapping):
            return False
        required_stages = tuple(stage for stage in expected_stages if isinstance(stage, str) and stage)
        if not required_stages:
            return False
        for stage in required_stages:
            entry = snapshot.get(stage)
            if not isinstance(entry, Mapping):
                return False
            status = entry.get("status")
            if isinstance(status, str) and status:
                if status != "stable":
                    return False
                continue
            if bool(entry.get("changed", False)):
                return False
        return True

    return _impl()


def persist_x86_16_tail_validation_snapshot(
    *,
    function_info: MutableMapping[str, TailValidationValue] | None,
    codegen: TailValidationValue,
    stage: str,
    validation: Mapping[str, TailValidationValue],
) -> dict[str, TailValidationValue]:
    """Persist one validation stage snapshot onto function info and codegen."""
    status = validation.get("status")
    if not isinstance(status, str) or not status:
        status = "changed" if bool(validation.get("changed", False)) else "stable"
    snapshot_entry = {
        "changed": bool(validation.get("changed", False)),
        "status": status,
        "mode": validation.get("mode"),
        "verdict": validation.get("verdict"),
        "summary_text": validation.get("summary_text"),
    }
    delta = validation.get("delta")
    if isinstance(delta, Mapping):
        snapshot_entry["delta"] = dict(delta)
    semantic_failures = normalize_tail_semantic_failures_8616(validation.get("semantic_failures"))
    if semantic_failures:
        snapshot_entry["semantic_failures"] = semantic_failures
    if isinstance(function_info, MutableMapping):
        validation_info = function_info.setdefault("x86_16_tail_validation", {})
        if isinstance(validation_info, MutableMapping):
            validation_info[stage] = dict(snapshot_entry)
    if codegen is not None:
        snapshot = getattr(codegen, "_inertia_tail_validation_snapshot", None)
        if not isinstance(snapshot, dict):
            snapshot = {}
            codegen._inertia_tail_validation_snapshot = snapshot
        snapshot[stage] = snapshot_entry
    return snapshot_entry


def check_x86_16_tail_validation_surface_consistency(
    summary: Mapping[str, TailValidationValue],
    surface: Mapping[str, TailValidationValue],
    *,
    scanned: int,
) -> tuple[str, ...]:
    """Return consistency issues between aggregate summary and UI surface."""

    def _stage_summaries() -> dict[str, Mapping[str, TailValidationValue]]:
        structuring = dict(summary.get("structuring", {}) or {})
        postprocess = dict(summary.get("postprocess", {}) or {})
        return {"structuring": structuring, "postprocess": postprocess}

    def _stage_rows() -> dict[str, Mapping[str, TailValidationValue]]:
        rows: dict[str, Mapping[str, TailValidationValue]] = {}
        for row in surface.get("stage_rows", ()) or ():
            if not isinstance(row, Mapping):
                continue
            stage_name = row.get("stage")
            if isinstance(stage_name, str):
                rows[stage_name] = row
        return rows

    def _summary_total(stage_summaries: dict[str, Mapping[str, TailValidationValue]], key: str) -> int:
        return sum(int(stage.get(key, 0) or 0) for stage in stage_summaries.values())

    def _scalar_checks(stage_summaries: dict[str, Mapping[str, TailValidationValue]]) -> tuple[tuple[str, int], ...]:
        return (
            ("changed_stage_total", _summary_total(stage_summaries, "changed_count")),
            ("missing_stage_total", _summary_total(stage_summaries, "missing_count")),
            ("unknown_stage_total", _summary_total(stage_summaries, "unknown_count")),
            ("coverage_count", _summary_total(stage_summaries, "coverage_count")),
            ("changed_function_count", int(summary.get("changed_function_count", 0) or 0)),
            ("passed_function_count", int(summary.get("passed_function_count", 0) or 0)),
            ("unknown_function_count", int(summary.get("unknown_function_count", 0) or 0)),
            ("uncollected_function_count", int(summary.get("uncollected_function_count", 0) or 0)),
        )

    def _record_scalar_issues(issues: list[str], checks: Sequence[tuple[str, int]]) -> None:
        for key, expected in checks:
            actual = int(surface.get(key, 0) or 0)
            if actual != expected:
                issues.append(f"{key}: surface={actual} summary={expected}")

    def _record_stage_row_issues(
        issues: list[str],
        stage_summaries: dict[str, Mapping[str, TailValidationValue]],
        stage_rows: dict[str, Mapping[str, TailValidationValue]],
    ) -> None:
        for stage_name, stage_summary in stage_summaries.items():
            row = stage_rows.get(stage_name)
            if not isinstance(row, Mapping):
                issues.append(f"{stage_name}: missing stage row")
                continue
            for key in ("changed_count", "stable_count", "unknown_count", "missing_count", "coverage_count"):
                actual = int(row.get(key, 0) or 0)
                expected = int(stage_summary.get(key, 0) or 0)
                if actual != expected:
                    issues.append(f"{stage_name}.{key}: surface={actual} summary={expected}")

    issues: list[str] = []
    scanned_count = max(int(scanned or 0), 0)
    stage_summaries = _stage_summaries()
    stage_rows = _stage_rows()
    _record_scalar_issues(issues, _scalar_checks(stage_summaries))
    if dict(surface.get("function_status_counts", {}) or {}) != dict(summary.get("function_status_counts", {}) or {}):
        issues.append("function_status_counts mismatch")
    if len(surface.get("function_statuses", ()) or ()) != scanned_count:
        issues.append(
            f"function_statuses: surface={len(surface.get('function_statuses', ()) or ())} scanned={scanned_count}"
        )
    _record_stage_row_issues(issues, stage_summaries, stage_rows)
    return tuple(issues)


def build_x86_16_tail_validation_surface(
    summary: Mapping[str, TailValidationValue], *, scanned: int
) -> dict[str, TailValidationValue]:
    """Build a human-facing aggregate tail-validation surface."""

    def _impl() -> dict[str, TailValidationValue]:
        scanned_count = max(int(scanned or 0), 0)
        severity = str(summary.get("severity", "uncollected"))
        changed_function_count = int(summary.get("changed_function_count", 0) or 0)
        structuring = dict(summary.get("structuring", {}) or {})
        postprocess = dict(summary.get("postprocess", {}) or {})
        changed_functions = _boundary_list_8616(summary.get("changed_functions", []) or [])
        function_status_counts = dict(summary.get("function_status_counts", {}) or {})
        function_statuses = _boundary_list_8616(summary.get("function_statuses", []) or [])
        uncollected_functions = _boundary_list_8616(summary.get("uncollected_functions", []) or [])
        unknown_functions = _boundary_list_8616(summary.get("unknown_functions", []) or [])
        stage_rows, total_changed, total_missing, total_unknown, total_coverage = (
            _build_tail_validation_stage_rows_8616(
                scanned_count=scanned_count,
                structuring=structuring,
                postprocess=postprocess,
            )
        )

        stage_hotspots = [
            {
                "stage": row["stage"],
                "changed_count": row["changed_count"],
                "changed_rate": row["changed_rate"],
                "top_verdicts": row["top_verdicts"],
            }
            for row in sorted(stage_rows, key=lambda item: (-item["changed_count"], item["stage"]))
            if row["changed_count"] > 0
        ]
        top_changed_verdicts = []
        verdict_counter: Counter[str] = Counter()
        for row in stage_rows:
            for item in row["top_verdicts"]:
                verdict = item.get("verdict")
                count = item.get("count")
                if isinstance(verdict, str) and verdict and isinstance(count, int):
                    verdict_counter[verdict] += count
        top_changed_verdicts = [
            {"verdict": verdict, "count": count}
            for verdict, count in sorted(verdict_counter.items(), key=lambda item: (-item[1], item[0]))
        ]
        changed_function_rows: dict[
            tuple[TailValidationValue, TailValidationValue, TailValidationValue], dict[str, TailValidationValue]
        ] = {}
        for item in changed_functions:
            if not isinstance(item, Mapping):
                continue
            key = (
                item.get("cod_file"),
                item.get("proc_name"),
                item.get("proc_kind"),
            )
            row = changed_function_rows.setdefault(
                key,
                {
                    "cod_file": item.get("cod_file"),
                    "proc_name": item.get("proc_name"),
                    "proc_kind": item.get("proc_kind"),
                    "stages": [],
                    "verdicts": [],
                    "changed_stage_count": 0,
                },
            )
            stage = item.get("stage")
            verdict = item.get("verdict")
            if isinstance(stage, str) and stage and stage not in row["stages"]:
                row["stages"].append(stage)
            if isinstance(verdict, str) and verdict and verdict not in row["verdicts"]:
                row["verdicts"].append(verdict)
            row["changed_stage_count"] = len(row["stages"])
        top_changed_functions = sorted(
            (
                {
                    **row,
                    "stages": tuple(sorted(row["stages"])),
                    "verdicts": tuple(row["verdicts"]),
                }
                for row in changed_function_rows.values()
            ),
            key=lambda item: (
                -int(item.get("changed_stage_count", 0) or 0),
                "" if isinstance(item.get("cod_file"), str) else "~",
                item.get("cod_file"),
                item.get("proc_name"),
                item.get("proc_kind"),
            ),
        )
        changed_families = _tail_validation_changed_family_summary(changed_functions)
        top_uncollected_functions = sorted(
            (dict(item) for item in uncollected_functions if isinstance(item, Mapping)),
            key=_tail_validation_function_sort_key,
        )
        top_unknown_functions = sorted(
            (dict(item) for item in unknown_functions if isinstance(item, Mapping)),
            key=_tail_validation_function_sort_key,
        )

        merge_gate = severity == "clean"
        headline = _tail_validation_headline_8616(severity, scanned_count, changed_function_count)

        surface = {
            "headline": headline,
            "severity": severity,
            "merge_gate": merge_gate,
            "changed_function_count": changed_function_count,
            "changed_stage_total": total_changed,
            "coverage_count": total_coverage,
            "missing_stage_total": total_missing,
            "unknown_stage_total": total_unknown,
            "function_status_counts": function_status_counts,
            "function_statuses": function_statuses,
            "passed_function_count": int(summary.get("passed_function_count", 0) or 0),
            "unknown_function_count": int(summary.get("unknown_function_count", 0) or 0),
            "uncollected_function_count": int(summary.get("uncollected_function_count", 0) or 0),
            "top_unknown_functions": top_unknown_functions,
            "top_uncollected_functions": top_uncollected_functions,
            "stage_rows": stage_rows,
            "stage_hotspots": stage_hotspots,
            "top_changed_verdicts": top_changed_verdicts,
            "top_changed_functions": top_changed_functions,
            "changed_families": changed_families,
            "changed_family_routing": build_tail_validation_family_routing(changed_families),
        }
        surface["consistency_issues"] = check_x86_16_tail_validation_surface_consistency(
            summary,
            surface,
            scanned=scanned_count,
        )
        return surface

    return _impl()


def _normalized_tail_validation_baseline_entries(
    entries: Sequence[Mapping[str, TailValidationValue]] | None,
) -> list[dict[str, str]]:
    normalized: set[tuple[str, str, str, str, str]] = set()
    for item in entries or ():
        if not isinstance(item, Mapping):
            continue
        cod_file = item.get("cod_file")
        proc_name = item.get("proc_name")
        proc_kind = item.get("proc_kind")
        stage = item.get("stage")
        verdict = item.get("verdict")
        if not all(isinstance(value, str) and value for value in (cod_file, proc_name, proc_kind, stage, verdict)):
            continue
        assert isinstance(cod_file, str)
        assert isinstance(proc_name, str)
        assert isinstance(proc_kind, str)
        assert isinstance(stage, str)
        assert isinstance(verdict, str)
        normalized.add((cod_file, proc_name, proc_kind, stage, verdict))
    return [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(normalized)
    ]


def build_x86_16_tail_validation_baseline(summary: Mapping[str, TailValidationValue]) -> dict[str, TailValidationValue]:
    """Build a baseline payload from currently changed validation entries."""
    normalized_entries = _normalized_tail_validation_baseline_entries(summary.get("changed_functions"))
    return {
        "version": 1,
        "entries": normalized_entries,
        "entry_count": len(normalized_entries),
    }


def compare_x86_16_tail_validation_baseline(
    summary: Mapping[str, TailValidationValue],
    baseline: Mapping[str, TailValidationValue] | None,
) -> dict[str, TailValidationValue]:
    """Compare current changed validation entries with a stored baseline."""
    if not isinstance(baseline, Mapping):
        return {"status": "unavailable", "unexpected": [], "missing": [], "matches": []}

    current_entries = _normalized_tail_validation_baseline_entries(summary.get("changed_functions"))
    baseline_entries = _normalized_tail_validation_baseline_entries(baseline.get("entries"))
    current_set = {
        (
            item["cod_file"],
            item["proc_name"],
            item["proc_kind"],
            item["stage"],
            item["verdict"],
        )
        for item in current_entries
    }
    baseline_set = {
        (
            item["cod_file"],
            item["proc_name"],
            item["proc_kind"],
            item["stage"],
            item["verdict"],
        )
        for item in baseline_entries
    }
    unexpected = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(current_set - baseline_set)
    ]
    missing = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(baseline_set - current_set)
    ]
    matches = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(current_set & baseline_set)
    ]
    if unexpected:
        status = "regressed"
    elif missing:
        status = "improved"
    else:
        status = "matches_baseline"
    return {
        "status": status,
        "unexpected": unexpected,
        "missing": missing,
        "matches": matches,
    }


def annotate_x86_16_tail_validation_surface_with_baseline(
    surface: Mapping[str, TailValidationValue],
    comparison: Mapping[str, TailValidationValue] | None,
) -> dict[str, TailValidationValue]:
    """Attach baseline comparison fields to an existing validation surface."""
    annotated = dict(surface)
    if not isinstance(comparison, Mapping):
        return annotated
    status = comparison.get("status")
    if not isinstance(status, str) or not status:
        return annotated
    unexpected = _boundary_list_8616(comparison.get("unexpected", []) or [])
    missing = _boundary_list_8616(comparison.get("missing", []) or [])
    annotated["baseline_status"] = status
    annotated["baseline_unexpected_count"] = len(unexpected)
    annotated["baseline_missing_count"] = len(missing)
    annotated["baseline_unexpected"] = unexpected
    annotated["baseline_missing"] = missing
    return annotated


def build_x86_16_tail_validation_aggregate(
    records: Sequence[Mapping[str, TailValidationValue]],
    *,
    scanned: int,
) -> dict[str, TailValidationValue]:
    """Build cached aggregate tail-validation summary and surface records."""
    normalized_records = _records_with_uncollected_placeholders(records, scanned=scanned)
    descriptor = build_x86_16_validation_cache_descriptor(
        "tail_validation.aggregate",
        {
            "records_fingerprint": _tail_validation_records_fingerprint(records, scanned=scanned),
            "scanned": int(scanned or 0),
        },
    )
    cached = resolve_x86_16_validation_cached_artifact(
        cache=_TAIL_VALIDATION_AGGREGATE_CACHE,
        descriptor=descriptor,
        build=lambda: {
            "summary": summarize_x86_16_tail_validation_records(normalized_records),
            "surface": None,
        },
        clone_on_hit=_clone_tail_validation_aggregate_payload,
        store_value=_clone_tail_validation_aggregate_payload,
    )
    payload = dict(cached["value"])
    if payload.get("surface") is None:
        payload["surface"] = build_x86_16_tail_validation_surface(payload["summary"], scanned=scanned)
        _TAIL_VALIDATION_AGGREGATE_CACHE[descriptor.cache_key] = {
            "summary": dict(payload["summary"]),
            "surface": dict(payload["surface"]),
        }
    return {
        "cache_key": cached["cache_key"],
        "cache_hit": bool(cached["cache_hit"]),
        "summary": payload["summary"],
        "surface": payload["surface"],
    }


def summarize_x86_16_tail_validation_records(
    records: Sequence[Mapping[str, TailValidationValue]],
) -> dict[str, TailValidationValue]:
    """Summarize per-function tail-validation records into aggregate counts."""
    structuring = _tail_validation_stage_summary(records, "structuring")
    postprocess = _tail_validation_stage_summary(records, "postprocess")
    function_accounting = _tail_validation_function_accounting(records)
    changed_functions = sorted(
        structuring["changed_functions"] + postprocess["changed_functions"],
        key=lambda item: (
            "" if isinstance(item.get("cod_file"), str) else "~",
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
            item.get("verdict"),
        ),
    )
    changed_function_count = len(changed_functions)
    changed_families = _tail_validation_changed_family_summary(changed_functions)
    coverage_count = int(structuring["coverage_count"]) + int(postprocess["coverage_count"])
    missing_count = int(structuring["missing_count"]) + int(postprocess["missing_count"])
    unknown_count = int(structuring["unknown_count"]) + int(postprocess["unknown_count"])
    severity = "clean"
    if changed_function_count > 0:
        severity = "changed"
    elif unknown_count > 0:
        severity = "unknown"
    elif coverage_count == 0 and missing_count > 0:
        severity = "uncollected"
    elif missing_count > 0:
        severity = "partial"
    return {
        "severity": severity,
        "changed_function_count": changed_function_count,
        "coverage_count": coverage_count,
        "missing_count": missing_count,
        "unknown_count": unknown_count,
        "structuring": structuring,
        "postprocess": postprocess,
        "changed_functions": changed_functions,
        "changed_families": changed_families,
        "function_status_counts": function_accounting["function_status_counts"],
        "function_statuses": function_accounting["function_statuses"],
        "passed_functions": function_accounting["passed_functions"],
        "unknown_functions": function_accounting["unknown_functions"],
        "uncollected_functions": function_accounting["uncollected_functions"],
        "passed_function_count": len(function_accounting["passed_functions"]),
        "unknown_function_count": len(function_accounting["unknown_functions"]),
        "uncollected_function_count": len(function_accounting["uncollected_functions"]),
    }


def _record_expr_locations(
    node: TailValidationValue, project: TailValidationValue, observed_locations: StackObservedLocations8616
) -> None:
    """Retain direct address exposure separately from ordinary value reads."""
    if node is None:
        return
    if isinstance(node, CVariable):
        observed_locations.add(_location_fingerprint(node, project))
        return
    if isinstance(node, CTypeCast):
        _record_expr_locations(node.expr, project, observed_locations)
        return
    if isinstance(node, CUnaryOp):
        observed_locations.add(_location_fingerprint(node, project))
        if node.op == "Reference":
            observed_locations.address_exposed_locations.add(_location_fingerprint(node.operand, project))
        _record_expr_locations(node.operand, project, observed_locations)
        return
    if isinstance(node, CBinaryOp):
        _record_expr_locations(node.lhs, project, observed_locations)
        _record_expr_locations(node.rhs, project, observed_locations)
        return
    if isinstance(node, CFunctionCall):
        if _is_runtime_segment_helper_call_8616(node):
            return
        for arg in node.args or ():
            _record_expr_locations(arg, project, observed_locations)
        return


def _is_control_flow_node(node: TailValidationValue) -> bool:
    return isinstance(
        node, (CIfElse, CIfBreak, CWhileLoop, CDoWhileLoop, CForLoop, CSwitchCase, CGoto, CBreak, CContinue, CReturn)
    )


def _collect_observed_locations(
    root: TailValidationValue,
    project: TailValidationValue,
    mode: str,
    contextual_conditions: Mapping[int, str] | None = None,
) -> StackObservedLocations8616:
    """Collect observable reads and explicit address exposure in one summary."""
    observed_locations = StackObservedLocations8616()
    if mode != "live_out":
        return observed_locations

    def _record_control_condition_locations(node: TailValidationValue) -> None:
        def _record_contextual_stack_locations(condition: TailValidationValue) -> None:
            if contextual_conditions is None:
                return
            fingerprint = contextual_conditions.get(id(condition))
            if fingerprint is not None:
                observed_locations.update(_STACK_SLOT_WRITE_TOKEN_RE_8616.findall(fingerprint))

        # Dynamic angr/codegen compatibility boundary.
        condition = getattr(node, "condition", None)
        if condition is not None:
            _record_expr_locations(condition, project, observed_locations)
            _record_contextual_stack_locations(condition)
        # Dynamic angr/codegen compatibility boundary.
        cond = getattr(node, "cond", None)
        if cond is not None and cond is not condition:
            _record_expr_locations(cond, project, observed_locations)
            _record_contextual_stack_locations(cond)
        # Dynamic angr/codegen compatibility boundary.
        for pair in _boundary_tuple_8616(getattr(node, "condition_and_nodes", ()) or ()):
            if not isinstance(pair, tuple) or not pair:
                continue
            _record_expr_locations(pair[0], project, observed_locations)
            _record_contextual_stack_locations(pair[0])

    return_value_unobserved = _active_codegen_return_value_is_unobserved_8616(project)
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, (CIfElse, CIfBreak, CWhileLoop, CDoWhileLoop, CForLoop, CSwitchCase)):
            _record_control_condition_locations(node)
        if isinstance(node, CFunctionCall):
            if _is_runtime_segment_helper_call_8616(node):
                continue
            for arg in node.args or ():
                _record_expr_locations(arg, project, observed_locations)
        if isinstance(node, CReturn):
            retval = node.retval
            if return_value_unobserved:
                if isinstance(retval, CFunctionCall) and not _is_runtime_segment_helper_call_8616(retval):
                    for arg in retval.args or ():
                        _record_expr_locations(arg, project, observed_locations)
                continue
            _record_expr_locations(retval, project, observed_locations)
    return observed_locations


def _iter_observable_call_nodes_for_validation_8616(
    node: TailValidationValue, _seen: set[int] | None = None
) -> TailValidationValue:
    """Yield every observable call, including calls nested in call arguments."""

    def _impl() -> TailValidationValue:
        if node is None:
            return
        seen = _seen
        if seen is None:
            seen = set()
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        if isinstance(node, CStatements):
            for stmt in node.statements or ():
                yield from _iter_observable_call_nodes_for_validation_8616(stmt, seen)
            return
        if isinstance(node, CFunctionCall):
            if not _is_runtime_segment_helper_call_8616(node) and not _is_structured_c_intrinsic_call_8616(node):
                yield node
            for arg in _boundary_tuple_8616(node.args or ()):
                yield from _iter_observable_call_nodes_for_validation_8616(arg, seen)
            return
        if isinstance(node, CAssignment):
            rhs = node.rhs
            if (
                isinstance(rhs, CFunctionCall)
                and not _is_runtime_segment_helper_call_8616(rhs)
                and not _is_structured_c_intrinsic_call_8616(rhs)
            ) or rhs is not None:
                yield from _iter_observable_call_nodes_for_validation_8616(rhs, seen)
            return
        for attr in ("retval", "condition", "cond", "expr", "lhs", "rhs", "operand"):
            child = getattr(node, attr, None)
            if (
                isinstance(child, CFunctionCall)
                and not _is_runtime_segment_helper_call_8616(child)
                and not _is_structured_c_intrinsic_call_8616(child)
            ) or child is not None:
                yield from _iter_observable_call_nodes_for_validation_8616(child, seen)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                if (
                    isinstance(cond, CFunctionCall)
                    and not _is_runtime_segment_helper_call_8616(cond)
                    and not _is_structured_c_intrinsic_call_8616(cond)
                ) or cond is not None:
                    yield from _iter_observable_call_nodes_for_validation_8616(cond, seen)
                yield from _iter_observable_call_nodes_for_validation_8616(body, seen)
        # Dynamic angr/codegen compatibility boundary.
        for arg in _boundary_tuple_8616(getattr(node, "args", ()) or ()):
            yield from _iter_observable_call_nodes_for_validation_8616(arg, seen)
        else_node = getattr(node, "else_node", None)
        if else_node is not None:
            yield from _iter_observable_call_nodes_for_validation_8616(else_node, seen)
        for attr in ("body", "initializer", "iterator"):
            child = getattr(node, attr, None)
            if child is not None:
                yield from _iter_observable_call_nodes_for_validation_8616(child, seen)

    return _impl()


def _summary_attr_8616(summary_entry: TailValidationValue, attr: str) -> TailValidationValue:
    """Read an explicit field from a contextual callsite summary contract."""
    if summary_entry is None:
        return None
    if isinstance(summary_entry, Mapping):
        if attr in summary_entry:
            return summary_entry.get(attr)
        nested = summary_entry.get("summary")
        if nested is not None:
            return _summary_attr_8616(nested, attr)
        return None
    if not isinstance(summary_entry, CallsiteSummary8616):
        return None
    if attr == "stack_probe_helper":
        return summary_entry.stack_probe_helper
    if attr == "target_addr":
        return summary_entry.target_addr
    if attr == "callsite_addr":
        return summary_entry.callsite_addr
    if attr == "return_register":
        return summary_entry.return_register
    if attr == "return_used":
        return summary_entry.return_used
    if attr == "return_use_kind":
        return summary_entry.return_use_kind.value if summary_entry.return_use_kind is not None else None
    return None


def _summary_proves_function_return_call_8616(summary_entry: TailValidationValue) -> bool:
    return (
        _summary_attr_8616(summary_entry, "return_register") == "ax"
        and _summary_attr_8616(summary_entry, "return_used") is True
        and _summary_attr_8616(summary_entry, "return_use_kind") == "function_return"
    )


def _standalone_call_from_tail_statement_8616(stmt: TailValidationValue) -> CFunctionCall | None:
    if isinstance(stmt, CFunctionCall):
        return stmt
    # Dynamic angr/codegen compatibility boundary.
    expr = getattr(stmt, "expr", None)
    if isinstance(expr, CFunctionCall):
        return expr
    # Dynamic angr/codegen compatibility boundary.
    nested = getattr(stmt, "statements", None)
    if isinstance(nested, (list, tuple)) and nested:
        return _standalone_call_from_tail_statement_8616(nested[-1])
    return None


def _split_tail_return_call_fingerprints_8616(
    root: TailValidationValue,
    project: TailValidationValue,
    contextual_call_summaries: Mapping[int, TailValidationValue],
) -> tuple[str, ...] | None:
    split_return_fingerprints: list[str] = []
    unaccounted_bare_returns = 0

    def _record_statement_list(statements: TailValidationValue) -> None:
        nonlocal unaccounted_bare_returns
        statement_list = list(statements or ())
        for idx, stmt in enumerate(statement_list):
            candidate = stmt
            # Dynamic angr/codegen compatibility boundary.
            nested = getattr(candidate, "statements", None)
            if isinstance(nested, (list, tuple)) and len(nested) == 1:
                candidate = nested[0]
            # Dynamic angr/codegen compatibility boundary.
            if isinstance(candidate, CReturn) and getattr(candidate, "retval", None) is None:
                previous_call = None
                scan_idx = idx - 1
                while scan_idx >= 0 and previous_call is None:
                    previous_call = _standalone_call_from_tail_statement_8616(statement_list[scan_idx])
                    if previous_call is None and statement_list[scan_idx].__class__.__name__ != "CStatements":
                        break
                    scan_idx -= 1
                summary = contextual_call_summaries.get(id(previous_call)) if previous_call is not None else None
                if previous_call is not None and _summary_proves_function_return_call_8616(summary):
                    split_return_fingerprints.append(_expr_fingerprint(previous_call, project))
                else:
                    unaccounted_bare_returns += 1
            # Dynamic angr/codegen compatibility boundary.
            child_statements = getattr(stmt, "statements", None)
            if isinstance(child_statements, (list, tuple)):
                _record_statement_list(child_statements)
            for attr in ("body", "else_node", "initializer", "iterator"):
                # Dynamic angr/codegen compatibility boundary.
                child = getattr(stmt, attr, None)
                # Dynamic angr/codegen compatibility boundary.
                child_statements = getattr(child, "statements", None)
                if isinstance(child_statements, (list, tuple)):
                    _record_statement_list(child_statements)
            if isinstance(stmt, CIfElse):
                # Dynamic angr/codegen compatibility boundary.
                for _cond, child in _boundary_tuple_8616(stmt.condition_and_nodes or ()):
                    # Dynamic angr/codegen compatibility boundary.
                    child_statements = getattr(child, "statements", None)
                    if isinstance(child_statements, (list, tuple)):
                        _record_statement_list(child_statements)

    # Dynamic angr/codegen compatibility boundary.
    root_statements = getattr(root, "statements", None)
    if isinstance(root_statements, (list, tuple)):
        _record_statement_list(root_statements)
    else:
        _record_statement_list((root,))
    if unaccounted_bare_returns:
        return None
    return tuple(dict.fromkeys(split_return_fingerprints))


def _build_contextual_call_summary_map(
    root: TailValidationValue,
    project: TailValidationValue,
    summary_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> dict[int, TailValidationValue]:
    """Map each observable call to the strongest available callsite summary.

    Exact codegen mappings are preferred, but they may be partial after an AST
    node is cloned or regenerated.  Unmatched calls must still be paired from
    callsite and target evidence; returning a partial identity map shifts the
    positional fingerprint fallback when a stack-probe call has no C node.
    """

    def _impl() -> dict[int, TailValidationValue]:
        if root is None:
            return {}
        summary_map: dict[int, TailValidationValue] = {}
        call_nodes = list(_iter_observable_call_nodes_for_validation_8616(root))
        # Dynamic angr/codegen compatibility boundary.
        codegen = getattr(root, "codegen", None)
        # Dynamic angr/codegen compatibility boundary.
        existing_summaries = getattr(codegen, "_inertia_callsite_summaries", None)
        if isinstance(existing_summaries, Mapping):
            for node in call_nodes:
                summary = existing_summaries.get(id(node))
                if summary is None:
                    continue
                target_addr = _call_summary_target_addr_8616(project, summary)
                if _target_addr_is_stack_probe_helper_8616(project, target_addr) and (
                    _call_node_has_nonprobe_target_evidence_8616(project, node)
                ):
                    continue
                callsite_addr = _summary_attr_8616(summary, "callsite_addr")
                if isinstance(summary, Mapping):
                    mapped_summary = dict(summary)
                    if isinstance(target_addr, int):
                        mapped_summary["target_addr"] = target_addr
                    if isinstance(callsite_addr, int):
                        mapped_summary["callsite_addr"] = callsite_addr
                    summary_map[id(node)] = mapped_summary
                else:
                    mapped_summary = {"summary": summary}
                    if isinstance(target_addr, int):
                        mapped_summary["target_addr"] = target_addr
                    if isinstance(callsite_addr, int):
                        mapped_summary["callsite_addr"] = callsite_addr
                    summary_map[id(node)] = mapped_summary
        function = _function_for_call_context_8616(root, project)
        if function is None:
            return summary_map
        ordered_pairs = _ordered_contextual_call_pairs_8616(
            root,
            project,
            summary_inventory,
        )
        for node, callsite_addr in ordered_pairs:
            if id(node) in summary_map:
                continue
            summary = (
                summary_inventory.get(callsite_addr)
                if summary_inventory is not None
                else summarize_x86_16_callsite(function, callsite_addr)
            )
            target_addr = _call_summary_target_addr_8616(project, summary)
            if summary is not None and target_addr is not None:
                if isinstance(summary, Mapping):
                    summary_map[id(node)] = {**summary, "target_addr": target_addr, "callsite_addr": callsite_addr}
                else:
                    summary_map[id(node)] = {
                        "target_addr": target_addr,
                        "callsite_addr": callsite_addr,
                        "summary": summary,
                    }
        if summary_map:
            return summary_map
        if not call_nodes:
            return {}
        direct_targets = _collect_direct_capstone_call_targets_for_function(function)
        callsite_addrs = _function_callsite_addrs_for_validation_8616(function)
        for idx, (node, target_addr) in enumerate(zip(call_nodes, direct_targets, strict=False)):
            normalized_target = _normalized_call_target_addr_8616(project, target_addr)
            if isinstance(normalized_target, int):
                summary_map[id(node)] = {"target_addr": normalized_target}
                if idx < len(callsite_addrs):
                    summary_map[id(node)]["callsite_addr"] = callsite_addrs[idx]
        return summary_map

    return _impl()


def _call_from_statement_8616(stmt: TailValidationValue) -> CFunctionCall | None:
    """Return a direct call payload from equivalent structured statement wrappers."""
    if isinstance(stmt, CFunctionCall):
        return stmt
    if isinstance(stmt, CAssignment):
        rhs = stmt.rhs
        if isinstance(rhs, CFunctionCall):
            return rhs
    expr = getattr(stmt, "expr", None)
    if isinstance(expr, CFunctionCall):
        return expr
    nested_statements = getattr(stmt, "statements", None)
    if isinstance(nested_statements, (list, tuple)) and len(nested_statements) == 1:
        return _call_from_statement_8616(nested_statements[0])
    return None


def _assignment_lhs_rhs_8616(
    node: TailValidationValue,
) -> tuple[TailValidationValue | None, TailValidationValue | None]:
    lhs = getattr(node, "lhs", None)
    rhs = getattr(node, "rhs", None)
    if lhs is None and hasattr(node, "dst"):
        lhs = getattr(node, "dst", None)
        rhs = getattr(node, "src", None)
    return lhs, rhs


def _iter_assignment_nodes_8616(node: TailValidationValue) -> Iterator[TailValidationValue]:
    if isinstance(node, CAssignment) or node.__class__.__name__.endswith("Assignment"):
        yield node
    nested_statements = getattr(node, "statements", None)
    if isinstance(nested_statements, (list, tuple)):
        for nested in nested_statements:
            yield from _iter_assignment_nodes_8616(nested)


def _assignment_lhs_writes_memory_8616(lhs: TailValidationValue, project: TailValidationValue) -> bool:
    if lhs is None:
        return False
    if _dirty_expression_is_temporary_lvalue_8616(lhs):
        return False
    location = _location_fingerprint(
        lhs,
        project,
        resolve_copy_alias=False,
    )
    location_text = str(location)
    return location_text.startswith(("stack:", "global:", "deref:"))


def _dirty_expression_is_temporary_lvalue_8616(lhs: TailValidationValue) -> bool:
    """Return whether an unresolved angr lvalue has explicit temporary storage."""
    if not isinstance(lhs, CDirtyExpression):
        return False
    # Dynamic angr/AIL boundary: CDirtyExpression wraps a VirtualVariable.
    category = getattr(lhs.dirty, "category", None)
    return category is VirtualVariableCategory.TMP


def _dirty_expression_write_width_bytes_8616(lhs: TailValidationValue) -> int:
    """Return exact byte width carried by an unresolved angr virtual value."""
    if not isinstance(lhs, CDirtyExpression):
        return 0
    dirty = lhs.dirty
    # Dynamic angr/AIL boundary: VirtualVariable exposes byte and bit widths.
    size = getattr(dirty, "size", None)
    bits = getattr(dirty, "bits", None)
    if not isinstance(size, int) or not isinstance(bits, int):
        return 0
    if size <= 0 or bits != size * 8:
        return 0
    return size


def _assignment_write_locations_8616(
    lhs: TailValidationValue,
    project: TailValidationValue,
) -> tuple[str, ...]:
    """Return byte-precise locations for a fixed-width direct memory write."""
    if _dirty_expression_is_temporary_lvalue_8616(lhs):
        return ()
    indexed_locations = _indexed_global_write_location_fingerprints_8616(lhs, project)
    if indexed_locations:
        return tuple(str(location) for location in indexed_locations)
    location = _location_fingerprint(lhs, project, resolve_copy_alias=False)
    if not location.startswith("global:"):
        return (location,)
    width = 0
    if isinstance(lhs, CVariable) and isinstance(lhs.variable, SimMemoryVariable):
        width = int(lhs.variable.size or 0)
    elif isinstance(lhs, CUnaryOp) and lhs.op == "Dereference":
        width = _target_abi_type_size_bytes_8616(lhs.type, project, default=0)
    elif isinstance(lhs, CTypeCast):
        width = _target_abi_type_size_bytes_8616(lhs.dst_type, project, default=0)
    elif isinstance(lhs, CDirtyExpression):
        width = _dirty_expression_write_width_bytes_8616(lhs)
    base = _tail_validation_ds_global_write_offset_8616(location)
    if not isinstance(base, int) or width <= 1 or width > 8:
        return (location,)
    return tuple(f"global:{base + byte_offset:#x}" for byte_offset in range(width))


def _contains_call_8616(node: TailValidationValue) -> bool:
    if isinstance(node, CFunctionCall):
        return True
    expr = getattr(node, "expr", None)
    if isinstance(expr, CFunctionCall):
        return True
    return any(isinstance(child, CFunctionCall) for child in _iter_c_nodes_deep_8616(node))


def _is_stack_carrier_temp_assignment_8616(stmt: TailValidationValue) -> bool:
    def _impl() -> bool:
        candidates = list(_iter_assignment_nodes_8616(stmt))
        if not candidates:
            return False
        lhs, rhs = _assignment_lhs_rhs_8616(candidates[-1])
        if lhs is None or rhs is None:
            return False
        variable = getattr(lhs, "variable", None)
        name = getattr(variable, "name", None) or getattr(lhs, "name", None)
        if not isinstance(name, str) or not (
            name.startswith(("vvar_", "ir_", "tmp_"))
        ):
            return False
        rhs_node = rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        if isinstance(rhs_node, CUnaryOp) and rhs_node.op in {"Reference", "Dereference"}:
            return True
        return isinstance(rhs_node, CBinaryOp) and rhs_node.op in {
            "Add",
            "Sub",
            "Mul",
            "Shl",
            "Shr",
            "And",
            "Or",
            "Xor",
        }

    return _impl()


def _is_value_only_assignment_8616(stmt: TailValidationValue, project: TailValidationValue) -> bool:
    candidates = list(_iter_assignment_nodes_8616(stmt))
    if not candidates:
        return False
    lhs, _rhs = _assignment_lhs_rhs_8616(candidates[-1])
    return not _assignment_lhs_writes_memory_8616(lhs, project)


def _expr_mentions_temp_carrier_8616(expr: TailValidationValue) -> bool:
    def _impl() -> bool:
        if expr is None:
            return False
        nodes = (expr, *_iter_c_nodes_deep_8616(expr))
        for node in nodes:
            variable = getattr(node, "variable", None)
            name = getattr(variable, "name", None) or getattr(node, "name", None)
            if isinstance(name, str) and (
                name.startswith(("vvar_", "ir_", "tmp_"))
            ):
                return True
            if node.__class__.__name__ == "CDirtyExpression":
                dirty = getattr(node, "dirty", None)
                dirty_name = getattr(dirty, "name", None)
                if isinstance(dirty_name, str) and (
                    dirty_name.startswith(("vvar_", "ir_", "tmp_"))
                ):
                    return True
        return False

    return _impl()


def _looks_like_ss_segment_store_8616(lhs: TailValidationValue, project: TailValidationValue) -> bool:
    while isinstance(lhs, CTypeCast):
        lhs = lhs.expr
    if not isinstance(lhs, CUnaryOp) or lhs.op != "Dereference":
        return False
    location = _location_fingerprint(lhs, project)
    if location.startswith("deref:ss:"):
        return True
    return "reg:ss" in _expr_fingerprint(lhs.operand, project)


def _is_dynamic_dirty_ss_location_8616(location: str) -> bool:
    if not isinstance(location, str) or not location.startswith("deref:"):
        return False
    if "reg:ss" in location and re.search(r"virtual:(?:vvar|tmp|ir)_\d+", location):
        return True
    if "reg:ss" in location and ("CDirtyExpression" in location or "CFakeVariable" in location):
        return True
    dynamic_frame_atom = r"(?:CDirtyExpression|CFakeVariable|virtual:unknown|Reference\(CIndexedVariable\))"
    if re.fullmatch(rf"deref:Add\(Mul\(reg:ss,const:16\),{dynamic_frame_atom},const:-?[0-9]+\)", location):
        return True
    if "CDirtyExpression" not in location and "CFakeVariable" not in location:
        return False
    # MS C helper-focused slices can leave the internal frame-store address as
    # (dirty_segment * 16) + dirty_offset - K instead of preserving literal SS.
    # In live-out mode that is still a dynamic stack-frame artifact, not an
    # observable segmented-memory write.
    return bool(
        re.fullmatch(
            r"deref:Add\(Mul\((?:CDirtyExpression|CFakeVariable),const:16\),(?:CDirtyExpression|CFakeVariable),const:-[0-9]+\)",
            location,
        )
    )


def _lhs_aliases_dynamic_stack_frame_8616(lhs: TailValidationValue, project: TailValidationValue) -> bool:
    aliased_location = _location_fingerprint(lhs, project, resolve_copy_alias=True)
    if aliased_location.startswith(("stack:", "stack_slot:", "unresolved_stack_carrier:")):
        return True
    return _is_dynamic_dirty_ss_location_8616(aliased_location)


def _canonicalize_segmented_write_aliases_8616(segmented_writes: set[str], global_writes: set[str]) -> set[str]:
    if not segmented_writes or not global_writes:
        return segmented_writes
    filtered: set[str] = set()
    for location in segmented_writes:
        global_offset: int | None = None
        direct_match = re.fullmatch(r"deref:ds:0x([0-9a-fA-F]+)", location)
        if direct_match is not None:
            global_offset = int(direct_match.group(1), 16)
        else:
            linear_match = re.fullmatch(
                r"deref:Add\(Mul\(reg:ds,const:16\),const:(-?[0-9]+)\)",
                location,
            )
            if linear_match is not None:
                global_offset = int(linear_match.group(1), 10)
        if isinstance(global_offset, int) and global_offset >= 0:
            global_location = f"global:{global_offset:#x}"
            if global_location in global_writes:
                continue
        filtered.add(location)
    return filtered


def _prunable_live_out_segment_write_ids_8616(
    root: TailValidationValue,
    project: TailValidationValue,
    contextual_call_summaries: Mapping[int, TailValidationValue],
) -> set[int]:
    prunable_ids: set[int] = set()

    def _scan_statement_list(statements: Sequence[TailValidationValue]) -> None:
        stmt_list = list(statements or ())
        for idx, stmt in enumerate(stmt_list):
            call = _call_from_statement_8616(stmt)
            if call is not None:
                summary_entry = contextual_call_summaries.get(id(call))
                summary_obj = (
                    summary_entry.get("summary")
                    if isinstance(summary_entry, Mapping)
                    else summary_entry
                )
                typed_summary = summary_obj if isinstance(summary_obj, CallsiteSummary8616) else None
                expected_arg_count = typed_summary.arg_count if typed_summary is not None else None
                push_arg_sources = typed_summary.push_arg_sources if typed_summary is not None else ()
                push_arg_source_count = (
                    len(push_arg_sources) if isinstance(push_arg_sources, (tuple, list)) and push_arg_sources else 0
                )
                explicit_arg_count = len(_boundary_tuple_8616(getattr(call, "args", ()) or ()))
                carrier_backed_args = any(
                    _expr_mentions_temp_carrier_8616(arg) for arg in (getattr(call, "args", ()) or ())
                )
                missing_arg_count = (
                    expected_arg_count - explicit_arg_count if isinstance(expected_arg_count, int) else 0
                )
                wanted_prunable_count = max(missing_arg_count, 1 if carrier_backed_args else 0)
                if (
                    isinstance(expected_arg_count, int)
                    and expected_arg_count > 0
                    and explicit_arg_count >= expected_arg_count
                    and push_arg_source_count > 0
                ):
                    wanted_prunable_count = max(wanted_prunable_count, push_arg_source_count)
                if wanted_prunable_count > 0:
                    scan = idx - 1
                    collected = 0
                    while scan >= 0 and collected < wanted_prunable_count:
                        candidate = stmt_list[scan]
                        if _is_stack_carrier_temp_assignment_8616(candidate):
                            scan -= 1
                            continue
                        if _is_value_only_assignment_8616(candidate, project):
                            scan -= 1
                            continue
                        assignments = list(_iter_assignment_nodes_8616(candidate))
                        if len(assignments) == 1 and not _contains_call_8616(candidate):
                            lhs, _rhs = _assignment_lhs_rhs_8616(assignments[0])
                            if _looks_like_ss_segment_store_8616(lhs, project):
                                prunable_ids.add(id(assignments[0]))
                                collected += 1
                                scan -= 1
                                continue
                        break
            nested_statements = getattr(stmt, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                _scan_statement_list(nested_statements)
            else_node = getattr(stmt, "else_node", None)
            if else_node is not None:
                _scan_statement_list(getattr(else_node, "statements", ()) or ())
            for attr in ("body", "initializer", "iterator"):
                child = getattr(stmt, attr, None)
                if child is not None:
                    _scan_statement_list(getattr(child, "statements", ()) or ())
            if isinstance(stmt, CIfElse):
                for _cond, child in _boundary_tuple_8616(stmt.condition_and_nodes or ()):
                    _scan_statement_list(getattr(child, "statements", ()) or ())

    if isinstance(root, CStatements):
        _scan_statement_list(root.statements or ())
    else:
        _scan_statement_list((root,))
    return prunable_ids


def _collect_direct_capstone_call_targets_for_function(function: TailValidationValue) -> tuple[int, ...]:
    def _impl() -> tuple[int, ...]:
        project = getattr(function, "project", None)
        if project is None or getattr(getattr(project, "arch", None), "name", None) != "86_16":
            return ()
        main_object = getattr(getattr(project, "loader", None), "main_object", None)
        linked_base = getattr(main_object, "linked_base", None)
        max_addr = getattr(main_object, "max_addr", None)
        image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None
        factory = getattr(project, "factory", None)
        if factory is None:
            return ()
        targets: list[int] = []
        for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
            try:
                block = factory.block(block_addr, opt_level=0)
            except Exception:
                continue
            for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
                if str(getattr(insn, "mnemonic", "") or "").lower() != "call":
                    continue
                target = _direct_capstone_call_target_8616(insn)
                if not isinstance(target, int):
                    continue
                resolved = normalize_x86_16_direct_call_target_8616(target, linked_base, image_end)
                if isinstance(resolved, int):
                    if _target_addr_is_stack_probe_helper_8616(project, resolved):
                        continue
                    targets.append(resolved)
        return tuple(targets)

    return _impl()


def _direct_capstone_call_target_8616(insn: TailValidationValue) -> int | None:
    def _impl() -> int | None:
        capstone_insn = getattr(insn, "insn", None)
        operands = getattr(capstone_insn, "operands", None)
        if operands:
            operand = operands[0]
            if getattr(operand, "type", None) == 2 and isinstance(getattr(operand, "imm", None), int):
                return int(operand.imm)
        op_str = str(getattr(insn, "op_str", "") or "").strip().lower()
        if not op_str or "[" in op_str or any(ch.isalpha() for ch in op_str if ch not in "xabcdef"):
            return None
        for token in re.split(r"[\s,:]+", op_str):
            if not token:
                continue
            try:
                return int(token, 0)
            except ValueError:
                continue
        return None

    return _impl()


def _maybe_add_coarse_conditions_8616(
    node: TailValidationValue, project: TailValidationValue, conditions: set[str], mode: str
) -> None:
    if mode != "coarse" or _is_control_flow_node(node):
        return
    for attr in ("condition", "cond"):
        value = getattr(node, attr, None)
        if value is not None:
            conditions.add(_expr_fingerprint(value, project))


def _process_control_flow_node_8616(
    node: TailValidationValue,
    *,
    project: TailValidationValue,
    mode: str,
    observed_locations: set[str],
    contextual_call_summaries: Mapping[int, TailValidationValue],
    contextual_call_fingerprints: Mapping[int, str],
    expected_helper_call_counts: Counter[str],
    contextual_condition_fingerprints: Mapping[int, str],
    normalized_loop_conditions: Mapping[int, str],
    canonical_loop_node_ids: Collection[int],
    canonical_loop_body_suppressed_write_ids: Mapping[int, frozenset[int]],
    prunable_segment_write_ids: set[int],
    conditions: set[str],
    control_flow_effects: set[str],
) -> bool:
    def _observable_body_write_locations(
        body: TailValidationValue,
        suppressed_write_ids: Collection[int],
    ) -> tuple[str, ...]:
        locations: set[str] = set()
        for child in _iter_c_nodes_deep_8616(body):
            if (
                not isinstance(child, CAssignment)
                or id(child) in prunable_segment_write_ids
                or id(child) in suppressed_write_ids
            ):
                continue
            for location in _assignment_write_locations_8616(getattr(child, "lhs", None), project):
                if location.startswith("reg:"):
                    if mode == "coarse" or location in observed_locations:
                        locations.add(location)
                elif location.startswith(("stack:", "stack_slot:")):
                    if include_x86_16_tail_validation_stack_write(
                        location,
                        mode=mode,
                        observed_locations=observed_locations,
                    ):
                        locations.add(location)
                elif location.startswith(("global:", "deref:")):
                    locations.add(location)
        return _sorted_unique(locations)

    def _record_loop_body_writes(
        kind: str,
        cond_fp: str,
        body: TailValidationValue,
        loop_id: int,
    ) -> None:
        body_writes = _observable_body_write_locations(
            body,
            canonical_loop_body_suppressed_write_ids.get(loop_id, frozenset()),
        )
        if not body_writes:
            return
        writes_fp = ",".join(body_writes)
        control_flow_effects.add(f"{kind}-body-writes:{cond_fp}:{writes_fp}")

    def _observable_body_call_fingerprints(body: TailValidationValue) -> tuple[str, ...]:
        entries: list[tuple[str, int | None, int]] = []
        located_fingerprints: set[str] = set()
        for child in _iter_observable_call_nodes_for_validation_8616(body):
            if _is_runtime_segment_helper_call_8616(child) or _is_structured_c_intrinsic_call_8616(child):
                continue
            fingerprint = _call_effect_fingerprint_8616(
                child,
                project,
                contextual_call_summaries=contextual_call_summaries,
                contextual_call_fingerprints=contextual_call_fingerprints,
            )
            if _helper_call_fingerprint_targets_stack_probe_8616(project, fingerprint):
                continue
            callsite_addr = _call_identity_callsite_addr_8616(child, contextual_call_summaries.get(id(child)))
            if isinstance(callsite_addr, int):
                located_fingerprints.add(fingerprint)
            entries.append((fingerprint, callsite_addr, id(child)))

        calls: list[str] = []
        seen_callsite_keys: set[tuple[int, str]] = set()
        seen_node_ids: set[int] = set()
        for fingerprint, callsite_addr, node_id in entries:
            if isinstance(callsite_addr, int):
                key = (callsite_addr, fingerprint)
                if key in seen_callsite_keys:
                    continue
                seen_callsite_keys.add(key)
            else:
                if fingerprint in located_fingerprints:
                    continue
                if node_id in seen_node_ids:
                    continue
                seen_node_ids.add(node_id)
            calls.append(fingerprint)
        collapsed_calls = _collapse_mixed_addr_name_addr_duplicates_8616(calls)
        return _cap_helper_call_fingerprints_to_expected_8616(project, collapsed_calls, expected_helper_call_counts)

    def _record_body_calls(kind: str, cond_fp: str, body: TailValidationValue) -> None:
        body_calls = _observable_body_call_fingerprints(body)
        if not body_calls:
            return
        control_flow_effects.add(f"{kind}-body-calls:{cond_fp}:{','.join(body_calls)}")

    def _impl() -> bool:
        if isinstance(node, CIfElse):
            if (
                identical_assignment_arm_condition_8616(
                    node,
                    project,
                    _TAIL_VALIDATION_EXPRESSION_CALLBACKS_8616,
                )
                is not None
            ):
                return False
            pairs = _boundary_tuple_8616(node.condition_and_nodes or ())
            for idx, (cond, _child) in enumerate(pairs):
                normalized_cond = _normalized_if_chain_condition_8616(pairs, idx, node.codegen)
                if normalized_cond is not None:
                    cond = normalized_cond
                cond_fp = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
                control_flow_effects.add(f"if:{cond_fp}")
                _record_body_calls("if", cond_fp, _child)
                if mode == "live_out":
                    conditions.add(cond_fp)
            if node.else_node is not None:
                control_flow_effects.add("if:else")
                # Dynamic angr/codegen compatibility boundary.
                _record_body_calls("if-else", "else", node.else_node)
            return True
        if isinstance(node, CIfBreak):
            cond = node.condition
            cond_fp = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
            control_flow_effects.add(f"ifbreak:{cond_fp}")
            if mode == "live_out":
                conditions.add(cond_fp)
            return True
        if isinstance(node, CWhileLoop):
            cond = node.condition
            cond_fp = normalized_loop_conditions.get(
                id(node), contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
            )
            loop_kind = "loop" if id(node) in canonical_loop_node_ids else "while"
            control_flow_effects.add(f"{loop_kind}:{cond_fp}")
            # Dynamic angr/codegen compatibility boundary.
            _record_body_calls(loop_kind, cond_fp, node.body)
            _record_loop_body_writes(loop_kind, cond_fp, node.body, id(node))
            if mode == "live_out":
                conditions.add(cond_fp)
            return True
        if isinstance(node, CDoWhileLoop):
            cond = node.condition
            cond_fp = normalized_loop_conditions.get(
                id(node),
                contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project)),
            )
            control_flow_effects.add(f"dowhile:{cond_fp}")
            # Dynamic angr/codegen compatibility boundary.
            _record_body_calls("dowhile", cond_fp, node.body)
            _record_loop_body_writes("dowhile", cond_fp, node.body, id(node))
            if mode == "live_out":
                conditions.add(cond_fp)
            return True
        if isinstance(node, CForLoop):
            cond = node.condition
            cond_fp = normalized_loop_conditions.get(
                id(node),
                contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project)),
            )
            loop_kind = "loop" if id(node) in canonical_loop_node_ids else "for"
            control_flow_effects.add(f"{loop_kind}:{cond_fp}")
            # Dynamic angr/codegen compatibility boundary.
            _record_body_calls(loop_kind, cond_fp, node.body)
            _record_loop_body_writes(loop_kind, cond_fp, node.body, id(node))
            if mode == "live_out":
                conditions.add(cond_fp)
            return True
        if isinstance(node, CSwitchCase):
            switch_fp = _expr_fingerprint(node.switch, project)
            control_flow_effects.add(f"switch:{switch_fp}")
            if mode == "live_out":
                conditions.add(switch_fp)
            # Dynamic angr/codegen compatibility boundary.
            for case_value, case_body in _switch_case_items_8616(node.cases):
                case_fp = _switch_case_fingerprint(case_value, project)
                control_flow_effects.add(f"case:{case_fp}")
                _record_body_calls("case", case_fp, case_body)
            if node.default is not None:
                control_flow_effects.add("case:default")
                # Dynamic angr/codegen compatibility boundary.
                _record_body_calls("case-default", "default", node.default)
            return True
        if isinstance(node, CGoto):
            control_flow_effects.add(f"goto:{node.target!r}")
            return True
        if isinstance(node, CBreak):
            control_flow_effects.add("break")
            return True
        if isinstance(node, CContinue):
            control_flow_effects.add("continue")
            return True
        return False

    return _impl()


def _process_tail_validation_node_8616(
    node: TailValidationValue,
    *,
    project: TailValidationValue,
    mode: str,
    observed_locations: set[str],
    contextual_call_summaries: Mapping[int, TailValidationValue],
    contextual_call_fingerprints: Mapping[int, str],
    expected_helper_call_counts: Counter[str],
    contextual_condition_fingerprints: Mapping[int, str],
    normalized_loop_conditions: Mapping[int, str],
    canonical_loop_node_ids: Collection[int],
    canonical_loop_body_suppressed_write_ids: Mapping[int, frozenset[int]],
    prunable_segment_write_ids: set[int],
    helper_calls: list[str],
    helper_call_node_ids: set[int],
    helper_callsite_keys: set[int],
    helper_callsite_fingerprints: set[str],
    register_writes: set[str],
    stack_writes: set[str],
    global_writes: set[str],
    segmented_writes: set[str],
    returns: set[str],
    conditions: set[str],
    control_flow_effects: set[str],
) -> None:
    """Collect one structured node's validation-visible semantic effects."""

    def _record_helper_call(call_node: TailValidationValue) -> None:
        if _is_runtime_segment_helper_call_8616(call_node) or _is_structured_c_intrinsic_call_8616(call_node):
            return
        summary = contextual_call_summaries.get(id(call_node))
        if _call_node_is_stack_probe_helper_8616(project, call_node, summary):
            return
        fingerprint = _call_effect_fingerprint_8616(
            call_node,
            project,
            contextual_call_summaries=contextual_call_summaries,
            contextual_call_fingerprints=contextual_call_fingerprints,
        )
        if _helper_call_fingerprint_targets_stack_probe_8616(project, fingerprint):
            return
        normalized_fingerprint = _normalize_helper_call_fingerprint_8616(project, fingerprint)
        canonical_fingerprint = _canonicalize_helper_call_fingerprint_for_compare_8616(
            str(normalized_fingerprint or fingerprint)
        )
        node_id = id(call_node)
        if node_id in helper_call_node_ids:
            return
        helper_call_node_ids.add(node_id)
        callsite_addr = _call_identity_callsite_addr_8616(call_node, summary)
        if isinstance(callsite_addr, int):
            # A machine-code callsite represents one call even when angr
            # materializes multiple AST nodes or changes the target spelling.
            if callsite_addr in helper_callsite_keys:
                return
            helper_callsite_keys.add(callsite_addr)
            helper_callsite_fingerprints.add(canonical_fingerprint)
        else:
            if canonical_fingerprint in helper_callsite_fingerprints:
                return
            if fingerprint in {"<indirect>", "name:<indirect>", "<unknown-call>"} and (
                _helper_call_fingerprints_satisfy_expected_8616(project, helper_calls, expected_helper_call_counts)
            ):
                return
        helper_calls.append(fingerprint)

    def _impl() -> None:
        if isinstance(node, CFunctionCall):
            for call_node in _iter_observable_call_nodes_for_validation_8616(node):
                _record_helper_call(call_node)
            return
        if isinstance(node, CReturn):
            # Dynamic angr/codegen compatibility boundary.
            for call_node in _iter_observable_call_nodes_for_validation_8616(node.retval):
                _record_helper_call(call_node)
            # Dynamic angr/codegen compatibility boundary.
            retval = node.retval
            if _active_codegen_return_value_is_unobserved_8616(project):
                returns.add("none")
            else:
                returns.add(_expr_fingerprint(retval, project))
            control_flow_effects.add("return")
            return
        if isinstance(node, CAssignment):
            if id(node) in prunable_segment_write_ids:
                return
            tags = node.tags
            if isinstance(tags, Mapping) and tags.get("inertia_software_interrupt_status_output_8616") is True:
                # Lowering exposes FLAGS already produced by the owning INT.
                # Keep this assignment visible to def-use validation, but do
                # not count its C projection as a new machine-code effect.
                return
            # Dynamic angr/codegen compatibility boundary.
            for call_node in _iter_observable_call_nodes_for_validation_8616(node.rhs):
                _record_helper_call(call_node)
            for location in _assignment_write_locations_8616(
                node.lhs,
                project,
            ):
                if location.startswith("reg:"):
                    if mode == "coarse" or location in observed_locations:
                        register_writes.add(location)
                elif location.startswith(("stack:", "stack_slot:")):
                    if include_x86_16_tail_validation_stack_write(
                        location, mode=mode, observed_locations=observed_locations
                    ):
                        stack_writes.add(location)
                        if isinstance(observed_locations, StackObservedLocations8616):
                            observed_locations.record_write(location, _expr_fingerprint(node.rhs, project))
                elif location.startswith("global:"):
                    global_writes.add(location)
                elif location.startswith("deref:"):
                    if mode == "live_out" and (
                        _is_dynamic_dirty_ss_location_8616(location)
                        or _lhs_aliases_dynamic_stack_frame_8616(node.lhs, project)
                    ):
                        continue
                    segmented_writes.add(location)
            return
        _process_control_flow_node_8616(
            node,
            project=project,
            mode=mode,
            observed_locations=observed_locations,
            contextual_call_summaries=contextual_call_summaries,
            contextual_call_fingerprints=contextual_call_fingerprints,
            expected_helper_call_counts=expected_helper_call_counts,
            contextual_condition_fingerprints=contextual_condition_fingerprints,
            normalized_loop_conditions=normalized_loop_conditions,
            canonical_loop_node_ids=canonical_loop_node_ids,
            canonical_loop_body_suppressed_write_ids=canonical_loop_body_suppressed_write_ids,
            prunable_segment_write_ids=prunable_segment_write_ids,
            conditions=conditions,
            control_flow_effects=control_flow_effects,
        )

    return _impl()


def _build_tail_validation_stage_rows_8616(
    *,
    scanned_count: int,
    structuring: Mapping[str, TailValidationValue],
    postprocess: Mapping[str, TailValidationValue],
) -> tuple[list[dict[str, TailValidationValue]], int, int, int, int]:
    def _impl() -> tuple[list[dict[str, TailValidationValue]], int, int, int, int]:
        stage_rows: list[dict[str, TailValidationValue]] = []
        total_changed = total_missing = total_unknown = total_coverage = 0
        for stage_name, stage_summary in (("structuring", structuring), ("postprocess", postprocess)):
            changed_count = int(stage_summary.get("changed_count", 0) or 0)
            stable_count = int(stage_summary.get("stable_count", 0) or 0)
            unknown_count = int(stage_summary.get("unknown_count", 0) or 0)
            missing_count = int(stage_summary.get("missing_count", 0) or 0)
            coverage_count = int(stage_summary.get("coverage_count", stable_count + changed_count + unknown_count) or 0)
            total_changed += changed_count
            total_missing += missing_count
            total_unknown += unknown_count
            total_coverage += coverage_count
            stage_rows.append(
                {
                    "stage": stage_name,
                    "changed_count": changed_count,
                    "stable_count": stable_count,
                    "unknown_count": unknown_count,
                    "missing_count": missing_count,
                    "coverage_count": coverage_count,
                    "changed_rate": 0.0 if scanned_count == 0 else round(changed_count / scanned_count, 6),
                    "coverage_rate": 0.0 if scanned_count == 0 else round(coverage_count / scanned_count, 6),
                    "mode_counts": dict(stage_summary.get("mode_counts", {}) or {}),
                    "top_verdicts": _boundary_list_8616(stage_summary.get("top_verdicts", []) or []),
                }
            )
        return stage_rows, total_changed, total_missing, total_unknown, total_coverage

    return _impl()


def _tail_validation_headline_8616(severity: str, scanned_count: int, changed_function_count: int) -> str:
    if scanned_count == 0:
        return "whole-tail validation: no functions scanned"
    if severity == "clean":
        return f"whole-tail validation clean across {scanned_count} functions"
    if severity == "uncollected":
        return f"whole-tail validation not collected across {scanned_count} functions"
    if severity == "partial":
        return f"whole-tail validation failed across {scanned_count} functions"
    if severity == "unknown":
        return f"whole-tail validation incomplete across {scanned_count} functions"
    return f"whole-tail validation failed across {changed_function_count} functions"


def _def_use_call_output_definitions_8616(
    codegen: TailValidationValue,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> dict[int, tuple[DefUseCallOutputDefinition8616, ...]]:
    """Join lowering-owned output facts to exact current structured calls.

    Structuring may regenerate a call node after Lowering records its output
    object. Reconnect that clone only through the typed machine-call tag and
    authoritative callsite inventory; target names and AST order are not
    evidence of identity.
    """
    try:
        raw_facts = codegen._inertia_call_output_stack_object_facts_8616
        summary_map = codegen._inertia_callsite_summaries
        root = codegen.cfunc.statements
    except AttributeError:
        return {}
    if query_index is not None:
        query_index.require_root(root)
    if not isinstance(summary_map, Mapping):
        return {}
    inventory = callsite_summary_inventory_8616(codegen)
    facts = tuple(
        fact
        for fact in _boundary_tuple_8616(raw_facts)
        if isinstance(fact, CallOutputStackObjectFact8616)
        and fact.boundary_offset > fact.base_offset
    )
    facts_by_callsite: dict[int, list[CallOutputStackObjectFact8616]] = {}
    for fact in facts:
        facts_by_callsite.setdefault(fact.callsite_addr, []).append(fact)
    definitions: dict[int, tuple[DefUseCallOutputDefinition8616, ...]] = {}
    nodes = query_index.nodes if query_index is not None else _iter_c_nodes_deep_8616(root)
    for node in nodes:
        if not isinstance(node, CFunctionCall):
            continue
        call_node_id = id(node)
        summary = summary_map.get(call_node_id)
        tagged_callsite_addr = structured_callsite_addr_8616(node)
        if isinstance(summary, CallsiteSummary8616):
            if (
                tagged_callsite_addr is not None
                and tagged_callsite_addr != summary.callsite_addr
            ):
                raise PipelineHardError(
                    "structured call output identity conflicts with typed summary: "
                    f"tag={tagged_callsite_addr:#x} summary={summary.callsite_addr:#x}"
                )
        elif tagged_callsite_addr is not None:
            summary = inventory.get(tagged_callsite_addr)
        if not isinstance(summary, CallsiteSummary8616):
            continue
        call_definitions = tuple(
            DefUseCallOutputDefinition8616(
                base_offset=fact.base_offset,
                width=fact.boundary_offset - fact.base_offset,
            )
            for fact in facts_by_callsite.get(summary.callsite_addr, ())
        )
        if call_definitions:
            definitions[call_node_id] = call_definitions
    return definitions


def _def_use_entry_registers_8616(codegen: TailValidationValue) -> tuple[object, ...]:
    """Return explicit function arguments available at the C entry boundary."""
    try:
        arg_list = codegen.cfunc.arg_list
    except AttributeError:
        return ()
    if arg_list is None:
        return ()
    try:
        return tuple(cast(Iterable[object], arg_list))
    except TypeError:
        return ()


def _def_use_indexed_stack_read_proofs_8616(
    codegen: TailValidationValue,
    root: object,
) -> dict[int, IndexedStackReadProof8616]:
    """Collect Structuring-owned bounded-index proofs for the exact final AST."""
    try:
        raw_facts = codegen._inertia_direct_stack_move_facts_8616
    except AttributeError:
        raw_facts = ()
    direct_stack_move_facts = tuple(
        fact
        for fact in _boundary_tuple_8616(raw_facts)
        if isinstance(fact, DirectStackMoveFact8616)
    )
    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=direct_stack_move_facts,
        codegen=codegen,
    )
    codegen._inertia_indexed_stack_read_proof_report_8616 = report
    if os.environ.get("INERTIA_DEBUG_INDEXED_STACK_RANGES") == "1":
        logging.getLogger(__name__).warning(
            "indexed-stack-range-proof facts=%r report=%r",
            tuple(
                (
                    fact.dst_offset,
                    fact.width,
                    fact.source_kind.value,
                    fact.source_offset,
                    fact.source_immediate,
                    fact.source_call_ins_addr,
                    fact.source_call_return_contract,
                )
                for fact in direct_stack_move_facts
            ),
            report,
        )
    return cast(dict[int, Any], report.by_read_node_id())


def _def_use_segment_register_offsets_8616(project: TailValidationValue) -> frozenset[int]:
    """Return architectural segment-register offsets from the angr boundary."""
    try:
        registers = project.arch.registers
    except AttributeError:
        return frozenset()
    if not isinstance(registers, Mapping):
        return frozenset()
    offsets: set[int] = set()
    for register_name in ("cs", "ds", "es", "ss"):
        register = registers.get(register_name)
        if (
            isinstance(register, (list, tuple))
            and register
            and isinstance(register[0], int)
        ):
            offsets.add(register[0])
    return frozenset(offsets)


def _def_use_entry_segment_register_offsets_8616(
    project: TailValidationValue,
    codegen: TailValidationValue,
) -> frozenset[int]:
    """Return segment offsets proven as architectural live-ins by typed IR."""
    try:
        artifact = codegen._inertia_segment_state_artifact
    except AttributeError:
        return frozenset()
    if not isinstance(artifact, SegmentStateArtifact):
        return frozenset()
    try:
        function_addr = codegen.cfunc.addr
    except AttributeError:
        return frozenset()
    if not isinstance(function_addr, int):
        return frozenset()
    entry_states = artifact.entry_states.get(function_addr, {})
    proven_names = {
        register_name
        for register_name, state in entry_states.items()
        if state.origin is SegmentOrigin.PROVEN
        and state.value_kind is SegmentValueKind8616.ARCHITECTURAL_LIVE_IN
    }
    try:
        registers = project.arch.registers
    except AttributeError:
        return frozenset()
    if not isinstance(registers, Mapping):
        return frozenset()
    offsets: set[int] = set()
    for register_name in proven_names:
        register = registers.get(register_name)
        if isinstance(register, (list, tuple)) and register and isinstance(register[0], int):
            offsets.add(register[0])
    return frozenset(offsets)


def _validate_final_control_flow_8616(
    project: TailValidationValue,
    codegen: TailValidationValue,
    root: object,
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> ControlFlowValidationReport8616:
    """Join final AST reachability checks with binary-proven exit obligations."""
    structured = validate_structured_control_flow_8616(
        root,
        query_index=query_index,
        loop_branch_facts=loop_branch_guard_facts_8616(codegen),
        condition_fingerprint=lambda condition: _expr_fingerprint(
            condition,
            project,
        ),
        condition_ir_fingerprint=lambda condition: condition_ir_semantic_fingerprint_8616(
            project, codegen, condition
        ),
        condition_fingerprint_normalizer=_canonicalize_final_branch_condition_fingerprint_8616,
        condition_storage_matcher=lambda condition, candidate, inverted: condition_storage_views_match_8616(
            project, codegen, condition, candidate, inverted,
        ),
    )
    branch_conditions = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        query_index=query_index,
        condition_fingerprint=lambda condition: _expr_fingerprint(
            condition,
            project,
        ),
        condition_ir_fingerprint=lambda condition: condition_ir_semantic_fingerprint_8616(
            project,
            codegen,
            condition,
        ),
        condition_fingerprint_normalizer=_canonicalize_final_branch_condition_fingerprint_8616,
    )
    shared_exits = shared_loop_exit_report_8616(codegen)
    obligations = validate_switch_exit_obligations_8616(
        root,
        switch_exit_obligations_from_codegen_8616(codegen),
        shared_bindings=shared_exits.bindings if shared_exits is not None else (),
        fingerprint=lambda expression: shared_exit_fingerprint_8616(expression, project),
    )
    return ControlFlowValidationReport8616(
        raw_fact_count=(
            structured.raw_fact_count
            + branch_conditions.raw_fact_count
            + obligations.raw_fact_count
        ),
        normalized_fact_count=(
            structured.normalized_fact_count
            + branch_conditions.normalized_fact_count
            + obligations.normalized_fact_count
        ),
        classified_fact_count=(
            structured.classified_fact_count
            + branch_conditions.classified_fact_count
            + obligations.classified_fact_count
        ),
        materialized_count=(
            structured.materialized_count
            + branch_conditions.materialized_count
            + obligations.materialized_count
        ),
        issues=(
            *structured.issues,
            *branch_conditions.issues,
            *obligations.issues,
        ),
    )
def refresh_x86_16_final_semantic_validation_8616(
    project: TailValidationValue,
    codegen: TailValidationValue,
    *,
    persist_failures: bool = True,
    include_virtual_carriers: bool = False,
) -> X86_16FinalSemanticValidationReport8616:
    """Evaluate absolute semantic guards on the exact final codegen AST.

    Validation-stage comparisons can be stable even when both their baseline
    and result already contain the same lost definition or missing call. This
    refresh runs after all output mutations and promotes such absolute failures
    into the canonical ``postprocess`` snapshot. It reports only and never
    mutates the C AST. Final emission callers opt into regenerated virtual
    carriers only after all lowering and cleanup mutations have stopped.
    """
    root = _codegen_root(codegen)
    if root is None:
        def_use_report = DefUseValidationReport8616()
        required_call_report = RequiredCallsiteValidationReport8616(
            raw_fact_count=0,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=0,
            missing_calls=(),
        )
        callsite_multiplicity_report = CallsiteMultiplicityValidationReport8616()
        call_interface_report = CallInterfaceValidationReport8616()
        call_argument_class_report = CallArgumentClassValidationReport8616()
        function_parameter_report = FunctionParameterValidationReport8616()
        function_return_class_report = FunctionReturnClassValidationReport8616()
        control_flow_report = ControlFlowValidationReport8616()
        storage_identity_report = StorageIdentityValidationReport8616()
        required_memory_effect_report = RequiredMemoryEffectValidationReport8616()
        pointer_parameter_output_report = PointerParameterOutputValidationReport8616()
        software_interrupt_input_report = SoftwareInterruptValidationReport8616()
        return X86_16FinalSemanticValidationReport8616(
            def_use=def_use_report,
            required_calls=required_call_report,
            callsite_multiplicity=callsite_multiplicity_report,
            call_interfaces=call_interface_report,
            call_argument_classes=call_argument_class_report,
            function_parameters=function_parameter_report,
            function_return_class=function_return_class_report,
            control_flow=control_flow_report,
            storage_identities=storage_identity_report,
            required_memory_effects=required_memory_effect_report,
            pointer_parameter_outputs=pointer_parameter_output_report,
            software_interrupt_inputs=software_interrupt_input_report,
        )
    query_index = StructuredAstQueryIndex8616.build(root)
    required_call_surface = build_required_call_validation_surface_8616(
        codegen,
        root,
        query_index=query_index,
    )
    def_use_report = validate_structured_def_use_8616(
        root,
        call_output_definitions=_def_use_call_output_definitions_8616(codegen, query_index),
        indexed_stack_read_proofs=_def_use_indexed_stack_read_proofs_8616(
            codegen,
            root,
        ),
        entry_defined_stack_ranges=entry_stack_ranges_from_codegen_8616(codegen).ranges,
        entry_defined_registers=_def_use_entry_registers_8616(codegen),
        segment_register_offsets=_def_use_segment_register_offsets_8616(project),
        entry_defined_segment_register_offsets=_def_use_entry_segment_register_offsets_8616(
            project,
            codegen,
        ),
        packed_status_flag_preservation=packed_status_flag_preservation_evidence_8616(project, codegen),
        include_virtual_carriers=include_virtual_carriers,
        stack_variable_offset_resolver=lambda variable: final_c_function_machine_bp_offset_8616(
            codegen,
            variable,
        ),
    )
    required_call_report = validate_required_callsites_8616(
        codegen,
        root,
        query_index=query_index,
        surface=required_call_surface,
    )
    callsite_multiplicity_report = validate_required_callsite_multiplicity_8616(
        codegen,
        root,
    )
    call_interface_report = validate_call_interfaces_8616(
        codegen,
        root,
        query_index=query_index,
        surface=required_call_surface,
    )
    call_argument_class_report = validate_call_argument_classes_8616(
        codegen,
        root,
        query_index=query_index,
        surface=required_call_surface,
    )
    function_parameter_report = validate_function_parameters_8616(project, codegen)
    function_return_class_report = validate_function_return_class_8616(project, codegen)
    control_flow_report = _validate_final_control_flow_8616(
        project,
        codegen,
        root,
        query_index=query_index,
    )
    storage_identity_report = validate_storage_identities_8616(
        codegen,
        root,
        query_index=query_index,
    )
    required_memory_effect_report = validate_required_memory_effects_8616(project, codegen, root)
    pointer_parameter_output_report = validate_pointer_parameter_outputs_8616(
        project,
        codegen,
        root,
    )
    software_interrupt_input_report = validate_software_interrupt_inputs_8616(
        codegen,
        root,
        query_index=query_index,
    )
    report = X86_16FinalSemanticValidationReport8616(
        def_use=def_use_report,
        required_calls=required_call_report,
        callsite_multiplicity=callsite_multiplicity_report,
        call_interfaces=call_interface_report,
        call_argument_classes=call_argument_class_report,
        function_parameters=function_parameter_report,
        function_return_class=function_return_class_report,
        control_flow=control_flow_report,
        storage_identities=storage_identity_report,
        required_memory_effects=required_memory_effect_report,
        pointer_parameter_outputs=pointer_parameter_output_report,
        software_interrupt_inputs=software_interrupt_input_report,
    )
    semantic_failures = report.semantic_failures()
    if not semantic_failures or not persist_failures:
        return report
    summary_text = (
        "absolute final semantic guard failed: "
        + ", ".join(f"{family}={len(failures)}" for family, failures in semantic_failures.items())
    )
    failure_details = format_tail_semantic_failures_8616(semantic_failures)
    if failure_details:
        summary_text += "; " + "; ".join(failure_details)
    validation: dict[str, TailValidationValue] = {
        "changed": True,
        "status": "failed",
        "mode": "live_out",
        "summary_text": summary_text,
        "verdict": f"postprocess whole-tail validation [live_out] failed: {summary_text}",
    }
    snapshot_entry = persist_x86_16_tail_validation_snapshot(
        function_info=None,
        codegen=codegen,
        stage="postprocess",
        validation=validation,
    )
    snapshot_entry["semantic_failures"] = semantic_failures
    snapshot_entry["final_semantic_guard"] = report.evidence_counts()
    return report


def collect_x86_16_tail_validation_summary(
    project: TailValidationValue,
    codegen: TailValidationValue,
    *,
    mode: str = "live_out",
    boundary_fingerprint: str | None = None,
) -> X86_16TailValidationSummary:
    """Collect observable structured-codegen effects for whole-tail validation."""

    def _impl() -> X86_16TailValidationSummary:
        if mode not in _TAIL_VALIDATION_MODES:
            raise ValueError(f"Unsupported x86-16 tail validation mode: {mode}")
        # C codegen nodes are mutated in-place between validation stages. The
        # expression fingerprint cache is keyed by object identity, so carrying
        # it across summaries can make tail validation compare stale semantics.
        _clear_tail_validation_expr_fingerprint_cache_8616(project)
        with contextlib.suppress(Exception):
            codegen._inertia_jcc_register_exprs_by_ins_addr_8616 = None
        cache = _tail_validation_summary_cache_store(codegen)
        summary_boundary_fingerprint = boundary_fingerprint
        if summary_boundary_fingerprint is None:
            summary_boundary_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode=mode)
        root = _codegen_root(codegen)
        if root is None:
            return X86_16TailValidationSummary((), (), (), (), (), (), (), ())

        def _finish_summary(
            summary: X86_16TailValidationSummary,
            *,
            cache_hit: bool,
            cache_key: str,
        ) -> X86_16TailValidationSummary:
            if os.environ.get("INERTIA_DEBUG_TV_SUMMARY", "").strip().lower() in {"1", "true", "yes", "on"}:
                import sys

                sys.stderr.write(
                    "[tail-validation-summary-debug] "
                    f"cache_hit={cache_hit} "
                    f"helpers={summary.helper_calls!r} "
                    f"registers={summary.register_writes!r} "
                    f"stack={summary.stack_writes!r} "
                    f"globals={summary.global_writes!r} "
                    f"segmented={summary.segmented_writes!r} "
                    f"conditions={summary.conditions!r} "
                    f"returns={summary.returns!r} "
                    f"control={summary.control_flow_effects!r} "
                    f"def_use={summary.def_use_issues!r} "
                    f"required_calls={summary.missing_required_calls!r} "
                    f"callsite_multiplicity={summary.callsite_multiplicity_issues!r} "
                    f"control_flow={summary.control_flow_issues!r} "
                    f"storage_identities={summary.storage_identity_issues!r}\n"
                )
                sys.stderr.flush()
            stat_name = "hits" if cache_hit else "misses"
            cache["stats"][stat_name] = int(cache["stats"].get(stat_name, 0) or 0) + 1
            codegen._inertia_tail_validation_last_summary_cache_hit = cache_hit
            codegen._inertia_tail_validation_last_summary_cache_key = cache_key
            return summary

        boundary_context = _consume_tail_validation_boundary_context_8616(
            codegen,
            mode=mode,
            boundary_fingerprint=summary_boundary_fingerprint,
            root=root,
        )
        boundary_entries = cache.get("boundary_entries")
        boundary_cache_key = (
            mode,
            summary_boundary_fingerprint,
            boundary_context.summary_input_generation,
        ) if boundary_context is not None else None
        if isinstance(boundary_entries, dict) and boundary_cache_key is not None:
            boundary_cached_summary = boundary_entries.get(boundary_cache_key)
            if isinstance(boundary_cached_summary, X86_16TailValidationSummary):
                return _finish_summary(
                    boundary_cached_summary,
                    cache_hit=True,
                    cache_key=f"tail_validation.summary.boundary:{summary_boundary_fingerprint}",
                )
        # Observable fingerprints intentionally canonicalize structural detail,
        # but semantic guards depend on that detail. Include their current
        # results in cache identity so a rewritten definition or callsite cannot
        # reuse a stale failure/success from an observably equivalent tree.
        query_index = StructuredAstQueryIndex8616.build(root)
        required_call_surface = build_required_call_validation_surface_8616(
            codegen,
            root,
            query_index=query_index,
        )
        def_use_report = validate_structured_def_use_8616(
            root,
            call_output_definitions=_def_use_call_output_definitions_8616(codegen, query_index),
            indexed_stack_read_proofs=_def_use_indexed_stack_read_proofs_8616(
                codegen,
                root,
            ),
            entry_defined_stack_ranges=entry_stack_ranges_from_codegen_8616(codegen).ranges,
            entry_defined_registers=_def_use_entry_registers_8616(codegen),
            segment_register_offsets=_def_use_segment_register_offsets_8616(project),
            entry_defined_segment_register_offsets=_def_use_entry_segment_register_offsets_8616(
                project,
                codegen,
            ),
            packed_status_flag_preservation=packed_status_flag_preservation_evidence_8616(project, codegen),
            stack_variable_offset_resolver=lambda variable: final_c_function_machine_bp_offset_8616(
                codegen,
                variable,
            ),
        )
        required_call_report = validate_required_callsites_8616(
            codegen,
            root,
            query_index=query_index,
            surface=required_call_surface,
        )
        callsite_multiplicity_report = validate_required_callsite_multiplicity_8616(
            codegen,
            root,
        )
        call_interface_report = validate_call_interfaces_8616(
            codegen,
            root,
            query_index=query_index,
            surface=required_call_surface,
        )
        call_argument_class_report = validate_call_argument_classes_8616(
            codegen,
            root,
            query_index=query_index,
            surface=required_call_surface,
        )
        function_parameter_report = validate_function_parameters_8616(project, codegen)
        function_return_class_report = validate_function_return_class_8616(project, codegen)
        control_flow_report = _validate_final_control_flow_8616(
            project,
            codegen,
            root,
            query_index=query_index,
        )
        storage_identity_report = validate_storage_identities_8616(
            codegen,
            root,
            query_index=query_index,
        )
        descriptor = build_x86_16_validation_cache_descriptor(
            "tail_validation.summary",
            {
                "mode": mode,
                "boundary_fingerprint": summary_boundary_fingerprint,
                "def_use_issues": def_use_report.semantic_issue_tokens(),
                "missing_required_calls": required_call_report.missing_calls,
                "callsite_multiplicity_issues": callsite_multiplicity_report.issue_tokens(),
                "call_interface_issues": call_interface_report.issue_tokens(),
                "call_argument_class_issues": call_argument_class_report.issue_tokens(),
                "function_parameter_issues": function_parameter_report.issue_tokens(),
                "function_return_class_issues": function_return_class_report.issue_tokens(),
                "control_flow_issues": control_flow_report.issue_tokens(),
                "storage_identity_issues": storage_identity_report.issue_tokens(),
            },
        )
        entries = cache.get("entries", {})

        def _build_summary() -> X86_16TailValidationSummary:
            helper_calls: list[str] = []
            register_writes: set[str] = set()
            stack_writes: set[str] = set()
            global_writes: set[str] = set()
            segmented_writes: set[str] = set()
            returns: set[str] = set()
            conditions: set[str] = set()
            control_flow_effects: set[str] = set()
            helper_call_node_ids: set[int] = set()
            helper_callsite_keys: set[int] = set()
            helper_callsite_fingerprints: set[str] = set()
            previous_active_codegen = getattr(project, "_inertia_tail_validation_active_codegen", None)
            # Dynamic angr/codegen compatibility boundary.
            previous_snapshot_expr_cache = getattr(
                project,
                "_inertia_tail_validation_snapshot_expr_cache_enabled_8616",
                None,
            )
            project._inertia_tail_validation_active_codegen = codegen
            project._inertia_tail_validation_snapshot_expr_cache_enabled_8616 = True
            try:
                # Dynamic angr/codegen compatibility boundary.
                func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
                summary_inventory = callsite_summary_inventory_8616(codegen) or None
                with span(
                    "x86_16.tail_validation.summary.context",
                    function=func_addr,
                    reused_boundary=boundary_context is not None,
                ):
                    if boundary_context is not None:
                        contextual_call_fingerprints = boundary_context.contextual_call_fingerprints
                        contextual_call_summaries = boundary_context.contextual_call_summaries
                        contextual_condition_fingerprints = boundary_context.contextual_condition_fingerprints
                        codegen._inertia_tail_validation_boundary_context_reused_8616 = (
                            # Dynamic angr/codegen compatibility boundary.
                            int(getattr(codegen, "_inertia_tail_validation_boundary_context_reused_8616", 0) or 0) + 1
                        )
                    else:
                        contextual_call_fingerprints = build_x86_16_contextual_call_fingerprints(
                            root,
                            project,
                            summary_inventory=summary_inventory,
                        )
                        contextual_call_summaries = _build_contextual_call_summary_map(
                            root,
                            project,
                            summary_inventory,
                        )
                        contextual_condition_fingerprints = build_x86_16_contextual_condition_fingerprints(
                            root, project
                        )
                with span("x86_16.tail_validation.summary.observed_locations", function=func_addr):
                    observed_locations = _collect_observed_locations(
                        root,
                        project,
                        mode,
                        contextual_condition_fingerprints,
                    )
                with span("x86_16.tail_validation.summary.expected_helper_counts", function=func_addr):
                    expected_helper_call_counts = _expected_helper_call_counts_for_validation_8616(
                        root,
                        project,
                        summary_inventory,
                    )
                with span("x86_16.tail_validation.summary.prunable_segment_writes", function=func_addr):
                    prunable_segment_write_ids = (
                        _prunable_live_out_segment_write_ids_8616(root, project, contextual_call_summaries)
                        if mode == "live_out"
                        else set()
                    )
                with span("x86_16.tail_validation.summary.split_tail_returns", function=func_addr):
                    split_tail_return_call_fingerprints = (
                        ()
                        if _active_codegen_return_value_is_unobserved_8616(project)
                        else _split_tail_return_call_fingerprints_8616(root, project, contextual_call_summaries)
                    )
                normalized_loop_conditions: dict[int, str] = {}
                suppressed_control_flow_nodes: set[int] = set()
                canonical_loop_node_ids: set[int] = set()
                canonical_loop_body_suppressed_write_ids: dict[int, frozenset[int]] = {}
                with span("x86_16.tail_validation.summary.loop_normalization", function=func_addr):
                    for node in _iter_c_nodes_deep_8616(root):
                        if isinstance(node, CDoWhileLoop):
                            post_body_condition = _do_while_post_body_condition_fingerprint_8616(node, project)
                            if post_body_condition is not None:
                                normalized_loop_conditions[id(node)] = post_body_condition
                            continue
                        if not isinstance(node, (CWhileLoop, CForLoop)):
                            continue
                        canonical_shape = canonical_loop_validation_shape_8616(node)
                        if canonical_shape is not None:
                            normalized_loop_conditions[id(node)] = contextual_condition_fingerprints.get(
                                id(canonical_shape.condition),
                                _expr_fingerprint(canonical_shape.condition, project),
                            )
                            suppressed_control_flow_nodes.update(
                                canonical_shape.suppressed_control_node_ids
                            )
                            canonical_loop_node_ids.add(id(node))
                            canonical_loop_body_suppressed_write_ids[id(node)] = (
                                canonical_shape.suppressed_body_write_node_ids
                            )
                            continue
                        normalized = _extract_loop_break_guard_normalization_8616(
                            node,
                            project,
                            contextual_condition_fingerprints,
                        )
                        if normalized is None:
                            continue
                        normalized_loop_conditions[id(node)] = normalized[0]
                        suppressed_control_flow_nodes.update(normalized[1])

                with span("x86_16.tail_validation.summary.process_nodes", function=func_addr):
                    for node in _iter_c_nodes_deep_8616(root):
                        if id(node) in suppressed_control_flow_nodes:
                            continue
                        _process_tail_validation_node_8616(
                            node,
                            project=project,
                            mode=mode,
                            observed_locations=observed_locations,
                            contextual_call_summaries=contextual_call_summaries,
                            contextual_call_fingerprints=contextual_call_fingerprints,
                            expected_helper_call_counts=expected_helper_call_counts,
                            contextual_condition_fingerprints=contextual_condition_fingerprints,
                            normalized_loop_conditions=normalized_loop_conditions,
                            canonical_loop_node_ids=canonical_loop_node_ids,
                            canonical_loop_body_suppressed_write_ids=(
                                canonical_loop_body_suppressed_write_ids
                            ),
                            prunable_segment_write_ids=prunable_segment_write_ids,
                            helper_calls=helper_calls,
                            helper_call_node_ids=helper_call_node_ids,
                            helper_callsite_keys=helper_callsite_keys,
                            helper_callsite_fingerprints=helper_callsite_fingerprints,
                            register_writes=register_writes,
                            stack_writes=stack_writes,
                            global_writes=global_writes,
                            segmented_writes=segmented_writes,
                            returns=returns,
                            conditions=conditions,
                            control_flow_effects=control_flow_effects,
                        )
                        _maybe_add_coarse_conditions_8616(node, project, conditions, mode)
                selector_returns = collect_selector_return_fingerprints_8616(
                    root,
                    condition_fingerprint=lambda condition: contextual_condition_fingerprints.get(
                        id(condition), _expr_fingerprint(condition, project)
                    ),
                    return_fingerprint=lambda value: _expr_fingerprint(value, project),
                )
                codegen._inertia_tail_validation_selector_return_stats_8616 = selector_returns.stats
                if selector_returns.stats.failure_count:
                    raise PipelineHardError(
                        "classified selector-return validation evidence was not materialized",
                        layer="tail_validation",
                        function_addr=func_addr if isinstance(func_addr, int) else None,
                    )
                control_flow_effects.update(selector_returns.fingerprints)
                if split_tail_return_call_fingerprints:
                    returns.discard("none")
                    returns.update(split_tail_return_call_fingerprints)
                with span("x86_16.tail_validation.summary.finalize", function=func_addr):
                    _append_missing_contextual_callsite_fingerprints_8616(
                        root,
                        project,
                        helper_calls,
                        summary_inventory,
                    )
                    canonical_segmented_writes = _canonicalize_segmented_write_aliases_8616(
                        segmented_writes,
                        global_writes,
                    )
                    capped_helper_calls = _cap_helper_call_fingerprints_to_expected_8616(
                        project,
                        helper_calls,
                        expected_helper_call_counts,
                    )
                return X86_16TailValidationSummary(
                    helper_calls=capped_helper_calls,
                    register_writes=_sorted_unique(register_writes),
                    stack_writes=_sorted_unique(stack_writes),
                    exposed_stack_values=observed_locations.write_fingerprints(),
                    global_writes=_sorted_unique(global_writes),
                    segmented_writes=_sorted_unique(canonical_segmented_writes),
                    returns=_sorted_unique(returns),
                    conditions=_sorted_unique(_compact_tail_validation_observables_8616("conditions", conditions)),
                    control_flow_effects=_sorted_unique(
                        _compact_tail_validation_observables_8616("control_flow_effects", control_flow_effects)
                    ),
                    def_use_issues=def_use_report.semantic_issue_tokens(),
                    missing_required_calls=required_call_report.missing_calls,
                    callsite_multiplicity_issues=callsite_multiplicity_report.issue_tokens(),
                    call_interface_issues=call_interface_report.issue_tokens(),
                    call_argument_class_issues=call_argument_class_report.issue_tokens(),
                    function_parameter_issues=function_parameter_report.issue_tokens(),
                    function_return_class_issues=function_return_class_report.issue_tokens(),
                    control_flow_issues=control_flow_report.issue_tokens(),
                    storage_identity_issues=storage_identity_report.issue_tokens(),
                )
            finally:
                if previous_snapshot_expr_cache is None:
                    with contextlib.suppress(Exception):
                        delattr(project, "_inertia_tail_validation_snapshot_expr_cache_enabled_8616")
                else:
                    project._inertia_tail_validation_snapshot_expr_cache_enabled_8616 = previous_snapshot_expr_cache
                if previous_active_codegen is None:
                    with contextlib.suppress(Exception):
                        delattr(project, "_inertia_tail_validation_active_codegen")
                else:
                    project._inertia_tail_validation_active_codegen = previous_active_codegen

        cached = resolve_x86_16_validation_cached_artifact(
            cache=entries if isinstance(entries, dict) else None,
            descriptor=descriptor,
            build=_build_summary,
        )
        summary = cached["value"]
        if not isinstance(summary, X86_16TailValidationSummary):
            raise TypeError("tail-validation summary cache must contain X86_16TailValidationSummary")
        if isinstance(boundary_entries, dict) and boundary_cache_key is not None:
            if len(boundary_entries) >= 32:
                boundary_entries.pop(next(iter(boundary_entries)))
            boundary_entries[boundary_cache_key] = summary
        return _finish_summary(
            summary,
            cache_hit=bool(cached["cache_hit"]),
            cache_key=str(cached["cache_key"]),
        )

    return _impl()


def _tail_validation_return_precision_improvement_8616(
    field_name: str,
    *,
    added: tuple[str, ...],
    removed: tuple[str, ...],
) -> bool:
    if field_name != "returns" or not added or not removed:
        return False
    imprecise_prefixes = ("virtual:", "expr_cycle", "alias_cycle")
    if any(not value.startswith(imprecise_prefixes) for value in removed):
        return False
    concrete_prefixes = (
        "const:",
        "stack_slot:",
        "Add(",
        "Sub(",
        "Mul(",
        "And(",
        "Or(",
        "Xor(",
        "Cmp",
    )
    return all(value.startswith(concrete_prefixes) for value in added)


def _tail_validation_linear_ds_write_offset_8616(location: str) -> int | None:
    """Return the DS-relative byte offset from an accepted write fingerprint."""
    if not isinstance(location, str):
        return None
    direct_match = re.fullmatch(r"deref:ds:0x([0-9a-fA-F]+)", location)
    if direct_match is not None:
        return int(direct_match.group(1), 16)
    match = re.fullmatch(r"deref:Add\(Mul\(reg:ds,const:16\),const:(-?[0-9]+)\)", location)
    if match is not None:
        offset = int(match.group(1), 10)
        return offset if offset >= 0 else None
    match = re.fullmatch(r"deref:Add\(Add\(Mul\(reg:ds,const:16\),const:(-?[0-9]+)\),const:(-?[0-9]+)\)", location)
    if match is None:
        return None
    offset = int(match.group(1), 10) + int(match.group(2), 10)
    return offset if offset >= 0 else None


def _tail_validation_ds_global_write_offset_8616(location: str) -> int | None:
    """Return the offset from Condition IR's canonical DS-global identity."""
    if not isinstance(location, str):
        return None
    canonical_location = canonicalize_condition_storage_fingerprint_8616(location)
    match = re.fullmatch(r"ds_global:0x([0-9a-fA-F]+)", canonical_location)
    if match is None:
        return None
    return int(match.group(1), 16)


def _suppress_global_linear_ds_write_precision_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Suppress only proven DS/global write-location precision aliases."""
    delta = diff.get("delta")
    if not isinstance(delta, dict):
        return
    global_delta = delta.get("global_writes")
    segmented_delta = delta.get("segmented_writes")
    if not isinstance(global_delta, dict) or not isinstance(segmented_delta, dict):
        return

    def _suppress(global_key: str, segmented_key: str) -> bool:
        global_values = _boundary_set_8616(global_delta.get(global_key, ()) or ())
        segmented_values = _boundary_set_8616(segmented_delta.get(segmented_key, ()) or ())
        if not global_values or not segmented_values:
            return False
        changed = False
        global_by_offset = {
            offset: location
            for location in global_values
            if isinstance((offset := _tail_validation_ds_global_write_offset_8616(location)), int)
        }
        segmented_by_offset: dict[int, set[str]] = {}
        for location in segmented_values:
            offset = _tail_validation_linear_ds_write_offset_8616(location)
            if isinstance(offset, int):
                segmented_by_offset.setdefault(offset, set()).add(location)
        byte_expanded_word_bases = {
            offset
            for offset in global_by_offset
            if offset + 1 in global_by_offset and offset in segmented_by_offset and offset + 1 in segmented_by_offset
        }
        for word_base in sorted(byte_expanded_word_bases):
            high_global = global_by_offset.get(word_base + 1)
            if high_global in global_values:
                global_values.remove(high_global)
            changed = True
        for global_location in tuple(global_values):
            global_base = _tail_validation_ds_global_write_offset_8616(global_location)
            if not isinstance(global_base, int):
                continue
            if global_base in byte_expanded_word_bases:
                continue
            matching_segmented = {
                location
                for location in segmented_values
                if _tail_validation_linear_ds_write_offset_8616(location)
                in {global_base, global_base + 1}
            }
            if not any(
                _tail_validation_linear_ds_write_offset_8616(location)
                == global_base
                for location in matching_segmented
            ):
                continue
            global_values.remove(global_location)
            segmented_values.difference_update(matching_segmented)
            changed = True
        if changed:
            global_delta[global_key] = tuple(sorted(global_values))
            segmented_delta[segmented_key] = tuple(sorted(segmented_values))
        return changed

    _suppress("added", "removed")
    _suppress("removed", "added")


def compare_x86_16_tail_validation_summaries(
    before: X86_16TailValidationSummary,
    after: X86_16TailValidationSummary,
) -> dict[str, TailValidationValue]:
    """Compare two tail-validation summaries and return normalized deltas."""
    changed = False
    precision_improvements: dict[str, TailValidationValue] = {}
    before_fields = before.as_dict()
    after_fields = after.as_dict()
    diff: dict[str, TailValidationValue] = {
        "changed": False,
        "before": before_fields,
        "after": after_fields,
        "delta": {},
        "precision_improvements": precision_improvements,
    }
    for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
        before_field = before_fields[field_name]
        after_field = after_fields[field_name]
        if field_name == "helper_calls":
            before_counter = _canonicalize_summary_field_counter_8616(field_name, before_field)
            after_counter = _canonicalize_summary_field_counter_8616(field_name, after_field)
            added = _counter_delta_items_8616(after_counter, before_counter)
            removed = _counter_delta_items_8616(before_counter, after_counter)
            missing_callsite_fingerprints = _missing_callsite_fingerprints_8616(after_field)
            if missing_callsite_fingerprints:
                removed = tuple(dict.fromkeys(tuple(removed) + missing_callsite_fingerprints))
        else:
            before_values = canonicalize_tail_validation_summary_field_values_8616(
                field_name, _boundary_set_8616(before_field)
            )
            after_values = canonicalize_tail_validation_summary_field_values_8616(
                field_name, _boundary_set_8616(after_field)
            )
            added = tuple(sorted(after_values - before_values))
            removed = tuple(sorted(before_values - after_values))
        if _tail_validation_return_precision_improvement_8616(field_name, added=added, removed=removed):
            precision_improvements[field_name] = {"added": added, "removed": removed}
            added = ()
            removed = ()
        if added or removed:
            changed = True
        diff["delta"][field_name] = {"added": added, "removed": removed}
    _suppress_global_linear_ds_write_precision_delta_8616(diff)
    _suppress_switch_helper_structuring_precision_delta_8616(diff)
    _suppress_structuring_callsite_target_local_int_precision_delta_8616(diff)
    _suppress_void_return_loop_exit_guard_structuring_delta_8616(diff)
    _suppress_loop_continue_exit_guard_inverse_structuring_delta_8616(diff)
    _suppress_if_else_inverse_guard_structuring_delta_8616(diff)
    _suppress_if_body_call_membership_structuring_delta_8616(diff)
    _suppress_helper_calls_accounted_by_control_body_calls_8616(diff)
    _suppress_helper_calls_accounted_by_conditions_8616(diff)
    _suppress_loop_condition_call_result_carrier_delta_8616(diff)
    _suppress_flags_register_write_condition_transfer_delta_8616(diff)
    _suppress_void_return_loop_call_feeder_delta_8616(diff)
    _suppress_straight_line_local_stack_write_precision_delta_8616(diff)
    _suppress_loop_body_local_stack_write_precision_delta_8616(diff)
    _suppress_local_stack_abi_int_width_delta_8616(diff)
    _suppress_signed_i16_return_else_structuring_delta_8616(diff)
    _suppress_typed_stack_condition_storage_delta_8616(diff)
    changed = any(
        bool((field_delta.get("added", ()) or ()) or (field_delta.get("removed", ()) or ()))
        for field_delta in diff["delta"].values()
        if isinstance(field_delta, dict)
    )
    semantic_failures = collect_tail_semantic_failures_8616(
        after,
        before=before,
        scope=TailSemanticFailureScope8616.INTRODUCED,
    )
    if semantic_failures:
        diff["semantic_failures"] = semantic_failures
        changed = True
    diff["changed"] = changed
    diff["status"] = "failed" if semantic_failures else ("changed" if changed else "stable")
    return diff


def _suppress_typed_stack_condition_storage_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify a typed local-store condition replacing a wider global alias.

    The branch validator separately proves the final predicate against ConditionIR
    and the call-return store. This comparison rule only removes the corresponding
    representation delta when every other observable field is unchanged.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    condition_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    if not isinstance(condition_delta, dict) or not isinstance(control_delta, dict):
        return
    added = tuple(str(value) for value in condition_delta.get("added", ()) or ())
    removed = tuple(str(value) for value in condition_delta.get("removed", ()) or ())
    control_added = tuple(str(value) for value in control_delta.get("added", ()) or ())
    control_removed = tuple(str(value) for value in control_delta.get("removed", ()) or ())
    if len(added) != len(removed) != len(control_added) != len(control_removed) or len(added) != 1:
        return
    if "stack_slot:SS:BP-" not in added[0] or "ds_global:" not in removed[0]:
        return
    added_condition = _canonicalize_structuring_precision_condition_text_8616(added[0])
    removed_condition = _canonicalize_structuring_precision_condition_text_8616(removed[0])
    if added_condition == removed_condition:
        return
    if not any(added_condition in value for value in control_added):
        return
    if not any(removed_condition in value for value in control_removed):
        return
    for field_name, field_delta in delta.items():
        if field_name in {"conditions", "control_flow_effects"}:
            continue
        if not isinstance(field_delta, dict) or field_delta.get("added", ()) or field_delta.get("removed", ()):
            return
    precision["typed_stack_condition_storage"] = {
        "conditions": {"added": added, "removed": removed},
        "control_flow_effects": {"added": control_added, "removed": control_removed},
    }
    condition_delta["added"] = ()
    condition_delta["removed"] = ()
    control_delta["added"] = ()
    control_delta["removed"] = ()




def _control_body_call_addr_tokens_8616(values: Sequence[str]) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        if "-body-calls:" not in str(value):
            continue
        tokens.update(re.findall(r"(?<![A-Za-z0-9_])addr:0x[0-9a-fA-F]+", str(value)))
    return tokens


def _control_body_call_token_counter_8616(values: Sequence[str]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for value in values:
        split = _split_control_flow_body_call_effect_8616(str(value))
        if split is None:
            continue
        _prefix, calls = split
        for call in calls:
            counter[_canonicalize_helper_call_fingerprint_for_compare_8616(call)] += 1
    return counter


def _is_control_body_call_fingerprint_token_8616(value: str) -> bool:
    if value in {"<indirect>", "name:<indirect>", "<unknown-call>"}:
        return True
    return value.startswith(("addr:", "name:"))


def _split_control_flow_body_call_effect_8616(value: str) -> tuple[str, tuple[str, ...]] | None:
    if "-body-calls:" not in value:
        return None
    depth = 0
    for idx, char in enumerate(value):
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth = max(0, depth - 1)
            continue
        if char != ":" or depth != 0:
            continue
        payload = value[idx + 1 :]
        calls = tuple(part for part in payload.split(",") if part)
        if calls and all(_is_control_body_call_fingerprint_token_8616(call) for call in calls):
            return value[: idx + 1], calls
    return None


def _canonicalize_structuring_precision_condition_text_8616(value: str) -> str:
    value = _canonicalize_local_stack_abi_int_width_8616(value)

    def _replace_linear_ds(match: re.Match[str]) -> str:
        return f"ds_global:{int(match.group('offset'), 10):#x}"

    return re.sub(
        r"Dereference\(Add\(Mul\(reg:ds,const:16\),const:(?P<offset>\d+)\)\)",
        _replace_linear_ds,
        value,
    )


def _canonicalize_structuring_precision_effect_8616(value: str) -> str | None:
    value = _canonicalize_embedded_helper_call_tokens_for_compare_8616(
        _canonicalize_structuring_precision_condition_text_8616(value)
    )
    if "-body-writes:" in value:
        if value.endswith(":reg:ax"):
            return None
        if value.endswith(",reg:ax"):
            value = value[: -len(",reg:ax")]
    split = _split_control_flow_loop_body_write_effect_8616(value)
    if split is None:
        return value
    prefix, locations = split
    kept_locations = tuple(location for location in locations if location != "reg:ax")
    if not kept_locations:
        return None
    return f"{prefix}{','.join(kept_locations)}"


def _canonicalize_structuring_precision_counter_8616(values: Sequence[str]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for value in values:
        canonical = _canonicalize_structuring_precision_effect_8616(str(value))
        if canonical is not None:
            counter[canonical] += 1
    return counter


def _suppress_structuring_callsite_target_local_int_precision_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify structuring-only precision when the same loop helper remains.

    This comparison accepts a narrow before/after bundle produced when
    structuring replaces an unstructured callsite identity with the resolved
    helper target while also narrowing source-backed DOS ``int`` locals from
    host size4 to x86-16 size2.  It refuses global, segmented, return, or
    unrelated helper changes, so true call loss remains a validation failure.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    allowed_fields = {"helper_calls", "register_writes", "stack_writes", "conditions", "control_flow_effects"}
    suppressed: dict[str, dict[str, tuple[str, ...]]] = {}
    for field_name, field_delta in delta.items():
        if not isinstance(field_delta, dict):
            return
        added = _boundary_tuple_8616(str(value) for value in _boundary_tuple_8616(field_delta.get("added", ()) or ()))
        removed = _boundary_tuple_8616(
            str(value) for value in _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
        if not added and not removed:
            continue
        if field_name not in allowed_fields:
            return
        suppressed[field_name] = {"added": added, "removed": removed}

    helper_delta = suppressed.get("helper_calls")
    control_delta = suppressed.get("control_flow_effects")
    if helper_delta is None or control_delta is None:
        return
    helper_added = helper_delta["added"]
    helper_removed = helper_delta["removed"]
    if any(value not in {"<indirect>", "name:<indirect>"} and not value.startswith("addr:") for value in helper_added):
        return
    if any(not value.startswith("addr:") for value in helper_removed):
        return
    control_added = control_delta["added"]
    control_removed = control_delta["removed"]
    body_targets = _control_body_call_addr_tokens_8616(control_added) & _control_body_call_addr_tokens_8616(
        control_removed
    )
    if not body_targets:
        return
    if not any(value in body_targets for value in helper_added):
        return

    register_delta = suppressed.get("register_writes")
    if register_delta is not None:  # noqa: SIM102
        if register_delta["added"] or any(value != "reg:ax" for value in register_delta["removed"]):
            return

    stack_delta = suppressed.get("stack_writes")
    if stack_delta is not None:
        added_stack = stack_delta["added"]
        removed_stack = stack_delta["removed"]
        if any(not value.startswith("stack_slot:SS:BP-") for value in added_stack + removed_stack):
            return
        removed_canonical = Counter(_canonicalize_local_stack_abi_int_width_8616(value) for value in removed_stack)
        added_canonical = Counter(_canonicalize_local_stack_abi_int_width_8616(value) for value in added_stack)
        if any(count > added_canonical.get(key, 0) for key, count in removed_canonical.items()):
            return

    condition_delta = suppressed.get("conditions")
    if condition_delta is not None:
        added_conditions = Counter(
            _canonicalize_structuring_precision_condition_text_8616(value) for value in condition_delta["added"]
        )
        removed_conditions = Counter(
            _canonicalize_structuring_precision_condition_text_8616(value) for value in condition_delta["removed"]
        )
        if added_conditions != removed_conditions:
            return

    if _canonicalize_structuring_precision_counter_8616(control_added) != (
        _canonicalize_structuring_precision_counter_8616(control_removed)
    ):
        return

    precision["structuring_callsite_target_local_int_precision"] = suppressed
    for field_name in suppressed:
        field_delta = delta.get(field_name)
        if isinstance(field_delta, dict):
            field_delta["added"] = ()
            field_delta["removed"] = ()


def _suppress_void_return_loop_exit_guard_structuring_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify while(true)+void-exit guard normalization.

    Structuring can turn ``while (true) { if (exit) return; body; }`` into a
    structured loop with the inverted condition.  Tail validation should compare
    the same helper call in that loop body, not treat the removed synthetic void
    return as call loss.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    allowed_fields = {"helper_calls", "returns", "conditions", "control_flow_effects"}
    suppressed: dict[str, dict[str, tuple[str, ...]]] = {}
    for field_name, field_delta in delta.items():
        if not isinstance(field_delta, dict):
            return
        added = _boundary_tuple_8616(str(value) for value in _boundary_tuple_8616(field_delta.get("added", ()) or ()))
        removed = _boundary_tuple_8616(
            str(value) for value in _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
        if not added and not removed:
            continue
        if field_name not in allowed_fields:
            return
        suppressed[field_name] = {"added": added, "removed": removed}

    helper_delta = suppressed.get("helper_calls")
    return_delta = suppressed.get("returns")
    condition_delta = suppressed.get("conditions")
    control_delta = suppressed.get("control_flow_effects")
    if (
        not isinstance(helper_delta, dict)
        or not isinstance(return_delta, dict)
        or not isinstance(condition_delta, dict)
        or not isinstance(control_delta, dict)
    ):
        return
    helper_added = helper_delta["added"]
    helper_removed = helper_delta["removed"]
    if helper_added or not helper_removed or any(not value.startswith("addr:") for value in helper_removed):
        return
    helper_targets = set(helper_removed)
    if len(helper_targets) != 1:
        return
    helper_target = next(iter(helper_targets))
    if return_delta["added"] or return_delta["removed"] != ("none",):
        return

    condition_added = tuple(value for value in condition_delta["added"] if value != "const:True")
    condition_removed = tuple(value for value in condition_delta["removed"] if value != "const:True")
    if len(condition_added) != 1 or len(condition_removed) != 1:
        return
    added_condition = normalize_condition_fingerprint_string_8616(condition_added[0])
    removed_condition = normalize_condition_fingerprint_string_8616(condition_removed[0])
    inverted_removed = invert_condition_fingerprint_string_8616(removed_condition)
    if normalize_condition_fingerprint_string_8616(inverted_removed or "") != added_condition:
        return
    if "const:True" not in condition_delta["removed"]:
        return

    control_added = set(control_delta["added"])
    control_removed = set(control_delta["removed"])
    expected_added = {
        f"while:{added_condition}",
        f"while-body-calls:{added_condition}:{helper_target}",
    }
    expected_removed = {
        f"if:{removed_condition}",
        "return",
        "while:const:True",
        f"while-body-calls:const:True:{helper_target}",
    }
    if control_added != expected_added or control_removed != expected_removed:
        return

    precision["void_return_loop_exit_guard_structuring"] = suppressed
    for field_name in suppressed:
        field_delta = delta.get(field_name)
        if isinstance(field_delta, dict):
            field_delta["added"] = ()
            field_delta["removed"] = ()


def _suppress_loop_continue_exit_guard_inverse_structuring_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify loop continue guard vs machine exit-branch guard inversion.

    A structured loop commonly prints the condition for continuing the loop
    body, while the machine branch at the same boundary may be the inverted
    exit guard.  This is a validation-layer comparison rule only: it refuses if
    any helper, return, memory, or non-AX register effect changed.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return

    condition_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    register_delta = delta.get("register_writes")
    if not isinstance(condition_delta, dict) or not isinstance(control_delta, dict):
        return
    condition_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(condition_delta.get("added", ()) or ())
    )
    condition_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(condition_delta.get("removed", ()) or ())
    )
    control_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("added", ()) or ())
    )
    control_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    )
    if len(condition_added) != 1 or len(condition_removed) != 1:
        return
    if control_added != (f"if:{condition_added[0]}",) or control_removed != (f"if:{condition_removed[0]}",):
        return

    added_condition = normalize_condition_fingerprint_string_8616(condition_added[0])
    removed_condition = normalize_condition_fingerprint_string_8616(condition_removed[0])
    inverted_removed = invert_condition_fingerprint_string_8616(removed_condition)
    if normalize_condition_fingerprint_string_8616(inverted_removed or "") != added_condition:
        return

    suppressed: dict[str, dict[str, tuple[str, ...]]] = {
        "conditions": {"added": condition_added, "removed": condition_removed},
        "control_flow_effects": {"added": control_added, "removed": control_removed},
    }
    if isinstance(register_delta, dict):
        register_added = _boundary_tuple_8616(
            str(value) for value in _boundary_tuple_8616(register_delta.get("added", ()) or ())
        )
        register_removed = _boundary_tuple_8616(
            str(value) for value in _boundary_tuple_8616(register_delta.get("removed", ()) or ())
        )
        if register_removed or any(value != "reg:ax" for value in register_added):
            return
        if register_added:
            suppressed["register_writes"] = {"added": register_added, "removed": register_removed}

    for field_name, field_delta in delta.items():
        if field_name in suppressed:
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return

    precision["loop_continue_exit_guard_inverse_structuring"] = suppressed
    for field_name in suppressed:
        field_delta = delta.get(field_name)
        if isinstance(field_delta, dict):
            field_delta["added"] = ()
            field_delta["removed"] = ()


def _suppress_if_else_inverse_guard_structuring_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify an empty-then inverse guard folded into one direct if body.

    angr may initially represent ``if (x == 0) {} else { call(); }`` and later
    structure the same branch as ``if (x != 0) { call(); }``. This comparison
    rule accepts only that exact inverse-guard shape with identical calls and
    no other observable delta. It does not mutate or recover control flow.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    before = diff.get("before")
    after = diff.get("after")
    if (
        not isinstance(delta, dict)
        or not isinstance(precision, dict)
        or not isinstance(before, Mapping)
        or not isinstance(after, Mapping)
    ):
        return

    condition_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    helper_delta = delta.get("helper_calls")
    if not isinstance(condition_delta, dict) or not isinstance(control_delta, dict) or not isinstance(helper_delta, dict):
        return
    if helper_delta.get("added", ()) or helper_delta.get("removed", ()):
        return
    if _canonicalize_summary_field_counter_8616("helper_calls", before.get("helper_calls", ()) or ()) != (
        _canonicalize_summary_field_counter_8616("helper_calls", after.get("helper_calls", ()) or ())
    ):
        return

    condition_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(condition_delta.get("added", ()) or ())
    )
    condition_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(condition_delta.get("removed", ()) or ())
    )
    if len(condition_removed) != 1 or len(condition_added) > 1:
        return
    removed_condition = normalize_condition_fingerprint_string_8616(condition_removed[0])
    inverted_condition = normalize_condition_fingerprint_string_8616(
        invert_condition_fingerprint_string_8616(removed_condition) or ""
    )
    if not inverted_condition:
        return

    before_conditions = canonicalize_tail_validation_summary_field_values_8616(
        "conditions", {str(value) for value in before.get("conditions", ()) or ()}
    )
    after_conditions = canonicalize_tail_validation_summary_field_values_8616(
        "conditions", {str(value) for value in after.get("conditions", ()) or ()}
    )
    if removed_condition not in before_conditions or removed_condition in after_conditions:
        return
    if inverted_condition not in after_conditions:
        return
    if condition_added and condition_added != (inverted_condition,):
        return
    if not condition_added and inverted_condition not in before_conditions:
        return

    control_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("added", ()) or ())
    )
    control_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    )
    removed_else_effects = tuple(
        value for value in control_removed if value.startswith("if-else-body-calls:else:")
    )
    if len(removed_else_effects) != 1:
        return
    split_else = _split_control_flow_body_call_effect_8616(removed_else_effects[0])
    if split_else is None:
        return
    _else_prefix, else_calls = split_else
    expected_added_body = f"if-body-calls:{inverted_condition}:{','.join(else_calls)}"
    expected_removed = {
        f"if:{removed_condition}",
        "if:else",
        removed_else_effects[0],
    }
    if set(control_removed) != expected_removed:
        return
    if set(control_added) not in ({expected_added_body}, {f"if:{inverted_condition}", expected_added_body}):
        return

    before_control = canonicalize_tail_validation_summary_field_values_8616(
        "control_flow_effects", {str(value) for value in before.get("control_flow_effects", ()) or ()}
    )
    after_control = canonicalize_tail_validation_summary_field_values_8616(
        "control_flow_effects", {str(value) for value in after.get("control_flow_effects", ()) or ()}
    )
    if expected_added_body not in after_control:
        return
    if f"if:{inverted_condition}" not in after_control:
        return
    if f"if:{inverted_condition}" not in control_added and f"if:{inverted_condition}" not in before_control:
        return

    suppressed: dict[str, dict[str, tuple[str, ...]]] = {
        "conditions": {"added": condition_added, "removed": condition_removed},
        "control_flow_effects": {"added": control_added, "removed": control_removed},
    }
    for field_name, field_delta in delta.items():
        if field_name in suppressed:
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return

    precision["if_else_inverse_guard_structuring"] = suppressed
    for field_name in suppressed:
        field_delta = delta.get(field_name)
        if isinstance(field_delta, dict):
            field_delta["added"] = ()
            field_delta["removed"] = ()


def _suppress_if_body_call_membership_structuring_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify an if-body call membership refinement with no call-count change.

    The pre-structuring surface can know a branch condition and all helper
    calls, but only associate the first call with the branch body.  After
    structuring, the same condition may own a larger body-call set, as in
    ``if (fSound) { Beep(); Sleep(); return; } Sleep();``.  This is accepted
    only when the complete helper-call multiset is unchanged and the delta is
    strictly an ``if-body-calls`` superset for the same condition prefix.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    before = diff.get("before")
    after = diff.get("after")
    if (
        not isinstance(delta, dict)
        or not isinstance(precision, dict)
        or not isinstance(before, Mapping)
        or not isinstance(after, Mapping)
    ):
        return

    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, dict):
        return
    if _boundary_tuple_8616(helper_delta.get("added", ()) or ()) or _boundary_tuple_8616(
        helper_delta.get("removed", ()) or ()
    ):
        return
    if _canonicalize_summary_field_counter_8616("helper_calls", before.get("helper_calls", ()) or ()) != (
        _canonicalize_summary_field_counter_8616("helper_calls", after.get("helper_calls", ()) or ())
    ):
        return

    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, dict):
        return
    control_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("added", ()) or ())
    )
    control_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    )
    if not control_added:
        if not control_removed:
            return
        if any(value != "if:else" and not value.startswith("if-else-body-calls:else:") for value in control_removed):
            return
        for field_name, field_delta in delta.items():
            if field_name in {"helper_calls", "control_flow_effects"}:
                continue
            if not isinstance(field_delta, dict):
                return
            if field_delta.get("added", ()) or field_delta.get("removed", ()):
                return
        helper_counter = _canonicalize_summary_field_counter_8616("helper_calls", before.get("helper_calls", ()) or ())
        removed_else_calls: Counter[str] = Counter()
        for value in control_removed:
            if not value.startswith("if-else-body-calls:else:"):
                continue
            calls = value.removeprefix("if-else-body-calls:else:").split(",")
            removed_else_calls.update(
                _canonicalize_helper_call_fingerprint_for_compare_8616(call) for call in calls if call
            )
        if any(count > helper_counter.get(call, 0) for call, count in removed_else_calls.items()):
            return
        precision["if_else_body_membership_structuring"] = {
            "control_flow_effects": {"added": control_added, "removed": control_removed}
        }
        control_delta["added"] = ()
        control_delta["removed"] = ()
        return
    if any(not value.startswith("if-body-calls:") for value in control_added + control_removed):
        return

    for field_name, field_delta in delta.items():
        if field_name in {"helper_calls", "control_flow_effects"}:
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return

    added_parts = [_split_control_flow_body_call_effect_8616(value) for value in control_added]
    removed_parts = [_split_control_flow_body_call_effect_8616(value) for value in control_removed]
    if any(item is None for item in added_parts + removed_parts):
        return
    normalized_added_parts = [item for item in added_parts if item is not None]
    normalized_removed_parts = [item for item in removed_parts if item is not None]
    if not control_removed:
        helper_counter = _canonicalize_summary_field_counter_8616("helper_calls", after.get("helper_calls", ()) or ())
        added_call_counter: Counter[str] = Counter()
        for _added_prefix, added_calls in normalized_added_parts:
            added_call_counter.update(
                _canonicalize_helper_call_fingerprint_for_compare_8616(call) for call in added_calls
            )
        if any(count > helper_counter.get(call, 0) for call, count in added_call_counter.items()):
            return
        precision["if_body_call_membership_structuring"] = {
            "control_flow_effects": {"added": control_added, "removed": control_removed}
        }
        control_delta["added"] = ()
        control_delta["removed"] = ()
        return

    used_added: set[int] = set()
    for removed_prefix, removed_calls in normalized_removed_parts:
        removed_counter = Counter(removed_calls)
        match_idx = None
        for idx, added_item in enumerate(normalized_added_parts):
            if idx in used_added:
                continue
            added_prefix, added_calls = added_item
            if added_prefix != removed_prefix:
                continue
            added_counter = Counter(added_calls)
            if not removed_counter or any(
                count > added_counter.get(call, 0) for call, count in removed_counter.items()
            ):
                continue
            if added_counter == removed_counter:
                continue
            match_idx = idx
            break
        if match_idx is None:
            return
        used_added.add(match_idx)
    if len(used_added) != len(added_parts):
        return

    precision["if_body_call_membership_structuring"] = {
        "control_flow_effects": {"added": control_added, "removed": control_removed}
    }
    control_delta["added"] = ()
    control_delta["removed"] = ()


def _suppress_helper_calls_accounted_by_control_body_calls_8616(diff: dict[str, TailValidationValue]) -> None:
    """Suppress top-level helper-call accounting loss when body-call evidence remains.

    Some postprocess cleanup can change how validation walks helper calls:
    top-level ``helper_calls`` may lose entries while the same calls remain in
    structured ``*-body-calls`` control-flow evidence.  This is comparison
    precision only.  It is accepted only when the helper delta has no additions,
    every removed call is still present in the after-summary body-call multiset,
    and all other observable fields are stable.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    after = diff.get("after")
    if not isinstance(delta, dict) or not isinstance(precision, dict) or not isinstance(after, Mapping):
        return

    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, dict):
        return
    helper_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(helper_delta.get("added", ()) or ())
    )
    helper_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(helper_delta.get("removed", ()) or ())
    )
    if helper_added or not helper_removed:
        return

    for field_name, field_delta in delta.items():
        if field_name == "helper_calls":
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return

    after_control_counter = _control_body_call_token_counter_8616(after.get("control_flow_effects", ()) or ())
    removed_counter = Counter(_canonicalize_helper_call_fingerprint_for_compare_8616(value) for value in helper_removed)
    if not after_control_counter:
        return
    if any(count > after_control_counter.get(call, 0) for call, count in removed_counter.items()):
        return

    precision["helper_calls_accounted_by_control_body_calls"] = {
        "helper_calls": {"added": helper_added, "removed": helper_removed}
    }
    helper_delta["added"] = ()
    helper_delta["removed"] = ()


def _control_body_call_effect_without_calls_8616(value: str, removed_calls: set[str]) -> str | None:
    """Return a body-call effect fingerprint with selected helper calls removed."""
    split = _split_control_flow_body_call_effect_8616(value)
    if split is None:
        return None
    prefix, calls = split
    kept = tuple(
        call for call in calls if _canonicalize_helper_call_fingerprint_for_compare_8616(call) not in removed_calls
    )
    return f"{prefix}{','.join(kept)}" if kept else None


def _canonical_control_flow_effect_for_compare_8616(value: str) -> str:
    """Return the canonical validation-comparison form for one control-flow effect."""
    split = _split_control_flow_body_call_effect_8616(value)
    if split is not None:
        prefix, calls = split
        normalized_calls = tuple(_canonicalize_helper_call_fingerprint_for_compare_8616(call) for call in calls)
        if prefix.endswith(":") and ":" in prefix[:-1]:
            kind, condition = prefix[:-1].split(":", 1)
            normalized_condition = _canonicalize_condition_fingerprint_for_compare_8616(condition)
            return f"{kind}:{normalized_condition}:{','.join(normalized_calls)}"
        return f"{prefix}{','.join(normalized_calls)}"
    write_split = _split_control_flow_loop_body_write_effect_8616(value)
    if write_split is not None:
        prefix, locations = write_split
        normalized_locations: list[str] = []
        for location in locations:
            canonical_location = _canonicalize_segmented_write_fingerprint_for_compare_8616(location)
            offset = _tail_validation_ds_global_write_offset_8616(canonical_location)
            if offset is None:
                offset = _tail_validation_linear_ds_write_offset_8616(canonical_location)
            normalized_location = f"ds_global:{offset:#x}" if offset is not None else canonical_location
            if normalized_location not in normalized_locations:
                normalized_locations.append(normalized_location)
        if prefix.endswith(":") and ":" in prefix[:-1]:
            kind, condition = prefix[:-1].split(":", 1)
            normalized_condition = _canonicalize_condition_fingerprint_for_compare_8616(condition)
            return f"{kind}:{normalized_condition}:{','.join(sorted(normalized_locations))}"
        return f"{prefix}{','.join(sorted(normalized_locations))}"
    normalized_control_flow = _canonicalize_condition_fingerprint_for_compare_8616(value)
    normalized_control_flow = _canonicalize_embedded_helper_call_tokens_for_compare_8616(normalized_control_flow)
    return normalized_control_flow


def _suppress_helper_calls_accounted_by_conditions_8616(diff: dict[str, TailValidationValue]) -> None:
    """Suppress helper-call loss when the same calls remain in condition evidence."""
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    after = diff.get("after")
    if not isinstance(delta, dict) or not isinstance(precision, dict) or not isinstance(after, Mapping):
        return

    helper_delta = delta.get("helper_calls")
    control_delta = delta.get("control_flow_effects")
    if not isinstance(helper_delta, dict) or not isinstance(control_delta, dict):
        return
    helper_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(helper_delta.get("added", ()) or ())
    )
    helper_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(helper_delta.get("removed", ()) or ())
    )
    if helper_added or not helper_removed:
        return

    for field_name, field_delta in delta.items():
        if field_name in {"helper_calls", "control_flow_effects"}:
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return

    removed_call_tokens = set(helper_removed)
    removed_calls = {_canonicalize_helper_call_fingerprint_for_compare_8616(value) for value in removed_call_tokens}
    after_condition_text = "\n".join(
        str(value)
        for value in _boundary_tuple_8616(after.get("conditions", ()) or ())
        + _boundary_tuple_8616(after.get("control_flow_effects", ()) or ())
    )
    if any(f"call:{helper}" not in after_condition_text for helper in removed_call_tokens):
        return

    control_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("added", ()) or ())
    )
    control_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    )
    after_controls = {
        _canonical_control_flow_effect_for_compare_8616(str(value))
        for value in _boundary_tuple_8616(after.get("control_flow_effects", ()) or ())
        if "-body-calls:" in str(value)
    }
    for removed_effect in control_removed:
        if "-body-calls:" not in removed_effect:
            return
        reduced = _control_body_call_effect_without_calls_8616(removed_effect, removed_calls)
        if reduced is not None and _canonical_control_flow_effect_for_compare_8616(reduced) not in after_controls:
            return
    for added_effect in control_added:
        if "-body-calls:" not in added_effect:
            return

    precision["helper_calls_accounted_by_conditions"] = {
        "helper_calls": {"added": helper_added, "removed": helper_removed},
        "control_flow_effects": {"added": control_added, "removed": control_removed},
    }
    helper_delta["added"] = ()
    helper_delta["removed"] = ()
    control_delta["added"] = ()
    control_delta["removed"] = ()


def _value_mentions_helper_target_8616(value: str, helper_target: str) -> bool:
    """Return whether a validation fingerprint references a helper target."""
    return helper_target in value or f"call:{helper_target}" in value


def _loop_body_write_effect_has_only_register_carriers_8616(value: str) -> bool:
    """Return whether a loop body-write effect contains only register carriers."""
    locations = _control_flow_loop_body_write_locations_8616(value)
    return locations is not None and all(location.startswith("reg:") for location in locations)


def _after_control_mentions_helper_as_loop_evidence_8616(after_controls: Sequence[str], helper_target: str) -> bool:
    """Return whether after-summary loop evidence still accounts for a helper."""
    return any(
        _value_mentions_helper_target_8616(value, helper_target)
        and ("-body-calls:" in value or value.startswith(("while:", "for:", "dowhile:", "do-while:")))
        for value in after_controls
    )


def _suppress_loop_condition_call_result_carrier_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify a call-result carrier disappearing into a structured loop condition.

    Structuring can turn ``while (true)`` plus a helper-backed compare carrier
    into cleaner loop evidence where the same helper remains in body-call or
    condition evidence.  This is comparison precision only: the removed helper
    must still be referenced by after-summary loop evidence, and removed body
    writes must be register-only call-result carriers.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    after = diff.get("after")
    if not isinstance(delta, dict) or not isinstance(precision, dict) or not isinstance(after, Mapping):
        return

    helper_delta = delta.get("helper_calls")
    condition_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    if (
        not isinstance(helper_delta, dict)
        or not isinstance(condition_delta, dict)
        or not isinstance(control_delta, dict)
    ):
        return

    helper_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(helper_delta.get("added", ()) or ())
    )
    helper_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(helper_delta.get("removed", ()) or ())
    )
    if helper_added or not helper_removed or any(not value.startswith("addr:") for value in helper_removed):
        return

    condition_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(condition_delta.get("added", ()) or ())
    )
    condition_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(condition_delta.get("removed", ()) or ())
    )
    control_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("added", ()) or ())
    )
    control_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    )

    after_controls = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(after.get("control_flow_effects", ()) or ())
    )
    for helper_target in helper_removed:
        if not _after_control_mentions_helper_as_loop_evidence_8616(after_controls, helper_target):
            return

    if not condition_added and not condition_removed:
        for value in control_added:
            if not (
                value.startswith(("while:", "for:", "dowhile:", "do-while:"))
                and any(
                    _value_mentions_helper_target_8616(value, helper_target)
                    for helper_target in helper_removed
                )
            ):
                return
        for value in control_removed:
            if value in {
                "while:const:True",
                "for:const:True",
                "dowhile:const:True",
                "do-while:const:True",
            }:
                continue
            if not _loop_body_write_effect_has_only_register_carriers_8616(value):
                return
    else:
        if len(condition_added) != 1:
            return
        added_condition = normalize_condition_fingerprint_string_8616(condition_added[0])
        condition_mentions_removed_helper = any(
            _value_mentions_helper_target_8616(added_condition, helper_target)
            for helper_target in helper_removed
        )
        if not condition_mentions_removed_helper and "call:" not in added_condition:
            return

        removed_nonconstant_conditions = tuple(value for value in condition_removed if value != "const:True")
        if len(removed_nonconstant_conditions) > 1:
            return
        removed_break_condition = (
            normalize_condition_fingerprint_string_8616(removed_nonconstant_conditions[0])
            if removed_nonconstant_conditions
            else None
        )
        if removed_break_condition is not None:
            inverted_break_condition = invert_condition_fingerprint_string_8616(removed_break_condition)
            if normalize_condition_fingerprint_string_8616(inverted_break_condition or "") != added_condition:
                return

        loop_kinds = ("while", "for", "dowhile", "do-while")
        added_loop_kinds = tuple(
            kind for kind in loop_kinds if f"{kind}:{added_condition}" in control_added
        )
        if len(added_loop_kinds) != 1:
            return
        loop_kind = added_loop_kinds[0]
        added_body_call_controls = {
            value
            for value in control_added
            if value.startswith(f"{loop_kind}-body-calls:{added_condition}:")
            and any(
                _value_mentions_helper_target_8616(value, helper_target) for helper_target in helper_removed
            )
        }
        if not condition_mentions_removed_helper and not added_body_call_controls:
            return
        allowed_added_controls = {f"{loop_kind}:{added_condition}"}
        allowed_added_controls.update(added_body_call_controls)
        if set(control_added) != allowed_added_controls:
            return

        if removed_break_condition is None:
            allowed_removed_controls = {f"{loop_kind}:const:True"}
        else:
            required_removed_controls = {
                f"{loop_kind}:const:True",
                f"ifbreak:{removed_break_condition}",
            }
            if not required_removed_controls.issubset(control_removed):
                return
            allowed_removed_controls = set(required_removed_controls)
        allowed_removed_controls.update(
            value
            for value in control_removed
            if value.startswith(f"{loop_kind}-body-calls:const:True:")
            and any(
                _value_mentions_helper_target_8616(value, helper_target) for helper_target in helper_removed
            )
        )
        allowed_removed_controls.update(
            value
            for value in control_removed
            if _loop_body_write_effect_has_only_register_carriers_8616(value)
        )
        if set(control_removed) != allowed_removed_controls:
            return

    for field_name, field_delta in delta.items():
        if field_name in {"helper_calls", "conditions", "control_flow_effects"}:
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return

    precision["loop_condition_call_result_carrier_structuring"] = {
        "helper_calls": {"added": helper_added, "removed": helper_removed},
        "conditions": {"added": condition_added, "removed": condition_removed},
        "control_flow_effects": {"added": control_added, "removed": control_removed},
    }
    helper_delta["added"] = ()
    helper_delta["removed"] = ()
    condition_delta["added"] = ()
    condition_delta["removed"] = ()
    control_delta["added"] = ()
    control_delta["removed"] = ()


def _suppress_flags_register_write_condition_transfer_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    register_delta = delta.get("register_writes")
    if not isinstance(register_delta, dict):
        return
    added = _boundary_tuple_8616(register_delta.get("added", ()) or ())
    removed = _boundary_tuple_8616(register_delta.get("removed", ()) or ())
    if added or removed != ("reg:flags",):
        return
    for field_name, field_delta in delta.items():
        if field_name == "register_writes":
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return
    precision["flags_register_condition_transfer"] = {"register_writes": {"added": added, "removed": removed}}
    register_delta["added"] = ()
    register_delta["removed"] = ()


def _suppress_void_return_loop_call_feeder_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    register_delta = delta.get("register_writes")
    control_delta = delta.get("control_flow_effects")
    if not isinstance(register_delta, dict) or not isinstance(control_delta, dict):
        return
    register_added = _boundary_tuple_8616(register_delta.get("added", ()) or ())
    register_removed = _boundary_tuple_8616(register_delta.get("removed", ()) or ())
    control_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("added", ()) or ())
    )
    control_removed = _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    if register_removed or control_removed:
        return
    if not register_added or any(not str(value).startswith("reg:") for value in register_added):
        return
    if not control_added or any(
        not value.startswith(("while-body-calls:", "while-body-writes:")) for value in control_added
    ):
        return
    if not any(":call:" in value or ":name:" in value for value in control_added):
        return
    if not any(any(str(reg) in value for reg in register_added) for value in control_added):
        return
    for field_name, field_delta in delta.items():
        if field_name in {"register_writes", "control_flow_effects"}:
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return
    precision["void_return_loop_call_feeder"] = {
        "register_writes": {"added": register_added, "removed": register_removed},
        "control_flow_effects": {"added": control_added, "removed": control_removed},
    }
    register_delta["added"] = ()
    register_delta["removed"] = ()
    control_delta["added"] = ()
    control_delta["removed"] = ()


def _control_flow_loop_body_write_locations_8616(value: str) -> tuple[str, ...] | None:
    """Parse top-level write locations from a loop-body effect fingerprint."""
    is_compact_loop_write = value.startswith("control_flow_effects:sha256:") and ":loop-body-writes:" in value
    if not value.startswith(_LOOP_BODY_WRITE_EFFECT_PREFIXES_8616) and not is_compact_loop_write:
        return None
    candidates: list[int] = []
    depth = 0
    for idx, char in enumerate(value):
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth = max(0, depth - 1)
            continue
        if depth != 0 or idx == 0 or value[idx - 1] != ":":
            continue
        if value.startswith(_CONTROL_FLOW_WRITE_LOCATION_MARKERS_8616, idx):
            candidates.append(idx)
    for idx in sorted(candidates):
        locations = tuple(part for part in _split_fingerprint_args_8616(value[idx:]) if part)
        if locations and all(location.startswith(_CONTROL_FLOW_WRITE_LOCATION_MARKERS_8616) for location in locations):
            return locations
    return None


def _split_control_flow_loop_body_write_effect_8616(value: str) -> tuple[str, tuple[str, ...]] | None:
    locations = _control_flow_loop_body_write_locations_8616(value)
    if not locations:
        return None
    first_location = locations[0]
    idx = value.find(first_location)
    if idx < 0:
        return None
    return value[:idx], locations


def indexed_segmented_global_precision_delta_8616(
    materialized_count: int,
    evidence: Sequence[IndexedSegmentedGlobalEvidence8616],
    validation: Mapping[str, TailValidationValue],
) -> bool:
    """Accept exact byte-location precision added by indexed-global lowering.

    Lowering may replace a one-byte dirty write fingerprint with the complete
    byte span of a proven indexed global. This policy accepts only that location
    refinement: the same loop/control prefix must remain, and every changed
    global byte must be covered by materialized typed evidence.
    """
    if materialized_count <= 0 or not evidence:
        return False
    if any(not isinstance(item, IndexedSegmentedGlobalEvidence8616) for item in evidence):
        return False
    spans = tuple((item.base_offset & 0xFFFF, int(item.width)) for item in evidence if 0 < int(item.width) <= 0x10000)
    if not spans:
        return False

    def _is_evidenced_location(location: str) -> bool:
        offset = _tail_validation_ds_global_write_offset_8616(location)
        return isinstance(offset, int) and any(((offset - start) & 0xFFFF) < width for start, width in spans)

    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    if validation_delta_touched_fields_8616(delta) != {"global_writes", "control_flow_effects"}:
        return False
    global_delta = delta.get("global_writes")
    control_delta = delta.get("control_flow_effects")
    if not isinstance(global_delta, Mapping) or not isinstance(control_delta, Mapping):
        return False

    global_added = _boundary_tuple_8616(global_delta.get("added") or ())
    global_removed = _boundary_tuple_8616(global_delta.get("removed") or ())
    if not global_added and not global_removed:
        return False
    if any(not isinstance(item, str) or not _is_evidenced_location(item) for item in (*global_added, *global_removed)):
        return False

    control_added = _boundary_tuple_8616(control_delta.get("added") or ())
    control_removed = _boundary_tuple_8616(control_delta.get("removed") or ())
    if len(control_added) != 1 or len(control_removed) != 1:
        return False
    if not isinstance(control_added[0], str) or not isinstance(control_removed[0], str):
        return False
    after_split = _split_control_flow_loop_body_write_effect_8616(control_added[0])
    before_split = _split_control_flow_loop_body_write_effect_8616(control_removed[0])
    if after_split is None or before_split is None or after_split[0] != before_split[0]:
        return False

    after_locations = Counter(after_split[1])
    before_locations = Counter(before_split[1])
    added_locations = after_locations - before_locations
    removed_locations = before_locations - after_locations
    if not added_locations and not removed_locations:
        return False
    changed_locations = (*added_locations.elements(), *removed_locations.elements())
    if any(not location.startswith("ds_global:") or not _is_evidenced_location(location) for location in changed_locations):
        return False
    return added_locations == Counter(global_added) and removed_locations == Counter(global_removed)


def indexed_global_read_carrier_precision_delta_8616(
    record: IndexedGlobalReadCarrierMaterializationRecord8616,
    validation: Mapping[str, TailValidationValue],
) -> bool:
    """Accept an exact machine-proven indexed load replacing its register carrier."""
    if (
        record.raw_fact_count <= 0
        or record.normalized_fact_count <= 0
        or record.classified_fact_count <= 0
        or record.materialized_count <= 0
        or record.failure_count != 0
        or not record.evidence
    ):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    if validation_delta_touched_fields_8616(delta) != {
        "register_writes",
        "conditions",
        "control_flow_effects",
    }:
        return False
    register_delta = delta.get("register_writes")
    condition_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    if (
        not isinstance(register_delta, Mapping)
        or not isinstance(condition_delta, Mapping)
        or not isinstance(control_delta, Mapping)
    ):
        return False
    register_added = _boundary_tuple_8616(register_delta.get("added") or ())
    register_removed = _boundary_tuple_8616(register_delta.get("removed") or ())
    condition_added = _boundary_tuple_8616(condition_delta.get("added") or ())
    condition_removed = _boundary_tuple_8616(condition_delta.get("removed") or ())
    control_added = _boundary_tuple_8616(control_delta.get("added") or ())
    control_removed = _boundary_tuple_8616(control_delta.get("removed") or ())
    if (
        register_added
        or len(register_removed) != 1
        or len(condition_added) != 1
        or len(condition_removed) != 1
        or not control_added
        or not control_removed
        or not all(
            isinstance(item, str)
            for item in (*register_removed, *condition_added, *condition_removed, *control_added, *control_removed)
        )
    ):
        return False

    removed_register = register_removed[0]
    before_condition = condition_removed[0]
    after_condition = condition_added[0]
    for site in record.evidence:
        register_name = site.destination_register
        if not isinstance(register_name, str) or not register_name:
            continue
        register_token = f"reg:{register_name.lower()}"
        if removed_register != register_token or before_condition.count(register_token) != 1:
            continue
        stack_sign = "+" if site.index_stack_offset >= 0 else "-"
        stack_index = (
            f"stack_slot:SS:BP{stack_sign}0x{abs(site.index_stack_offset):x}"
            f":size{site.index_stack_width}"
        )
        scaled_index = (
            stack_index
            if site.index_shift == 0
            else f"Shl({stack_index},const:{site.index_shift})"
        )
        indexed_load = (
            "Dereference(Add(Mul(reg:ds,const:16),"
            f"{scaled_index},const:{site.base_offset & 0xFFFF}))"
        )
        if before_condition.replace(register_token, indexed_load, 1) != after_condition:
            continue

        rewritten_effects: list[str] = []
        for effect in control_removed:
            rewritten = effect.replace(before_condition, after_condition)
            rewritten = rewritten.replace(f":{register_token},", ":")
            rewritten = rewritten.replace(f",{register_token},", ",")
            rewritten = rewritten.replace(f",{register_token}", "")
            if rewritten == effect or register_token in rewritten:
                break
            rewritten_effects.append(rewritten)
        else:
            if Counter(rewritten_effects) == Counter(control_added):
                return True
    return False


def dword_global_zero_test_precision_delta_8616(
    materialized_count: int,
    evidence: Sequence[DwordGlobalZeroTestEvidence8616],
    validation: Mapping[str, TailValidationValue],
) -> bool:
    """Accept an exact split-word OR zero-test rewritten as one dword test.

    The binary evidence proves adjacent low/high word loads feeding one OR and
    Jcc. Validation accepts only the corresponding condition substitution when
    every control-flow effect, including body calls, remains otherwise exact.
    """
    if materialized_count <= 0 or not evidence:
        return False
    if any(not isinstance(item, DwordGlobalZeroTestEvidence8616) for item in evidence):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    touched_fields = validation_delta_touched_fields_8616(delta)
    if touched_fields not in ({"conditions", "control_flow_effects"}, {"control_flow_effects"}):
        return False
    condition_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, Mapping):
        return False
    condition_added: str | None = None
    condition_removed: str | None = None
    if touched_fields == {"conditions", "control_flow_effects"}:
        if not isinstance(condition_delta, Mapping):
            return False
        condition_added_items = _boundary_tuple_8616(condition_delta.get("added") or ())
        condition_removed_items = _boundary_tuple_8616(condition_delta.get("removed") or ())
        if len(condition_added_items) != 1 or len(condition_removed_items) != 1:
            return False
        if not isinstance(condition_added_items[0], str) or not isinstance(condition_removed_items[0], str):
            return False
        condition_added = condition_added_items[0]
        condition_removed = condition_removed_items[0]
    else:
        condition_added = None
        condition_removed = None
    control_added = _boundary_tuple_8616(control_delta.get("added") or ())
    control_removed = _boundary_tuple_8616(control_delta.get("removed") or ())
    if not control_added or len(control_added) != len(control_removed):
        return False
    if any(not isinstance(effect, str) for effect in (*control_added, *control_removed)):
        return False
    if condition_added is None and condition_removed is None:
        control_added_conditions = tuple(
            effect[3:] for effect in control_added if effect.startswith("if:")
        )
        control_removed_conditions = tuple(
            effect[3:] for effect in control_removed if effect.startswith("if:")
        )
        if len(control_added_conditions) == 1 and len(control_removed_conditions) == 1:
            condition_added = control_added_conditions[0]
            condition_removed = control_removed_conditions[0]

    matched_condition_pair: tuple[str, str] | None = None
    for item in evidence:
        for compare_op in ("CmpEQ", "CmpNE"):
            after_condition = f"{compare_op}(ds_global:{item.base_offset & 0xFFFF:#x},const:0)"
            before_conditions = (
                f"{compare_op}(Or(ds_global:{item.high_offset & 0xFFFF:#x},"
                f"ds_global:{item.low_offset & 0xFFFF:#x}),const:0)",
                f"{compare_op}(Or(ds_global:{item.low_offset & 0xFFFF:#x},"
                f"ds_global:{item.high_offset & 0xFFFF:#x}),const:0)",
            )
            if (
                condition_added == after_condition
                and condition_removed is not None
                and condition_removed in before_conditions
            ):
                matched_condition_pair = condition_removed, after_condition
                break
        if matched_condition_pair is not None:
            break
    if matched_condition_pair is None:
        return False

    before_condition, after_condition = matched_condition_pair
    if any(effect.count(before_condition) != 1 for effect in control_removed):
        return False
    expected_added = Counter(
        effect.replace(before_condition, after_condition, 1)
        for effect in control_removed
    )
    return Counter(control_added) == expected_added


def _is_local_stack_body_write_precision_effect_8616(value: str) -> bool:
    locations = _control_flow_loop_body_write_locations_8616(value)
    if not locations:
        return False
    return all(location.startswith(("stack_slot:SS:BP-", "stack:-")) for location in locations)


def _suppress_straight_line_local_stack_write_precision_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify added straight-line local scratch writes with no observable use."""
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    stack_delta = delta.get("stack_writes")
    if not isinstance(stack_delta, dict):
        return
    added = _boundary_tuple_8616(str(value) for value in _boundary_tuple_8616(stack_delta.get("added", ()) or ()))
    removed = _boundary_tuple_8616(str(value) for value in _boundary_tuple_8616(stack_delta.get("removed", ()) or ()))
    if not added or removed:
        return
    if any(not value.startswith(("stack_slot:SS:BP-", "stack:-")) for value in added):
        return
    for field_name, field_delta in delta.items():
        if field_name == "stack_writes":
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return
    precision["straight_line_local_stack_write_precision"] = {"stack_writes": {"added": added, "removed": ()}}
    stack_delta["added"] = ()
    stack_delta["removed"] = ()


def _suppress_loop_body_local_stack_write_precision_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, dict):
        return
    added = _boundary_tuple_8616(control_delta.get("added", ()) or ())
    removed = _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    if not added and not removed:
        return
    return_locations = {
        str(value)
        for summary_key in ("before", "after")
        for summary in (diff.get(summary_key),)
        if isinstance(summary, Mapping)
        for value in _boundary_tuple_8616(summary.get("returns", ()) or ())
    }
    loop_body_write_locations: set[str] = set()
    for effect in (*added, *removed):
        split_effect = _split_control_flow_loop_body_write_effect_8616(str(effect))
        if split_effect is not None:
            loop_body_write_locations.update(split_effect[1])
    if return_locations & loop_body_write_locations:
        return
    added_stack_writes: tuple[str, ...] = ()
    stack_delta = delta.get("stack_writes")
    if isinstance(stack_delta, dict):
        added_stack_writes = _boundary_tuple_8616(
            str(value) for value in _boundary_tuple_8616(stack_delta.get("added", ()) or ())
        )
        if _boundary_tuple_8616(stack_delta.get("removed", ()) or ()):
            return
        if any(not value.startswith("stack_slot:SS:BP-") for value in added_stack_writes):
            return
    elif "stack_writes" in delta:
        return

    pure_local_precision = all(
        _is_local_stack_body_write_precision_effect_8616(str(value)) for value in added + removed
    )
    mixed_precision = False
    precision_added_locations: set[str] = set()
    if not pure_local_precision:
        added_effects = [_split_control_flow_loop_body_write_effect_8616(str(value)) for value in added]
        removed_effects = [_split_control_flow_loop_body_write_effect_8616(str(value)) for value in removed]
        if any(item is None for item in added_effects + removed_effects):
            return
        normalized_added_effects = [item for item in added_effects if item is not None]
        normalized_removed_effects = [item for item in removed_effects if item is not None]
        used_added: set[int] = set()
        for removed_prefix, removed_locations in normalized_removed_effects:
            removed_set = set(removed_locations)
            match_idx = None
            for idx, added_item in enumerate(normalized_added_effects):
                if idx in used_added:
                    continue
                added_prefix, added_locations = added_item
                added_set = set(added_locations)
                extra_locations = added_set - removed_set
                if (
                    added_prefix == removed_prefix
                    and removed_set <= added_set
                    and extra_locations
                    and all(location.startswith("stack_slot:SS:BP-") for location in extra_locations)
                ):
                    match_idx = idx
                    precision_added_locations.update(extra_locations)
                    break
            if match_idx is None:
                return
            used_added.add(match_idx)
        mixed_precision = len(used_added) == len(added_effects)
        if not mixed_precision:
            return

    for field_name, field_delta in delta.items():
        if field_name in {"control_flow_effects", "stack_writes"}:
            continue
        if not isinstance(field_delta, dict):
            return
        if field_delta.get("added", ()) or field_delta.get("removed", ()):
            return
    if mixed_precision and added_stack_writes and not set(added_stack_writes) <= precision_added_locations:
        return
    precision_record = {"control_flow_effects": {"added": added, "removed": removed}}
    if added_stack_writes:
        precision_record["stack_writes"] = {"added": added_stack_writes, "removed": ()}
    precision["loop_body_local_stack_write_precision"] = precision_record
    control_delta["added"] = ()
    control_delta["removed"] = ()
    if isinstance(stack_delta, dict):
        stack_delta["added"] = ()
        stack_delta["removed"] = ()


def _canonicalize_local_stack_abi_int_width_8616(value: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        return f"stack_slot:SS:BP{match.group('offset').lower()}:size2"

    return _LOCAL_STACK_ABI_INT_WIDTH_TOKEN_RE_8616.sub(_replace, value)


def _suppress_local_stack_abi_int_width_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Suppress source-backed host-int width noise for the same local BP slot.

    Source C parsed on the host can spell a DOS ``int`` stack local as size4
    while the binary/decompiled surface correctly spells the same BP slot as
    size2.  This is validation comparison canonicalization only: it does not
    rewrite recovered code, and it refuses to fire if any helper, register,
    global, segmented, return, or non-local condition delta remains.
    """
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    allowed_fields = {"stack_writes", "conditions", "control_flow_effects"}
    suppressed: dict[str, dict[str, tuple[str, ...]]] = {}
    saw_width_token = False
    for field_name, field_delta in delta.items():
        if not isinstance(field_delta, dict):
            return
        added = _boundary_tuple_8616(str(value) for value in _boundary_tuple_8616(field_delta.get("added", ()) or ()))
        removed = _boundary_tuple_8616(
            str(value) for value in _boundary_tuple_8616(field_delta.get("removed", ()) or ())
        )
        if not added and not removed:
            continue
        if field_name not in allowed_fields:
            return
        added_canonical = Counter(_canonicalize_local_stack_abi_int_width_8616(value) for value in added)
        removed_canonical = Counter(_canonicalize_local_stack_abi_int_width_8616(value) for value in removed)
        if added_canonical != removed_canonical:
            return
        if any(_LOCAL_STACK_ABI_INT_WIDTH_TOKEN_RE_8616.search(value) for value in added + removed):
            saw_width_token = True
        suppressed[field_name] = {"added": added, "removed": removed}
    if not saw_width_token or not suppressed:
        return
    precision["local_stack_abi_int_width"] = suppressed
    for field_name in suppressed:
        field_delta = delta.get(field_name)
        if isinstance(field_delta, dict):
            field_delta["added"] = ()
            field_delta["removed"] = ()


def _suppress_switch_helper_structuring_precision_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Classify a multi-guard switch decision tree becoming structured cases."""
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    helper_delta = delta.get("helper_calls")
    register_delta = delta.get("register_writes")
    return_delta = delta.get("returns")
    condition_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    if (
        not isinstance(helper_delta, dict)
        or not isinstance(register_delta, dict)
        or not isinstance(return_delta, dict)
        or not isinstance(condition_delta, dict)
        or not isinstance(control_delta, dict)
    ):
        return
    helper_added = _boundary_tuple_8616(helper_delta.get("added", ()) or ())
    helper_removed = _boundary_tuple_8616(helper_delta.get("removed", ()) or ())
    register_added = _boundary_tuple_8616(register_delta.get("added", ()) or ())
    register_removed = _boundary_tuple_8616(register_delta.get("removed", ()) or ())
    return_added = _boundary_tuple_8616(return_delta.get("added", ()) or ())
    return_removed = _boundary_tuple_8616(return_delta.get("removed", ()) or ())
    condition_added = _boundary_tuple_8616(condition_delta.get("added", ()) or ())
    condition_removed = _boundary_tuple_8616(condition_delta.get("removed", ()) or ())
    control_added = _boundary_tuple_8616(control_delta.get("added", ()) or ())
    control_removed = _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    if helper_added:
        return
    if "if:else" not in control_removed:
        return
    if not return_added and not return_removed:
        if helper_removed or register_added or register_removed:
            return
        if len(condition_added) < 2 or len(condition_removed) < 2:
            return
    elif return_added and return_removed:
        if helper_removed and not all(str(value).startswith("addr:") for value in helper_removed):
            return
        if not helper_removed and not all(
            _switch_helper_unstructured_return_8616(str(value)) for value in return_removed
        ):
            return
        if helper_removed and not any("CFakeVariable" in str(value) for value in return_removed):
            return
        if not all(_switch_helper_structured_return_8616(str(value)) for value in return_added):
            return
        if register_added:
            return
        if register_removed and not all(str(value) == "reg:ax" for value in register_removed):
            return
    else:
        return
    if not condition_added or not condition_removed or not control_added:
        return
    if not all(_switch_helper_condition_fingerprint_8616(str(value)) for value in condition_added + condition_removed):
        return
    precision["switch_helper_structuring"] = {
        "helper_calls": {"added": helper_added, "removed": helper_removed},
        "register_writes": {"added": register_added, "removed": register_removed},
        "returns": {"added": return_added, "removed": return_removed},
        "conditions": {"added": condition_added, "removed": condition_removed},
        "control_flow_effects": {"added": control_added, "removed": control_removed},
    }
    for field_name in ("helper_calls", "register_writes", "returns", "conditions", "control_flow_effects"):
        field_delta = delta.get(field_name)
        if isinstance(field_delta, dict):
            field_delta["added"] = ()
            field_delta["removed"] = ()


def _const_return_i16_value_8616(value: str) -> int | None:
    if not isinstance(value, str) or not value.startswith("const:"):
        return None
    try:
        return int(value[len("const:") :], 0) & 0xFFFF
    except ValueError:
        return None


def _suppress_signed_i16_return_else_structuring_delta_8616(diff: dict[str, TailValidationValue]) -> None:
    """Suppress signed/unsigned 16-bit return spelling drift after structuring."""
    delta = diff.get("delta")
    precision = diff.get("precision_improvements")
    if not isinstance(delta, dict) or not isinstance(precision, dict):
        return
    return_delta = delta.get("returns")
    control_delta = delta.get("control_flow_effects")
    if not isinstance(return_delta, dict) or not isinstance(control_delta, dict):
        return
    return_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(return_delta.get("added", ()) or ())
    )
    return_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(return_delta.get("removed", ()) or ())
    )
    control_added = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("added", ()) or ())
    )
    control_removed = _boundary_tuple_8616(
        str(value) for value in _boundary_tuple_8616(control_delta.get("removed", ()) or ())
    )
    if not return_added or not return_removed:
        return
    if Counter(filter(None, (_const_return_i16_value_8616(value) for value in return_added))) != Counter(
        filter(None, (_const_return_i16_value_8616(value) for value in return_removed))
    ):
        return
    if any(_const_return_i16_value_8616(value) is None for value in return_added + return_removed):
        return
    if control_added or tuple(value for value in control_removed if value != "if:else"):
        return
    for field_name, field_delta in delta.items():
        if field_name in {"returns", "control_flow_effects"}:
            continue
        if not isinstance(field_delta, dict):
            return
        if _boundary_tuple_8616(field_delta.get("added", ()) or ()) or _boundary_tuple_8616(
            field_delta.get("removed", ()) or ()
        ):
            return
    precision["signed_i16_return_else_structuring"] = {
        "returns": {"added": return_added, "removed": return_removed},
        "control_flow_effects": {"added": control_added, "removed": control_removed},
    }
    return_delta["added"] = ()
    return_delta["removed"] = ()
    control_delta["added"] = ()
    control_delta["removed"] = ()


def _switch_helper_structured_return_8616(value: str) -> bool:
    if value.startswith("const:"):
        return True
    return "stack_slot:SS:BP+" in value and value.startswith(("Add(", "Shl(", "Mul("))


def _switch_helper_unstructured_return_8616(value: str) -> bool:
    if value.startswith("const:"):
        return True
    if "CFakeVariable" in value and "Mul(reg:ss,const:16)" in value:
        return value.startswith(("Add(", "Shl(", "Mul("))
    return "stack_slot:SS:BP+" in value and (
        value.startswith(("Add(", "Shl(", "Mul(")) or "Dereference(Add(stack_slot:SS:BP+" in value
    )


def _switch_helper_condition_fingerprint_8616(value: str) -> bool:
    if value.startswith("if:"):
        value = value[len("if:") :]
    if value == "else":
        return True
    if value == "CITE":
        return True
    if value in {"CmpEQ(reg:ax,const:0)", "CmpNE(reg:ax,const:0)"}:
        return True
    return value.startswith(("CmpEQ(", "CmpNE(", "CmpLT(", "CmpLE(", "CmpGT(", "CmpGE(")) and (
        "stack_slot:SS:BP+" in value
    )


def format_x86_16_tail_validation_diff(validation: dict[str, TailValidationValue]) -> str:
    """Format a tail-validation comparison for diagnostic output."""
    if not validation.get("changed", False):
        return "no observable whole-tail changes"

    delta = validation.get("delta", {})
    parts: list[str] = []
    for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
        field_delta = delta.get(field_name, {})
        added = field_delta.get("added", ()) or ()
        removed = field_delta.get("removed", ()) or ()
        if not added and not removed:
            continue

        def _display(value: TailValidationValue) -> TailValidationValue:
            if field_name == "helper_calls" and isinstance(value, str) and value.startswith("name:"):  # noqa: B023
                return value[len("name:") :]
            return value

        field_parts = [f"+{_display(value)}" for value in added] + [f"-{_display(value)}" for value in removed]
        parts.append(f"{field_name}: " + ", ".join(field_parts))
    semantic_failures = normalize_tail_semantic_failures_8616(validation.get("semantic_failures"))
    parts.extend(format_tail_semantic_failures_8616(semantic_failures))
    return "; ".join(parts) if parts else "observable whole-tail delta present"


def _format_x86_16_tail_validation_timing_suffix(validation: Mapping[str, TailValidationValue]) -> str:
    def _impl() -> str:
        timing_debug = os.environ.get("INERTIA_DEBUG_TIMING")
        if timing_debug is None or timing_debug.strip().lower() in {"", "0", "false", "no", "off"}:
            return ""
        timings = validation.get("timings")
        if not isinstance(timings, Mapping):
            return ""

        parts: list[str] = []
        collect_before_ms = timings.get("collect_before_ms")
        collect_after_ms = timings.get("collect_after_ms")
        compare_ms = timings.get("compare_ms")
        total_ms = timings.get("total_ms")

        if isinstance(collect_before_ms, (int, float)) and isinstance(collect_after_ms, (int, float)):
            parts.append(f"collect={collect_before_ms:.1f}+{collect_after_ms:.1f}ms")
        elif isinstance(collect_before_ms, (int, float)):
            parts.append(f"collect={collect_before_ms:.1f}ms")
        elif isinstance(collect_after_ms, (int, float)):
            parts.append(f"collect={collect_after_ms:.1f}ms")

        if isinstance(compare_ms, (int, float)):
            parts.append(f"compare={compare_ms:.1f}ms")
        if isinstance(total_ms, (int, float)):
            parts.append(f"tail_validation={total_ms:.1f}ms")
        if not parts:
            return ""
        return " [" + " ".join(parts) + "]"

    return _impl()


def build_x86_16_tail_validation_verdict(stage: str, validation: dict[str, TailValidationValue]) -> str:
    """Build a stable user-facing verdict for one tail-validation stage."""
    mode = validation.get("mode", "unknown")
    summary_text = validation.get("summary_text")
    if not isinstance(summary_text, str) or not summary_text:
        summary_text = format_x86_16_tail_validation_diff(validation)
    status = validation.get("status")
    if not isinstance(status, str) or not status:
        status = "changed" if validation.get("changed", False) else "stable"
    timing_suffix = _format_x86_16_tail_validation_timing_suffix(validation)
    return f"{stage} whole-tail validation [{mode}] {status}: {summary_text}{timing_suffix}"


def describe_x86_16_tail_validation_scope() -> dict[str, TailValidationValue]:
    """Describe the owned validation boundary, modes, observables, and cache policy."""
    return {
        "boundary": (
            "whole-tail validation compares observable structured-codegen effects before and after late x86-16 passes"
        ),
        "preferred_mode": "live_out",
        "modes": ("coarse", "live_out"),
        "cache_policy": (
            "reuse summaries and stage comparisons only when structured-codegen boundary fingerprints match exactly"
        ),
        "coverage_semantics": {
            "missing": "validation metadata was not collected for that stage on that function",
            "unknown": "validation metadata existed but could not be classified into stable or changed",
        },
        "layers": ("structuring", "postprocess"),
        "observables": _TAIL_VALIDATION_OBSERVABLE_FIELDS,
        "semantic_failure_fields": _TAIL_VALIDATION_SEMANTIC_FAILURE_FIELDS,
        "ignored": (
            "temporary names",
            "dead internal rewrites",
            "non-live flag churn",
        ),
    }


def build_x86_16_tail_validation_cached_result(
    *,
    owner: TailValidationValue,
    stage: str,
    mode: str,
    before_fingerprint: str,
    after_fingerprint: str,
    before_summary: X86_16TailValidationSummary,
    after_summary: X86_16TailValidationSummary,
    semantic_failure_scope: TailSemanticFailureScope8616 = TailSemanticFailureScope8616.ALL_AFTER,
) -> dict[str, TailValidationValue]:
    """Compare summaries through the validation cache owned by a stage object."""

    def _impl() -> dict[str, TailValidationValue]:
        cache = _tail_validation_validation_cache_store(owner)
        comparisons = cache.get("comparisons", {})
        descriptor = build_x86_16_validation_cache_descriptor(
            "tail_validation.comparison",
            {
                "comparison_version": _TAIL_VALIDATION_COMPARISON_VERSION_8616,
                "stage": stage,
                "mode": mode,
                "before_fingerprint": before_fingerprint,
                "after_fingerprint": after_fingerprint,
                "before_summary": before_summary.as_dict(),
                "after_summary": after_summary.as_dict(),
                "semantic_failure_scope": semantic_failure_scope.value,
            },
        )
        cached = resolve_x86_16_validation_cached_artifact(
            cache=comparisons if isinstance(comparisons, dict) else None,
            descriptor=descriptor,
            build=lambda: {
                **compare_x86_16_tail_validation_summaries(before_summary, after_summary),
                "mode": mode,
            },
            clone_on_hit=cast(Callable[[object], object], dict),
            store_value=cast(Callable[[object], Any], dict),
        )
        result = dict(cached["value"])
        semantic_failures = collect_tail_semantic_failures_8616(
            after_summary,
            before=before_summary,
            scope=semantic_failure_scope,
        )
        if semantic_failures:
            result["semantic_failures"] = semantic_failures
            result["changed"] = True
            result["status"] = "failed"
            result["summary_text"] = format_x86_16_tail_validation_diff(result)
        if "status" not in result or not isinstance(result.get("status"), str) or not result.get("status"):
            result["status"] = "changed" if bool(result.get("changed", False)) else "stable"
        if "summary_text" not in result:
            result["summary_text"] = format_x86_16_tail_validation_diff(result)
        if "scope" not in result:
            result["scope"] = describe_x86_16_tail_validation_scope()
        if "verdict" not in result:
            result["verdict"] = build_x86_16_tail_validation_verdict(stage, result)
        result["cache_hit"] = bool(cached["cache_hit"])
        result["cache_key"] = cached["cache_key"]
        if isinstance(comparisons, dict) and not cached["cache_hit"]:
            comparisons[cached["cache_key"]] = dict(result)
        return result

    return _impl()
