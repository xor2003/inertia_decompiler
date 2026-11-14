# cython: language_level=3, infer_types=True
"""Typed helpers for recognizing real-mode segment:offset linearizations.

Layer: Types/Lowering.
Responsibility: recognize proven real-mode linear address forms for stack and global lowering.
Consumes alias, widening, and typed facts by translating proven segment:offset
carriers into stack/global lowering inputs.
Do not recover semantics from COD, source, assembly, or rendered C text.
Dynamic boundary: attribute access in this legacy module is limited to angr
structured-C and codegen compatibility objects; avoidable owned-contract
getattr/setattr is cleanup debt and must be removed when touching nearby code.

The x86-16 lifter represents a real-mode memory address as
``(segment << 4) + offset`` (or equivalently ``segment * 16 + offset``).
This module centralizes that structural recognition so stack lowering can
consume a typed SS address fact instead of re-learning the arithmetic shape in
late cleanup code.
"""

from __future__ import annotations
import typing
import cython

import contextlib
import logging
import os
import re
import sys
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from types import SimpleNamespace
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import (
    SimStruct,
    SimTypeChar,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimVariable
from capstone import CS_AC_WRITE
from capstone.x86_const import (
    X86_GRP_JUMP,
    X86_GRP_RET,
    X86_INS_ADC,
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_CBW,
    X86_INS_CDQ,
    X86_INS_CWD,
    X86_INS_CWDE,
    X86_INS_DEC,
    X86_INS_IDIV,
    X86_INS_INC,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_INS_NEG,
    X86_INS_OR,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_INS_SAL,
    X86_INS_SAR,
    X86_INS_SBB,
    X86_INS_SHL,
    X86_INS_SHR,
    X86_INS_SUB,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_CS,
    X86_REG_CX,
    X86_REG_DH,
    X86_REG_DI,
    X86_REG_DL,
    X86_REG_DS,
    X86_REG_DX,
    X86_REG_ES,
    X86_REG_INVALID,
    X86_REG_SI,
    X86_REG_SP,
    X86_REG_SS,
)

from inertia.alias.alias_model import _stack_storage_facts_for_segmented_address_8616
from inertia.alias.alias_model_impl import AliasStorageFacts, _StackSlotIdentity
from inertia.alias.stack_memory_ssa_contracts import StackMemoryAliasFactKind8616, StackMemorySSAAliasArtifact8616
from inertia.ir.core import MemSpace
from inertia.lowering.analysis_helpers import canonicalize_x86_16_padding_call_target_8616
from inertia.lowering.annotations import ANNOTATION_KEY
from inertia.lowering.c_ast_utils import (
    _iter_c_nodes_deep_8616,
    _iter_c_statement_nodes_8616,
    _structured_codegen_node_8616,
)
from inertia.lowering.structured_tags import copy_structured_tags_8616
from inertia.pipeline.contracts import SemanticLaneState
from inertia.pipeline.errors import PipelineHardError
from inertia.pipeline.structured_ast_query_index import (
    StructuredAstQueryIndex8616,
    TaggedAssignmentAddressIndex8616,
)
from inertia.semantics.binary_call_contracts import binary_call_return_contract_8616
from inertia.semantics.call_contracts import (
    RuntimeCallReturnContract8616,
    runtime_call_return_contract_8616,
)
from inertia.semantics.callee_name_normalization import normalize_callee_name_8616
from inertia.semantics.callsite_summary import (
    CallsiteSummary8616,
    callsite_summary_inventory_8616,
    structured_callsite_addr_8616,
)
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.stack_widening import prove_adjacent_storage_slices

from .balanced_memory_stack_restore import rebind_balanced_memory_stack_restores_8616
from .binary_callback_targets import (
    BinaryCallbackTargetStatus8616,
    prove_binary_near_callback_target_8616,
)
from .c_runtime_header import LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616
from .call_argument_carrier_liveness import (
    CallArgumentCarrierLivenessVerdict8616,
    classify_call_argument_carrier_liveness_8616,
)
from .call_execution_frame_replay import (
    prune_materialized_call_execution_frames_8616,
)
from .call_return_bridge_projection import word_call_bridge_projection_8616
from .call_return_frame import (
    CallReturnFrameCarrierPrune8616,
    prune_exact_call_return_frame_projections_8616,
)
from .call_return_stack_bindings import preserve_word_call_carrier_8616
from .call_return_stack_stores import recover_zero_arg_call_return_stack_store_8616
from .callee_saved_frame import (
    CalleeSavedFrameCarrierKind8616,
    CalleeSavedFrameInstructionRole8616,
    CalleeSavedFramePair8616,
    CalleeSavedFramePairSemantics8616,
    CalleeSavedFramePruneFact8616,
    CalleeSavedFramePruneRecord8616,
    callee_saved_frame_pairs_8616,
)
from .condition_stack_operands import materialize_typed_condition_stack_operand_8616
from .consumed_call_push_evidence import (
    ConsumedCallPushEvidenceStatus8616,
    normalize_consumed_call_push_evidence_8616,
)
from .control_stack_escape import (
    classify_control_stack_escape_8616,
    materialize_control_stack_escape_8616,
)
from .direct_stack_replay import (
    DirectStackMaterializationResult8616,
    DirectStackReplayOptions8616,
    execute_direct_stack_replay_8616,
)
from .direct_stack_segmented_projection import (
    SegmentedStackSourceProjection8616,
    projected_segmented_stack_assignment_present_8616,
)
from .frame_carrier_liveness import prove_frame_carrier_uses_8616
from .frame_instruction_evidence import canonical_frame_instruction_addresses_8616
from .frame_prologue_carriers import (
    is_exact_bp_frame_setup_carrier_8616,
    is_exact_push_bp_carrier_8616,
)
from .frame_register_carriers import collect_frame_register_carriers_8616
from .function_pointer_parameters import _function_pointer_type_8616
from .global_declarations import (
    ctype_for_global_width_8616,
    record_global_declaration_spec_8616,
    record_scalar_global_declaration_spec_8616,
)
from .gp_register_state import (
    runtime_gp_expression_view_8616,
    runtime_gp_live_in_name_8616,
    runtime_gp_state_names_8616,
)
from .instruction_bp_stack_access import (
    InstructionBpStackAccess8616,
    InstructionBpStackAccessEvidence8616,
    InstructionBpStackAccessIndex8616,
    ensure_instruction_bp_stack_access_index_8616,
    select_instruction_bp_stack_access_8616,
)
from .linear_global_decomposition_cache import (
    LinearGlobalCarrierKey8616,
    LinearGlobalDecompositionCache8616,
)
from .machine_stack_names import machine_bp_stack_object_name_8616
from .physical_registers import physical_register_name_8616, physical_register_offset_8616
from .register_reload_consumers import instruction_local_register_read_8616
from .register_variable_identity import (
    capstone_register_name_8616 as _capstone_register_name_8616,
)
from .register_variable_identity import (
    register_cvar_name_8616 as _cvar_register_name_8616,
)
from .register_variable_identity import (
    register_cvar_names_8616,
)
from .runtime_memory_helpers import memory_pointer_helper_8616, segmented_memory_read_helper_8616
from .runtime_push_carrier import RuntimePushCarrierVerdict8616, classify_runtime_push_carrier_8616
from .runtime_segment_access import runtime_segment_access_space_8616
from .segment_access_policy import (
    instruction_addrs_from_node_8616,
    may_lower_codegen_access_to_entry_ds_object_8616,
    may_lower_codegen_address_to_entry_ds_object_8616,
)
from .segment_register_state import runtime_segment_name_for_variable_8616
from .semantic_cast import (
    CSemanticCast8616,
    RequiredAssignmentCastReconcileStatus8616,
    reconcile_required_assignment_cast_8616,
)
from .stack_address_coordinates import (
    absolute_machine_bp_offset_from_wrapped_anchor_8616,
    consume_indexed_stack_frame_terms_8616,
    machine_bp_offset_for_entry_sp_anchor_8616,
    machine_bp_offset_for_native_anchor_8616,
    native_entry_sp_offset_for_anchor_8616,
)
from .stack_aggregate_objects import StackAggregateObjectFact8616, materialize_stack_aggregate_objects_8616
from .stack_frame_projection import entry_sp_offset_for_machine_bp_range_8616
from .stack_lowering_from_facts import (
    _canonical_stack_offset_8616,
    _stack_object_name,
    materialize_stack_cvar_at_offset_from_facts_8616,
)
from .stack_probe_return_facts import TypedStackProbeReturnFact8616
from .stack_storage_evidence import (
    alias_proves_private_stack_source_8616,
    alias_proves_stack_range_8616,
    proven_bp_entry_sp_delta_8616,
)
from .stack_value_projection import (
    StackValueOwnerHint8616,
    StackValueProjectionStatus8616,
)
from .stack_value_projection import (
    project_stack_value_range_8616 as project_stack_value_range_8616,
)
from .stack_variable_binding import (
    StackBaseBpBiasEvidence8616,
    StackVariableBinding,
    select_stack_annotation_spec_8616,
    stack_binding_inherits_containing_name_8616,
)
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    publish_selected_stack_cvar_projection_8616,
    stack_cvar_for_machine_bp_range_8616,
)
from .stack_variable_coordinates import (
    stack_cvar_for_machine_bp_value_range_8616 as stack_cvar_for_machine_bp_value_range_8616,
)
from .stack_word_load_materialization import (
    materialize_stack_word_load_recompositions_8616,
)
from .storage_identity_facts import (
    GlobalStorageIdentityFact8616,
    StorageIdentityEvidenceKind8616,
    record_global_storage_identity_fact_8616,
)
from .wide_call_output_assignment_replay import (
    classify_authoritative_wide_call_output_projection_8616,
)
import dataclasses
import operator
import builtins

AngrProjectValue = typing.TypeAliasType("AngrProjectValue", Any)
StructuredCodegenValue = typing.TypeAliasType("StructuredCodegenValue", Any)
StructuredAstValue = typing.TypeAliasType("StructuredAstValue", Any)


@dataclasses.dataclass(frozen=True, )
class _BpMemoryOperandOffsetCache8616:
    """Cache immutable BP-relative disassembly facts for one function context."""

    code_function_identity: cython.longlong
    function_identities: object
    offsets: object


@cython.ccall
def _boundary_tuple_8616(value: StructuredAstValue) -> tuple[StructuredAstValue, ...]:
    """Convert a dynamic angr/codegen iterable to a tuple without changing semantics."""
    return tuple(cast(Iterable[StructuredAstValue], value))


@cython.ccall
def _boundary_list_8616(value: StructuredAstValue) -> list[StructuredAstValue]:
    """Convert a dynamic angr/codegen iterable to a list without changing semantics."""
    return list(cast(Iterable[StructuredAstValue], value))


@cython.ccall
def _boundary_set_8616(value: StructuredAstValue) -> set[StructuredAstValue]:
    """Convert a dynamic angr/codegen iterable to a set without changing semantics."""
    return set(cast(Iterable[StructuredAstValue], value))


_SEGMENT_REGISTER_NAMES_8616 = {"cs", "ds", "es", "ss"}
log: logging.Logger = logging.getLogger(__name__)


@cython.ccall
def _stat_counter_8616(stats: Mapping[str, StructuredAstValue], key: object) -> cython.longlong:
    """Return a non-throwing integer counter from lowering telemetry stats."""
    value: object
    value = stats.get(key, 0)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _record_semantic_lane_8616(
    codegen: StructuredAstValue,
    *,
    name: object,
    raw: cython.longlong,
    normalized: cython.longlong,
    classified: cython.longlong,
    materialized: cython.longlong,
    failures: cython.longlong,
) -> SemanticLaneState:
    """Record one semantic-lane counter snapshot on codegen."""
    lane = SemanticLaneState(
        name=name,
        raw=raw,
        normalized=normalized,
        classified=classified,
        materialized=materialized,
        failures=failures,
    )
    lanes = _boundary_tuple_8616(getattr(codegen, "_inertia_semantic_lanes_8616", ()) or ())
    filtered = tuple(existing for existing in iter(lanes) if operator.ne(existing.name, lane.name))
    codegen._inertia_semantic_lanes_8616 = (*filtered, lane)
    return lane


def _record_direct_stack_move_lanes_8616(
    codegen: StructuredAstValue,
    stats: Mapping[str, StructuredAstValue],
    *,
    prior_stats: Mapping[str, int] | None = None,
    current_raw_fact_count: int | None = None,
) -> None:
    """Record the current direct stack MOV pass without historical failures."""

    def _current_counter(name: object) -> cython.longlong:
        current = _stat_counter_8616(stats, name)
        if prior_stats is None:
            return current
        return max(current - prior_stats.get(name, 0), 0)

    raw = (
        max(current_raw_fact_count, 0)
        if current_raw_fact_count is not None
        else _current_counter("raw_fact_count")
    )
    classified = _current_counter("classified_fact_count")
    materialized = _current_counter("materialized_count") + _current_counter(
        "already_materialized_count"
    )
    failures = _current_counter("failure_count")
    lane = _record_semantic_lane_8616(
        codegen,
        name="direct_stack_mov",
        raw=raw,
        normalized=raw,
        classified=classified,
        materialized=materialized,
        failures=failures,
    )
    codegen._inertia_direct_stack_mov_lane_8616 = lane


@cython.ccall
def _record_direct_stack_update_lane_8616(codegen: StructuredAstValue, stats: Mapping[str, StructuredAstValue]) -> None:
    """Record direct stack update evidence counters as a semantic lane."""
    raw = _stat_counter_8616(stats, "raw_fact_count")
    classified = _stat_counter_8616(stats, "classified_fact_count")
    materialized = _stat_counter_8616(stats, "materialized_count")
    failures = _stat_counter_8616(stats, "failure_count")
    refused = _stat_counter_8616(stats, "refused_count")
    already_present = max(0, classified - materialized - failures - refused)
    lane = _record_semantic_lane_8616(
        codegen,
        name="direct_stack_update",
        raw=raw,
        normalized=raw,
        classified=classified,
        materialized=materialized + already_present,
        failures=failures,
    )
    codegen._inertia_direct_stack_update_lane_8616 = lane


@cython.ccall
def _dirty_reg_offset_8616(dirty: StructuredAstValue) -> int | None:
    offset = physical_register_offset_8616(dirty)
    return offset if isinstance(offset, int) else None


@dataclasses.dataclass(frozen=True, )
class RealModeLinearStackAccess8616:
    """Stable SS stack access recovered from real-mode linear address math."""

    displacement: cython.longlong
    width: int | None
    entry_sp_offset: int | None = None


@dataclasses.dataclass(frozen=True, )
class RealModeIndexedStackAddress8616:
    """BP-indexed stack address recovered from binary memory-operand evidence."""

    base_displacement: cython.longlong
    residual_terms: object
    width: int | None


@dataclasses.dataclass(frozen=True, )
class RealModeLinearGlobalAddress8616:
    """Stable DS/ES address-valued expression recovered from real-mode linear math."""

    segment_name: object
    displacement: cython.longlong
    residual_terms: object
    width: int | None = None


@cython.ccall
def _record_real_mode_global_lowering_evidence_8616(
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
    access: RealModeLinearGlobalAddress8616,
) -> None:
    lowering: object
    owner: object
    previous: object
    stats: object
    segment_name = access.segment_name.lower()
    if segment_name not in {"ds", "es"}:
        return
    segment_key = segment_name.upper()
    for owner in (codegen, project):
        if owner is None:
            continue
        lowering = getattr(owner, "_inertia_segmented_memory_lowering", None)
        if not isinstance(lowering, dict):
            lowering = {}
            owner._inertia_segmented_memory_lowering = lowering
        previous = lowering.get(segment_key)
        entry = dict(previous) if isinstance(previous, dict) else {}
        entry.update(
            {
                "classification": entry.get("classification") or "materialized_global_access",
                "space": entry.get("space") or "data",
                "allow_linear_lowering": True,
                "allow_object_lowering": True,
                "reason": entry.get("reason") or "materialized DS/ES linear global access",
                "materialized_count": int(entry.get("materialized_count", 0) or 0) + 1,
            }
        )
        lowering[segment_key] = entry
    stats = getattr(codegen, "_inertia_real_mode_global_lowering_evidence", None)
    if not isinstance(stats, dict):
        stats = {"materialized_count": 0}
        codegen._inertia_real_mode_global_lowering_evidence = stats
    stats["materialized_count"] = int(stats.get("materialized_count", 0) or 0) + 1


@dataclasses.dataclass(frozen=True, )
class DirectGlobalUpdateFact8616:
    """Binary-proven direct no-base/no-index global INC/DEC side effect."""

    displacement: cython.longlong
    width: cython.longlong
    delta: cython.longlong
    ins_addr: cython.longlong


@dataclasses.dataclass(frozen=True, )
class ConsumedCallPushCarrierPrune8616:
    """Evidence census for impossible BP-local assignments tagged to consumed PUSH effects."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    preserved_live_definition_count: cython.longlong = 0
    liveness_refusal_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, )
class MaterializedCallPushReplay8616:
    """Evidence census for replaying exact callsite PUSH consumption."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    consumed_push_instruction_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class MaterializedCallCleanupReplay8616:
    """Evidence census for caller cleanup effects consumed by structured calls."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    consumed_cleanup_instruction_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class FramePrologueCarrierPrune8616:
    """Evidence census for source-invisible canonical BP-prologue assignments."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


class _FramePrologueCarrierPruneOwner8616(Protocol):
    """Typed owned field for canonical frame-prologue cleanup evidence."""

    _inertia_frame_prologue_carrier_prune_8616: FramePrologueCarrierPrune8616


class DirectStackUpdateSourceKind8616(Enum):
    """Binary-proven source kind for a direct BP-relative stack arithmetic update."""

    IMMEDIATE = "immediate"
    STACK_SLOT = "stack_slot"
    INDEXED_POINTER = "indexed_pointer"


class DirectStackUpdateOp8616(Enum):
    """Binary-proven operation for a direct BP-relative stack update."""

    ARITHMETIC = "arithmetic"
    OR = "or"
    SHIFT_LEFT = "shift_left"
    SHIFT_RIGHT = "shift_right"


@dataclasses.dataclass(frozen=True, )
class DirectStackUpdateFact8616:
    """Binary-proven direct BP-relative stack arithmetic side effect."""

    offset: cython.longlong
    width: cython.longlong
    delta: cython.longlong
    ins_addr: cython.longlong
    source_kind: DirectStackUpdateSourceKind8616 = DirectStackUpdateSourceKind8616.IMMEDIATE
    source_value: int | None = 1
    source_offset: int | None = None
    operation: DirectStackUpdateOp8616 = DirectStackUpdateOp8616.ARITHMETIC
    source_base_offset: int | None = None
    source_index_offset: int | None = None
    source_index_scale: int | None = None


@dataclasses.dataclass(frozen=True, )
class DirectStackLoopIteratorMaterialization8616:
    """Result of binding one binary stack update to one structured loop iterator."""

    matched: cython.bint
    changed: cython.bint


class DirectStackMoveSourceKind8616(Enum):
    """Binary-proven source kind for a direct BP-relative stack MOV store."""

    IMMEDIATE = "immediate"
    STACK_SLOT = "stack_slot"
    STACK_SLOT_EXPR = "stack_slot_expr"
    STACK_SLOT_BINARY_EXPR = "stack_slot_binary_expr"
    STACK_AGGREGATE_ELEMENT = "stack_aggregate_element"
    GLOBAL_EXPR = "global_expr"
    GLOBAL_MINUS_STACK_SLOT = "global_minus_stack_slot"
    SEGMENTED_MEMORY = "segmented_memory"
    GLOBAL_MINUS_SEGMENTED_MEMORY = "global_minus_segmented_memory"
    SIGNED_IDIV_REMAINDER = "signed_idiv_remainder"
    ZERO_ARG_CALL_RETURN = "zero_arg_call_return"
    WIDE_CALL_RETURN_STACK_ARITH = "wide_call_return_stack_arith"


class DirectStackMoveExpressionOp8616(Enum):
    """Pure expression operation in a binary-proven stack MOV source."""

    ADD = "Add"
    SUB = "Sub"
    MOD = "Mod"
    SHL = "Shl"
    SIGNED_DIV2 = "Div"


class DirectStackRegisterValueKind8616(Enum):
    """Proven register-value provenance used while collecting stack MOV facts."""

    STACK_SLOT = "stack_slot"
    STACK_SLOT_EXPR = "stack_slot_expr"
    SEGMENTED_MEMORY = "segmented_memory"


class DirectStackFunctionTargetEvidence8616(Enum):
    """Evidence source for a near-code pointer used as a function pointer."""

    SYNTHETIC_GLOBAL = "synthetic_global"
    LABEL = "label"
    FUNCTION = "function"
    BINARY_CALL_FLOW = "binary_call_flow"


class DirectStackMoveArtifactReplacementKind8616(Enum):
    """How a structured-codegen artifact was matched to a binary stack-store fact."""

    EXACT_DESTINATION_STACK_SLOT = "exact_destination_stack_slot"
    UNIQUE_SIGNED_IDIV_STACK_ARTIFACT = "unique_signed_idiv_stack_artifact"


class DirectStackWriteClassification8616(Enum):
    """Binary provenance verdict for one tagged BP-relative C assignment."""

    EXACT_WRITE = "exact_write"
    PROVEN_NOT_WRITE = "proven_not_write"
    UNKNOWN = "unknown"


class DirectStackMoveFallbackDecision8616(Enum):
    """Whether a binary-proven stack move may use an unscoped insertion fallback."""

    SAFE_TO_INSERT = "safe_to_insert"
    REFUSE_STRUCTURED_CONTROL_SCOPE = "refuse_structured_control_scope"


class StructuredCIntrinsic8616(Enum):
    """Structured-codegen intrinsic helper identities consumed during lowering."""

    INSERT = "INSERT"


@dataclasses.dataclass(frozen=True, )
class DirectStackRegisterValue8616:
    """Small instruction-state fact for register values feeding BP stack stores."""

    kind: DirectStackRegisterValueKind8616
    stack_offset: int | None = None
    width: int | None = None
    source_op: DirectStackMoveExpressionOp8616 | None = None
    source_immediate: int | None = None
    segment_name: object = None
    displacement: int | None = None
    index_stack_offset: int | None = None
    index_shift: int | None = None
    access_width: int | None = None
    sign_extend: cython.bint = False


@dataclasses.dataclass(frozen=True, )
class DirectStackIndexFact8616:
    """Binary-proven logical stack index and its byte-address scale."""

    stack_offset: cython.longlong
    width: cython.longlong
    byte_scale: cython.longlong


@dataclasses.dataclass(frozen=True, )
class DirectStackIndexedLoadFact8616:
    """Binary-proven indexed load from a BP-relative stack aggregate."""

    base_offset: cython.longlong
    access_width: cython.longlong
    index: DirectStackIndexFact8616


class DirectGlobalUpdateMaterializationKind8616(Enum):
    """How a binary-proven direct global update was materialized in C."""

    REPLACED_TAGGED_ASSIGNMENT = "replace"
    INSERTED_IN_PROVEN_LOOP = "insert_in_proven_loop"
    INSERTED_BEFORE_NEXT_TAGGED_STATEMENT = "insert_before_next"
    INSERTED_AT_BODY_START = "insert_body_start"


class DirectGlobalLoopInsertionStatus8616(Enum):
    """Typed result for binary-proven direct-global loop placement."""

    NOT_APPLICABLE = "not_applicable"
    INSERTED = "inserted"
    REFUSED_UNPROVEN_NESTED_SCOPE = "refused_unproven_nested_scope"


@dataclasses.dataclass(frozen=True, )
class DirectStackMoveFact8616:
    """Binary-proven direct BP-relative stack MOV side effect."""

    dst_offset: cython.longlong
    width: cython.longlong
    source_kind: DirectStackMoveSourceKind8616
    ins_addr: cython.longlong
    source_value: int | None = None
    source_offset: int | None = None
    source_rhs_offset: int | None = None
    source_op: DirectStackMoveExpressionOp8616 | None = None
    source_immediate: int | None = None
    source_call_target: int | None = None
    source_call_name: object = None
    source_call_ins_addr: int | None = None
    source_call_return_contract: RuntimeCallReturnContract8616 | None = None
    source_low_arith_ins_addr: int | None = None
    source_high_arith_ins_addr: int | None = None
    dst_high_ins_addr: int | None = None
    source_segment_name: object = None
    source_global_displacement: int | None = None
    source_aggregate_base_offset: int | None = None
    source_displacement: int | None = None
    source_index_offset: int | None = None
    source_index_shift: int | None = None
    source_index_byte_scale: cython.longlong = 1
    source_access_width: int | None = None
    source_sign_extend: cython.bint = False
    dst_index_global_displacement: int | None = None
    dst_index_stack_offset: int | None = None
    dst_index_immediate: int | None = None
    dst_index_scale: cython.longlong = 1
    dst_index_byte_scale: cython.longlong = 1
    source_register_offset: int | None = None


@dataclasses.dataclass(frozen=True, )
class DirectStackWriteSite8616:
    """One explicit binary instruction write to a BP-relative stack range."""

    dst_offset: cython.longlong
    width: cython.longlong
    ins_addr: cython.longlong

    def overlaps(self, offset: cython.longlong, width: cython.longlong) -> cython.bint:
        """Return whether this write overlaps the requested BP-relative range."""
        return self.dst_offset < offset + width and offset < self.dst_offset + self.width


@dataclasses.dataclass(frozen=True, )
class DirectStackWriteInventory8616:
    """Typed Lowering inventory for exact binary BP-relative write provenance."""

    decoded_instruction_addrs: object
    write_sites: object
    unknown_write_sites: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    def classify(
        self,
        *,
        ins_addr: cython.longlong,
        dst_offset: cython.longlong,
        width: cython.longlong,
    ) -> DirectStackWriteClassification8616:
        """Classify one tagged assignment against exact decoded instructions."""
        if ins_addr not in self.decoded_instruction_addrs:
            return DirectStackWriteClassification8616.UNKNOWN
        if any(
            operator.eq(site.ins_addr, ins_addr) and site.overlaps(dst_offset, width)
            for site in iter(self.unknown_write_sites)
        ):
            return DirectStackWriteClassification8616.UNKNOWN
        if any(
            operator.eq(site.ins_addr, ins_addr) and site.overlaps(dst_offset, width)
            for site in iter(self.write_sites)
        ):
            return DirectStackWriteClassification8616.EXACT_WRITE
        return DirectStackWriteClassification8616.PROVEN_NOT_WRITE


@dataclasses.dataclass(frozen=True, )
class DirectStackMoveExtentEvidence8616:
    """Closed evidence loop for an inventory-proven function decode extension."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    function_addr: int | None
    original_end: int | None
    proven_end: int | None
    recovered_fact_count: cython.longlong


class _DirectStackMoveExtentEvidenceOwner8616(Protocol):
    """Typed owned evidence field carried by an angr codegen object."""

    _inertia_direct_stack_move_extent_evidence_8616: DirectStackMoveExtentEvidence8616


class _DirectStackWriteInventoryOwner8616(Protocol):
    """Typed stack-write inventory field carried by an angr codegen object."""

    _inertia_direct_stack_write_inventory_8616: DirectStackWriteInventory8616


@dataclasses.dataclass(frozen=True, )
class DirectStackFunctionTarget8616:
    """Resolved near-code pointer target for a function-pointer stack store."""

    name: object
    addr: cython.longlong
    evidence: DirectStackFunctionTargetEvidence8616


@dataclasses.dataclass(frozen=True, )
class DirectStackReloadFact8616:
    """Binary-proven register reload from a materialized BP-relative stack slot."""

    source_offset: cython.longlong
    width: cython.longlong
    dst_reg_id: cython.longlong
    dst_reg_name: object
    ins_addr: cython.longlong
    source_store_ins_addr: cython.longlong
    source_kind: DirectStackMoveSourceKind8616


class _DirectStackReloadPlacement8616(Enum):
    """Typed outcome of placing one proven register reload in structured C."""

    NO_MATCH = "no_match"
    ALREADY_PRESENT = "already_present"
    MATERIALIZED = "materialized"

    @property
    def present(self) -> cython.bint:
        """Return whether the reload semantics are present after the operation."""
        return self is not _DirectStackReloadPlacement8616.NO_MATCH

    @property
    def changed(self) -> cython.bint:
        """Return whether this operation changed the structured C AST."""
        return self is _DirectStackReloadPlacement8616.MATERIALIZED


def _materialized_store_fact_for_reload_8616(
    reload_fact: DirectStackReloadFact8616,
    materialized_facts: object,
) -> DirectStackMoveFact8616 | None:
    """Return the unique materialized store fact that owns one exact reload."""
    candidates = tuple(
        dict.fromkeys(
            fact
            for fact in iter(materialized_facts)
            if operator.eq(fact.ins_addr, reload_fact.source_store_ins_addr)
            and operator.eq(fact.dst_offset, reload_fact.source_offset)
            and operator.eq(fact.width, reload_fact.width)
            and fact.source_kind is reload_fact.source_kind
        )
    )
    return candidates[0] if len(candidates) == 1 else None


class StackCarrierDeltaSource8616(Enum):
    """Evidence source for a recovered virtual stack-pointer carrier delta."""

    SP_REGISTER_SEED = "sp_register_seed"
    STACK_REFERENCE_SEED = "stack_reference_seed"
    ALIAS_OBSERVATION = "alias_observation"


_STACK_CARRIER_DELTA_SOURCE_PRIORITY_8616 = {
    StackCarrierDeltaSource8616.SP_REGISTER_SEED: 1,
    StackCarrierDeltaSource8616.STACK_REFERENCE_SEED: 2,
    StackCarrierDeltaSource8616.ALIAS_OBSERVATION: 3,
}


_UNRESOLVED_STACK_OFFSET_8616 = object()


@cython.ccall
def _type_for_access_width_8616(width: int | None) -> StructuredAstValue:
    if width == 1:
        return SimTypeChar(False)
    if width == 4:
        return SimTypeLong(False)
    return SimTypeShort(False)


@cython.ccall
def _bind_type_to_codegen_arch_8616(codegen: StructuredCodegenValue, type_: object) -> StructuredAstValue:
    arch: object
    arch = getattr(getattr(codegen, "project", None), "arch", None)
    if arch is None or type_ is None or getattr(type_, "_arch", None) is not None:
        return type_
    if not hasattr(type_, "with_arch"):
        return type_
    try:
        return type_.with_arch(arch)
    except Exception:
        return type_


@cython.ccall
def _bind_c_expr_type_to_codegen_arch_8616(codegen: StructuredCodegenValue, expr: object) -> None:
    current_type: object
    if expr is None:
        return
    current_type = getattr(expr, "variable_type", None)
    bound_type = _bind_type_to_codegen_arch_8616(codegen, current_type)
    if bound_type is not current_type:
        with contextlib.suppress(Exception):
            expr.variable_type = bound_type


@cython.ccall
def _dereference_access_width_bytes_8616(node: StructuredAstValue) -> int | None:
    dst_type: object
    operand: object
    width_bits: object
    width_bits = getattr(getattr(node, "type", None), "size", None)
    if isinstance(width_bits, int) and width_bits > 0:
        return max(width_bits // 8, 1)
    operand = getattr(node, "operand", None)
    if isinstance(operand, structured_c.CTypeCast):
        dst_type = getattr(operand, "dst_type", None)
        pts_to = getattr(dst_type, "pts_to", None) if isinstance(dst_type, SimTypePointer) else None
        width = _type_size_bytes_8616(pts_to, default=0)
        if width > 0:
            return width
    return None


@cython.ccall
def _cvar_storage_size_bytes_8616(cvar: StructuredAstValue, variable: StructuredAstValue) -> int | None:
    candidates: list[cython.longlong] = []
    size = variable.size if isinstance(variable, SimVariable) else None
    if isinstance(size, int) and size > 0:
        candidates.append(size)
    variable_type = cvar.variable_type if isinstance(cvar, structured_c.CVariable) else None
    type_size = _type_size_bytes_8616(variable_type, default=0)
    if isinstance(type_size, int) and type_size > 0:
        candidates.append(type_size)
    if not candidates:
        return None
    return min(candidates)


@cython.ccall
def _stack_bindings_from_codegen_8616(codegen: StructuredCodegenValue) -> tuple[StackVariableBinding, ...]:
    """Adapt concrete angr stack variables to the owned lowering contract once."""
    variable: object
    try:
        cfunc = codegen.cfunc
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        # Dynamic angr/codegen boundary: partial codegen fixtures may omit the
        # variable-manager surface entirely.
        return ()
    if not isinstance(variables_in_use, Mapping):
        return ()
    bindings: list[StackVariableBinding] = []
    for variable in variables_in_use:
        if not isinstance(variable, SimStackVariable):
            continue
        offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        size = variable.size
        if not isinstance(offset, int) or not isinstance(size, int) or size <= 0:
            continue
        bindings.append(
            StackVariableBinding(
                bp_offset=offset,
                size=size,
                var_name=variable.name,
            )
        )
    return tuple(bindings)


@cython.ccall
def _apply_preferred_stack_cvar_name_8616(
    cvar: StructuredAstValue, displacement: cython.longlong, codegen: StructuredAstValue
) -> None:
    """Apply the best known stack-object name to a CVariable surface."""
    target: object
    if not isinstance(cvar, structured_c.CVariable):
        return
    variable = cvar.variable
    byte_size = _cvar_storage_size_bytes_8616(cvar, variable)
    known_bindings = _stack_bindings_from_codegen_8616(codegen)
    preferred_name = _preferred_stack_object_name_8616(
        displacement,
        codegen=codegen,
        byte_size=byte_size,
        known_bindings=known_bindings,
    )
    if not isinstance(preferred_name, str) or not preferred_name:
        return
    for target in (variable, cvar.unified_variable):
        if target is None:
            continue
        with contextlib.suppress(Exception):
            if operator.ne(target.name, preferred_name):
                target.name = preferred_name


@cython.ccall
def _copy_existing_arg_surface_to_stack_cvar_8616(existing_arg: StructuredAstValue, cvar: StructuredAstValue) -> cython.bint:
    """Preserve stronger existing argument name/type evidence on a promoted body CVariable."""
    existing_type: object
    existing_variable: object
    target: object
    if existing_arg is cvar or not isinstance(cvar, structured_c.CVariable):
        return False
    changed = False
    existing_type = getattr(existing_arg, "variable_type", None)
    if existing_type is not None and operator.ne(getattr(cvar, "variable_type", None), existing_type):
        cvar.variable_type = existing_type
        changed = True
    existing_variable = getattr(existing_arg, "variable", None)
    existing_name = getattr(existing_variable, "name", None) or getattr(existing_arg, "name", None)
    if isinstance(existing_name, str) and existing_name and not _is_generated_stack_cvar_name_8616(existing_name):
        for target in (getattr(cvar, "variable", None), getattr(cvar, "unified_variable", None)):
            if target is None:
                continue
            with contextlib.suppress(Exception):
                if operator.ne(getattr(target, "name", None), existing_name):
                    target.name = existing_name
                    changed = True
    return changed


def _prototype_arg_type_for_bp_offset_8616(codegen: StructuredCodegenValue, offset: cython.longlong) -> StructuredAstValue | None:
    """Resolve a parameter type by its exact materialized BP coordinate."""
    cfunc: object
    variable: object
    arg_type: object
    argument: object
    proto: object
    if not isinstance(offset, int) or offset < 4:
        return None
    cfunc = getattr(codegen, "cfunc", None)
    physical_arguments = _boundary_tuple_8616(
        getattr(cfunc, "arg_list", ()) or ()
    )
    for proto in _candidate_function_prototypes_8616(codegen):
        prototype_arguments = _boundary_tuple_8616(
            getattr(proto, "args", ()) or ()
        )
        if prototype_arguments and operator.eq(len(physical_arguments), len(
            prototype_arguments
        )):
            physical_types: list[tuple[cython.longlong, StructuredAstValue]] = []
            for argument, arg_type in zip(
                physical_arguments,
                prototype_arguments,
                strict=True,
            ):
                variable = getattr(argument, "variable", None)
                bp_offset = (
                    machine_bp_offset_for_stack_variable_8616(codegen, variable)
                    if isinstance(variable, SimStackVariable)
                    else None
                )
                if not isinstance(bp_offset, int):
                    break
                physical_types.append((bp_offset, arg_type))
            else:
                matches = tuple(
                    arg_type
                    for bp_offset, arg_type in iter(physical_types)
                    if bp_offset == offset
                )
                return matches[0] if len(matches) == 1 else None
        current_offset = 4
        for arg_type in prototype_arguments:
            if current_offset == offset:
                return arg_type
            current_offset += max(2, _type_size_bytes_8616(arg_type))
    return None


@cython.ccall
def _canonical_arg_offset_8616(codegen: StructuredAstValue, arg: StructuredAstValue) -> int | None:
    """Return a canonical BP offset for an arg's backing stack variable."""
    arg_var: object
    arg_var = getattr(arg, "variable", None)
    if not isinstance(arg_var, SimStackVariable):
        return None
    return cast(
        "int | None",
        _canonical_stack_offset_8616(
            machine_bp_offset_for_stack_variable_8616(codegen, arg_var)
        ),
    )


@cython.ccall
def _bp_arg_offset_map_8616(codegen: StructuredAstValue, cfunc: StructuredAstValue) -> object:
    """Map positive BP argument offsets to their arg cvars."""
    arg_var: object
    arg: object
    arg_by_offset: dict[cython.longlong, StructuredAstValue] = {}
    for arg in _boundary_tuple_8616(getattr(cfunc, "arg_list", ()) or ()):
        arg_var = getattr(arg, "variable", None)
        arg_offset = _canonical_arg_offset_8616(codegen, arg)
        if isinstance(arg_var, SimStackVariable) and isinstance(arg_offset, int) and arg_offset > 2:
            arg_by_offset[arg_offset] = arg
    return arg_by_offset


@cython.ccall
def _prune_unified_stack_vars_at_offset_8616(
    codegen: StructuredAstValue, cfunc: StructuredAstValue, offset: cython.longlong
) -> None:
    """Drop stale unified-local entries aliasing the proven BP offset."""
    unified: object
    existing: object
    unified = getattr(cfunc, "unified_local_vars", None)
    if not isinstance(unified, dict):
        return
    for existing in tuple(unified.keys()):
        existing_offset = (
            _canonical_stack_offset_8616(
                machine_bp_offset_for_stack_variable_8616(codegen, existing)
            )
            if isinstance(existing, SimStackVariable)
            else None
        )
        if isinstance(existing, SimStackVariable) and existing_offset == offset:
            del unified[existing]


@cython.ccall
def _rebuild_cfunc_prototype_8616(codegen: StructuredAstValue, cfunc: StructuredAstValue) -> None:
    """Rebuild the function prototype from the reconciled arg list."""
    arch: object
    arg_var: object
    proto_arg_type: object
    prototype: object
    arg: object
    prototype = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    return_type = getattr(prototype, "returnty", None) if prototype is not None else SimTypeShort(False)
    arg_types = []
    for arg in cfunc.arg_list:
        arg_var = getattr(arg, "variable", None)
        arg_offset = _canonical_arg_offset_8616(codegen, arg)
        proto_arg_type = (
            _prototype_arg_type_for_bp_offset_8616(codegen, arg_offset) if isinstance(arg_offset, int) else None
        )
        arg_storage_width = arg_var.size if isinstance(arg_var, SimStackVariable) else 0
        if (
            proto_arg_type is not None
            and isinstance(arg_storage_width, int)
            and _type_size_bytes_8616(proto_arg_type, default=0) < arg_storage_width
        ):
            proto_arg_type = None
        arg_type = proto_arg_type or getattr(arg, "variable_type", None) or SimTypeShort(False)
        if proto_arg_type is not None and operator.ne(getattr(arg, "variable_type", None), proto_arg_type):
            arg.variable_type = proto_arg_type
        arg_types.append(arg_type)
    arg_names = [
        getattr(getattr(arg, "variable", None), "name", None) or getattr(arg, "name", None) or f"arg_{idx}"
        for idx, arg in builtins.iter(enumerate(cfunc.arg_list))
    ]
    new_proto = SimTypeFunction(arg_types, return_type, arg_names=arg_names)
    arch = getattr(getattr(codegen, "project", None), "arch", None)
    if arch is not None:
        new_proto = new_proto.with_arch(arch)
    with contextlib.suppress(Exception):
        cfunc.functy = new_proto
    with contextlib.suppress(Exception):
        cfunc.prototype = new_proto


@cython.ccall
def _ensure_positive_bp_stack_arg_8616(
    codegen: StructuredAstValue, cvar: StructuredAstValue, target_type: StructuredAstValue
) -> None:
    """Register a proven positive-BP stack CVariable without weakening argument evidence."""
    cfunc: object
    existing_arg: object
    prototype_type: object
    variable: object
    variables_in_use: object
    cfunc = getattr(codegen, "cfunc", None)
    variable = getattr(cvar, "variable", None)
    if cfunc is None or not isinstance(variable, SimStackVariable):
        return
    offset = _canonical_stack_offset_8616(
        machine_bp_offset_for_stack_variable_8616(codegen, variable)
    )
    if not isinstance(offset, int) or offset <= 2:
        return
    if getattr(variable, "base", None) != "bp":
        return
    prototype_type = _prototype_arg_type_for_bp_offset_8616(codegen, offset)
    target_width = _type_size_bytes_8616(target_type, default=0)
    effective_type = (
        prototype_type
        if prototype_type is not None
        and _type_size_bytes_8616(prototype_type, default=0) >= target_width
        else target_type
    )
    if operator.ne(getattr(cvar, "variable_type", None), effective_type):
        cvar.variable_type = effective_type
        if prototype_type is not None:
            codegen._inertia_stack_arg_source_prototype_type_materialized_8616 = (
                int(getattr(codegen, "_inertia_stack_arg_source_prototype_type_materialized_8616", 0) or 0) + 1
            )

    arg_by_offset = _bp_arg_offset_map_8616(codegen, cfunc)
    existing_arg = arg_by_offset.get(offset)
    if existing_arg is not None:
        _copy_existing_arg_surface_to_stack_cvar_8616(existing_arg, cvar)
    required_width = max(target_width, variable.size if isinstance(variable.size, int) else 0)
    _ensure_stack_cvar_min_width_8616(codegen, cvar, required_width)
    arg_by_offset[offset] = cvar
    cfunc.arg_list = [arg_by_offset[key] for key in builtins.iter(sorted(arg_by_offset))]

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    _prune_unified_stack_vars_at_offset_8616(codegen, cfunc, offset)
    _rebuild_cfunc_prototype_8616(codegen, cfunc)


@cython.ccall
def _projected_materialized_owner_8616(
    projected_value: StructuredAstValue,
    owner_projection: StructuredAstValue,
    projected_owner: StructuredAstValue,
    target_type: StructuredAstValue,
    variables_in_use: StructuredAstValue,
    codegen: StructuredAstValue,
) -> StructuredAstValue:
    """Accept the already-materialized owner cvar from the value projection."""
    if projected_owner.variable_type is None:
        projected_owner.variable_type = target_type
    owner_offset = owner_projection.bp_offset
    _apply_preferred_stack_cvar_name_8616(projected_owner, owner_offset, codegen)
    variable = projected_owner.variable
    if isinstance(variables_in_use, dict) and isinstance(variable, SimStackVariable):
        variables_in_use.setdefault(variable, projected_owner)
    _ensure_positive_bp_stack_arg_8616(codegen, projected_owner, target_type)
    return projected_value.expression


_NO_STACK_PROJECTION_8616 = object()


@cython.ccall
def _projected_stack_cvar_8616(
    projected_value: object,
    target_type: StructuredAstValue,
    variables_in_use: StructuredAstValue,
    codegen: StructuredAstValue,
) -> StructuredAstValue:
    """Resolve the projection outcome: owner cvar, refusal, or no projection."""
    owner_projection: object
    if projected_value is None:
        return _NO_STACK_PROJECTION_8616
    owner_projection = projected_value.owner
    projected_owner = owner_projection.cvar if owner_projection is not None else None
    if (
        projected_value.materialized
        and owner_projection is not None
        and isinstance(projected_owner, structured_c.CVariable)
    ):
        return _projected_materialized_owner_8616(
            projected_value, owner_projection, projected_owner, target_type, variables_in_use, codegen
        )
    if projected_value.status in {
        StackValueProjectionStatus8616.AMBIGUOUS_OWNER,
        StackValueProjectionStatus8616.OUTSIDE_VALUE,
        StackValueProjectionStatus8616.OWNER_NOT_EXPRESSION,
        StackValueProjectionStatus8616.UNSUPPORTED_WRITE_VIEW,
    }:
        return None
    return _NO_STACK_PROJECTION_8616


@cython.ccall
def _existing_stack_cvar_8616(
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    displacement: cython.longlong,
    requested_size: int | None,
    require_lvalue: cython.bint,
    target_type: StructuredAstValue,
    variables_in_use: StructuredAstValue,
) -> StructuredAstValue:
    """Reuse an existing arg-list or variables_in_use cvar for the displacement."""
    existing: object
    existing = _existing_arg_stack_cvar_8616(
        codegen, cfunc, displacement, requested_size, require_lvalue, target_type, variables_in_use
    )
    if existing is not None:
        return existing
    if isinstance(variables_in_use, dict):
        return _existing_variables_in_use_stack_cvar_8616(
            codegen, displacement, requested_size, require_lvalue, target_type, variables_in_use
        )
    return None


@cython.ccall
def _existing_stack_cvar_size_ok_8616(
    existing_size: int | None,
    requested_size: object,
    require_lvalue: cython.bint,
    displacement: cython.longlong,
) -> cython.bint:
    """Check the stored size of an existing cvar against the request."""
    return not (
        (requested_size is not None and isinstance(existing_size, int) and existing_size < requested_size)
        or (require_lvalue and requested_size is not None and operator.ne(existing_size, requested_size))
        or (
            displacement < 0
            and requested_size is not None
            and isinstance(existing_size, int)
            and operator.ne(existing_size, requested_size)
        )
    )


@cython.ccall
def _existing_arg_stack_cvar_8616(
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    displacement: cython.longlong,
    requested_size: int | None,
    require_lvalue: cython.bint,
    target_type: StructuredAstValue,
    variables_in_use: StructuredAstValue,
) -> StructuredAstValue:
    """Reuse an argument-list cvar already bound to the stack displacement."""
    variable: object
    arg: object
    for arg in getattr(cfunc, "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if not (
            isinstance(arg, structured_c.CVariable)
            and isinstance(variable, SimStackVariable)
            and operator.eq(_canonical_stack_offset_8616(
                machine_bp_offset_for_stack_variable_8616(codegen, variable)
            ), displacement)
        ):
            continue
        existing_size = _cvar_storage_size_bytes_8616(arg, variable)
        if not _existing_stack_cvar_size_ok_8616(
            existing_size, requested_size, require_lvalue, displacement
        ):
            continue
        if arg.variable_type is None:
            arg.variable_type = target_type
        _apply_preferred_stack_cvar_name_8616(arg, displacement, codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use.setdefault(variable, arg)
        _ensure_positive_bp_stack_arg_8616(codegen, arg, target_type)
        publish_selected_stack_cvar_projection_8616(
            codegen, arg, bp_offset=displacement, size=variable.size,
            entry_sp_offset=entry_sp_offset_for_machine_bp_range_8616(
                codegen, displacement, variable.size,
            ),
        )
        return arg
    return None


@cython.ccall
def _existing_variables_in_use_stack_cvar_8616(
    codegen: StructuredAstValue,
    displacement: cython.longlong,
    requested_size: int | None,
    require_lvalue: cython.bint,
    target_type: StructuredAstValue,
    variables_in_use: object,
) -> StructuredAstValue:
    """Reuse a variables_in_use cvar already bound to the stack displacement."""
    cvar: object
    variable: object
    for variable, cvar in variables_in_use.items():
        if not (
            isinstance(variable, SimStackVariable)
            and operator.eq(_canonical_stack_offset_8616(
                machine_bp_offset_for_stack_variable_8616(codegen, variable)
            ), displacement)
        ):
            continue
        existing_size = _cvar_storage_size_bytes_8616(cvar, variable)
        if not _existing_stack_cvar_size_ok_8616(
            existing_size, requested_size, require_lvalue, displacement
        ):
            continue
        if getattr(cvar, "variable_type", None) is None:
            cvar.variable_type = target_type
        _apply_preferred_stack_cvar_name_8616(cvar, displacement, codegen)
        _ensure_positive_bp_stack_arg_8616(codegen, cvar, target_type)
        publish_selected_stack_cvar_projection_8616(
            codegen, cvar, bp_offset=displacement, size=variable.size,
            entry_sp_offset=entry_sp_offset_for_machine_bp_range_8616(
                codegen, displacement, variable.size,
            ),
        )
        return cvar
    return None


@cython.ccall
def _entry_sp_fallback_cvar_8616(
    codegen: StructuredAstValue,
    displacement: cython.longlong,
    storage_size: cython.longlong,
    instruction_access: object,
    target_type: StructuredAstValue,
) -> StructuredAstValue:
    """Materialize from instruction evidence when entry-SP mapping fails."""
    if (
        instruction_access is None
        or operator.ne(instruction_access.displacement, displacement)
        or operator.ne(instruction_access.size, storage_size)
    ):
        return None
    cvar = _resolve_direct_stack_update_cvar_8616(
        codegen,
        displacement,
        storage_size,
    )
    if not isinstance(cvar, structured_c.CVariable):
        return None
    _ensure_stack_cvar_min_width_8616(codegen, cvar, storage_size)
    _ensure_positive_bp_stack_arg_8616(codegen, cvar, target_type)
    return cvar


@cython.ccall
def stack_cvar_for_stable_ss_linear_access_8616(
    codegen: StructuredAstValue,
    access: RealModeLinearStackAccess8616,
    *,
    instruction_access: InstructionBpStackAccess8616 | None = None,
    owner_hint: StackValueOwnerHint8616 | None = None,
    require_lvalue: cython.bint = False,
) -> StructuredAstValue | None:
    """Materialize a proven SS access, retaining exact instruction evidence."""
    cfunc: object
    existing: object
    requested_size: object
    variables_in_use: object
    if access.entry_sp_offset is not None:
        if access.width is None or access.width <= 0:
            return None
        return materialize_stack_cvar_at_offset_from_facts_8616(
            codegen, access.entry_sp_offset, access.width, publish_machine_bp=False,
        )
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    displacement = _canonical_stack_offset_8616(access.displacement)
    if not isinstance(displacement, int):
        return None
    if not _positive_bp_stack_access_has_arg_evidence_8616(codegen, displacement, access.width):
        codegen._inertia_positive_bp_stack_access_without_arg_evidence_refused_8616 = (
            int(getattr(codegen, "_inertia_positive_bp_stack_access_without_arg_evidence_refused_8616", 0) or 0) + 1
        )
        return None
    target_type = _type_for_access_width_8616(access.width)
    requested_size = int(access.width) if isinstance(access.width, int) and access.width > 0 else None
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    projected_value = (
        project_stack_value_range_8616(
            codegen,
            displacement,
            requested_size,
            owner_hint=owner_hint,
            require_lvalue=require_lvalue,
        )
        if requested_size is not None
        else None
    )
    projected = _projected_stack_cvar_8616(
        projected_value, target_type, variables_in_use, codegen
    )
    if projected is not _NO_STACK_PROJECTION_8616:
        return projected
    existing = _existing_stack_cvar_8616(
        codegen, cfunc, displacement, requested_size, require_lvalue, target_type, variables_in_use
    )
    if existing is not None:
        return existing
    return _materialize_ss_access_cvar_8616(
        codegen, displacement, requested_size, instruction_access, target_type
    )


@cython.ccall
def _materialize_ss_access_cvar_8616(
    codegen: StructuredAstValue,
    displacement: cython.longlong,
    requested_size: int | None,
    instruction_access: InstructionBpStackAccess8616 | None,
    target_type: StructuredAstValue,
) -> StructuredAstValue | None:
    """Materialize the access cvar from facts or the entry-SP fallback."""
    entry_sp_offset: object
    storage_size = requested_size or 1
    entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(
        codegen,
        displacement,
        storage_size,
    )
    if entry_sp_offset is None:
        return _entry_sp_fallback_cvar_8616(
            codegen, displacement, storage_size, instruction_access, target_type
        )
    cvar = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        entry_sp_offset,
        storage_size,
        machine_bp_offset=displacement,
        preferred_name=_preferred_stack_object_name_8616(
            displacement,
            codegen=codegen,
            byte_size=storage_size,
            known_bindings=_stack_bindings_from_codegen_8616(codegen),
        ),
    )
    if not isinstance(cvar, structured_c.CVariable):
        return None
    if cvar.variable_type is None:
        cvar.variable_type = target_type
    _ensure_positive_bp_stack_arg_8616(codegen, cvar, target_type)
    return cvar


@cython.ccall
def _positive_stack_spec_lookup_bias_8616(stack_specs: object) -> cython.longlong:
    positive_offsets = {int(key) for key in iter(stack_specs) if isinstance(key, int) and key > 0}
    # Some debug/object-file stack maps are biased by the near return address:
    # source arg0 is recorded at +2 while the linked binary uses BP+4. Pick one
    # bias for all positive argument slots; probing offset and offset-2 per slot
    # can collapse BP+4 and BP+6 onto the same source name.
    if 2 in positive_offsets and 6 not in positive_offsets:
        return -2
    return 0


@cython.ccall
def _stack_object_func_8616(codegen: object, cfunc: object) -> StructuredAstValue:
    """Resolve the angr function backing the active cfunc."""
    func: object
    funcs: object
    try:
        func = codegen._func if codegen is not None else None
    except AttributeError:
        func = None
    if func is None and cfunc is not None:
        assert codegen is not None
        project = codegen.project
        try:
            funcs = project.kb.functions
        except AttributeError:
            # Tests and embedding callers may expose only the project arch.
            funcs = None
        func_addr = cfunc.addr
        if funcs is not None and isinstance(func_addr, int):
            with contextlib.suppress(Exception):
                func = funcs.function(addr=func_addr, create=False)
    return func


@cython.ccall
def _stack_spec_candidate_offsets_8616(
    offset: cython.longlong,
    codegen: object,
    stack_specs: object,
) -> object:
    """Build the ordered BP-offset candidates including stack-base biases."""
    candidate_offsets = [offset]
    stack_base_bias = None
    if isinstance(offset, int):
        try:
            stack_base_bias = codegen._inertia_active_stack_base_bp_bias_8616 if codegen is not None else None
        except AttributeError:
            stack_base_bias = None
        if not isinstance(stack_base_bias, int) and codegen is not None:
            with contextlib.suppress(Exception):
                stack_base_bias = _infer_stack_base_bp_bias_8616(codegen)
        if not isinstance(stack_base_bias, int) and codegen is not None and _has_bp_stack_alias_evidence_8616(codegen):
            stack_base_bias = 2
        if isinstance(stack_base_bias, int) and stack_base_bias != 0:
            candidate_offsets.append(offset - stack_base_bias)
    if isinstance(offset, int) and offset > 2:
        bias = _positive_stack_spec_lookup_bias_8616(stack_specs)
        if bias != 0:
            candidate_offsets.insert(0, offset + bias)
    return candidate_offsets


@cython.ccall
def _resolved_stack_spec_size_8616(
    offset: cython.longlong,
    byte_size: int | None,
    bindings: object,
) -> cython.longlong:
    """Pick the size for the stack annotation binding."""
    resolved_size = byte_size
    if not isinstance(resolved_size, int) or resolved_size <= 0:
        matching_sizes = [binding.size for binding in iter(bindings) if operator.eq(binding.bp_offset, offset)]
        resolved_size = max(matching_sizes, default=1)
    return resolved_size


@cython.ccall
def _preferred_stack_object_name_8616(
    offset: cython.longlong,
    codegen: StructuredCodegenValue = None,
    *,
    byte_size: int | None = None,
    known_bindings: object = None,
) -> object:
    """Return an annotation name only for the matching proven stack object."""
    func: object
    selected: object
    default_name = machine_bp_stack_object_name_8616(offset, codegen=codegen)
    cfunc = codegen.cfunc if codegen is not None else None
    func = _stack_object_func_8616(codegen, cfunc)
    try:
        info = func.info if func is not None else None
    except AttributeError:
        info = None
    annotations = info.get("x86_16_annotations") if isinstance(info, dict) else None
    stack_specs = annotations.get("stack_vars") if isinstance(annotations, dict) else None
    if not isinstance(stack_specs, dict):
        return default_name
    candidate_offsets = _stack_spec_candidate_offsets_8616(offset, codegen, stack_specs)
    bindings = known_bindings if known_bindings is not None else (
        _stack_bindings_from_codegen_8616(codegen) if codegen is not None else ()
    )
    binding = StackVariableBinding(
        offset, _resolved_stack_spec_size_8616(offset, byte_size, bindings), var_name=default_name
    )
    selected = select_stack_annotation_spec_8616(
        binding,
        stack_specs=stack_specs,
        candidate_offsets=candidate_offsets,
        known_bindings=bindings,
    )
    if selected is not None and selected.name is not None:
        selected_name = selected.name
        if isinstance(selected_name, str):
            return selected_name
    return default_name


@cython.ccall
def _strip_casts_8616(node: StructuredAstValue) -> StructuredAstValue:
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


@cython.ccall
def _constant_value_8616(node: StructuredAstValue) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


@cython.ccall
def _sim_variable_global_address_8616(variable: StructuredAstValue) -> int | None:
    if isinstance(variable, SimMemoryVariable):
        addr = variable.addr
        return (int(addr) & 0xFFFF) if isinstance(addr, int) else None
    if isinstance(variable, SimVariable):
        # Internal fallback used by the structured codegen when a global address
        # label exists without a SimMemoryVariable identity.
        name = variable.name
        if isinstance(name, str) and len(name) == 6 and name.startswith("g_"):
            try:
                return int(name[2:], 16) & 0xFFFF
            except ValueError:
                return None
    return None


@cython.ccall
def _address_label_value_8616(node: StructuredAstValue, *, allow_sp_anchor: cython.bint = False) -> int | None:
    """Return an address literal carried by an address-label C expression.

    This is intentionally narrower than `_constant_value_8616`: it only applies
    inside real-mode effective-address decomposition, where a materialized
    `&global` label is evidence for an offset, not a pointer-valued data use.
    """
    addr: object
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Reference":
        return None
    operand = _strip_casts_8616(getattr(node, "operand", None))
    if not isinstance(operand, structured_c.CVariable):
        return None
    variable = operand.variable
    addr = _sim_variable_global_address_8616(variable)
    if addr is not None:
        return addr
    if allow_sp_anchor and isinstance(variable, SimStackVariable):
        base = variable.base
        offset = variable.offset
        if base == "sp" and offset == 0:
            return 0
    return None


def _term_contains_memory_address_label_8616(node: StructuredAstValue) -> cython.bint:
    child: object
    children: object
    expr: object
    variable: object
    attr: object
    pending: list[StructuredAstValue] = [_strip_casts_8616(node)]
    seen: set[cython.longlong] = set()
    while pending:
        expr = _strip_casts_8616(pending.pop())
        if expr is None:
            continue
        expr_id = id(expr)
        if expr_id in seen:
            continue
        seen.add(expr_id)
        if isinstance(expr, structured_c.CUnaryOp) and expr.op == "Reference":
            operand = _strip_casts_8616(expr.operand)
            variable = getattr(operand, "variable", None)
            if _sim_variable_global_address_8616(variable) is not None:
                return True
            pending.append(operand)
            continue
        for attr in ("lhs", "rhs", "operand", "expr", "index"):
            child = getattr(expr, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("args", "operands"):
            children = getattr(expr, attr, None)
            if isinstance(children, (list, tuple)):
                pending.extend(child for child in iter(children) if child is not None)
    return False


@cython.ccall
def _normalize_address_label_terms_8616(
    node: StructuredAstValue,
    codegen: StructuredCodegenValue = None,
    *,
    allow_sp_anchor: cython.bint = False,
) -> tuple[StructuredAstValue, cython.longlong]:
    """Fold address-label references to integer offsets inside EA arithmetic."""
    folded_value: object
    if isinstance(node, CSemanticCast8616):
        expression, count = _normalize_address_label_terms_8616(
            node.expr, codegen=codegen, allow_sp_anchor=allow_sp_anchor,
        )
        if not count:
            return node, 0
        # Required truncation/extension is part of the retained term's value,
        # even when address labels beneath it can be resolved to offsets.
        return CSemanticCast8616(
            node.src_type, node.dst_type, expression,
            codegen=node.codegen or codegen, tags=node.tags,
        ), count
    folded_value = _address_label_value_8616(node, allow_sp_anchor=allow_sp_anchor)
    if folded_value is not None:
        ctype = SimTypeShort(False)
        return structured_c.CConstant(
            folded_value,
            ctype,
            codegen=getattr(node, "codegen", None) or codegen,
        ), 1

    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CUnaryOp):
        operand, count = _normalize_address_label_terms_8616(
            node.operand,
            codegen=codegen,
            allow_sp_anchor=allow_sp_anchor,
        )
        if count:
            return structured_c.CUnaryOp(node.op, operand, codegen=node.codegen or codegen), count
        return node, 0
    if isinstance(node, structured_c.CBinaryOp):
        lhs, lhs_count = _normalize_address_label_terms_8616(
            node.lhs,
            codegen=codegen,
            allow_sp_anchor=allow_sp_anchor,
        )
        rhs, rhs_count = _normalize_address_label_terms_8616(
            node.rhs,
            codegen=codegen,
            allow_sp_anchor=allow_sp_anchor,
        )
        count = lhs_count + rhs_count
        if count:
            return structured_c.CBinaryOp(node.op, lhs, rhs, codegen=node.codegen or codegen), count
        return node, 0
    return node, 0


@cython.ccall
def _has_bp_stack_alias_evidence_8616(codegen: StructuredAstValue) -> cython.bint:
    facts: object
    variables_in_use: object
    fact: object
    variable: object
    facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if isinstance(facts, list):
        for fact in facts:
            if not isinstance(fact, AliasStorageFacts):
                continue
            identity = fact.identity
            if not (isinstance(identity, tuple) and len(identity) >= 2 and identity[0] == "stack"):
                continue
            slot = identity[1]
            if isinstance(slot, _StackSlotIdentity) and slot.base == "bp":
                return True

    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in variables_in_use:
            if isinstance(variable, SimStackVariable) and getattr(variable, "base", None) == "bp":
                return True
    return False


@cython.ccall
def _bp_offsets_from_alias_facts_8616(facts: StructuredAstValue) -> object:
    """Collect canonical BP offsets from stack-alias storage facts."""
    fact: object
    offsets: set[cython.longlong] = set()
    if not isinstance(facts, list):
        return offsets
    for fact in facts:
        if not isinstance(fact, AliasStorageFacts):
            continue
        identity = fact.identity
        if not (isinstance(identity, tuple) and len(identity) >= 2 and identity[0] == "stack"):
            continue
        slot = identity[1]
        if not isinstance(slot, _StackSlotIdentity) or slot.base != "bp":
            continue
        offset = _canonical_stack_offset_8616(slot.offset)
        if isinstance(offset, int):
            offsets.add(offset)
    return offsets


@cython.ccall
def _bp_offsets_from_bindings_8616(bindings: StructuredAstValue) -> object:
    """Collect canonical BP offsets from stack-variable bindings."""
    binding: object
    offsets: set[cython.longlong] = set()
    if not isinstance(bindings, tuple):
        return offsets
    for binding in bindings:
        if not isinstance(binding, StackVariableBinding):
            continue
        offset = _canonical_stack_offset_8616(binding.bp_offset)
        if isinstance(offset, int):
            offsets.add(offset)
    return offsets


@cython.ccall
def _bp_offset_of_stack_variable_8616(
    codegen: StructuredAstValue, variable: StructuredAstValue
) -> int | None:
    """Resolve a canonical BP offset for a SimStackVariable, or None."""
    if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
        return None
    return cast("int | None", _canonical_stack_offset_8616(machine_bp_offset_for_stack_variable_8616(codegen, variable)))


@cython.ccall
def _known_bp_stack_offsets_8616(codegen: StructuredAstValue) -> object:
    cfunc: object
    variables_in_use: object
    arg: object
    variable: object
    cfunc = getattr(codegen, "cfunc", None)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    arg_list = getattr(cfunc, "arg_list", ()) or ()

    offsets: set[cython.longlong] = set()
    offsets.update(_bp_offsets_from_alias_facts_8616(getattr(codegen, "_inertia_semantic_alias_facts", None)))
    offsets.update(_bp_offsets_from_bindings_8616(getattr(codegen, "_inertia_stack_variable_bindings", None)))

    if isinstance(variables_in_use, dict):
        for variable in variables_in_use:
            offset = _bp_offset_of_stack_variable_8616(codegen, variable)
            if isinstance(offset, int):
                offsets.add(offset)

    for arg in arg_list:
        offset = _bp_offset_of_stack_variable_8616(codegen, getattr(arg, "variable", None))
        if isinstance(offset, int):
            offsets.add(offset)

    offsets.update(_prototype_bp_stack_offsets_8616(codegen))
    offsets.update(_bp_memory_operand_offsets_from_function_blocks_8616(codegen))

    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[ss-linear-lowering] known-bp-offsets function=%#x offsets=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            tuple(sorted(offsets)),
        )

    return offsets


def _typed_stack_probe_return_facts_8616(codegen: StructuredAstValue) -> tuple[TypedStackProbeReturnFact8616, ...]:
    """Return lowering-owned typed stack-probe facts attached to codegen."""
    facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}
    if not isinstance(facts, dict):
        return ()
    return tuple(fact for fact in builtins.iter(facts.values()) if isinstance(fact, TypedStackProbeReturnFact8616))


@cython.ccall
def _bp_stack_arg_offsets_8616(codegen: StructuredCodegenValue) -> object:
    variable: object
    arg: object
    offsets: set[cython.longlong] = set()
    for arg in getattr(getattr(codegen, "cfunc", None), "arg_list", ()) or ():
        variable = getattr(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        offset = _canonical_stack_offset_8616(
            machine_bp_offset_for_stack_variable_8616(codegen, variable)
        )
        if isinstance(offset, int):
            offsets.add(offset)

    offsets.update(_prototype_bp_stack_offsets_8616(codegen))
    return offsets


@cython.ccall
def _positive_bp_stack_access_has_arg_evidence_8616(
    codegen: StructuredAstValue, offset: cython.longlong, width: int | None
) -> cython.bint:
    """Return whether a positive BP offset is proven as an argument slot."""
    if not isinstance(offset, int) or offset <= 2:
        return True
    return (
        offset in _bp_stack_arg_offsets_8616(codegen)
        or offset in _known_bp_stack_offsets_8616(codegen)
        or _has_stack_storage_evidence_for_displacement_8616(codegen, offset, width)
    )


@cython.ccall
def _bp_stack_abi_argument_region_offsets_8616(offsets: object) -> set[cython.longlong]:
    # In near BP-framed 16-bit C functions, BP+0 is saved BP and BP+2 is the
    # return address. Positive data arguments begin at BP+4. If this filtered
    # set is still ambiguous, carrier inference refuses instead of guessing.
    return {offset for offset in iter(offsets) if offset >= 4}


@cython.ccall
def _type_size_bytes_8616(type_: StructuredAstValue, *, default: cython.longlong = 2) -> cython.longlong:
    bits: object
    if isinstance(type_, SimTypeChar):
        return 1
    if isinstance(type_, SimTypeShort):
        return 2
    try:
        bits = getattr(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


@cython.ccall
def _owner_candidate_prototypes_8616(
    codegen: StructuredAstValue, cfunc: StructuredAstValue
) -> tuple[list[StructuredAstValue], list[StructuredAstValue]]:
    """Return (proven, deferred) prototypes collected from function owners."""
    func_addr: object
    kb: object
    owner: object
    project: object
    proto: object
    proven: list[StructuredAstValue] = []
    deferred: list[StructuredAstValue] = []
    project = getattr(codegen, "project", None)
    func_addr = getattr(cfunc, "addr", None)
    owner_candidates = [
        getattr(codegen, "_func", None),
        getattr(codegen, "function", None),
        getattr(codegen, "func", None),
    ]
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is not None and isinstance(func_addr, int):
        with contextlib.suppress(Exception):
            owner_candidates.append(kb.functions.function(addr=func_addr, create=False))

    for owner in owner_candidates:
        info = getattr(owner, "info", None) if owner is not None else None
        annotations = info.get(ANNOTATION_KEY) if isinstance(info, Mapping) else None
        annotated_prototype = annotations.get("prototype") if isinstance(annotations, Mapping) else None
        if isinstance(annotated_prototype, SimTypeFunction) and annotated_prototype not in proven:
            proven.append(annotated_prototype)
        proto = getattr(owner, "prototype", None) if owner is not None else None
        if proto is None:
            continue
        if getattr(owner, "is_prototype_guessed", True) is False:
            if proto not in proven:
                proven.append(proto)
        elif proto not in deferred:
            deferred.append(proto)
    return proven, deferred


@cython.ccall
def _candidate_function_prototypes_8616(codegen: StructuredCodegenValue) -> tuple[StructuredAstValue, ...]:
    cfunc: object
    proto: object
    attr: object
    cfunc = getattr(codegen, "cfunc", None)
    prototypes, deferred_owner_prototypes = _owner_candidate_prototypes_8616(codegen, cfunc)
    for attr in ("functy", "prototype"):
        proto = getattr(cfunc, attr, None)
        if proto is not None and proto not in prototypes:
            prototypes.append(proto)
    for proto in deferred_owner_prototypes:
        if proto not in prototypes:
            prototypes.append(proto)
    return tuple(prototypes)


@cython.ccall
def _prototype_bp_stack_offsets_8616(codegen: StructuredAstValue) -> object:
    """Return BP argument offsets implied by known function prototypes."""
    cached: object
    cfunc: object
    arg_type: object
    proto: object
    cfunc = getattr(codegen, "cfunc", None)
    cached = getattr(codegen, "_inertia_preserved_prototype_bp_stack_offsets_8616", None)
    offsets: object = (
        set(cached[1]) if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is cfunc else set()
    )
    for proto in _candidate_function_prototypes_8616(codegen):
        proto_args = _boundary_tuple_8616(getattr(proto, "args", ()) or ())
        if not proto_args:
            continue
        offset = 4
        for arg_type in proto_args:
            offsets.add(offset)
            offset += max(2, _type_size_bytes_8616(arg_type))
    if offsets:
        codegen._inertia_preserved_prototype_bp_stack_offsets_8616 = (cfunc, frozenset(offsets))
        codegen._inertia_stack_arg_offsets_from_prototype_count_8616 = max(
            int(getattr(codegen, "_inertia_stack_arg_offsets_from_prototype_count_8616", 0) or 0),
            len(offsets),
        )
    return offsets


@cython.ccall
def _candidate_functions_for_stack_facts_8616(
    codegen: StructuredCodegenValue,
    project: StructuredAstValue | None = None,
) -> tuple[StructuredAstValue, ...]:
    """Return deduplicated function owners available at the angr boundary."""
    candidate: object
    cfunc: object
    func_addr: object
    kb: object
    addr: object
    if project is None:
        project = getattr(codegen, "project", None)
    candidates = [
        candidate
        for candidate in iter((
            getattr(codegen, "_inertia_current_function_8616", None),
            getattr(codegen, "function", None),
            getattr(codegen, "_func", None),
            getattr(getattr(codegen, "cfunc", None), "function", None),
        ))
        if candidate is not None
    ]
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is not None and isinstance(func_addr, int):
        delta = int(getattr(project, "_inertia_original_linear_delta", 0) or 0)
        for addr in (func_addr, func_addr + delta):
            with contextlib.suppress(Exception):
                candidate = kb.functions.function(addr=addr, create=False)
                if candidate is not None:
                    candidates.append(candidate)
    deduped: list[StructuredAstValue] = []
    seen_ids: set[cython.longlong] = set()
    for candidate in candidates:
        if id(candidate) in seen_ids:
            continue
        seen_ids.add(id(candidate))
        deduped.append(candidate)
    return tuple(deduped)


def _bp_memory_operand_offsets_from_function_blocks_8616(codegen: StructuredCodegenValue) -> object:
    """Return BP-relative displacements from one cached scan of function blocks."""
    cached: object
    capstone: object
    cfunc: object
    disp: object
    mem: object
    block: object
    function: object
    insn: object
    operand: object
    functions = _candidate_functions_for_stack_facts_8616(codegen)
    cfunc = getattr(codegen, "cfunc", None)
    code_function_identity = id(cfunc)
    function_identities = tuple(id(function) for function in iter(functions))
    cached = getattr(codegen, "_inertia_bp_memory_operand_offset_cache_8616", None)
    if (
        isinstance(cached, _BpMemoryOperandOffsetCache8616)
        and operator.eq(cached.code_function_identity, code_function_identity)
        and operator.eq(cached.function_identities, function_identities)
    ):
        return set(cached.offsets)

    offsets: set[cython.longlong] = set()
    for function in functions:
        for block in getattr(function, "blocks", ()) or ():
            capstone = getattr(block, "capstone", None)
            for insn in getattr(capstone, "insns", ()) or ():
                for operand in getattr(insn, "operands", ()) or ():
                    if operator.ne(getattr(operand, "type", None), X86_OP_MEM):
                        continue
                    mem = getattr(operand, "mem", None)
                    if operator.ne(getattr(mem, "base", None), X86_REG_BP):
                        continue
                    disp = getattr(mem, "disp", None)
                    if isinstance(disp, int):
                        offsets.add(disp)
    codegen._inertia_bp_memory_operand_offset_cache_8616 = _BpMemoryOperandOffsetCache8616(
        code_function_identity=code_function_identity,
        function_identities=function_identities,
        offsets=frozenset(offsets),
    )
    if offsets:
        codegen._inertia_stack_bp_offsets_from_capstone_count_8616 = len(offsets)
    return offsets


@cython.ccall
def _stack_base_displacement_8616(node: StructuredAstValue) -> int | None:
    """Fold a ``stack_base [+/- const]`` expression into a displacement."""
    lhs: object
    rhs: object
    node = _strip_casts_8616(node)
    if _is_stack_base_placeholder_8616(node):
        return 0
    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs = _stack_base_displacement_8616(node.lhs)
        rhs = _stack_base_displacement_8616(node.rhs)
        lhs_const = _constant_value_8616(node.lhs)
        rhs_const = _constant_value_8616(node.rhs)
        if lhs is not None and isinstance(rhs_const, int):
            return lhs + (rhs_const if node.op == "Add" else -rhs_const)
        if rhs is not None and isinstance(lhs_const, int) and node.op == "Add":
            return rhs + lhs_const
    return None


_STACK_BASE_CHILD_ATTRS_8616 = (
    "statements",
    "condition_and_nodes",
    "else_node",
    "lhs",
    "rhs",
    "operand",
    "variable",
    "index",
    "expr",
    "stmts",
    "init",
    "initializer",
    "iftrue",
    "iffalse",
    "iteration",
    "iterator",
    "body",
    "args",
    "operands",
)


@cython.ccall
def _push_stack_base_children_8616(node: StructuredAstValue, stack: object) -> None:
    """Push all structured-codegen child nodes for the displacement walk."""
    value: object
    attr: object
    item: object
    for attr in _STACK_BASE_CHILD_ATTRS_8616:
        if not hasattr(node, attr):
            continue
        try:
            value = getattr(node, attr)
        except Exception:
            continue
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            for item in reversed(tuple(value)):
                if isinstance(item, tuple):
                    stack.extend(reversed(item))
                else:
                    stack.append(item)
        else:
            stack.append(value)


@cython.ccall
def _record_stack_base_subexpr_displacements_8616(
    node: StructuredAstValue, displacements: object
) -> None:
    """Record displacements from indexed/dereferenced stack_base subexpressions."""
    if isinstance(node, structured_c.CIndexedVariable):
        base_disp = _stack_base_displacement_8616(node.variable)
        index_value = _constant_value_8616(node.index)
        if isinstance(base_disp, int) and isinstance(index_value, int):
            displacements.add(base_disp + index_value)

    if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
        disp = _stack_base_displacement_8616(node.operand)
        if isinstance(disp, int):
            displacements.add(disp)


@cython.ccall
def _iter_stack_base_displacements_8616(root: StructuredAstValue) -> tuple[cython.longlong, ...]:
    """Collect all ``stack_base`` displacement observations under a statement root."""
    node: object
    stack = [root]
    seen: set[cython.longlong] = set()
    displacements: set[cython.longlong] = set()
    while stack:
        node = stack.pop()
        if node is None:
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)

        disp = _stack_base_displacement_8616(node)
        if isinstance(disp, int):
            displacements.add(disp)
            # Consume the maximal stack_base expression. Recursing into its
            # children would add the bare stack_base as a separate zero-offset
            # observation and can make BP-bias evidence ambiguous.
            continue

        _record_stack_base_subexpr_displacements_8616(node, displacements)
        _push_stack_base_children_8616(node, stack)

    return tuple(sorted(displacements))



@cython.ccall
def _infer_bp_bias_from_multi_displacements_8616(
    displacements: object, known_offsets: object
) -> int | None:
    """Vote on one BP bias when two or more stack_base displacements exist."""
    disp: object
    offset: object
    best_bias = None
    best_score = 0
    tied = False
    for disp in displacements:
        for offset in known_offsets:
            bias = offset - disp
            score = len({candidate + bias for candidate in iter(displacements) if candidate + bias in known_offsets})
            if score > best_score:
                best_bias = bias
                best_score = score
                tied = False
            elif score == best_score and score > 0 and bias != best_bias:
                tied = True
    if isinstance(best_bias, int) and best_score >= 2 and not tied:
        return best_bias
    return None


@cython.ccall
def _infer_stack_base_bp_bias_8616(codegen: StructuredCodegenValue) -> int | None:
    """Infer a BP bias from one exact structured-C and stack-evidence snapshot."""
    root = codegen.cfunc.statements
    known_offsets = _known_bp_stack_offsets_8616(codegen)
    displacements = _iter_stack_base_displacements_8616(root)
    try:
        cached = codegen._inertia_stack_base_bp_bias_evidence_8616
    except AttributeError:
        cached = None
    if isinstance(cached, StackBaseBpBiasEvidence8616) and cached.matches(root, displacements, known_offsets):
        cached_bias = cached.inferred_bias
        return cached_bias if isinstance(cached_bias, int) else None

    inferred: int | None = None

    if len(displacements) >= 2 and known_offsets:
        inferred = _infer_bp_bias_from_multi_displacements_8616(displacements, known_offsets)
    elif len(displacements) == 1 and known_offsets:
        # Exact-entry BP-framed slices may expose only one stack_base-relative
        # argument load, e.g. entry-SP+2 == BP+4 after `push bp; mov bp, sp`.
        # Keep this single-observation bridge narrow: one ABI argument slot and
        # only the two proven BP-frame biases used elsewhere in this module.
        abi_offsets = _bp_stack_abi_argument_region_offsets_8616(known_offsets)
        if len(abi_offsets) == 1:
            bias = next(iter(abi_offsets)) - displacements[0]
            if bias in {0, 2}:
                inferred = bias

    codegen._inertia_stack_base_bp_bias_evidence_8616 = StackBaseBpBiasEvidence8616(
        statement_root=root,
        stack_base_displacements=displacements,
        known_bp_offsets=frozenset(known_offsets),
        inferred_bias=inferred,
    )
    if isinstance(inferred, int):
        codegen._inertia_stack_base_bp_bias_inferred_count_8616 = (
            int(getattr(codegen, "_inertia_stack_base_bp_bias_inferred_count_8616", 0) or 0) + 1
        )
        if len(displacements) == 1:
            codegen._inertia_stack_base_bp_bias_single_arg_inferred_count_8616 = (
                int(getattr(codegen, "_inertia_stack_base_bp_bias_single_arg_inferred_count_8616", 0) or 0) + 1
            )
    return inferred


@cython.ccall
def _stack_base_bp_bias_8616(node: StructuredAstValue, codegen: StructuredCodegenValue = None) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base":
        active_bias = getattr(codegen, "_inertia_active_stack_base_bp_bias_8616", None) if codegen is not None else None
        if isinstance(active_bias, int):
            return active_bias
        inferred = _infer_stack_base_bp_bias_8616(codegen) if codegen is not None else None
        if isinstance(inferred, int):
            return inferred
        # angr's stack_base is the entry-SP placeholder. In BP-framed 16-bit
        # functions, `push bp; mov bp, sp` makes BP two bytes below entry SP.
        return 2 if _has_bp_stack_alias_evidence_8616(codegen) else None
    return None


@cython.ccall
def _is_stack_base_placeholder_8616(node: StructuredAstValue) -> cython.bint:
    node = _strip_casts_8616(node)
    return isinstance(node, structured_c.CFakeVariable) and getattr(node, "name", None) == "stack_base"


@cython.ccall
def _segment_base_name_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue = None
) -> object:
    """Return the segment register name for ``seg << 4`` or ``seg * 16``.

    If the segment term is a temporary name (for example ``vvar_*``), resolve
    its defining expression and retry. This keeps SS/DS/ES lowering sound while
    still avoiding speculative text-driven matching.
    """
    return _segment_base_name_8616_impl(node, project, codegen, set())


@cython.ccall
def _segment_base_name_from_dirty_8616(
    dirty: StructuredAstValue,
    project: AngrProjectValue,
    codegen: object,
    seen: object,
) -> object:
    """Resolve a segment name from an angr dirty-temp leaf."""
    dirty_name: object
    reg_name: object
    rhs: object
    varid: object
    reg = _dirty_reg_offset_8616(dirty)
    if isinstance(reg, int):
        reg_name = getattr(project.arch, "register_names", {}).get(reg)
        if isinstance(reg_name, str) and reg_name in _SEGMENT_REGISTER_NAMES_8616:
            return reg_name
    dirty_name = getattr(dirty, "name", None)
    varid = getattr(dirty, "varid", None)
    if isinstance(varid, int):
        dirty_name = f"vvar_{varid}"
    if isinstance(dirty_name, str) and dirty_name.startswith(("vvar_", "tmp_", "ir_")) and codegen is not None:
        rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, dirty_name)
        if rhs is not None:
            return _segment_base_name_8616_impl(rhs, project, codegen, seen)
    return None


@cython.ccall
def _segment_base_name_from_leaf_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    codegen: object,
    seen: object,
) -> object:
    """Resolve a segment name from a non-binary-op leaf node."""
    dirty: object
    dirty_name: object
    reg_name: object
    rhs: object
    dirty = getattr(node, "dirty", None)
    if dirty is not None:
        dirty_name = _segment_base_name_from_dirty_8616(dirty, project, codegen, seen)
        if dirty_name is not None:
            return dirty_name
    if isinstance(node, structured_c.CVariable):
        variable = node.variable
        runtime_segment_name = runtime_segment_name_for_variable_8616(variable)
        if isinstance(runtime_segment_name, str):
            return runtime_segment_name
        if isinstance(variable, SimRegisterVariable):
            reg_name = getattr(project.arch, "register_names", {}).get(variable.reg)
            if isinstance(reg_name, str) and reg_name in _SEGMENT_REGISTER_NAMES_8616:
                return reg_name

        variable_name = node.name or getattr(variable, "name", None)
        if (
            isinstance(variable_name, str)
            and variable_name.startswith(("vvar_", "tmp_", "ir_"))
            and codegen is not None
        ):
            rhs = _single_assignment_rhs_8616(codegen, node)
            if rhs is not None:
                return _segment_base_name_8616_impl(rhs, project, codegen, seen)
    return None


@cython.ccall
def _segment_base_name_from_scale_pairs_8616(
    node: StructuredAstValue,
    expected_scale: cython.longlong,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    seen: object,
) -> object:
    """Try both operand orders of ``seg << 4`` / ``seg * 16``."""
    segment_name: object
    maybe_scale: object
    maybe_seg: object
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        scale_value = _constant_value_8616(maybe_scale)
        if scale_value != expected_scale:
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[ss-linear-lowering] segment-base scale mismatch op=%r expected=%r got=%r seg=%s scale=%s expr=%s",
                    node.op,
                    expected_scale,
                    scale_value,
                    _debug_c_repr_8616(maybe_seg),
                    _debug_c_repr_8616(maybe_scale),
                    _debug_c_repr_8616(node),
                )
            continue
        maybe_seg = _strip_casts_8616(maybe_seg)
        segment_name = _segment_base_name_8616_impl(maybe_seg, project, codegen, seen)
        if segment_name is not None:
            return segment_name
    return None


@cython.ccall
def _segment_base_name_8616_impl(
    node: StructuredAstValue,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    seen: object,
) -> object:
    expected_scale: object
    node = _strip_casts_8616(node)
    node_id = id(node)
    if node_id in seen:
        return None
    seen.add(node_id)

    if not isinstance(node, structured_c.CBinaryOp):
        return _segment_base_name_from_leaf_8616(node, project, codegen, seen)

    expected_scale = 4 if node.op == "Shl" else 16 if node.op == "Mul" else None
    if expected_scale is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[ss-linear-lowering] segment-base non-scale op=%r expr=%s",
                node.op,
                _debug_c_repr_8616(node),
            )
        return None
    return _segment_base_name_from_scale_pairs_8616(node, expected_scale, project, codegen, seen)



@cython.ccall
def _flatten_signed_terms_8616(
    node: StructuredAstValue,
    sign: cython.longlong = 1,
) -> object:
    return cast(tuple[tuple[int, Any], ...], _flatten_signed_terms_impl_8616(node, sign))


@cython.ccall
def _flatten_signed_terms_impl_8616(
    node: StructuredAstValue, sign: cython.longlong
) -> object:
    """Iteratively flatten Add/Sub trees into signed leaf terms."""
    current: object
    current_sign: object
    exiting: object
    terms: list[tuple[cython.longlong, StructuredAstValue]] = []
    # We use an explicit stack to avoid recursion depth crashes on very deep trees.
    # active path markers prevent infinite loops from cyclic expressions.
    pending: list[tuple[StructuredAstValue, cython.longlong, cython.bint]] = [(node, sign, False)]
    active: set[cython.longlong] = set()

    while pending:
        current, current_sign, exiting = pending.pop()
        current = _strip_casts_8616(current)
        if current is None:
            return None
        if exiting:
            if isinstance(current, int):
                active.discard(current)
            continue

        node_id = id(current)
        if node_id in active:
            return None
        if len(active) > 1024:
            return None

        if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
            active.add(node_id)
            pending.append((node_id, 0, True))
            pending.append((current.rhs, current_sign, False))
            pending.append((current.lhs, current_sign, False))
            continue
        if isinstance(current, structured_c.CBinaryOp) and current.op == "Sub":
            active.add(node_id)
            pending.append((node_id, 0, True))
            pending.append((current.rhs, -current_sign, False))
            pending.append((current.lhs, current_sign, False))
            continue

        terms.append((current_sign, current))
        if len(terms) > 4096:
            return None

    return tuple(terms)


@cython.ccall
def _linear_carrier_key_8616(term: StructuredAstValue) -> LinearGlobalCarrierKey8616 | None:
    """Return the stable carrier key for a vvar/tmp/ir term."""
    dirty: object
    name: object
    varid: object
    term = _strip_casts_8616(term)
    dirty = getattr(term, "dirty", None)
    if dirty is not None:
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return "name", f"vvar_{varid}"
        name = getattr(dirty, "name", None)
        if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
            return "name", name
    if not isinstance(term, structured_c.CVariable):
        return None
    variable = term.variable
    name = term.name or getattr(variable, "name", None)
    if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
        return "name", name
    return None


@cython.dataclasses.dataclass
class _LinearGlobalDecomposer8616:
    """Decompose one signed-term expression into segment + displacement + residuals."""

    project: AngrProjectValue
    codegen: StructuredCodegenValue
    seen_carriers: object
    carrier_cache: LinearGlobalDecompositionCache8616 | None
    segment_name: object = None
    displacement: cython.longlong = 0
    residual_terms: object = field(default_factory=list)

    @cython.ccall
    def _single_assignment_linear_carrier_rhs(self, term: StructuredAstValue) -> StructuredAstValue:
        """Resolve a carrier term to its single assignment RHS."""
        key: object
        rhs: object
        if self.codegen is None:
            return None
        key = _linear_carrier_key_8616(term)
        if key is None or key in self.seen_carriers:
            return None
        self.seen_carriers.add(key)
        term = _strip_casts_8616(term)
        rhs = _single_assignment_rhs_8616(self.codegen, term) if isinstance(term, structured_c.CVariable) else None
        if rhs is None and key[0] == "name" and isinstance(key[1], str):
            rhs = _single_assignment_rhs_for_virtual_name_8616(self.codegen, key[1])
        if rhs is not None:
            self.codegen._inertia_real_mode_global_carrier_resolved_count_8616 = (
                int(getattr(self.codegen, "_inertia_real_mode_global_carrier_resolved_count_8616", 0) or 0) + 1
            )
        return rhs

    @cython.ccall
    def _record_label_constants_8616(self, count: cython.longlong) -> None:
        """Bump the folded address-label constant counter."""
        if count and self.codegen is not None:
            self.codegen._inertia_real_mode_global_address_label_constants = (
                int(getattr(self.codegen, "_inertia_real_mode_global_address_label_constants", 0) or 0) + count
            )

    @cython.ccall
    def _carrier_decomposition_8616(
        self, term: StructuredAstValue, carrier_key: object
    ) -> StructuredAstValue:
        """Decompose a carrier term through its defining assignment, with caching."""
        carrier_rhs: object
        decomposed_carrier: object
        decomposed_carrier = None
        if carrier_key is not None and carrier_key not in self.seen_carriers and self.carrier_cache is not None:
            cached = self.carrier_cache.lookup(carrier_key)
            if cached.found:
                self.seen_carriers.add(carrier_key)
                decomposed_carrier = cached.result
        if decomposed_carrier is None and carrier_key not in self.seen_carriers:
            carrier_rhs = self._single_assignment_linear_carrier_rhs(term)
            if carrier_rhs is not None:
                decomposed_carrier = _decompose_linear_global_terms_8616(
                    carrier_rhs,
                    self.project,
                    codegen=self.codegen,
                    _seen_carriers=self.seen_carriers,
                    _carrier_cache=self.carrier_cache,
                )
            if carrier_key is not None and self.carrier_cache is not None:
                self.carrier_cache.record(carrier_key, decomposed_carrier)
        return decomposed_carrier

    def _absorb_carrier_8616(self, sign: cython.longlong, decomposed_carrier: StructuredAstValue) -> cython.bint:
        """Merge a decomposed carrier into this term list; False on conflict."""
        carrier_segment: object
        carrier_segment, carrier_displacement, carrier_residual_terms = decomposed_carrier
        if carrier_segment is not None:
            if sign != 1 or self.segment_name is not None:
                return False
            self.segment_name = carrier_segment
        self.displacement += sign * carrier_displacement
        self.residual_terms.extend(
            (sign * carrier_sign, carrier_term) for carrier_sign, carrier_term in iter(carrier_residual_terms)
        )
        return True

    @cython.ccall
    def _classify_term_8616(self, sign: cython.longlong, term: StructuredAstValue, allow_sp_anchor: cython.bint) -> cython.bint:
        """Fold one signed term into segment, displacement, or residuals."""
        const: object
        decomposed_carrier: object
        label_value: object
        seg: object
        seg = _segment_base_name_8616(term, self.project, codegen=self.codegen)
        if seg is not None:
            if sign != 1 or self.segment_name is not None:
                return False
            self.segment_name = seg
            return True
        label_value = _address_label_value_8616(term, allow_sp_anchor=allow_sp_anchor)
        if label_value is not None:
            self.displacement += sign * label_value
            self._record_label_constants_8616(1)
            return True
        term, folded_count = _normalize_address_label_terms_8616(
            term,
            codegen=self.codegen,
            allow_sp_anchor=allow_sp_anchor,
        )
        self._record_label_constants_8616(folded_count)
        const = _constant_value_8616(term)
        if const is not None:
            self.displacement += sign * const
            return True
        carrier_key = _linear_carrier_key_8616(term)
        decomposed_carrier = self._carrier_decomposition_8616(term, carrier_key)
        if decomposed_carrier is not None:
            return self._absorb_carrier_8616(sign, decomposed_carrier)
        if not _address_projection_term_is_safe_8616(term):
            return False
        self.residual_terms.append((sign, term))
        return True

    def decompose_8616(self, node: StructuredAstValue) -> object:
        """Run the term classification; None when any term is unsafe."""
        terms: object
        sign: object
        term: object
        terms = _flatten_signed_terms_8616(node)
        if terms is None:
            return None
        allow_sp_anchor = any(_term_contains_memory_address_label_8616(term) for _sign, term in iter(terms))
        for sign, term in terms:
            if not self._classify_term_8616(sign, term, allow_sp_anchor):
                return None
        return self.segment_name, self.displacement, tuple(self.residual_terms)


@cython.ccall
def _decompose_linear_global_terms_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue = None,
    _seen_carriers: object = None,
    _carrier_cache: LinearGlobalDecompositionCache8616 | None = None,
) -> object:
    """Decompose a signed-term expression into segment, displacement, residuals."""
    return _LinearGlobalDecomposer8616(
        project=project,
        codegen=codegen,
        seen_carriers=_seen_carriers if _seen_carriers is not None else set(),
        carrier_cache=_carrier_cache,
    ).decompose_8616(node)


@cython.ccall
def _global_displacement_known_8616(codegen: StructuredCodegenValue, displacement: cython.longlong) -> cython.bint:
    variables_in_use: object
    variable: object
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return False
    addr = displacement & 0xFFFF
    global_name = f"g_{addr:04X}"
    for variable in variables_in_use:
        variable_addr = _sim_variable_global_address_8616(variable)
        if variable_addr == addr:
            return True
        if isinstance(variable, SimVariable) and operator.eq(getattr(variable, "name", None), global_name):
            return True
    return False


def _global_size_from_displacement_8616(codegen: StructuredCodegenValue, displacement: cython.longlong) -> int | None:
    def _impl() -> StructuredAstValue:
        declared: object
        variables_in_use: object
        variable: object
        variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
        if not isinstance(variables_in_use, dict):
            return None
        addr = displacement & 0xFFFF
        global_name = f"g_{addr:04X}"
        for variable in variables_in_use:
            if isinstance(variable, SimMemoryVariable) and operator.eq(getattr(variable, "addr", None), addr):
                size = variable.size
                if isinstance(size, int) and size > 0:
                    return size
            if isinstance(variable, SimVariable) and operator.eq(getattr(variable, "name", None), global_name):
                cvar = variables_in_use[variable]
                declared = getattr(cvar, "variable", None)
                if isinstance(declared, SimMemoryVariable):
                    size = declared.size
                    if isinstance(size, int) and size > 0:
                        return size
                size = getattr(declared, "size", None) if declared is not None else None
                if isinstance(size, int) and size > 0:
                    return size
        return None

    return cast(int | None, _impl())


@cython.ccall
def _cvar_has_array_type_8616(cvar: StructuredAstValue) -> cython.bint:
    type_name = type(getattr(cvar, "variable_type", None)).__name__
    return "Array" in type_name


def _iter_structured_c_nodes_8616(root: StructuredAstValue) -> Iterator[StructuredAstValue]:
    """Yield every structured-C node through the shared angr-boundary walker."""
    node: object
    for node in _iter_c_nodes_deep_8616(root):
        yield cast(StructuredAstValue, node)


def _direct_stack_move_fallback_decision_8616(root: StructuredAstValue) -> DirectStackMoveFallbackDecision8616:
    control_types = _boundary_tuple_8616(
        candidate
        for candidate in iter((
            getattr(structured_c, "CIfElse", None),
            getattr(structured_c, "CIfBreak", None),
            getattr(structured_c, "CForLoop", None),
            getattr(structured_c, "CWhileLoop", None),
            getattr(structured_c, "CDoWhileLoop", None),
        ))
        if isinstance(candidate, type)
    )
    if control_types and any(isinstance(node, control_types) for node in builtins.iter(_iter_structured_c_nodes_8616(root))):
        return DirectStackMoveFallbackDecision8616.REFUSE_STRUCTURED_CONTROL_SCOPE
    return DirectStackMoveFallbackDecision8616.SAFE_TO_INSERT


def _same_variable_storage_8616(lhs: StructuredAstValue, rhs: StructuredAstValue) -> cython.bint:
    def _impl() -> StructuredAstValue:
        lhs_var: object
        rhs_var: object
        if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
            return False
        lhs_var = getattr(lhs, "variable", None)
        rhs_var = getattr(rhs, "variable", None)
        if lhs_var is rhs_var:
            return True
        lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
        rhs_name = getattr(rhs, "name", None) or getattr(rhs_var, "name", None)
        if isinstance(lhs_name, str) and lhs_name and lhs_name == rhs_name:
            return True
        return (
            isinstance(lhs_var, SimRegisterVariable)
            and isinstance(rhs_var, SimRegisterVariable)
            and operator.eq(getattr(lhs_var, "reg", None), getattr(rhs_var, "reg", None))
            and operator.eq(getattr(lhs_var, "size", None), getattr(rhs_var, "size", None))
        )

    return bool(_impl())


# ── Precomputed maps (built once per lowering pass) ──


@cython.ccall
def _record_assignment_key_8616(
    key_map: object,
    multi: object,
    first_map: object,
    key: StructuredAstValue,
    rhs: StructuredAstValue,
) -> None:
    """Record one key→rhs binding, marking repeats in the multi set."""
    if first_map is not None and key not in first_map:
        first_map[key] = rhs
    if key in key_map:
        multi.add(key)
        key_map[key] = None
    elif key not in multi:
        key_map[key] = rhs


@cython.ccall
def _record_dirty_lhs_8616(
    lhs: object,
    rhs: StructuredAstValue,
    name_map: object,
    multi_name: object,
    first_name_map: object,
) -> None:
    """Record a CDirtyExpression lhs through name and vvar keys."""
    dirty_lhs: object
    dirty_name: object
    dirty_varid: object
    dirty_key: object
    dirty_lhs = getattr(lhs, "dirty", None) if lhs is not None else None
    if dirty_lhs is not None and os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[ss-linear-lowering] assignment-map dirty lhs text=%s varid=%r tmp_idx=%r "
            "reg_offset=%r variable_offset=%r category=%r was_reg=%r was_tmp=%r rhs=%s",
            _debug_c_repr_8616(lhs),
            _safe_debug_attr_8616(dirty_lhs, "varid"),
            _safe_debug_attr_8616(dirty_lhs, "tmp_idx"),
            _safe_debug_attr_8616(dirty_lhs, "reg_offset"),
            _safe_debug_attr_8616(dirty_lhs, "variable_offset"),
            _safe_debug_attr_8616(dirty_lhs, "category"),
            _safe_debug_attr_8616(dirty_lhs, "was_reg"),
            _safe_debug_attr_8616(dirty_lhs, "was_tmp"),
            _debug_c_repr_8616(rhs),
        )
    dirty_name = getattr(dirty_lhs, "name", None)
    dirty_varid = getattr(dirty_lhs, "varid", None)
    dirty_keys: set[str] = set()
    if isinstance(dirty_name, str):
        dirty_keys.add(dirty_name)
    if isinstance(dirty_varid, int):
        dirty_keys.add(f"vvar_{dirty_varid}")
    for dirty_key in dirty_keys:
        _record_assignment_key_8616(name_map, multi_name, first_name_map, dirty_key, rhs)


@cython.ccall
def _record_cvar_lhs_8616(
    lhs: structured_c.CVariable,
    rhs: StructuredAstValue,
    var_id_map: object,
    name_map: object,
    reg_map: object,
    multi_var: object,
    multi_name: object,
    multi_reg: object,
    first_name_map: object,
    first_reg_map: object,
) -> None:
    """Record a CVariable lhs under its variable id, name, and register keys."""
    var: object
    var_id: object
    var = lhs.variable
    var_id = id(var) if var is not None else None
    if var_id is not None:
        _record_assignment_key_8616(var_id_map, multi_var, None, var_id, rhs)
    name = lhs.name or getattr(var, "name", None)
    if isinstance(name, str) and name:
        _record_assignment_key_8616(name_map, multi_name, first_name_map, name, rhs)
    if isinstance(var, SimRegisterVariable):
        reg = var.reg
        size = var.size
        if isinstance(reg, int) and isinstance(size, int):
            _record_assignment_key_8616(reg_map, multi_reg, first_reg_map, (reg, size), rhs)


@cython.ccall
def _build_assignment_maps_8616(codegen: StructuredCodegenValue) -> StructuredAstValue:
    """Precompute assignment maps used by lowering and validation fingerprinting."""
    root: object
    stmt: object
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return ({}, {}, {}, set(), set(), set(), {}, {})

    var_id_map: dict[cython.longlong, StructuredAstValue] = {}
    name_map: dict[str, StructuredAstValue] = {}
    reg_map: dict[tuple[Any, ...], StructuredAstValue] = {}
    multi_var: set[cython.longlong] = set()
    multi_name: set[str] = set()
    multi_reg: set[tuple[Any, ...]] = set()
    first_name_map: dict[str, StructuredAstValue] = {}
    first_reg_map: dict[tuple[Any, ...], StructuredAstValue] = {}

    for stmt in _iter_c_statement_nodes_8616(root):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        lhs = stmt.lhs
        rhs = stmt.rhs
        if not isinstance(lhs, structured_c.CVariable):
            _record_dirty_lhs_8616(lhs, rhs, name_map, multi_name, first_name_map)
            continue
        _record_cvar_lhs_8616(
            lhs, rhs, var_id_map, name_map, reg_map,
            multi_var, multi_name, multi_reg, first_name_map, first_reg_map,
        )

    return (var_id_map, name_map, reg_map, multi_var, multi_name, multi_reg, first_name_map, first_reg_map)


@cython.ccall
def _ensure_assignment_maps_8616(codegen: StructuredCodegenValue) -> object:
    """Return cached maps or build and cache them on codegen."""
    cached: object
    cached = getattr(codegen, "_inertia_assignment_maps", None)
    if cached is not None:
        return cast(tuple[Any, ...], cached)
    maps = _build_assignment_maps_8616(codegen)
    codegen._inertia_assignment_maps = maps
    return cast(tuple[Any, ...], maps)


@cython.ccall
def _single_virtual_carrier_offset_observation_8616(expr: StructuredAstValue) -> object:
    const: object
    terms: object
    sign: object
    term: object
    terms = _flatten_signed_terms_8616(expr)
    if terms is None:
        return None
    base_ids: list[tuple[cython.longlong, cython.longlong]] = []
    const_total = 0
    for sign, term in terms:
        base_id = _extract_vvar_id_8616(term)
        if isinstance(base_id, int):
            base_ids.append((sign, base_id))
            continue
        const = _constant_value_8616(term)
        if const is not None:
            const_total += sign * const
            continue
        return None
    if len(base_ids) != 1:
        return None
    sign, base_id = base_ids[0]
    if sign != 1:
        return None
    return base_id, const_total


@cython.ccall
def _ss_virtual_carrier_offset_observations_8616(
    root: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue
) -> object:
    const: object
    observation: object
    seg: object
    segment_name: object
    terms: object
    node: object
    sign: object
    term: object
    observations: dict[cython.longlong, set[cython.longlong]] = {}
    for node in _iter_structured_c_nodes_8616(root):
        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            continue
        terms = _flatten_signed_terms_8616(getattr(node, "operand", None))
        if terms is None:
            continue

        segment_name = None
        const_total = 0
        offset_terms: list[StructuredAstValue] = []
        malformed = False
        for sign, term in terms:
            seg = _segment_base_name_8616(term, project, codegen=codegen)
            if seg is not None:
                if sign != 1 or segment_name is not None:
                    malformed = True
                    break
                segment_name = seg
                continue
            const = _constant_value_8616(term)
            if const is not None:
                const_total += sign * const
                continue
            offset_terms.append(
                term
                if sign == 1
                else structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeInt(signed=False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            )
        if malformed or segment_name != "ss" or len(offset_terms) != 1:
            continue

        observation = _single_virtual_carrier_offset_observation_8616(offset_terms[0])
        if observation is None:
            continue
        base_id, carrier_const = observation
        observations.setdefault(base_id, set()).add(const_total + carrier_const)
    return observations


@cython.ccall
def _infer_carrier_delta_8616(constants: object, offsets: object) -> int | None:
    """Vote on one carrier delta that maps all constants onto known offsets."""
    const: object
    offset: object
    if len(constants) < 2 or len(offsets) < 2:
        return None
    best_delta: int | None = None
    best_score = 0
    tied = False
    for const in constants:
        for offset in offsets:
            delta = offset - const
            score = len({candidate for candidate in iter(constants) if candidate + delta in offsets})
            if score > best_score:
                best_delta = delta
                best_score = score
                tied = False
            elif score == best_score and score > 0 and delta != best_delta:
                tied = True
    if isinstance(best_delta, int) and operator.eq(best_score, len(constants)) and best_score >= 2 and not tied:
        return best_delta
    return None


@cython.ccall
def _infer_varid_carrier_delta_8616(
    codegen: StructuredCodegenValue,
    constants: object,
    strong_arg_offsets: object,
    abi_arg_region_offsets: object,
    known_offsets: object,
) -> int | None:
    """Infer one vvar's carrier delta, preferring stronger offset evidence."""
    strong_delta = _infer_carrier_delta_8616(constants, strong_arg_offsets)
    if isinstance(strong_delta, int):
        codegen._inertia_stack_carrier_delta_inferred_from_arg_offsets_count_8616 = (
            int(getattr(codegen, "_inertia_stack_carrier_delta_inferred_from_arg_offsets_count_8616", 0) or 0) + 1
        )
        return strong_delta
    abi_arg_region_delta = _infer_carrier_delta_8616(constants, abi_arg_region_offsets)
    if isinstance(abi_arg_region_delta, int):
        codegen._inertia_stack_carrier_delta_inferred_from_abi_arg_region_count_8616 = (
            int(getattr(codegen, "_inertia_stack_carrier_delta_inferred_from_abi_arg_region_count_8616", 0) or 0)
            + 1
        )
        return abi_arg_region_delta
    return _infer_carrier_delta_8616(constants, known_offsets)


@cython.ccall
def _infer_vvar_carrier_deltas_from_ss_alias_observations_8616(
    root: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue
) -> object:
    constants: object
    varid: object
    known_offsets = _known_bp_stack_offsets_8616(codegen)
    if not known_offsets:
        return {}
    strong_arg_offsets = _bp_stack_arg_offsets_8616(codegen)
    abi_arg_region_offsets = _bp_stack_abi_argument_region_offsets_8616(known_offsets)
    observations = _ss_virtual_carrier_offset_observations_8616(root, project, codegen)
    inferred: dict[cython.longlong, cython.longlong] = {}

    for varid, constants in observations.items():
        delta = _infer_varid_carrier_delta_8616(
            codegen, constants, strong_arg_offsets, abi_arg_region_offsets, known_offsets
        )
        if isinstance(delta, int):
            inferred[varid] = delta
    if inferred:
        codegen._inertia_stack_carrier_delta_inferred_from_alias_count_8616 = int(
            getattr(codegen, "_inertia_stack_carrier_delta_inferred_from_alias_count_8616", 0) or 0
        ) + len(inferred)
    return inferred


@cython.dataclasses.dataclass
class _VvarCarrierDeltaRun8616:
    """Precompute vvar_id → carrier_delta in a single pass."""

    codegen: StructuredAstValue
    project: StructuredAstValue
    sp_reg: StructuredAstValue
    has_ss_facts: cython.bint
    root: StructuredAstValue
    deltas: object = field(default_factory=dict)
    delta_sources: object = field(default_factory=dict)

    @staticmethod
    def _delta_source_priority(source: StackCarrierDeltaSource8616) -> cython.longlong:
        return _STACK_CARRIER_DELTA_SOURCE_PRIORITY_8616[source]

    @cython.ccall
    def _record_delta(self, lhs_id: cython.longlong, delta: cython.longlong, source: StackCarrierDeltaSource8616) -> cython.bint:
        old_delta: object
        old_source: object
        old_delta = self.deltas.get(lhs_id)
        old_source = self.delta_sources.get(lhs_id)
        if old_source is None:
            self.deltas[lhs_id] = delta
            self.delta_sources[lhs_id] = source
            return True
        if operator.eq(old_delta, delta):
            if self._delta_source_priority(source) > self._delta_source_priority(old_source):
                self.delta_sources[lhs_id] = source
            return False
        if self._delta_source_priority(source) <= self._delta_source_priority(old_source):
            return False
        self.deltas[lhs_id] = delta
        self.delta_sources[lhs_id] = source
        self.codegen._inertia_stack_carrier_delta_alias_override_count_8616 = (
            int(getattr(self.codegen, "_inertia_stack_carrier_delta_alias_override_count_8616", 0) or 0) + 1
        )
        return True

    @cython.ccall
    def _seed_ref_operands_8616(
        self, rhs_stripped: structured_c.CBinaryOp
    ) -> tuple[StructuredAstValue, cython.longlong]:
        """Find the Reference operand and constant delta inside an Add/Sub."""
        lhs_const: object
        ref_node: object
        rhs_const: object
        ref_node = None
        const_delta = 0
        if isinstance(_strip_casts_8616(rhs_stripped.lhs), structured_c.CUnaryOp):
            lhs_u = _strip_casts_8616(rhs_stripped.lhs)
            if lhs_u.op == "Reference":
                ref_node = lhs_u.operand
                rhs_const = _constant_value_8616(rhs_stripped.rhs)
                if rhs_const is not None:
                    const_delta = rhs_const if rhs_stripped.op == "Add" else -rhs_const
        if ref_node is None and isinstance(_strip_casts_8616(rhs_stripped.rhs), structured_c.CUnaryOp):
            rhs_u = _strip_casts_8616(rhs_stripped.rhs)
            if rhs_u.op == "Reference" and rhs_stripped.op == "Add":
                ref_node = rhs_u.operand
                lhs_const = _constant_value_8616(rhs_stripped.lhs)
                if lhs_const is not None:
                    const_delta = lhs_const
        return ref_node, const_delta

    @cython.ccall
    def _record_stack_ref_seed_8616(
        self, ref_node: object, const_delta: cython.longlong, lhs_id: StructuredAstValue
    ) -> cython.bint:
        """Record the seed delta when the Reference targets a stack variable."""
        if ref_node is None:
            return False
        operand = _strip_casts_8616(ref_node)
        if not isinstance(operand, structured_c.CVariable):
            return False
        var = operand.variable
        if not isinstance(var, SimStackVariable):
            return False
        offset = var.offset
        if not isinstance(offset, int):
            return False
        self._record_delta(
            lhs_id,
            offset + const_delta,
            StackCarrierDeltaSource8616.STACK_REFERENCE_SEED,
        )
        return True

    @cython.ccall
    def _seed_from_init(self, expr: object, lhs_id: StructuredAstValue) -> StructuredAstValue:
        if expr is None:
            return None
        rhs_stripped = _strip_casts_8616(expr)
        if isinstance(rhs_stripped, structured_c.CUnaryOp) and rhs_stripped.op == "Reference":
            if self._record_stack_ref_seed_8616(rhs_stripped.operand, 0, lhs_id):
                return True
        elif isinstance(rhs_stripped, structured_c.CBinaryOp) and rhs_stripped.op in {"Add", "Sub"}:
            ref_node, const_delta = self._seed_ref_operands_8616(rhs_stripped)
            if self._record_stack_ref_seed_8616(ref_node, const_delta, lhs_id):
                return True
        if isinstance(rhs_stripped, structured_c.CVariable):
            var = rhs_stripped.variable
            if isinstance(var, SimRegisterVariable) and operator.eq(getattr(var, "reg", None), self.sp_reg) and self.has_ss_facts:
                self._record_delta(lhs_id, 0, StackCarrierDeltaSource8616.SP_REGISTER_SEED)
                return True
        return None

    @cython.ccall
    def _seed_pass_8616(self) -> None:
        """Seed carrier deltas from direct stack-reference initializers."""
        stmt: object
        for stmt in _iter_c_statement_nodes_8616(self.root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            lhs_id = _extract_vvar_id_8616(stmt.lhs)
            if not isinstance(lhs_id, int):
                continue
            self._seed_from_init(stmt.rhs, lhs_id)

    @cython.ccall
    def _alias_observation_pass_8616(self) -> None:
        """Record deltas proven by SS-alias observations."""
        delta: object
        lhs_id: object
        if self.project is None:
            return
        for lhs_id, delta in _infer_vvar_carrier_deltas_from_ss_alias_observations_8616(
            self.root, self.project, self.codegen
        ).items():
            self._record_delta(lhs_id, delta, StackCarrierDeltaSource8616.ALIAS_OBSERVATION)

    @cython.ccall
    def _propagate_stmt_8616(self, stmt: StructuredAstValue) -> cython.bint:
        """Record a derived delta for one assignment, returning whether it changed."""
        const: object
        terms: object
        sign: object
        term: object
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs_id = _extract_vvar_id_8616(stmt.lhs)
        if not isinstance(lhs_id, int) or lhs_id in self.deltas:
            return False
        base_ids: list[tuple[cython.longlong, cython.longlong]] = []
        const_total = 0
        unknown = False
        terms = _flatten_signed_terms_8616(stmt.rhs)
        if terms is None:
            return False
        for sign, term in terms:
            base_id = _extract_vvar_id_8616(term)
            if isinstance(base_id, int):
                base_ids.append((sign, base_id))
                continue
            const = _constant_value_8616(term)
            if const is not None:
                const_total += sign * const
                continue
            unknown = True
        if unknown or len(base_ids) != 1:
            return False
        sign, base_id = base_ids[0]
        if sign != 1 or base_id not in self.deltas:
            return False
        return self._record_delta(lhs_id, self.deltas[base_id] + const_total, self.delta_sources[base_id])

    @cython.ccall
    def _propagate_pass_8616(self) -> None:
        """Propagate deltas through single-base copy expressions to fixpoint."""
        stmt: object
        changed = True
        while changed:
            changed = False
            for stmt in _iter_c_statement_nodes_8616(self.root):
                if self._propagate_stmt_8616(stmt):
                    changed = True

    @cython.ccall
    def _report_8616(self) -> None:
        """Publish delta sources and emit the optional debug summary."""
        self.codegen._inertia_stack_carrier_delta_sources_8616 = dict(self.delta_sources)
        if os.environ.get("INERTIA_DEBUG_STACK_CARRIER_DELTAS"):
            log.warning(
                "[stack-carrier-deltas] function=%r deltas=%r sources=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", None),
                self.deltas,
                self.delta_sources,
            )

    @cython.ccall
    def run_8616(self) -> object:
        """Run seed, alias-observation, and propagation passes."""
        self._seed_pass_8616()
        self._alias_observation_pass_8616()
        self._propagate_pass_8616()
        self._report_8616()
        return self.deltas


def _build_vvar_carrier_delta_map_8616(codegen: StructuredAstValue) -> object:
    """Precompute vvar_id → carrier_delta in a single pass, caching on codegen."""
    _sp_size: object
    project: object
    root: object
    sp_reg: object
    project = getattr(codegen, "project", None)
    sp_reg, _sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
    has_ss_facts = any(fact.segment_space == "ss" for fact in builtins.iter(_typed_stack_probe_return_facts_8616(codegen)))
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return {}
    return _VvarCarrierDeltaRun8616(
        codegen=codegen,
        project=project,
        sp_reg=sp_reg,
        has_ss_facts=has_ss_facts,
        root=root,
    ).run_8616()


@cython.ccall
def _ensure_vvar_carrier_delta_map_8616(codegen: StructuredCodegenValue) -> object:
    """Return carrier deltas cached for the current structured-C root."""
    cached: object
    cached_root: object
    root: object
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    cached = getattr(codegen, "_inertia_vvar_carrier_deltas", None)
    cached_root = getattr(codegen, "_inertia_vvar_carrier_delta_root_8616", None)
    if cached is not None and cached_root is root:
        return cast(dict[int, int], cached)
    deltas = _build_vvar_carrier_delta_map_8616(codegen)
    codegen._inertia_vvar_carrier_deltas = deltas
    codegen._inertia_vvar_carrier_delta_root_8616 = root
    return deltas


# ── O(1) lookup wrappers ──


def _single_assignment_rhs_8616(codegen: StructuredCodegenValue, target: StructuredAstValue) -> StructuredAstValue:
    def _impl() -> StructuredAstValue:
        var: object
        var_id: object
        if not isinstance(target, structured_c.CVariable):
            return None
        var_id_map, name_map, reg_map, multi_var, multi_name, multi_reg, _first_name_map, _first_reg_map = (
            _ensure_assignment_maps_8616(codegen)
        )
        var = target.variable
        var_id = id(var) if var is not None else None
        if var_id is not None and var_id in var_id_map and var_id not in multi_var:
            return var_id_map[var_id]
        name = target.name or getattr(var, "name", None)
        if isinstance(name, str) and name in name_map and name not in multi_name:
            return name_map[name]
        if isinstance(var, SimRegisterVariable):
            reg = var.reg
            size = var.size
            if isinstance(reg, int) and isinstance(size, int):
                reg_key = (reg, size)
                if reg_key in reg_map and reg_key not in multi_reg:
                    return reg_map[reg_key]
        return None

    return _impl()


@cython.ccall
def _carrier_reg_and_early_offset_8616(
    node: StructuredAstValue,
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    seen: object,
) -> tuple[StructuredAstValue, StructuredAstValue, tuple[cython.bint, int | None]]:
    """Identify the carrier register/size; resolve vvar indirections eagerly.

    The third element is (handled, offset): when handled is True the caller
    must return offset (which may legitimately be None) immediately.
    """
    bits: object
    delta: object
    dirty: object
    resolved: object
    varid: object
    variable = getattr(node, "variable", None) if isinstance(node, structured_c.CVariable) else None
    dirty = getattr(node, "dirty", None)
    if isinstance(variable, SimRegisterVariable):
        return variable.reg, variable.size, (False, None)
    reg = _dirty_reg_offset_8616(dirty)
    bits = getattr(dirty, "bits", None)
    size = (bits // 8) if isinstance(bits, int) else None
    varid = getattr(dirty, "varid", None)
    if isinstance(reg, int) or not isinstance(varid, int):
        return reg, size, (False, None)
    resolved = _single_assignment_rhs_for_virtual_name_8616(codegen, f"vvar_{varid}")
    if resolved is not None:
        return reg, size, (True, _stack_offset_from_expr_8616(resolved, project, codegen, seen))
    delta = _stack_probe_carrier_delta_8616(node, codegen)
    if delta is not None:
        return reg, size, (True, delta)
    return reg, size, (False, None)


@cython.ccall
def _sp_carrier_offset_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    reg: StructuredAstValue,
    size: object,
) -> int | None:
    """Accept an SP carrier only under proven SS-fact evidence."""
    sp_reg: object
    sp_size: object
    fact: object
    sp_reg, sp_size = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))
    if not (isinstance(sp_reg, int) and operator.eq(reg, sp_reg) and (size is None or operator.eq(size, sp_size))):
        return None
    if getattr(codegen, "_inertia_allow_runtime_helper_sp_segment_proof_8616", False):
        codegen._inertia_runtime_helper_sp_segment_proof_count_8616 = (
            int(getattr(codegen, "_inertia_runtime_helper_sp_segment_proof_count_8616", 0) or 0) + 1
        )
        return 0
    if getattr(codegen, "_inertia_allow_direct_sp_for_callee_save_spill", False):
        return 0
    facts = _typed_stack_probe_return_facts_8616(codegen)
    if not facts:
        return None
    for fact in facts:
        if fact.segment_space != "ss":
            continue
        if fact.width > 0:
            return 0
    return None


@cython.ccall
def _stack_pointer_carrier_offset_8616(
    node: StructuredAstValue,
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    seen: object = None,
) -> int | None:
    """Recover the BP-relative offset represented by a stack-pointer carrier."""
    bp_reg: object
    bp_size: object
    size: object
    if seen is None:
        seen = set()
    reg, size, early = _carrier_reg_and_early_offset_8616(node, codegen, project, seen)
    if early[0]:
        return early[1]

    bp_reg, bp_size = getattr(getattr(project, "arch", None), "registers", {}).get("bp", (None, None))
    if isinstance(bp_reg, int) and operator.eq(reg, bp_reg) and (size is None or operator.eq(size, bp_size)):
        return 0
    return _sp_carrier_offset_8616(codegen, project, reg, size)


@cython.ccall
def _lhs_name_8616(lhs: StructuredAstValue) -> object:
    """Extract variable name from CVariable or CDirtyExpression LHS."""
    dirty: object
    name: object
    varid: object
    if isinstance(lhs, structured_c.CVariable):
        return lhs.name or getattr(lhs.variable, "name", None)
    dirty = getattr(lhs, "dirty", None)
    if dirty is not None:
        name = getattr(dirty, "name", None)
        if isinstance(name, str):
            return name
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return f"vvar_{varid}"
    return None


@cython.ccall
def _single_assignment_rhs_for_virtual_name_8616(
    codegen: StructuredCodegenValue, target_name: object, *, allow_multi: cython.bint = False
) -> StructuredAstValue:
    (
        _unused_var_id_map,
        name_map,
        _unused_reg_map,
        _unused_multi_var,
        multi_name,
        _unused_multi_reg,
        first_name_map,
        _first_reg_map,
    ) = _ensure_assignment_maps_8616(codegen)
    if allow_multi:
        # O(1) lookup from precomputed first-assignment map
        return first_name_map.get(target_name)
    if target_name in name_map and target_name not in multi_name:
        return name_map[target_name]
    return None


@cython.ccall
def _virtual_carrier_name_8616(node: StructuredAstValue) -> object:
    dirty: object
    dirty_name: object
    varid: object
    dirty = getattr(node, "dirty", None)
    if dirty is not None:
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return f"vvar_{varid}"
        dirty_name = getattr(dirty, "name", None)
        if isinstance(dirty_name, str) and dirty_name.startswith(("vvar_", "tmp_", "ir_")):
            return dirty_name
    if isinstance(node, structured_c.CVariable):
        variable = node.variable
        name = node.name or getattr(variable, "name", None)
        if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
            return name
    return None


@cython.ccall
def _rhs_terms_contain_segment_scale_8616(
    terms: object, project: AngrProjectValue, codegen: StructuredCodegenValue
) -> cython.bint:
    sign: object
    term: object
    for sign, term in terms:
        if sign != 1:
            continue
        if _segment_base_name_8616(term, project, codegen=codegen) is not None:
            return True
        if _is_unresolved_segment_scale_candidate_8616(term):
            return True
    return False


@cython.ccall
def _expand_virtual_linear_address_carrier_terms_8616(
    terms: object,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
) -> tuple[tuple[cython.longlong, StructuredAstValue], ...]:
    carrier_name: object
    rhs: object
    rhs_terms: object
    rhs_sign: object
    rhs_term: object
    sign: object
    term: object
    expanded: list[tuple[cython.longlong, StructuredAstValue]] = []
    changed = False
    for sign, term in terms:
        carrier_name = _virtual_carrier_name_8616(_strip_casts_8616(term))
        if carrier_name is None:
            expanded.append((sign, term))
            continue
        rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, carrier_name)
        if rhs is None:
            expanded.append((sign, term))
            continue
        rhs_terms = _flatten_signed_terms_8616(rhs)
        if rhs_terms is None or not _rhs_terms_contain_segment_scale_8616(rhs_terms, project, codegen):
            expanded.append((sign, term))
            continue
        changed = True
        for rhs_sign, rhs_term in rhs_terms:
            expanded.append((sign * rhs_sign, rhs_term))
    if changed:
        codegen._inertia_ss_linear_virtual_address_carrier_expanded_8616 = (
            int(getattr(codegen, "_inertia_ss_linear_virtual_address_carrier_expanded_8616", 0) or 0) + 1
        )
    return tuple(expanded)


@cython.ccall
def _extract_vvar_id_8616(node: StructuredAstValue) -> int | None:
    dirty: object
    varid: object
    candidate: object
    dirty = getattr(node, "dirty", None)
    varid = getattr(dirty, "varid", None)
    if isinstance(varid, int):
        return varid
    if isinstance(node, structured_c.CVariable):
        for candidate in (node.name, getattr(node.variable, "name", None)):
            if not (isinstance(candidate, str) and candidate.startswith("vvar_")):
                continue
            try:
                return int(candidate.removeprefix("vvar_"), 10)
            except ValueError:
                return None
    return None


@cython.ccall
def _stack_probe_carrier_delta_8616(node: StructuredAstValue, codegen: StructuredCodegenValue) -> int | None:
    carrier: object
    carrier = _stack_probe_carrier_delta_with_source_8616(node, codegen)
    return carrier[0] if carrier is not None else None


@cython.ccall
def _stack_probe_carrier_delta_with_source_8616(
    node: StructuredAstValue, codegen: StructuredCodegenValue
) -> object:
    delta: object
    sources: object
    varid = _extract_vvar_id_8616(node)
    if not isinstance(varid, int):
        return None
    deltas = _ensure_vvar_carrier_delta_map_8616(codegen)
    delta = deltas.get(varid)
    if not isinstance(delta, int):
        return None
    sources = getattr(codegen, "_inertia_stack_carrier_delta_sources_8616", None)
    source = sources.get(varid) if isinstance(sources, dict) else None
    source = source if isinstance(source, StackCarrierDeltaSource8616) else None
    return delta, source


@cython.ccall
def _vvar_carrier_delta_from_name_8616(
    node_name: object,
    codegen: StructuredCodegenValue,
) -> object:
    delta: object
    sources: object
    if not node_name.startswith("vvar_"):
        return None
    suffix = node_name.removeprefix("vvar_")
    if not suffix.isdigit():
        return None
    varid = int(suffix)
    deltas = _ensure_vvar_carrier_delta_map_8616(codegen)
    delta = deltas.get(varid)
    if not isinstance(delta, int):
        return None
    sources = getattr(codegen, "_inertia_stack_carrier_delta_sources_8616", None)
    source = sources.get(varid) if isinstance(sources, dict) else None
    source = source if isinstance(source, StackCarrierDeltaSource8616) else None
    return delta, source


@cython.ccall
def _resolve_virtual_name_offset_8616(
    node_name: object, project: AngrProjectValue, codegen: StructuredCodegenValue, seen: object
) -> int | None:
    carrier_delta: object
    resolved: object
    rhs: object
    if not (node_name.startswith(("vvar_", "tmp_", "ir_"))):
        return None
    carrier_delta = _vvar_carrier_delta_from_name_8616(node_name, codegen)
    if carrier_delta is not None and carrier_delta[1] is StackCarrierDeltaSource8616.ALIAS_OBSERVATION:
        return carrier_delta[0]
    rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, node_name)
    if rhs is None:
        return None
    resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
    if resolved is not None:
        return resolved
    return carrier_delta[0] if carrier_delta is not None else None


@cython.ccall
def _resolve_stack_offset_from_variable_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue, seen: object
) -> int | None:
    carrier_offset: object
    resolved: object
    rhs: object
    variable: object
    variable = getattr(node, "variable", None)
    if isinstance(variable, SimStackVariable):
        stack_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        return stack_offset if isinstance(stack_offset, int) else None
    if isinstance(variable, SimRegisterVariable):
        carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
        if carrier_offset is not None:
            return carrier_offset
    rhs = _single_assignment_rhs_8616(codegen, node)
    if rhs is not None:
        return _stack_offset_from_expr_8616(rhs, project, codegen, seen)
    node_name = getattr(node, "name", None) or getattr(variable, "name", None)
    if isinstance(node_name, str):
        resolved = _resolve_virtual_name_offset_8616(node_name, project, codegen, seen)
        if resolved is not None:
            return resolved
        if node_name.startswith("vvar_"):
            return _stack_probe_carrier_delta_8616(node, codegen)
    return None


@cython.ccall
def _dirty_varid_offset_8616(
    varid: cython.longlong,
    node: StructuredAstValue,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    seen: object,
    diag: object,
) -> int | None:
    carrier: object
    resolved: object
    rhs: object
    diag["varid"] = varid
    carrier = _stack_probe_carrier_delta_with_source_8616(node, codegen)
    if carrier is not None and carrier[1] is StackCarrierDeltaSource8616.ALIAS_OBSERVATION:
        return carrier[0]
    target_name = f"vvar_{varid}"
    rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, target_name, allow_multi=True)
    if rhs is not None:
        resolved = _stack_offset_from_expr_8616(rhs, project, codegen, seen)
        if resolved is not None:
            return resolved
        diag["rhs_found_but_unresolvable"] = True
    else:
        diag["rhs_not_found"] = True
    if carrier is not None:
        return carrier[0]
    diag["carrier_delta_none"] = True
    return None


@cython.ccall
def _dirty_name_offset_8616(
    dirty_name: object,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    seen: object,
    diag: object,
) -> int | None:
    resolved: object
    rhs: object
    diag["dirty_name"] = dirty_name
    resolved = _resolve_virtual_name_offset_8616(dirty_name, project, codegen, seen)
    if resolved is not None:
        return resolved
    if dirty_name.startswith(("vvar_", "tmp_", "ir_")):
        rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, dirty_name)
        if rhs is None:
            diag["rhs_not_found"] = True
        else:
            diag["rhs_found_but_unresolvable"] = True
    return None


@cython.ccall
def _resolve_stack_offset_from_dirty_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue, seen: object
) -> int | None:
    _bp_size: object
    bp_reg: object
    carrier_offset: object
    dirty: object
    dirty_name: object
    resolved: object
    varid: object
    dirty = getattr(node, "dirty", None)
    if dirty is None:
        return None
    varid = getattr(dirty, "varid", None)
    dirty_name = getattr(dirty, "name", None)
    diag: dict[str, StructuredAstValue] = {}
    dirty_reg = _dirty_reg_offset_8616(dirty)
    bp_reg, _bp_size = getattr(getattr(project, "arch", None), "registers", {}).get("bp", (None, None))
    if isinstance(dirty_reg, int) and isinstance(bp_reg, int) and operator.eq(dirty_reg, bp_reg):
        return 0
    if isinstance(varid, int):
        resolved = _dirty_varid_offset_8616(varid, node, project, codegen, seen, diag)
        if resolved is not None:
            return resolved
    elif isinstance(dirty_name, str):
        resolved = _dirty_name_offset_8616(dirty_name, project, codegen, seen, diag)
        if resolved is not None:
            return resolved
    else:
        diag["no_varid_or_name"] = True
    carrier_offset = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
    if carrier_offset is not None:
        return carrier_offset
    diag["carrier_none"] = True
    _log_refusal_8616(codegen, "cdirty_diag", **diag)
    return None


@cython.ccall
def _resolve_binary_stack_base_shortcuts_8616(node: StructuredAstValue, codegen: StructuredCodegenValue) -> int | None:
    base: object
    lhs_const: object
    rhs_const: object
    if _is_stack_base_placeholder_8616(node.lhs):
        rhs_const = _constant_value_8616(node.rhs)
        if rhs_const is not None:
            base = _stack_base_bp_bias_8616(node.lhs, codegen)
            if base is not None:
                return base + (int(rhs_const) if node.op == "Add" else -int(rhs_const))
    if node.op == "Add" and _is_stack_base_placeholder_8616(node.rhs):
        lhs_const = _constant_value_8616(node.lhs)
        if lhs_const is not None:
            base = _stack_base_bp_bias_8616(node.rhs, codegen)
            if base is not None:
                return base + int(lhs_const)
    return None


@cython.ccall
def _is_unresolved_segment_scale_candidate_8616(node: StructuredAstValue) -> cython.bint:
    maybe_scale: object
    maybe_segment: object
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return False
    if node.op == "Mul":
        pairs: tuple[tuple[Any, Any], ...] = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        expected_scale = 16
    elif node.op == "Shl":
        pairs = ((node.lhs, node.rhs),)
        expected_scale = 4
    else:
        return False
    for maybe_segment, maybe_scale in pairs:
        if operator.eq(_constant_value_8616(maybe_scale), expected_scale) and _constant_value_8616(maybe_segment) is None:
            return True
    return False


@cython.ccall
def _is_stack_offset_term_direct_8616(node: StructuredAstValue) -> cython.bint:
    variable: object
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Reference":
        variable = getattr(node.operand, "variable", None)
        return isinstance(variable, SimStackVariable)

    variable = getattr(node, "variable", None)
    if isinstance(variable, SimStackVariable):
        return True

    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        lhs = node.lhs
        rhs = node.rhs
        lhs_is_const = _constant_value_8616(lhs) is not None
        rhs_is_const = _constant_value_8616(rhs) is not None
        if lhs_is_const and _is_stack_offset_term_direct_8616(rhs):
            return True
        if rhs_is_const and _is_stack_offset_term_direct_8616(lhs):
            return True

    return _constant_value_8616(node) is not None


@cython.ccall
def _stack_offset_term_stackish_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue
) -> cython.bint:
    if _is_stack_offset_term_direct_8616(node):
        return True
    return _stack_offset_from_expr_8616(node, project, codegen) is not None


def _ss_probe_enabled_8616(codegen: StructuredAstValue) -> cython.bint:
    return any(fact.segment_space == "ss" for fact in builtins.iter(_typed_stack_probe_return_facts_8616(codegen)))


@cython.ccall
def _slot_range_contains_access_8616(
    slot_offset: StructuredAstValue,
    slot_width: StructuredAstValue,
    displacement: cython.longlong,
    width: int | None,
) -> cython.bint:
    """Check whether a proven stack slot fully contains the access range."""
    return (
        isinstance(width, int)
        and width > 0
        and isinstance(slot_width, int)
        and slot_width > 0
        and slot_offset < displacement
        and displacement + width <= slot_offset + slot_width
    )


def _has_stack_storage_evidence_for_displacement_8616(
    codegen: StructuredAstValue, displacement: cython.longlong, width: int | None
) -> cython.bint:
    facts: object
    fact: object
    displacement = _canonical_stack_offset_8616(displacement)
    if alias_proves_stack_range_8616(codegen, displacement, width):
        return True
    if isinstance(width, int) and width > 0 and any(
        binding.is_stable and binding.contains_access(displacement, width)
        for binding in builtins.iter(_stack_bindings_from_codegen_8616(codegen))
    ):
        return True
    facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if not isinstance(facts, list):
        return False
    for fact in facts:
        if not isinstance(fact, AliasStorageFacts):
            continue
        identity = fact.identity
        if not (isinstance(identity, tuple) and len(identity) >= 2 and identity[0] == "stack"):
            continue
        slot = identity[1]
        if not isinstance(slot, _StackSlotIdentity):
            continue
        slot_offset = _canonical_stack_offset_8616(slot.offset)
        slot_width = slot.width
        if slot_offset == displacement and (
            not isinstance(width, int) or width <= 0 or not isinstance(slot_width, int) or slot_width >= width
        ):
            return True
        if _slot_range_contains_access_8616(slot_offset, slot_width, displacement, width):
            return True
    return False


@cython.ccall
def _resolve_binary_stack_probe_fallback_8616(
    node: StructuredAstValue, lhs: object, rhs: object, codegen: StructuredCodegenValue
) -> int | None:
    if lhs is None:
        rhs_const = _constant_value_8616(node.rhs)
        lhs_delta = _stack_probe_carrier_delta_8616(_strip_casts_8616(node.lhs), codegen)
        if isinstance(rhs_const, int) and isinstance(lhs_delta, int):
            return lhs_delta + (rhs_const if node.op == "Add" else -rhs_const)
    if rhs is None and node.op == "Add":
        lhs_const = _constant_value_8616(node.lhs)
        rhs_delta = _stack_probe_carrier_delta_8616(_strip_casts_8616(node.rhs), codegen)
        if isinstance(lhs_const, int) and isinstance(rhs_delta, int):
            return lhs_const + rhs_delta
    return None


def _resolve_stack_offset_from_binary_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue, seen: object
) -> int | None:
    def _impl() -> StructuredAstValue:
        fallback: object
        lhs: object
        rhs: object
        shortcut: object
        shortcut = _resolve_binary_stack_base_shortcuts_8616(node, codegen)
        if shortcut is not None:
            return shortcut
        lhs = _stack_offset_from_expr_8616(node.lhs, project, codegen, seen)
        rhs = _stack_offset_from_expr_8616(node.rhs, project, codegen, seen)
        fallback = _resolve_binary_stack_probe_fallback_8616(node, lhs, rhs, codegen)
        if fallback is not None:
            return fallback
        if lhs is None and _constant_value_8616(node.rhs) is not None:
            return None
        if rhs is None and _constant_value_8616(node.lhs) is not None and node.op == "Add":
            return None
        if lhs is None or rhs is None:
            return None
        return lhs + rhs if node.op == "Add" else lhs - rhs

    return cast(int | None, _impl())


@cython.ccall
def _stack_offset_cache_entry_8616(
    codegen: StructuredCodegenValue,
    node_id: cython.longlong,
    seen: object,
    offset_cache: object,
) -> tuple[cython.bint, int | None]:
    """Return (True, cached) on a cache/seen hit, else record the visit and continue."""
    cached: object
    if node_id in offset_cache:
        cached = offset_cache.get(node_id)
        if cached is _UNRESOLVED_STACK_OFFSET_8616:
            return True, None
        return True, cached
    if node_id in seen or len(seen) > 8192:
        offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
        return True, None
    seen.add(node_id)
    return False, None


@cython.ccall
def _stack_offset_cache_record_8616(
    offset_cache: object, node_id: cython.longlong, resolved: object
) -> int | None:
    """Cache a resolution result, marking unresolvable nodes explicitly."""
    offset_cache[node_id] = resolved if resolved is not None else _UNRESOLVED_STACK_OFFSET_8616
    return resolved


@cython.ccall
def _stack_offset_leaf_value_8616(
    codegen: StructuredCodegenValue, node: StructuredAstValue
) -> int | None:
    """Resolve trivial leaf offsets: native anchor, constant, BP/stack_base bases."""
    const: object
    native_anchor: object
    runtime_gp_view: object
    native_anchor = machine_bp_offset_for_native_anchor_8616(codegen, node)
    if native_anchor is not None:
        return native_anchor
    const = _constant_value_8616(node)
    if const is not None:
        return const
    runtime_gp_view = runtime_gp_expression_view_8616(node)
    if runtime_gp_view is not None and runtime_gp_view.register_name == "bp":
        return 0
    return _stack_base_bp_bias_8616(node, codegen)


@cython.ccall
def _stack_offset_reference_value_8616(
    codegen: StructuredCodegenValue,
    node: StructuredAstValue,
    offset_cache: object,
    node_id: cython.longlong,
) -> tuple[cython.bint, int | None]:
    """Handle the ``Reference`` arm; returns (handled, offset)."""
    if not (isinstance(node, structured_c.CUnaryOp) and node.op == "Reference"):
        return False, None
    operand = _strip_casts_8616(node.operand)
    variable = getattr(operand, "variable", None) if isinstance(operand, structured_c.CVariable) else None
    if isinstance(variable, SimStackVariable):
        variable_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if isinstance(variable_offset, int):
            offset_cache[node_id] = variable_offset
            return True, variable_offset
    offset_cache[node_id] = _UNRESOLVED_STACK_OFFSET_8616
    return True, None


@cython.ccall
def _stack_offset_nonleaf_value_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    seen: object,
) -> int | None:
    """Resolve an offset from variable/dirty/binary nodes; None when unsupported."""
    resolved: object
    if isinstance(node, structured_c.CVariable):
        return _resolve_stack_offset_from_variable_8616(node, project, codegen, seen)
    resolved = _resolve_stack_offset_from_dirty_8616(node, project, codegen, seen)
    if resolved is not None:
        return resolved
    resolved = _stack_pointer_carrier_offset_8616(node, project, codegen, seen)
    if resolved is not None:
        return resolved
    if isinstance(node, structured_c.CBinaryOp) and node.op in {"Add", "Sub"}:
        return _resolve_stack_offset_from_binary_8616(node, project, codegen, seen)
    return None


@cython.ccall
def _stack_offset_from_expr_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue, seen: object = None
) -> int | None:
    """Resolve stack-address expressions using their proven coordinate domain."""
    leaf: object
    offset_cache: object
    if seen is None:
        seen = set()
    node = _strip_casts_8616(node)
    offset_cache = getattr(codegen, "_inertia_stack_offset_cache", None)
    if not isinstance(offset_cache, dict):
        offset_cache = {}
        codegen._inertia_stack_offset_cache = offset_cache
    node_id = id(node)
    hit, cached = _stack_offset_cache_entry_8616(codegen, node_id, seen, offset_cache)
    if hit:
        return cached

    leaf = _stack_offset_leaf_value_8616(codegen, node)
    if leaf is not None:
        offset_cache[node_id] = leaf
        return leaf

    handled, ref_value = _stack_offset_reference_value_8616(codegen, node, offset_cache, node_id)
    if handled:
        return ref_value

    resolved = _stack_offset_nonleaf_value_8616(node, project, codegen, seen)
    return _stack_offset_cache_record_8616(offset_cache, node_id, resolved)


def _log_refusal_8616(codegen: StructuredCodegenValue, kind: object, /, **details: StructuredAstValue) -> None:
    refusals: object
    refusals = getattr(codegen, "_inertia_ss_lowering_refusal_log", None)
    normalized = {k: str(v) for k, v in builtins.iter(details.items())}
    if isinstance(refusals, list):
        refusals.append({"kind": kind, **normalized})
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning("[ss-linear-lowering] refusal kind=%s details=%r", kind, normalized)


def _debug_c_repr_8616(node: StructuredAstValue) -> object:
    try:
        chunks = node.c_repr_chunks(asexpr=True)
        return "".join(str(text) for text, _obj in iter(chunks))
    except Exception:
        return repr(node)


@cython.ccall
def _safe_debug_attr_8616(obj: StructuredAstValue, attr: object) -> StructuredAstValue:
    try:
        return getattr(obj, attr, None)
    except (AttributeError, TypeError, ValueError):
        return None


@cython.dataclasses.dataclass
class _SsLinearMatch8616:
    """Match a dereference of ``(ss << 4) + stack_offset`` with stack proof."""

    node: StructuredAstValue
    project: AngrProjectValue
    codegen: StructuredCodegenValue
    segment_name: object = None
    offset_total: cython.longlong = 0
    offset_terms: object = field(default_factory=list)
    unresolved_segment_terms: object = field(default_factory=list)
    inferred_ss_from_stack_fact: cython.bint = False
    base_offset: int | None = None
    width: StructuredAstValue = None
    displacement: cython.longlong = 0
    known_offsets: StructuredAstValue = ()

    @cython.ccall
    def _classify_terms_8616(self, terms: StructuredAstValue) -> cython.bint:
        """Fold each signed term into segment, const, or offset evidence."""
        const: object
        seg: object
        sign: object
        term: object
        for sign, term in terms:
            seg = _segment_base_name_8616(term, self.project, codegen=self.codegen)
            if seg is not None:
                if sign != 1 or self.segment_name is not None:
                    return False
                self.segment_name = seg
                continue
            const = _constant_value_8616(term)
            if const is not None:
                self.offset_total += sign * const
                continue
            if sign == 1 and _is_unresolved_segment_scale_candidate_8616(term):
                self.unresolved_segment_terms.append(term)
                continue
            self.offset_terms.append(
                term
                if sign == 1
                else structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeInt(signed=False), codegen=self.codegen),
                    term,
                    codegen=self.codegen,
                )
            )
        return True

    @cython.ccall
    def _infer_ss_segment_8616(self) -> None:
        """Infer an SS segment when one stack-offset term carries proof."""
        candidate_base_offset: object
        if self.segment_name is None and len(self.unresolved_segment_terms) == 1 and len(self.offset_terms) == 1:
            candidate_base_offset = _stack_offset_from_expr_8616(self.offset_terms[0], self.project, self.codegen)
            if candidate_base_offset is not None:
                candidate_displacement = candidate_base_offset + self.offset_total
                if _has_stack_storage_evidence_for_displacement_8616(self.codegen, candidate_displacement, self.width):
                    self.segment_name = "ss"
                    self.base_offset = candidate_base_offset
                    self.inferred_ss_from_stack_fact = True
                    self.codegen._inertia_ss_segment_inferred_from_stack_offset_count = (
                        int(getattr(self.codegen, "_inertia_ss_segment_inferred_from_stack_offset_count", 0) or 0) + 1
                    )

    def _refused_on_segment_shape_8616(self) -> cython.bint:
        """Refuse when the segment or term shape is not a proven stack access."""
        if not (
            self.segment_name != "ss"
            or (self.unresolved_segment_terms and not self.inferred_ss_from_stack_fact)
            or len(self.offset_terms) > 1
        ):
            return False
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            _log_refusal_8616(
                self.codegen,
                "segment_or_terms",
                segment=self.segment_name,
                terms=len(self.offset_terms),
                unresolved_segments=len(self.unresolved_segment_terms),
                operand=repr(self.node.operand),
                offset_term_types=tuple(type(term).__name__ for term in iter(self.offset_terms)),
                offset_terms=tuple(_debug_c_repr_8616(term) for term in iter(self.offset_terms)),
            )
        else:
            _log_refusal_8616(self.codegen, "segment_or_terms", segment=self.segment_name, terms=len(self.offset_terms))
        return True

    @cython.ccall
    def _resolve_base_offset_8616(self) -> cython.bint:
        """Resolve the base BP offset; False when unresolvable."""
        self.known_offsets = _known_bp_stack_offsets_8616(self.codegen)
        if self.base_offset is None and len(self.offset_terms) == 0:
            self.base_offset = 0
        elif self.base_offset is None:
            self.base_offset = _stack_offset_from_expr_8616(self.offset_terms[0], self.project, self.codegen)
        if self.base_offset is None and len(self.offset_terms) == 1 and self.offset_total in self.known_offsets:
            self.base_offset = 0
        if self.base_offset is None:
            _log_refusal_8616(
                self.codegen,
                "offset_unresolved",
                segment=self.segment_name,
                offset_expr_type=type(self.offset_terms[0]).__name__ if self.offset_terms else "None",
                const_offset=self.offset_total,
            )
            return False
        return True

    @cython.ccall
    def _rebase_absolute_anchor_8616(self) -> None:
        """Rebase onto the wrapped anchor when the computed offset lacks proof."""
        assert self.base_offset is not None
        absolute_displacement = (
            absolute_machine_bp_offset_from_wrapped_anchor_8616(
                self.offset_terms[0],
                self.offset_total,
                self.known_offsets,
            )
            if len(self.offset_terms) == 1
            else None
        )
        if (
            isinstance(absolute_displacement, int)
            and not _has_stack_storage_evidence_for_displacement_8616(
                self.codegen,
                self.base_offset + self.offset_total,
                self.width,
            )
        ):
            self.base_offset = 0
            self.offset_total = absolute_displacement

    def _ss_offset_alias_ok_8616(self) -> cython.bint:
        """Require stack-alias evidence for non-direct SS offset terms."""
        assert self.base_offset is not None
        if self.segment_name != "ss" or all(
            _is_stack_offset_term_direct_8616(term) for term in iter(self.offset_terms)
        ):
            return True
        if _has_stack_storage_evidence_for_displacement_8616(
            self.codegen, self.base_offset + self.offset_total, self.width
        ) or all(
            _stack_offset_term_stackish_8616(term, self.project, self.codegen) for term in iter(self.offset_terms)
        ) or self.base_offset + self.offset_total in self.known_offsets or (
            _ss_probe_enabled_8616(self.codegen)
            and all(
                _stack_offset_term_stackish_8616(term, self.project, self.codegen) for term in iter(self.offset_terms)
            )
        ):
            self.codegen._inertia_ss_segment_inferred_from_stack_offset_count += 1
            return True
        _log_refusal_8616(
            self.codegen,
            "no_stack_alias_fact_for_ss_offset",
            segment=self.segment_name,
            displacement=self.base_offset + self.offset_total,
            width=self.width,
        )
        return False

    @cython.ccall
    def _resolve_displacement_8616(self) -> None:
        """Resolve displacement, rebasing through the entry-SP anchor if needed."""
        assert self.base_offset is not None
        self.displacement = self.base_offset + self.offset_total
        if not _has_stack_storage_evidence_for_displacement_8616(self.codegen, self.displacement, self.width):
            entry_sp_anchor = (
                machine_bp_offset_for_entry_sp_anchor_8616(self.codegen, self.offset_terms[0])
                if len(self.offset_terms) == 1
                else None
            )
            rebased_displacement = (
                entry_sp_anchor + self.offset_total
                if isinstance(entry_sp_anchor, int)
                else None
            )
            if (
                isinstance(rebased_displacement, int)
                and _has_stack_storage_evidence_for_displacement_8616(
                    self.codegen,
                    rebased_displacement,
                    self.width,
                )
            ):
                self.displacement = rebased_displacement
                self.codegen._inertia_entry_sp_stack_anchor_rebased_count_8616 = (
                    int(getattr(self.codegen, "_inertia_entry_sp_stack_anchor_rebased_count_8616", 0) or 0)
                    + 1
                )

    @cython.ccall
    def _final_gate_8616(self) -> cython.bint:
        """Refuse when no stack fact or inferred alias evidence backs the access."""
        facts: object
        region: object
        region = getattr(getattr(self.codegen, "cfunc", None), "addr", None)
        facts = _stack_storage_facts_for_segmented_address_8616("ss", self.displacement, self.width, region=region)
        try:
            direct_sp_frame_carrier = bool(self.codegen._inertia_allow_direct_sp_for_callee_save_spill)
        except AttributeError:
            direct_sp_frame_carrier = False
        direct_sp_frame_carrier = bool(
            direct_sp_frame_carrier
            and len(self.offset_terms) == 1
            and _expr_register_name_8616(self.offset_terms[0], self.project) == "sp"
        )
        if (facts is None or facts.identity is None) and not direct_sp_frame_carrier:
            _log_refusal_8616(self.codegen, "no_stack_facts", displacement=self.displacement, width=self.width, region=region)
            return False
        if self.inferred_ss_from_stack_fact and not _has_stack_storage_evidence_for_displacement_8616(
            self.codegen, self.displacement, self.width
        ):
            _log_refusal_8616(self.codegen, "no_inferred_ss_stack_alias_fact", displacement=self.displacement, width=self.width)
            return False
        return True

    @cython.ccall
    def match_8616(self) -> RealModeLinearStackAccess8616 | None:
        """Run the SS-linear access match, refusing without proof."""
        native_offset: object
        terms: object
        if not hasattr(self.codegen, "_inertia_ss_segment_inferred_from_stack_offset_count"):
            self.codegen._inertia_ss_segment_inferred_from_stack_offset_count = 0

        self.node = _strip_casts_8616(self.node)
        if not isinstance(self.node, structured_c.CUnaryOp) or self.node.op != "Dereference":
            return None
        access_width = _dereference_access_width_bytes_8616(self.node)
        self.width = access_width

        terms = _flatten_signed_terms_8616(self.node.operand)
        if terms is None:
            return None
        terms = _expand_virtual_linear_address_carrier_terms_8616(terms, self.project, self.codegen)
        if not self._classify_terms_8616(terms):
            return None
        self._infer_ss_segment_8616()
        if self._refused_on_segment_shape_8616():
            return None
        if not self._resolve_base_offset_8616():
            return None
        self._rebase_absolute_anchor_8616()
        if not self._ss_offset_alias_ok_8616():
            return None
        self._resolve_displacement_8616()
        if not self._final_gate_8616():
            return None
        native_offset = (
            native_entry_sp_offset_for_anchor_8616(self.offset_terms[0])
            if len(self.offset_terms) == 1 and proven_bp_entry_sp_delta_8616(self.codegen) is None else None
        )
        entry_sp_offset = (
            _canonical_stack_offset_8616(native_offset + self.offset_total) if native_offset is not None else None
        )
        return RealModeLinearStackAccess8616(self.displacement, self.width, entry_sp_offset=entry_sp_offset)


@cython.ccall
def match_stable_ss_linear_stack_access_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue
) -> RealModeLinearStackAccess8616 | None:
    """Match a dereference of ``(ss << 4) + stack_offset`` with stack proof."""
    return _SsLinearMatch8616(node=node, project=project, codegen=codegen).match_8616()


def match_stable_ds_es_linear_global_access_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue
) -> RealModeLinearGlobalAddress8616 | None:
    """Match a dereference of ``(ds << 4) + addr`` or ``(es << 4) + addr``."""

    def _impl() -> StructuredAstValue:
        decomposed: object
        segment_name: object
        width: object
        width_bits: object
        nonlocal node
        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None

        decomposed = _decompose_linear_global_terms_8616(node.operand, project, codegen=codegen)
        if decomposed is None:
            return None
        segment_name, displacement, residual_terms = decomposed

        if segment_name in {"ds", "es"}:
            width_bits = getattr(getattr(node, "type", None), "size", None)
            width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
            if width is None:
                inferred_width = _global_size_from_displacement_8616(codegen, displacement)
                if isinstance(inferred_width, int) and inferred_width > 0:
                    width = inferred_width
            return RealModeLinearGlobalAddress8616(
                segment_name=segment_name,
                displacement=displacement,
                residual_terms=tuple(residual_terms),
                width=width,
            )

        if segment_name is not None or not _global_displacement_known_8616(codegen, displacement):
            return None

        width_bits = getattr(getattr(node, "type", None), "size", None)
        width = max(width_bits // 8, 1) if isinstance(width_bits, int) and width_bits > 0 else None
        if width is None:
            inferred_width = _global_size_from_displacement_8616(codegen, displacement)
            if isinstance(inferred_width, int) and inferred_width > 0:
                width = inferred_width
        return RealModeLinearGlobalAddress8616(
            segment_name="segless",
            displacement=displacement,
            residual_terms=tuple(residual_terms),
            width=width,
        )

    return cast(RealModeLinearGlobalAddress8616 | None, _impl())


@cython.ccall
def _address_projection_term_is_safe_8616(node: StructuredAstValue) -> cython.bint:
    expr: object
    allowed_unary = {"Neg", "BitNot", "Reference"}
    allowed_binary = {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}
    pending: list[StructuredAstValue] = [_strip_casts_8616(node)]
    seen: set[cython.longlong] = set()
    while pending:
        expr = _strip_casts_8616(pending.pop())
        if expr is None:
            return False
        expr_id = id(expr)
        if expr_id in seen:
            return False
        seen.add(expr_id)
        if _constant_value_8616(expr) is not None:
            continue
        if isinstance(expr, structured_c.CVariable):
            continue
        if isinstance(expr, structured_c.CUnaryOp) and expr.op in allowed_unary:
            pending.append(expr.operand)
            continue
        if isinstance(expr, structured_c.CBinaryOp) and expr.op in allowed_binary:
            pending.append(expr.rhs)
            pending.append(expr.lhs)
            continue
        return False
    return True


def _contains_materialized_global_reference_8616(node: StructuredAstValue) -> cython.bint:
    child: object
    children: object
    expr: object
    variable: object
    attr: object
    pending: list[StructuredAstValue] = [_strip_casts_8616(node)]
    seen: set[cython.longlong] = set()
    while pending:
        expr = _strip_casts_8616(pending.pop())
        if expr is None:
            continue
        expr_id = id(expr)
        if expr_id in seen:
            continue
        seen.add(expr_id)
        if isinstance(expr, structured_c.CUnaryOp) and expr.op == "Reference":
            variable = getattr(expr.operand, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                return True
            pending.append(expr.operand)
            continue
        for attr in ("lhs", "rhs", "operand", "expr", "index"):
            child = getattr(expr, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("args", "operands"):
            children = getattr(expr, attr, None)
            if isinstance(children, (list, tuple)):
                pending.extend(child for child in iter(children) if child is not None)
    return False


def _return_register_virtual_name_8616(node: StructuredAstValue, project: AngrProjectValue) -> object:
    _ax_size: object
    ax_reg: object
    child: object
    current: object
    name: object
    seq: object
    attr: object
    ax_reg, _ax_size = getattr(getattr(project, "arch", None), "registers", {}).get("ax", (None, None))
    pending = [_strip_casts_8616(node)]
    seen: set[cython.longlong] = set()
    while pending:
        current = _strip_casts_8616(pending.pop())
        if current is None:
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        name = _return_ax_name_8616(current, ax_reg)
        if name is not None:
            return name
        for attr in ("lhs", "rhs", "operand", "expr", "cond", "iftrue", "iffalse"):
            child = getattr(current, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("operands", "args"):
            seq = getattr(current, attr, None)
            if seq:
                pending.extend(item for item in iter(seq) if item is not None)
    return None


@cython.ccall
def _return_ax_name_8616(current: StructuredAstValue, ax_reg: StructuredAstValue) -> object:
    """Return the vvar name for an ax-carrier node, else None."""
    dirty: object
    varid: object
    dirty = getattr(current, "dirty", None)
    if dirty is not None:
        reg = _dirty_reg_offset_8616(dirty)
        varid = getattr(dirty, "varid", None)
        if isinstance(ax_reg, int) and reg == ax_reg and isinstance(varid, int):
            return f"vvar_{varid}"
    if isinstance(current, structured_c.CVariable):
        variable = current.variable
        if isinstance(variable, SimRegisterVariable):
            reg = variable.reg
            name = current.name or variable.name
            if isinstance(ax_reg, int) and reg == ax_reg and isinstance(name, str) and name.startswith("vvar_"):
                return name
    return None


@cython.ccall
def _return_rhs_is_safe_8616(expr: StructuredAstValue) -> cython.bint:
    expr = _strip_casts_8616(expr)
    if isinstance(expr, (structured_c.CConstant, structured_c.CVariable, structured_c.CDirtyExpression)):
        return True
    if isinstance(expr, structured_c.CTypeCast):
        return _return_rhs_is_safe_8616(expr.expr)
    if isinstance(expr, structured_c.CUnaryOp):
        return expr.op != "Dereference" and _return_rhs_is_safe_8616(expr.operand)
    if isinstance(expr, structured_c.CBinaryOp):
        return _return_rhs_is_safe_8616(expr.lhs) and _return_rhs_is_safe_8616(expr.rhs)
    return False


@cython.ccall
def _materialize_return_retval_8616(
    node: structured_c.CReturn, codegen: StructuredCodegenValue, project: AngrProjectValue
) -> cython.bint:
    """Substitute a proven ax-carrier return value with its safe assignment RHS."""
    rhs: object
    virtual_name: object
    virtual_name = _return_register_virtual_name_8616(node.retval, project)
    if virtual_name is None:
        return False
    rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, virtual_name)
    if rhs is None or not _return_rhs_is_safe_8616(rhs):
        return False
    node.retval = rhs
    codegen._inertia_return_register_materialized_count = (
        int(getattr(codegen, "_inertia_return_register_materialized_count", 0) or 0) + 1
    )
    return True


@cython.ccall
def _materialize_return_register_assignments_8616(codegen: StructuredCodegenValue, project: AngrProjectValue) -> cython.bint:
    node: object
    root: object
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False
    changed = False
    stack = [root]
    seen: set[cython.longlong] = set()
    while stack:
        node = stack.pop()
        if node is None:
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        if isinstance(node, structured_c.CReturn) and _materialize_return_retval_8616(
            node, codegen, project
        ):
            changed = True
            continue
        _push_return_walk_children_8616(node, stack)
    return changed


_RETURN_WALK_CHILD_ATTRS_8616 = ("statements", "body", "else_node", "condition_and_nodes", "condition", "init", "iteration")


@cython.ccall
def _push_return_walk_children_8616(node: StructuredAstValue, stack: object) -> None:
    """Push statement/child nodes for the return-assignment walk."""
    value: object
    attr: object
    item: object
    for attr in _RETURN_WALK_CHILD_ATTRS_8616:
        value = getattr(node, attr, None)
        if value is None:
            continue
        if isinstance(value, list | tuple):
            for item in reversed(tuple(value)):
                if isinstance(item, tuple):
                    stack.extend(reversed(item))
                else:
                    stack.append(item)
        else:
            stack.append(value)


@cython.ccall
def _op_reg_id_8616(insn: StructuredAstValue, index: cython.longlong) -> int | None:
    operands: object
    reg: object
    operands = getattr(insn, "operands", None)
    if operands is None or len(operands) <= index:
        return None
    operand = operands[index]
    if getattr(operand, "type", None) != 1:
        return None
    reg = getattr(operand, "reg", None)
    return int(reg) if isinstance(reg, int) else None


@cython.ccall
def _is_mov_sp_bp_8616(insn: StructuredAstValue) -> cython.bint:
    if operator.ne(getattr(insn, "id", None), X86_INS_MOV):
        return False
    return bool(operator.eq(_op_reg_id_8616(insn, 0), X86_REG_SP) and operator.eq(_op_reg_id_8616(insn, 1), X86_REG_BP))


@cython.ccall
def _is_function_return_instruction_8616(insn: StructuredAstValue) -> cython.bint:
    """Recognize decoded near and far returns through Capstone semantics."""
    return bool(
        operator.eq(getattr(insn, "id", None), X86_INS_RET)
        or X86_GRP_RET in frozenset(getattr(insn, "groups", ()) or ())
    )


@cython.ccall
def _decode_insn_cache_entry_8616(
    project: AngrProjectValue, function_addr: cython.longlong, limit: cython.longlong, function: object
) -> tuple[dict[StructuredAstValue, StructuredAstValue], StructuredAstValue, StructuredAstValue]:
    """Return (cache, key, hit) for the RET-terminated decode cache."""
    cache: object
    cached: object
    cache = getattr(project, "_inertia_decode_function_insns_cache_8616", None)
    if not isinstance(cache, dict):
        cache = {}
        with contextlib.suppress(Exception):
            project._inertia_decode_function_insns_cache_8616 = cache
    key = (
        tuple((int(function_addr), int(limit), id(function)))
        if function is not None
        else tuple((int(function_addr), int(limit)))
    )
    cached = cache.get(key)
    return cache, key, cached if isinstance(cached, tuple) else None


@cython.ccall
def _resolve_decode_function_8616(
    project: AngrProjectValue, function_addr: cython.longlong, function: object
) -> StructuredAstValue | None:
    """Resolve function metadata from the knowledge base when absent."""
    funcs: object
    if function is None:
        funcs = getattr(getattr(project, "kb", None), "functions", None)
        if funcs is not None:
            with contextlib.suppress(Exception):
                function = funcs.function(addr=function_addr, create=False)
    if function is None:
        if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE") == "1":
            log.warning("[callee-save-prune] no function metadata at %#x", function_addr)
        return None
    return function


def _ordered_ret_terminated_insns_8616(
    project: AngrProjectValue, function: StructuredAstValue
) -> tuple[tuple[StructuredAstValue, ...], list[StructuredAstValue]]:
    """Return (all decoded insns, insns through the first RET)."""
    insn: object
    block: object
    wrapper: object
    blocks = _direct_global_update_blocks_8616(project, function)
    insns = []
    for block in blocks:
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = getattr(wrapper, "insn", wrapper)
            if isinstance(getattr(insn, "address", None), int):
                insns.append(insn)
    ordered = []
    for insn in sorted(insns, key=lambda item: int(getattr(item, "address", 0) or 0)):
        ordered.append(insn)
        if _is_function_return_instruction_8616(insn):
            break
    return tuple(blocks), ordered


def _decode_function_insns_at_8616(
    project: AngrProjectValue,
    function_addr: cython.longlong,
    *,
    limit: cython.longlong = 0x100,
    function: StructuredAstValue | None = None,
) -> object:
    """Return a complete function decode, caching only RET-terminated evidence."""
    cached: object
    debug = os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE") == "1"
    cache, key, cached = _decode_insn_cache_entry_8616(project, function_addr, limit, function)
    if cached is not None:
        return cast("tuple[StructuredAstValue, ...]", cached)

    function = _resolve_decode_function_8616(project, function_addr, function)
    if function is None:
        return ()

    blocks, ordered = _ordered_ret_terminated_insns_8616(project, function)
    if not any(_is_function_return_instruction_8616(insn) for insn in iter(ordered)):
        if debug:
            log.warning(
                "[callee-save-prune] incomplete decode addr=%#x blocks=%d insns=%d first=%r last=%r",
                function_addr,
                len(blocks),
                len(ordered),
                getattr(ordered[0], "address", None) if ordered else None,
                getattr(ordered[-1], "address", None) if ordered else None,
            )
        return ()
    result = tuple(ordered)
    cache[key] = result
    return result


@cython.ccall
def _decode_function_insns_8616(
    project: AngrProjectValue,
    function_addr: cython.longlong,
    *,
    limit: cython.longlong = 0x100,
    function: StructuredAstValue | None = None,
) -> object:
    """Decode one function through its current and original linear addresses."""
    delta: object
    insns = _decode_function_insns_at_8616(
        project,
        function_addr,
        limit=limit,
        function=function,
    )
    if insns:
        return insns
    if function is not None:
        insns = _decode_function_insns_at_8616(project, function_addr, limit=limit)
        if insns:
            return insns
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        return _decode_function_insns_at_8616(project, function_addr + delta, limit=limit)
    return ()


@cython.ccall
def _callee_save_cache_8616(project: AngrProjectValue) -> object:
    """Return the project-owned callee-save name cache, creating it once."""
    cache: object
    cache = getattr(project, "_inertia_callee_saved_register_names_cache_8616", None)
    if not isinstance(cache, dict):
        cache = {}
        with contextlib.suppress(Exception):
            project._inertia_callee_saved_register_names_cache_8616 = cache
    return cache


@cython.ccall
def _normalized_function_insns_8616(
    decoded_insns: StructuredAstValue,
) -> tuple[StructuredAstValue, ...]:
    """Dedup decoded instructions by (address, id), preserving order."""
    address: object
    instruction_id: object
    insn: object
    normalized_insns: list[StructuredAstValue] = []
    seen_instruction_keys: set[tuple[cython.longlong, cython.longlong]] = set()
    for insn in decoded_insns:
        address = getattr(insn, "address", None)
        instruction_id = getattr(insn, "id", None)
        if not isinstance(address, int) or not isinstance(instruction_id, int):
            continue
        key = (address, instruction_id)
        if key in seen_instruction_keys:
            continue
        seen_instruction_keys.add(key)
        normalized_insns.append(insn)
    return tuple(normalized_insns)


@cython.ccall
def _callee_save_pushes_8616(
    insns: object, preservable: object
) -> object:
    """Collect pushed preservable registers before the first return."""
    insn: object
    pushed: list[str] = []
    for insn in insns:
        if operator.eq(getattr(insn, "id", None), X86_INS_PUSH):
            reg_id = _op_reg_id_8616(insn, 0)
            if isinstance(reg_id, int):
                reg_name = insn.reg_name(reg_id)
                if reg_name in preservable:
                    pushed.append(reg_name)
        if _is_function_return_instruction_8616(insn):
            break
    return pushed


@cython.ccall
def _callee_save_restores_8616(
    insns: object,
    ret_index: cython.longlong,
    preservable: object,
) -> object:
    """Collect restored registers whose values stay live until the return."""
    canonical_name: object
    insn_id: object
    insn: object
    written_register_id: object
    canonical_register_names = {
        "al": "ax",
        "ah": "ax",
        "bl": "bx",
        "bh": "bx",
        "cl": "cx",
        "ch": "cx",
        "dl": "dx",
        "dh": "dx",
    }
    restored: list[str] = []
    registers_written_after: set[str] = set()
    for insn in reversed(insns[:ret_index]):
        insn_id = getattr(insn, "id", None)
        if operator.eq(insn_id, X86_INS_POP):
            reg_id = _op_reg_id_8616(insn, 0)
            if isinstance(reg_id, int) and reg_id != X86_REG_BP:
                reg_name = insn.reg_name(reg_id)
                canonical_name = canonical_register_names.get(reg_name, reg_name)
                if canonical_name in preservable and canonical_name not in registers_written_after:
                    restored.append(canonical_name)
                if canonical_name in preservable:
                    registers_written_after.add(canonical_name)
            continue
        try:
            _read_registers, written_register_ids = insn.regs_access()
        except (AttributeError, TypeError):
            written_register_ids = ()
        for written_register_id in written_register_ids:
            if not isinstance(written_register_id, int):
                continue
            written_name = insn.reg_name(written_register_id)
            canonical_name = canonical_register_names.get(written_name, written_name)
            if canonical_name in preservable:
                registers_written_after.add(canonical_name)
    return restored


def _callee_saved_register_names_from_frame_evidence_8616(
    project: AngrProjectValue,
    function_addr: cython.longlong,
    *,
    function: StructuredAstValue | None = None,
) -> object:
    """Return exact push/pop-proven explicitly preserved general registers.

    Negative results remain uncached because function discovery may still be
    extending the CFG and instruction extent during Structuring retries.
    """
    cached: object
    ret_index: object
    debug = os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE") == "1"
    cache = _callee_save_cache_8616(project)
    cache_key = (int(function_addr), id(function)) if function is not None else int(function_addr)
    cached = cache.get(cache_key)
    if isinstance(cached, frozenset):
        return cached
    decoded_insns = _decode_function_insns_8616(
        project,
        function_addr,
        function=function,
    )
    insns = _normalized_function_insns_8616(decoded_insns)
    if debug:
        log.warning(
            "[callee-save-prune] decoded func=%#x count=%d first=%r last=%r",
            function_addr,
            len(insns),
            getattr(insns[0], "address", None) if insns else None,
            getattr(insns[-1], "address", None) if insns else None,
        )
    if not insns:
        return frozenset()
    preservable = frozenset({"ax", "bx", "cx", "dx", "si", "di", "ds", "es"})
    pushed = _callee_save_pushes_8616(insns, preservable)
    if debug:
        log.warning("[callee-save-prune] decoded pushes=%r", tuple(pushed))
    if not pushed:
        return frozenset()

    ret_index = next(
        (
            idx
            for idx, insn in builtins.iter(enumerate(insns))
            if _is_function_return_instruction_8616(insn)
        ),
        None,
    )
    if ret_index is None:
        return frozenset()
    restored = _callee_save_restores_8616(insns, ret_index, preservable)
    if debug:
        log.warning("[callee-save-prune] decoded restores=%r ret_index=%r", tuple(restored), ret_index)
    if not restored:
        return frozenset()
    result = frozenset(set(pushed) & set(restored))
    if result:
        cache[cache_key] = result
    return result


@cython.ccall
def _expr_register_name_8616(node: StructuredAstValue, project) -> object:
    del project
    register_name = physical_register_name_8616(_strip_casts_8616(node))
    return register_name if isinstance(register_name, str) else None


@cython.ccall
def _statement_ins_addr_8616(stmt: StructuredAstValue) -> int | None:
    ins_addr: object
    tags: object
    tags = copy_structured_tags_8616(getattr(stmt, "tags", None))
    if tags is not None:
        ins_addr = tags.get("ins_addr")
        if isinstance(ins_addr, int):
            return ins_addr
    ins_addr = getattr(stmt, "ins_addr", None)
    return ins_addr if isinstance(ins_addr, int) else None


@cython.ccall
def _round_trip_callee_saved_regs_8616(decoded_insns: StructuredAstValue) -> frozenset[str]:
    """Return registers with both a PUSH and a POP in the function prologue."""
    instruction_id: object
    insn: object
    preservable = frozenset({"ax", "bx", "cx", "dx", "si", "di", "ds", "es"})
    pushed: set[str] = set()
    popped: set[str] = set()
    for insn in decoded_insns:
        instruction_id = getattr(insn, "id", None)
        if instruction_id not in {X86_INS_PUSH, X86_INS_POP}:
            continue
        reg_id = _op_reg_id_8616(insn, 0)
        if not isinstance(reg_id, int):
            continue
        register_name = insn.reg_name(reg_id)
        if register_name not in preservable:
            continue
        (pushed if operator.eq(instruction_id, X86_INS_PUSH) else popped).add(register_name)
    return frozenset(pushed & popped)


@cython.ccall
def _frame_instruction_roles_8616(
    frame_pairs: StructuredAstValue,
    runtime_gp_names: StructuredAstValue,
) -> object:
    """Map frame push/pop instruction addresses to their owning pairs."""
    pair: object
    roles: dict[cython.longlong, tuple[CalleeSavedFramePair8616, CalleeSavedFrameInstructionRole8616]] = {}
    for pair in frame_pairs:
        runtime_owned = (
            pair.register_name in {"ds", "es"}
            or runtime_gp_live_in_name_8616(pair.register_name) in runtime_gp_names
        )
        if runtime_owned:
            continue
        roles[pair.push_addr] = (
            pair,
            CalleeSavedFrameInstructionRole8616.PUSH,
        )
        roles[pair.pop_addr] = (
            pair,
            CalleeSavedFrameInstructionRole8616.POP,
        )
    return roles


@cython.ccall
def _callee_saved_prune_stats_8616(codegen: StructuredCodegenValue) -> object:
    """Return the codegen-owned spill-prune stats bucket, creating it once."""
    stats: object
    stats = getattr(codegen, "_inertia_callee_saved_spill_prune_stats", None)
    if not isinstance(stats, dict):
        stats = {
            "candidates": 0,
            "pruned": 0,
            "refused": 0,
            "raw_fact_count": 0,
            "normalized_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "failure_count": 0,
        }
        codegen._inertia_callee_saved_spill_prune_stats = stats
    return stats


@cython.dataclasses.dataclass
class _CalleeSavedSpillPrune8616:
    """Remove exact push/pop-proven callee-save spill assignments."""

    codegen: StructuredCodegenValue
    project: AngrProjectValue
    saved_regs: StructuredAstValue
    frame_instruction_roles: object
    stats: object
    pruned_facts: object
    prior_facts: StructuredAstValue
    function_addr: cython.longlong
    changed: cython.bint = False

    @cython.ccall
    def carrier_storage(
        self,
        stmt: StructuredAstValue,
        pair: CalleeSavedFramePair8616,
        role: CalleeSavedFrameInstructionRole8616,
    ) -> tuple[CalleeSavedFrameCarrierKind8616, int | None, int | None]:
        """Classify the observable storage carried by one frame assignment."""
        access: object
        previous_allow_sp: object
        previous_offset_cache: object
        if role is not CalleeSavedFrameInstructionRole8616.PUSH:
            return CalleeSavedFrameCarrierKind8616.FRAME_BOOKKEEPING, None, None
        lhs = _strip_casts_8616(stmt.lhs)
        if operator.ne(_expr_register_name_8616(stmt.rhs, self.project), pair.register_name):
            return CalleeSavedFrameCarrierKind8616.FRAME_BOOKKEEPING, None, None
        if isinstance(lhs, structured_c.CVariable):
            variable = lhs.variable
            if isinstance(variable, SimStackVariable) and variable.base == "bp":
                return (
                    CalleeSavedFrameCarrierKind8616.STACK_SLOT_WRITE,
                    machine_bp_offset_for_stack_variable_8616(self.codegen, variable),
                    variable.size,
                )
            return CalleeSavedFrameCarrierKind8616.FRAME_BOOKKEEPING, None, None
        if not isinstance(lhs, structured_c.CUnaryOp) or lhs.op != "Dereference":
            return CalleeSavedFrameCarrierKind8616.FRAME_BOOKKEEPING, None, None
        previous_allow_sp = getattr(self.codegen, "_inertia_allow_direct_sp_for_callee_save_spill", False)
        previous_offset_cache = getattr(self.codegen, "_inertia_stack_offset_cache", None)
        self.codegen._inertia_allow_direct_sp_for_callee_save_spill = True
        self.codegen._inertia_stack_offset_cache = None
        try:
            access = match_stable_ss_linear_stack_access_8616(lhs, self.project, self.codegen)
        finally:
            self.codegen._inertia_allow_direct_sp_for_callee_save_spill = previous_allow_sp
            self.codegen._inertia_stack_offset_cache = previous_offset_cache
        if access is None:
            return CalleeSavedFrameCarrierKind8616.FRAME_BOOKKEEPING, None, None
        return (
            CalleeSavedFrameCarrierKind8616.SEGMENTED_STACK_WRITE,
            access.displacement,
            access.width,
        )

    @cython.ccall
    def is_prunable(self, stmt: StructuredAstValue) -> cython.bint:
        """Check whether a statement is a proven frame spill to drop."""
        frame_owner: object
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        ins_addr = _statement_ins_addr_8616(stmt)
        if not isinstance(ins_addr, int):
            return False
        frame_owner = self.frame_instruction_roles.get(ins_addr)
        if frame_owner is not None:
            pair, role = frame_owner
            pair_semantics = (
                CalleeSavedFramePairSemantics8616.PRESERVED
                if pair.register_name in self.saved_regs
                else CalleeSavedFramePairSemantics8616.RESTORED_BEFORE_UPDATE
            )
            carrier_kind, displacement, access_width = self.carrier_storage(stmt, pair, role)
            self.stats["raw_fact_count"] = int(self.stats.get("raw_fact_count", 0) or 0) + 1
            self.stats["normalized_fact_count"] = int(self.stats.get("normalized_fact_count", 0) or 0) + 1
            self.stats["classified_fact_count"] = int(self.stats.get("classified_fact_count", 0) or 0) + 1
            self.stats["candidates"] = int(self.stats.get("candidates", 0) or 0) + 1
            self.pruned_facts.append(
                CalleeSavedFramePruneFact8616(
                    function_addr=self.function_addr,
                    register_name=pair.register_name,
                    push_addr=pair.push_addr,
                    pop_addr=pair.pop_addr,
                    instruction_addr=ins_addr,
                    carrier_ordinal=len(self.prior_facts) + len(self.pruned_facts),
                    instruction_role=role,
                    carrier_kind=carrier_kind,
                    stack_displacement=displacement,
                    access_width=access_width,
                    pair_semantics=pair_semantics,
                )
            )
            return True
        return False

    @cython.ccall
    def rewrite_statement_list(self, statements: object) -> None:
        """Drop prunable assignments and recurse into statement containers."""
        stmt: object
        kept = []
        for stmt in statements:
            if self.is_prunable(stmt):
                self.stats["pruned"] = int(self.stats.get("pruned", 0) or 0) + 1
                self.stats["materialized_count"] = int(self.stats.get("materialized_count", 0) or 0) + 1
                self.changed = True
                continue
            kept.append(stmt)
        if operator.ne(len(kept), len(statements)):
            statements[:] = kept
        for stmt in tuple(kept):
            self._rewrite_stmt_children_8616(stmt)

    @cython.ccall
    def _rewrite_stmt_children_8616(self, stmt: StructuredAstValue) -> None:
        """Recurse the rewrite into a statement's child containers."""
        condition_nodes: object
        value: object
        attr: object
        item: object
        for attr in ("statements", "body", "else_node"):
            value = getattr(stmt, attr, None)
            if isinstance(value, structured_c.CStatements):
                self.rewrite_statement_list(value.statements)
            elif isinstance(value, list):
                self.rewrite_statement_list(value)
        condition_nodes = getattr(stmt, "condition_and_nodes", None)
        if isinstance(condition_nodes, list | tuple):
            for item in condition_nodes:
                if isinstance(item, tuple) and len(item) >= 2:
                    body = item[1]
                    if isinstance(body, structured_c.CStatements):
                        self.rewrite_statement_list(body.statements)


@cython.ccall
def _remove_callee_saved_stack_spills_8616(
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
    *,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Remove exact push/pop-proven callee-save spill assignments."""
    function_addr: object
    root: object
    function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(function_addr, int):
        return False
    saved_regs = _callee_saved_register_names_from_frame_evidence_8616(
        project,
        function_addr,
        function=function,
    )
    decoded_insns = _decode_function_insns_8616(
        project,
        function_addr,
        function=function,
    )
    round_trip_regs = _round_trip_callee_saved_regs_8616(decoded_insns)
    if os.environ.get("INERTIA_DEBUG_CALLEE_SAVE_PRUNE"):
        log.warning(
            "[callee-save-prune] func=%#x saved_regs=%r round_trip_regs=%r",
            function_addr,
            sorted(saved_regs),
            sorted(round_trip_regs),
        )
    if not round_trip_regs:
        return False
    frame_pairs = callee_saved_frame_pairs_8616(decoded_insns, round_trip_regs)
    runtime_gp_names = runtime_gp_state_names_8616(codegen)
    frame_instruction_roles = _frame_instruction_roles_8616(frame_pairs, runtime_gp_names)
    stats = _callee_saved_prune_stats_8616(codegen)

    try:
        prior_record = codegen._inertia_callee_saved_frame_prune_record_8616
    except AttributeError:
        prior_record = None
    prior_facts = (
        prior_record.evidence
        if isinstance(prior_record, CalleeSavedFramePruneRecord8616)
        else ()
    )
    pruned_facts: list[CalleeSavedFramePruneFact8616] = []
    prune = _CalleeSavedSpillPrune8616(
        codegen=codegen,
        project=project,
        saved_regs=saved_regs,
        frame_instruction_roles=frame_instruction_roles,
        stats=stats,
        pruned_facts=pruned_facts,
        prior_facts=prior_facts,
        function_addr=function_addr,
    )

    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if isinstance(root, structured_c.CStatements):
        prune.rewrite_statement_list(root.statements)
    elif isinstance(root, list):
        prune.rewrite_statement_list(root)
    if pruned_facts:
        codegen._inertia_callee_saved_frame_prune_record_8616 = (
            CalleeSavedFramePruneRecord8616.closed(tuple(prior_facts) + tuple(pruned_facts))
        )
    return prune.changed


@cython.ccall
def prune_callee_saved_stack_spills_8616(
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
    *,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Replay binary frame-evidence pruning after structured AST regeneration."""
    return _remove_callee_saved_stack_spills_8616(
        codegen,
        project,
        function=function,
    )


@cython.ccall
def materialize_proven_control_stack_escape_8616(
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
    *,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Materialize an exact entry-POP/terminal-RET non-local escape."""
    fact: object
    function_addr: object
    function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(function_addr, int):
        return False
    fact = classify_control_stack_escape_8616(
        _decode_function_insns_8616(
            project,
            function_addr,
            function=function,
        ),
        function_addr,
    )
    return bool(fact is not None and materialize_control_stack_escape_8616(codegen, fact))


@cython.ccall
def match_stable_ds_es_linear_global_address_8616(
    node: StructuredAstValue, project: AngrProjectValue, codegen: StructuredCodegenValue
) -> RealModeLinearGlobalAddress8616 | None:
    """Match an address-valued ``(ds << 4) + base + projection`` expression."""
    decomposed: object
    segment_name: object
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
        return None
    if _contains_materialized_global_reference_8616(node):
        return None

    decomposed = _decompose_linear_global_terms_8616(node, project, codegen=codegen)
    if decomposed is None:
        return None
    segment_name, displacement, residual_terms = decomposed

    if segment_name in {"ds", "es"}:
        return RealModeLinearGlobalAddress8616(
            segment_name=segment_name,
            displacement=displacement,
            residual_terms=tuple(residual_terms),
            width=None,
        )

    if segment_name is not None or not residual_terms or not _global_displacement_known_8616(codegen, displacement):
        return None
    return RealModeLinearGlobalAddress8616(
        segment_name="segless",
        displacement=displacement & 0xFFFF,
        residual_terms=tuple(residual_terms),
        width=None,
    )


@cython.ccall
def _walk_dses_list_children_8616(
    value: object,
    node_stack: object,
    transform: Callable[[StructuredAstValue], StructuredAstValue],
) -> cython.bint:
    """Transform each element of a child list in place."""
    index: object
    item: object
    local_changed = False
    for index, item in enumerate(tuple(value)):
        if not type(item).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            continue
        replacement = transform(item)
        if replacement is not item:
            value[index] = replacement
            local_changed = True
            continue
        candidate = value[index]
        if type(candidate).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            node_stack.append(candidate)
    return local_changed


@cython.ccall
def _walk_dses_attr_children_8616(
    node: StructuredAstValue,
    node_stack: object,
    transform: Callable[[StructuredAstValue], StructuredAstValue],
) -> cython.bint:
    """Transform each child-bearing attribute of one node in place."""
    value: object
    attr: object
    local_changed = False
    for attr in (
        "statements",
        "lhs",
        "rhs",
        "operand",
        "expr",
        "init",
        "condition",
        "iteration",
        "body",
        "else_node",
    ):
        if not hasattr(node, attr):
            continue
        try:
            value = getattr(node, attr)
        except Exception:
            continue
        if isinstance(value, list):
            if _walk_dses_list_children_8616(value, node_stack, transform):
                local_changed = True
        elif value is not None:
            replacement = transform(value)
            if replacement is not value:
                setattr(node, attr, replacement)
                local_changed = True
                continue
            node_stack.append(value)
    return local_changed


@cython.ccall
def _walk_dses_pair_children_8616(
    node: StructuredAstValue,
    node_stack: object,
    transform: Callable[[StructuredAstValue], StructuredAstValue],
) -> cython.bint:
    """Transform condition/body pairs of one node in place."""
    condition_and_nodes: object
    body: object
    cond: object
    condition_and_nodes = getattr(node, "condition_and_nodes", None)
    if not condition_and_nodes:
        return False
    local_changed = False
    new_pairs = []
    for cond, body in condition_and_nodes:
        new_cond = (
            transform(cond)
            if type(cond).__module__.startswith("angr.analyses.decompiler.structured_codegen")
            else cond
        )
        if new_cond is not cond:
            local_changed = True
        new_body = (
            transform(body)
            if type(body).__module__.startswith("angr.analyses.decompiler.structured_codegen")
            else body
        )
        if new_body is not body:
            local_changed = True
        if new_cond is cond and type(new_cond).__module__.startswith(
            "angr.analyses.decompiler.structured_codegen"
        ):
            node_stack.append(new_cond)
        if new_body is body and type(new_body).__module__.startswith(
            "angr.analyses.decompiler.structured_codegen"
        ):
            node_stack.append(new_body)
        new_pairs.append((new_cond, new_body))
    if local_changed:
        node.condition_and_nodes = new_pairs
    return local_changed


@cython.ccall
def _replace_children_walk_8616(
    root_node: object,
    seen: object,
    transform: Callable[[StructuredAstValue], StructuredAstValue],
) -> cython.bint:
    """Walk a structured tree once, transforming children in place."""
    node: object
    if root_node is None:
        return False
    node_stack: list[StructuredAstValue] = [root_node]
    local_changed = False
    while node_stack:
        node = node_stack.pop()
        if node is None or not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        if _walk_dses_attr_children_8616(node, node_stack, transform):
            local_changed = True
        if _walk_dses_pair_children_8616(node, node_stack, transform):
            local_changed = True
    return local_changed


@cython.dataclasses.dataclass
class _DsEsGlobalDerefRun8616:
    """One DS/ES-linear global dereference lowering walk over a structured tree."""

    codegen: StructuredAstValue
    project: StructuredAstValue
    changed: cython.bint = False
    seen: object = field(default_factory=set)

    @cython.ccall
    def _rebind_stack_entry_to_global_8616(
        self,
        variables_in_use: object,
        variable: StructuredAstValue,
        cvar: StructuredAstValue,
        addr: cython.longlong,
        name: object,
        scalar_width: cython.longlong,
        target_type: StructuredAstValue,
    ) -> StructuredAstValue:
        """Replace a same-displacement stack entry with a global memory cvar."""
        unified: object
        replacement = SimMemoryVariable(
            addr,
            scalar_width,
            name=name,
            region=getattr(self.codegen.cfunc, "addr", None),
        )
        replacement_type = getattr(cvar, "variable_type", None) or target_type
        replacement_cvar = structured_c.CVariable(
            replacement, variable_type=replacement_type, codegen=self.codegen
        )
        variables_in_use.pop(variable, None)
        variables_in_use[replacement] = replacement_cvar
        unified = getattr(self.codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified.pop(variable, None)
            unified[replacement] = {(replacement_cvar, getattr(replacement_cvar, "variable_type", None))}
        return replacement_cvar

    @cython.ccall
    def _reuse_one_global_cvar_8616(
        self,
        variables_in_use: object,
        access: RealModeLinearGlobalAddress8616,
        variable: StructuredAstValue,
        cvar: StructuredAstValue,
        addr: cython.longlong,
        name: object,
        scalar_width: cython.longlong,
        target_type: StructuredAstValue,
    ) -> StructuredAstValue:
        """Return a reusable cvar for one registry entry, or None."""
        if isinstance(variable, SimMemoryVariable) and operator.eq(getattr(variable, "addr", None), addr):
            existing_size = variable.size
            if _cvar_has_array_type_8616(cvar) or (isinstance(existing_size, int) and existing_size > 2):
                return None
            if operator.ne(variable.size, scalar_width):
                variable.size = scalar_width
            if getattr(cvar, "variable_type", None) is None:
                cvar.variable_type = target_type
            return cvar
        if isinstance(variable, SimVariable) and operator.eq(getattr(variable, "name", None), name):
            if _cvar_has_array_type_8616(cvar):
                return None
            if getattr(cvar, "variable_type", None) is None:
                cvar.variable_type = target_type
            return cvar
        if (
            isinstance(variable, SimStackVariable)
            and operator.eq(machine_bp_offset_for_stack_variable_8616(self.codegen, variable), access.displacement)
        ):
            return self._rebind_stack_entry_to_global_8616(
                variables_in_use, variable, cvar, addr, name, scalar_width, target_type
            )
        return None

    @cython.ccall
    def _reuse_global_cvar_8616(
        self,
        variables_in_use: object,
        access: RealModeLinearGlobalAddress8616,
        addr: cython.longlong,
        name: object,
        scalar_width: cython.longlong,
        target_type: StructuredAstValue,
    ) -> StructuredAstValue:
        """Reuse or rebind an existing cvar covering the global displacement."""
        reused: object
        cvar: object
        variable: object
        for variable, cvar in tuple(variables_in_use.items()):
            reused = self._reuse_one_global_cvar_8616(
                variables_in_use, access, variable, cvar, addr, name, scalar_width, target_type
            )
            if reused is not None:
                return reused
        return None

    @cython.ccall
    def global_cvar_8616(self, access: RealModeLinearGlobalAddress8616) -> StructuredAstValue:
        """Return a reused or fresh global memory cvar for the access displacement."""
        reused: object
        unified: object
        variables_in_use: object
        addr = access.displacement & 0xFFFF
        name = f"g_{addr:04X}"
        scalar_width = min(access.width or 1, 2)
        target_type = _type_for_access_width_8616(scalar_width)
        variables_in_use = getattr(self.codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            reused = self._reuse_global_cvar_8616(
                variables_in_use, access, addr, name, scalar_width, target_type
            )
            if reused is not None:
                return reused
        variable = SimMemoryVariable(
            addr, scalar_width, name=f"mem_{addr:04X}", region=getattr(self.codegen.cfunc, "addr", None)
        )
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=self.codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(self.codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar
    @cython.ccall
    def global_expr_8616(self, access: RealModeLinearGlobalAddress8616) -> StructuredAstValue:
        """Build the global dereference expression, including residual index terms."""
        sign: object
        term: object
        if not access.residual_terms:
            return self.global_cvar_8616(access)
        target_type = _type_for_access_width_8616(access.width)
        ptr_type = SimTypePointer(target_type).with_arch(self.project.arch)
        rebuilt = structured_c.CUnaryOp(
            "Reference",
            self.global_cvar_8616(access),
            codegen=self.codegen,
        )
        for sign, term in access.residual_terms:
            rebuilt = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                rebuilt,
                term,
                codegen=self.codegen,
            )
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(ptr_type, ptr_type, rebuilt, codegen=self.codegen),
            codegen=self.codegen,
        )
    @cython.ccall
    def transform(self, node: StructuredAstValue) -> StructuredAstValue:
        """Lower a stable DS/ES linear dereference to a global; node when refused."""
        access: object
        access = match_stable_ds_es_linear_global_access_8616(node, self.project, self.codegen)
        if access is not None:
            if not may_lower_codegen_access_to_entry_ds_object_8616(
                self.codegen,
                node,
                segment_register=access.segment_name,
                offset=access.displacement,
                width=access.width,
            ):
                return node
            self.changed = True
            _record_real_mode_global_lowering_evidence_8616(self.codegen, self.project, access)
            return self.global_expr_8616(access)
        return node
    @cython.ccall
    def replace_children(self, root_node: StructuredAstValue) -> cython.bint:
        """Walk the structured tree applying the transform; True when any node changed."""
        return _replace_children_walk_8616(root_node, self.seen, self.transform)
@cython.ccall
def lower_stable_ds_es_linear_global_dereferences_8616(
    codegen: StructuredAstValue, project: StructuredAstValue | None = None
) -> cython.bint:
    """Replace stable DS/ES real-mode linear dereferences with global variable references."""
    previous_active_bias: object
    root: object
    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-update] unavailable project=%s root=%s",
                project is not None,
                root is not None,
            )
        return False



    run = _DsEsGlobalDerefRun8616(codegen=codegen, project=project)
    had_active_bias = hasattr(codegen, "_inertia_active_stack_base_bp_bias_8616")
    previous_active_bias = getattr(codegen, "_inertia_active_stack_base_bp_bias_8616", None)
    pass_stack_base_bias = _infer_stack_base_bp_bias_8616(codegen)
    if isinstance(pass_stack_base_bias, int):
        codegen._inertia_active_stack_base_bp_bias_8616 = pass_stack_base_bias
    try:
        if run.replace_children(root):
            run.changed = True
    finally:
        if had_active_bias:
            codegen._inertia_active_stack_base_bp_bias_8616 = previous_active_bias
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_active_stack_base_bp_bias_8616")
    if materialize_proven_control_stack_escape_8616(codegen, project):
        run.changed = True
    if prune_callee_saved_stack_spills_8616(codegen, project):
        run.changed = True
    if _materialize_return_register_assignments_8616(codegen, project):
        run.changed = True
    return run.changed


@cython.dataclasses.dataclass
class _DsEsGlobalAddrRun8616:
    """One DS/ES-linear global address lowering walk over a structured tree."""

    codegen: StructuredAstValue
    project: StructuredAstValue
    changed: cython.bint = False
    seen: object = field(default_factory=set)

    @cython.ccall
    def global_address_cvar_8616(self, displacement: cython.longlong) -> StructuredAstValue:
        """Return a reused or fresh byte global cvar for the displacement."""
        unified: object
        variables_in_use: object
        cvar: object
        variable: object
        addr = displacement & 0xFFFF
        name = f"g_{addr:04X}"
        target_type = SimTypeChar(False)
        variables_in_use = getattr(self.codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in tuple(variables_in_use.items()):
                if (
                    isinstance(variable, SimMemoryVariable)
                    and operator.eq(getattr(variable, "addr", None), addr)
                    and getattr(variable, "size", None) == 1
                ):
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
                if (
                    isinstance(variable, SimVariable)
                    and operator.eq(getattr(variable, "name", None), name)
                    and getattr(variable, "size", None) == 1
                ):
                    if getattr(cvar, "variable_type", None) is None:
                        cvar.variable_type = target_type
                    return cvar
        variable = SimMemoryVariable(addr, 1, name=name, region=getattr(self.codegen.cfunc, "addr", None))
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=self.codegen)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(self.codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    @cython.ccall
    def reference_expr_8616(self, displacement: cython.longlong) -> StructuredAstValue:
        """Build a Reference expression over the displacement's global cvar."""
        base_cvar = self.global_address_cvar_8616(displacement)
        return structured_c.CUnaryOp(
            "Reference",
            base_cvar,
            codegen=self.codegen,
        )

    @cython.ccall
    def transform(self, node: StructuredAstValue) -> StructuredAstValue:
        """Lower a stable DS/ES linear address to a typed global reference; node when refused."""
        access: object
        sign: object
        term: object
        access = match_stable_ds_es_linear_global_address_8616(node, self.project, self.codegen)
        if access is None:
            return node
        if not may_lower_codegen_address_to_entry_ds_object_8616(
            self.codegen,
            node,
            segment_register=access.segment_name,
        ):
            return node
        base_expr = self.reference_expr_8616(access.displacement)
        rebuilt = base_expr
        for sign, term in access.residual_terms:
            rebuilt = structured_c.CBinaryOp(
                "Add" if sign == 1 else "Sub",
                rebuilt,
                term,
                codegen=self.codegen,
            )
        ptr_type = SimTypePointer(SimTypeChar(False)).with_arch(self.project.arch)
        self.changed = True
        return structured_c.CTypeCast(ptr_type, ptr_type, rebuilt, codegen=self.codegen)
    @cython.ccall
    def replace_children(self, root_node: StructuredAstValue) -> cython.bint:
        """Walk the structured tree applying the transform; True when any node changed."""
        return _replace_children_walk_8616(root_node, self.seen, self.transform)
@cython.ccall
def lower_stable_ds_es_linear_global_addresses_8616(
    codegen: StructuredCodegenValue, project: AngrProjectValue = None
) -> cython.bint:
    """Replace stable DS/ES address-valued expressions with data-space object references."""
    root: object
    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    run = _DsEsGlobalAddrRun8616(codegen=codegen, project=project)
    new_root = run.transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        run.changed = True
    if run.replace_children(root):
        run.changed = True
    if _materialize_return_register_assignments_8616(codegen, project):
        run.changed = True
    return run.changed




@cython.ccall
def _direct_global_update_name_8616(project: AngrProjectValue, func_addr: int | None, displacement: cython.longlong) -> object:
    label: object
    labels: object
    labels = getattr(getattr(project, "kb", None), "labels", None)
    if isinstance(labels, dict):
        label = labels.get(displacement & 0xFFFF)
        if isinstance(label, str) and label.strip():
            return label.lstrip("_")
    return f"g_{displacement & 0xFFFF:04X}"


def _linear_block_covered_8616(
    blocks: object,
    linear_addr: StructuredAstValue,
    linear_size: StructuredAstValue,
    linear_insns: StructuredAstValue,
) -> cython.bint:
    """Check whether an existing block already covers the linear block."""
    block_addr: object
    block_size: object
    block: object
    for block in blocks:
        block_addr = getattr(block, "addr", None)
        block_size = getattr(block, "size", None)
        block_insns = _boundary_tuple_8616(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not all(isinstance(value, int) for value in iter((linear_addr, linear_size, block_addr, block_size))):
            continue
        if (
            operator.eq(block_addr, linear_addr)
            and block_size >= linear_size
            and block_insns
            and len(block_insns) >= len(linear_insns)
        ):
            return True
    return False


@cython.ccall
def _append_linear_block_8616(
    blocks: object,
    project: StructuredAstValue,
    function: StructuredAstValue,
) -> object:
    """Append the fallback linear block unless an existing block covers it."""
    linear_addr: object
    linear_size: object
    linear = _linear_capstone_function_block_8616(project, function)
    if not linear:
        return blocks
    linear_addr = getattr(linear[0], "addr", None)
    linear_size = getattr(linear[0], "size", None)
    linear_insns = _boundary_tuple_8616(getattr(getattr(linear[0], "capstone", None), "insns", ()) or ())
    if _linear_block_covered_8616(blocks, linear_addr, linear_size, linear_insns):
        return blocks
    return blocks + linear


@cython.ccall
def _direct_global_update_blocks_8616(
    project: object, function: StructuredAstValue
) -> object:
    """Return candidate blocks for direct stack/global instruction facts."""
    block_addr: object
    local_blocks = _boundary_tuple_8616((getattr(function, "_local_blocks", {}) or {}).values())
    if local_blocks:
        return _append_linear_block_8616(local_blocks, project, function)
    blocks = _boundary_tuple_8616(getattr(function, "blocks", ()) or ())
    if blocks:
        return _append_linear_block_8616(blocks, project, function)
    block_addrs = _boundary_tuple_8616(sorted(tuple(getattr(function, "block_addrs_set", ()) or ())))
    if project is None:
        return ()
    if not block_addrs:
        return _linear_capstone_function_block_8616(project, function)
    decoded = []
    for block_addr in block_addrs:
        try:
            decoded.append(project.factory.block(block_addr, opt_level=0))
        except Exception:
            continue
    if decoded:
        return _append_linear_block_8616(tuple(decoded), project, function)
    return _linear_capstone_function_block_8616(project, function)


@cython.ccall
def _capstone_candidate_code_8616(
    candidate_project: StructuredAstValue,
    load_addr: cython.longlong,
    size: cython.longlong,
    addr: cython.longlong,
    disasm_addr: cython.longlong,
    original_project: StructuredAstValue,
) -> object:
    """Load the candidate byte window, returning None on any boundary miss."""
    loader: object
    memory: object
    loader = getattr(candidate_project, "loader", None)
    memory = getattr(loader, "memory", None)
    debug = bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))
    if memory is None:
        if debug:
            log.warning(
                "[linear-capstone] skip no-memory function=%#x load=%#x disasm=%#x original=%s",
                addr,
                load_addr,
                disasm_addr,
                candidate_project is original_project,
            )
        return None
    try:
        code = bytes(memory.load(load_addr, size))
    except Exception as exc:
        if debug:
            log.warning(
                "[linear-capstone] load-failed function=%#x load=%#x disasm=%#x original=%s error=%s",
                addr,
                load_addr,
                disasm_addr,
                candidate_project is original_project,
                exc.__class__.__name__,
            )
        return None
    if not code:
        if debug:
            log.warning(
                "[linear-capstone] empty-bytes function=%#x load=%#x disasm=%#x original=%s",
                addr,
                load_addr,
                disasm_addr,
                candidate_project is original_project,
            )
        return None
    return code


def _capstone_candidate_insns_8616(
    candidate_project: StructuredAstValue,
    code: object,
    load_addr: cython.longlong,
    disasm_addr: cython.longlong,
    addr: cython.longlong,
    original_project: StructuredAstValue,
) -> object:
    """Disassemble the candidate window, returning None on any boundary miss."""
    capstone: object
    capstone = getattr(getattr(candidate_project, "arch", None), "capstone", None)
    if capstone is None:
        return None
    debug = bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))
    with contextlib.suppress(Exception):
        capstone.detail = True
    try:
        insns = tuple(capstone.disasm(code, disasm_addr))
    except Exception as exc:
        if debug:
            log.warning(
                "[linear-capstone] disasm-failed function=%#x load=%#x disasm=%#x original=%s error=%s",
                addr,
                load_addr,
                disasm_addr,
                candidate_project is original_project,
                exc.__class__.__name__,
            )
        return None
    if not insns:
        if debug:
            log.warning(
                "[linear-capstone] no-insns function=%#x load=%#x disasm=%#x original=%s bytes=%d",
                addr,
                load_addr,
                disasm_addr,
                candidate_project is original_project,
                len(code),
            )
        return None
    if debug:
        preview = _boundary_tuple_8616(
            (
                getattr(insn, "address", None),
                getattr(insn, "mnemonic", None),
                getattr(insn, "op_str", None),
            )
            for insn in iter(insns[:8])
        )
        log.warning(
            "[linear-capstone] decoded function=%#x load=%#x disasm=%#x original=%s bytes=%d insns=%d preview=%r",
            addr,
            load_addr,
            disasm_addr,
            candidate_project is original_project,
            len(code),
            len(insns),
            preview,
        )
    return insns


@cython.ccall
def _linear_capstone_function_block_8616(
    project: object, function: object
) -> tuple[StructuredAstValue, ...]:
    """Return a lightweight full-function Capstone block when CFG blocks are absent.

    Direct stack move/update evidence is instruction-local. If CFG block
    metadata is unavailable for a recovered function, decode the function byte
    window directly instead of silently producing no evidence.
    """
    addr: object
    code: object
    delta: object
    insns: object
    original_project: object
    size: object
    candidate_project: object
    disasm_addr: object
    load_addr: object
    if project is None or function is None:
        return ()
    addr = getattr(function, "addr", None)
    if not isinstance(addr, int):
        return ()
    size = getattr(function, "size", None)
    if not isinstance(size, int) or size <= 0:
        size = 0x300
    size = max(1, min(int(size), 0x600))
    candidates: list[tuple[StructuredAstValue, cython.longlong, cython.longlong]] = [(project, addr, addr)]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    original_project = getattr(project, "_inertia_original_project", None)
    if original_project is not None and isinstance(delta, int) and delta:
        candidates.append((original_project, addr + delta, addr))

    seen: set[tuple[cython.longlong, cython.longlong, cython.longlong]] = set()
    for candidate_project, load_addr, disasm_addr in candidates:
        key = (id(candidate_project), int(load_addr), int(disasm_addr))
        if key in seen:
            continue
        seen.add(key)
        code = _capstone_candidate_code_8616(
            candidate_project, load_addr, size, addr, disasm_addr, original_project
        )
        if code is None:
            continue
        insns = _capstone_candidate_insns_8616(
            candidate_project, code, load_addr, disasm_addr, addr, original_project
        )
        if insns is None:
            continue
        return (SimpleNamespace(addr=disasm_addr, size=size, capstone=SimpleNamespace(insns=insns)),)
    return ()


@cython.ccall
def _capstone_insns_for_direct_global_update_8616(
    project: object, block: StructuredAstValue
) -> object:
    block_addr: object
    block_bytes: object
    block_size: object
    cached: object
    capstone: object
    cached = getattr(block, "_inertia_capstone_insns_8616", None)
    if isinstance(cached, tuple):
        return cached
    capstone = getattr(block, "capstone", None)
    insns = _boundary_tuple_8616(getattr(capstone, "insns", ()) or ())
    if insns or project is None:
        with contextlib.suppress(Exception):
            block._inertia_capstone_insns_8616 = insns
        return insns
    block_addr = getattr(block, "addr", None)
    if not isinstance(block_addr, int):
        return ()
    block_size = getattr(block, "size", None)
    if not isinstance(block_size, int) or block_size <= 0:
        block_bytes = getattr(block, "bytes", None)
        block_size = len(block_bytes) if isinstance(block_bytes, (bytes, bytearray)) else None
    with contextlib.suppress(Exception):
        if isinstance(block_size, int) and block_size > 0:
            decoded = project.factory.block(block_addr, size=block_size, opt_level=0)
        else:
            decoded = project.factory.block(block_addr, opt_level=0)
        insns = _boundary_tuple_8616(getattr(getattr(decoded, "capstone", None), "insns", ()) or ())
        with contextlib.suppress(Exception):
            block._inertia_capstone_insns_8616 = insns
        return insns
    return ()


def _dedup_sorted_capstone_insns_by_addr_8616(wrappers: StructuredAstValue) -> tuple[StructuredAstValue, ...]:
    """Return a deterministic instruction stream from overlapping evidence blocks."""
    ins_addr: object
    insn: object
    wrapper: object
    ordered = sorted(
        wrappers,
        key=lambda wrapper: int(getattr(getattr(wrapper, "insn", wrapper), "address", 0) or 0),
    )
    deduped: list[StructuredAstValue] = []
    seen_addrs: set[cython.longlong] = set()
    for wrapper in ordered:
        insn = getattr(wrapper, "insn", wrapper)
        ins_addr = getattr(insn, "address", None)
        if isinstance(ins_addr, int):
            if int(ins_addr) in seen_addrs:
                continue
            seen_addrs.add(int(ins_addr))
        deduped.append(wrapper)
    return tuple(deduped)


@cython.ccall
def _global_update_insn_delta_8616(
    insn: StructuredAstValue,
) -> object:
    """Decode INC/DEC/ADD/SUB update targets into (operand, signed delta)."""
    insn_id: object
    width: object
    insn_id = getattr(insn, "id", None)
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if insn_id in {X86_INS_INC, X86_INS_DEC}:
        if len(operands) != 1:
            return None
        return operands[0], 1 if operator.eq(insn_id, X86_INS_INC) else -1
    if insn_id in {X86_INS_ADD, X86_INS_SUB}:
        if len(operands) != 2 or operator.ne(getattr(operands[1], "type", None), X86_OP_IMM):
            return None
        operand = operands[0]
        width = getattr(operand, "size", None)
        imm = int(getattr(operands[1], "imm", 0) or 0)
        if width == 1:
            imm &= 0xFF
            if imm & 0x80:
                imm -= 0x100
        else:
            imm &= 0xFFFF
            if imm & 0x8000:
                imm -= 0x10000
        return operand, imm if operator.eq(insn_id, X86_INS_ADD) else -imm
    return None


@cython.ccall
def _global_update_mem_target_8616(
    operand: StructuredAstValue, insn: StructuredAstValue
) -> object:
    """Validate a bare-displacement memory target and return (disp, width, addr)."""
    base: object
    displacement: object
    index: object
    ins_addr: object
    mem: object
    width: object
    width = getattr(operand, "size", None)
    if operator.ne(getattr(operand, "type", None), X86_OP_MEM) or width not in {1, 2}:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    base = getattr(mem, "base", X86_REG_INVALID)
    index = getattr(mem, "index", X86_REG_INVALID)
    if base not in {0, X86_REG_INVALID} or index not in {0, X86_REG_INVALID}:
        return None
    displacement = getattr(mem, "disp", None)
    ins_addr = getattr(insn, "address", None)
    if not isinstance(displacement, int) or not isinstance(ins_addr, int):
        return None
    return displacement, int(width), ins_addr


@cython.ccall
def _direct_global_update_instruction_facts_8616(
    project: AngrProjectValue, function: StructuredAstValue
) -> object:
    cached: object
    decoded: object
    insn: object
    mem_target: object
    block: object
    wrapper: object
    cached = getattr(function, "_inertia_direct_global_update_instruction_facts_8616", None)
    if isinstance(cached, tuple):
        return cached
    facts: list[DirectGlobalUpdateFact8616] = []
    for block in _direct_global_update_blocks_8616(project, function):
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = getattr(wrapper, "insn", wrapper)
            decoded = _global_update_insn_delta_8616(insn)
            if decoded is None:
                continue
            operand, delta = decoded
            mem_target = _global_update_mem_target_8616(operand, insn)
            if mem_target is None:
                continue
            displacement, width, ins_addr = mem_target
            facts.append(
                DirectGlobalUpdateFact8616(
                    displacement & 0xFFFF,
                    int(width),
                    int(delta),
                    ins_addr,
                )
            )
    result = tuple(dict.fromkeys(facts))
    with contextlib.suppress(Exception):
        function._inertia_direct_global_update_instruction_facts_8616 = result
    return result


@cython.ccall
def _mov_stack_update_fact_8616(
    insns: StructuredAstValue, index: cython.longlong, insn: StructuredAstValue, operands: StructuredAstValue
) -> DirectStackUpdateFact8616 | None:
    """Recover a read-modify-write update stored through a register MOV."""
    ins_addr: object
    reg_id: object
    slot: object
    update: object
    if operator.ne(getattr(insn, "id", None), X86_INS_MOV) or len(operands) != 2:
        return None
    slot = _stack_mem_operand_offset_width_8616(operands[0])
    if slot is None or operator.ne(getattr(operands[1], "type", None), X86_OP_REG):
        return None
    offset, width = slot
    reg_id = getattr(operands[1], "reg", None)
    if not isinstance(reg_id, int):
        return None
    update = _previous_register_stack_update_8616(insns, index, reg_id, int(width))
    if update is None:
        return None
    source_offset, delta = update
    # This collector owns read-modify-write updates.  When the
    # register was loaded from a different stack slot, the sequence
    # is an assignment expression and is already represented by a
    # DirectStackMoveFact8616.  Emitting both facts composes the
    # destination into its own initializer during replay.
    if source_offset != offset:
        return None
    ins_addr = getattr(insn, "address", None)
    if not isinstance(ins_addr, int):
        return None
    return DirectStackUpdateFact8616(
        offset,
        int(width),
        delta,
        ins_addr,
        DirectStackUpdateSourceKind8616.STACK_SLOT,
        None,
        source_offset,
    )


@cython.ccall
def _incdec_stack_update_fact_8616(
    insn: StructuredAstValue, operands: StructuredAstValue
) -> DirectStackUpdateFact8616 | None:
    """Recover a direct stack INC/DEC update."""
    ins_addr: object
    insn_id: object
    slot: object
    insn_id = getattr(insn, "id", None)
    if insn_id not in {X86_INS_INC, X86_INS_DEC}:
        return None
    if len(operands) != 1:
        return None
    slot = _stack_mem_operand_offset_width_8616(operands[0])
    if slot is None:
        return None
    offset, width = slot
    ins_addr = getattr(insn, "address", None)
    if not isinstance(ins_addr, int):
        return None
    return DirectStackUpdateFact8616(offset, int(width), 1 if operator.eq(insn_id, X86_INS_INC) else -1, ins_addr)


@cython.ccall
def _arith_immediate_update_fact_8616(
    source: StructuredAstValue,
    offset: StructuredAstValue,
    width: StructuredAstValue,
    sign: cython.longlong,
    ins_addr: cython.longlong,
    operation: StructuredAstValue,
) -> DirectStackUpdateFact8616 | None:
    """Recover an immediate-operand stack arithmetic update."""
    value: object
    value = getattr(source, "imm", None)
    if not isinstance(value, int):
        return None
    if operation in {
        DirectStackUpdateOp8616.SHIFT_LEFT,
        DirectStackUpdateOp8616.SHIFT_RIGHT,
    }:
        value = int(value) & 0x1F
        if value == 0:
            return None
    return DirectStackUpdateFact8616(
        offset,
        int(width),
        sign * abs(int(value)),
        ins_addr,
        DirectStackUpdateSourceKind8616.IMMEDIATE,
        abs(int(value)),
        None,
        operation,
    )


@cython.ccall
def _arith_reg_update_fact_8616(
    insns: StructuredAstValue,
    index: cython.longlong,
    reg_id: cython.longlong,
    offset: StructuredAstValue,
    width: StructuredAstValue,
    sign: cython.longlong,
    ins_addr: cython.longlong,
    operation: StructuredAstValue,
) -> DirectStackUpdateFact8616 | None:
    """Recover a register-operand stack arithmetic update."""
    immediate: object
    indexed_source: object
    source_slot: object
    if operation in {
        DirectStackUpdateOp8616.SHIFT_LEFT,
        DirectStackUpdateOp8616.SHIFT_RIGHT,
    }:
        immediate = _previous_register_immediate_8616(insns, index, reg_id)
        if immediate is not None:
            masked_immediate = immediate & 0x1F
            if masked_immediate:
                return DirectStackUpdateFact8616(
                    offset,
                    int(width),
                    0,
                    ins_addr,
                    DirectStackUpdateSourceKind8616.IMMEDIATE,
                    masked_immediate,
                    None,
                    operation,
                )
            return None
    source_slot = _previous_stack_load_for_register_8616(insns, index, reg_id)
    indexed_source = None
    if source_slot is None:
        indexed_source = _previous_indexed_pointer_load_for_register_8616(insns, index, reg_id)
    if source_slot is None and indexed_source is None:
        return None
    if indexed_source is not None:
        source_base_offset, source_index_offset, source_index_scale, source_width = indexed_source
        if source_width != width:
            return None
        return DirectStackUpdateFact8616(
            offset,
            int(width),
            sign,
            ins_addr,
            DirectStackUpdateSourceKind8616.INDEXED_POINTER,
            None,
            None,
            operation,
            source_base_offset,
            source_index_offset,
            source_index_scale,
        )
    assert source_slot is not None
    source_offset, source_width = source_slot
    if source_width != width:
        return None
    return DirectStackUpdateFact8616(
        offset,
        int(width),
        sign,
        ins_addr,
        DirectStackUpdateSourceKind8616.STACK_SLOT,
        None,
        source_offset,
        operation,
    )


@cython.ccall
def _arith_stack_update_fact_8616(
    insns: StructuredAstValue, index: cython.longlong, insn: StructuredAstValue, operands: StructuredAstValue
) -> DirectStackUpdateFact8616 | None:
    """Recover an ADD/SUB/OR/SAL/SHL/SHR stack arithmetic update."""
    ins_addr: object
    insn_id: object
    operation: object
    reg_id: object
    slot: object
    source_type: object
    insn_id = getattr(insn, "id", None)
    if insn_id not in {
        X86_INS_ADD,
        X86_INS_SUB,
        X86_INS_OR,
        X86_INS_SAL,
        X86_INS_SHL,
        X86_INS_SHR,
    } or len(operands) != 2:
        return None
    slot = _stack_mem_operand_offset_width_8616(operands[0])
    if slot is None:
        return None
    offset, width = slot
    ins_addr = getattr(insn, "address", None)
    if not isinstance(offset, int) or not isinstance(ins_addr, int):
        return None
    operation = {
        X86_INS_OR: DirectStackUpdateOp8616.OR,
        X86_INS_SAL: DirectStackUpdateOp8616.SHIFT_LEFT,
        X86_INS_SHL: DirectStackUpdateOp8616.SHIFT_LEFT,
        X86_INS_SHR: DirectStackUpdateOp8616.SHIFT_RIGHT,
    }.get(insn_id, DirectStackUpdateOp8616.ARITHMETIC)
    sign = -1 if operator.eq(insn_id, X86_INS_SUB) else 1
    source = operands[1]
    source_type = getattr(source, "type", None)
    if operator.eq(source_type, X86_OP_IMM):
        return _arith_immediate_update_fact_8616(source, offset, width, sign, ins_addr, operation)
    if operator.ne(source_type, X86_OP_REG):
        return None
    reg_id = getattr(source, "reg", None)
    if not isinstance(reg_id, int):
        return None
    return _arith_reg_update_fact_8616(insns, index, reg_id, offset, width, sign, ins_addr, operation)


@cython.ccall
def _stack_update_fact_at_8616(
    insns: StructuredAstValue, index: cython.longlong, insn: StructuredAstValue
) -> DirectStackUpdateFact8616 | None:
    """Collect the stack-update fact for one instruction, if any."""
    fact: object
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    fact = _mov_stack_update_fact_8616(insns, index, insn, operands)
    if fact is None:
        fact = _incdec_stack_update_fact_8616(insn, operands)
    if fact is None:
        fact = _arith_stack_update_fact_8616(insns, index, insn, operands)
    return fact


@cython.ccall
def _direct_stack_update_instruction_facts_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
) -> object:
    """Collect binary-proven BP-relative stack update facts."""
    cached: object
    fact: object
    insn: object
    block: object
    index: object
    wrapper: object
    cached = getattr(function, "_inertia_direct_stack_update_instruction_facts_8616", None)
    if isinstance(cached, tuple) and cached:
        return cached
    facts: list[DirectStackUpdateFact8616] = []
    for block in _direct_global_update_blocks_8616(project, function):
        insns = _capstone_insns_for_direct_global_update_8616(project, block)
        for index, wrapper in enumerate(insns):
            insn = getattr(wrapper, "insn", wrapper)
            fact = _stack_update_fact_at_8616(insns, index, insn)
            if fact is not None:
                facts.append(fact)
    result = tuple(dict.fromkeys(facts))
    with contextlib.suppress(Exception):
        function._inertia_direct_stack_update_instruction_facts_8616 = result
    return result


def _filter_direct_stack_update_facts_for_active_function_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    facts: object,
) -> object:
    """Filter broad-slice stack update facts to the active focused function."""
    active_addr: object
    function_addr: object
    original_delta: object
    # Dynamic project boundary: direct PROC fallback can decompile a broad
    # synthetic slice while accepting one focused function from that slice.
    active_addr = getattr(project, "_inertia_tv_active_function_addr", None)
    function_addr = getattr(function, "addr", None)
    if not isinstance(active_addr, int) or not isinstance(function_addr, int) or operator.eq(function_addr, active_addr):
        return facts
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int) and operator.eq(function_addr + original_delta, active_addr):
        return facts
    if function_addr > active_addr:
        return facts
    return tuple(fact for fact in iter(facts) if fact.ins_addr >= active_addr)


@cython.ccall
def _previous_incdec_stack_update_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
    width: cython.longlong,
    update_operands: StructuredAstValue,
    update_id: StructuredAstValue,
) -> object:
    """Recover the loaded-slot offset carried through a register INC/DEC."""
    loaded: object
    if len(update_operands) != 1:
        return None
    target = update_operands[0]
    if operator.ne(getattr(target, "type", None), X86_OP_REG) or operator.ne(getattr(target, "reg", None), reg_id):
        return None
    loaded = _previous_stack_load_for_register_8616(insns, index - 1, reg_id)
    if loaded is None:
        return None
    source_offset, source_width = loaded
    if source_width != width:
        return None
    return source_offset, 1 if update_id == X86_INS_INC else -1


@cython.ccall
def _previous_register_stack_update_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
    width: cython.longlong,
) -> object:
    """Recover stack-slot arithmetic carried through a register before a store."""
    loaded: object
    update: object
    update_id: object
    value: object
    if index < 2 or width not in {1, 2}:
        return None
    update = getattr(insns[index - 1], "insn", insns[index - 1])
    update_operands = _boundary_tuple_8616(getattr(update, "operands", ()) or ())
    update_id = getattr(update, "id", None)
    if update_id in {X86_INS_INC, X86_INS_DEC}:
        return _previous_incdec_stack_update_8616(insns, index, reg_id, width, update_operands, update_id)
    if update_id not in {X86_INS_ADD, X86_INS_SUB} or len(update_operands) != 2:
        return None
    target, source = update_operands
    if operator.ne(getattr(target, "type", None), X86_OP_REG) or operator.ne(getattr(target, "reg", None), reg_id):
        return None
    if operator.ne(getattr(source, "type", None), X86_OP_IMM):
        return None
    value = getattr(source, "imm", None)
    if not isinstance(value, int):
        return None
    loaded = _previous_stack_load_for_register_8616(insns, index - 1, reg_id)
    if loaded is None:
        return None
    source_offset, source_width = loaded
    if source_width != width:
        return None
    delta = abs(int(value))
    if operator.eq(update_id, X86_INS_SUB):
        delta = -delta
    return source_offset, delta


@cython.ccall
def _stack_mem_operand_offset_width_8616(operand: StructuredAstValue) -> object:
    base: object
    index: object
    mem: object
    width: object
    width = getattr(operand, "size", None)
    if operator.ne(getattr(operand, "type", None), X86_OP_MEM) or width not in {1, 2}:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    base = getattr(mem, "base", X86_REG_INVALID)
    index = getattr(mem, "index", X86_REG_INVALID)
    if operator.ne(base, X86_REG_BP) or index not in {0, X86_REG_INVALID}:
        return None
    offset = _canonical_stack_offset_8616(getattr(mem, "disp", None))
    if not isinstance(offset, int):
        return None
    return offset, int(width)


def _direct_stack_write_inventory_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
) -> DirectStackWriteInventory8616:
    """Inventory exact decoded instructions and their explicit BP writes."""
    access: object
    ins_addr: object
    insn: object
    slot: object
    operand: object
    wrapper: object
    wrappers = _dedup_sorted_capstone_insns_by_addr_8616(
        wrapper
        for block in builtins.iter(_direct_global_update_blocks_8616(project, function))
        for wrapper in builtins.iter(_capstone_insns_for_direct_global_update_8616(project, block))
    )
    decoded_instruction_addrs: set[cython.longlong] = set()
    write_sites: list[DirectStackWriteSite8616] = []
    unknown_write_sites: list[DirectStackWriteSite8616] = []
    classified = 0
    for wrapper in wrappers:
        insn = getattr(wrapper, "insn", wrapper)
        ins_addr = getattr(insn, "address", None)
        if not isinstance(ins_addr, int):
            continue
        decoded_instruction_addrs.add(ins_addr)
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        for operand in operands:
            slot = _stack_mem_operand_offset_width_8616(operand)
            if slot is None:
                continue
            classified += 1
            dst_offset, width = slot
            site = DirectStackWriteSite8616(dst_offset, width, ins_addr)
            access = getattr(operand, "access", 0)
            if isinstance(access, int) and access & CS_AC_WRITE:
                write_sites.append(site)
            else:
                unknown_write_sites.append(site)
    normalized_write_sites = tuple(
        sorted(
            tuple(set(write_sites)),
            key=lambda site: (site.ins_addr, site.dst_offset, site.width),
        )
    )
    normalized_unknown_sites = tuple(
        sorted(
            tuple(set(unknown_write_sites)),
            key=lambda site: (site.ins_addr, site.dst_offset, site.width),
        )
    )
    return DirectStackWriteInventory8616(
        decoded_instruction_addrs=frozenset(decoded_instruction_addrs),
        write_sites=normalized_write_sites,
        unknown_write_sites=normalized_unknown_sites,
        raw_fact_count=len(wrappers),
        normalized_fact_count=len(decoded_instruction_addrs),
        classified_fact_count=classified,
        materialized_count=len(normalized_write_sites),
        failure_count=len(normalized_unknown_sites),
    )


@cython.ccall
def _indexed_stack_mem_operand_8616(
    operand: StructuredAstValue,
) -> object:
    """Return an exact BP+index stack destination from a Capstone operand."""
    index: object
    mem: object
    width: object
    width = getattr(operand, "size", None)
    if operator.ne(getattr(operand, "type", None), X86_OP_MEM) or width not in {1, 2}:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None or operator.ne(getattr(mem, "base", X86_REG_INVALID), X86_REG_BP):
        return None
    index = getattr(mem, "index", X86_REG_INVALID)
    scale = int(getattr(mem, "scale", 1) or 1)
    if not isinstance(index, int) or index in {0, X86_REG_INVALID} or scale != 1:
        return None
    offset = _canonical_stack_offset_8616(getattr(mem, "disp", None))
    if not isinstance(offset, int):
        return None
    return offset, int(width), index, scale


@cython.ccall
def _index_mem_source_kind_8616(src: StructuredAstValue) -> object:
    """Classify a MOV memory source as a BP-stack or bare-global load."""
    base: object
    mem: object
    if operator.ne(getattr(src, "type", None), X86_OP_MEM) or int(getattr(src, "size", 0) or 0) != 2:
        return None
    mem = getattr(src, "mem", None)
    if mem is None or getattr(mem, "index", X86_REG_INVALID) not in {0, X86_REG_INVALID}:
        return None
    displacement = _canonical_stack_offset_8616(getattr(mem, "disp", None))
    if not isinstance(displacement, int):
        return None
    base = getattr(mem, "base", X86_REG_INVALID)
    if operator.eq(base, X86_REG_BP):
        return "stack", displacement
    if base in {0, X86_REG_INVALID}:
        return "global", displacement & 0xFFFF
    return None


@cython.ccall
def _immediate_predecessor_index_source_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong
) -> object:
    """Classify an index register from the immediately preceding MOV only."""
    previous: object
    value: object
    if index <= 0:
        return None
    previous = getattr(insns[index - 1], "insn", insns[index - 1])
    if operator.ne(getattr(previous, "id", None), X86_INS_MOV):
        return None
    operands = _boundary_tuple_8616(getattr(previous, "operands", ()) or ())
    if len(operands) != 2:
        return None
    dst, src = operands
    if operator.ne(getattr(dst, "type", None), X86_OP_REG) or operator.ne(getattr(dst, "reg", None), reg_id):
        return None
    if operator.eq(getattr(src, "type", None), X86_OP_IMM):
        value = getattr(src, "imm", None)
        return ("immediate", int(value)) if isinstance(value, int) else None
    return _index_mem_source_kind_8616(src)


_DIRECT_STACK_MOVE_REGISTER_NAMES_8616 = {
    X86_REG_AL: "al",
    X86_REG_AX: "ax",
    X86_REG_BX: "bx",
    X86_REG_CX: "cx",
    X86_REG_DH: "dh",
    X86_REG_DL: "dl",
    X86_REG_DX: "dx",
    X86_REG_SI: "si",
    X86_REG_DI: "di",
    X86_REG_BP: "bp",
    X86_REG_SP: "sp",
    X86_REG_DS: "ds",
    X86_REG_ES: "es",
    X86_REG_SS: "ss",
}


@cython.ccall
def _direct_stack_move_register_name_8616(insn: StructuredAstValue, reg_id: int | None) -> object:
    if not isinstance(reg_id, int) or reg_id == X86_REG_INVALID:
        return None
    with contextlib.suppress(Exception):
        name = insn.reg_name(reg_id)
        if isinstance(name, str) and name:
            return name.lower()
    return _DIRECT_STACK_MOVE_REGISTER_NAMES_8616.get(int(reg_id))


@cython.ccall
def _direct_stack_move_segment_name_8616(insn: StructuredAstValue, reg_id: int | None) -> object:
    if not isinstance(reg_id, int) or reg_id in {0, X86_REG_INVALID}:
        return "ds"
    name = _direct_stack_move_register_name_8616(insn, reg_id)
    if name in {"ds", "es", "ss"}:
        return name
    return None


@cython.ccall
def proven_wide_stack_pair_low_offset_8616(high_expr: object, low_expr: object) -> int | None:
    """Return the low stack offset only when widening proves one logical pair."""
    if not isinstance(high_expr, structured_c.CVariable) or not isinstance(low_expr, structured_c.CVariable):
        return None
    high_variable = high_expr.variable
    low_variable = low_expr.variable
    if not isinstance(high_variable, SimStackVariable) or not isinstance(low_variable, SimStackVariable):
        return None
    low_offset = low_variable.offset
    if not isinstance(low_offset, int):
        return None
    proof = prove_adjacent_storage_slices(low_expr, high_expr)
    return low_offset if proof.ok else None


@cython.ccall
def _direct_stack_move_forget_register_8616(
    reg_state: object,
    reg_name: object,
) -> None:
    if not isinstance(reg_name, str) or not reg_name:
        return
    reg_state.pop(reg_name, None)
    if reg_name == "al":
        reg_state.pop("ax", None)
        reg_state.pop("eax", None)
    elif reg_name in {"ax", "eax"}:
        reg_state.pop("al", None)


@cython.dataclasses.dataclass
class _SegmentedRegTrace8616:
    """Replay one block's register provenance for segmented-memory sources."""

    insns: object
    index: cython.longlong
    reg_id: cython.longlong
    reg_state: object = field(default_factory=dict)
    target_reg_name: object = None

    @cython.ccall
    def _mov_mem_base_value_8616(
        self, insn: StructuredAstValue, src: StructuredAstValue, dst_name: object
    ) -> object:
        """Resolve the index offset/shift proven by the memory base register."""
        base_name: object
        base_value: object
        mem: object
        mem = getattr(src, "mem", None)
        if mem is None:
            return None
        base_name = _direct_stack_move_register_name_8616(insn, getattr(mem, "base", None))
        if base_name is None:
            return None
        base_value = self.reg_state.get(base_name)
        if base_value is None:
            return None
        if base_value.kind is DirectStackRegisterValueKind8616.STACK_SLOT:
            return base_value.stack_offset, 0
        if (
            base_value.kind is DirectStackRegisterValueKind8616.STACK_SLOT_EXPR
            and base_value.source_op is DirectStackMoveExpressionOp8616.SHL
        ):
            if base_value.source_immediate is None:
                return None
            return base_value.stack_offset, base_value.source_immediate
        return None

    @cython.ccall
    def _mov_mem_src_8616(
        self, insn: StructuredAstValue, dst: StructuredAstValue, src: StructuredAstValue, dst_name: object
    ) -> None:
        """Track a memory load into a register: stack slot or segmented access."""
        access_width: object
        base_ref: object
        displacement: object
        mem: object
        segment_name: object
        stack_slot: object
        stack_slot = _stack_mem_operand_offset_width_8616(src)
        if stack_slot is not None:
            source_offset, source_width = stack_slot
            self.reg_state[dst_name] = DirectStackRegisterValue8616(
                DirectStackRegisterValueKind8616.STACK_SLOT,
                stack_offset=source_offset,
                width=source_width,
            )
            return
        base_ref = self._mov_mem_base_value_8616(insn, src, dst_name)
        if base_ref is None:
            _direct_stack_move_forget_register_8616(self.reg_state, dst_name)
            return
        index_offset, index_shift = base_ref
        mem = getattr(src, "mem", None)
        segment_name = _direct_stack_move_segment_name_8616(insn, getattr(mem, "segment", None))
        displacement = getattr(mem, "disp", None)
        access_width = getattr(src, "size", None)
        if (
            segment_name is None
            or not isinstance(displacement, int)
            or not isinstance(index_offset, int)
            or not isinstance(index_shift, int)
            or access_width not in {1, 2}
        ):
            _direct_stack_move_forget_register_8616(self.reg_state, dst_name)
            return
        self.reg_state[dst_name] = DirectStackRegisterValue8616(
            DirectStackRegisterValueKind8616.SEGMENTED_MEMORY,
            width=int(getattr(dst, "size", 0) or access_width),
            segment_name=segment_name,
            displacement=int(displacement),
            index_stack_offset=int(index_offset),
            index_shift=int(index_shift),
            access_width=int(access_width),
        )

    @cython.ccall
    def _mov_insn_8616(self, pos: cython.longlong, insn: StructuredAstValue, operands: StructuredAstValue) -> cython.bint:
        """Track one MOV's register destination; False when not a reg-dst MOV."""
        dst_name: object
        src_name: object
        src_value: object
        if operator.ne(getattr(insn, "id", None), X86_INS_MOV) or len(operands) != 2:
            return False
        dst, src = operands
        if operator.ne(getattr(dst, "type", None), X86_OP_REG):
            return True
        dst_name = _direct_stack_move_register_name_8616(insn, getattr(dst, "reg", None))
        if dst_name is None:
            return True
        if operator.eq(pos, self.index - 1) and operator.eq(getattr(dst, "reg", None), self.reg_id):
            self.target_reg_name = dst_name
        if operator.eq(getattr(src, "type", None), X86_OP_MEM):
            self._mov_mem_src_8616(insn, dst, src, dst_name)
            return True
        if operator.eq(getattr(src, "type", None), X86_OP_REG):
            src_name = _direct_stack_move_register_name_8616(insn, getattr(src, "reg", None))
            if src_name is None:
                _direct_stack_move_forget_register_8616(self.reg_state, dst_name)
                return True
            src_value = self.reg_state.get(src_name)
            if src_value is not None:
                self.reg_state[dst_name] = src_value
            else:
                _direct_stack_move_forget_register_8616(self.reg_state, dst_name)
            return True
        _direct_stack_move_forget_register_8616(self.reg_state, dst_name)
        return True

    @cython.ccall
    def _shift_insn_8616(self, insn: StructuredAstValue, operands: StructuredAstValue) -> cython.bint:
        """Track a SHL/SAL applied to a stack-slot-proven register."""
        immediate: object
        previous: object
        reg_name: object
        if getattr(insn, "id", None) not in {X86_INS_SHL, X86_INS_SAL} or len(operands) != 2:
            return False
        dst, amount = operands
        if operator.ne(getattr(dst, "type", None), X86_OP_REG) or operator.ne(getattr(amount, "type", None), X86_OP_IMM):
            return True
        reg_name = _direct_stack_move_register_name_8616(insn, getattr(dst, "reg", None))
        if reg_name is None:
            return True
        immediate = getattr(amount, "imm", None)
        previous = self.reg_state.get(reg_name)
        if (
            previous is not None
            and previous.kind is DirectStackRegisterValueKind8616.STACK_SLOT
            and isinstance(immediate, int)
            and immediate >= 0
        ):
            self.reg_state[reg_name] = DirectStackRegisterValue8616(
                DirectStackRegisterValueKind8616.STACK_SLOT_EXPR,
                stack_offset=previous.stack_offset,
                width=previous.width,
                source_op=DirectStackMoveExpressionOp8616.SHL,
                source_immediate=int(immediate),
            )
        else:
            _direct_stack_move_forget_register_8616(self.reg_state, reg_name)
        return True

    @cython.ccall
    def _cbw_insn_8616(self, insn: StructuredAstValue) -> cython.bint:
        """Promote a segmented al value through CBW/CWDE sign extension."""
        al_value: object
        if getattr(insn, "id", None) not in {X86_INS_CBW, X86_INS_CWDE}:
            return False
        al_value = self.reg_state.get("al")
        if al_value is not None and al_value.kind is DirectStackRegisterValueKind8616.SEGMENTED_MEMORY:
            promoted = DirectStackRegisterValue8616(
                DirectStackRegisterValueKind8616.SEGMENTED_MEMORY,
                width=2,
                segment_name=al_value.segment_name,
                displacement=al_value.displacement,
                index_stack_offset=al_value.index_stack_offset,
                index_shift=al_value.index_shift,
                access_width=al_value.access_width,
                sign_extend=True,
            )
            self.reg_state["ax"] = promoted
            self.reg_state["eax"] = promoted
        else:
            self.reg_state.pop("ax", None)
            self.reg_state.pop("eax", None)
        return True

    @cython.ccall
    def scan_8616(self) -> DirectStackRegisterValue8616 | None:
        """Replay the block prefix and return the segmented source value."""
        insn: object
        last: object
        value: object
        for pos in range(self.index):
            insn = getattr(self.insns[pos], "insn", self.insns[pos])
            operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
            if self._mov_insn_8616(pos, insn, operands):
                continue
            if self._shift_insn_8616(insn, operands):
                continue
            if self._cbw_insn_8616(insn):
                continue
            if operands and operator.eq(getattr(operands[0], "type", None), X86_OP_REG):
                reg_name = _direct_stack_move_register_name_8616(insn, getattr(operands[0], "reg", None))
                _direct_stack_move_forget_register_8616(self.reg_state, reg_name)
        if self.target_reg_name is None:
            last = getattr(self.insns[self.index], "insn", self.insns[self.index])
            self.target_reg_name = _direct_stack_move_register_name_8616(last, self.reg_id)
        if self.target_reg_name is None:
            return None
        value = self.reg_state.get(self.target_reg_name)
        if value is None or value.kind is not DirectStackRegisterValueKind8616.SEGMENTED_MEMORY:
            return None
        return value


@cython.ccall
def _direct_stack_move_segmented_source_for_register_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
) -> DirectStackRegisterValue8616 | None:
    """Recover a register value proven by prior instructions in the same block.

    This deliberately tracks a narrow set of pure register transfers used by
    MS C real-mode code:
    stack slot -> index register -> shifted index -> DS/ES/SS memory byte/word
    load -> optional sign extension -> BP-relative stack store.
    Unknown writes erase provenance instead of guessing.
    """
    if index <= 0:
        return None
    return _SegmentedRegTrace8616(insns=insns, index=index, reg_id=reg_id).scan_8616()


@cython.ccall
def _direct_global_mem_operand_offset_width_8616(operand: StructuredAstValue) -> object:
    """Return global displacement/width for a direct memory operand."""
    base: object
    displacement: object
    index: object
    mem: object
    width: object
    if operator.ne(getattr(operand, "type", None), X86_OP_MEM):
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    base = getattr(mem, "base", X86_REG_INVALID)
    index = getattr(mem, "index", X86_REG_INVALID)
    displacement = getattr(mem, "disp", None)
    width = getattr(operand, "size", None)
    if base not in {0, X86_REG_INVALID} or index not in {0, X86_REG_INVALID}:
        return None
    if not isinstance(displacement, int) or width not in {1, 2, 4}:
        return None
    return displacement & 0xFFFF, int(width)


@cython.ccall
def _neg_sub_ax_global_displacement_8616(
    neg_insn: StructuredAstValue, sub_insn: StructuredAstValue
) -> int | None:
    """Return the global displacement for a ``sub ax, [global]; neg ax`` pair."""
    global_slot: object
    if operator.ne(getattr(neg_insn, "id", None), X86_INS_NEG):
        return None
    neg_operands = _boundary_tuple_8616(getattr(neg_insn, "operands", ()) or ())
    if len(neg_operands) != 1 or _direct_stack_move_register_name_8616(
        neg_insn, getattr(neg_operands[0], "reg", None)
    ) not in {"ax", "eax"}:
        return None
    if operator.ne(getattr(sub_insn, "id", None), X86_INS_SUB):
        return None
    sub_operands = _boundary_tuple_8616(getattr(sub_insn, "operands", ()) or ())
    if len(sub_operands) != 2:
        return None
    if _direct_stack_move_register_name_8616(sub_insn, getattr(sub_operands[0], "reg", None)) not in {"ax", "eax"}:
        return None
    global_slot = _direct_global_mem_operand_offset_width_8616(sub_operands[1])
    if global_slot is None:
        return None
    global_displacement, global_width = global_slot
    return global_displacement if global_width == 2 else None


@cython.ccall
def _previous_global_minus_segmented_source_for_register_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
) -> object:
    """Recover AX = global - signext(indexed byte global) before a BP store."""
    cbw_insn: object
    global_displacement: object
    neg_insn: object
    segmented_source: object
    store: object
    sub_insn: object
    if index < 4:
        return None
    store = getattr(insns[index], "insn", insns[index])
    target_reg_name = _direct_stack_move_register_name_8616(store, reg_id)
    if target_reg_name not in {"ax", "eax"}:
        return None

    neg_insn = getattr(insns[index - 1], "insn", insns[index - 1])
    sub_insn = getattr(insns[index - 2], "insn", insns[index - 2])
    cbw_insn = getattr(insns[index - 3], "insn", insns[index - 3])
    global_displacement = _neg_sub_ax_global_displacement_8616(neg_insn, sub_insn)
    if global_displacement is None:
        return None
    if getattr(cbw_insn, "id", None) not in {X86_INS_CBW, X86_INS_CWDE}:
        return None

    segmented_source = _direct_stack_move_segmented_source_for_register_8616(insns, index - 2, reg_id)
    if segmented_source is None or segmented_source.access_width != 1:
        return None
    return global_displacement, segmented_source


@cython.ccall
def _previous_stack_load_for_register_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong
) -> object:
    prev: object
    if index <= 0:
        return None
    prev = getattr(insns[index - 1], "insn", insns[index - 1])
    if operator.ne(getattr(prev, "id", None), X86_INS_MOV):
        return None
    operands = _boundary_tuple_8616(getattr(prev, "operands", ()) or ())
    if len(operands) != 2:
        return None
    dst, src = operands
    if operator.ne(getattr(dst, "type", None), X86_OP_REG) or operator.ne(getattr(dst, "reg", None), reg_id):
        return None
    return _stack_mem_operand_offset_width_8616(src)


@cython.ccall
def _previous_register_immediate_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong
) -> int | None:
    """Return an immediate moved into ``reg_id`` immediately before ``index``."""
    previous: object
    if index <= 0:
        return None
    previous = getattr(insns[index - 1], "insn", insns[index - 1])
    if operator.ne(getattr(previous, "id", None), X86_INS_MOV):
        return None
    operands = _boundary_tuple_8616(getattr(previous, "operands", ()) or ())
    if len(operands) != 2:
        return None
    destination, source = operands
    if operator.ne(getattr(destination, "type", None), X86_OP_REG) or operator.ne(getattr(destination, "reg", None), reg_id):
        return None
    immediate = getattr(source, "imm", None) if operator.eq(getattr(source, "type", None), X86_OP_IMM) else None
    return int(immediate) if isinstance(immediate, int) else None


@cython.ccall
def _previous_binary_stack_expr_for_register_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
    width: cython.longlong,
) -> object:
    """Recover a directly preceding stack-load plus stack arithmetic value."""
    arithmetic: object
    arithmetic_id: object
    lhs_slot: object
    rhs_slot: object
    if index < 2:
        return None
    arithmetic = getattr(insns[index - 1], "insn", insns[index - 1])
    arithmetic_id = getattr(arithmetic, "id", None)
    if arithmetic_id not in {X86_INS_ADD, X86_INS_SUB}:
        return None
    arithmetic_operands = _boundary_tuple_8616(getattr(arithmetic, "operands", ()) or ())
    if len(arithmetic_operands) != 2 or not _register_operand_is_8616(arithmetic_operands[0], reg_id):
        return None
    rhs_slot = _stack_mem_operand_offset_width_8616(arithmetic_operands[1])
    lhs_slot = _previous_stack_load_for_register_8616(insns, index - 1, reg_id)
    if lhs_slot is None or rhs_slot is None:
        return None
    lhs_offset, lhs_width = lhs_slot
    rhs_offset, rhs_width = rhs_slot
    if lhs_width != width or rhs_width != width:
        return None
    operation = (
        DirectStackMoveExpressionOp8616.ADD
        if operator.eq(arithmetic_id, X86_INS_ADD)
        else DirectStackMoveExpressionOp8616.SUB
    )
    return lhs_offset, rhs_offset, operation


@cython.ccall
def _previous_signed_byte_stack_load_for_register_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong, width: cython.longlong
) -> object:
    load: object
    loaded: object
    sign_extend: object
    if reg_id != X86_REG_AX or width != 2 or index <= 1:
        return None
    sign_extend = getattr(insns[index - 1], "insn", insns[index - 1])
    if getattr(sign_extend, "id", None) not in {X86_INS_CBW, X86_INS_CWDE}:
        return None
    load = getattr(insns[index - 2], "insn", insns[index - 2])
    if operator.ne(getattr(load, "id", None), X86_INS_MOV):
        return None
    operands = _boundary_tuple_8616(getattr(load, "operands", ()) or ())
    if len(operands) != 2:
        return None
    dst, src = operands
    if not _register_operand_is_8616(dst, X86_REG_AL):
        return None
    loaded = _stack_mem_operand_offset_width_8616(src)
    if loaded is None:
        return None
    source_offset, source_width = loaded
    if source_width != 1:
        return None
    return source_offset, source_width


@cython.ccall
def _previous_stack_index_for_register_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
) -> DirectStackIndexFact8616 | None:
    """Recover a stack-backed logical index and its proven byte scale."""
    insn: object
    insn_id: object
    loaded: object
    previous_loaded: object
    cursor = index - 1
    while cursor >= 0:
        insn = getattr(insns[cursor], "insn", insns[cursor])
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if not operands:
            cursor -= 1
            continue
        dst = operands[0]
        if operator.ne(getattr(dst, "type", None), X86_OP_REG) or operator.ne(getattr(dst, "reg", None), reg_id):
            cursor -= 1
            continue
        insn_id = getattr(insn, "id", None)
        if operator.eq(insn_id, X86_INS_MOV) and len(operands) == 2:
            loaded = _stack_mem_operand_offset_width_8616(operands[1])
            if loaded is None:
                return None
            offset, width = loaded
            return DirectStackIndexFact8616(offset, width, 1)
        if insn_id in {X86_INS_SAL, X86_INS_SHL} and len(operands) == 2:
            amount = operands[1]
            if operator.ne(getattr(amount, "type", None), X86_OP_IMM) or getattr(amount, "imm", None) != 1:
                return None
            previous_loaded = _previous_stack_index_for_register_8616(insns, cursor, reg_id)
            if previous_loaded is None:
                return None
            return replace(previous_loaded, byte_scale=previous_loaded.byte_scale * 2)
        return None
    return None


@cython.ccall
def _previous_indexed_stack_load_for_register_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
) -> DirectStackIndexedLoadFact8616 | None:
    """Recover the nearest unmodified register load from a BP-indexed stack object."""
    index_fact: object
    indexed_load: object
    insn: object
    cursor = index - 1
    while cursor >= 0:
        insn = getattr(insns[cursor], "insn", insns[cursor])
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if not operands or not _register_operand_is_8616(operands[0], reg_id):
            cursor -= 1
            continue
        if operator.ne(getattr(insn, "id", None), X86_INS_MOV) or len(operands) != 2:
            return None
        indexed_load = _indexed_stack_mem_operand_8616(operands[1])
        if indexed_load is None:
            return None
        base_offset, access_width, index_reg, memory_scale = indexed_load
        index_fact = _previous_stack_index_for_register_8616(insns, cursor, index_reg)
        if index_fact is None:
            return None
        return DirectStackIndexedLoadFact8616(
            base_offset=base_offset,
            access_width=access_width,
            index=replace(
                index_fact,
                byte_scale=index_fact.byte_scale * memory_scale,
            ),
        )
    return None


@cython.ccall
def _signed_halving_insns_match_8616(
    sign_extend: StructuredAstValue, subtract: StructuredAstValue, shift: StructuredAstValue
) -> cython.bint:
    """Check the ``cwd; sub ax,dx; sar ax,1`` signed-halving idiom."""
    if getattr(sign_extend, "id", None) not in {X86_INS_CWD, X86_INS_CDQ}:
        return False
    if operator.ne(getattr(subtract, "id", None), X86_INS_SUB):
        return False
    sub_operands = _boundary_tuple_8616(getattr(subtract, "operands", ()) or ())
    if len(sub_operands) != 2:
        return False
    if not _register_operand_is_8616(sub_operands[0], X86_REG_AX):
        return False
    if not _register_operand_is_8616(sub_operands[1], X86_REG_DX):
        return False
    if operator.ne(getattr(shift, "id", None), X86_INS_SAR):
        return False
    shift_operands = _boundary_tuple_8616(getattr(shift, "operands", ()) or ())
    if len(shift_operands) != 2:
        return False
    dst, amount = shift_operands
    if not _register_operand_is_8616(dst, X86_REG_AX):
        return False
    return operator.eq(getattr(amount, "type", None), X86_OP_IMM) and getattr(amount, "imm", None) == 1


def _indexed_mem_base_index_regs_8616(src: StructuredAstValue) -> object:
    """Return (base, index) register ids for a disp-less ``[base+index]`` operand."""
    mem: object
    mem = getattr(src, "mem", None)
    if mem is None:
        return None
    regs = _boundary_tuple_8616(
        reg
        for reg in iter((getattr(mem, "base", X86_REG_INVALID), getattr(mem, "index", X86_REG_INVALID)))
        if isinstance(reg, int) and reg not in {0, X86_REG_INVALID}
    )
    if len(regs) != 2 or getattr(mem, "disp", 0) not in {0, None}:
        return None
    return regs


@cython.ccall
def _mov_cx_immediate_8616(insn: StructuredAstValue) -> int | None:
    """Return the nonzero immediate loaded into CX, or None."""
    imm: object
    if operator.ne(getattr(insn, "id", None), X86_INS_MOV):
        return None
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or not _register_operand_is_8616(operands[0], X86_REG_CX):
        return None
    if operator.ne(getattr(operands[1], "type", None), X86_OP_IMM):
        return None
    imm = getattr(operands[1], "imm", None)
    return imm if isinstance(imm, int) and imm != 0 else None


@cython.ccall
def _mov_ax_stack_source_8616(insn: StructuredAstValue, width: cython.longlong) -> int | None:
    """Return the BP stack source offset for ``mov ax, [bp+off]``, or None."""
    source: object
    if operator.ne(getattr(insn, "id", None), X86_INS_MOV):
        return None
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or not _register_operand_is_8616(operands[0], X86_REG_AX):
        return None
    source = _stack_mem_operand_offset_width_8616(operands[1])
    if source is None:
        return None
    source_offset, source_width = source
    return source_offset if source_width == width else None


@cython.ccall
def _indexed_pointer_reg_facts_8616(
    insns: object, index: cython.longlong, regs: StructuredAstValue
) -> object:
    """Resolve stack-index facts for both [base+index] registers."""
    fact: object
    mem_reg: object
    reg_facts: list[tuple[cython.longlong, cython.longlong, cython.longlong, cython.longlong]] = []
    for mem_reg in regs:
        fact = _previous_stack_index_for_register_8616(insns, index - 1, mem_reg)
        if fact is None:
            return None
        reg_facts.append((mem_reg, fact.stack_offset, fact.width, fact.byte_scale))
    return reg_facts


@cython.ccall
def _previous_indexed_pointer_load_for_register_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
) -> object:
    access_width: object
    prev: object
    reg_facts: object
    regs: object
    if index <= 0:
        return None
    prev = getattr(insns[index - 1], "insn", insns[index - 1])
    if operator.ne(getattr(prev, "id", None), X86_INS_MOV):
        return None
    operands = _boundary_tuple_8616(getattr(prev, "operands", ()) or ())
    if len(operands) != 2:
        return None
    dst, src = operands
    if operator.ne(getattr(dst, "type", None), X86_OP_REG) or operator.ne(getattr(dst, "reg", None), reg_id):
        return None
    if operator.ne(getattr(src, "type", None), X86_OP_MEM):
        return None
    access_width = getattr(src, "size", None)
    if access_width not in {1, 2}:
        return None
    regs = _indexed_mem_base_index_regs_8616(src)
    if regs is None:
        return None
    reg_facts = _indexed_pointer_reg_facts_8616(insns, index, regs)
    if reg_facts is None:
        return None
    pointer_candidates = [item for item in iter(reg_facts) if item[1] > 0 and item[3] == 1]
    index_candidates = [item for item in iter(reg_facts) if item[1] < 0 and operator.eq(item[3], access_width)]
    if len(pointer_candidates) != 1 or len(index_candidates) != 1:
        return None
    _ptr_reg, pointer_offset, _pointer_width, _pointer_scale = pointer_candidates[0]
    _idx_reg, index_offset, _index_width, index_scale = index_candidates[0]
    return pointer_offset, index_offset, int(index_scale), int(access_width)


@cython.ccall
def _previous_shifted_stack_load_for_register_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong, width: cython.longlong
) -> object:
    immediate: object
    shift: object
    source: object
    if index <= 1:
        return None
    shift = getattr(insns[index - 1], "insn", insns[index - 1])
    if getattr(shift, "id", None) not in {X86_INS_SAL, X86_INS_SHL}:
        return None
    operands = _boundary_tuple_8616(getattr(shift, "operands", ()) or ())
    if len(operands) != 2:
        return None
    dst, amount = operands
    if operator.ne(getattr(dst, "type", None), X86_OP_REG) or operator.ne(getattr(dst, "reg", None), reg_id):
        return None
    if operator.ne(getattr(amount, "type", None), X86_OP_IMM):
        return None
    immediate = getattr(amount, "imm", None)
    if not isinstance(immediate, int) or immediate < 0 or immediate >= width * 8:
        return None
    source = _previous_stack_load_for_register_8616(insns, index - 1, reg_id)
    if source is None:
        return None
    source_offset, source_width = source
    if source_width != width:
        return None
    return source_offset, immediate, DirectStackMoveExpressionOp8616.SHL


@cython.ccall
def _previous_signed_half_stack_load_for_register_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong, width: cython.longlong
) -> object:
    """Recover MS C signed /2 lowering feeding a direct stack store.

    MS C emits signed division by two as:
    ``mov ax, [bp+off]; cwd/cdq; sub ax, dx; sar ax, 1; mov [bp+dst], ax``.
    The store is a semantic stack-slot assignment and must be materialized
    before later uses of the destination local.
    """
    source: object
    if reg_id != X86_REG_AX or width != 2 or index <= 3:
        return None
    if not _signed_halving_insns_match_8616(
        getattr(insns[index - 3], "insn", insns[index - 3]),
        getattr(insns[index - 2], "insn", insns[index - 2]),
        getattr(insns[index - 1], "insn", insns[index - 1]),
    ):
        return None
    source = _previous_stack_load_for_register_8616(insns, index - 3, X86_REG_AX)
    if source is None:
        return None
    source_offset, source_width = source
    if source_width != width:
        return None
    return source_offset, 2, DirectStackMoveExpressionOp8616.SIGNED_DIV2


@cython.ccall
def _previous_stack_signed_idiv_const_for_register_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong, width: cython.longlong
) -> object:
    """Recover ``mov cx,K; mov ax,[bp+off]; cwd; idiv cx`` before a BP store."""
    const_load: object
    divide: object
    divisor: object
    sign_extend: object
    source_offset: object
    stack_load: object
    if reg_id != X86_REG_AX or width != 2 or index <= 3:
        return None
    const_load = getattr(insns[index - 4], "insn", insns[index - 4])
    stack_load = getattr(insns[index - 3], "insn", insns[index - 3])
    sign_extend = getattr(insns[index - 2], "insn", insns[index - 2])
    divide = getattr(insns[index - 1], "insn", insns[index - 1])
    divisor = _mov_cx_immediate_8616(const_load)
    if divisor is None:
        return None
    source_offset = _mov_ax_stack_source_8616(stack_load, width)
    if source_offset is None:
        return None
    if getattr(sign_extend, "id", None) not in {X86_INS_CWD, X86_INS_CDQ}:
        return None
    if operator.ne(getattr(divide, "id", None), X86_INS_IDIV):
        return None
    divide_operands = _boundary_tuple_8616(getattr(divide, "operands", ()) or ())
    if len(divide_operands) != 1 or not _register_operand_is_8616(divide_operands[0], X86_REG_CX):
        return None
    return source_offset, int(divisor), DirectStackMoveExpressionOp8616.SIGNED_DIV2


@cython.ccall
def _previous_global_signed_half_for_register_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong, width: cython.longlong
) -> object:
    """Recover ``mov ax, global; cwd; sub ax,dx; sar ax,1`` before a BP store."""
    global_slot: object
    load: object
    shift: object
    sign_extend: object
    subtract: object
    if reg_id != X86_REG_AX or width != 2 or index <= 3:
        return None
    load = getattr(insns[index - 4], "insn", insns[index - 4])
    sign_extend = getattr(insns[index - 3], "insn", insns[index - 3])
    subtract = getattr(insns[index - 2], "insn", insns[index - 2])
    shift = getattr(insns[index - 1], "insn", insns[index - 1])
    if operator.ne(getattr(load, "id", None), X86_INS_MOV):
        return None
    load_operands = _boundary_tuple_8616(getattr(load, "operands", ()) or ())
    if len(load_operands) != 2 or not _register_operand_is_8616(load_operands[0], X86_REG_AX):
        return None
    global_slot = _direct_global_mem_operand_offset_width_8616(load_operands[1])
    if global_slot is None:
        return None
    global_displacement, global_width = global_slot
    if global_width != width:
        return None
    if not _signed_halving_insns_match_8616(sign_extend, subtract, shift):
        return None
    return global_displacement, 2, DirectStackMoveExpressionOp8616.SIGNED_DIV2


@cython.ccall
def _previous_global_minus_stack_for_register_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong, width: cython.longlong
) -> object:
    """Recover ``mov ax, global; sub ax, [bp+off]`` before a BP store."""
    global_slot: object
    load: object
    source_slot: object
    subtract: object
    if reg_id != X86_REG_AX or width != 2 or index <= 1:
        return None
    subtract = getattr(insns[index - 1], "insn", insns[index - 1])
    load = getattr(insns[index - 2], "insn", insns[index - 2])
    if operator.ne(getattr(subtract, "id", None), X86_INS_SUB):
        return None
    sub_operands = _boundary_tuple_8616(getattr(subtract, "operands", ()) or ())
    if len(sub_operands) != 2 or not _register_operand_is_8616(sub_operands[0], X86_REG_AX):
        return None
    source_slot = _stack_mem_operand_offset_width_8616(sub_operands[1])
    if source_slot is None:
        return None
    source_offset, source_width = source_slot
    if source_width != width:
        return None
    if operator.ne(getattr(load, "id", None), X86_INS_MOV):
        return None
    load_operands = _boundary_tuple_8616(getattr(load, "operands", ()) or ())
    if len(load_operands) != 2 or not _register_operand_is_8616(load_operands[0], X86_REG_AX):
        return None
    global_slot = _direct_global_mem_operand_offset_width_8616(load_operands[1])
    if global_slot is None:
        return None
    global_displacement, global_width = global_slot
    if global_width != width:
        return None
    return global_displacement, source_offset


@cython.ccall
def _register_adjustment_before_8616(insn: StructuredAstValue, reg_id: cython.longlong) -> int | None:
    immediate: object
    insn_id: object
    insn_id = getattr(insn, "id", None)
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if operator.eq(insn_id, X86_INS_INC) and len(operands) == 1 and _register_operand_is_8616(operands[0], reg_id):
        return 1
    if operator.eq(insn_id, X86_INS_DEC) and len(operands) == 1 and _register_operand_is_8616(operands[0], reg_id):
        return -1
    if insn_id not in {X86_INS_ADD, X86_INS_SUB} or len(operands) != 2:
        return None
    if not _register_operand_is_8616(operands[0], reg_id):
        return None
    if operator.ne(getattr(operands[1], "type", None), X86_OP_IMM):
        return None
    immediate = getattr(operands[1], "imm", None)
    if not isinstance(immediate, int):
        return None
    return immediate if operator.eq(insn_id, X86_INS_ADD) else -immediate


@cython.ccall
def _previous_stack_load_with_adjust_for_register_8616(
    insns: object, index: cython.longlong, reg_id: cython.longlong, width: cython.longlong
) -> object:
    """Recover a stack load plus one adjustment across unrelated register setup."""
    adjusted: object
    adjustment: object
    direct: object
    insn: object
    insn_id: object
    if index <= 0:
        return None
    for cursor in range(index - 1, max(index - 9, -1), -1):
        insn = getattr(insns[cursor], "insn", insns[cursor])
        insn_id = getattr(insn, "id", None)
        if insn_id in {
            X86_INS_CALL,
            X86_INS_LCALL,
            X86_INS_IDIV,
            X86_INS_CBW,
            X86_INS_CWDE,
            X86_INS_CWD,
            X86_INS_CDQ,
        }:
            return None
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if not operands:
            continue
        if not _register_operand_is_8616(operands[0], reg_id):
            continue
        adjustment = _register_adjustment_before_8616(insn, reg_id)
        if adjustment is None:
            direct = _stack_mem_operand_offset_width_8616(operands[1]) if len(operands) == 2 else None
            if operator.ne(insn_id, X86_INS_MOV) or direct is None:
                return None
            source_offset, source_width = direct
            return (source_offset, 0, cursor) if source_width == width else None
        adjusted = _previous_stack_load_for_register_8616(insns, cursor, reg_id)
        if adjusted is None:
            return None
        source_offset, source_width = adjusted
        if source_width != width:
            return None
        return source_offset, adjustment, cursor - 1
    return None


@cython.ccall
def _previous_global_load_with_adjust_for_register_8616(
    insns: object,
    index: cython.longlong,
    reg_id: cython.longlong,
    width: cython.longlong,
) -> object:
    """Recover a direct global load with an optional register adjustment."""
    adjust_insn: object
    global_slot: object
    load_insn: object
    proven_adjustment: object
    if index <= 0:
        return None
    load_index = index - 1
    adjustment = 0
    if index > 1:
        adjust_insn = getattr(insns[index - 1], "insn", insns[index - 1])
        proven_adjustment = _register_adjustment_before_8616(adjust_insn, reg_id)
        if proven_adjustment is not None:
            adjustment = proven_adjustment
            load_index -= 1
    load_insn = getattr(insns[load_index], "insn", insns[load_index])
    operands = _boundary_tuple_8616(getattr(load_insn, "operands", ()) or ())
    if (
        operator.ne(getattr(load_insn, "id", None), X86_INS_MOV)
        or len(operands) != 2
        or not _register_operand_is_8616(operands[0], reg_id)
    ):
        return None
    global_slot = _direct_global_mem_operand_offset_width_8616(operands[1])
    if global_slot is None:
        return None
    displacement, source_width = global_slot
    return (displacement, adjustment) if source_width == width else None


@cython.ccall
def _register_operand_is_8616(operand: StructuredAstValue, reg_id: cython.longlong) -> cython.bint:
    return operator.eq(getattr(operand, "type", None), X86_OP_REG) and operator.eq(getattr(operand, "reg", None), reg_id)


@cython.ccall
def _direct_call_target_from_operand_8616(operand: StructuredAstValue) -> int | None:
    target: object
    if operator.ne(getattr(operand, "type", None), X86_OP_IMM):
        return None
    target = getattr(operand, "imm", None)
    return target if isinstance(target, int) else None


@cython.ccall
def _project_main_object_min_addr_8616(project: StructuredAstValue) -> int | None:
    loader: object
    main_object: object
    min_addr: object
    loader = getattr(project, "loader", None)
    main_object = getattr(loader, "main_object", None)
    min_addr = getattr(main_object, "min_addr", None)
    return int(min_addr) if isinstance(min_addr, int) else None


@cython.ccall
def _raw_call_target_candidates_8616(
    project: StructuredAstValue, target: cython.longlong
) -> object:
    """Build raw (project, address) candidates across coordinate spaces."""
    delta: object
    original_project: object
    candidate_project: object
    candidates: list[tuple[StructuredAstValue, cython.longlong]] = [(project, target)]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    original_project = getattr(project, "_inertia_original_project", None)
    projects: list[StructuredAstValue] = [project]
    if original_project is not None:
        projects.append(original_project)
        candidates.append((original_project, target))
        if isinstance(delta, int) and delta:
            candidates.append((original_project, target + delta))
            rebased = target - delta
            if rebased >= 0:
                candidates.append((project, rebased))
    if 0 <= target <= 0xFFFF:
        for candidate_project in projects:
            image_base = _project_main_object_min_addr_8616(candidate_project)
            if isinstance(image_base, int):
                candidates.append((candidate_project, image_base + target))
    return candidates


@cython.ccall
def _dedup_call_target_candidates_8616(
    candidates: object, include_padding_aliases: cython.bint
) -> tuple[tuple[StructuredAstValue, cython.longlong], ...]:
    """Canonicalize padding aliases and deduplicate by (project, address)."""
    candidate_project: object
    candidate_target: object
    canonicalized_candidates: list[tuple[StructuredAstValue, cython.longlong]] = []
    for candidate_project, candidate_target in candidates:
        if include_padding_aliases:
            canonical_target = canonicalize_x86_16_padding_call_target_8616(
                candidate_project,
                candidate_target,
            )
            if (
                isinstance(canonical_target, int)
                and canonical_target != candidate_target
            ):
                canonicalized_candidates.append((candidate_project, canonical_target))
        canonicalized_candidates.append((candidate_project, candidate_target))
    deduped: list[tuple[StructuredAstValue, cython.longlong]] = []
    seen: set[tuple[cython.longlong, cython.longlong]] = set()
    for candidate_project, candidate_target in canonicalized_candidates:
        key = (id(candidate_project), int(candidate_target))
        if key in seen:
            continue
        seen.add(key)
        deduped.append((candidate_project, int(candidate_target)))
    return tuple(deduped)


@cython.ccall
def _direct_stack_move_call_target_candidates_8616(
    project: StructuredAstValue,
    target: cython.longlong,
    *,
    include_padding_aliases: cython.bint = True,
) -> object:
    """Return coordinate-space candidates for a direct stack code offset."""
    candidates = _raw_call_target_candidates_8616(project, int(target))
    return _dedup_call_target_candidates_8616(candidates, include_padding_aliases)


@cython.ccall
def _normalize_direct_stack_function_name_8616(raw_name: object) -> object:
    if not isinstance(raw_name, str):
        return None
    stripped = raw_name.strip()
    if not stripped:
        return None
    normalized = normalize_callee_name_8616(stripped.lstrip("_"))
    return normalized or stripped.lstrip("_")


@cython.ccall
def _direct_stack_function_target_8616(
    project: AngrProjectValue,
    target: cython.longlong,
    *,
    include_padding_aliases: cython.bint = True,
) -> DirectStackFunctionTarget8616 | None:
    """Resolve a direct stack code offset to typed function identity evidence."""
    functions: object
    label: object
    labels: object
    synthetic: object
    synthetic_globals: object
    candidate_project: object
    candidate_target: object
    for candidate_project, candidate_target in _direct_stack_move_call_target_candidates_8616(
        project,
        target,
        include_padding_aliases=include_padding_aliases,
    ):
        synthetic_globals = getattr(candidate_project, "_inertia_synthetic_globals", None)
        if isinstance(synthetic_globals, dict):
            synthetic = synthetic_globals.get(int(candidate_target))
            if isinstance(synthetic, tuple) and synthetic:
                name = _normalize_direct_stack_function_name_8616(
                    synthetic[0] if isinstance(synthetic[0], str) else None
                )
                if name:
                    return DirectStackFunctionTarget8616(
                        name=name,
                        addr=int(candidate_target),
                        evidence=DirectStackFunctionTargetEvidence8616.SYNTHETIC_GLOBAL,
                    )

        for labels in (
            getattr(getattr(candidate_project, "kb", None), "labels", None),
            getattr(getattr(candidate_project, "_inertia_lst_metadata", None), "code_labels", None),
        ):
            if labels is None:
                continue
            label = None
            with contextlib.suppress(Exception):
                label = labels.get(int(candidate_target))
            name = _normalize_direct_stack_function_name_8616(label if isinstance(label, str) else None)
            if name:
                return DirectStackFunctionTarget8616(
                    name=name,
                    addr=int(candidate_target),
                    evidence=DirectStackFunctionTargetEvidence8616.LABEL,
                )

        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        callee = None
        if functions is not None:
            with contextlib.suppress(Exception):
                callee = functions.function(addr=int(candidate_target), create=False)
        name = _normalize_direct_stack_function_name_8616(getattr(callee, "name", None))
        if name:
            return DirectStackFunctionTarget8616(
                name=name,
                addr=int(candidate_target),
                evidence=DirectStackFunctionTargetEvidence8616.FUNCTION,
            )
    return None


@cython.ccall
def _callee_name_for_direct_stack_move_8616(
    project: AngrProjectValue, target: cython.longlong
) -> tuple[str, StructuredAstValue | None, cython.longlong]:
    functions: object
    label: object
    labels: object
    name: object
    resolved: object
    candidate_project: object
    candidate_target: object
    resolved = _direct_stack_function_target_8616(project, target)
    if resolved is not None:
        return resolved.name, None, resolved.addr
    for candidate_project, candidate_target in _direct_stack_move_call_target_candidates_8616(project, target):
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        callee = None
        if functions is not None:
            with contextlib.suppress(Exception):
                callee = functions.function(addr=int(candidate_target), create=False)
        name = getattr(callee, "name", None)
        if isinstance(name, str) and name:
            return name, callee, int(candidate_target)
        for labels in (
            getattr(getattr(candidate_project, "kb", None), "labels", None),
            getattr(getattr(candidate_project, "_inertia_lst_metadata", None), "code_labels", None),
        ):
            if labels is None:
                continue
            with contextlib.suppress(Exception):
                label = labels.get(int(candidate_target))
                if isinstance(label, str) and label.strip():
                    return label.lstrip("_"), callee, int(candidate_target)
    return f"sub_{int(target):x}", None, int(target)


@cython.ccall
def _is_stack_probe_helper_name_for_linear_lowering_8616(name: object) -> cython.bint:
    if not isinstance(name, str):
        return False
    lowered = name.strip().lower().lstrip("_")
    return lowered in {"anchkstk", "chkstk"}


@cython.ccall
def _callee_has_zero_args_8616(callee: StructuredAstValue, callee_name: object) -> cython.bint:
    """Return whether typed callee evidence proves an empty argument list."""
    args: object
    prototype: object
    prototype = getattr(callee, "prototype", None)
    args = getattr(prototype, "args", None)
    if isinstance(args, (list, tuple)):
        return len(args) == 0
    return callee_name.lstrip("_") in LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616


@cython.ccall
def _call_has_nearby_stack_arg_setup_8616(insns: object, call_index: cython.longlong) -> cython.bint:
    insn: object
    for scan_index in range(max(0, call_index - 8), call_index):
        insn = getattr(insns[scan_index], "insn", insns[scan_index])
        if operator.eq(getattr(insn, "id", None), X86_INS_PUSH):
            return True
    return False


@cython.ccall
def _direct_zero_arg_call_before_8616(
    project: AngrProjectValue, insns: object, index: cython.longlong
) -> StructuredAstValue:
    call_addr: object
    call_insn: object
    call_target: object
    if index <= 0:
        return None
    call_index = index - 1
    call_insn = getattr(insns[call_index], "insn", insns[call_index])
    if getattr(call_insn, "id", None) not in {X86_INS_CALL, X86_INS_LCALL}:
        return None
    call_operands = _boundary_tuple_8616(getattr(call_insn, "operands", ()) or ())
    if len(call_operands) != 1:
        return None
    call_target = _direct_call_target_from_operand_8616(call_operands[0])
    if call_target is None:
        return None
    callee_name, callee, resolved_call_target = _callee_name_for_direct_stack_move_8616(project, call_target)
    if not _callee_has_zero_args_8616(callee, callee_name) and _call_has_nearby_stack_arg_setup_8616(
        insns,
        call_index,
    ):
        return None
    call_addr = getattr(call_insn, "address", None)
    if not isinstance(call_addr, int):
        return None
    return callee_name, resolved_call_target, call_addr


@cython.ccall
def _dx_stack_store_offset_8616(store: StructuredAstValue) -> int | None:
    """Return the destination offset of a ``mov [bp+dst], dx`` store."""
    dst_slot: object
    store_operands = _boundary_tuple_8616(getattr(store, "operands", ()) or ())
    if len(store_operands) != 2:
        return None
    dst_slot = _stack_mem_operand_offset_width_8616(store_operands[0])
    if dst_slot is None or not _register_operand_is_8616(store_operands[1], X86_REG_DX):
        return None
    dst_offset, dst_width = dst_slot
    return dst_offset if dst_width == 2 else None


@cython.ccall
def _idiv_divisor_reg_8616(idiv_insn: StructuredAstValue, sign_extend: StructuredAstValue) -> int | None:
    """Return the divisor register of a ``cwd; idiv r`` pair, or None."""
    divisor_reg: object
    if operator.ne(getattr(idiv_insn, "id", None), X86_INS_IDIV) or getattr(sign_extend, "id", None) not in {
        X86_INS_CWD,
        X86_INS_CDQ,
    }:
        return None
    idiv_operands = _boundary_tuple_8616(getattr(idiv_insn, "operands", ()) or ())
    if len(idiv_operands) != 1 or operator.ne(getattr(idiv_operands[0], "type", None), X86_OP_REG):
        return None
    divisor_reg = getattr(idiv_operands[0], "reg", None)
    return divisor_reg if isinstance(divisor_reg, int) else None


@cython.ccall
def _signed_idiv_remainder_stack_store_fact_at_8616(
    project: AngrProjectValue,
    insns: object,
    index: cython.longlong,
) -> DirectStackMoveFact8616 | None:
    call: object
    call_return_contract: object
    divisor: object
    divisor_reg: object
    dst_offset: object
    ins_addr: object
    store: object
    if index <= 3:
        return None
    store = getattr(insns[index], "insn", insns[index])
    dst_offset = _dx_stack_store_offset_8616(store)
    if dst_offset is None:
        return None

    divisor_reg = _idiv_divisor_reg_8616(
        getattr(insns[index - 1], "insn", insns[index - 1]),
        getattr(insns[index - 2], "insn", insns[index - 2]),
    )
    if divisor_reg is None:
        return None
    divisor = _previous_stack_load_with_adjust_for_register_8616(insns, index - 2, divisor_reg, 2)
    if divisor is None:
        return None
    divisor_offset, divisor_adjust, divisor_load_index = divisor
    call = _direct_zero_arg_call_before_8616(project, insns, divisor_load_index)
    if call is None:
        return None
    call_name, call_target, call_ins_addr = call
    ins_addr = getattr(store, "address", None)
    if not isinstance(ins_addr, int):
        return None
    call_return_contract = runtime_call_return_contract_8616(call_name)
    if call_return_contract is None:
        call_return_contract = binary_call_return_contract_8616(
            project,
            call_target,
        )
    return DirectStackMoveFact8616(
        dst_offset,
        2,
        DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER,
        ins_addr,
        source_offset=divisor_offset,
        source_op=DirectStackMoveExpressionOp8616.MOD,
        source_immediate=divisor_adjust,
        source_call_target=call_target,
        source_call_name=call_name,
        source_call_ins_addr=call_ins_addr,
        source_call_return_contract=call_return_contract,
    )


@cython.ccall
def _callsite_proves_zero_args_8616(
    callsite_inventory: object,
    call_ins_addr: StructuredAstValue,
    resolved_call_target: StructuredAstValue,
) -> cython.bint:
    """Check whether the callsite summary proves a zero-argument callee."""
    callsite_summary = (
        callsite_inventory.get(call_ins_addr)
        if isinstance(call_ins_addr, int) and callsite_inventory is not None
        else None
    )
    return (
        isinstance(callsite_summary, CallsiteSummary8616)
        and operator.eq(callsite_summary.callsite_addr, call_ins_addr)
        and operator.eq(callsite_summary.target_addr, resolved_call_target)
        and callsite_summary.arg_count == 0
        and not callsite_summary.arg_widths
        and callsite_summary.stack_cleanup == 0
    )


@cython.ccall
def _wide_call_arith_call_gate_8616(
    project: StructuredAstValue,
    insns: object,
    index: cython.longlong,
    callsite_inventory: Mapping[int, CallsiteSummary8616] | None,
) -> object:
    """Validate the call arm, returning (callee_name, call_target, call_addr) or a reason."""
    call_ins_addr: object
    call_insn: object
    call_target: object
    if index + 4 >= len(insns):
        return None
    call_insn = getattr(insns[index], "insn", insns[index])
    if getattr(call_insn, "id", None) not in {X86_INS_CALL, X86_INS_LCALL}:
        return None
    call_operands = _boundary_tuple_8616(getattr(call_insn, "operands", ()) or ())
    if len(call_operands) != 1:
        return "call_operand_count"
    call_target = _direct_call_target_from_operand_8616(call_operands[0])
    if call_target is None:
        return "call_target"
    callee_name, callee, resolved_call_target = _callee_name_for_direct_stack_move_8616(project, call_target)
    call_ins_addr = getattr(call_insn, "address", None)
    if not _callee_has_zero_args_8616(callee, callee_name) and not _callsite_proves_zero_args_8616(
        callsite_inventory, call_ins_addr, resolved_call_target
    ):
        return f"callee_not_zero_args:{callee_name}"
    return (callee_name, resolved_call_target, call_ins_addr)


@cython.ccall
def _wide_call_arith_gate_8616(
    insns: object, index: cython.longlong
) -> object:
    """Validate the ADD/ADC arm, returning (arg_offset, add_addr, adc_addr) or a reason."""
    adc_insn: object
    add_insn: object
    arg_hi: object
    arg_lo: object
    add_insn = getattr(insns[index + 1], "insn", insns[index + 1])
    adc_insn = getattr(insns[index + 2], "insn", insns[index + 2])
    if operator.ne(getattr(add_insn, "id", None), X86_INS_ADD) or operator.ne(getattr(adc_insn, "id", None), X86_INS_ADC):
        return "not_add_adc"
    add_operands = _boundary_tuple_8616(getattr(add_insn, "operands", ()) or ())
    adc_operands = _boundary_tuple_8616(getattr(adc_insn, "operands", ()) or ())
    if len(add_operands) != 2 or len(adc_operands) != 2:
        return "arith_operand_count"
    if not _register_operand_is_8616(add_operands[0], X86_REG_AX):
        return "add_dst_not_ax"
    if not _register_operand_is_8616(adc_operands[0], X86_REG_DX):
        return "adc_dst_not_dx"
    arg_lo = _stack_mem_operand_offset_width_8616(add_operands[1])
    arg_hi = _stack_mem_operand_offset_width_8616(adc_operands[1])
    if arg_lo is None or arg_hi is None:
        return "arg_not_stack"
    arg_offset, arg_width = arg_lo
    arg_hi_offset, arg_hi_width = arg_hi
    if arg_width != 2 or arg_hi_width != 2 or operator.ne(arg_hi_offset, arg_offset + 2):
        return "arg_not_wide_pair"
    return (arg_offset, getattr(add_insn, "address", None), getattr(adc_insn, "address", None))


@cython.ccall
def _wide_call_mov_gate_8616(
    insns: object, index: cython.longlong
) -> object:
    """Validate the MOV pair arm, returning (dst_offset, lo_addr, hi_addr) or a reason."""
    dst_hi: object
    dst_lo: object
    mov_hi: object
    mov_lo: object
    mov_lo = getattr(insns[index + 3], "insn", insns[index + 3])
    mov_hi = getattr(insns[index + 4], "insn", insns[index + 4])
    if operator.ne(getattr(mov_lo, "id", None), X86_INS_MOV) or operator.ne(getattr(mov_hi, "id", None), X86_INS_MOV):
        return "not_mov_pair"
    mov_lo_operands = _boundary_tuple_8616(getattr(mov_lo, "operands", ()) or ())
    mov_hi_operands = _boundary_tuple_8616(getattr(mov_hi, "operands", ()) or ())
    if len(mov_lo_operands) != 2 or len(mov_hi_operands) != 2:
        return "mov_operand_count"
    if not _register_operand_is_8616(mov_lo_operands[1], X86_REG_AX):
        return "mov_lo_src_not_ax"
    if not _register_operand_is_8616(mov_hi_operands[1], X86_REG_DX):
        return "mov_hi_src_not_dx"
    dst_lo = _stack_mem_operand_offset_width_8616(mov_lo_operands[0])
    dst_hi = _stack_mem_operand_offset_width_8616(mov_hi_operands[0])
    if dst_lo is None or dst_hi is None:
        return "dst_not_stack"
    dst_offset, dst_width = dst_lo
    dst_hi_offset, dst_hi_width = dst_hi
    if dst_width != 2 or dst_hi_width != 2 or operator.ne(dst_hi_offset, dst_offset + 2):
        return "dst_not_wide_pair"
    return (dst_offset, getattr(mov_lo, "address", None), getattr(mov_hi, "address", None))


def _wide_call_return_stack_arith_fact_at_8616(
    project: StructuredAstValue,
    insns: object,
    index: cython.longlong,
    callsite_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> DirectStackMoveFact8616 | None:
    """Recover a stack-store fact for wide call-return arithmetic."""
    call_gate: object
    debug_stack_noise = bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))

    def _debug_reject(reason: object) -> None:
        insn: object
        wrapper: object
        if not debug_stack_noise:
            return
        window = []
        for wrapper in insns[index : min(index + 5, len(insns))]:
            insn = getattr(wrapper, "insn", wrapper)
            window.append(
                (
                    getattr(insn, "address", None),
                    getattr(insn, "mnemonic", None),
                    getattr(insn, "op_str", None),
                )
            )
        log.warning("[wide-call-return-stack-arith] reject reason=%s index=%d window=%r", reason, index, tuple(window))

    call_gate = _wide_call_arith_call_gate_8616(project, insns, index, callsite_inventory)
    if not isinstance(call_gate, tuple):
        if call_gate is not None:
            _debug_reject(call_gate)
        return None
    callee_name, resolved_call_target, call_ins_addr = call_gate
    arith = _wide_call_arith_gate_8616(insns, index)
    if not isinstance(arith, tuple):
        _debug_reject(arith)
        return None
    arg_offset, add_ins_addr, adc_ins_addr = arith
    mov = _wide_call_mov_gate_8616(insns, index)
    if not isinstance(mov, tuple):
        _debug_reject(mov)
        return None
    dst_offset, ins_addr, dst_high_ins_addr = mov
    if not all(
        isinstance(value, int)
        for value in iter((ins_addr, call_ins_addr, add_ins_addr, adc_ins_addr, dst_high_ins_addr))
    ):
        return None
    return DirectStackMoveFact8616(
        dst_offset,
        4,
        DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH,
        ins_addr,
        source_offset=arg_offset,
        source_op=DirectStackMoveExpressionOp8616.ADD,
        source_call_target=resolved_call_target,
        source_call_name=callee_name,
        source_call_ins_addr=call_ins_addr,
        source_low_arith_ins_addr=add_ins_addr,
        source_high_arith_ins_addr=adc_ins_addr,
        dst_high_ins_addr=dst_high_ins_addr,
    )




@cython.dataclasses.dataclass
class _DirectStackMoveFactCollector8616:
    """Classify one MOV-to-stack instruction into a typed source fact."""

    project: StructuredAstValue
    callsite_inventory: StructuredAstValue
    insns: StructuredAstValue
    index: cython.longlong
    insn: StructuredAstValue
    operands: StructuredAstValue
    facts: object
    dst_offset: StructuredAstValue = None
    width: StructuredAstValue = None
    ins_addr: StructuredAstValue = None
    dst_index_global_displacement: StructuredAstValue = None
    dst_index_stack_offset: StructuredAstValue = None
    dst_index_immediate: StructuredAstValue = None
    dst_index_scale: cython.longlong = 1
    dst_index_byte_scale: cython.longlong = 1
    source_register_offset: int | None = None
    reg_id: StructuredAstValue = None

    @cython.ccall
    def append_destination_fact(self, fact: DirectStackMoveFact8616) -> None:
        """Attach the current MOV destination's typed index evidence."""
        self.facts.append(
            replace(
                fact,
                source_register_offset=self.source_register_offset,
                dst_index_global_displacement=self.dst_index_global_displacement,
                dst_index_stack_offset=self.dst_index_stack_offset,
                dst_index_immediate=self.dst_index_immediate,
                dst_index_scale=self.dst_index_scale,
                dst_index_byte_scale=self.dst_index_byte_scale,
            )
        )

    @cython.ccall
    def classify_destination_8616(self) -> cython.bint:
        """Resolve the destination offset/width and typed index evidence."""
        dst_slot: object
        index_source: object
        indexed_dst: object
        ins_addr: object
        stack_index: object
        dst_slot = _stack_mem_operand_offset_width_8616(self.operands[0])
        indexed_dst = _indexed_stack_mem_operand_8616(self.operands[0])
        if dst_slot is None and indexed_dst is None:
            return False
        if indexed_dst is not None:
            self.dst_offset, self.width, dst_index_reg, self.dst_index_scale = indexed_dst
            index_source = _immediate_predecessor_index_source_8616(self.insns, self.index, dst_index_reg)
            if index_source is None:
                stack_index = _previous_stack_index_for_register_8616(self.insns, self.index, dst_index_reg)
                if stack_index is None or stack_index.width != 2:
                    return False
                self.dst_index_stack_offset = stack_index.stack_offset
                self.dst_index_byte_scale = stack_index.byte_scale * self.dst_index_scale
            else:
                index_kind, index_value = index_source
                if index_kind == "global":
                    self.dst_index_global_displacement = index_value
                elif index_kind == "stack":
                    self.dst_index_stack_offset = index_value
                else:
                    self.dst_index_immediate = index_value
                self.dst_index_byte_scale = self.dst_index_scale
        else:
            assert dst_slot is not None
            self.dst_offset, self.width = dst_slot
        ins_addr = getattr(self.insn, "address", None)
        if not isinstance(ins_addr, int):
            return False
        self.ins_addr = ins_addr
        return True

    @cython.ccall
    def _emit_immediate_source_8616(self, src: StructuredAstValue) -> cython.bint:
        """Emit an IMMEDIATE fact for a constant source operand."""
        value: object
        value = getattr(src, "imm", None)
        if not isinstance(value, int):
            return True
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.IMMEDIATE,
                self.ins_addr,
                source_value=value,
            )
        )
        return True

    @cython.ccall
    def _try_call_return_store_8616(self, register_name: StructuredAstValue) -> cython.bint:
        """Emit a ZERO_ARG_CALL_RETURN fact when the source is a call result."""
        call_return_store: object
        call_return_store = recover_zero_arg_call_return_stack_store_8616(
            self.callsite_inventory,
            store_ins_addr=self.ins_addr,
            dst_offset=self.dst_offset,
            width=self.width,
            source_register_name=register_name,
        )
        if call_return_store is None:
            return False
        callee_name, _callee, resolved_target = _callee_name_for_direct_stack_move_8616(
            self.project,
            call_return_store.target_addr,
        )
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN,
                self.ins_addr,
                source_call_target=resolved_target,
                source_call_name=callee_name,
                source_call_ins_addr=call_return_store.callsite_addr,
            )
        )
        return True

    @cython.ccall
    def _try_binary_stack_expr_8616(self) -> cython.bint:
        """Emit a STACK_SLOT_BINARY_EXPR fact for a proven register binop."""
        binary_stack_expr: object
        binary_stack_expr = _previous_binary_stack_expr_for_register_8616(
            self.insns, self.index, self.reg_id, self.width
        )
        if binary_stack_expr is None:
            return False
        source_offset, source_rhs_offset, source_op = binary_stack_expr
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR,
                self.ins_addr,
                source_offset=source_offset,
                source_rhs_offset=source_rhs_offset,
                source_op=source_op,
            )
        )
        return True

    @cython.ccall
    def _try_prev_load_8616(self) -> cython.bint:
        """Emit a STACK_SLOT fact for a same-width proven stack load."""
        prev_load: object
        prev_load = _previous_stack_load_for_register_8616(self.insns, self.index, self.reg_id)
        if prev_load is None:
            return False
        source_offset, source_width = prev_load
        if operator.ne(source_width, self.width):
            return True
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.STACK_SLOT,
                self.ins_addr,
                source_offset=source_offset,
            )
        )
        return True

    @cython.ccall
    def _try_signed_byte_load_8616(self) -> cython.bint:
        """Emit a sign-extended STACK_SLOT fact for a proven byte load."""
        signed_byte_load: object
        signed_byte_load = _previous_signed_byte_stack_load_for_register_8616(
            self.insns, self.index, self.reg_id, self.width
        )
        if signed_byte_load is None:
            return False
        source_offset, source_width = signed_byte_load
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.STACK_SLOT,
                self.ins_addr,
                source_offset=source_offset,
                source_access_width=source_width,
                source_sign_extend=True,
            )
        )
        return True

    @cython.ccall
    def _try_indexed_stack_load_8616(self) -> cython.bint:
        """Emit a STACK_AGGREGATE_ELEMENT fact for a proven indexed load."""
        indexed_stack_load: object
        indexed_stack_load = _previous_indexed_stack_load_for_register_8616(
            self.insns, self.index, self.reg_id
        )
        if indexed_stack_load is None or operator.ne(indexed_stack_load.access_width, self.width):
            return False
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
                self.ins_addr,
                source_aggregate_base_offset=indexed_stack_load.base_offset,
                source_index_offset=indexed_stack_load.index.stack_offset,
                source_index_byte_scale=indexed_stack_load.index.byte_scale,
                source_access_width=indexed_stack_load.access_width,
            )
        )
        return True

    @cython.ccall
    def _expr_load_8616(self) -> StructuredAstValue:
        """Resolve the stack-derived expression load evidence for the register."""
        adjusted_load: object
        expr_load: object
        expr_load = _previous_shifted_stack_load_for_register_8616(
            self.insns, self.index, self.reg_id, self.width
        )
        if expr_load is None:
            adjusted_load = _previous_stack_load_with_adjust_for_register_8616(
                self.insns, self.index, self.reg_id, self.width
            )
            if adjusted_load is not None:
                source_offset, adjustment, _load_index = adjusted_load
                if adjustment != 0:
                    expr_load = (source_offset, adjustment, DirectStackMoveExpressionOp8616.ADD)
        if expr_load is None:
            expr_load = _previous_signed_half_stack_load_for_register_8616(
                self.insns, self.index, self.reg_id, self.width
            )
        if expr_load is None:
            expr_load = _previous_stack_signed_idiv_const_for_register_8616(
                self.insns, self.index, self.reg_id, self.width
            )
        return expr_load

    @cython.ccall
    def _try_global_adjusted_8616(self) -> cython.bint:
        """Emit a GLOBAL_EXPR fact for an adjusted proven global load."""
        global_adjusted_load: object
        global_expr_load: object
        global_adjusted_load = _previous_global_load_with_adjust_for_register_8616(
            self.insns,
            self.index,
            self.reg_id,
            self.width,
        )
        if global_adjusted_load is not None:
            global_displacement, adjustment = global_adjusted_load
            self.append_destination_fact(
                DirectStackMoveFact8616(
                    self.dst_offset,
                    self.width,
                    DirectStackMoveSourceKind8616.GLOBAL_EXPR,
                    self.ins_addr,
                    source_global_displacement=global_displacement,
                    source_op=DirectStackMoveExpressionOp8616.ADD,
                    source_immediate=adjustment,
                )
            )
            return True
        global_expr_load = _previous_global_signed_half_for_register_8616(
            self.insns, self.index, self.reg_id, self.width
        )
        if global_expr_load is None:
            return False
        global_displacement, immediate, source_op = global_expr_load
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.GLOBAL_EXPR,
                self.ins_addr,
                source_global_displacement=global_displacement,
                source_op=source_op,
                source_immediate=immediate,
            )
        )
        return True

    @cython.ccall
    def _try_global_minus_8616(self) -> cython.bint:
        """Emit GLOBAL_MINUS_* facts for proven difference loads."""
        global_minus_segmented: object
        global_minus_stack: object
        global_minus_stack = _previous_global_minus_stack_for_register_8616(
            self.insns, self.index, self.reg_id, self.width
        )
        if global_minus_stack is not None:
            global_displacement, source_offset = global_minus_stack
            self.append_destination_fact(
                DirectStackMoveFact8616(
                    self.dst_offset,
                    self.width,
                    DirectStackMoveSourceKind8616.GLOBAL_MINUS_STACK_SLOT,
                    self.ins_addr,
                    source_global_displacement=global_displacement,
                    source_offset=source_offset,
                )
            )
            return True
        global_minus_segmented = _previous_global_minus_segmented_source_for_register_8616(
            self.insns,
            self.index,
            self.reg_id,
        )
        if global_minus_segmented is None:
            return False
        global_displacement, segmented_source = global_minus_segmented
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.GLOBAL_MINUS_SEGMENTED_MEMORY,
                self.ins_addr,
                source_segment_name=segmented_source.segment_name,
                source_global_displacement=global_displacement,
                source_displacement=segmented_source.displacement,
                source_index_offset=segmented_source.index_stack_offset,
                source_index_shift=segmented_source.index_shift,
                source_access_width=segmented_source.access_width,
                source_sign_extend=segmented_source.sign_extend,
            )
        )
        return True

    @cython.ccall
    def _try_segmented_source_8616(self) -> cython.bint:
        """Emit a SEGMENTED_MEMORY fact for a proven segmented register source."""
        register_segmented_source: object
        register_segmented_source = _direct_stack_move_segmented_source_for_register_8616(
            self.insns, self.index, self.reg_id
        )
        if register_segmented_source is None:
            return False
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
                self.ins_addr,
                source_segment_name=register_segmented_source.segment_name,
                source_displacement=register_segmented_source.displacement,
                source_index_offset=register_segmented_source.index_stack_offset,
                source_index_shift=register_segmented_source.index_shift,
                source_access_width=register_segmented_source.access_width,
                source_sign_extend=register_segmented_source.sign_extend,
            )
        )
        return True

    @cython.ccall
    def _try_register_source_arms_8616(self, register_name: StructuredAstValue) -> cython.bint:
        """Run the ordered register-source arm sequence."""
        if self._try_call_return_store_8616(register_name):
            return True
        if self._try_binary_stack_expr_8616():
            return True
        if self._try_prev_load_8616():
            return True
        if self._try_signed_byte_load_8616():
            return True
        return self._try_indexed_stack_load_8616()

    @cython.ccall
    def collect_source_8616(self) -> None:
        """Classify the register source and emit the first matching fact."""
        expr_load: object
        reg_id: object
        register_name: object
        src_type: object
        src = self.operands[1]
        src_type = getattr(src, "type", None)
        if operator.eq(src_type, X86_OP_IMM):
            self._emit_immediate_source_8616(src)
            return
        if operator.ne(src_type, X86_OP_REG):
            return
        reg_id = getattr(src, "reg", None)
        if not isinstance(reg_id, int):
            return
        self.reg_id = reg_id
        register_name = _direct_stack_move_register_name_8616(self.insn, reg_id)
        register_info = self.project.arch.registers.get(register_name) if register_name is not None else None
        if isinstance(register_info, tuple) and len(register_info) == 2 and isinstance(register_info[0], int):
            self.source_register_offset = register_info[0]
        if self._try_register_source_arms_8616(register_name):
            return
        expr_load = self._expr_load_8616()
        if expr_load is None:
            if self._try_global_adjusted_8616():
                return
            if self._try_global_minus_8616():
                return
            self._try_segmented_source_8616()
            return
        source_offset, immediate, source_op = expr_load
        self.append_destination_fact(
            DirectStackMoveFact8616(
                self.dst_offset,
                self.width,
                DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
                self.ins_addr,
                source_offset=source_offset,
                source_op=source_op,
                source_immediate=immediate,
            )
        )


@cython.ccall
def _collect_block_mov_facts_8616(
    project: StructuredAstValue,
    block: StructuredAstValue,
    callsite_inventory: StructuredAstValue,
    facts: object,
) -> None:
    """Collect every MOV-to-stack fact in one block."""
    idiv_remainder_fact: object
    insn: object
    index: object
    wrapper: object
    insns = _capstone_insns_for_direct_global_update_8616(project, block)
    for index, wrapper in enumerate(insns):
        insn = getattr(wrapper, "insn", wrapper)
        if operator.ne(getattr(insn, "id", None), X86_INS_MOV):
            continue
        idiv_remainder_fact = _signed_idiv_remainder_stack_store_fact_at_8616(project, insns, index)
        if idiv_remainder_fact is not None:
            facts.append(idiv_remainder_fact)
            continue
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if len(operands) != 2:
            continue
        collector = _DirectStackMoveFactCollector8616(
            project=project,
            callsite_inventory=callsite_inventory,
            insns=insns,
            index=index,
            insn=insn,
            operands=operands,
            facts=facts,
        )
        if collector.classify_destination_8616():
            collector.collect_source_8616()


def _direct_stack_move_instruction_facts_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    callsite_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> object:
    """Collect binary-proven BP-relative stack MOV facts."""
    cached: object
    idiv_remainder_fact: object
    wide_fact: object
    block: object
    cached = getattr(function, "_inertia_direct_stack_move_instruction_facts_8616", None)
    if isinstance(cached, tuple) and not callsite_inventory:
        return cached
    facts: list[DirectStackMoveFact8616] = []
    blocks = tuple(_direct_global_update_blocks_8616(project, function))
    merged_insns = _dedup_sorted_capstone_insns_by_addr_8616(
        wrapper for block in iter(blocks) for wrapper in builtins.iter(_capstone_insns_for_direct_global_update_8616(project, block))
    )
    for index in range(len(merged_insns)):
        wide_fact = _wide_call_return_stack_arith_fact_at_8616(
            project,
            merged_insns,
            index,
            callsite_inventory,
        )
        if wide_fact is not None:
            facts.append(wide_fact)
        idiv_remainder_fact = _signed_idiv_remainder_stack_store_fact_at_8616(project, merged_insns, index)
        if idiv_remainder_fact is not None:
            facts.append(idiv_remainder_fact)
    for block in blocks:
        _collect_block_mov_facts_8616(project, block, callsite_inventory, facts)
    result = tuple(dict.fromkeys(facts))
    if not callsite_inventory:
        with contextlib.suppress(Exception):
            function._inertia_direct_stack_move_instruction_facts_8616 = result
    return result


def _direct_stack_move_instruction_facts_for_codegen_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    function: StructuredAstValue,
) -> object:
    """Collect stack MOV facts through the exact extent proven by callsites.

    angr can expose a partial function size while Structuring is still
    converging. A typed callsite return address proves that the active function
    reaches at least that address, so Lowering may decode that exact prefix.
    The bounded extension changes evidence collection only; it does not mutate
    CFG ownership or guess a function end.
    """
    function_addr: object
    function_size: object
    inventory = _direct_stack_write_inventory_8616(project, function)
    cast(
        _DirectStackWriteInventoryOwner8616,
        codegen,
    )._inertia_direct_stack_write_inventory_8616 = inventory
    callsite_inventory = callsite_summary_inventory_8616(codegen)
    primary_facts = _direct_stack_move_instruction_facts_8616(
        project,
        function,
        callsite_inventory,
    )
    function_addr = getattr(function, "addr", None)
    function_size = getattr(function, "size", None)
    if not isinstance(function_addr, int):
        evidence = DirectStackMoveExtentEvidence8616(
            raw_fact_count=len(callsite_inventory),
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=0,
            function_addr=None,
            original_end=None,
            proven_end=None,
            recovered_fact_count=0,
        )
        cast(
            _DirectStackMoveExtentEvidenceOwner8616,
            codegen,
        )._inertia_direct_stack_move_extent_evidence_8616 = evidence
        return primary_facts

    bounded_size = min(function_size, 0x600) if isinstance(function_size, int) and function_size > 0 else 0x300
    original_end = function_addr + bounded_size
    maximum_end = function_addr + 0x600
    exact_returns = tuple(
        summary.return_addr
        for summary in builtins.iter(callsite_inventory.values())
        if function_addr <= summary.callsite_addr < maximum_end
        and isinstance(summary.return_addr, int)
        and summary.callsite_addr < summary.return_addr <= maximum_end
    )
    proven_end = max(exact_returns, default=original_end)
    extension_required = proven_end > original_end
    if not extension_required:
        evidence = DirectStackMoveExtentEvidence8616(
            raw_fact_count=len(callsite_inventory),
            normalized_fact_count=len(exact_returns),
            classified_fact_count=0,
            materialized_count=0,
            failure_count=0,
            function_addr=function_addr,
            original_end=original_end,
            proven_end=proven_end,
            recovered_fact_count=0,
        )
        cast(
            _DirectStackMoveExtentEvidenceOwner8616,
            codegen,
        )._inertia_direct_stack_move_extent_evidence_8616 = evidence
        return primary_facts

    extended_function = SimpleNamespace(addr=function_addr, size=proven_end - function_addr)
    decoded_blocks = _linear_capstone_function_block_8616(project, extended_function)
    if not decoded_blocks:
        evidence = DirectStackMoveExtentEvidence8616(
            raw_fact_count=len(callsite_inventory),
            normalized_fact_count=len(exact_returns),
            classified_fact_count=1,
            materialized_count=0,
            failure_count=1,
            function_addr=function_addr,
            original_end=original_end,
            proven_end=proven_end,
            recovered_fact_count=0,
        )
        cast(
            _DirectStackMoveExtentEvidenceOwner8616,
            codegen,
        )._inertia_direct_stack_move_extent_evidence_8616 = evidence
        raise PipelineHardError(
            "callsite-proven function extent could not be decoded",
            layer="types_lowering:direct_stack_move_extent",
            function_addr=function_addr,
            details={
                "original_end": original_end,
                "proven_end": proven_end,
                "callsite_count": len(callsite_inventory),
            },
        )

    extended_function.blocks = decoded_blocks
    extended_inventory = _direct_stack_write_inventory_8616(project, extended_function)
    cast(
        _DirectStackWriteInventoryOwner8616,
        codegen,
    )._inertia_direct_stack_write_inventory_8616 = extended_inventory
    extended_facts = _direct_stack_move_instruction_facts_8616(
        project,
        extended_function,
        callsite_inventory,
    )
    merged_facts = tuple(dict.fromkeys(tuple(primary_facts) + tuple(extended_facts)))
    recovered_fact_count = len(merged_facts) - len(primary_facts)
    evidence = DirectStackMoveExtentEvidence8616(
        raw_fact_count=len(callsite_inventory),
        normalized_fact_count=len(exact_returns),
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        function_addr=function_addr,
        original_end=original_end,
        proven_end=proven_end,
        recovered_fact_count=recovered_fact_count,
    )
    cast(
        _DirectStackMoveExtentEvidenceOwner8616,
        codegen,
    )._inertia_direct_stack_move_extent_evidence_8616 = evidence
    return merged_facts


@cython.ccall
def _reload_fact_for_mov_insn_8616(
    insn: StructuredAstValue,
    source_by_slot: object,
) -> DirectStackReloadFact8616 | None:
    """Classify one instruction as a register reload of a materialized slot."""
    ins_addr: object
    reg_id: object
    reg_name: object
    src_slot: object
    if operator.ne(getattr(insn, "id", None), X86_INS_MOV):
        return None
    ins_addr = getattr(insn, "address", None)
    if not isinstance(ins_addr, int):
        return None
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2:
        return None
    dst, src = operands
    if operator.ne(getattr(dst, "type", None), X86_OP_REG):
        return None
    src_slot = _stack_mem_operand_offset_width_8616(src)
    if src_slot is None:
        return None
    source_offset, width = src_slot
    reg_id = getattr(dst, "reg", None)
    if not isinstance(reg_id, int):
        return None
    reg_name = _capstone_register_name_8616(reg_id)
    if reg_name is None:
        return None
    prior_sources = [
        fact for fact in builtins.iter(source_by_slot.get((source_offset, width), ())) if int(fact.ins_addr) < int(ins_addr)
    ]
    if not prior_sources:
        return None
    source_fact = prior_sources[-1]
    return DirectStackReloadFact8616(
        source_offset,
        width,
        reg_id,
        reg_name,
        ins_addr,
        source_fact.ins_addr,
        source_fact.source_kind,
    )


def _direct_stack_reload_instruction_facts_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    materialized_move_facts: object,
) -> tuple[DirectStackReloadFact8616, ...]:
    """Collect register reloads from previously materialized stack slots."""
    fact: object
    facts: object
    move_fact: object
    wrapper: object
    source_by_slot: dict[tuple[cython.longlong, cython.longlong], list[DirectStackMoveFact8616]] = {}
    for move_fact in materialized_move_facts:
        source_by_slot.setdefault((move_fact.dst_offset, move_fact.width), []).append(move_fact)
    if not source_by_slot:
        return ()

    for facts in source_by_slot.values():
        facts.sort(key=lambda fact: int(fact.ins_addr))

    blocks = tuple(_direct_global_update_blocks_8616(project, function))
    merged_insns = _dedup_sorted_capstone_insns_by_addr_8616(
        wrapper for block in iter(blocks) for wrapper in builtins.iter(_capstone_insns_for_direct_global_update_8616(project, block))
    )

    reload_facts: list[DirectStackReloadFact8616] = []
    for wrapper in merged_insns:
        fact = _reload_fact_for_mov_insn_8616(getattr(wrapper, "insn", wrapper), source_by_slot)
        if fact is not None:
            reload_facts.append(fact)
    return tuple(dict.fromkeys(reload_facts))


@cython.ccall
def _stack_slot_has_intervening_direct_update_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    *,
    offset: cython.longlong,
    width: cython.longlong,
    start_ins_addr: cython.longlong,
    end_ins_addr: cython.longlong,
) -> cython.bint:
    """Return whether direct update evidence modifies a stack slot in a range."""
    update_addr: object
    update_width: object
    update_fact: object
    for update_fact in _direct_stack_update_instruction_facts_8616(project, function):
        if operator.ne(getattr(update_fact, "offset", None), offset):
            continue
        update_width = getattr(update_fact, "width", None)
        if isinstance(update_width, int) and operator.ne(update_width, width):
            continue
        update_addr = getattr(update_fact, "ins_addr", None)
        if isinstance(update_addr, int) and start_ins_addr < update_addr < end_ins_addr:
            return True
    return False


@cython.ccall
def _has_direct_global_update_assignment_8616(root: StructuredAstValue, addr: cython.longlong) -> cython.bint:
    stmt: object
    for stmt in _boundary_tuple_8616(getattr(root, "statements", ()) or ()):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        lhs = _strip_casts_8616(stmt.lhs)
        variable = getattr(lhs, "variable", None) if isinstance(lhs, structured_c.CVariable) else None
        if isinstance(variable, SimMemoryVariable) and operator.eq(getattr(variable, "addr", None), addr):
            return True
    return False


@cython.ccall
def _global_cvar_identity_8616(cvar: StructuredAstValue) -> object:
    cvar = _strip_casts_8616(cvar)
    if not isinstance(cvar, structured_c.CVariable):
        return None
    variable = cvar.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = variable.addr
    if not isinstance(addr, int):
        return None
    size = variable.size
    return addr, size if isinstance(size, int) else None


@cython.ccall
def _global_cvar_name_8616(cvar: StructuredAstValue) -> object:
    candidate: object
    cvar = _strip_casts_8616(cvar)
    if not isinstance(cvar, structured_c.CVariable):
        return None
    for candidate in (cvar.name, getattr(cvar.variable, "name", None)):
        if isinstance(candidate, str) and _valid_c_identifier_8616(candidate):
            return candidate
    return None


def _is_generated_global_name_8616(name: object) -> cython.bint:
    if not isinstance(name, str):
        return False
    stripped = name.lstrip("_")
    if not stripped.startswith("g_"):
        return False
    suffix = stripped[2:]
    if not suffix:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in iter(suffix))


@cython.ccall
def _preferred_same_addr_global_name_8616(root: StructuredAstValue, addr: cython.longlong, width: cython.longlong, fallback: object) -> object:
    identity: object
    node_size: object
    node: object
    if _valid_c_identifier_8616(fallback) and not _is_generated_global_name_8616(fallback):
        return fallback
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        identity = _global_cvar_identity_8616(node)
        if identity is None:
            continue
        node_addr, node_size = identity
        if operator.ne((node_addr & 0xFFFF), (addr & 0xFFFF)):
            continue
        if node_size is not None and operator.ne(node_size, width):
            continue
        name = _global_cvar_name_8616(node)
        if isinstance(name, str) and _valid_c_identifier_8616(name) and not _is_generated_global_name_8616(name):
            return name
    return fallback


@cython.ccall
def _rename_generated_same_addr_global_cvars_8616(
    root: StructuredAstValue, addr: cython.longlong, width: cython.longlong, preferred_name: object
) -> cython.longlong:
    identity: object
    node_size: object
    unified: object
    node: object
    if not _valid_c_identifier_8616(preferred_name) or _is_generated_global_name_8616(preferred_name):
        return 0
    renamed = 0
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        identity = _global_cvar_identity_8616(node)
        if identity is None:
            continue
        node_addr, node_size = identity
        if operator.ne((node_addr & 0xFFFF), (addr & 0xFFFF)):
            continue
        if node_size is not None and operator.ne(node_size, width):
            continue
        current_name = _global_cvar_name_8616(node)
        if current_name == preferred_name or not _is_generated_global_name_8616(current_name):
            continue
        variable = node.variable
        if isinstance(variable, SimMemoryVariable):
            variable.name = preferred_name
        unified = getattr(node, "unified_variable", None)
        if isinstance(unified, SimMemoryVariable):
            unified.name = preferred_name
        renamed += 1
    return renamed


@cython.ccall
def _same_global_cvar_8616(lhs: StructuredAstValue, rhs: StructuredAstValue) -> cython.bint:
    lhs_id: object
    lhs_size: object
    rhs_id: object
    rhs_size: object
    lhs_id = _global_cvar_identity_8616(lhs)
    rhs_id = _global_cvar_identity_8616(rhs)
    if lhs_id is None or rhs_id is None:
        return False
    lhs_addr, lhs_size = lhs_id
    rhs_addr, rhs_size = rhs_id
    if operator.ne((lhs_addr & 0xFFFF), (rhs_addr & 0xFFFF)):
        return False
    return lhs_size is None or rhs_size is None or operator.eq(lhs_size, rhs_size)


@cython.ccall
def _is_same_global_update_assignment_8616(stmt: StructuredAstValue, dst_cvar: StructuredAstValue, delta: cython.longlong) -> cython.bint:
    if not isinstance(stmt, structured_c.CAssignment):
        return False
    if not _same_global_cvar_8616(stmt.lhs, dst_cvar):
        return False
    rhs = _strip_casts_8616(stmt.rhs)
    if not isinstance(rhs, structured_c.CBinaryOp):
        return False
    expected_op = "Add" if delta > 0 else "Sub"
    if operator.ne(rhs.op, expected_op):
        return False
    if not _same_global_cvar_8616(rhs.lhs, dst_cvar):
        return False
    rhs_const = _strip_casts_8616(rhs.rhs)
    return isinstance(rhs_const, structured_c.CConstant) and operator.eq(getattr(rhs_const, "value", None), abs(int(delta)))


def _list_has_global_update_assignment_8616(
    statements: object, dst_cvar: StructuredAstValue, delta: cython.longlong
) -> cython.bint:
    return any(_is_same_global_update_assignment_8616(stmt, dst_cvar, delta) for stmt in iter(statements))


@cython.ccall
def _tree_has_global_update_assignment_8616(root: StructuredAstValue, dst_cvar: StructuredAstValue, delta: cython.longlong) -> cython.bint:
    node: object
    for node in _iter_structured_c_nodes_8616(root):
        if _is_same_global_update_assignment_8616(node, dst_cvar, delta):
            return True
    return False


@cython.ccall
def _tree_has_global_update_assignment_for_insn_8616(
    root: StructuredAstValue, project: AngrProjectValue, dst_cvar: StructuredAstValue, delta: cython.longlong, ins_addr: cython.longlong
) -> cython.bint:
    node: object
    for node in _iter_structured_c_nodes_8616(root):
        if not _node_has_instruction_address_8616(node, project, ins_addr):
            continue
        if _is_same_global_update_assignment_8616(node, dst_cvar, delta):
            return True
    return False


@cython.ccall
def _tree_has_covering_dword_update_assignment_for_insn_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    *,
    addr: cython.longlong,
    delta: cython.longlong,
    ins_addr: cython.longlong,
) -> cython.bint:
    """Find an exact tagged dword update covering one proven low-word update."""
    node: object
    expected_op = "Add" if delta > 0 else "Sub"
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CAssignment):
            continue
        if not _node_has_instruction_address_8616(node, project, ins_addr):
            continue
        lhs_identity = _global_cvar_identity_8616(node.lhs)
        if lhs_identity != (addr & 0xFFFF, 4):
            continue
        rhs = _strip_casts_8616(node.rhs)
        if not isinstance(rhs, structured_c.CBinaryOp) or operator.ne(rhs.op, expected_op):
            continue
        rhs_identity = _global_cvar_identity_8616(_strip_casts_8616(rhs.lhs))
        rhs_delta = _strip_casts_8616(rhs.rhs)
        if (
            rhs_identity == lhs_identity
            and isinstance(rhs_delta, structured_c.CConstant)
            and operator.eq(rhs_delta.value, abs(int(delta)))
        ):
            return True
    return False


@cython.ccall
def _tree_has_untagged_global_update_assignment_8616(
    root: StructuredAstValue, dst_cvar: StructuredAstValue, delta: cython.longlong
) -> cython.bint:
    tags: object
    node: object
    for node in _iter_structured_c_nodes_8616(root):
        tags = copy_structured_tags_8616(getattr(node, "tags", None))
        if tags is not None and isinstance(tags.get("ins_addr"), int):
            continue
        if _is_same_global_update_assignment_8616(node, dst_cvar, delta):
            return True
    return False


@cython.ccall
def _list_has_global_update_assignment_for_insn_8616(
    statements: object,
    project: AngrProjectValue,
    dst_cvar: StructuredAstValue,
    delta: cython.longlong,
    ins_addr: cython.longlong,
) -> cython.bint:
    stmt: object
    for stmt in statements:
        if not _node_has_instruction_address_8616(stmt, project, ins_addr):
            continue
        if _is_same_global_update_assignment_8616(stmt, dst_cvar, delta):
            return True
    return False


@cython.ccall
def _insertion_point_has_global_update_assignment_8616(
    statements: object,
    insert_index: cython.longlong,
    project: AngrProjectValue,
    dst_cvar: StructuredAstValue,
    delta: cython.longlong,
    ins_addr: cython.longlong,
) -> cython.bint:
    if insert_index > 0:
        previous_assignment = _last_transparent_assignment_8616(statements[insert_index - 1])
        if _node_has_instruction_address_8616(
            previous_assignment, project, ins_addr
        ) and _is_same_global_update_assignment_8616(previous_assignment, dst_cvar, delta):
            return True
    if insert_index < len(statements):
        next_assignment = _first_transparent_assignment_8616(statements[insert_index])
        if _node_has_instruction_address_8616(
            next_assignment, project, ins_addr
        ) and _is_same_global_update_assignment_8616(next_assignment, dst_cvar, delta):
            return True
    return False


@cython.ccall
def _candidate_ins_addrs_8616(project: AngrProjectValue, ins_addr: cython.longlong) -> frozenset[cython.longlong]:
    delta: object
    candidates = {ins_addr}
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and delta:
        candidates.add(ins_addr + delta)
        candidates.add(ins_addr - delta)
    return frozenset(candidates)


def _candidate_function_ins_addrs_8616(
    project: AngrProjectValue,
    function: StructuredAstValue,
    ins_addr: cython.longlong,
) -> object:
    """Return address candidates proven to belong to the current function.

    Equality matching may consider translated and original address domains.
    Ordering must not compare an out-of-domain ``ins_addr +/- delta`` candidate
    with structured nodes from the current function.
    """
    decoded_addrs = frozenset(
        address
        for insn in builtins.iter(_direct_global_update_ordered_insns_8616(project, function))
        if isinstance(address := getattr(insn, "address", None), int)
    )
    return _candidate_ins_addrs_8616(project, ins_addr) & decoded_addrs


def _node_has_instruction_address_8616(node: StructuredAstValue, project: AngrProjectValue, ins_addr: cython.longlong) -> cython.bint:
    """Return whether a C node carries the instruction's current or relocated origin tag."""
    tags: object
    try:
        tags = copy_structured_tags_8616(node.tags)
    except AttributeError:
        return False
    if tags is None:
        return False
    candidate_addrs = _candidate_ins_addrs_8616(project, ins_addr)
    return any(
        isinstance(tagged_addr, int) and tagged_addr in candidate_addrs
        for tagged_addr in iter((
            tags.get("ins_addr"),
            tags.get("inertia_relocated_from_ins_addr"),
        ))
    )


def _valid_c_identifier_8616(name: StructuredAstValue) -> cython.bint:
    if not isinstance(name, str) or not name:
        return False
    first = name[0]
    if not (first == "_" or first.isalpha()):
        return False
    return all(ch == "_" or ch.isalnum() for ch in iter(name))


@cython.ccall
def _ensure_stack_cvar_has_identifier_8616(
    codegen: StructuredCodegenValue, cvar: StructuredAstValue, offset: cython.longlong
) -> None:
    """Ensure a concrete angr stack CVariable has a valid owned identifier."""
    if not isinstance(cvar, structured_c.CVariable):
        return
    variable = cvar.variable
    if not isinstance(variable, SimStackVariable):
        return
    current_name = variable.name
    if _valid_c_identifier_8616(current_name):
        return
    preferred_name = _preferred_stack_object_name_8616(
        offset,
        codegen=codegen,
        byte_size=variable.size,
        known_bindings=_stack_bindings_from_codegen_8616(codegen),
    )
    if not _valid_c_identifier_8616(preferred_name):
        return
    # CVariable.name is read-only and derives from these backing variables.
    variable.name = preferred_name
    unified = cvar.unified_variable
    if isinstance(unified, SimStackVariable):
        unified.name = preferred_name


@cython.ccall
def _is_generated_stack_cvar_name_8616(name: StructuredAstValue) -> cython.bint:
    if not isinstance(name, str) or not name:
        return True
    return bool(re.fullmatch(r"(?:local|arg|stack|s)_[0-9a-fA-F]+", name))


def _apply_annotation_name_to_stack_cvar_8616(
    codegen: StructuredAstValue,
    cvar: StructuredAstValue,
    variable_hint: StructuredAstValue | None,
    known_bindings: StructuredAstValue,
) -> cython.bint:
    """Reconcile one stack cvar's name against proven storage identity."""
    if not isinstance(cvar, structured_c.CVariable):
        return False
    variable = cvar.variable
    if not isinstance(variable, SimStackVariable):
        variable = variable_hint
    if not isinstance(variable, SimStackVariable) or variable.base != "bp":
        return False
    offset = _canonical_stack_offset_8616(
        machine_bp_offset_for_stack_variable_8616(codegen, variable)
    )
    if not isinstance(offset, int):
        return False
    preferred_name = _preferred_stack_object_name_8616(
        offset,
        codegen=codegen,
        byte_size=variable.size,
        known_bindings=known_bindings,
    )
    if not _valid_c_identifier_8616(preferred_name):
        return False
    default_name = _stack_object_name(offset, codegen=codegen)
    unified = cvar.unified_variable
    current_names = (
        variable.name,
        cvar.name,
        unified.name if isinstance(unified, SimVariable) else None,
    )
    binding = StackVariableBinding(
        bp_offset=offset,
        size=variable.size,
        var_name=variable.name,
    )
    inherited_container_name = any(
        stack_binding_inherits_containing_name_8616(
            binding,
            current_name=name,
            known_bindings=known_bindings,
        )
        and _valid_c_identifier_8616(name)
        and not _is_generated_stack_cvar_name_8616(name)
        for name in iter(current_names)
    )
    has_owned_name = any(
        _valid_c_identifier_8616(name) and not _is_generated_stack_cvar_name_8616(name) for name in iter(current_names)
    )
    if has_owned_name and not inherited_container_name:
        return False
    if preferred_name == default_name and not inherited_container_name:
        return False
    before = current_names
    if operator.ne(variable.name, preferred_name):
        variable.name = preferred_name
    if isinstance(unified, SimVariable) and operator.ne(unified.name, preferred_name):
        unified.name = preferred_name
    after = (
        variable.name,
        cvar.name,
        unified.name if isinstance(unified, SimVariable) else None,
    )
    return after != before


@cython.ccall
def _apply_annotation_names_to_existing_stack_cvars_8616(codegen: StructuredAstValue) -> cython.bint:
    """Reconcile inert metadata names with proven stack storage identities."""
    root: object
    cvar: object
    node: object
    variable: object
    cfunc = codegen.cfunc
    changed = False
    seen: set[cython.longlong] = set()
    known_bindings = _stack_bindings_from_codegen_8616(codegen)

    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        # Dynamic angr/codegen boundary: partial codegen surfaces have no
        # variable-manager bindings to reconcile.
        variables_in_use = None
    if isinstance(variables_in_use, dict):
        for variable, cvar in tuple(variables_in_use.items()):
            if id(cvar) in seen:
                continue
            seen.add(id(cvar))
            if _apply_annotation_name_to_stack_cvar_8616(codegen, cvar, variable, known_bindings):
                changed = True
    root = cfunc.statements
    if root is not None:
        for node in _iter_structured_c_nodes_8616(root):
            if not isinstance(node, structured_c.CVariable) or id(node) in seen:
                continue
            seen.add(id(node))
            if _apply_annotation_name_to_stack_cvar_8616(codegen, node, None, known_bindings):
                changed = True
    return changed


@cython.ccall
def _stack_cvar_size_matches_8616(node_size: object, target_size: object) -> cython.bint:
    """Check size compatibility for stack-cvar usage counting."""
    return (
        target_size is None
        or node_size is None
        or operator.eq(node_size, target_size)
        or (isinstance(node_size, int) and isinstance(target_size, int) and node_size >= target_size)
    )


@cython.ccall
def _stack_cvar_ast_usage_count_8616(codegen: StructuredAstValue, cvar: StructuredAstValue) -> cython.longlong:
    """Count uses of a stack C variable in the current AST."""
    cache: object
    cached: object
    node_id: object
    root: object
    target_id: object
    node: object
    target_id = _stack_cvar_identity_8616(cvar)
    if target_id is None:
        return 0
    target_offset, target_size = target_id
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return 0
    cache = getattr(codegen, "_inertia_stack_cvar_ast_usage_count_cache_8616", None)
    if not isinstance(cache, dict):
        cache = {}
        with contextlib.suppress(Exception):
            codegen._inertia_stack_cvar_ast_usage_count_cache_8616 = cache
    cache_key = (id(root), target_offset, target_size)
    cached = cache.get(cache_key)
    if isinstance(cached, int):
        return cached
    count = 0
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        node_id = _stack_cvar_identity_8616(node)
        if node_id is None:
            continue
        node_offset, node_size = node_id
        if node_offset == target_offset and _stack_cvar_size_matches_8616(node_size, target_size):
            count += 1
    cache[cache_key] = count
    return count


@cython.ccall
def _stack_cvar_matches_offset_width_8616(cvar: StructuredAstValue, offset: cython.longlong, width: cython.longlong) -> cython.bint:
    stack_id: object
    stack_id = _stack_cvar_identity_8616(cvar)
    if stack_id is None:
        return False
    stack_offset, stack_size = stack_id
    if stack_offset != offset:
        return False
    return not isinstance(stack_size, int) or stack_size <= 0 or stack_size >= width


@cython.ccall
def _stack_variable_min_width_ok_8616(
    codegen: StructuredAstValue,
    cvar: StructuredAstValue,
    variable: StructuredAstValue,
    offset: StructuredAstValue,
    width: cython.longlong,
) -> cython.bint:
    """Fix the backing SimStackVariable size and prototype type; True when done."""
    prototype_type: object
    size = variable.size
    if not isinstance(size, int) or size < width:
        with contextlib.suppress(Exception):
            variable.size = width
    prototype_type = _prototype_arg_type_for_bp_offset_8616(codegen, offset) if isinstance(offset, int) else None
    if prototype_type is None or _type_size_bytes_8616(prototype_type, default=0) < width:
        return False
    bound_type = _bind_type_to_codegen_arch_8616(codegen, prototype_type)
    if operator.ne(getattr(cvar, "variable_type", None), bound_type):
        cvar.variable_type = bound_type
    return True


@cython.ccall
def _prune_bp_alias_keys_8616(
    codegen: StructuredAstValue,
    mapping: StructuredAstValue,
    keep_variable: StructuredAstValue,
    offset: StructuredAstValue,
) -> None:
    """Remove stale same-offset BP stack variables from a cvar mapping."""
    existing: object
    if not isinstance(mapping, dict) or not isinstance(offset, int):
        return
    for existing in tuple(mapping):
        if existing is keep_variable or not isinstance(existing, SimStackVariable):
            continue
        if getattr(existing, "base", None) != "bp":
            continue
        if operator.eq(_canonical_stack_offset_8616(machine_bp_offset_for_stack_variable_8616(codegen, existing)), offset):
            del mapping[existing]


@cython.ccall
def _ensure_stack_cvar_min_width_8616(codegen: StructuredAstValue, cvar: StructuredAstValue, width: cython.longlong) -> None:
    """Ensure a stack C variable is wide enough for a materialized fact."""
    cfunc: object
    unified: object
    variable: object
    variables_in_use: object
    if not isinstance(cvar, structured_c.CVariable) or width <= 0:
        return
    variable = getattr(cvar, "variable", None)
    offset = (
        _canonical_stack_offset_8616(
            machine_bp_offset_for_stack_variable_8616(codegen, variable)
        )
        if isinstance(variable, SimStackVariable)
        else None
    )
    if isinstance(variable, SimStackVariable) and _stack_variable_min_width_ok_8616(
        codegen, cvar, variable, offset, width
    ):
        return
    current_width = _type_size_bytes_8616(getattr(cvar, "variable_type", None), default=0)
    if current_width < width:
        cvar.variable_type = _bind_type_to_codegen_arch_8616(codegen, _type_for_access_width_8616(width))
    cfunc = getattr(codegen, "cfunc", None)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    _prune_bp_alias_keys_8616(codegen, variables_in_use, variable, offset)
    if isinstance(variables_in_use, dict) and isinstance(offset, int) and isinstance(variable, SimStackVariable):
        variables_in_use[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    _prune_bp_alias_keys_8616(codegen, unified, variable, offset)
    if isinstance(unified, dict) and isinstance(offset, int) and isinstance(variable, SimStackVariable):
        unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}


@cython.ccall
def _stack_update_cvar_candidates_from_registry_8616(
    codegen: StructuredAstValue,
    offset: cython.longlong,
    width: cython.longlong,
    seen_candidate_ids: object,
    candidates: object,
) -> None:
    """Collect same-offset/width cvar candidates from variables_in_use."""
    size: object
    variables_in_use: object
    cvar: object
    variable: object
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return
    for variable, cvar in tuple(variables_in_use.items()):
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        if operator.ne(_canonical_stack_offset_8616(machine_bp_offset_for_stack_variable_8616(codegen, variable)), offset):
            continue
        size = getattr(variable, "size", None)
        if not isinstance(size, int) or operator.ne(size, width):
            continue
        if isinstance(cvar, structured_c.CVariable):
            _apply_preferred_stack_cvar_name_8616(cvar, offset, codegen)
            _ensure_stack_cvar_has_identifier_8616(codegen, cvar, offset)
            usage_count = _stack_cvar_ast_usage_count_8616(codegen, cvar)
            exact_size = int(isinstance(size, int) and operator.eq(size, width))
            seen_candidate_ids.add(id(cvar))
            candidates.append((usage_count, exact_size, cvar))


@cython.ccall
def _stack_update_cvar_candidates_from_ast_8616(
    codegen: StructuredAstValue,
    offset: cython.longlong,
    width: cython.longlong,
    seen_candidate_ids: object,
    candidates: object,
) -> None:
    """Collect same-offset/width cvar candidates still present in the AST."""
    root: object
    node: object
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CVariable) or id(node) in seen_candidate_ids:
            continue
        variable = node.variable
        if not isinstance(variable, SimStackVariable) or variable.base != "bp":
            continue
        stack_size = variable.size
        bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if operator.ne(_canonical_stack_offset_8616(bp_offset), offset) or stack_size != width:
            continue
        _apply_preferred_stack_cvar_name_8616(node, offset, codegen)
        _ensure_stack_cvar_has_identifier_8616(codegen, node, offset)
        usage_count = _stack_cvar_ast_usage_count_8616(codegen, node)
        exact_size = int(isinstance(stack_size, int) and stack_size == width)
        seen_candidate_ids.add(id(node))
        candidates.append((usage_count, exact_size, node))


@cython.ccall
def _materialize_stack_update_cvar_8616(
    codegen: StructuredAstValue, offset: cython.longlong, width: cython.longlong
) -> StructuredAstValue | None:
    """Materialize a stack cvar from facts when no live candidate exists."""
    entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(
        codegen,
        offset,
        width,
    )
    if isinstance(entry_sp_offset, int):
        materialized = materialize_stack_cvar_at_offset_from_facts_8616(
            codegen,
            entry_sp_offset,
            width,
            machine_bp_offset=offset,
            preferred_name=_preferred_stack_object_name_8616(
                offset,
                codegen=codegen,
                byte_size=width,
            ),
        )
        if isinstance(materialized, structured_c.CVariable):
            _ensure_stack_cvar_has_identifier_8616(codegen, materialized, offset)
            _ensure_stack_cvar_min_width_8616(codegen, materialized, width)
            return materialized
    return None


def _resolve_direct_stack_update_cvar_8616(
    codegen: StructuredAstValue, offset: cython.longlong, width: cython.longlong
) -> StructuredAstValue | None:
    """Resolve a stack update through the active registry, including old AST clones."""
    unified: object
    variables_in_use: object
    projected = stack_cvar_for_machine_bp_range_8616(codegen, offset, width)
    if isinstance(projected, structured_c.CVariable):
        _apply_preferred_stack_cvar_name_8616(projected, offset, codegen)
        _ensure_stack_cvar_has_identifier_8616(codegen, projected, offset)
        _ensure_stack_cvar_min_width_8616(codegen, projected, width)
        return projected
    candidates: list[tuple[cython.longlong, cython.longlong, StructuredAstValue]] = []
    seen_candidate_ids: set[cython.longlong] = set()
    _stack_update_cvar_candidates_from_registry_8616(codegen, offset, width, seen_candidate_ids, candidates)
    _stack_update_cvar_candidates_from_ast_8616(codegen, offset, width, seen_candidate_ids, candidates)
    if candidates:
        candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
        selected = candidates[0][2]
        _ensure_stack_cvar_min_width_8616(codegen, selected, width)
        publish_selected_stack_cvar_projection_8616(
            codegen, selected, bp_offset=offset, size=width,
            entry_sp_offset=entry_sp_offset_for_machine_bp_range_8616(codegen, offset, width),
        )
        return selected

    materialized = _materialize_stack_update_cvar_8616(codegen, offset, width)
    if isinstance(materialized, structured_c.CVariable):
        return materialized

    target_type = _prototype_arg_type_for_bp_offset_8616(codegen, offset) or _type_for_access_width_8616(width)
    variable = SimStackVariable(
        offset,
        width,
        base="bp",
        name=_preferred_stack_object_name_8616(offset, codegen=codegen),
        region=getattr(getattr(codegen, "cfunc", None), "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(getattr(codegen, "cfunc", None), "unified_local_vars", None)
    if isinstance(unified, dict):
        unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
    publish_selected_stack_cvar_projection_8616(
        codegen, cvar, bp_offset=offset, size=width,
        entry_sp_offset=entry_sp_offset_for_machine_bp_range_8616(codegen, offset, width),
    )
    return cvar


@cython.ccall
def _record_stack_owner_candidate_8616(
    codegen: StructuredAstValue,
    offset: cython.longlong,
    width: cython.longlong,
    require_wider_owner: cython.bint,
    candidate: StructuredAstValue,
    stack_size: StructuredAstValue,
    seen_candidate_ids: object,
    candidates: object,
) -> None:
    """Score and record one same-base owner cvar candidate."""
    if not isinstance(candidate, structured_c.CVariable) or not isinstance(stack_size, int):
        return
    if stack_size < width or (require_wider_owner and stack_size == width):
        return
    if id(candidate) in seen_candidate_ids:
        return
    seen_candidate_ids.add(id(candidate))
    _apply_preferred_stack_cvar_name_8616(candidate, offset, codegen)
    _ensure_stack_cvar_has_identifier_8616(codegen, candidate, offset)
    candidates.append(
        (
            int(stack_size == width),
            _stack_cvar_ast_usage_count_8616(codegen, candidate),
            stack_size,
            candidate,
        )
    )


@cython.ccall
def _stack_owner_candidates_8616(
    codegen: StructuredAstValue,
    offset: cython.longlong,
    width: cython.longlong,
    require_wider_owner: cython.bint,
) -> object:
    """Collect ranked owner candidates from the registry and the live AST."""
    root: object
    stack_identity: object
    variables_in_use: object
    cvar: object
    node: object
    variable: object
    candidates: list[tuple[cython.longlong, cython.longlong, cython.longlong, StructuredAstValue]] = []
    seen_candidate_ids: set[cython.longlong] = set()

    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable, cvar in tuple(variables_in_use.items()):
            if not isinstance(variable, SimStackVariable) or variable.base != "bp":
                continue
            if operator.ne(_canonical_stack_offset_8616(machine_bp_offset_for_stack_variable_8616(codegen, variable)), offset):
                continue
            _record_stack_owner_candidate_8616(
                codegen, offset, width, require_wider_owner,
                cvar, variable.size, seen_candidate_ids, candidates,
            )

    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is not None:
        for node in _iter_structured_c_nodes_8616(root):
            if not isinstance(node, structured_c.CVariable):
                continue
            stack_identity = _stack_cvar_identity_8616(node)
            if stack_identity is None or operator.ne(stack_identity[0], offset):
                continue
            _record_stack_owner_candidate_8616(
                codegen, offset, width, require_wider_owner,
                node, stack_identity[1], seen_candidate_ids, candidates,
            )
    return candidates


def _resolve_existing_direct_stack_owner_cvar_8616(
    codegen: StructuredAstValue,
    offset: cython.longlong,
    width: cython.longlong,
    *,
    require_wider_owner: cython.bint = False,
) -> StructuredAstValue | None:
    """Resolve an existing stack object that owns a same-base access range."""
    candidates = _stack_owner_candidates_8616(codegen, offset, width, require_wider_owner)
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[:3], reverse=True)
    return candidates[0][3]


@cython.ccall
def _resolve_direct_stack_read_cvar_8616(
    codegen: StructuredAstValue,
    offset: cython.longlong,
    width: cython.longlong,
) -> StructuredAstValue | None:
    """Resolve an exact stack read or its existing same-base storage owner."""
    owner: object
    projected = stack_cvar_for_machine_bp_range_8616(codegen, offset, width)
    if isinstance(projected, structured_c.CVariable):
        return projected
    owner = _resolve_existing_direct_stack_owner_cvar_8616(codegen, offset, width)
    if owner is not None:
        return owner
    return _resolve_direct_stack_update_cvar_8616(codegen, offset, width)


@cython.ccall
def _direct_stack_update_source_expr_8616(
    codegen: StructuredCodegenValue, fact: DirectStackUpdateFact8616
) -> StructuredAstValue:
    base: object
    index: object
    source_expr: object
    target_type = _bind_type_to_codegen_arch_8616(codegen, _type_for_access_width_8616(fact.width))
    source_expr = None
    if fact.source_kind is DirectStackUpdateSourceKind8616.IMMEDIATE:
        value = fact.source_value if isinstance(fact.source_value, int) else abs(int(fact.delta))
        source_expr = structured_c.CConstant(abs(int(value)), target_type, codegen=codegen)
    elif fact.source_kind is DirectStackUpdateSourceKind8616.STACK_SLOT:
        if not isinstance(fact.source_offset, int):
            return None
        source_expr = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, fact.width)
    elif fact.source_kind is DirectStackUpdateSourceKind8616.INDEXED_POINTER:
        if not isinstance(fact.source_base_offset, int) or not isinstance(fact.source_index_offset, int):
            return None
        if operator.ne(fact.source_index_scale, fact.width):
            return None
        base = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_base_offset, 2)
        index = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_index_offset, 2)
        if base is None or index is None:
            return None
        source_expr = structured_c.CIndexedVariable(
            base,
            index,
            variable_type=target_type,
            codegen=codegen,
        )
    if source_expr is None:
        return None
    if (
        fact.source_kind is not DirectStackUpdateSourceKind8616.IMMEDIATE
        and fact.operation
        in {
            DirectStackUpdateOp8616.SHIFT_LEFT,
            DirectStackUpdateOp8616.SHIFT_RIGHT,
        }
    ):
        source_expr = structured_c.CBinaryOp(
            "And",
            source_expr,
            structured_c.CConstant(0x1F, target_type, codegen=codegen),
            codegen=codegen,
        )
    return source_expr


@cython.ccall
def _direct_stack_update_op_name_8616(operation: DirectStackUpdateOp8616, delta: cython.longlong) -> object:
    """Map one typed direct-stack operation to its structured-C binary operator."""
    if operation is DirectStackUpdateOp8616.OR:
        return "Or"
    if operation is DirectStackUpdateOp8616.SHIFT_LEFT:
        return "Shl"
    if operation is DirectStackUpdateOp8616.SHIFT_RIGHT:
        return "Shr"
    return "Add" if delta > 0 else "Sub"


@cython.ccall
def _direct_stack_update_assignment_8616(
    codegen: StructuredCodegenValue,
    cvar: StructuredAstValue,
    width: cython.longlong,
    delta: cython.longlong,
    tags: StructuredAstValue = None,
    source_expr: StructuredAstValue = None,
    operation: DirectStackUpdateOp8616 = DirectStackUpdateOp8616.ARITHMETIC,
) -> StructuredAstValue:
    target_type = _bind_type_to_codegen_arch_8616(codegen, _type_for_access_width_8616(width))
    _bind_c_expr_type_to_codegen_arch_8616(codegen, cvar)
    _bind_c_expr_type_to_codegen_arch_8616(codegen, source_expr)
    if source_expr is None:
        source_expr = structured_c.CConstant(abs(int(delta)), target_type, codegen=codegen)
    op_name = _direct_stack_update_op_name_8616(operation, delta)
    rhs = structured_c.CBinaryOp(
        op_name,
        cvar,
        source_expr,
        codegen=codegen,
        tags=tags,
    )
    return structured_c.CAssignment(cvar, rhs, codegen=codegen, tags=tags)


@cython.ccall
def _is_same_stack_update_assignment_8616(
    stmt: StructuredAstValue,
    cvar: StructuredAstValue,
    delta: cython.longlong,
    source_expr: StructuredAstValue,
    operation: DirectStackUpdateOp8616 = DirectStackUpdateOp8616.ARITHMETIC,
) -> cython.bint:
    if not isinstance(stmt, structured_c.CAssignment):
        return False
    if not _same_stack_cvar_8616(stmt.lhs, cvar):
        return False
    rhs = _strip_casts_8616(stmt.rhs)
    if not isinstance(rhs, structured_c.CBinaryOp):
        return False
    op_name = _direct_stack_update_op_name_8616(operation, delta)
    if operator.ne(rhs.op, op_name):
        return False
    if not _same_stack_cvar_8616(rhs.lhs, cvar):
        return False
    return _same_stack_move_rhs_8616(rhs.rhs, source_expr)


def _rendered_stack_update_assignment_ids_8616(
    nodes: Iterable[StructuredAstValue],
) -> frozenset[cython.longlong]:
    """Index updates occupying structured-C positions rendered as code."""
    assignment: object
    attr: object
    owner: object
    rendered_ids: set[cython.longlong] = set()
    for owner in nodes:
        if isinstance(owner, structured_c.CStatements):
            rendered_ids.update(id(statement) for statement in builtins.iter(tuple(owner.statements or ())))
            continue
        if not isinstance(owner, structured_c.CForLoop):
            continue
        # Third-party angr versions expose this field as either name.
        for attr in ("iterator", "iteration"):
            assignment = getattr(owner, attr, None)
            if assignment is not None:
                rendered_ids.add(id(assignment))
    return frozenset(rendered_ids)


@cython.ccall
def _has_existing_stack_update_assignment_8616(
    root: StructuredAstValue,
    project: StructuredAstValue,
    fact: DirectStackUpdateFact8616,
    cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
    *,
    expected_semantic_count: cython.longlong,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> cython.bint:
    """Return whether structured C has an exact update or the proven group count."""
    node: object
    matching_assignment_ids: set[cython.longlong] = set()
    tagged_destination_ids: set[cython.longlong] = set()
    tagged_match = False
    if query_index is not None:
        query_index.require_root(root)
    nodes = (
        query_index.nodes
        if query_index is not None
        else tuple(_iter_structured_c_nodes_8616(root))
    )
    rendered_assignment_ids = _rendered_stack_update_assignment_ids_8616(nodes)
    for node in nodes:
        if (
            isinstance(node, structured_c.CAssignment)
            and operator.eq(_assignment_lhs_stack_offset_8616(node), fact.offset)
            and id(node) in rendered_assignment_ids
            and _node_has_instruction_address_8616(node, project, fact.ins_addr)
        ):
            tagged_destination_ids.add(id(node))
        if not _is_same_stack_update_assignment_8616(
            node,
            cvar,
            fact.delta,
            source_expr,
            operation=fact.operation,
        ):
            continue
        if id(node) not in rendered_assignment_ids:
            continue
        matching_assignment_ids.add(id(node))
        if _node_has_instruction_address_8616(node, project, fact.ins_addr):
            tagged_match = True
    if tagged_match:
        return len(tagged_destination_ids) == 1
    return operator.eq(len(matching_assignment_ids), expected_semantic_count)


@cython.ccall
def _same_direct_stack_update_semantics_8616(
    lhs: DirectStackUpdateFact8616,
    rhs: DirectStackUpdateFact8616,
) -> cython.bint:
    """Compare direct stack-update facts while excluding instruction identity."""
    return operator.eq(replace(lhs, ins_addr=rhs.ins_addr), rhs)


@cython.ccall
def _function_call_name_8616(expr: StructuredAstValue) -> object:
    callee_func: object
    candidate: object
    expr = _strip_casts_8616(expr)
    if not isinstance(expr, structured_c.CFunctionCall):
        return None
    callee_func = expr.callee_func
    for candidate in (expr.callee_target, callee_func.name if callee_func is not None else None):
        if isinstance(candidate, str) and candidate:
            return candidate.lstrip("_")
    return None


@cython.ccall
def _function_call_target_addr_8616(expr: StructuredAstValue) -> int | None:
    """Return a binary target address from one structured call expression."""
    callee_addr: object
    expr = _strip_casts_8616(expr)
    if not isinstance(expr, structured_c.CFunctionCall):
        return None
    if isinstance(expr.callee_target, int):
        return expr.callee_target
    if isinstance(expr.callee_target, structured_c.CConstant):
        target_value = expr.callee_target.value
        if isinstance(target_value, int):
            return target_value
    if expr.callee_func is None:
        return None
    # Dynamic angr Function boundary.
    callee_addr = getattr(expr.callee_func, "addr", None)
    return callee_addr if isinstance(callee_addr, int) else None


@cython.ccall
def _function_call_target_matches_8616(
    expr: StructuredAstValue,
    project: StructuredAstValue,
    expected_target: int | None,
) -> cython.bint:
    """Match original and exact-slice addresses for one binary call target."""
    original_delta: object
    if not isinstance(expected_target, int):
        return False
    observed_target = _function_call_target_addr_8616(expr)
    if not isinstance(observed_target, int):
        return False
    expected_variants = {expected_target}
    # Dynamic exact-slice project extension boundary.
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int) and original_delta:
        expected_variants.update(
            {
                expected_target - original_delta,
                expected_target + original_delta,
            }
        )
    return observed_target in expected_variants


def _expr_contains_function_call_8616(expr: StructuredAstValue) -> cython.bint:
    """Return whether a structured-C expression contains a function call."""
    return any(isinstance(node, structured_c.CFunctionCall) for node in builtins.iter(_iter_structured_c_nodes_8616(expr)))


@cython.ccall
def _structured_c_intrinsic_8616(expr: StructuredAstValue) -> StructuredCIntrinsic8616 | None:
    name: object
    candidate: object
    expr = _strip_casts_8616(expr)
    if not isinstance(expr, structured_c.CFunctionCall):
        return None
    candidates = (
        getattr(expr, "callee_target", None),
        getattr(expr, "callee", None),
        getattr(getattr(expr, "callee_func", None), "name", None),
    )
    for candidate in candidates:
        name = getattr(candidate, "name", candidate)
        if not isinstance(name, str) or not name:
            continue
        normalized = name.rsplit(".", 1)[-1].lstrip("_")
        if operator.eq(normalized, StructuredCIntrinsic8616.INSERT.value):
            return StructuredCIntrinsic8616.INSERT
    return None


def _expr_has_structured_c_intrinsic_8616(expr: StructuredAstValue, intrinsic: StructuredCIntrinsic8616) -> cython.bint:
    return any(_structured_c_intrinsic_8616(node) is intrinsic for node in builtins.iter(_iter_structured_c_nodes_8616(expr)))


def _expr_has_binary_op_8616(expr: StructuredAstValue, op: DirectStackMoveExpressionOp8616) -> cython.bint:
    return any(
        isinstance(node, structured_c.CBinaryOp) and operator.eq(node.op, op.value)
        for node in builtins.iter(_iter_structured_c_nodes_8616(expr))
    )


@cython.ccall
def _rhs_is_signed_idiv_remainder_artifact_8616(rhs: StructuredAstValue) -> cython.bint:
    return _expr_has_binary_op_8616(rhs, DirectStackMoveExpressionOp8616.MOD) and _expr_has_structured_c_intrinsic_8616(
        rhs,
        StructuredCIntrinsic8616.INSERT,
    )


_CALL_RESULT_CHILD_ATTRS_8616 = (
    "statements",
    "lhs",
    "rhs",
    "operand",
    "expr",
    "stmts",
    "init",
    "initializer",
    "iftrue",
    "iffalse",
    "iteration",
    "iterator",
    "body",
    "else_node",
    "switch",
    "default",
)


@cython.dataclasses.dataclass
class _CallResultCvarFinder8616:
    """Find the cvar receiving AX at a tagged call instruction."""

    project: AngrProjectValue
    call_ins_addr: cython.longlong
    normalized_call_name: object
    found: StructuredAstValue = None
    seen: object = field(default_factory=set)

    @cython.ccall
    def _visit_child_value_8616(self, value: object) -> None:
        """Visit one child attribute value (scalar or sequence)."""
        item: object
        if isinstance(value, (list, tuple)):
            for item in tuple(value):
                self.visit(item)
                if self.found is not None:
                    return
        elif value is not None:
            self.visit(value)

    @cython.ccall
    def _visit_children_8616(self, node: StructuredAstValue) -> None:
        """Recursively visit child attributes until a match is found."""
        condition_and_nodes: object
        value: object
        attr: object
        body: object
        condition: object
        for attr in _CALL_RESULT_CHILD_ATTRS_8616:
            if not hasattr(node, attr):
                continue
            with contextlib.suppress(Exception):
                value = getattr(node, attr)
            self._visit_child_value_8616(value)
            if self.found is not None:
                return
        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            for condition, body in tuple(condition_and_nodes):
                self.visit(condition)
                if self.found is not None:
                    return
                self.visit(body)
                if self.found is not None:
                    return

    @cython.ccall
    def visit(self, node: object) -> None:
        """Visit one node, recording the first AX-writing call assignment."""
        if self.found is not None or node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        if isinstance(node, structured_c.CAssignment) and _node_has_instruction_address_8616(
            node,
            self.project,
            self.call_ins_addr,
        ):
            callee_name = _function_call_name_8616(node.rhs)
            lhs = _strip_casts_8616(node.lhs)
            if (
                isinstance(lhs, structured_c.CVariable)
                and _cvar_register_name_8616(lhs) == "ax"
                and (self.normalized_call_name is None or operator.eq(callee_name, self.normalized_call_name))
            ):
                self.found = lhs
                return
        self._visit_children_8616(node)


@cython.ccall
def _call_result_cvar_at_instruction_8616(
    codegen: StructuredCodegenValue, project: AngrProjectValue, call_ins_addr: int | None, call_name: object
) -> StructuredAstValue:
    root: object
    if not isinstance(call_ins_addr, int):
        return None
    normalized_call_name = call_name.lstrip("_") if isinstance(call_name, str) else None
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return None
    finder = _CallResultCvarFinder8616(project, call_ins_addr, normalized_call_name)
    finder.visit(root)
    return finder.found


@cython.ccall
def _function_pointer_stack_slot_type_8616(cvar: StructuredAstValue) -> SimTypePointer | None:
    if not isinstance(cvar, structured_c.CVariable):
        return None
    try:
        variable_type = cvar.variable_type
    except AttributeError:
        return None
    if not isinstance(variable_type, SimTypePointer):
        return None
    try:
        pointee = variable_type.pts_to
    except AttributeError:
        return None
    return variable_type if isinstance(pointee, SimTypeFunction) else None


@cython.ccall
def _default_near_function_pointer_type_8616(codegen: StructuredCodegenValue, width: cython.longlong) -> SimTypePointer:
    """Build an architecture-bound near pointer while preserving its concrete type."""
    arch: object
    project: object
    word_type = _type_for_access_width_8616(width)
    prototype = SimTypeFunction([word_type], word_type, variadic=False)
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    if arch is not None:
        prototype = prototype.with_arch(arch)
    pointer_type = SimTypePointer(prototype)
    return cast(SimTypePointer, pointer_type.with_arch(arch)) if arch is not None else pointer_type


@cython.ccall
def _c_decl_type_for_function_pointer_target_8616(type_: StructuredAstValue) -> object:
    """Render a conservative C declaration type from a recovered function-pointer prototype."""
    if isinstance(type_, SimTypeChar):
        return "char" if bool(type_.signed) else "unsigned char"
    if isinstance(type_, SimTypeShort):
        return "short" if bool(type_.signed) else "unsigned short"
    if isinstance(type_, SimTypeInt):
        return "int" if bool(type_.signed) else "unsigned int"
    if isinstance(type_, SimTypeLong):
        return "long" if bool(type_.signed) else "unsigned long"
    return None


@cython.ccall
def _function_pointer_target_prototype_decl_8616(name: object, pointer_type: SimTypePointer) -> object:
    """Build a target declaration only from the recovered function-pointer type."""
    arg_decl_type: object
    prototype: object
    return_type: object
    arg_type: object
    idx: object
    if re.fullmatch(r"[A-Za-z_]\w*", name) is None:
        return None
    prototype = getattr(pointer_type, "pts_to", None)
    if not isinstance(prototype, SimTypeFunction):
        return None
    return_type = _c_decl_type_for_function_pointer_target_8616(getattr(prototype, "returnty", None))
    if return_type is None:
        return None
    args: list[str] = []
    for idx, arg_type in enumerate(_boundary_tuple_8616(getattr(prototype, "args", ()) or ())):
        arg_decl_type = _c_decl_type_for_function_pointer_target_8616(arg_type)
        if arg_decl_type is None:
            return None
        args.append(f"{arg_decl_type} a{idx}")
    return f"{return_type} {name}({', '.join(args) if args else 'void'});"


@cython.ccall
def _record_function_pointer_target_prototype_decl_8616(
    codegen: StructuredAstValue, resolved: DirectStackFunctionTarget8616, pointer_type: SimTypePointer
) -> None:
    """Record a binary-proven function-designator declaration for final rendering."""
    decl: object
    decl = _function_pointer_target_prototype_decl_8616(resolved.name, pointer_type)
    if decl is None:
        return
    existing = _boundary_tuple_8616(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
    if decl in existing:
        return
    codegen._inertia_callsite_prototype_decls = (*existing, decl)
    codegen._inertia_function_pointer_target_prototype_decl_count_8616 = (
        int(getattr(codegen, "_inertia_function_pointer_target_prototype_decl_count_8616", 0) or 0) + 1
    )


@cython.ccall
def _binary_direct_stack_callback_binding_8616(
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    target: cython.longlong,
) -> object:
    """Bind a code offset only when binary caller and callee prove its ABI."""
    if fact.width != 2:
        return None
    result = prove_binary_near_callback_target_8616(
        project,
        codegen,
        stack_offset=fact.dst_offset,
        source_value=target,
        candidates=_direct_stack_move_call_target_candidates_8616(
            project, target, include_padding_aliases=False
        ),
    )
    if result.status is not BinaryCallbackTargetStatus8616.PROVEN or result.proof is None:
        return None
    proof = result.proof
    resolved = DirectStackFunctionTarget8616(
        name=proof.name,
        addr=proof.addr,
        evidence=DirectStackFunctionTargetEvidence8616.BINARY_CALL_FLOW,
    )
    pointer_type = cast(SimTypePointer, _function_pointer_type_8616(proof.parameter_fact, project.arch))
    return resolved, pointer_type


@cython.ccall
def _direct_stack_near_function_pointer_expr_8616(
    codegen: StructuredAstValue, fact: DirectStackMoveFact8616, dst_cvar: StructuredAstValue
) -> StructuredAstValue | None:
    binary_binding: object
    pointer_type: object
    project: object
    resolved: object
    if fact.source_kind is not DirectStackMoveSourceKind8616.IMMEDIATE:
        return None
    if not isinstance(fact.source_value, int):
        return None
    project = getattr(codegen, "project", None)
    if project is None:
        return None
    mask = (1 << (fact.width * 8)) - 1
    target = fact.source_value & mask
    resolved = (
        _direct_stack_function_target_8616(project, target, include_padding_aliases=False)
        if target != 0 else None
    )
    if resolved is None:
        binary_binding = _binary_direct_stack_callback_binding_8616(codegen, project, fact, target)
        if binary_binding is None:
            return None
        resolved, pointer_type = binary_binding
    else:
        pointer_type = _function_pointer_stack_slot_type_8616(dst_cvar)
        if pointer_type is None:
            pointer_type = _default_near_function_pointer_type_8616(codegen, fact.width)
    if isinstance(dst_cvar, structured_c.CVariable):
        dst_cvar.variable_type = pointer_type
    _record_function_pointer_target_prototype_decl_8616(codegen, resolved, pointer_type)
    variable = SimMemoryVariable(
        resolved.addr,
        fact.width,
        name=resolved.name,
        region=getattr(getattr(codegen, "cfunc", None), "addr", None),
    )
    return structured_c.CVariable(variable, variable_type=pointer_type, codegen=codegen)


@cython.ccall
def _low_byte_field_for_two_byte_aggregate_8616(
    codegen: StructuredAstValue,
    source: StructuredAstValue,
) -> StructuredAstValue | None:
    """Return field zero when a scalar low-byte use targets a proven two-byte aggregate."""
    aggregate_type = source.type if isinstance(source, structured_c.CExpression) else None
    if not isinstance(aggregate_type, SimStruct) or aggregate_type.size != 16:
        return None
    fields = tuple(aggregate_type.fields.items())
    if len(fields) != 2:
        return None
    field_name, field_type = fields[0]
    if not isinstance(field_type, SimTypeChar) or aggregate_type.offsets.get(field_name) != 0:
        return None
    return structured_c.CVariableField(
        source,
        structured_c.CStructField(aggregate_type, 0, field_name, codegen=codegen),
        codegen=codegen,
    )


@cython.ccall
def _stack_move_source_immediate_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for immediate facts."""
    function_pointer_expr: object
    if not isinstance(fact.source_value, int):
        return None
    function_pointer_expr = _direct_stack_near_function_pointer_expr_8616(codegen, fact, dst_cvar)
    if function_pointer_expr is not None:
        return function_pointer_expr
    mask = (1 << (fact.width * 8)) - 1
    return structured_c.CConstant(fact.source_value & mask, target_type, codegen=codegen)


@cython.ccall
def _stack_move_source_stack_slot_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for stack_slot facts."""
    source: object
    if not isinstance(fact.source_offset, int):
        return None
    source_width = fact.source_access_width if isinstance(fact.source_access_width, int) else fact.width
    source = _resolve_direct_stack_read_cvar_8616(codegen, fact.source_offset, source_width)
    if source is None:
        return None
    if fact.source_sign_extend and source_width < fact.width:
        signed_source_type = SimTypeChar(True) if source_width == 1 else SimTypeShort(True)
        cast_source = (
            _low_byte_field_for_two_byte_aggregate_8616(codegen, source) if source_width == 1 else None
        ) or source
        return CSemanticCast8616(
            target_type,
            signed_source_type,
            cast_source,
            codegen=codegen,
        )
    return source


def _stack_move_source_stack_aggregate_element_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for stack_aggregate_element facts."""
    aggregate_cvar: object
    index_cvar: object
    if (
        not isinstance(fact.source_aggregate_base_offset, int)
        or not isinstance(fact.source_index_offset, int)
        or operator.ne(fact.source_access_width, fact.width)
    ):
        return None
    raw_facts = getattr(codegen, "_inertia_stack_aggregate_object_facts_8616", ()) or ()
    candidates = tuple(
        aggregate
        for aggregate in iter(raw_facts)
        if isinstance(aggregate, StackAggregateObjectFact8616)
        and operator.eq(aggregate.base_offset, fact.source_aggregate_base_offset)
        and operator.eq(aggregate.element_width, fact.source_access_width)
        and operator.eq(fact.source_index_byte_scale, aggregate.element_width)
    )
    if len(candidates) != 1:
        return None
    raw_cvars = getattr(codegen, "_inertia_stack_aggregate_cvars_8616", {}) or {}
    if not isinstance(raw_cvars, dict):
        return None
    aggregate_cvar = raw_cvars.get(candidates[0].base_offset)
    index_cvar = _resolve_direct_stack_update_cvar_8616(
        codegen,
        fact.source_index_offset,
        2,
    )
    if not isinstance(aggregate_cvar, structured_c.CVariable) or index_cvar is None:
        return None
    return structured_c.CIndexedVariable(aggregate_cvar, index_cvar, codegen=codegen)


@cython.ccall
def _stack_move_source_stack_slot_expr_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for stack_slot_expr facts."""
    source: object
    if (
        not isinstance(fact.source_offset, int)
        or not isinstance(fact.source_immediate, int)
        or fact.source_op
        not in {
            DirectStackMoveExpressionOp8616.ADD,
            DirectStackMoveExpressionOp8616.SHL,
            DirectStackMoveExpressionOp8616.SIGNED_DIV2,
        }
    ):
        return None
    source = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, fact.width)
    if source is None:
        return None
    if fact.source_op is DirectStackMoveExpressionOp8616.ADD:
        immediate = int(fact.source_immediate)
        if immediate == 0:
            return source
        return structured_c.CBinaryOp(
            "Add" if immediate > 0 else "Sub",
            source,
            structured_c.CConstant(abs(immediate), target_type, codegen=codegen),
            codegen=codegen,
        )
    if fact.source_op is DirectStackMoveExpressionOp8616.SIGNED_DIV2:
        signed_type = SimTypeShort(True)
        signed_source = CSemanticCast8616(
            target_type,
            signed_type,
            source,
            codegen=codegen,
        )
        return structured_c.CBinaryOp(
            fact.source_op.value,
            signed_source,
            structured_c.CConstant(fact.source_immediate, signed_type, codegen=codegen),
            codegen=codegen,
        )
    return structured_c.CBinaryOp(
        fact.source_op.value,
        source,
        structured_c.CConstant(fact.source_immediate, target_type, codegen=codegen),
        codegen=codegen,
    )


@cython.ccall
def _stack_move_source_stack_slot_binary_expr_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for stack_slot_binary_expr facts."""
    lhs: object
    rhs: object
    if (
        not isinstance(fact.source_offset, int)
        or not isinstance(fact.source_rhs_offset, int)
        or fact.source_op
        not in {
            DirectStackMoveExpressionOp8616.ADD,
            DirectStackMoveExpressionOp8616.SUB,
        }
    ):
        return None
    lhs = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, fact.width)
    rhs = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_rhs_offset, fact.width)
    if lhs is None or rhs is None:
        return None
    if fact.source_op is DirectStackMoveExpressionOp8616.SUB:
        signed_type = SimTypeShort(True) if fact.width == 2 else SimTypeChar(True)
        signed_type = _bind_type_to_codegen_arch_8616(codegen, signed_type)
        lhs = CSemanticCast8616(target_type, signed_type, lhs, codegen=codegen)
        rhs = CSemanticCast8616(target_type, signed_type, rhs, codegen=codegen)
    return structured_c.CBinaryOp(fact.source_op.value, lhs, rhs, codegen=codegen)


@cython.ccall
def _stack_move_source_global_expr_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for global_expr facts."""
    project: object
    source: object
    if not isinstance(fact.source_global_displacement, int):
        return None
    project = getattr(codegen, "project", None)
    name = _direct_global_update_name_8616(
        project,
        getattr(getattr(codegen, "cfunc", None), "addr", None),
        fact.source_global_displacement,
    )
    record_scalar_global_declaration_spec_8616(
        codegen,
        ctype=ctype_for_global_width_8616(fact.width),
        name=name,
    )
    global_expr = structured_c.CVariable(
        SimMemoryVariable(
            fact.source_global_displacement & 0xFFFF,
            fact.width,
            name=name,
            region=getattr(getattr(codegen, "cfunc", None), "addr", None),
        ),
        variable_type=target_type,
        codegen=codegen,
    )
    if fact.source_kind is DirectStackMoveSourceKind8616.GLOBAL_MINUS_STACK_SLOT:
        if not isinstance(fact.source_offset, int):
            return None
        source = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, fact.width)
        if source is None:
            return None
        return structured_c.CBinaryOp("Sub", global_expr, source, codegen=codegen)
    if fact.source_op is DirectStackMoveExpressionOp8616.ADD and isinstance(fact.source_immediate, int):
        if fact.source_immediate == 0:
            return global_expr
        return structured_c.CBinaryOp(
            "Add" if fact.source_immediate > 0 else "Sub",
            global_expr,
            structured_c.CConstant(
                abs(fact.source_immediate),
                target_type,
                codegen=codegen,
            ),
            codegen=codegen,
        )
    if fact.source_op is DirectStackMoveExpressionOp8616.SIGNED_DIV2 and isinstance(fact.source_immediate, int):
        signed_type = SimTypeShort(True)
        return structured_c.CBinaryOp(
            fact.source_op.value,
            CSemanticCast8616(target_type, signed_type, global_expr, codegen=codegen),
            structured_c.CConstant(fact.source_immediate, signed_type, codegen=codegen),
            codegen=codegen,
        )
    return global_expr



@cython.ccall
def _stack_move_source_global_minus_segmented_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for global_minus_segmented facts."""
    project: object
    right_expr: object
    if not isinstance(fact.source_global_displacement, int):
        return None
    right_expr = _segmented_memory_source_expr_8616(codegen, fact)
    if right_expr is None:
        return None
    project = getattr(codegen, "project", None)
    name = _direct_global_update_name_8616(
        project,
        getattr(getattr(codegen, "cfunc", None), "addr", None),
        fact.source_global_displacement,
    )
    record_scalar_global_declaration_spec_8616(
        codegen,
        ctype=ctype_for_global_width_8616(2),
        name=name,
    )
    left_expr = structured_c.CVariable(
        SimMemoryVariable(
            fact.source_global_displacement & 0xFFFF,
            2,
            name=name,
            region=getattr(getattr(codegen, "cfunc", None), "addr", None),
        ),
        variable_type=_type_for_access_width_8616(2),
        codegen=codegen,
    )
    return structured_c.CBinaryOp("Sub", left_expr, right_expr, codegen=codegen)


@cython.ccall
def _stack_move_source_zero_arg_call_return_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for zero_arg_call_return facts."""
    if not isinstance(fact.source_call_name, str) or not isinstance(fact.source_call_ins_addr, int):
        return None
    return structured_c.CFunctionCall(
        fact.source_call_name,
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": fact.source_call_ins_addr},
    )


@cython.ccall
def _stack_move_source_signed_idiv_remainder_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for signed_idiv_remainder facts."""
    dividend: object
    divisor: object
    project: object
    stats: object
    if (
        not isinstance(fact.source_offset, int)
        or fact.source_op is not DirectStackMoveExpressionOp8616.MOD
        or not isinstance(fact.source_call_target, int)
    ):
        return None
    project = getattr(codegen, "project", None)
    call_name = fact.source_call_name
    callee = None
    if project is not None:
        call_name, callee, _resolved_call_target = _callee_name_for_direct_stack_move_8616(
            project,
            fact.source_call_target,
        )
    if not isinstance(call_name, str) or not call_name:
        call_name = f"sub_{int(fact.source_call_target):x}"
    dividend = None
    if reuse_call_result and project is not None:
        dividend = _call_result_cvar_at_instruction_8616(
            codegen,
            project,
            fact.source_call_ins_addr,
            call_name,
        )
    if dividend is None:
        call_tags = (
            {"ins_addr": fact.source_call_ins_addr}
            if isinstance(fact.source_call_ins_addr, int)
            else None
        )
        dividend = structured_c.CFunctionCall(
            call_name,
            callee,
            [],
            codegen=codegen,
            tags=call_tags,
        )
    else:
        stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
        if isinstance(stats, dict):
            stats["call_result_reused_count"] = int(stats.get("call_result_reused_count", 0) or 0) + 1
    divisor = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, fact.width)
    if divisor is None:
        return None
    divisor_expr = divisor
    if isinstance(fact.source_immediate, int) and fact.source_immediate != 0:
        divisor_expr = structured_c.CBinaryOp(
            "Add" if fact.source_immediate > 0 else "Sub",
            divisor,
            structured_c.CConstant(abs(int(fact.source_immediate)), target_type, codegen=codegen),
            codegen=codegen,
        )
    signed_type = SimTypeShort(True)
    return structured_c.CBinaryOp(
        fact.source_op.value,
        CSemanticCast8616(target_type, signed_type, dividend, codegen=codegen),
        CSemanticCast8616(target_type, signed_type, divisor_expr, codegen=codegen),
        codegen=codegen,
    )


@cython.ccall
def _stack_move_source_wide_call_return_stack_arith_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for wide_call_return_stack_arith facts."""
    project: object
    stack_expr: object
    if (
        not isinstance(fact.source_offset, int)
        or fact.source_op is not DirectStackMoveExpressionOp8616.ADD
        or not isinstance(fact.source_call_target, int)
    ):
        return None
    project = getattr(codegen, "project", None)
    call_name = fact.source_call_name
    callee = None
    if project is not None:
        call_name, callee, _resolved_call_target = _callee_name_for_direct_stack_move_8616(
            project,
            fact.source_call_target,
        )
    if not isinstance(call_name, str) or not call_name:
        call_name = f"sub_{int(fact.source_call_target):x}"
    call_tags = (
        {"ins_addr": fact.source_call_ins_addr}
        if isinstance(fact.source_call_ins_addr, int)
        else None
    )
    call_expr = structured_c.CFunctionCall(
        call_name,
        callee,
        [],
        codegen=codegen,
        tags=call_tags,
    )
    stack_expr = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_offset, 4)
    if stack_expr is None:
        return None
    return structured_c.CBinaryOp(
        fact.source_op.value,
        call_expr,
        stack_expr,
        codegen=codegen,
    )


@cython.ccall
def _segmented_memory_source_expr_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
) -> StructuredAstValue | None:
    arch: object
    index_expr: object
    project: object
    if (
        not isinstance(fact.source_segment_name, str)
        or not isinstance(fact.source_displacement, int)
        or not isinstance(fact.source_index_offset, int)
        or not isinstance(fact.source_index_shift, int)
        or fact.source_access_width not in {1, 2}
    ):
        return None
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    reg_info = getattr(arch, "registers", {}).get(fact.source_segment_name.lower()) if arch is not None else None
    if not isinstance(reg_info, tuple) or len(reg_info) < 2:
        return None
    segment_type = SimTypeShort(False)
    with contextlib.suppress(Exception):
        segment_type = segment_type.with_arch(arch)
    segment_expr = structured_c.CVariable(
        SimRegisterVariable(reg_info[0], reg_info[1], name=fact.source_segment_name.lower()),
        variable_type=segment_type,
        codegen=codegen,
    )
    index_expr = _resolve_direct_stack_update_cvar_8616(codegen, fact.source_index_offset, 2)
    if index_expr is None:
        return None
    offset_type = _type_for_access_width_8616(2)
    if fact.source_index_shift:
        index_expr = structured_c.CBinaryOp(
            "Shl",
            index_expr,
            structured_c.CConstant(fact.source_index_shift, offset_type, codegen=codegen),
            codegen=codegen,
        )
    displacement = structured_c.CConstant(fact.source_displacement, offset_type, codegen=codegen)
    offset_expr = structured_c.CBinaryOp("Add", displacement, index_expr, codegen=codegen)
    macro_name = "SEG_U8" if int(fact.source_access_width) == 1 else "SEG_U16"
    return structured_c.CFunctionCall(
        macro_name,
        None,
        [segment_expr, offset_expr],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": macro_name},
    )



@cython.ccall
def _stack_move_source_segmented_memory_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None,
    target_type: StructuredAstValue,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build the MOV source expression for segmented-memory facts."""
    return _segmented_memory_source_expr_8616(codegen, fact)


@cython.ccall
def _direct_stack_move_source_expr_8616(
    codegen: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue | None = None,
    *,
    reuse_call_result: cython.bint = True,
) -> StructuredAstValue | None:
    """Build a C expression for a binary-proven direct stack MOV source."""
    handler: object
    target_type = _type_for_access_width_8616(fact.width)
    dispatch = {
        DirectStackMoveSourceKind8616.IMMEDIATE: _stack_move_source_immediate_8616,
        DirectStackMoveSourceKind8616.STACK_SLOT: _stack_move_source_stack_slot_8616,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT: _stack_move_source_stack_aggregate_element_8616,
        DirectStackMoveSourceKind8616.STACK_SLOT_EXPR: _stack_move_source_stack_slot_expr_8616,
        DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR: _stack_move_source_stack_slot_binary_expr_8616,
        DirectStackMoveSourceKind8616.GLOBAL_MINUS_SEGMENTED_MEMORY: _stack_move_source_global_minus_segmented_8616,
        DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN: _stack_move_source_zero_arg_call_return_8616,
        DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER: _stack_move_source_signed_idiv_remainder_8616,
        DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH: _stack_move_source_wide_call_return_stack_arith_8616,
        DirectStackMoveSourceKind8616.SEGMENTED_MEMORY: _stack_move_source_segmented_memory_8616,
    }
    global_kinds = {
        DirectStackMoveSourceKind8616.GLOBAL_EXPR,
        DirectStackMoveSourceKind8616.GLOBAL_MINUS_STACK_SLOT,
    }
    if fact.source_kind in global_kinds:
        return _stack_move_source_global_expr_8616(
            codegen,
            fact,
            dst_cvar,
            target_type,
            reuse_call_result=reuse_call_result,
        )
    handler = dispatch.get(fact.source_kind)
    if handler is None:
        return None
    return handler(
        codegen,
        fact,
        dst_cvar,
        target_type,
        reuse_call_result=reuse_call_result,
    )



@cython.ccall
def _direct_stack_move_assignment_8616(
    codegen: StructuredCodegenValue,
    dst_cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
    tags: StructuredAstValue = None,
) -> StructuredAstValue:
    return structured_c.CAssignment(dst_cvar, source_expr, codegen=codegen, tags=tags)


@cython.ccall
def _direct_stack_move_global_index_cvar_8616(
    codegen: StructuredCodegenValue, displacement: cython.longlong
) -> StructuredAstValue:
    """Resolve or materialize the direct global feeding an indexed stack store."""
    root: object
    variables_in_use: object
    node: object
    name = _direct_global_update_name_8616(
        getattr(codegen, "project", None),
        getattr(getattr(codegen, "cfunc", None), "addr", None),
        displacement,
    )
    record_scalar_global_declaration_spec_8616(
        codegen,
        ctype=ctype_for_global_width_8616(2),
        name=name,
    )
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        variable = node.variable
        if isinstance(variable, SimMemoryVariable) and operator.eq(getattr(variable, "addr", None), (displacement & 0xFFFF)):
            return node
    variable = SimMemoryVariable(
        displacement & 0xFFFF,
        2,
        name=name,
        region=getattr(getattr(codegen, "cfunc", None), "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=_type_for_access_width_8616(2), codegen=codegen)
    variables_in_use = getattr(getattr(codegen, "cfunc", None), "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    return cvar


def _stack_aggregate_destination_8616(
    codegen: StructuredCodegenValue,
    fact: DirectStackMoveFact8616,
    index_expr: object,
) -> StructuredAstValue | None:
    """Project a direct or indexed store through its proven aggregate object."""
    aggregate_cvar: object
    has_index_evidence = any(
        isinstance(value, int)
        for value in iter((
            fact.dst_index_global_displacement,
            fact.dst_index_stack_offset,
            fact.dst_index_immediate,
        ))
    )
    raw_facts = getattr(codegen, "_inertia_stack_aggregate_object_facts_8616", ()) or ()
    candidates = tuple(
        aggregate
        for aggregate in iter(raw_facts)
        if isinstance(aggregate, StackAggregateObjectFact8616)
        and operator.eq(fact.width, aggregate.element_width)
        and fact.dst_offset in aggregate.indexed_offsets
        and (not has_index_evidence or operator.eq(fact.dst_index_byte_scale, aggregate.element_width))
    )
    if len(candidates) != 1:
        return None
    aggregate = candidates[0]
    raw_cvars = getattr(codegen, "_inertia_stack_aggregate_cvars_8616", {}) or {}
    if not isinstance(raw_cvars, dict):
        return None
    aggregate_cvar = raw_cvars.get(aggregate.base_offset)
    if not isinstance(aggregate_cvar, structured_c.CVariable):
        return None
    if index_expr is None:
        if operator.ne(fact.dst_offset, aggregate.base_offset):
            return None
        index_expr = structured_c.CConstant(
            0,
            _type_for_access_width_8616(2),
            codegen=codegen,
        )
    displacement_delta = fact.dst_offset - aggregate.base_offset
    if displacement_delta % aggregate.element_width != 0:
        return None
    index_adjustment = displacement_delta // aggregate.element_width
    if index_adjustment:
        operation = "Add" if index_adjustment > 0 else "Sub"
        index_expr = structured_c.CBinaryOp(
            operation,
            index_expr,
            structured_c.CConstant(
                abs(index_adjustment),
                _type_for_access_width_8616(2),
                codegen=codegen,
            ),
            codegen=codegen,
        )
    return structured_c.CIndexedVariable(aggregate_cvar, index_expr, codegen=codegen)


@cython.ccall
def _direct_stack_move_index_expr_8616(
    codegen: StructuredCodegenValue, fact: DirectStackMoveFact8616
) -> tuple[StructuredAstValue, cython.bint]:
    """Resolve the destination index expression; (expr, supported)."""
    if isinstance(fact.dst_index_global_displacement, int):
        return _direct_stack_move_global_index_cvar_8616(codegen, fact.dst_index_global_displacement), True
    if isinstance(fact.dst_index_stack_offset, int):
        return _resolve_direct_stack_update_cvar_8616(codegen, fact.dst_index_stack_offset, 2), True
    if isinstance(fact.dst_index_immediate, int):
        return structured_c.CConstant(
            fact.dst_index_immediate & 0xFFFF,
            _type_for_access_width_8616(2),
            codegen=codegen,
        ), True
    if fact.dst_index_scale != 1:
        return None, False
    return None, True


def _stack_aggregate_covers_fact_8616(codegen: StructuredCodegenValue, fact: DirectStackMoveFact8616) -> cython.bint:
    """Check whether proven aggregate facts already cover this destination."""
    raw_aggregate_facts = getattr(codegen, "_inertia_stack_aggregate_object_facts_8616", ()) or ()
    return any(
        isinstance(aggregate, StackAggregateObjectFact8616)
        and operator.eq(fact.width, aggregate.element_width)
        and fact.dst_offset in aggregate.indexed_offsets
        for aggregate in iter(raw_aggregate_facts)
    )


@cython.ccall
def _promote_dst_cvar_to_array_8616(
    codegen: StructuredCodegenValue, dst_cvar: StructuredAstValue, width: StructuredAstValue
) -> None:
    """Give a scalar destination cvar a fixed-size array type for indexed writes."""
    if not isinstance(dst_cvar, structured_c.CVariable) or _cvar_has_array_type_8616(dst_cvar):
        return
    element_type = _bind_type_to_codegen_arch_8616(codegen, _type_for_access_width_8616(width))
    element_width = max(int(width or 1), 1)
    stack_variable = dst_cvar.variable
    storage_size = stack_variable.size if isinstance(stack_variable, SimStackVariable) else None
    array_len = (
        storage_size // element_width
        if isinstance(storage_size, int) and storage_size >= element_width and storage_size % element_width == 0
        else 1
    )
    dst_cvar.variable_type = _bind_type_to_codegen_arch_8616(
        codegen,
        SimTypeFixedSizeArray(element_type, array_len),
    )
    codegen._inertia_codegen_decl_refresh_required_8616 = True


@cython.ccall
def _direct_stack_move_destination_expr_8616(
    codegen: StructuredCodegenValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
) -> StructuredAstValue | None:
    """Build a scalar or binary-proven indexed BP stack destination."""
    aggregate_destination: object
    index_expr: object
    index_expr, index_supported = _direct_stack_move_index_expr_8616(codegen, fact)
    if not index_supported:
        return None
    aggregate_destination = _stack_aggregate_destination_8616(codegen, fact, index_expr)
    if aggregate_destination is not None:
        return aggregate_destination
    if _stack_aggregate_covers_fact_8616(codegen, fact):
        return None
    if fact.dst_index_byte_scale != 1:
        return None
    if index_expr is None:
        return dst_cvar
    _promote_dst_cvar_to_array_8616(codegen, dst_cvar, fact.width)
    if fact.dst_index_scale != 1:
        index_expr = structured_c.CBinaryOp(
            "Mul",
            index_expr,
            structured_c.CConstant(
                fact.dst_index_scale,
                _type_for_access_width_8616(2),
                codegen=codegen,
            ),
            codegen=codegen,
        )
    return structured_c.CIndexedVariable(dst_cvar, index_expr, codegen=codegen)


@dataclass
class _TaggedAssignmentReplacer8616:
    """Replace tagged fragments only when their execution scopes can agree."""

    root: StructuredAstValue
    project: AngrProjectValue
    ins_addr: cython.longlong
    replacement_factory: StructuredAstValue
    allow_tagged_iterator_expression: cython.bint
    replace_all_matches: cython.bint
    remove_duplicate_tagged_assignments: cython.bint
    already_materialized_predicate: StructuredAstValue
    already_materialized_attr: object
    candidate_position_predicate: Callable[[StructuredAstValue], bool] | None
    seen: object = field(default_factory=set)
    changed: cython.bint = False
    materialized: cython.bint = False

    def _already_materialized_8616(self, node: StructuredAstValue) -> cython.bint:
        """Record an already-materialized match without replacing it."""
        if callable(self.already_materialized_predicate) and self.already_materialized_predicate(node):
            if self.already_materialized_attr:
                setattr(self.root, self.already_materialized_attr, True)
            self.materialized = True
            return True
        return False

    def _replace_matching_8616(self, node: StructuredAstValue, tags: StructuredAstValue) -> StructuredAstValue:
        """Apply the factory to a matched tagged node."""
        if self.materialized and not self.replace_all_matches:
            return node
        replacement = self.replacement_factory(tags)
        if _is_same_stack_move_assignment_8616(
            node,
            getattr(replacement, "lhs", None),
            getattr(replacement, "rhs", None),
        ):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return node
        self.materialized = True
        self.changed = True
        return replacement

    def transform(self, node: StructuredAstValue) -> StructuredAstValue:
        """Replace a tagged CAssignment via the factory."""
        if isinstance(node, structured_c.CAssignment) and _node_has_instruction_address_8616(
            node, self.project, self.ins_addr
        ):
            if self.candidate_position_predicate is not None and not self.candidate_position_predicate(node):
                return node
            if self._already_materialized_8616(node):
                return node
            return self._replace_matching_8616(node, node.tags)
        return node

    def transform_iterator(self, node: object) -> StructuredAstValue:
        """Replace a tagged iterator expression when the pass allows it."""
        if not self.allow_tagged_iterator_expression:
            return node
        if isinstance(node, structured_c.CAssignment):
            return self.transform(node)
        if node is not None and _node_has_instruction_address_8616(node, self.project, self.ins_addr):
            if self._already_materialized_8616(node):
                return node
            return self._replace_matching_8616(node, getattr(node, "tags", None))
        return node

    def is_duplicate_tagged_assignment(self, node: StructuredAstValue) -> cython.bint:
        """Return whether the node is a later duplicate tagged assignment to drop."""
        return (
            self.remove_duplicate_tagged_assignments
            and self.materialized
            and not self.replace_all_matches
            and isinstance(node, structured_c.CAssignment)
            and _node_has_instruction_address_8616(node, self.project, self.ins_addr)
            and (self.candidate_position_predicate is None or self.candidate_position_predicate(node))
        )

    def replace_children(self, node: object) -> None:
        """Apply the transform to every child of a structured node."""
        if node is None or not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return
        node_id = id(node)
        if node_id in self.seen:
            return
        self.seen.add(node_id)
        self._replace_attr_children_8616(node)
        self._replace_case_children_8616(node)
        self._replace_pair_children_8616(node)

    def _replace_list_items_8616(self, value: object) -> None:
        """Transform list children, dropping duplicate tagged assignments."""
        item: object
        new_items = []
        list_changed = False
        for item in tuple(value):
            if self.is_duplicate_tagged_assignment(item):
                self.changed = True
                list_changed = True
                continue
            replacement = self.transform(item)
            if replacement is not item:
                list_changed = True
            self.replace_children(replacement)
            new_items.append(replacement)
        if list_changed:
            value[:] = new_items

    def _replace_attr_children_8616(self, node: StructuredAstValue) -> None:
        """Transform each child-bearing attribute in place."""
        value: object
        attr: object
        for attr in (
            "statements",
            "lhs",
            "rhs",
            "operand",
            "expr",
            "stmts",
            "init",
            "initializer",
            "iftrue",
            "iffalse",
            "iteration",
            "iterator",
            "body",
            "else_node",
        ):
            if not hasattr(node, attr):
                continue
            with contextlib.suppress(Exception):
                value = getattr(node, attr)
                if isinstance(value, list):
                    self._replace_list_items_8616(value)
                elif value is not None:
                    replacement = self.transform_iterator(value) if attr in {"iteration", "iterator"} else self.transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        value = replacement
                    self.replace_children(value)

    def _replace_case_children_8616(self, node: StructuredAstValue) -> None:
        """Transform switch-case bodies in place."""
        cases: object
        item: object
        cases = getattr(node, "cases", None)
        if isinstance(cases, (list, tuple)):
            new_cases = []
            cases_changed = False
            for item in tuple(cases):
                if not isinstance(item, tuple) or len(item) != 2:
                    new_cases.append(item)
                    continue
                case_value, case_body = item
                replacement_body = self.transform(case_body)
                if replacement_body is not case_body:
                    cases_changed = True
                self.replace_children(replacement_body)
                new_cases.append((case_value, replacement_body))
            if cases_changed:
                node.cases = new_cases

    def _replace_pair_children_8616(self, node: StructuredAstValue) -> None:
        """Transform condition/body pair bodies in place."""
        condition_and_nodes: object
        body: object
        condition: object
        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            new_pairs = []
            pair_changed = False
            for condition, body in tuple(condition_and_nodes):
                new_condition = condition
                new_body = self.transform(body)
                if new_body is not body:
                    pair_changed = True
                self.replace_children(new_body)
                new_pairs.append((new_condition, new_body))
            if pair_changed:
                with contextlib.suppress(Exception):
                    node.condition_and_nodes = new_pairs


def _replace_tagged_assignment_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    replacement_factory: StructuredAstValue,
    *,
    allow_tagged_iterator_expression: cython.bint = False,
    replace_all_matches: cython.bint = False,
    remove_duplicate_tagged_assignments: cython.bint = False,
    already_materialized_predicate: StructuredAstValue = None,
    already_materialized_attr: object = None,
    candidate_position_predicate: Callable[[StructuredAstValue], bool] | None = None,
) -> cython.bint:
    """Replace tagged fragments only when their execution scopes can agree."""
    from .stack_update_scope_guard import require_stack_update_scope_8616

    if allow_tagged_iterator_expression and remove_duplicate_tagged_assignments:
        require_stack_update_scope_8616(
            root, ins_addr,
            lambda node: _node_has_instruction_address_8616(node, project, ins_addr),
        )
    replacer = _TaggedAssignmentReplacer8616(
        root=root,
        project=project,
        ins_addr=ins_addr,
        replacement_factory=replacement_factory,
        allow_tagged_iterator_expression=allow_tagged_iterator_expression,
        replace_all_matches=replace_all_matches,
        remove_duplicate_tagged_assignments=remove_duplicate_tagged_assignments,
        already_materialized_predicate=already_materialized_predicate,
        already_materialized_attr=already_materialized_attr,
        candidate_position_predicate=candidate_position_predicate,
    )
    replacement_root = replacer.transform(root)
    if replacement_root is not root:
        return True
    replacer.replace_children(root)
    return replacer.changed


@cython.dataclasses.dataclass
class _TaggedStatementReplacer8616:
    """Replace a machine-tagged assignment in lists or control attributes."""

    project: StructuredAstValue
    ins_addr: cython.longlong
    replacement_factory: StructuredAstValue
    remove_duplicate_tagged_assignments: cython.bint = False
    changed: cython.bint = False
    materialized: cython.bint = False
    seen: object = field(default_factory=set)

    @cython.ccall
    def _visit_statement_list_8616(self, statements: object) -> None:
        """Replace or drop tagged assignments inside a statement list."""
        stmt: object
        new_statements = []
        list_changed = False
        for stmt in tuple(statements):
            if (
                self.materialized
                and self.remove_duplicate_tagged_assignments
                and isinstance(stmt, structured_c.CAssignment)
                and _node_has_instruction_address_8616(stmt, self.project, self.ins_addr)
            ):
                self.changed = True
                list_changed = True
                continue
            if (
                not self.materialized
                and isinstance(stmt, structured_c.CAssignment)
                and _node_has_instruction_address_8616(stmt, self.project, self.ins_addr)
            ):
                replacement = self.replacement_factory(stmt.tags)
                self.materialized = True
                if _is_same_stack_move_assignment_surface_8616(stmt, replacement):
                    new_statements.append(stmt)
                    self.visit(stmt)
                else:
                    self.changed = True
                    list_changed = True
                    new_statements.append(replacement)
                    self.visit(replacement)
                continue
            self.visit(stmt)
            new_statements.append(stmt)
        if list_changed:
            statements[:] = new_statements

    @cython.ccall
    def _visit_control_attr_8616(self, node: StructuredAstValue, attr: object) -> None:
        """Replace or drop a tagged assignment held in a control attribute."""
        child: object
        child = None
        with contextlib.suppress(Exception):
            child = getattr(node, attr, None)
        if child is None:
            return
        if (
            not self.materialized
            and isinstance(child, structured_c.CAssignment)
            and _node_has_instruction_address_8616(child, self.project, self.ins_addr)
        ):
            replacement = self.replacement_factory(child.tags)
            if _is_same_stack_move_assignment_surface_8616(child, replacement):
                self.materialized = True
                self.visit(child)
                return
            setattr(node, attr, replacement)
            child = replacement
            self.materialized = True
            self.changed = True
        elif (
            self.materialized
            and self.remove_duplicate_tagged_assignments
            and isinstance(child, structured_c.CAssignment)
            and _node_has_instruction_address_8616(child, self.project, self.ins_addr)
        ):
            setattr(node, attr, None)
            self.changed = True
            return
        self.visit(child)

    @cython.ccall
    def visit(self, node: object) -> None:
        """Replace the first assignment carrying the requested instruction tag."""
        pairs: object
        statements: object
        _condition: object
        attr: object
        body: object
        if node is None or id(node) in self.seen:
            return
        if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return
        self.seen.add(id(node))

        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            self._visit_statement_list_8616(statements)

        for attr in ("body", "else_node", "initializer", "init", "iteration", "iterator"):
            self._visit_control_attr_8616(node, attr)

        pairs = None
        with contextlib.suppress(Exception):
            pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.visit(body)


@cython.ccall
def _replace_tagged_statement_assignment_8616(
    root: StructuredAstValue,
    project: StructuredAstValue,
    ins_addr: cython.longlong,
    replacement_factory: StructuredAstValue,
    *,
    remove_duplicate_tagged_assignments: cython.bint = False,
) -> cython.bint:
    """Replace a machine-tagged assignment in statement lists or structured control attributes."""
    replacer = _TaggedStatementReplacer8616(
        project,
        ins_addr,
        replacement_factory,
        remove_duplicate_tagged_assignments=remove_duplicate_tagged_assignments,
    )
    replacer.visit(root)
    return replacer.changed


@cython.ccall
def _dirty_stack_update_candidates_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackUpdateFact8616,
    cvar: StructuredAstValue,
    query_index: object,
) -> tuple[list[tuple[list[StructuredAstValue], cython.longlong, StructuredAstValue, StructuredAstValue]], list[tuple[object, object, object, object]]]:
    """Collect exact dirty-RHS stack-update candidates and observed diagnostics."""
    index: object
    owner: object
    statement: object
    if query_index is not None:
        query_index.require_root(root)
    candidates: list[
        tuple[list[StructuredAstValue], cython.longlong, structured_c.CAssignment, structured_c.CDirtyExpression]
    ] = []
    observed: list[tuple[object, object, object, object]] = []
    nodes = query_index.nodes if query_index is not None else _iter_structured_c_nodes_8616(root)
    for owner in nodes:
        if not isinstance(owner, structured_c.CStatements):
            continue
        for index, statement in enumerate(tuple(owner.statements or ())):
            if not isinstance(statement, structured_c.CAssignment):
                continue
            if not _same_stack_cvar_8616(statement.lhs, cvar):
                continue
            dirty_rhs = _strip_casts_8616(statement.rhs)
            if not isinstance(dirty_rhs, structured_c.CDirtyExpression):
                continue
            # Diagnostic fields belong to angr's dynamic dirty-expression boundary.
            dirty = dirty_rhs.dirty
            observed.append(
                (
                    statement.tags,
                    dirty_rhs.tags,
                    getattr(dirty, "varid", None),
                    getattr(dirty, "name", None),
                )
            )
            if not (
                _node_has_instruction_address_8616(statement, project, fact.ins_addr)
                or _node_has_instruction_address_8616(dirty_rhs, project, fact.ins_addr)
            ):
                continue
            candidates.append((owner.statements, index, statement, dirty_rhs))
    return candidates, observed


@cython.ccall
def _replace_unique_tagged_dirty_stack_update_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackUpdateFact8616,
    cvar: StructuredAstValue,
    replacement_factory: Callable[[StructuredAstValue], StructuredAstValue],
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> cython.bint:
    """Replace one rendered dirty RHS carrying an exact stack-update tag.

    angr may preserve a direct BP-relative update as ``stack_slot = dirty``
    while attaching the machine instruction address only to the dirty RHS.
    The ordinary tagged-assignment path cannot see that nested tag.  Consume
    it only when one rendered assignment has both the proven stack identity
    and the exact instruction tag; duplicate candidates remain untouched.
    """
    candidates, observed = _dirty_stack_update_candidates_8616(root, project, fact, cvar, query_index)
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[direct-stack-update-dirty] ins=%#x offset=%d observed=%r exact_candidates=%d",
            fact.ins_addr,
            fact.offset,
            tuple(observed),
            len(candidates),
        )
    if len(candidates) != 1:
        return False
    statements, index, statement, dirty_rhs = candidates[0]
    tags = (
        statement.tags
        if _node_has_instruction_address_8616(statement, project, fact.ins_addr)
        else dirty_rhs.tags
    )
    statements[index] = replacement_factory(tags)
    return True


@cython.dataclasses.dataclass
class _TaggedCallReplacer8616:
    """Project an owned call result to stack storage while retaining word carriers."""

    root: StructuredAstValue
    project: StructuredAstValue
    call_ins_addr: StructuredAstValue
    call_target: StructuredAstValue
    accepted_call_names: StructuredAstValue
    replacement_factory: StructuredAstValue
    seen: object = field(default_factory=set)
    materialized_assignment: StructuredAstValue = None
    untagged_candidates: object = field(default_factory=list)
    call_stmt_summaries: object = field(default_factory=list)

    @cython.ccall
    def call_statement_identity_8616(
        self,
        stmt: StructuredAstValue,
    ) -> tuple[str | None, cython.bint, cython.bint, cython.bint]:
        """Return name, target match, tag state, and direct-call shape."""
        call_expr: object
        observed_name: object
        tagged = _node_has_instruction_address_8616(stmt, self.project, self.call_ins_addr)
        observed_name = _function_call_name_8616(stmt)
        call_expr = None
        if isinstance(stmt, structured_c.CAssignment):
            rhs = stmt.rhs
            if (
                _function_call_name_8616(rhs) is not None
                or _function_call_target_addr_8616(rhs) is not None
            ):
                call_expr = rhs
        elif isinstance(stmt, structured_c.CExpressionStatement):
            call_expr = stmt.expr
        elif isinstance(stmt, structured_c.CReturn):
            call_expr = stmt.retval
        elif isinstance(stmt, structured_c.CFunctionCall):
            call_expr = stmt
        if call_expr is not None:
            tagged = tagged or _node_has_instruction_address_8616(
                call_expr, self.project, self.call_ins_addr
            )
        if observed_name is None and call_expr is not None:
            observed_name = _function_call_name_8616(call_expr)
        target_matches = _function_call_target_matches_8616(
            call_expr,
            self.project,
            self.call_target,
        )
        return observed_name, target_matches, tagged, call_expr is not None

    @cython.ccall
    def is_target_call_statement(self, stmt: StructuredAstValue) -> cython.bint:
        """Check whether a tagged statement is the call being materialized."""
        observed_name: object
        if (
            isinstance(stmt, structured_c.CAssignment)
            and isinstance(_c_expr_stack_offset_8616(stmt.lhs), int)
        ):
            # A stack-local low-half assignment is a carrier, not the
            # full-width destination. Materialize the wide assignment first,
            # then consume the exact carrier below. Word SSA/register carriers
            # retain their definitions through the call-result bridge below.
            return False
        observed_name, target_matches, tagged, has_direct_call = (
            self.call_statement_identity_8616(stmt)
        )
        if not tagged or not has_direct_call:
            return False
        name_matches = observed_name is not None and (
            not self.accepted_call_names or observed_name in self.accepted_call_names
        )
        return target_matches or name_matches or isinstance(self.call_target, int)

    @cython.ccall
    def is_unique_untagged_target_call_statement(self, stmt: StructuredAstValue) -> cython.bint:
        """Check whether an untagged call statement uniquely matches the requested call."""
        observed_name: object
        if (
            isinstance(stmt, structured_c.CAssignment)
            and _cvar_register_name_8616(_strip_casts_8616(stmt.lhs)) != "ax"
        ):
            return False
        observed_name, target_matches, tagged, has_direct_call = (
            self.call_statement_identity_8616(stmt)
        )
        if tagged or not has_direct_call:
            return False
        name_matches = observed_name is not None and (
            not self.accepted_call_names or observed_name in self.accepted_call_names
        )
        return target_matches or name_matches

    @cython.ccall
    def visit(self, node: object) -> None:
        """Replace the tagged call statement with the stack assignment."""
        statements: object
        if node is None or id(node) in self.seen:
            return
        if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            self._visit_statements_8616(statements)
        self._visit_child_links_8616(node)

    def _visit_statements_8616(self, statements: object) -> None:
        """Replace the matching tagged call in one statement list."""
        index: object
        stmt: object
        for index, stmt in enumerate(tuple(statements)):
            prefer_later_non_assignment = isinstance(stmt, structured_c.CAssignment) and any(
                not isinstance(candidate_stmt, structured_c.CAssignment)
                and self.is_target_call_statement(candidate_stmt)
                for candidate_stmt in iter(tuple(statements)[index + 1 :])
            )
            if (
                self.materialized_assignment is None
                and not prefer_later_non_assignment
                and self.is_target_call_statement(stmt)
            ):
                replacement = self.replacement_factory({"ins_addr": self.call_ins_addr})
                if not isinstance(replacement, structured_c.CAssignment):
                    continue
                statements[index] = preserve_word_call_carrier_8616(stmt, replacement)
                self.materialized_assignment = replacement
                self.visit(replacement)
                continue
            self.visit(stmt)

    @cython.ccall
    def _visit_child_links_8616(self, node: StructuredAstValue) -> None:
        """Recurse into loop fields and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node", "initializer", "init", "iteration", "iterator"):
            child = None
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                self.visit(child)
        pairs = None
        with contextlib.suppress(Exception):
            pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.visit(body)

    @cython.ccall
    def collect_untagged(self, node: object) -> None:
        """Collect fallback untagged call statements matching the same call name."""
        statements: object
        index: object
        stmt: object
        if node is None or id(node) in self.seen:
            return
        if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for index, stmt in enumerate(tuple(statements)):
                if self.is_unique_untagged_target_call_statement(stmt):
                    self.untagged_candidates.append((statements, index))
                self.collect_untagged(stmt)
        self._collect_untagged_children_8616(node)

    @cython.ccall
    def _collect_untagged_children_8616(self, node: StructuredAstValue) -> None:
        """Recurse the untagged collector into child links and pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node", "initializer", "init", "iteration", "iterator"):
            child = None
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                self.collect_untagged(child)
        pairs = None
        with contextlib.suppress(Exception):
            pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.collect_untagged(body)

    @cython.ccall
    def collect_call_stmt_summaries(self, node: object) -> None:
        """Collect debug summaries for call statements when no fallback matched."""
        statements: object
        stmt: object
        if node is None or id(node) in self.seen:
            return
        if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for stmt in tuple(statements):
                self._collect_stmt_summary_8616(stmt)
        self._collect_summary_children_8616(node)

    def _collect_stmt_summary_8616(self, stmt: StructuredAstValue) -> None:
        """Record one statement's call names and shape for the debug dump."""
        call_names = tuple(
            name
            for name in iter((
                _function_call_name_8616(call_node)
                for call_node in builtins.iter(_iter_structured_c_nodes_8616(stmt))
                if isinstance(call_node, structured_c.CFunctionCall)
            ))
            if isinstance(name, str)
        )
        if call_names:
            self.call_stmt_summaries.append(
                (
                    type(stmt).__name__,
                    call_names,
                    getattr(stmt, "tags", None),
                    tuple(
                        attr
                        for attr in iter(("expr", "retval", "body", "statements", "stmts", "condition"))
                        if hasattr(stmt, attr)
                    ),
                )
            )
        self.collect_call_stmt_summaries(stmt)

    @cython.ccall
    def _collect_summary_children_8616(self, node: StructuredAstValue) -> None:
        """Recurse the summary collector into child links and pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node", "initializer", "init", "iteration", "iterator", "stmts"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                self.collect_call_stmt_summaries(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.collect_call_stmt_summaries(body)

    @cython.ccall
    def _debug_untagged_mismatch_8616(self) -> None:
        """Emit call-statement summaries when the untagged fallback is ambiguous."""
        if not (
            os.environ.get("INERTIA_DEBUG_STACK_NOISE") and len(self.untagged_candidates) != 1
        ):
            return
        self.seen.clear()
        self.collect_call_stmt_summaries(self.root)
        log.warning(
            "[direct-stack-mov-idiv-call] candidate-count=%d ins=%s target=%s accepted=%r summaries=%r",
            len(self.untagged_candidates),
            self.call_ins_addr,
            self.call_target,
            tuple(sorted(self.accepted_call_names)),
            tuple(self.call_stmt_summaries[:16]),
        )

    @cython.ccall
    def _untagged_fallback_8616(self, exact_callsite_present: cython.bint) -> None:
        """Replace the unique untagged matching call statement if present."""
        if self.materialized_assignment is not None or exact_callsite_present:
            return
        self.seen.clear()
        self.collect_untagged(self.root)
        self._debug_untagged_mismatch_8616()
        if len(self.untagged_candidates) == 1:
            statements, index = self.untagged_candidates[0]
            replacement = self.replacement_factory({"ins_addr": self.call_ins_addr})
            if isinstance(replacement, structured_c.CAssignment):
                statements[index] = replacement
                self.materialized_assignment = replacement


def _replace_tagged_call_statement_with_stack_assignment_8616(
    root: StructuredAstValue,
    project: object,
    call_ins_addr: int | None,
    call_name: object,
    replacement_factory: Callable[[StructuredAstValue], StructuredAstValue],
    *,
    call_target: int | None = None,
) -> structured_c.CAssignment | None:
    """Project an owned call result to stack storage while retaining word carriers."""
    if not isinstance(call_ins_addr, int):
        return None
    accepted_call_names: set[str] = set()
    if isinstance(call_name, str) and call_name:
        accepted_call_names.add(call_name.lstrip("_"))
    if isinstance(call_target, int) and project is not None:
        with contextlib.suppress(Exception):
            resolved_name, _callee, _resolved_target = _callee_name_for_direct_stack_move_8616(project, call_target)
            if isinstance(resolved_name, str) and resolved_name:
                accepted_call_names.add(resolved_name.lstrip("_"))
    replacer = _TaggedCallReplacer8616(
        root=root,
        project=project,
        call_ins_addr=call_ins_addr,
        call_target=call_target,
        accepted_call_names=accepted_call_names,
        replacement_factory=replacement_factory,
    )
    replacer.visit(root)
    exact_callsite_present = any(
        isinstance(node, structured_c.CFunctionCall)
        and _node_has_instruction_address_8616(node, project, call_ins_addr)
        for node in builtins.iter(_iter_structured_c_nodes_8616(root))
    )
    replacer._untagged_fallback_8616(exact_callsite_present)
    return replacer.materialized_assignment


@cython.dataclasses.dataclass
class _TaggedReloadReplacer8616:
    """Replace one tagged reload, distinguishing an idempotent existing value."""

    project: StructuredAstValue
    ins_addr: StructuredAstValue
    dst_reg_name: StructuredAstValue
    source_cvar: StructuredAstValue
    seen: object
    placement: StructuredAstValue = _DirectStackReloadPlacement8616.NO_MATCH

    @cython.ccall
    def transform(self, node: StructuredAstValue) -> StructuredAstValue:
        """Replace the matching tagged reload's RHS with the stack source."""
        if not isinstance(node, structured_c.CAssignment):
            return node
        if not _node_has_instruction_address_8616(node, self.project, self.ins_addr):
            return node
        lhs = _strip_casts_8616(node.lhs)
        if operator.ne(_cvar_register_name_8616(lhs), self.dst_reg_name):
            return node
        if self.placement.present:
            return node
        if _same_stack_cvar_8616(node.rhs, self.source_cvar):
            self.placement = _DirectStackReloadPlacement8616.ALREADY_PRESENT
            return node
        self.placement = _DirectStackReloadPlacement8616.MATERIALIZED
        return structured_c.CAssignment(
            node.lhs,
            self.source_cvar,
            codegen=getattr(self.source_cvar, "codegen", None),
            tags=node.tags,
        )

    @cython.ccall
    def replace_children(self, node: object) -> None:
        """Apply the transform to every child, stopping once placed."""
        if self.placement.present or node is None or not type(node).__module__.startswith(
            "angr.analyses.decompiler.structured_codegen"
        ):
            return
        node_id = id(node)
        if node_id in self.seen:
            return
        self.seen.add(node_id)
        self._replace_attr_children_8616(node)
        self._replace_pair_children_8616(node)

    @cython.ccall
    def _replace_attr_children_8616(self, node: StructuredAstValue) -> None:
        """Transform each child-bearing attribute in place."""
        value: object
        attr: object
        index: object
        item: object
        for attr in (
            "statements",
            "lhs",
            "rhs",
            "operand",
            "expr",
            "stmts",
            "init",
            "initializer",
            "condition",
            "cond",
            "args",
            "iftrue",
            "iffalse",
            "iteration",
            "iterator",
            "body",
            "else_node",
        ):
            if not hasattr(node, attr):
                continue
            with contextlib.suppress(Exception):
                value = getattr(node, attr)
                if isinstance(value, list):
                    for index, item in enumerate(tuple(value)):
                        if self.placement.present:
                            return
                        replacement = self.transform(item)
                        if replacement is not item:
                            value[index] = replacement
                        self.replace_children(value[index])
                elif value is not None:
                    replacement = self.transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        value = replacement
                    self.replace_children(value)

    @cython.ccall
    def _replace_pair_children_8616(self, node: StructuredAstValue) -> None:
        """Transform condition/body pairs in place."""
        condition_and_nodes: object
        body: object
        condition: object
        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            new_pairs = []
            pair_changed = False
            for condition, body in tuple(condition_and_nodes):
                new_condition = self.transform(condition)
                new_body = self.transform(body)
                if new_condition is not condition or new_body is not body:
                    pair_changed = True
                self.replace_children(new_condition)
                self.replace_children(new_body)
                new_pairs.append((new_condition, new_body))
            if pair_changed:
                with contextlib.suppress(Exception):
                    node.condition_and_nodes = new_pairs


@cython.ccall
def _indexed_reload_candidate_8616(
    indexed_candidates: StructuredAstValue,
    project: StructuredAstValue,
    fact: DirectStackReloadFact8616,
    source_cvar: StructuredAstValue,
) -> _DirectStackReloadPlacement8616:
    """Match or replace a reload through the tagged-assignment index."""
    candidate: object
    for candidate in indexed_candidates:
        if not _node_has_instruction_address_8616(
            candidate,
            project,
            fact.ins_addr,
        ):
            continue
        lhs = _strip_casts_8616(candidate.lhs)
        if operator.ne(_cvar_register_name_8616(lhs), fact.dst_reg_name):
            continue
        if _same_stack_cvar_8616(candidate.rhs, source_cvar):
            return _DirectStackReloadPlacement8616.ALREADY_PRESENT
        candidate.rhs = source_cvar
        return _DirectStackReloadPlacement8616.MATERIALIZED
    return _DirectStackReloadPlacement8616.NO_MATCH


@cython.ccall
def _replace_tagged_register_reload_assignment_8616(
    root: StructuredAstValue,
    project: StructuredAstValue,
    fact: DirectStackReloadFact8616,
    source_cvar: StructuredAstValue,
    *,
    candidate_index: TaggedAssignmentAddressIndex8616 | None = None,
) -> _DirectStackReloadPlacement8616:
    """Replace one tagged reload, distinguishing an idempotent existing value."""
    indexed_candidates: object
    candidate_addresses = _candidate_ins_addrs_8616(project, fact.ins_addr)
    if candidate_index is not None:
        indexed_candidates = candidate_index.candidate_assignments(candidate_addresses)
        if indexed_candidates is not None:
            return _indexed_reload_candidate_8616(
                indexed_candidates, project, fact, source_cvar
            )
    replacer = _TaggedReloadReplacer8616(
        project=project,
        ins_addr=fact.ins_addr,
        dst_reg_name=fact.dst_reg_name,
        source_cvar=source_cvar,
        seen=set(),
    )
    replacement_root = replacer.transform(root)
    if replacement_root is not root:
        return cast("_DirectStackReloadPlacement8616", replacer.placement)
    replacer.replace_children(root)
    return cast("_DirectStackReloadPlacement8616", replacer.placement)


@cython.ccall
def _c_expr_stack_offset_8616(node: StructuredAstValue) -> int | None:
    if isinstance(node, structured_c.CVariable):
        variable = node.variable
        if isinstance(variable, SimStackVariable) and getattr(variable, "base", None) == "bp":
            offset = _canonical_stack_offset_8616(variable.offset)
            return offset if isinstance(offset, int) else None
    return None


def _expr_reads_stack_offset_8616(node: StructuredAstValue, offset: cython.longlong) -> cython.bint:
    seen: set[cython.longlong] = set()

    def walk(current: object) -> cython.bint:
        attr: object
        if current is None:
            return False
        if isinstance(current, (list, tuple)):
            return any(walk(item) for item in iter(current))
        marker = id(current)
        if marker in seen:
            return False
        seen.add(marker)
        if operator.eq(_c_expr_stack_offset_8616(current), offset):
            return True
        if not type(current).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return False
        for attr in (
            "lhs",
            "rhs",
            "operand",
            "expr",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "initializer",
            "init",
            "iterator",
            "iteration",
            "body",
            "else_node",
            "statements",
            "condition_and_nodes",
        ):
            if hasattr(current, attr):
                with contextlib.suppress(Exception):
                    if walk(getattr(current, attr)):
                        return True
        return False

    return walk(node)


@cython.ccall
def _assignment_lhs_stack_offset_8616(node: StructuredAstValue) -> int | None:
    if not isinstance(node, structured_c.CAssignment):
        return None
    return _c_expr_stack_offset_8616(node.lhs)


def _stack_update_falls_through_to_loop_guard_8616(
    project: AngrProjectValue,
    function: StructuredAstValue,
    fact: DirectStackUpdateFact8616,
    loop_guard_addr: cython.longlong,
) -> cython.bint:
    """Prove that a stack update falls through to a guard read of the same slot."""
    guard_addr: object
    guard_insn: object
    ins_addr: object
    update_addr: object
    update_insn: object
    update_size: object
    insn: object
    fact_addrs = frozenset(_candidate_ins_addrs_8616(project, fact.ins_addr))
    guard_addrs = frozenset(_candidate_ins_addrs_8616(project, loop_guard_addr))
    update_insn = None
    guard_insn = None
    for insn in _direct_global_update_ordered_insns_8616(project, function):
        # Capstone instructions are a third-party dynamic boundary.
        ins_addr = getattr(insn, "address", None)
        if not isinstance(ins_addr, int):
            continue
        if ins_addr in fact_addrs:
            update_insn = insn
        if ins_addr in guard_addrs:
            guard_insn = insn
    if update_insn is None or guard_insn is None:
        return False
    update_addr = getattr(update_insn, "address", None)
    update_size = getattr(update_insn, "size", None)
    guard_addr = getattr(guard_insn, "address", None)
    if (
        not isinstance(update_addr, int)
        or not isinstance(update_size, int)
        or update_size <= 0
        or not isinstance(guard_addr, int)
        or operator.ne(update_addr + update_size, guard_addr)
    ):
        return False
    operands = _boundary_tuple_8616(getattr(guard_insn, "operands", ()) or ())
    return any(
        operator.eq(_stack_mem_operand_offset_width_8616(operand), (fact.offset, fact.width))
        for operand in iter(operands)
    )


@cython.ccall
def _stack_update_fallthrough_guard_addr_8616(
    project: AngrProjectValue,
    function: StructuredAstValue,
    fact: DirectStackUpdateFact8616,
) -> int | None:
    """Return the exact adjacent guard address proven for one stack update."""
    update_addr: object
    update_size: object
    insn: object
    fact_addrs = _candidate_ins_addrs_8616(project, fact.ins_addr)
    for insn in _direct_global_update_ordered_insns_8616(project, function):
        # Capstone instructions are a third-party dynamic boundary.
        update_addr = getattr(insn, "address", None)
        update_size = getattr(insn, "size", None)
        if (
            not isinstance(update_addr, int)
            or update_addr not in fact_addrs
            or not isinstance(update_size, int)
            or update_size <= 0
        ):
            continue
        guard_addr = update_addr + update_size
        if _stack_update_falls_through_to_loop_guard_8616(
            project,
            function,
            fact,
            guard_addr,
        ):
            return guard_addr
    return None


def _node_contains_instruction_address_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
) -> cython.bint:
    """Return whether an exact instruction tag occurs within one C subtree."""
    return any(
        _node_has_instruction_address_8616(candidate, project, ins_addr)
        for candidate in builtins.iter(_iter_structured_c_nodes_8616(node))
    )


@cython.ccall
def _transparent_statement_slots_8616(
    body: StructuredAstValue,
) -> tuple[tuple[list[StructuredAstValue], cython.longlong, StructuredAstValue], ...]:
    """Flatten only sequencing containers while retaining replacement slots."""
    index: object
    statement: object
    if not isinstance(body, structured_c.CStatements):
        return ()
    slots: list[tuple[list[StructuredAstValue], cython.longlong, StructuredAstValue]] = []
    for index, statement in enumerate(tuple(body.statements or ())):
        if isinstance(statement, structured_c.CStatements):
            slots.extend(_transparent_statement_slots_8616(statement))
        else:
            slots.append((body.statements, index, statement))
    return tuple(slots)


def _while_loop_update_candidates_8616(
    loop: StructuredAstValue,
    project: AngrProjectValue,
    guard_addr: cython.longlong,
    cvar: StructuredAstValue,
) -> object:
    """Return the unique post-guard dirty update inside one while loop."""
    index: object
    owner: object
    slot: object
    statement: object
    slots = _transparent_statement_slots_8616(loop.body)
    guard_indexes = tuple(
        index
        for index, (_owner, _slot, statement) in builtins.iter(enumerate(slots))
        if _node_contains_instruction_address_8616(
            statement,
            project,
            guard_addr,
        )
    )
    if len(guard_indexes) != 1:
        return []
    guard_index = guard_indexes[0]
    loop_candidates: list[
        tuple[list[StructuredAstValue], cython.longlong, structured_c.CAssignment]
    ] = []
    for index, (owner, slot, statement) in enumerate(slots):
        if index <= guard_index or not isinstance(
            statement,
            structured_c.CAssignment,
        ):
            continue
        if not _same_stack_cvar_8616(statement.lhs, cvar):
            continue
        if not isinstance(
            _strip_casts_8616(statement.rhs),
            structured_c.CDirtyExpression,
        ):
            continue
        loop_candidates.append((owner, slot, statement))
    if len(loop_candidates) == 1:
        return loop_candidates
    return []


@cython.ccall
def _replace_proven_while_stack_update_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    function: StructuredAstValue,
    fact: DirectStackUpdateFact8616,
    cvar: StructuredAstValue,
    replacement_factory: Callable[[StructuredAstValue], StructuredAstValue],
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> cython.bint:
    """Replace one dirty while latch anchored by an adjacent binary guard."""
    loop: object
    if query_index is not None:
        query_index.require_root(root)
    guard_addr = _stack_update_fallthrough_guard_addr_8616(
        project,
        function,
        fact,
    )
    if not isinstance(guard_addr, int):
        return False
    candidates: list[
        tuple[list[StructuredAstValue], cython.longlong, structured_c.CAssignment]
    ] = []
    nodes = query_index.nodes if query_index is not None else _iter_structured_c_nodes_8616(root)
    for loop in nodes:
        if isinstance(loop, structured_c.CWhileLoop):
            candidates.extend(
                _while_loop_update_candidates_8616(loop, project, guard_addr, cvar)
            )
    if len(candidates) != 1:
        return False
    owner, slot, statement = candidates[0]
    owner[slot] = replacement_factory(
        statement.tags or {"ins_addr": fact.ins_addr},
    )
    return True


@cython.ccall
def _materialize_proven_stack_update_loop_iterator_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    function: StructuredAstValue,
    fact: DirectStackUpdateFact8616,
    cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
    replacement_factory: Callable[[StructuredAstValue], StructuredAstValue],
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> DirectStackLoopIteratorMaterialization8616:
    """Bind an adjacent binary latch update to exactly one structured ``for`` loop."""
    condition_range: object
    node: object
    if query_index is not None:
        query_index.require_root(root)
    guard_addr = _stack_update_fallthrough_guard_addr_8616(
        project,
        function,
        fact,
    )
    if not isinstance(guard_addr, int):
        return DirectStackLoopIteratorMaterialization8616(False, False)
    candidates: list[structured_c.CForLoop] = []
    nodes = query_index.nodes if query_index is not None else _iter_structured_c_nodes_8616(root)
    for node in nodes:
        if not isinstance(node, structured_c.CForLoop):
            continue
        if operator.ne(_assignment_lhs_stack_offset_8616(node.initializer), fact.offset):
            continue
        condition = node.condition
        condition_range = _instruction_addr_range_in_node_8616(
            condition,
            project,
            fact.ins_addr,
        )
        if (
            condition_range is None
            or not condition_range[0] <= guard_addr <= condition_range[1]
            or not _expr_reads_stack_offset_8616(condition, fact.offset)
        ):
            continue
        candidates.append(node)
    if len(candidates) != 1:
        return DirectStackLoopIteratorMaterialization8616(False, False)
    loop = candidates[0]
    iterator = loop.iterator
    if _is_same_stack_update_assignment_8616(
        iterator,
        cvar,
        fact.delta,
        source_expr,
        operation=fact.operation,
    ) and _node_has_instruction_address_8616(iterator, project, fact.ins_addr):
        return DirectStackLoopIteratorMaterialization8616(True, False)
    loop.iterator = replacement_factory({"ins_addr": fact.ins_addr})
    return DirectStackLoopIteratorMaterialization8616(True, True)


@cython.ccall
def _remove_conflicting_tagged_stack_update_assignments_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackUpdateFact8616,
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> cython.longlong:
    """Remove statement-list stack aliases disproven by a preserved loop update."""
    statements: object
    node: object
    statement: object
    if query_index is not None:
        query_index.require_root(root)
    removed_count = 0
    nodes = query_index.nodes if query_index is not None else tuple(_iter_structured_c_nodes_8616(root))
    for node in nodes:
        # Structured-codegen nodes are a third-party dynamic boundary.
        statements = getattr(node, "statements", None)
        if not isinstance(statements, list):
            continue
        kept_statements: list[StructuredAstValue] = []
        for statement in statements:
            lhs_offset = _assignment_lhs_stack_offset_8616(statement)
            conflicts_with_fact = (
                isinstance(lhs_offset, int)
                and operator.ne(lhs_offset, fact.offset)
                and _node_has_instruction_address_8616(
                    statement,
                    project,
                    fact.ins_addr,
                )
            )
            if conflicts_with_fact:
                removed_count += 1
                continue
            kept_statements.append(statement)
        if operator.ne(len(kept_statements), len(statements)):
            statements[:] = kept_statements
    return removed_count


@cython.ccall
def _loop_initializer_8616(loop: StructuredAstValue) -> StructuredAstValue:
    """Return the first present loop initializer field."""
    value: object
    attr: object
    for attr in ("initializer", "init"):
        if hasattr(loop, attr):
            with contextlib.suppress(Exception):
                value = getattr(loop, attr)
                if value is not None:
                    return value
    return None


@cython.ccall
def _loop_iterator_8616(
    loop: StructuredAstValue,
) -> tuple[str | None, StructuredAstValue]:
    """Return the first present loop iterator field and its attribute name."""
    value: object
    attr: object
    for attr in ("iterator", "iteration"):
        if hasattr(loop, attr):
            with contextlib.suppress(Exception):
                value = getattr(loop, attr)
                if value is not None:
                    return attr, value
    return None, None


@cython.dataclasses.dataclass
class _LoopIteratorRewriter8616:
    """Rewrite placeholder loop iterators for a proven stack update."""

    root: StructuredAstValue
    cvar: StructuredAstValue
    target_offset: StructuredAstValue
    delta: StructuredAstValue
    replacement_factory: StructuredAstValue
    source_expr: StructuredAstValue
    seen: object
    changed: cython.bint = False

    @cython.ccall
    def _is_placeholder_iterator_8616(self, iterator: object) -> cython.bint:
        """Return whether the iterator does not own the target stack offset."""
        if iterator is None:
            return False
        if isinstance(iterator, structured_c.CAssignment):
            return bool(operator.ne(_assignment_lhs_stack_offset_8616(iterator), self.target_offset))
        return True

    @cython.ccall
    def maybe_rewrite_loop(self, loop: StructuredAstValue) -> None:
        """Rewrite the loop iterator when it is a placeholder for this update."""
        condition: object
        iterator_attr: object
        initializer = _loop_initializer_8616(loop)
        if operator.ne(_assignment_lhs_stack_offset_8616(initializer), self.target_offset):
            return
        condition = getattr(loop, "condition", None) or getattr(loop, "cond", None)
        if condition is not None and not _expr_reads_stack_offset_8616(
            condition, self.target_offset
        ):
            return
        iterator_attr, iterator = _loop_iterator_8616(loop)
        if iterator_attr is None:
            return
        if self.source_expr is not None and _is_same_stack_update_assignment_8616(
            iterator, self.cvar, self.delta, self.source_expr
        ):
            self.root._inertia_stack_update_assignment_already_present_8616 = True
            return
        if not self._is_placeholder_iterator_8616(iterator):
            return
        replacement = self.replacement_factory(getattr(iterator, "tags", None))
        setattr(loop, iterator_attr, replacement)
        self.changed = True

    @cython.ccall
    def walk(self, node: object) -> None:
        """Walk the structured-C tree and rewrite matching loop iterators."""
        item: object
        if node is None:
            return
        if isinstance(node, (list, tuple)):
            for item in tuple(node):
                self.walk(item)
            return
        marker = id(node)
        if marker in self.seen:
            return
        self.seen.add(marker)
        if isinstance(node, structured_c.CForLoop):
            self.maybe_rewrite_loop(node)
        if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return
        self._walk_children_8616(node)

    @cython.ccall
    def _walk_children_8616(self, node: StructuredAstValue) -> None:
        """Recurse into loop-bearing attributes and condition/body pairs."""
        condition_and_nodes: object
        attr: object
        body: object
        condition: object
        for attr in (
            "statements",
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "initializer",
            "init",
        ):
            if hasattr(node, attr):
                with contextlib.suppress(Exception):
                    self.walk(getattr(node, attr))
        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            for condition, body in tuple(condition_and_nodes):
                self.walk(condition)
                self.walk(body)


@cython.ccall
def _replace_stack_update_loop_iterator_8616(
    root: StructuredAstValue,
    cvar: StructuredAstValue,
    width: cython.longlong,
    delta: cython.longlong,
    replacement_factory: StructuredAstValue,
    source_expr: StructuredAstValue = None,
    *,
    query_index: StructuredAstQueryIndex8616 | None = None,
) -> cython.bint:
    node: object
    target_offset = _c_expr_stack_offset_8616(cvar)
    if not isinstance(target_offset, int):
        return False
    rewriter = _LoopIteratorRewriter8616(
        root=root,
        cvar=cvar,
        target_offset=target_offset,
        delta=delta,
        replacement_factory=replacement_factory,
        source_expr=source_expr,
        seen=set(),
    )
    if query_index is None:
        rewriter.walk(root)
    else:
        query_index.require_root(root)
        for node in query_index.nodes:
            if isinstance(node, structured_c.CForLoop):
                rewriter.maybe_rewrite_loop(node)
    return rewriter.changed


@cython.ccall
def _stack_cvar_identity_8616(cvar: StructuredAstValue) -> object:
    """Return one CVariable's machine-BP identity and storage width."""
    size: object
    variable_codegen: object
    if not isinstance(cvar, structured_c.CVariable):
        return None
    variable = cvar.variable
    if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
        return None
    try:
        variable_codegen = cvar.codegen
    except AttributeError:
        variable_codegen = None
    offset = _canonical_stack_offset_8616(
        machine_bp_offset_for_stack_variable_8616(variable_codegen, variable)
        if variable_codegen is not None
        else variable.offset
    )
    if not isinstance(offset, int):
        return None
    size = getattr(variable, "size", None)
    if not isinstance(size, int) or size <= 0:
        type_size = _type_size_bytes_8616(cvar.variable_type, default=0)
        size = type_size if isinstance(type_size, int) and type_size > 0 else None
    return offset, size if isinstance(size, int) else None


@cython.ccall
def _structured_cvar_names_8616(cvar: StructuredAstValue) -> frozenset[str]:
    name: object
    obj: object
    names: set[str] = set()
    for obj in (
        cvar,
        getattr(cvar, "variable", None),
        getattr(cvar, "unified_variable", None),
    ):
        name = getattr(obj, "name", None)
        if isinstance(name, str) and name and not name.startswith(("vvar_", "tmp_", "ir_")):
            names.add(name)
    return frozenset(names)


def _generated_stack_cvar_names_8616(cvar: StructuredAstValue) -> frozenset[str]:
    stack_id: object
    stack_id = _stack_cvar_identity_8616(cvar)
    if stack_id is None:
        return frozenset()
    offset, _size = stack_id
    names = set(_structured_cvar_names_8616(cvar))
    with contextlib.suppress(Exception):
        names.add(_stack_object_name(offset))
    return frozenset(name for name in iter(names) if isinstance(name, str) and name)


@cython.ccall
def _same_stack_cvar_8616(lhs: StructuredAstValue, rhs: StructuredAstValue) -> cython.bint:
    lhs_id: object
    rhs_id: object
    lhs = _strip_casts_8616(lhs)
    rhs = _strip_casts_8616(rhs)
    if isinstance(lhs, structured_c.CIndexedVariable) and isinstance(rhs, structured_c.CIndexedVariable):
        return _same_stack_cvar_8616(lhs.variable, rhs.variable) and _same_stack_move_rhs_8616(
            lhs.index, rhs.index
        )
    if isinstance(lhs, structured_c.CIndexedVariable) or isinstance(rhs, structured_c.CIndexedVariable):
        return False
    lhs_id = _stack_cvar_identity_8616(lhs)
    rhs_id = _stack_cvar_identity_8616(rhs)
    if lhs_id is not None and rhs_id is not None:
        return operator.eq(lhs_id, rhs_id)
    if lhs_id is None and rhs_id is None:
        return False

    stack_cvar = lhs if lhs_id is not None else rhs
    other_cvar = rhs if lhs_id is not None else lhs
    generated_names = _generated_stack_cvar_names_8616(stack_cvar)
    if not generated_names:
        return False
    return bool(generated_names & _structured_cvar_names_8616(other_cvar))


@cython.ccall
def _same_stack_low_half_cvar_8616(lhs: StructuredAstValue, rhs: StructuredAstValue) -> cython.bint:
    lhs_id: object
    rhs_id: object
    lhs_id = _stack_cvar_identity_8616(_strip_casts_8616(lhs))
    rhs_id = _stack_cvar_identity_8616(_strip_casts_8616(rhs))
    if lhs_id is None or rhs_id is None:
        return False
    lhs_offset, lhs_size = lhs_id
    rhs_offset, rhs_size = rhs_id
    return (
        lhs_offset == rhs_offset and isinstance(lhs_size, int) and isinstance(rhs_size, int) and 0 < lhs_size < rhs_size
    )


@cython.dataclasses.dataclass
class _LowHalfRebinder8616:
    """Rebind proven low-half reads of a widened stack object to the wide object."""

    wide_cvar: StructuredAstValue
    seen: object
    changed_count: cython.longlong = 0

    @cython.ccall
    def transform(self, node: StructuredAstValue) -> StructuredAstValue:
        """Replace matching low-half reads with a typed wide-owner projection."""
        projected: object
        if node is self.wide_cvar:
            return node
        if isinstance(node, structured_c.CVariable) and _same_stack_low_half_cvar_8616(
            node, self.wide_cvar
        ):
            projected = materialize_typed_condition_stack_operand_8616(
                getattr(self.wide_cvar, "codegen", None),
                base="bp",
                offset=int(getattr(node.variable, "offset", 0)),
                size=2,
                storage_size=4,
                name=str(getattr(self.wide_cvar, "name", "stack")),
                signed=False,
                preferred=self.wide_cvar,
            )
            if projected is not None:
                self.changed_count += 1
                return projected
        return node

    @cython.ccall
    def visit(self, node: object) -> None:
        """Walk structured-C nodes and apply low-half rebinding."""
        if node is None or not type(node).__module__.startswith(
            "angr.analyses.decompiler.structured_codegen"
        ):
            return
        node_id = id(node)
        if node_id in self.seen:
            return
        self.seen.add(node_id)
        self._visit_attr_children_8616(node)
        self._visit_condition_pairs_8616(node)

    @cython.ccall
    def _visit_attr_children_8616(self, node: StructuredAstValue) -> None:
        """Transform and recurse into each child-bearing attribute."""
        value: object
        attr: object
        index: object
        item: object
        for attr in (
            "statements",
            "rhs",
            "operand",
            "expr",
            "stmts",
            "init",
            "initializer",
            "condition",
            "cond",
            "args",
            "iftrue",
            "iffalse",
            "iteration",
            "iterator",
            "body",
            "else_node",
        ):
            if not hasattr(node, attr):
                continue
            with contextlib.suppress(Exception):
                value = getattr(node, attr)
                if isinstance(value, list):
                    for index, item in enumerate(tuple(value)):
                        replacement = self.transform(item)
                        if replacement is not item:
                            value[index] = replacement
                        self.visit(value[index])
                elif value is not None:
                    replacement = self.transform(value)
                    if replacement is not value:
                        setattr(node, attr, replacement)
                        value = replacement
                    self.visit(value)

    @cython.ccall
    def _visit_condition_pairs_8616(self, node: StructuredAstValue) -> None:
        """Transform and recurse into condition/body pairs."""
        condition_and_nodes: object
        body: object
        condition: object
        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            new_pairs = []
            pair_changed = False
            for condition, body in tuple(condition_and_nodes):
                new_condition = self.transform(condition)
                new_body = self.transform(body)
                if new_condition is not condition or new_body is not body:
                    pair_changed = True
                self.visit(new_condition)
                self.visit(new_body)
                new_pairs.append((new_condition, new_body))
            if pair_changed:
                with contextlib.suppress(Exception):
                    node.condition_and_nodes = new_pairs


@cython.ccall
def _rebind_low_half_stack_reads_to_wide_cvar_8616(root: object, wide_cvar: object) -> cython.longlong:
    """Rebind proven low-half reads of a widened stack object to the wide object."""
    if root is None or wide_cvar is None:
        return 0
    rebinder = _LowHalfRebinder8616(wide_cvar=wide_cvar, seen=set())
    replacement_root = rebinder.transform(root)
    if replacement_root is not root:
        return rebinder.changed_count
    rebinder.visit(root)
    return rebinder.changed_count


@cython.ccall
def _sim_memory_identity_8616(variable: StructuredAstValue) -> object:
    """Return the memory-space identity for a SimMemoryVariable."""
    if isinstance(variable, SimMemoryVariable):
        addr = variable.addr
        if isinstance(addr, int):
            return ("mem", addr)
    return None


@cython.ccall
def _sim_register_identity_8616(variable: StructuredAstValue) -> object:
    """Return the register-space identity for a SimRegisterVariable."""
    if isinstance(variable, SimRegisterVariable):
        reg = variable.reg
        size = variable.size
        name = variable.name
        if isinstance(reg, int) and isinstance(size, int):
            return ("reg", (reg, size))
        if isinstance(name, str) and name:
            return ("reg-name", name)
    return None


@cython.ccall
def _sim_stack_identity_8616(variable: StructuredAstValue) -> object:
    """Return the stack-space identity for a SimStackVariable."""
    if isinstance(variable, SimStackVariable):
        offset = variable.offset
        size = variable.size
        if isinstance(offset, int) and isinstance(size, int):
            return ("stack", (_canonical_stack_offset_8616(offset), size))
        name = variable.name
        if isinstance(name, str) and name and not name.startswith(("vvar_", "tmp_", "ir_")):
            return ("name", name)
    return None


@cython.ccall
def _generic_name_identity_8616(
    variable: StructuredAstValue, node: StructuredAstValue
) -> object:
    """Return the name identity for a variable or its carrier node."""
    name = getattr(variable, "name", None) or node.name
    if isinstance(name, str) and name and not name.startswith(("vvar_", "tmp_", "ir_")):
        return ("name", name)
    return None


@cython.ccall
def _semantic_cvar_identity_8616(node: StructuredAstValue) -> object:
    identity: object
    variable: object
    node = _strip_casts_8616(node)
    identity = (
        _sim_memory_identity_8616(node)
        or _sim_register_identity_8616(node)
        or _sim_stack_identity_8616(node)
    )
    if identity is not None:
        return identity
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if variable is None:
        return None
    identity = _sim_memory_identity_8616(variable) or _sim_register_identity_8616(variable)
    if identity is not None:
        return identity
    return _generic_name_identity_8616(variable, node)


def _same_function_call_rhs_8616(
    lhs: StructuredAstValue, rhs: StructuredAstValue
) -> cython.bint:
    """Return whether two call expressions share callee and arguments."""
    lhs_name: object
    lhs_target: object
    rhs_name: object
    rhs_target: object
    lhs_target = _function_call_target_addr_8616(lhs)
    rhs_target = _function_call_target_addr_8616(rhs)
    if lhs_target is not None or rhs_target is not None:
        same_callee = (
            lhs_target is not None
            and rhs_target is not None
            and operator.eq(lhs_target, rhs_target)
        )
    else:
        lhs_name = _function_call_name_8616(lhs)
        rhs_name = _function_call_name_8616(rhs)
        same_callee = (
            lhs_name is not None
            and rhs_name is not None
            and operator.eq(lhs_name, rhs_name)
        )
    return (
        same_callee
        and operator.eq(len(lhs.args), len(rhs.args))
        and all(
            _same_stack_move_rhs_8616(lhs_arg, rhs_arg)
            for lhs_arg, rhs_arg in builtins.iter(zip(lhs.args, rhs.args, strict=True))
        )
    )


@cython.ccall
def _same_stack_move_rhs_8616(lhs: StructuredAstValue, rhs: StructuredAstValue) -> cython.bint:
    if isinstance(lhs, CSemanticCast8616) or isinstance(
        rhs,
        CSemanticCast8616,
    ):
        if not isinstance(lhs, CSemanticCast8616) or not isinstance(
            rhs,
            CSemanticCast8616,
        ):
            return False
        lhs_type = lhs.dst_type
        rhs_type = rhs.dst_type
        return (
            type(lhs_type) is type(rhs_type)
            and operator.eq(getattr(lhs_type, "size", None), getattr(rhs_type, "size", None))
            and operator.eq(getattr(lhs_type, "signed", None), getattr(rhs_type, "signed", None))
            and _same_stack_move_rhs_8616(lhs.expr, rhs.expr)
        )
    lhs = _strip_casts_8616(lhs)
    rhs = _strip_casts_8616(rhs)
    if isinstance(lhs, structured_c.CFunctionCall) and isinstance(
        rhs,
        structured_c.CFunctionCall,
    ):
        return _same_function_call_rhs_8616(lhs, rhs)
    if isinstance(lhs, structured_c.CIndexedVariable) and isinstance(rhs, structured_c.CIndexedVariable):
        return _same_stack_move_rhs_8616(lhs.variable, rhs.variable) and (
            _same_stack_move_rhs_8616(lhs.index, rhs.index)
        )
    if isinstance(lhs, structured_c.CBinaryOp) and isinstance(rhs, structured_c.CBinaryOp):
        return (
            operator.eq(lhs.op, rhs.op)
            and _same_stack_move_rhs_8616(lhs.lhs, rhs.lhs)
            and _same_stack_move_rhs_8616(lhs.rhs, rhs.rhs)
        )
    if isinstance(lhs, structured_c.CUnaryOp) and isinstance(rhs, structured_c.CUnaryOp):
        return operator.eq(lhs.op, rhs.op) and _same_stack_move_rhs_8616(
            lhs.operand, rhs.operand
        )
    if isinstance(lhs, structured_c.CVariableField) and isinstance(rhs, structured_c.CVariableField):
        return (
            operator.eq(lhs.field.field, rhs.field.field)
            and operator.eq(lhs.field.offset, rhs.field.offset)
            and _same_stack_move_rhs_8616(lhs.variable, rhs.variable)
        )
    return _same_scalar_move_rhs_8616(lhs, rhs)


@cython.ccall
def _same_scalar_move_rhs_8616(lhs: StructuredAstValue, rhs: StructuredAstValue) -> cython.bint:
    """Return whether two leaf expressions carry the same scalar identity."""
    lhs_identity: object
    lhs_stack_id: object
    rhs_identity: object
    rhs_stack_id: object
    lhs_stack_id = _stack_cvar_identity_8616(lhs)
    rhs_stack_id = _stack_cvar_identity_8616(rhs)
    if lhs_stack_id is not None or rhs_stack_id is not None:
        return lhs_stack_id is not None and operator.eq(lhs_stack_id, rhs_stack_id)
    lhs_identity = _semantic_cvar_identity_8616(lhs)
    rhs_identity = _semantic_cvar_identity_8616(rhs)
    if lhs_identity is not None or rhs_identity is not None:
        return lhs_identity is not None and operator.eq(lhs_identity, rhs_identity)
    if isinstance(lhs, structured_c.CConstant) and isinstance(rhs, structured_c.CConstant):
        return bool(operator.eq(lhs.value, rhs.value))
    return lhs is rhs


def _is_control_statement_8616(stmt: StructuredAstValue) -> cython.bint:
    return any(hasattr(stmt, attr) for attr in iter(("condition_and_nodes", "body", "else_node", "iterator", "iteration")))


@cython.ccall
def _direct_stack_move_first_control_addr_8616(root: StructuredAstValue, project: StructuredAstValue) -> int | None:
    cached: object
    first_control_addr: object
    node: object
    cached = getattr(root, "_inertia_direct_stack_move_first_control_addr_8616", None)
    if isinstance(cached, int):
        return cached
    if cached is False:
        return None
    first_control_addr = None
    for node in _iter_structured_c_nodes_8616(root):
        if not _is_control_statement_8616(node):
            continue
        candidate = _following_instruction_addr_in_node_8616(node, project, -1, set())
        if isinstance(candidate, int) and (first_control_addr is None or candidate < first_control_addr):
            first_control_addr = candidate
    with contextlib.suppress(Exception):
        root._inertia_direct_stack_move_first_control_addr_8616 = first_control_addr if isinstance(first_control_addr, int) else False
    return first_control_addr


@cython.ccall
def _direct_stack_move_is_before_first_control_8616(
    root: StructuredAstValue, project: StructuredAstValue, ins_addr: cython.longlong
) -> cython.bint:
    first_control_addr: object
    first_control_addr = _direct_stack_move_first_control_addr_8616(root, project)
    return first_control_addr is None or int(ins_addr) < first_control_addr


@cython.ccall
def _direct_stack_move_is_before_known_first_control_8616(
    root: StructuredAstValue, project: StructuredAstValue, ins_addr: cython.longlong
) -> cython.bint:
    first_control_addr = _direct_stack_move_first_control_addr_8616(root, project)
    return isinstance(first_control_addr, int) and int(ins_addr) < first_control_addr


@cython.ccall
def _direct_stack_move_first_machine_control_addr_8616(
    function: StructuredAstValue, project: StructuredAstValue, ins_addr: cython.longlong
) -> int | None:
    address: object
    capstone: object
    first_control_addr: object
    insn: object
    block: object
    wrapped: object
    first_control_addr = None
    for block in _boundary_tuple_8616(getattr(function, "blocks", ()) or ()):
        capstone = getattr(block, "capstone", None)
        for wrapped in _boundary_tuple_8616(getattr(capstone, "insns", ()) or ()):
            insn = getattr(wrapped, "insn", wrapped)
            groups = frozenset(getattr(insn, "groups", ()) or ())
            if X86_GRP_JUMP not in groups and X86_GRP_RET not in groups and operator.ne(getattr(insn, "id", None), X86_INS_RET):
                continue
            address = getattr(insn, "address", None)
            if not isinstance(address, int):
                continue
            candidate = _comparable_instruction_addr_8616(project, address, ins_addr)
            if isinstance(candidate, int) and (first_control_addr is None or candidate < first_control_addr):
                first_control_addr = candidate
    return first_control_addr


@cython.ccall
def _direct_stack_move_is_before_known_precontrol_8616(
    root: StructuredAstValue, project: StructuredAstValue, function: StructuredAstValue, ins_addr: cython.longlong
) -> cython.bint:
    machine_control_addr = _direct_stack_move_first_machine_control_addr_8616(function, project, ins_addr)
    if isinstance(machine_control_addr, int):
        return int(ins_addr) < machine_control_addr
    return _direct_stack_move_is_before_known_first_control_8616(root, project, ins_addr)


@cython.ccall
def _call_name_from_expr_8616(expr: StructuredAstValue) -> object:
    """Return the normalized helper name of a direct structured-C call."""
    callee: object
    expr = _strip_casts_8616(expr)
    if not isinstance(expr, structured_c.CFunctionCall):
        return None
    target = expr.callee_target
    if isinstance(target, str) and target.strip():
        return target.lstrip("_")
    callee = expr.callee_func
    name = callee.name if callee is not None else None
    return name.lstrip("_") if isinstance(name, str) and name.strip() else None


@cython.dataclasses.dataclass
class _PrecontrolReplacer8616:
    """Replace the first proven pre-control assignment to one stack object."""

    root: StructuredAstValue
    dst_cvar: StructuredAstValue
    replacement: StructuredAstValue
    allow_low_half_lhs: StructuredAstValue
    insert_before_control_when_no_match: StructuredAstValue
    refused: object = field(default_factory=list)

    @cython.ccall
    def scan_container(self, container: StructuredAstValue, path: object) -> cython.bint:
        """Scan one statement container for the replaceable pre-control store."""
        result: object
        statements: object
        index: object
        stmt: object
        statements = getattr(container, "statements", None)
        if not isinstance(statements, list):
            self.refused.append(f"no-statements:path={path}:type={type(container).__name__}")
            return False
        for index, stmt in enumerate(tuple(statements)):
            result = self._process_statement_8616(statements, index, stmt, f"{path}.{index}")
            if result is not None:
                return result
        return False

    @cython.ccall
    def _process_statement_8616(
        self,
        statements: object,
        index: cython.longlong,
        stmt: StructuredAstValue,
        item_path: object,
    ) -> bool | None:
        """Dispatch one statement; None means keep scanning this container."""
        nested: object
        if _is_control_statement_8616(stmt):
            return self._control_gate_8616(statements, index, stmt, item_path)
        nested = getattr(stmt, "statements", None)
        if isinstance(nested, list):
            return True if self.scan_container(stmt, item_path) else None
        if not isinstance(stmt, structured_c.CAssignment):
            self.refused.append(
                f"not-assignment:path={item_path}:type={type(stmt).__name__}"
            )
            return None
        lhs = stmt.lhs
        if not _same_stack_cvar_8616(lhs, self.dst_cvar) and not (
            self.allow_low_half_lhs and _same_stack_low_half_cvar_8616(lhs, self.dst_cvar)
        ):
            self.refused.append(
                "lhs-mismatch:"
                f"path={item_path}:lhs={_stack_cvar_identity_8616(stmt.lhs)}:"
                f"dst={_stack_cvar_identity_8616(self.dst_cvar)}"
            )
            return None
        dst_offset = _c_expr_stack_offset_8616(self.dst_cvar)
        if isinstance(dst_offset, int) and _expr_reads_stack_offset_8616(stmt.rhs, dst_offset):
            self.refused.append(
                f"rhs-reads-destination:path={item_path}:dst={_stack_cvar_identity_8616(self.dst_cvar)}"
            )
            return None
        if _is_same_stack_move_assignment_8616(stmt, self.dst_cvar, self.replacement.rhs):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return False
        statements[index] = self.replacement
        return True

    @cython.ccall
    def _control_gate_8616(
        self,
        statements: object,
        index: cython.longlong,
        stmt: StructuredAstValue,
        item_path: object,
    ) -> cython.bint:
        """Stop at control flow, optionally inserting just before it."""
        self.refused.append(
            f"control-before-match:path={item_path}:type={type(stmt).__name__}"
        )
        self.root._inertia_stack_mov_refused_reasons_8616 = tuple(self.refused)
        if (
            self.insert_before_control_when_no_match
            and not _insertion_point_has_stack_move_assignment_8616(
                statements,
                index,
                self.dst_cvar,
                self.replacement.rhs,
            )
        ):
            statements.insert(index, self.replacement)
            return True
        return False


@cython.ccall
def _replace_precontrol_stack_assignment_8616(
    root: StructuredAstValue,
    dst_cvar: StructuredAstValue,
    replacement: StructuredAstValue,
    *,
    allow_low_half_lhs: cython.bint = False,
    insert_before_control_when_no_match: cython.bint = False,
) -> cython.bint:
    """Replace the first proven pre-control assignment to one stack object."""
    replacer = _PrecontrolReplacer8616(
        root=root,
        dst_cvar=dst_cvar,
        replacement=replacement,
        allow_low_half_lhs=allow_low_half_lhs,
        insert_before_control_when_no_match=insert_before_control_when_no_match,
    )
    if replacer.scan_container(root, "root"):
        return True
    root._inertia_stack_mov_refused_reasons_8616 = tuple(replacer.refused)
    return False


@cython.ccall
def _prune_wide_call_return_carriers_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
) -> cython.longlong:
    """Remove exact low-half call carriers consumed by a proven wide assignment."""
    node: object
    stmt: object
    if (
        fact.source_kind is not DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH
        or not isinstance(fact.source_call_ins_addr, int)
        or not isinstance(fact.source_call_name, str)
    ):
        return 0
    removed = 0
    expected_call_name = fact.source_call_name.lstrip("_")
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        retained: list[StructuredAstValue] = []
        for stmt in node.statements:
            is_exact_carrier = (
                isinstance(stmt, structured_c.CAssignment)
                and _node_has_instruction_address_8616(
                    stmt,
                    project,
                    fact.source_call_ins_addr,
                )
                and (
                    _same_stack_cvar_8616(stmt.lhs, dst_cvar)
                    or _same_stack_low_half_cvar_8616(stmt.lhs, dst_cvar)
                )
                and operator.eq(_call_name_from_expr_8616(stmt.rhs), expected_call_name)
            )
            if is_exact_carrier:
                removed += 1
            else:
                retained.append(stmt)
        if operator.ne(len(retained), len(node.statements)):
            node.statements[:] = retained
    return removed


def _prune_wide_call_return_decomposition_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
) -> cython.longlong:
    """Remove pure split-word assignments consumed by one proven wide operation."""
    node: object
    stmt: object
    if fact.source_kind is not DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH:
        return 0
    low_arith_addr = fact.source_low_arith_ins_addr
    high_arith_addr = fact.source_high_arith_ins_addr
    low_store_addr = fact.ins_addr
    high_store_addr = fact.dst_high_ins_addr
    if (
        not isinstance(low_arith_addr, int)
        or not isinstance(high_arith_addr, int)
        or not isinstance(low_store_addr, int)
        or not isinstance(high_store_addr, int)
    ):
        return 0

    register_assignment_addrs = {
        low_arith_addr,
        high_arith_addr,
    }
    removed = 0
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        retained: list[StructuredAstValue] = []
        for stmt in node.statements:
            remove_assignment = False
            if isinstance(stmt, structured_c.CAssignment) and not _expr_contains_function_call_8616(stmt.rhs):
                lhs_variable = stmt.lhs.variable if isinstance(stmt.lhs, structured_c.CVariable) else None
                remove_assignment = (
                    isinstance(lhs_variable, SimRegisterVariable)
                    and any(
                        _node_has_instruction_address_8616(stmt, project, address)
                        for address in iter(register_assignment_addrs)
                    )
                ) or (
                    isinstance(lhs_variable, SimStackVariable)
                    and any(
                        _node_has_instruction_address_8616(stmt, project, address)
                        for address in iter((low_store_addr, high_store_addr))
                    )
                )
            if remove_assignment:
                removed += 1
            else:
                retained.append(stmt)
        if operator.ne(len(retained), len(node.statements)):
            node.statements[:] = retained
    return removed


@cython.ccall
def _wide_call_return_direct_call_8616(node: StructuredAstValue) -> StructuredAstValue | None:
    """Return the direct call carried by one expression or statement."""
    current = _strip_casts_8616(node)
    if isinstance(current, structured_c.CFunctionCall):
        return current
    if isinstance(current, structured_c.CExpressionStatement):
        return _wide_call_return_direct_call_8616(current.expr)
    if isinstance(current, structured_c.CAssignment):
        return _wide_call_return_direct_call_8616(current.rhs)
    return None


@cython.ccall
def _call_return_call_matches_fact_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
) -> cython.bint:
    """Match one call against the exact binary callsite and target evidence."""
    call: object
    if not isinstance(fact.source_call_ins_addr, int):
        return False
    call = _wide_call_return_direct_call_8616(node)
    if call is None:
        return False
    if not (
        _node_has_instruction_address_8616(node, project, fact.source_call_ins_addr)
        or _node_has_instruction_address_8616(call, project, fact.source_call_ins_addr)
    ):
        return False
    observed_name = _call_name_from_expr_8616(call)
    expected_name = fact.source_call_name.lstrip("_") if isinstance(fact.source_call_name, str) else None
    name_matches = (
        isinstance(observed_name, str)
        and isinstance(expected_name, str)
        and observed_name == expected_name
    )
    target_matches = (
        isinstance(fact.source_call_target, int)
        and _function_call_target_matches_8616(call, project, fact.source_call_target)
    )
    return name_matches or target_matches


@cython.ccall
def _wide_call_return_assignment_matches_fact_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
) -> cython.bint:
    """Match one already-materialized wide assignment to its binary fact."""
    stack_identity: object
    call_candidate: object
    stack_candidate: object
    if (
        not isinstance(node, structured_c.CAssignment)
        or not _same_stack_cvar_8616(node.lhs, dst_cvar)
        or not isinstance(fact.source_offset, int)
    ):
        return False
    rhs = _strip_casts_8616(node.rhs)
    if not isinstance(rhs, structured_c.CBinaryOp) or operator.ne(rhs.op, DirectStackMoveExpressionOp8616.ADD.value):
        return False
    for call_candidate, stack_candidate in ((rhs.lhs, rhs.rhs), (rhs.rhs, rhs.lhs)):
        if not _call_return_call_matches_fact_8616(
            call_candidate,
            project,
            fact,
        ):
            continue
        stack_identity = _stack_cvar_identity_8616(_strip_casts_8616(stack_candidate))
        if stack_identity is None:
            continue
        stack_offset, stack_size = stack_identity
        if (
            operator.eq(stack_offset, _canonical_stack_offset_8616(fact.source_offset))
            and (not isinstance(stack_size, int) or stack_size >= fact.width)
        ):
            return True
    return False


@cython.ccall
def _zero_arg_call_return_assignment_matches_fact_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
) -> cython.bint:
    """Match a direct assignment or its preserved call-carrier bridge."""
    bridge: object
    bridge = word_call_bridge_projection_8616(node)
    carrier, node = bridge if bridge is not None else (node, node)
    if not isinstance(node, structured_c.CAssignment) or not _same_stack_cvar_8616(
        node.lhs,
        dst_cvar,
    ):
        return False
    call = _wide_call_return_direct_call_8616(carrier)
    return (
        isinstance(call, structured_c.CFunctionCall)
        and not call.args
        and _call_return_call_matches_fact_8616(carrier, project, fact)
    )


def _tree_has_zero_arg_call_return_assignment_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
) -> cython.bint:
    """Return whether the exact callsite-to-local assignment remains materialized."""
    return any(
        _zero_arg_call_return_assignment_matches_fact_8616(
            node,
            project,
            fact,
            dst_cvar,
        )
        for node in builtins.iter(_iter_structured_c_nodes_8616(root))
    )


@cython.dataclasses.dataclass
class _WideCallReturnReconciler8616:
    """Remove replay artifacts while retaining the proven wide assignment."""

    project: AngrProjectValue
    fact: DirectStackMoveFact8616
    dst_cvar: StructuredAstValue
    matching_assignment_ids: object
    retained_assignment_id: cython.longlong
    removed: cython.longlong = 0
    seen: object = field(default_factory=set)

    @cython.ccall
    def _is_replayed_call_carrier_8616(self, statement: StructuredAstValue) -> cython.bint:
        """Return whether one statement duplicates the consumed call result."""
        if not _call_return_call_matches_fact_8616(statement, self.project, self.fact):
            return False
        if isinstance(statement, structured_c.CAssignment):
            lhs = _strip_casts_8616(statement.lhs)
            return (
                _cvar_register_name_8616(lhs) == "ax"
                or _same_stack_cvar_8616(lhs, self.dst_cvar)
                or _same_stack_low_half_cvar_8616(lhs, self.dst_cvar)
            )
        return isinstance(
            statement,
            (structured_c.CExpressionStatement, structured_c.CFunctionCall),
        )

    @cython.ccall
    def visit(self, node: object) -> None:
        """Remove replay artifacts from mutable structured statement lists."""
        pairs: object
        statements: object
        _condition: object
        attr: object
        body: object
        statement: object
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            retained: list[StructuredAstValue] = []
            for statement in tuple(statements):
                duplicate_assignment = (
                    id(statement) in self.matching_assignment_ids
                    and operator.ne(id(statement), self.retained_assignment_id)
                )
                if duplicate_assignment or self._is_replayed_call_carrier_8616(statement):
                    self.removed += 1
                    continue
                retained.append(statement)
                self.visit(statement)
            statements[:] = retained
        for attr in ("body", "else_node"):
            self.visit(getattr(node, attr, None))
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.visit(body)


def _reconcile_materialized_wide_call_return_assignment_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
) -> tuple[cython.bint, cython.longlong]:
    """Keep one proven wide assignment and remove exact replay artifacts."""
    matching_assignment_ids = tuple(
        dict.fromkeys(
            id(node)
            for node in builtins.iter(_iter_structured_c_nodes_8616(root))
            if _wide_call_return_assignment_matches_fact_8616(
                node,
                project,
                fact,
                dst_cvar,
            )
        )
    )
    if not matching_assignment_ids:
        return False, 0
    reconciler = _WideCallReturnReconciler8616(
        project,
        fact,
        dst_cvar,
        matching_assignment_ids,
        matching_assignment_ids[0],
    )
    reconciler.visit(root)
    return True, reconciler.removed


@cython.ccall
def _direct_stack_move_materialized_ins_addrs_8616(codegen: StructuredCodegenValue) -> frozenset[cython.longlong]:
    value: object
    record: object
    evidence = getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()
    materialized: set[cython.longlong] = set()
    for record in evidence:
        if isinstance(record, Mapping):
            value = record.get("ins_addr")
        else:
            try:
                value = dict(record).get("ins_addr")
            except (TypeError, ValueError):
                continue
        if isinstance(value, int):
            materialized.add(value)
    return frozenset(materialized)


@cython.ccall
def _tree_has_assignment_for_instruction_addr_8616(
    root: StructuredAstValue, project: AngrProjectValue, ins_addr: cython.longlong
) -> cython.bint:
    node: object
    for node in _iter_structured_c_nodes_8616(root):
        if isinstance(node, structured_c.CAssignment) and _node_has_instruction_address_8616(node, project, ins_addr):
            return True
    return False


@cython.ccall
def _tree_has_stack_assignment_for_instruction_addr_8616(
    root: StructuredAstValue, project: StructuredAstValue, ins_addr: cython.longlong, dst_cvar: StructuredAstValue
) -> cython.bint:
    node: object
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CAssignment):
            continue
        if not _node_has_instruction_address_8616(node, project, ins_addr):
            continue
        if _same_stack_cvar_8616(node.lhs, dst_cvar):
            return True
    return False


@cython.ccall
def _direct_stack_move_fact_key_8616(fact: DirectStackMoveFact8616) -> tuple[StructuredAstValue, ...]:
    return (
        fact.dst_offset,
        fact.width,
        fact.source_kind,
        fact.source_register_offset,
        fact.source_value,
        fact.source_offset,
        fact.source_rhs_offset,
        fact.source_op,
        fact.source_immediate,
        fact.source_call_target,
        fact.source_call_name,
        fact.source_call_ins_addr,
        fact.source_call_return_contract,
        fact.source_low_arith_ins_addr,
        fact.source_high_arith_ins_addr,
        fact.dst_high_ins_addr,
        fact.source_segment_name,
        fact.source_global_displacement,
        fact.source_aggregate_base_offset,
        fact.source_displacement,
        fact.source_index_offset,
        fact.source_index_shift,
        fact.source_index_byte_scale,
        fact.source_access_width,
        fact.source_sign_extend,
        fact.dst_index_global_displacement,
        fact.dst_index_stack_offset,
        fact.dst_index_immediate,
        fact.dst_index_scale,
        fact.dst_index_byte_scale,
        fact.ins_addr,
    )


@cython.ccall
def _direct_stack_move_evidence_key_8616(record: StructuredAstValue) -> object:
    if isinstance(record, Mapping):
        values = record
    else:
        try:
            values = dict(record)
        except (TypeError, ValueError):
            return None
    if not isinstance(values.get("ins_addr"), int):
        return None
    return (
        values.get("dst_offset"),
        values.get("width"),
        values.get("source_kind"),
        values.get("source_register_offset"),
        values.get("source_value"),
        values.get("source_offset"),
        values.get("source_rhs_offset"),
        values.get("source_op"),
        values.get("source_immediate"),
        values.get("source_call_target"),
        values.get("source_call_name"),
        values.get("source_call_ins_addr"),
        values.get("source_call_return_contract"),
        values.get("source_low_arith_ins_addr"),
        values.get("source_high_arith_ins_addr"),
        values.get("dst_high_ins_addr"),
        values.get("source_segment_name"),
        values.get("source_global_displacement"),
        values.get("source_aggregate_base_offset"),
        values.get("source_displacement"),
        values.get("source_index_offset"),
        values.get("source_index_shift"),
        values.get("source_index_byte_scale", 1),
        values.get("source_access_width"),
        values.get("source_sign_extend"),
        values.get("dst_index_global_displacement"),
        values.get("dst_index_stack_offset"),
        values.get("dst_index_immediate"),
        values.get("dst_index_scale", 1),
        values.get("dst_index_byte_scale", 1),
        values.get("ins_addr"),
    )


@cython.ccall
def _direct_stack_move_materialized_fact_keys_8616(
    codegen: StructuredCodegenValue,
) -> frozenset[tuple[StructuredAstValue, ...]]:
    key: object
    record: object
    evidence = getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()
    materialized: set[tuple[StructuredAstValue, ...]] = set()
    for record in evidence:
        key = _direct_stack_move_evidence_key_8616(record)
        if key is not None:
            materialized.add(key)
    return frozenset(materialized)


@cython.ccall
def _record_direct_stack_move_evidence_8616(
    codegen: StructuredCodegenValue,
    fact: DirectStackMoveFact8616,
) -> None:
    """Persist one successfully materialized direct stack-move fact."""
    record = (
        ("dst_offset", fact.dst_offset),
        ("width", fact.width),
        ("source_kind", fact.source_kind),
        ("source_register_offset", fact.source_register_offset),
        ("source_value", fact.source_value),
        ("source_offset", fact.source_offset),
        ("source_rhs_offset", fact.source_rhs_offset),
        ("source_op", fact.source_op),
        ("source_immediate", fact.source_immediate),
        ("source_call_target", fact.source_call_target),
        ("source_call_name", fact.source_call_name),
        ("source_call_ins_addr", fact.source_call_ins_addr),
        ("source_call_return_contract", fact.source_call_return_contract),
        ("source_low_arith_ins_addr", fact.source_low_arith_ins_addr),
        ("source_high_arith_ins_addr", fact.source_high_arith_ins_addr),
        ("dst_high_ins_addr", fact.dst_high_ins_addr),
        ("source_segment_name", fact.source_segment_name),
        ("source_global_displacement", fact.source_global_displacement),
        ("source_aggregate_base_offset", fact.source_aggregate_base_offset),
        ("source_displacement", fact.source_displacement),
        ("source_index_offset", fact.source_index_offset),
        ("source_index_shift", fact.source_index_shift),
        ("source_index_byte_scale", fact.source_index_byte_scale),
        ("source_access_width", fact.source_access_width),
        ("source_sign_extend", fact.source_sign_extend),
        ("dst_index_global_displacement", fact.dst_index_global_displacement),
        ("dst_index_stack_offset", fact.dst_index_stack_offset),
        ("dst_index_immediate", fact.dst_index_immediate),
        ("dst_index_scale", fact.dst_index_scale),
        ("dst_index_byte_scale", fact.dst_index_byte_scale),
        ("ins_addr", fact.ins_addr),
    )
    evidence = _boundary_tuple_8616(
        getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()
    )
    codegen._inertia_direct_stack_move_evidence_8616 = tuple(
        dict.fromkeys(tuple(evidence) + (record,))
    )


@cython.ccall
def _tree_has_materialized_signed_idiv_remainder_8616(
    root: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
) -> cython.bint:
    """Recognize an evidence-backed signed-IDIV assignment after carrier use."""
    node: object
    if fact.source_kind is not DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER:
        return False
    instruction_addrs = {
        address
        for address in iter((fact.source_call_ins_addr, fact.ins_addr))
        if isinstance(address, int)
    }
    if not instruction_addrs:
        return False
    destination_identity = _stack_cvar_identity_8616(dst_cvar)
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CAssignment):
            continue
        if _statement_ins_addr_8616(node) not in instruction_addrs:
            continue
        if operator.ne(_stack_cvar_identity_8616(node.lhs), destination_identity):
            continue
        if _expr_has_binary_op_8616(node.rhs, DirectStackMoveExpressionOp8616.MOD):
            return True
    return False


@cython.dataclasses.dataclass
class _SignedIdivArtifactCollector8616:
    """Collect exact signed-remainder artifact assignments with reject counters."""

    root: StructuredAstValue
    dst_cvar: StructuredAstValue
    candidate_stmt_ids: object = field(default_factory=set)
    candidates: object = field(default_factory=list)
    artifact_seen_count: cython.longlong = 0
    artifact_reject_dst_read_count: cython.longlong = 0
    artifact_reject_memory_lhs_count: cython.longlong = 0
    artifact_reject_used_lhs_count: cython.longlong = 0
    artifact_reject_no_lhs_key_count: cython.longlong = 0

    @cython.ccall
    def collect_candidate(self, stmt: StructuredAstValue) -> None:
        """Collect one candidate when its artifact is provably dead."""
        if not isinstance(stmt, structured_c.CAssignment):
            return
        stmt_id = id(stmt)
        if stmt_id in self.candidate_stmt_ids:
            return
        if not _rhs_is_signed_idiv_remainder_artifact_8616(stmt.rhs):
            return
        self.artifact_seen_count += 1
        if _node_reads_stack_cvar_8616(stmt.rhs, self.dst_cvar):
            self.artifact_reject_dst_read_count += 1
            return
        exact = _same_stack_cvar_8616(stmt.lhs, self.dst_cvar)
        if not exact and not self._nonexact_lhs_dead_8616(stmt, stmt_id):
            return
        self.candidate_stmt_ids.add(stmt_id)
        self.candidates.append((stmt, exact))

    @cython.ccall
    def _nonexact_lhs_dead_8616(self, stmt: StructuredAstValue, stmt_id: cython.longlong) -> cython.bint:
        """Return whether a non-exact LHS is provably unused elsewhere."""
        lhs_key: object
        lhs = _strip_casts_8616(stmt.lhs)
        lhs_key = _c_lvalue_key_8616(lhs)
        lhs_variable = lhs.variable if isinstance(lhs, structured_c.CVariable) else None
        if lhs_key is None:
            self.artifact_reject_no_lhs_key_count += 1
            return False
        if isinstance(lhs_variable, SimMemoryVariable) and not isinstance(
            lhs_variable, SimStackVariable
        ):
            self.artifact_reject_memory_lhs_count += 1
            return False
        if _c_node_reads_lvalue_key_8616(self.root, lhs_key, exclude_node_id=stmt_id):
            self.artifact_reject_used_lhs_count += 1
            return False
        return True


def _replace_signed_idiv_remainder_artifact_assignment_8616(
    root: StructuredAstValue,
    dst_cvar: StructuredAstValue,
    replacement_factory: StructuredAstValue,
    *,
    allow_unique_stack_lhs_bridge: cython.bint = False,
) -> DirectStackMoveArtifactReplacementKind8616 | None:
    _exact: object
    node: object
    stmt: object
    collector = _SignedIdivArtifactCollector8616(root=root, dst_cvar=dst_cvar)
    for node in _iter_structured_c_nodes_8616(root):
        collector.collect_candidate(node)

    candidates = collector.candidates
    root._inertia_signed_idiv_artifact_seen_count_8616 = collector.artifact_seen_count
    root._inertia_signed_idiv_artifact_candidate_count_8616 = len(candidates)
    root._inertia_signed_idiv_artifact_exact_candidate_count_8616 = sum(
        1 for candidate in iter(candidates) if candidate[1]
    )
    root._inertia_signed_idiv_artifact_reject_dst_read_count_8616 = (
        collector.artifact_reject_dst_read_count
    )
    root._inertia_signed_idiv_artifact_reject_memory_lhs_count_8616 = (
        collector.artifact_reject_memory_lhs_count
    )
    root._inertia_signed_idiv_artifact_reject_used_lhs_count_8616 = (
        collector.artifact_reject_used_lhs_count
    )
    root._inertia_signed_idiv_artifact_reject_no_lhs_key_count_8616 = (
        collector.artifact_reject_no_lhs_key_count
    )
    exact_candidates = [candidate for candidate in iter(candidates) if candidate[1]]
    if exact_candidates:
        selected = exact_candidates
        decision = DirectStackMoveArtifactReplacementKind8616.EXACT_DESTINATION_STACK_SLOT
    elif allow_unique_stack_lhs_bridge and len(candidates) == 1:
        selected = candidates
        decision = DirectStackMoveArtifactReplacementKind8616.UNIQUE_SIGNED_IDIV_STACK_ARTIFACT
    else:
        root._inertia_signed_idiv_artifact_refusal_8616 = "ambiguous" if len(candidates) > 1 else "no_candidate"
        return None

    changed = False
    for stmt, _exact in selected:
        replacement = replacement_factory(stmt.tags)
        if not isinstance(replacement, structured_c.CAssignment):
            continue
        if _is_same_stack_move_assignment_8616(
            stmt,
            replacement.lhs,
            replacement.rhs,
        ):
            root._inertia_stack_mov_assignment_already_present_8616 = True
            continue
        stmt.lhs = replacement.lhs
        stmt.rhs = replacement.rhs
        stmt.tags = replacement.tags
        changed = True
    return decision if changed else None


def _signed_idiv_insert_expression_8616(
    stmt: StructuredAstValue,
) -> object:
    """Return (assignment, expression) when the statement is an INSERT artifact."""
    assignment: object
    assignment = stmt if isinstance(stmt, structured_c.CAssignment) else None
    if assignment is not None:
        expression = assignment.rhs
    elif isinstance(stmt, structured_c.CExpressionStatement):
        expression = stmt.expr
    elif isinstance(stmt, structured_c.CFunctionCall):
        expression = stmt
    else:
        return None
    if not _expr_has_structured_c_intrinsic_8616(
        expression,
        StructuredCIntrinsic8616.INSERT,
    ):
        return None
    if _expr_has_binary_op_8616(
        expression,
        DirectStackMoveExpressionOp8616.MOD,
    ):
        return None
    if assignment is None and any(
        isinstance(candidate, structured_c.CFunctionCall)
        and _structured_c_intrinsic_8616(candidate)
        is not StructuredCIntrinsic8616.INSERT
        for candidate in builtins.iter(_iter_structured_c_nodes_8616(expression))
    ):
        return None
    return assignment, expression


@cython.ccall
def _signed_idiv_insert_statement_addr_8616(
    stmt: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    call_addr: cython.longlong,
) -> int | None:
    """Resolve the statement address inside the call-to-remainder window."""
    instruction_range: object
    statement_addr = _statement_instruction_addr_8616(stmt, project, fact.ins_addr)
    if not isinstance(statement_addr, int):
        instruction_range = _instruction_addr_range_in_node_8616(
            stmt,
            project,
            fact.ins_addr,
        )
        if (
            instruction_range is not None
            and call_addr < instruction_range[0]
            and instruction_range[1] < fact.ins_addr
        ):
            statement_addr = instruction_range[0]
    if (
        not isinstance(statement_addr, int)
        or not call_addr < statement_addr < fact.ins_addr
    ):
        return None
    return statement_addr


@cython.ccall
def _signed_idiv_aux_lhs_live_8616(
    root: StructuredAstValue,
    stmt: StructuredAstValue,
    assignment: StructuredAstValue,
) -> cython.bint:
    """Return whether the artifact assignment LHS is still live elsewhere."""
    lhs_key: object
    lhs = _strip_casts_8616(assignment.lhs)
    lhs_key = _c_lvalue_key_8616(lhs)
    if lhs_key is None:
        return True
    if isinstance(lhs, structured_c.CVariable):
        lhs_variable = lhs.variable
        if isinstance(lhs_variable, SimMemoryVariable) and not isinstance(
            lhs_variable,
            SimStackVariable,
        ):
            return True
    return _c_node_reads_lvalue_key_8616(
        root,
        lhs_key,
        exclude_node_id=id(stmt),
    )


@cython.ccall
def _signed_idiv_aux_is_candidate_8616(
    root: StructuredAstValue,
    stmt: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    call_addr: cython.longlong,
) -> cython.bint:
    """Return whether a statement is a removable signed-IDIV INSERT artifact."""
    assignment: object
    pair: object
    pair = _signed_idiv_insert_expression_8616(stmt)
    if pair is None:
        return False
    assignment, _expression = pair
    if _signed_idiv_insert_statement_addr_8616(stmt, project, fact, call_addr) is None:
        return False
    if assignment is None:
        return True
    return not _signed_idiv_aux_lhs_live_8616(root, stmt, assignment)


@cython.ccall
def _prune_signed_idiv_auxiliary_insert_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
) -> cython.longlong:
    """Remove one unused INSERT artifact inside a proven signed-IDIV window.

    AIL may emit the widened dividend setup either as an assignment to an
    unread carrier or as a standalone expression whose result is discarded.
    Both forms are removable only inside the exact call-to-remainder-store
    instruction window and only after signed-remainder materialization.
    """
    index: object
    node: object
    stmt: object
    if not isinstance(fact.source_call_ins_addr, int):
        return 0
    candidates: list[tuple[list[StructuredAstValue], cython.longlong]] = []
    call_addr = _comparable_instruction_addr_8616(
        project,
        fact.source_call_ins_addr,
        fact.ins_addr,
    )
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        for index, stmt in enumerate(node.statements):
            if _signed_idiv_aux_is_candidate_8616(root, stmt, project, fact, call_addr):
                candidates.append((node.statements, index))
    if len(candidates) != 1:
        return 0
    statements, index = candidates[0]
    del statements[index]
    return 1


def _reconcile_materialized_signed_idiv_call_order_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
) -> tuple[cython.bint, cython.longlong]:
    """Move a replayed remainder assignment back to its exact call carrier."""
    assignment: object
    call_source_expr: object
    if fact.source_kind is not DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER:
        return False, 0
    call_source_expr = _direct_stack_move_source_expr_8616(
        codegen,
        fact,
        dst_cvar,
        reuse_call_result=False,
    )
    if call_source_expr is None or not _expr_contains_function_call_8616(
        call_source_expr,
    ):
        return False, 0

    def replacement_factory(
        tags: StructuredAstValue,
        *,
        _dst_cvar: StructuredAstValue = dst_cvar,
        _source_expr: StructuredAstValue = call_source_expr,
    ) -> StructuredAstValue:
        """Build the exact remainder assignment at the binary call position."""
        return _direct_stack_move_assignment_8616(
            codegen,
            _dst_cvar,
            _source_expr,
            tags=tags,
        )

    assignment = _replace_tagged_call_statement_with_stack_assignment_8616(
        root,
        project,
        fact.source_call_ins_addr,
        fact.source_call_name,
        replacement_factory,
        call_target=fact.source_call_target,
    )
    if assignment is None:
        return False, 0
    duplicate_count = _remove_duplicate_stack_move_assignments_8616(
        root,
        project,
        fact.ins_addr,
        dst_cvar,
        call_source_expr,
        assignment,
    )
    if isinstance(fact.source_call_ins_addr, int):
        duplicate_count += _remove_duplicate_stack_move_assignments_8616(
            root,
            project,
            fact.source_call_ins_addr,
            dst_cvar,
            call_source_expr,
            assignment,
        )
    return True, duplicate_count


def _comparable_instruction_addr_8616(project: AngrProjectValue, tagged_addr: cython.longlong, ins_addr: cython.longlong) -> cython.longlong:
    delta: object
    variants = [tagged_addr]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and delta:
        variants.extend([tagged_addr + delta, tagged_addr - delta])
    return min(variants, key=lambda candidate: abs(candidate - ins_addr))


@cython.ccall
def _statement_instruction_addr_8616(stmt: StructuredAstValue, project: AngrProjectValue, ins_addr: cython.longlong) -> int | None:
    tagged_addr: object
    tags: object
    tags = copy_structured_tags_8616(getattr(stmt, "tags", None))
    if tags is None:
        return None
    tagged_addr = tags.get("ins_addr")
    if not isinstance(tagged_addr, int):
        return None
    return _comparable_instruction_addr_8616(project, tagged_addr, ins_addr)


_NODE_RANGE_CHILD_ATTRS_8616 = (
    "statements",
    "lhs",
    "rhs",
    "operand",
    "expr",
    "args",
    "operands",
    "stmts",
    "init",
    "initializer",
    "condition",
    "cond",
    "iftrue",
    "iffalse",
    "iteration",
    "iterator",
    "body",
    "else_node",
)


@cython.ccall
def _extend_child_ranges_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    seen: object,
    candidates: object,
) -> None:
    """Extend candidates with instruction ranges from child attributes."""
    child_range: object
    attr: object
    for attr in _NODE_RANGE_CHILD_ATTRS_8616:
        if not hasattr(node, attr):
            continue
        with contextlib.suppress(Exception):
            child_range = _instruction_addr_range_in_node_8616(
                getattr(node, attr), project, ins_addr, seen
            )
        if child_range is not None:
            candidates.extend(child_range)


def _instruction_addr_range_in_node_8616(
    node: object, project: AngrProjectValue, ins_addr: cython.longlong, seen: object = None
) -> object:
    child_range: object
    condition_and_nodes: object
    if node is None:
        return None
    if seen is None:
        seen = set()
    if isinstance(node, (list, tuple)):
        ranges = [
            item_range
            for item in builtins.iter(tuple(node))
            if (item_range := _instruction_addr_range_in_node_8616(item, project, ins_addr, seen)) is not None
        ]
        if not ranges:
            return None
        return min(item[0] for item in iter(ranges)), max(item[1] for item in iter(ranges))
    node_id = id(node)
    if node_id in seen:
        return None
    seen.add(node_id)

    candidates: list[cython.longlong] = []
    direct_addr = _statement_instruction_addr_8616(node, project, ins_addr)
    if isinstance(direct_addr, int):
        candidates.append(direct_addr)
    if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
        return (min(candidates), max(candidates)) if candidates else None

    _extend_child_ranges_8616(node, project, ins_addr, seen, candidates)
    condition_and_nodes = getattr(node, "condition_and_nodes", None)
    if condition_and_nodes:
        child_range = _instruction_addr_range_in_node_8616(tuple(condition_and_nodes), project, ins_addr, seen)
        if child_range is not None:
            candidates.extend(child_range)
    return (min(candidates), max(candidates)) if candidates else None


@cython.ccall
def _extend_child_preceding_addrs_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    seen: object,
    candidates: object,
) -> None:
    """Extend candidates with preceding addresses from child attributes."""
    attr: object
    for attr in _NODE_RANGE_CHILD_ATTRS_8616:
        if not hasattr(node, attr):
            continue
        with contextlib.suppress(Exception):
            candidate = _preceding_instruction_addr_in_node_8616(
                getattr(node, attr), project, ins_addr, seen
            )
        if isinstance(candidate, int):
            candidates.append(candidate)


@cython.ccall
def _preceding_instruction_addr_in_node_8616(
    node: object, project: AngrProjectValue, ins_addr: cython.longlong, seen: object = None
) -> int | None:
    condition_and_nodes: object
    if node is None:
        return None
    if seen is None:
        seen = set()
    if isinstance(node, (list, tuple)):
        nested_candidates = [
            candidate
            for item in builtins.iter(tuple(node))
            if (candidate := _preceding_instruction_addr_in_node_8616(item, project, ins_addr, seen)) is not None
        ]
        return max(nested_candidates) if nested_candidates else None
    node_id = id(node)
    if node_id in seen:
        return None
    seen.add(node_id)

    candidates: list[cython.longlong] = []
    direct_addr = _statement_instruction_addr_8616(node, project, ins_addr)
    if isinstance(direct_addr, int) and direct_addr < ins_addr:
        candidates.append(direct_addr)
    if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
        return max(candidates) if candidates else None

    _extend_child_preceding_addrs_8616(node, project, ins_addr, seen, candidates)
    condition_and_nodes = getattr(node, "condition_and_nodes", None)
    if condition_and_nodes:
        candidate = _preceding_instruction_addr_in_node_8616(tuple(condition_and_nodes), project, ins_addr, seen)
        if isinstance(candidate, int):
            candidates.append(candidate)
    return max(candidates) if candidates else None



def _instruction_block_addr_map_8616(project: StructuredAstValue, function: StructuredAstValue) -> object:
    block_addr: object
    cached: object
    ins_addr: object
    insn: object
    project_cache: object
    block: object
    wrapper: object
    cached = getattr(function, "_inertia_instruction_block_addr_map_8616", None)
    if isinstance(cached, dict):
        return cached
    blocks = tuple(_direct_global_update_blocks_8616(project, function))
    cache_key = (
        int(getattr(function, "addr", 0) or 0),
        _boundary_tuple_8616(
            (int(getattr(block, "addr", 0) or 0), int(getattr(block, "size", 0) or 0)) for block in iter(blocks)
        ),
    )
    project_cache = getattr(project, "_inertia_instruction_block_addr_map_cache_8616", None)
    if not isinstance(project_cache, dict):
        project_cache = {}
        with contextlib.suppress(Exception):
            project._inertia_instruction_block_addr_map_cache_8616 = project_cache
    cached = project_cache.get(cache_key)
    if isinstance(cached, dict):
        return cached
    block_by_insn: dict[cython.longlong, cython.longlong] = {}
    for block in blocks:
        block_addr = getattr(block, "addr", None)
        if not isinstance(block_addr, int):
            continue
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = getattr(wrapper, "insn", wrapper)
            ins_addr = getattr(insn, "address", None)
            if isinstance(ins_addr, int):
                block_by_insn[int(ins_addr)] = int(block_addr)
    project_cache[cache_key] = block_by_insn
    with contextlib.suppress(Exception):
        function._inertia_instruction_block_addr_map_8616 = block_by_insn
    return block_by_insn


def _instruction_by_addr_map_8616(
    project: StructuredAstValue, function: StructuredAstValue
) -> object:
    cached: object
    ins_addr: object
    insn: object
    project_cache: object
    block: object
    wrapper: object
    cached = getattr(function, "_inertia_instruction_by_addr_map_8616", None)
    if isinstance(cached, dict):
        return cached
    blocks = tuple(_direct_global_update_blocks_8616(project, function))
    cache_key = (
        int(getattr(function, "addr", 0) or 0),
        _boundary_tuple_8616(
            (int(getattr(block, "addr", 0) or 0), int(getattr(block, "size", 0) or 0)) for block in iter(blocks)
        ),
    )
    project_cache = getattr(project, "_inertia_instruction_by_addr_map_cache_8616", None)
    if not isinstance(project_cache, dict):
        project_cache = {}
        with contextlib.suppress(Exception):
            project._inertia_instruction_by_addr_map_cache_8616 = project_cache
    cached = project_cache.get(cache_key)
    if isinstance(cached, dict):
        return cached
    insn_by_addr: dict[cython.longlong, StructuredAstValue] = {}
    for block in blocks:
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = getattr(wrapper, "insn", wrapper)
            ins_addr = getattr(insn, "address", None)
            if isinstance(ins_addr, int):
                insn_by_addr[int(ins_addr)] = insn
    project_cache[cache_key] = insn_by_addr
    with contextlib.suppress(Exception):
        function._inertia_instruction_by_addr_map_8616 = insn_by_addr
    return insn_by_addr


@cython.ccall
def _instruction_at_or_decode_8616(
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    insn_by_addr: Mapping[cython.longlong, StructuredAstValue],
) -> StructuredAstValue:
    """Return one exact instruction, decoding beyond incomplete CFG block inventories."""
    candidate: object
    decoded_addr: object
    insn: object
    candidate_addr: object
    insn = insn_by_addr.get(ins_addr)
    if insn is not None:
        return insn
    for candidate_addr in _candidate_ins_addrs_8616(project, ins_addr):
        with contextlib.suppress(Exception):
            block = project.factory.block(candidate_addr, num_inst=1, opt_level=0)
            wrappers = _boundary_tuple_8616(block.capstone.insns)
            if not wrappers:
                continue
            candidate = getattr(wrappers[0], "insn", wrappers[0])
            decoded_addr = getattr(candidate, "address", None)
            if operator.eq(decoded_addr, candidate_addr):
                return candidate
    return None


def _pure_consumed_push_carrier_expression_8616(node: StructuredAstValue) -> cython.bint:
    """Return whether removing a false PUSH carrier drops no C-level side effect."""
    helper: object
    if isinstance(node, (structured_c.CConstant, structured_c.CVariable, structured_c.CDirtyExpression)):
        return True
    if isinstance(node, structured_c.CBinaryOp):
        return _pure_consumed_push_carrier_expression_8616(
            node.lhs
        ) and _pure_consumed_push_carrier_expression_8616(node.rhs)
    if isinstance(node, structured_c.CTypeCast):
        return _pure_consumed_push_carrier_expression_8616(node.expr)
    if isinstance(node, structured_c.CUnaryOp):
        return _pure_consumed_push_carrier_expression_8616(node.operand)
    if isinstance(node, structured_c.CFunctionCall):
        helper = memory_pointer_helper_8616(node) or segmented_memory_read_helper_8616(node)
        return helper is not None and all(
            _pure_consumed_push_carrier_expression_8616(argument)
            for argument in builtins.iter(_boundary_tuple_8616(node.args or ()))
        )
    return False


@cython.ccall
def _call_target_name_8616(call: structured_c.CFunctionCall) -> object:
    """Return a target name from the third-party angr call boundary."""
    callee: object
    if isinstance(call.callee_target, str) and call.callee_target:
        return call.callee_target
    callee = call.callee_func
    name = callee.name if callee is not None else None
    return name if isinstance(name, str) and name else None


@cython.ccall
def _is_indexed_ss_stack_store_lhs_8616(
    project: AngrProjectValue,
    lhs: StructuredAstValue,
) -> cython.bint:
    """Recognize ``(&BP-slot)[SS * 16]`` as a lowered SS stack lvalue."""
    if not isinstance(lhs, structured_c.CIndexedVariable):
        return False
    base = _strip_casts_8616(lhs.variable)
    if not isinstance(base, structured_c.CUnaryOp) or base.op != "Reference":
        return False
    stack_expr = _strip_casts_8616(base.operand)
    if not isinstance(stack_expr, structured_c.CVariable):
        return False
    stack_variable = stack_expr.variable
    return (
        isinstance(stack_variable, SimStackVariable)
        and stack_variable.base == "bp"
        and _segment_base_name_8616(lhs.index, project) == "ss"
    )


@cython.ccall
def _is_consumed_push_ss_store_lhs_8616(
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    lhs: StructuredAstValue,
) -> cython.bint:
    """Recognize a helper or indexed SS stack-store lvalue for one PUSH effect."""
    if isinstance(lhs, structured_c.CUnaryOp) and lhs.op == "Dereference":
        # Exact decoded PUSH provenance proves the unresolved dereference is
        # the instruction's SS:SP store, even after angr loses its segment.
        return _pure_consumed_push_carrier_expression_8616(lhs.operand)
    return _is_indexed_ss_stack_store_lhs_8616(
        project, lhs
    ) or runtime_segment_access_space_8616(
        project,
        codegen,
        lhs,
    ) is MemSpace.SS


@cython.ccall
def _is_consumed_push_stack_carrier_lhs_8616(
    project: AngrProjectValue,
    lhs: StructuredAstValue,
) -> cython.bint:
    """Recognize a side-effect-free stack carrier produced by a PUSH lift."""
    sp_register: object
    lhs = _strip_casts_8616(lhs)
    if isinstance(lhs, structured_c.CBinaryOp) and lhs.op == "Shr":
        shift = _strip_casts_8616(lhs.rhs)
        if isinstance(shift, structured_c.CConstant) and shift.value == 8:
            lhs = _strip_casts_8616(lhs.lhs)
    if isinstance(lhs, structured_c.CDirtyExpression):
        return True
    if not isinstance(lhs, structured_c.CVariable):
        return False
    variable = lhs.variable
    if isinstance(variable, SimStackVariable):
        return bool(variable.base == "bp")
    if not isinstance(variable, SimRegisterVariable):
        return False
    sp_register = project.arch.registers.get("sp")
    return (
        isinstance(sp_register, tuple)
        and len(sp_register) >= 1
        and operator.eq(variable.reg, sp_register[0])
    )


def prune_materialized_call_push_stack_assignments_8616(
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    *,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Replay exact consumed-PUSH lowering for current materialized calls.

    The authoritative callsite inventory owns physical PUSH provenance. A
    structured call participates only when its exact machine callsite identity
    survives AST cloning and it currently has materialized arguments.
    """
    node: object
    cfunc = codegen.cfunc
    root = cfunc.statements
    inventory = callsite_summary_inventory_8616(codegen)
    cleanup_summaries = {
        callsite_addr: summary
        for callsite_addr, summary in builtins.iter(inventory.items())
        if summary.stack_cleanup_instruction_addr is not None
    }
    normalized_cleanup_summaries = {
        callsite_addr: summary
        for callsite_addr, summary in builtins.iter(cleanup_summaries.items())
        if isinstance(summary.stack_cleanup_instruction_addr, int)
        and not isinstance(summary.stack_cleanup_instruction_addr, bool)
        and isinstance(summary.stack_cleanup, int)
        and not isinstance(summary.stack_cleanup, bool)
        and summary.stack_cleanup > 0
    }
    push_summaries = {
        callsite_addr: summary
        for callsite_addr, summary in builtins.iter(inventory.items())
        if summary.push_arg_instruction_addrs
    }
    raw_count = len(push_summaries)
    push_evidence_by_callsite = {
        callsite_addr: normalize_consumed_call_push_evidence_8616(summary)
        for callsite_addr, summary in builtins.iter(push_summaries.items())
    }
    normalized_summaries = {
        callsite_addr: summary
        for callsite_addr, summary in builtins.iter(push_summaries.items())
        if push_evidence_by_callsite[callsite_addr].status
        is ConsumedCallPushEvidenceStatus8616.NORMALIZED
    }
    normalized_count = len(normalized_summaries)
    classified_callsite_addrs: set[cython.longlong] = set()
    classified_cleanup_callsite_addrs: set[cython.longlong] = set()
    materialized_args_by_callsite: dict[cython.longlong, tuple[StructuredAstValue, ...]] = {}
    observed_calls: list[tuple[str | None, int | None, cython.longlong]] = []
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        callsite_addr = structured_callsite_addr_8616(node)
        observed_calls.append(
            (_call_target_name_8616(node), callsite_addr, len(node.args or ()))
        )
        if not _boundary_tuple_8616(node.args or ()):
            continue
        if callsite_addr in normalized_summaries:
            classified_callsite_addrs.add(callsite_addr)
            materialized_args_by_callsite[callsite_addr] = _boundary_tuple_8616(
                node.args or ()
            )
        if callsite_addr in normalized_cleanup_summaries:
            classified_cleanup_callsite_addrs.add(callsite_addr)
    if os.environ.get("INERTIA_DEBUG_CONSUMED_CALL_PUSH"):
        log.warning(
            "[materialized-call-push] observed_calls=%r classified_callsites=%r",
            tuple(observed_calls),
            tuple(hex(address) for address in builtins.iter(sorted(classified_callsite_addrs))),
        )

    consumed_push_instruction_addrs = frozenset(
        address
        for callsite_addr in iter(classified_callsite_addrs)
        for address in iter(push_evidence_by_callsite[callsite_addr].instruction_addrs)
    )
    materialized_args_by_push_instruction_addr = {
        address: materialized_args_by_callsite[callsite_addr]
        for callsite_addr in iter(classified_callsite_addrs)
        for address in iter(push_evidence_by_callsite[callsite_addr].instruction_addrs)
    }
    consumed_cleanup_instruction_addrs = frozenset(
        cast(
            int,
            normalized_cleanup_summaries[
                callsite_addr
            ].stack_cleanup_instruction_addr,
        )
        for callsite_addr in iter(classified_cleanup_callsite_addrs)
    )
    cleanup_result = MaterializedCallCleanupReplay8616(
        raw_fact_count=len(cleanup_summaries),
        normalized_fact_count=len(normalized_cleanup_summaries),
        classified_fact_count=len(classified_cleanup_callsite_addrs),
        materialized_count=len(classified_cleanup_callsite_addrs)
        if consumed_cleanup_instruction_addrs
        else 0,
        failure_count=max(
            len(cleanup_summaries) - len(normalized_cleanup_summaries),
            0,
        ),
        consumed_cleanup_instruction_count=len(
            consumed_cleanup_instruction_addrs
        ),
    )
    codegen._inertia_materialized_call_cleanup_replay_8616 = cleanup_result
    codegen._inertia_consumed_call_cleanup_carrier_ins_addrs_8616 = (
        consumed_cleanup_instruction_addrs
    )
    if os.environ.get("INERTIA_DEBUG_CONSUMED_CALL_PUSH"):
        log.warning(
            "[materialized-call-cleanup] consumed_addrs=%s raw=%d "
            "normalized=%d classified=%d materialized=%d failures=%d",
            tuple(
                hex(address)
                for address in builtins.iter(sorted(consumed_cleanup_instruction_addrs))
            ),
            cleanup_result.raw_fact_count,
            cleanup_result.normalized_fact_count,
            cleanup_result.classified_fact_count,
            cleanup_result.materialized_count,
            cleanup_result.failure_count,
        )
    if (
        cleanup_result.classified_fact_count > 0
        and cleanup_result.materialized_count == 0
    ):
        raise PipelineHardError(
            "materialized call cleanup replay classified callsites without "
            "materializing exact consumed cleanup addresses"
        )
    classified_count = len(classified_callsite_addrs)
    materialized_count = classified_count if consumed_push_instruction_addrs else 0
    result = MaterializedCallPushReplay8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=max(raw_count - normalized_count, 0)
        + max(classified_count - materialized_count, 0),
        consumed_push_instruction_count=len(consumed_push_instruction_addrs),
    )
    codegen._inertia_materialized_call_push_replay_8616 = result
    if classified_count > 0 and materialized_count == 0:
        raise PipelineHardError(
            "materialized call PUSH replay classified callsites without "
            "materializing exact consumed PUSH addresses"
        )
    push_changed = prune_consumed_call_push_stack_assignments_8616(
        project,
        codegen,
        consumed_push_instruction_addrs,
        materialized_args_by_push_instruction_addr=materialized_args_by_push_instruction_addr,
        function=function,
    )
    execution_frame_changed = prune_materialized_call_execution_frames_8616(
        codegen,
        (
            (node, inventory[callsite_addr])
            for node in builtins.iter(_iter_structured_c_nodes_8616(root))
            if isinstance(node, structured_c.CFunctionCall)
            and (callsite_addr := structured_callsite_addr_8616(node)) in inventory
        ),
    )
    return push_changed or execution_frame_changed


@cython.dataclasses.dataclass
class _PushCarrierClassifier8616:
    """Classify assignments against exact consumed PUSH evidence."""

    project: StructuredAstValue
    codegen: StructuredAstValue
    root: StructuredAstValue
    consumed_push_instruction_addrs: StructuredAstValue
    materialized_args_by_push_instruction_addr: StructuredAstValue
    insn_by_addr: StructuredAstValue
    debug: StructuredAstValue
    raw_count: cython.longlong = 0
    normalized_count: cython.longlong = 0
    classified_count: cython.longlong = 0
    preserved_live_definition_count: cython.longlong = 0
    liveness_refusal_count: cython.longlong = 0

    def is_false_push_carrier(self, statement: StructuredAstValue) -> cython.bint:
        """Classify one assignment against exact consumed PUSH evidence."""
        ins_addr: object
        tags: object
        if not isinstance(statement, structured_c.CAssignment):
            return False
        tags = copy_structured_tags_8616(statement.tags)
        statement_ins_addr = tags.get("ins_addr") if tags is not None else None
        lhs = statement.lhs
        candidate_addrs = self._candidate_addrs_8616(statement, lhs, statement_ins_addr)
        if not candidate_addrs:
            return False
        self.raw_count += 1
        if len(candidate_addrs) != 1:
            return False
        self.normalized_count += 1
        ins_addr = next(iter(candidate_addrs))
        insn = _instruction_at_or_decode_8616(self.project, ins_addr, self.insn_by_addr)
        if operator.ne(getattr(insn, "id", None), X86_INS_PUSH):
            return False
        materialized_args = (
            self.materialized_args_by_push_instruction_addr.get(ins_addr, ())
            if self.materialized_args_by_push_instruction_addr is not None
            else ()
        )
        if not self._carrier_lhs_gate_8616(statement, lhs, materialized_args):
            return False
        if not _pure_consumed_push_carrier_expression_8616(
            statement.rhs
        ) and not any(
            _same_stack_move_rhs_8616(statement.rhs, argument)
            for argument in iter(materialized_args)
        ):
            return False
        self.classified_count += 1
        return True

    def _candidate_addrs_8616(
        self,
        statement: StructuredAstValue,
        lhs: StructuredAstValue,
        statement_ins_addr: StructuredAstValue,
    ) -> StructuredAstValue:
        """Return the consumed PUSH addresses this statement may carry."""
        lhs_helper = (
            _call_target_name_8616(lhs)
            if isinstance(lhs, structured_c.CFunctionCall)
            else None
        )
        candidate_addrs = (
            instruction_addrs_from_node_8616(lhs) & self.consumed_push_instruction_addrs
        )
        if (
            isinstance(statement_ins_addr, int)
            and statement_ins_addr in self.consumed_push_instruction_addrs
        ):
            candidate_addrs |= frozenset({statement_ins_addr})
        if self.debug and (candidate_addrs or lhs_helper in {"SEG_U8", "SEG_U16", "SEG_U32"}):
            log.warning(
                "[consumed-call-push] statement_ins_addr=%r candidate_addrs=%s lhs_type=%s "
                "lhs_helper=%r rhs_type=%s rhs_pure=%s",
                None if not isinstance(statement_ins_addr, int) else hex(statement_ins_addr),
                tuple(hex(address) for address in builtins.iter(sorted(candidate_addrs))),
                type(lhs).__name__,
                lhs_helper,
                type(statement.rhs).__name__,
                _pure_consumed_push_carrier_expression_8616(statement.rhs),
            )
        return candidate_addrs

    @cython.ccall
    def _carrier_lhs_gate_8616(
        self,
        statement: StructuredAstValue,
        lhs: StructuredAstValue,
        materialized_args: StructuredAstValue,
    ) -> cython.bint:
        """Return whether the assignment's LHS is a proven consumed carrier."""
        dirty_verdict: object
        from .consumed_push_stack_liveness import (
            PushStackReadVerdict8616,
            consumed_push_stack_read_verdict_8616,
        )

        stack_read = consumed_push_stack_read_verdict_8616(self.root, statement, codegen=self.codegen)
        if stack_read in {PushStackReadVerdict8616.OBSERVED, PushStackReadVerdict8616.UNKNOWN_REFUSE}:
            self.liveness_refusal_count += 1
            return False
        runtime_verdict = classify_runtime_push_carrier_8616(
            self.root,
            statement,
            materialized_args,
            sp_offset=self.project.arch.registers["sp"][0],
        )
        if runtime_verdict in {
            RuntimePushCarrierVerdict8616.UNKNOWN_REFUSE,
            RuntimePushCarrierVerdict8616.OBSERVED,
        }:
            self.liveness_refusal_count += 1
            return False
        if not (
            runtime_verdict is RuntimePushCarrierVerdict8616.UNOBSERVED
            or _is_consumed_push_stack_carrier_lhs_8616(self.project, lhs)
            or _is_consumed_push_ss_store_lhs_8616(self.project, self.codegen, lhs)
        ):
            return False
        dirty_verdict = self._dirty_carrier_liveness_8616(lhs, materialized_args)
        return dirty_verdict if dirty_verdict is not None else True

    @cython.ccall
    def _dirty_carrier_liveness_8616(
        self,
        lhs: StructuredAstValue,
        materialized_args: StructuredAstValue,
    ) -> bool | None:
        """Classify dirty-carrier liveness; None means keep checking."""
        if not isinstance(
            lhs, structured_c.CDirtyExpression
        ) or self.materialized_args_by_push_instruction_addr is None:
            return None
        liveness = classify_call_argument_carrier_liveness_8616(
            lhs,
            materialized_args,
        )
        if liveness.verdict is CallArgumentCarrierLivenessVerdict8616.LIVE_ARGUMENT_DEFINITION:
            self.preserved_live_definition_count += 1
            return False
        if liveness.verdict is CallArgumentCarrierLivenessVerdict8616.UNKNOWN_REFUSE:
            self.liveness_refusal_count += 1
            return False
        return None


def prune_consumed_call_push_stack_assignments_8616(
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    consumed_push_instruction_addrs: object,
    *,
    materialized_args_by_push_instruction_addr: Mapping[
        int, tuple[StructuredAstValue, ...]
    ]
    | None = None,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Prune lowered stack effects for PUSH instructions consumed as call arguments.

    Exact machine instruction provenance is mandatory. The pass removes only
    BP-local aliases, SP/dirty carriers, and segmented SS stores whose PUSH
    value has already been materialized in the typed call argument.
    """
    cfunc: object
    func_addr: object
    root: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    debug = bool(os.environ.get("INERTIA_DEBUG_CONSUMED_CALL_PUSH"))
    if root is None or not consumed_push_instruction_addrs:
        return False
    if function is None:
        func_addr = getattr(cfunc, "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    classifier = _PushCarrierClassifier8616(
        project=project,
        codegen=codegen,
        root=root,
        consumed_push_instruction_addrs=consumed_push_instruction_addrs,
        materialized_args_by_push_instruction_addr=materialized_args_by_push_instruction_addr,
        insn_by_addr=_instruction_by_addr_map_8616(project, function),
        debug=debug,
    )
    materialized_count = _prune_c_statement_lists_8616(root, classifier.is_false_push_carrier)

    result = ConsumedCallPushCarrierPrune8616(
        raw_fact_count=classifier.raw_count,
        normalized_fact_count=classifier.normalized_count,
        classified_fact_count=classifier.classified_count,
        materialized_count=materialized_count,
        failure_count=max(classifier.raw_count - classifier.classified_count, 0)
        + max(classifier.classified_count - materialized_count, 0),
        preserved_live_definition_count=classifier.preserved_live_definition_count,
        liveness_refusal_count=classifier.liveness_refusal_count,
    )
    codegen._inertia_consumed_call_push_carrier_prune_8616 = result
    if debug:
        log.warning(
            "[consumed-call-push] consumed_addrs=%s raw=%d normalized=%d "
            "classified=%d materialized=%d failures=%d",
            tuple(hex(address) for address in builtins.iter(sorted(consumed_push_instruction_addrs))),
            result.raw_fact_count,
            result.normalized_fact_count,
            result.classified_fact_count,
            result.materialized_count,
            result.failure_count,
        )
    return bool(materialized_count > 0)



@cython.ccall
def _is_far_call_cs_frame_value_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
) -> cython.bint:
    """Recognize the low or high byte of the current CS register."""
    node = _strip_casts_8616(node)
    if _expr_register_name_8616(node, project) == "cs":
        return True
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Shr":
        return False
    shift = _strip_casts_8616(node.rhs)
    return (
        isinstance(shift, structured_c.CConstant)
        and shift.value == 8
        and _expr_register_name_8616(node.lhs, project) == "cs"
    )


@cython.ccall
def _callsite_after_push_cs_8616(
    project: AngrProjectValue,
    push_ins_addr: cython.longlong,
    insn_by_addr: Mapping[cython.longlong, StructuredAstValue],
    return_addr_by_callsite: Mapping[cython.longlong, cython.longlong],
) -> int | None:
    """Prove a linked far-call ``PUSH CS; CALL`` return-segment prefix."""
    push_size: object
    push_insn = _instruction_at_or_decode_8616(project, push_ins_addr, insn_by_addr)
    if (
        operator.ne(getattr(push_insn, "id", None), X86_INS_PUSH)
        or operator.ne(_op_reg_id_8616(push_insn, 0), X86_REG_CS)
    ):
        return None
    push_size = getattr(push_insn, "size", None)
    if not isinstance(push_size, int) or push_size <= 0:
        return None
    callsite_addr = push_ins_addr + push_size
    if callsite_addr not in return_addr_by_callsite:
        return None
    call_insn = _instruction_at_or_decode_8616(project, callsite_addr, insn_by_addr)
    if getattr(call_insn, "id", None) not in {X86_INS_CALL, X86_INS_LCALL}:
        return None
    return callsite_addr


@cython.ccall
def _prune_c_statement_lists_8616(
    root: StructuredAstValue,
    drop: Callable[[StructuredAstValue], cython.bint],
) -> cython.longlong:
    """Drop statements matching the predicate from every CStatements list."""
    node: object
    statement: object
    materialized_count = 0
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, structured_c.CStatements):
            statements = node.statements
            retained: list[StructuredAstValue] = []
            for statement in tuple(statements):
                if drop(statement):
                    materialized_count += 1
                    continue
                retained.append(statement)
            statements[:] = retained
    return materialized_count


@cython.dataclasses.dataclass
class _CallReturnFrameClassifier8616:
    """Classify assignments against exact callsite return-frame evidence."""

    project: StructuredAstValue
    codegen: StructuredAstValue
    return_addr_by_callsite: StructuredAstValue
    insn_by_addr: StructuredAstValue
    debug_return_frame: StructuredAstValue
    raw_count: cython.longlong = 0
    normalized_count: cython.longlong = 0
    classified_count: cython.longlong = 0

    @cython.ccall
    def is_call_return_frame_carrier(self, statement: StructuredAstValue) -> cython.bint:
        """Classify one assignment against exact callsite return-frame evidence."""
        tags: object
        if not isinstance(statement, structured_c.CAssignment):
            return False
        lhs = statement.lhs
        tags = copy_structured_tags_8616(statement.tags)
        ins_addr = tags.get("ins_addr") if tags is not None else None
        rhs = statement.rhs
        self._debug_candidate_8616(ins_addr, lhs, rhs)
        if not (
            _is_consumed_push_stack_carrier_lhs_8616(self.project, lhs)
            or _is_consumed_push_ss_store_lhs_8616(self.project, self.codegen, lhs)
        ):
            return False
        if not isinstance(ins_addr, int):
            return False
        constant_return_value = (
            isinstance(rhs, structured_c.CConstant)
            and isinstance(rhs.value, int)
        )
        cs_frame_value = _is_far_call_cs_frame_value_8616(rhs, self.project)
        return self._classify_callsite_evidence_8616(
            rhs, ins_addr, constant_return_value, cs_frame_value
        )

    @cython.ccall
    def _debug_candidate_8616(
        self,
        ins_addr: StructuredAstValue,
        lhs: StructuredAstValue,
        rhs: StructuredAstValue,
    ) -> None:
        """Emit optional debug noise for a callsite-adjacent candidate."""
        if self.debug_return_frame and isinstance(ins_addr, int) and (
            ins_addr in self.return_addr_by_callsite
            or (ins_addr + 1) in self.return_addr_by_callsite
        ):
            log.warning(
                "[call-return-frame] candidate ins_addr=%#x lhs_type=%s "
                "rhs_type=%s indexed_ss_stack=%s",
                ins_addr,
                type(lhs).__name__,
                type(rhs).__name__,
                _is_indexed_ss_stack_store_lhs_8616(self.project, lhs),
            )

    @cython.ccall
    def _debug_reject_8616(
        self,
        ins_addr: cython.longlong,
        constant_return_value: cython.bint,
        cs_frame_value: cython.bint,
    ) -> None:
        """Emit optional debug noise for a rejected callsite."""
        if self.debug_return_frame:
            insn = _instruction_at_or_decode_8616(
                self.project,
                ins_addr,
                self.insn_by_addr,
            )
            log.warning(
                "[call-return-frame] reject ins_addr=%#x insn_id=%r "
                "insn_size=%r op0_reg=%r constant=%s cs=%s",
                ins_addr,
                getattr(insn, "id", None),
                getattr(insn, "size", None),
                _op_reg_id_8616(insn, 0),
                constant_return_value,
                cs_frame_value,
            )

    @cython.ccall
    def _classify_callsite_evidence_8616(
        self,
        rhs: StructuredAstValue,
        ins_addr: cython.longlong,
        constant_return_value: cython.bint,
        cs_frame_value: cython.bint,
    ) -> cython.bint:
        """Resolve the callsite and check the RHS against its return frame."""
        exact_callsite_addr: object
        prefixed_callsite_addr: object
        exact_callsite_addr = (
            ins_addr if ins_addr in self.return_addr_by_callsite else None
        )
        prefixed_callsite_addr = _callsite_after_push_cs_8616(
            self.project,
            ins_addr,
            self.insn_by_addr,
            self.return_addr_by_callsite,
        )
        if (
            not constant_return_value
            and not cs_frame_value
            and prefixed_callsite_addr is None
        ):
            return False
        if exact_callsite_addr is None and prefixed_callsite_addr is None:
            self._debug_reject_8616(ins_addr, constant_return_value, cs_frame_value)
            return False
        self.raw_count += 1
        self.normalized_count += 1
        insn = (
            _instruction_at_or_decode_8616(
                self.project,
                exact_callsite_addr,
                self.insn_by_addr,
            )
            if exact_callsite_addr is not None
            else None
        )
        if (
            exact_callsite_addr is not None
            and getattr(insn, "id", None) not in {X86_INS_CALL, X86_INS_LCALL}
        ):
            return False
        if not self._matches_return_frame_8616(
            rhs,
            insn,
            exact_callsite_addr,
            prefixed_callsite_addr,
            constant_return_value,
            cs_frame_value,
        ):
            return False
        self.classified_count += 1
        return True

    @cython.ccall
    def _matches_return_frame_8616(
        self,
        rhs: StructuredAstValue,
        insn: StructuredAstValue,
        exact_callsite_addr: object,
        prefixed_callsite_addr: object,
        constant_return_value: cython.bint,
        cs_frame_value: cython.bint,
    ) -> cython.bint:
        """Return whether the RHS is the callsite's return IP or CS part."""
        expected_return_addr: object
        expected_return_addr = (
            self.return_addr_by_callsite[exact_callsite_addr]
            if exact_callsite_addr is not None
            else None
        )
        is_return_ip = (
            expected_return_addr is not None
            and constant_return_value
            and operator.eq((int(rhs.value) & 0xFFFF), (int(expected_return_addr) & 0xFFFF))
        )
        is_return_cs = (
            cs_frame_value
            and operator.eq(getattr(insn, "id", None), X86_INS_LCALL)
        )
        is_return_cs |= prefixed_callsite_addr is not None
        return is_return_ip or is_return_cs


def prune_call_return_frame_stack_assignments_8616(
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    return_addr_by_callsite: Mapping[cython.longlong, cython.longlong],
    *,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Prune stack writes proven to model a CALL's machine return frame.

    A candidate is removable only when its statement tag names an actual CALL
    instruction or the exact ``PUSH CS`` immediately before one. Its RHS must
    be that callsite's typed fall-through return IP or an exact CS projection
    for a far call. Source-level writes that merely resemble return-frame
    values remain.
    """
    cfunc: object
    func_addr: object
    root: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    if root is None or not return_addr_by_callsite:
        return False
    debug_return_frame = bool(os.environ.get("INERTIA_DEBUG_CALL_RETURN_FRAME"))
    if debug_return_frame:
        log.warning(
            "[call-return-frame] callsites=%s",
            tuple(hex(address) for address in builtins.iter(sorted(return_addr_by_callsite))),
        )
    if function is None:
        func_addr = getattr(cfunc, "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    exact_result = prune_exact_call_return_frame_projections_8616(
        project,
        codegen,
        function,
        return_addr_by_callsite,
    )
    classifier = _CallReturnFrameClassifier8616(
        project=project,
        codegen=codegen,
        return_addr_by_callsite=return_addr_by_callsite,
        insn_by_addr=_instruction_by_addr_map_8616(project, function),
        debug_return_frame=debug_return_frame,
        raw_count=exact_result.raw_fact_count,
        normalized_count=exact_result.normalized_fact_count,
        classified_count=exact_result.classified_fact_count,
    )
    materialized_count = exact_result.materialized_count + _prune_c_statement_lists_8616(
        root, classifier.is_call_return_frame_carrier
    )

    result = CallReturnFrameCarrierPrune8616(
        raw_fact_count=classifier.raw_count,
        normalized_fact_count=classifier.normalized_count,
        classified_fact_count=classifier.classified_count,
        materialized_count=materialized_count,
        failure_count=max(classifier.classified_count - materialized_count, 0),
    )
    codegen._inertia_call_return_frame_carrier_prune_8616 = result
    _record_semantic_lane_8616(
        codegen,
        name="call-return-frame-carrier-prune",
        raw=classifier.raw_count,
        normalized=classifier.normalized_count,
        classified=classifier.classified_count,
        materialized=materialized_count,
        failures=result.failure_count,
    )
    restore_changed = rebind_balanced_memory_stack_restores_8616(
        codegen,
        function,
        project=project,
    )
    return bool(materialized_count > 0 or restore_changed)


@cython.ccall
def _frame_setup_addr_8616(
    project: AngrProjectValue,
    function_addr: cython.longlong,
    insn_by_addr: StructuredAstValue,
) -> int | None:
    """Decode the ``push bp`` / ``mov bp, sp`` entry pair addresses."""
    push_bp: object
    push_size: object
    setup: object
    setup_addr: int | None = None
    push_bp = _instruction_at_or_decode_8616(project, function_addr, insn_by_addr)
    if push_bp is not None:
        insn_by_addr[function_addr] = push_bp
        push_size = getattr(push_bp, "size", None)
        if isinstance(push_size, int) and push_size > 0:
            setup_addr = function_addr + push_size
            setup = _instruction_at_or_decode_8616(project, setup_addr, insn_by_addr)
            if setup is not None:
                insn_by_addr[setup_addr] = setup
    return setup_addr


def _prove_frame_entry_carrier_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    function_addr: cython.longlong,
    setup_addr: object,
    frame_instruction_addresses: StructuredAstValue,
    register_carriers: StructuredAstValue,
) -> cython.bint:
    """Prove the canonical BP frame entry carrier exists and its uses complete."""
    entry_carrier_proven = any(
        is_exact_push_bp_carrier_8616(
            node,
            root,
            project,
            function_addr,
            canonical_frame_proven=function_addr in frame_instruction_addresses,
            codegen=codegen,
            register_carriers=register_carriers,
        )
        for node in builtins.iter(_iter_c_nodes_deep_8616(root))
    )
    if (
        not entry_carrier_proven
        and setup_addr is not None
        and setup_addr in frame_instruction_addresses
    ):
        entry_carrier_proven = any(
            is_exact_bp_frame_setup_carrier_8616(
                node,
                project,
                setup_addr,
                register_carriers=register_carriers,
            )
            for node in builtins.iter(_iter_c_nodes_deep_8616(root))
        )
    return entry_carrier_proven and prove_frame_carrier_uses_8616(
        root, frozenset(frame_instruction_addresses),
    ).complete


def prune_frame_prologue_stack_assignments_8616(
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
    *,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Consume exact C carriers for a canonical BP frame and its teardown.

    A matching structured carrier for ``push bp`` or ``mov bp, sp`` proves that
    instruction tags and the decoded entry pair agree. Only then are
    assignments owned by the entry pair and contiguous
    ``mov sp, bp; pop bp; ret`` sequences consumed, and only if their scalar
    definitions have no surviving uses outside the complete frame group.
    """
    cfunc: object
    func_addr: object
    function_addr: object
    previous_result: object
    root: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    if root is None:
        return False
    if function is None:
        func_addr = getattr(cfunc, "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    function_addr = getattr(function, "addr", None)
    if function is None or not isinstance(function_addr, int):
        return False

    insn_by_addr = _instruction_by_addr_map_8616(project, function)
    setup_addr = _frame_setup_addr_8616(project, function_addr, insn_by_addr)
    frame_instruction_addresses = canonical_frame_instruction_addresses_8616(
        insn_by_addr,
        function_addr,
    )
    register_carriers = collect_frame_register_carriers_8616(root, project, function_addr)
    entry_carrier_proven = _prove_frame_entry_carrier_8616(
        root,
        project,
        codegen,
        function_addr,
        setup_addr,
        frame_instruction_addresses,
        register_carriers,
    )
    register_carriers = register_carriers.with_frame_proof(entry_carrier_proven)
    if register_carriers.raw_fact_count:
        _record_semantic_lane_8616(
            codegen,
            name="frame-prologue-register-carriers",
            raw=register_carriers.raw_fact_count,
            normalized=register_carriers.normalized_fact_count,
            classified=register_carriers.classified_fact_count,
            materialized=register_carriers.materialized_count,
            failures=register_carriers.failure_count,
        )

    raw_count = 0
    normalized_count = 0
    classified_count = 0

    def is_prologue_carrier(statement: StructuredAstValue) -> cython.bint:
        """Classify one assignment owned by the proven canonical BP frame."""
        tags: object
        nonlocal raw_count, normalized_count, classified_count
        if not entry_carrier_proven or not isinstance(statement, structured_c.CAssignment):
            return False
        tags = copy_structured_tags_8616(statement.tags)
        ins_addr = tags.get("ins_addr") if tags is not None else None
        if ins_addr not in frame_instruction_addresses:
            return False
        raw_count += 1
        normalized_count += 1
        classified_count += 1
        return True

    pruner = _StatementListPruner8616(drop=is_prologue_carrier, seen=set())
    pruner.visit(root)
    materialized_count = pruner.removed
    evidence_owner = cast(_FramePrologueCarrierPruneOwner8616, codegen)
    try:
        previous_result = evidence_owner._inertia_frame_prologue_carrier_prune_8616
    except AttributeError:
        previous_result = None
    if (
        previous_result is not None
        and raw_count == 0
        and normalized_count == 0
        and classified_count == 0
        and materialized_count == 0
    ):
        return False

    result = FramePrologueCarrierPrune8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=max(classified_count - materialized_count, 0),
    )
    evidence_owner._inertia_frame_prologue_carrier_prune_8616 = result
    _record_semantic_lane_8616(
        codegen,
        name="frame-prologue-carrier-prune",
        raw=raw_count,
        normalized=normalized_count,
        classified=classified_count,
        materialized=materialized_count,
        failures=result.failure_count,
    )
    return materialized_count > 0


@cython.ccall
def _instruction_block_addr_8616(
    project: StructuredAstValue, function: object, ins_addr: cython.longlong
) -> int | None:
    block_addr: object
    candidate: object
    if function is None:
        return None
    block_by_insn = _instruction_block_addr_map_8616(project, function)
    block_addrs = {int(block_addr) for block_addr in builtins.iter(block_by_insn.values()) if isinstance(block_addr, int)}
    for candidate in _candidate_ins_addrs_8616(project, ins_addr):
        block_addr = block_by_insn.get(int(candidate))
        if isinstance(block_addr, int):
            return block_addr
        if int(candidate) in block_addrs:
            return int(candidate)
    return None


@cython.ccall
def _instruction_at_addr_8616(
    project: AngrProjectValue, function: object, ins_addr: cython.longlong
) -> StructuredAstValue:
    insn: object
    candidate: object
    if function is None:
        return None
    insn_by_addr = _instruction_by_addr_map_8616(project, function)
    for candidate in _candidate_ins_addrs_8616(project, ins_addr):
        insn = insn_by_addr.get(int(candidate))
        if insn is not None:
            return insn
    return None


@cython.ccall
def _is_direct_call_fallthrough_predecessor_8616(
    project: AngrProjectValue, function: StructuredAstValue, left_addr: cython.longlong, right_addr: cython.longlong
) -> cython.bint:
    call_size: object
    call_insn = _instruction_at_addr_8616(project, function, left_addr)
    if getattr(call_insn, "id", None) not in {X86_INS_CALL, X86_INS_LCALL}:
        return False
    call_size = getattr(call_insn, "size", None)
    if not isinstance(call_size, int) or call_size <= 0:
        return False
    right_block = _instruction_block_addr_8616(project, function, right_addr)
    if not isinstance(right_block, int):
        return False
    return operator.eq(int(left_addr) + int(call_size), right_block)


@cython.ccall
def _has_callsite_fallthrough_between_8616(
    project: AngrProjectValue, function: StructuredAstValue, left_addr: cython.longlong, right_addr: cython.longlong
) -> cython.bint:
    call_addr: object
    insn_by_addr = _instruction_by_addr_map_8616(project, function)
    if not insn_by_addr:
        return False
    for call_addr in sorted(insn_by_addr):
        if not (int(left_addr) < int(call_addr) < int(right_addr)):
            continue
        call_insn = insn_by_addr[call_addr]
        if getattr(call_insn, "id", None) not in {X86_INS_CALL, X86_INS_LCALL}:
            continue
        if _is_direct_call_fallthrough_predecessor_8616(project, function, call_addr, right_addr):
            return True
    return False


@cython.ccall
def _same_instruction_block_8616(
    project: AngrProjectValue, function: object, left_addr: cython.longlong, right_addr: cython.longlong
) -> cython.bint:
    left_block: object
    right_block: object
    if function is None:
        return True
    if not _instruction_block_addr_map_8616(project, function):
        return True
    left_block = _instruction_block_addr_8616(project, function, left_addr)
    right_block = _instruction_block_addr_8616(project, function, right_addr)
    if left_block is None or right_block is None:
        return True
    if operator.eq(left_block, right_block):
        return True
    return _is_direct_call_fallthrough_predecessor_8616(
        project, function, left_addr, right_addr
    ) or _has_callsite_fallthrough_between_8616(project, function, left_addr, right_addr)


@cython.ccall
def _strict_same_instruction_block_8616(
    project: StructuredAstValue, function: object, left_addr: cython.longlong, right_addr: cython.longlong
) -> cython.bint:
    left_block: object
    right_block: object
    if function is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning("[direct-stack-update] function unavailable")
        return False
    if not _instruction_block_addr_map_8616(project, function):
        return False
    left_block = _instruction_block_addr_8616(project, function, left_addr)
    right_block = _instruction_block_addr_8616(project, function, right_addr)
    if left_block is None or right_block is None:
        return False
    if operator.eq(left_block, right_block):
        return True
    return _is_direct_call_fallthrough_predecessor_8616(
        project, function, left_addr, right_addr
    ) or _has_callsite_fallthrough_between_8616(project, function, left_addr, right_addr)


def _list_has_stack_move_assignment_8616(
    statements: object, dst_cvar: StructuredAstValue, source_expr: StructuredAstValue
) -> cython.bint:
    return any(_is_same_stack_move_assignment_8616(stmt, dst_cvar, source_expr) for stmt in iter(statements))


@cython.ccall
def _tree_has_stack_move_assignment_8616(
    root: StructuredAstValue, dst_cvar: StructuredAstValue, source_expr: StructuredAstValue
) -> cython.bint:
    child: object
    attr: object
    node: object
    if _is_same_stack_move_assignment_8616(root, dst_cvar, source_expr):
        return True
    for node in _iter_structured_c_nodes_8616(root):
        if _is_same_stack_move_assignment_8616(node, dst_cvar, source_expr):
            return True
        for attr in ("initializer", "init", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None and _is_same_stack_move_assignment_8616(
                _first_transparent_assignment_8616(child),
                dst_cvar,
                source_expr,
            ):
                return True
    return False


def _prune_inverse_stack_move_artifacts_8616(
    root: StructuredAstValue,
    facts: object,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
) -> cython.longlong:
    """Remove stack-copy assignments contradicted by a binary-proven MOV direction."""
    source_offset: object
    if fact.source_kind is not DirectStackMoveSourceKind8616.STACK_SLOT:
        return 0
    dst_offset = _c_expr_stack_offset_8616(dst_cvar)
    source_offset = _c_expr_stack_offset_8616(source_expr)
    if source_offset is None and isinstance(fact.source_offset, int):
        source_offset = _canonical_stack_offset_8616(fact.source_offset)
    if not isinstance(dst_offset, int) or not isinstance(source_offset, int) or operator.eq(dst_offset, source_offset):
        return 0
    has_inverse_fact = any(
        candidate.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT
        and operator.eq(_canonical_stack_offset_8616(candidate.dst_offset), source_offset)
        and operator.eq(_canonical_stack_offset_8616(candidate.source_offset), dst_offset)
        for candidate in iter(facts)
    )
    if has_inverse_fact:
        return 0

    def is_inverse_assignment(node: StructuredAstValue) -> cython.bint:
        """Return whether a node is an exact inverse stack-copy assignment."""
        lhs: object
        rhs: object
        lhs = getattr(node, "lhs", None)
        rhs = getattr(node, "rhs", None)
        lhs_offset = _c_expr_stack_offset_8616(_strip_casts_8616(lhs))
        rhs_offset = _c_expr_stack_offset_8616(_strip_casts_8616(rhs))
        return (
            isinstance(node, structured_c.CAssignment)
            and (lhs_offset == source_offset or _same_stack_cvar_8616(lhs, source_expr))
            and (rhs_offset == dst_offset or _same_stack_move_rhs_8616(rhs, dst_cvar))
        )

    def statement_is_inverse_assignment(node: StructuredAstValue) -> cython.bint:
        """Return whether a statement or its expr is an inverse assignment."""
        expr: object
        if is_inverse_assignment(node):
            return True
        expr = getattr(node, "expr", None)
        return is_inverse_assignment(expr)

    pruner = _StatementListPruner8616(
        drop=statement_is_inverse_assignment,
        seen=set(),
        child_attrs=("body", "else_node", "initializer", "init", "iteration", "iterator"),
    )
    pruner.visit(root)
    return pruner.removed


@cython.ccall
def _collect_function_pointer_allowed_sources_8616(
    codegen: StructuredAstValue,
    facts: object,
) -> tuple[
    dict[tuple[cython.longlong, int | None], list[StructuredAstValue]],
    dict[tuple[cython.longlong, int | None], set[cython.longlong]],
]:
    """Collect proven function-pointer stack writes per destination identity."""
    dst_identity: object
    source_identity: object
    fact: object
    allowed_sources: dict[tuple[cython.longlong, int | None], list[StructuredAstValue]] = {}
    direct_write_addrs: dict[tuple[cython.longlong, int | None], set[cython.longlong]] = {}
    for fact in facts:
        if fact.source_kind is not DirectStackMoveSourceKind8616.IMMEDIATE:
            continue
        dst_cvar = _resolve_direct_stack_update_cvar_8616(codegen, fact.dst_offset, fact.width)
        if _function_pointer_stack_slot_type_8616(dst_cvar) is None:
            continue
        source_expr = _direct_stack_move_source_expr_8616(codegen, fact, dst_cvar)
        source_identity = _semantic_cvar_identity_8616(source_expr)
        if source_identity is None or source_identity[0] != "mem":
            continue
        dst_identity = _stack_cvar_identity_8616(dst_cvar)
        if dst_identity is None:
            continue
        allowed_sources.setdefault(dst_identity, []).append(source_expr)
        direct_write_addrs.setdefault(dst_identity, set()).add(int(fact.ins_addr))
    return allowed_sources, direct_write_addrs


def _prune_unsupported_function_pointer_stack_move_assignments_8616(
    root: StructuredAstValue,
    codegen: StructuredAstValue,
    facts: object,
) -> cython.longlong:
    """Drop untagged stack writes contradicted by direct function-pointer MOV facts."""
    allowed_sources, direct_write_addrs = _collect_function_pointer_allowed_sources_8616(
        codegen, facts
    )
    if not allowed_sources:
        return 0

    def assignment_is_unsupported(stmt: StructuredAstValue) -> cython.bint:
        """Return whether an untagged stack write contradicts direct MOV evidence."""
        tags: object
        allowed_source: object
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        dst_identity = _stack_cvar_identity_8616(stmt.lhs)
        if dst_identity not in allowed_sources:
            return False
        tags = copy_structured_tags_8616(stmt.tags)
        if (
            tags is not None
            and isinstance(tagged_addr := tags.get("ins_addr"), int)
            and tagged_addr in direct_write_addrs.get(dst_identity, set())
        ):
            return False
        rhs = stmt.rhs
        for allowed_source in allowed_sources[dst_identity]:
            if _same_stack_move_rhs_8616(rhs, allowed_source):
                return False
        return True

    pruner = _StatementListPruner8616(
        drop=assignment_is_unsupported,
        seen=set(),
        child_attrs=("body", "else_node", "initializer", "init", "iteration", "iterator"),
    )
    pruner.visit(root)
    return pruner.removed


def prune_unsupported_function_pointer_stack_move_assignments_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue | None = None,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Prune function-pointer stack writes only when contradicted by direct MOV facts."""
    func_addr: object
    root: object
    stats: object
    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False
    if function is None:
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    facts = _direct_stack_move_instruction_facts_for_codegen_8616(
        codegen,
        project,
        function,
    )
    if not facts:
        return False
    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(stats, dict):
        stats = {
            "raw_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "already_materialized_count": 0,
            "failure_count": 0,
        }
        codegen._inertia_direct_stack_move_lowering_8616 = stats
    pruned = _prune_unsupported_function_pointer_stack_move_assignments_8616(root, codegen, facts)
    if pruned <= 0:
        return False
    stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + len(facts)
    stats["classified_fact_count"] = int(stats.get("classified_fact_count", 0) or 0) + len(facts)
    stats["materialized_count"] = int(stats.get("materialized_count", 0) or 0) + pruned
    stats["unsupported_function_pointer_assignment_pruned_count"] = (
        int(stats.get("unsupported_function_pointer_assignment_pruned_count", 0) or 0) + pruned
    )
    evidence = _boundary_tuple_8616(getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ())
    evidence_items = tuple(
        (
            ("dst_offset", fact.dst_offset),
            ("width", fact.width),
            ("source_kind", fact.source_kind),
            ("source_value", fact.source_value),
            ("source_offset", fact.source_offset),
            ("ins_addr", fact.ins_addr),
        )
        for fact in iter(facts)
    )
    codegen._inertia_direct_stack_move_evidence_8616 = tuple(dict.fromkeys(evidence + evidence_items))
    with contextlib.suppress(Exception):
        codegen.cfunc.body = root
    return True


@cython.ccall
def _is_same_stack_move_assignment_8616(
    stmt: StructuredAstValue, dst_cvar: StructuredAstValue, source_expr: StructuredAstValue
) -> cython.bint:
    return (
        isinstance(stmt, structured_c.CAssignment)
        and _same_stack_cvar_8616(getattr(stmt, "lhs", None), dst_cvar)
        and _same_stack_move_rhs_8616(getattr(stmt, "rhs", None), source_expr)
    )


@cython.ccall
def _is_same_stack_move_assignment_surface_8616(
    actual: StructuredAstValue,
    expected: StructuredAstValue,
) -> cython.bint:
    """Return whether equivalent assignments already use the canonical storage surface."""
    if not isinstance(expected, structured_c.CAssignment) or not _is_same_stack_move_assignment_8616(
        actual,
        expected.lhs,
        expected.rhs,
    ):
        return False
    if not isinstance(actual.lhs, structured_c.CVariable) or not isinstance(
        expected.lhs,
        structured_c.CVariable,
    ):
        return True
    return (
        actual.lhs.variable is expected.lhs.variable
        and actual.lhs.unified_variable is expected.lhs.unified_variable
    )


def _removable_tagged_stack_move_assignment_count_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    dst_cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
) -> cython.longlong:
    """Count exact tagged stack assignments stored in mutable statement lists."""
    count = 0
    seen: set[cython.longlong] = set()

    def visit(node: object) -> None:
        """Count matches reachable through the same mutable lists as removal."""
        pairs: object
        statements: object
        _condition: object
        attr: object
        body: object
        stmt: object
        nonlocal count
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for stmt in tuple(statements):
                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and _is_same_stack_move_assignment_8616(stmt, dst_cvar, source_expr)
                    and _node_has_instruction_address_8616(stmt, project, ins_addr)
                ):
                    count += 1
                    continue
                visit(stmt)
        for attr in ("body", "else_node"):
            visit(getattr(node, attr, None))
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                visit(body)

    visit(root)
    return count


def _remove_tagged_stack_move_assignments_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    dst_cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
) -> cython.longlong:
    """Remove exact late tagged assignments after a proven relocation."""
    removed = 0
    seen: set[cython.longlong] = set()

    def visit(node: object) -> None:
        """Prune matching assignments from mutable structured statement lists."""
        pairs: object
        statements: object
        _condition: object
        attr: object
        body: object
        stmt: object
        nonlocal removed
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            kept = []
            for stmt in tuple(statements):
                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and _is_same_stack_move_assignment_8616(stmt, dst_cvar, source_expr)
                    and _node_has_instruction_address_8616(stmt, project, ins_addr)
                ):
                    removed += 1
                    continue
                kept.append(stmt)
                visit(stmt)
            statements[:] = kept
        for attr in ("body", "else_node"):
            visit(getattr(node, attr, None))
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                visit(body)

    visit(root)
    return removed


@cython.dataclasses.dataclass
class _StatementListPruner8616:
    """Prune matching assignments from executable structured statement lists."""

    drop: Callable[[StructuredAstValue], cython.bint]
    seen: object
    child_attrs: tuple[str, ...] = ("body", "else_node")
    removed: cython.longlong = 0

    @cython.ccall
    def visit(self, node: object) -> None:
        """Prune matching statements, then recurse into nested containers."""
        statements: object
        stmt: object
        if node is None or id(node) in self.seen:
            return
        if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            kept: list[StructuredAstValue] = []
            for stmt in tuple(statements):
                if self.drop(stmt):
                    self.removed += 1
                    continue
                kept.append(stmt)
                self.visit(stmt)
            statements[:] = kept
        self._visit_children_8616(node)

    @cython.ccall
    def _visit_children_8616(self, node: StructuredAstValue) -> None:
        """Recurse into the configured child links and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in self.child_attrs:
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                self.visit(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.visit(body)


def _remove_duplicate_stack_move_assignments_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    dst_cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
    preserved_assignment: StructuredAstValue,
) -> cython.longlong:
    """Remove exact stale copies after a binary-proven loop-entry relocation.

    Regeneration may discard the original instruction tag while retaining the
    assignment.  An exact untagged copy is therefore removable here, but an
    assignment owned by a different instruction remains independent evidence.
    """
    candidate_addrs = _candidate_ins_addrs_8616(project, ins_addr)

    def is_duplicate(stmt: StructuredAstValue) -> cython.bint:
        """Return whether a statement is the relocated store's stale carrier."""
        tagged_addr: object
        tags: object
        if stmt is preserved_assignment or not _is_same_stack_move_assignment_8616(
            stmt, dst_cvar, source_expr
        ):
            return False
        tags = copy_structured_tags_8616(stmt.tags)
        if tags is None:
            return True
        tagged_addr = tags.get("ins_addr")
        if not isinstance(tagged_addr, int):
            tagged_addr = tags.get("inertia_relocated_from_ins_addr")
        return not isinstance(tagged_addr, int) or tagged_addr in candidate_addrs

    pruner = _StatementListPruner8616(drop=is_duplicate, seen=set())
    pruner.visit(root)
    return pruner.removed


def _remove_consumed_signed_idiv_store_assignments_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    fact: DirectStackMoveFact8616,
    dst_cvar: StructuredAstValue,
    preserved_assignment: StructuredAstValue,
) -> cython.longlong:
    """Remove the exact remainder store consumed by a callsite assignment.

    Lowering may first rewrite the binary remainder-store instruction through
    an SSA call-result carrier, then replace the exact call statement with the
    complete signed-remainder assignment.  The latter assignment consumes the
    former store.  Only an exact machine-tagged write to the proven destination
    with a modulo RHS is removable; untagged and independently tagged writes
    remain executable evidence.
    """
    if (
        fact.source_kind
        is not DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
        or not isinstance(fact.ins_addr, int)
    ):
        return 0

    def is_consumed_store(statement: StructuredAstValue) -> cython.bint:
        """Return whether the statement is the consumed tagged remainder store."""
        return (
            statement is not preserved_assignment
            and isinstance(statement, structured_c.CAssignment)
            and _same_stack_cvar_8616(statement.lhs, dst_cvar)
            and _node_has_instruction_address_8616(
                statement,
                project,
                fact.ins_addr,
            )
            and _expr_has_binary_op_8616(
                statement.rhs,
                DirectStackMoveExpressionOp8616.MOD,
            )
        )

    pruner = _StatementListPruner8616(drop=is_consumed_store, seen=set())
    pruner.visit(root)
    return pruner.removed



def _structured_loopback_edges_covering_instruction_8616(
    function: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    loop_range: object,
    condition_range: object,
) -> tuple[tuple[cython.longlong, cython.longlong], ...]:
    """Return binary backedges that contain the store and cover the structured loop."""
    if loop_range is None:
        return ()
    _loop_start, loop_end = loop_range
    repeated_region_start = (
        condition_range[0] if condition_range is not None else loop_range[0]
    )
    store_candidates = _candidate_function_ins_addrs_8616(
        project,
        function,
        ins_addr,
    )
    return tuple(
        (entry, jump)
        for entry, jump in builtins.iter(_function_backward_jump_edges_8616(function, project, ins_addr))
        if entry <= repeated_region_start
        and jump >= loop_end
        and any(entry <= candidate <= jump for candidate in iter(store_candidates))
    )


@cython.ccall
def _loop_body_insertion_index_before_tagged_stack_move_8616(
    loop: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    dst_cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
) -> int | None:
    """Return the first sibling read that must follow the tagged stack definition."""
    body_statements: object
    first_read_index: object
    index: object
    stmt: object
    body_statements = getattr(getattr(loop, "body", None), "statements", None)
    if not isinstance(body_statements, list):
        return None
    first_read_index = None
    for index, stmt in enumerate(tuple(body_statements)):
        direct_tagged_move = (
            isinstance(stmt, structured_c.CAssignment)
            and _is_same_stack_move_assignment_8616(stmt, dst_cvar, source_expr)
            and _node_has_instruction_address_8616(stmt, project, ins_addr)
        )
        nested_tagged_move = _removable_tagged_stack_move_assignment_count_8616(
            stmt,
            project,
            ins_addr,
            dst_cvar,
            source_expr,
        )
        if direct_tagged_move or nested_tagged_move:
            return first_read_index
        if first_read_index is None and _node_reads_stack_cvar_8616(stmt, dst_cvar):
            first_read_index = index
    return None


@cython.dataclasses.dataclass
class _TaggedLoopMoveRelocater8616:
    """Restore an exact tagged stack definition at its binary-proven loop scope."""

    project: StructuredAstValue
    function: StructuredAstValue
    ins_addr: StructuredAstValue
    dst_cvar: StructuredAstValue
    source_expr: StructuredAstValue
    assignment: StructuredAstValue
    backward_edges: StructuredAstValue
    seen: StructuredAstValue

    @cython.ccall
    def visit(self, node: object) -> cython.longlong:
        """Prefer the deepest loop with sufficient binary placement evidence."""
        statements: object
        if node is None or id(node) in self.seen:
            return 0
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            result = self._visit_statements_8616(statements)
            if result:
                return result
        return self._visit_control_links_8616(node)

    @cython.ccall
    def _visit_statements_8616(self, statements: object) -> cython.longlong:
        """Scan each statement; loop containers get the relocation arms."""
        index: object
        stmt: object
        for index, stmt in enumerate(tuple(statements)):
            if isinstance(
                stmt, (structured_c.CForLoop, structured_c.CWhileLoop, structured_c.CDoWhileLoop)
            ):
                result = self._visit_loop_statement_8616(statements, index, stmt)
                if result:
                    return result
                continue
            nested = self.visit(stmt)
            if nested:
                return nested
        return 0

    def _visit_loop_statement_8616(
        self,
        statements: object,
        index: cython.longlong,
        stmt: StructuredAstValue,
    ) -> cython.longlong:
        """Try the in-loop and before-loop relocation arms for one loop."""
        condition_range: object
        loop_range: object
        nested = self.visit(getattr(stmt, "body", None))
        if nested:
            return nested
        if isinstance(stmt, structured_c.CDoWhileLoop):
            # Post-test conditions execute after the body. Keep exact
            # body stores in place so loop-carried state is preserved.
            return 0
        tagged_count = _removable_tagged_stack_move_assignment_count_8616(
            stmt,
            self.project,
            self.ins_addr,
            self.dst_cvar,
            self.source_expr,
        )
        if tagged_count == 0:
            return 0
        condition_range = _instruction_addr_range_in_node_8616(
            getattr(stmt, "condition", None),
            self.project,
            self.ins_addr,
        )
        loop_range = _instruction_addr_range_in_node_8616(stmt, self.project, self.ins_addr)
        store_candidates = _candidate_function_ins_addrs_8616(
            self.project,
            self.function,
            self.ins_addr,
        )
        covering_loopback_edges = _structured_loopback_edges_covering_instruction_8616(
            self.function,
            self.project,
            self.ins_addr,
            loop_range,
            condition_range,
        )
        following_loop_addr = _following_instruction_addr_in_node_8616(
            stmt,
            self.project,
            self.ins_addr,
            set(),
        )
        in_loop_insertion_index = (
            _loop_body_insertion_index_before_tagged_stack_move_8616(
                stmt,
                self.project,
                self.ins_addr,
                self.dst_cvar,
                self.source_expr,
            )
        )
        machine_loop_after_store = bool(
            loop_range is not None
            and any(
                any(candidate < entry for candidate in iter(store_candidates))
                and (
                    entry <= loop_range[0]
                    or (
                        condition_range is None
                        and isinstance(following_loop_addr, int)
                        and entry <= following_loop_addr
                    )
                )
                and jump >= loop_range[1]
                for entry, jump in iter(self.backward_edges)
            )
        )
        self._debug_loop_relocate_8616(
            stmt,
            tagged_count,
            condition_range,
            loop_range,
            machine_loop_after_store,
            covering_loopback_edges,
            in_loop_insertion_index,
        )
        result = self._try_in_loop_relocate_8616(
            stmt,
            tagged_count,
            covering_loopback_edges,
            in_loop_insertion_index,
        )
        if result:
            return result
        return self._try_before_loop_relocate_8616(
            statements,
            index,
            stmt,
            tagged_count,
            condition_range,
            store_candidates,
            machine_loop_after_store,
        )

    @cython.ccall
    def _debug_loop_relocate_8616(
        self,
        stmt: StructuredAstValue,
        tagged_count: cython.longlong,
        condition_range: object,
        loop_range: object,
        machine_loop_after_store: cython.bint,
        covering_loopback_edges: StructuredAstValue,
        in_loop_insertion_index: object,
    ) -> None:
        """Emit optional debug noise for the loop relocation decision."""
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-move-before-loop] ins=%#x tagged=%d condition=%r loop=%r "
                "machine_after=%s covering=%r read_before_tagged=%s reads_dst=%s",
                self.ins_addr,
                tagged_count,
                condition_range,
                loop_range,
                machine_loop_after_store,
                covering_loopback_edges,
                in_loop_insertion_index is not None,
                _node_reads_stack_cvar_8616(stmt, self.dst_cvar),
            )

    @cython.ccall
    def _try_in_loop_relocate_8616(
        self,
        stmt: StructuredAstValue,
        tagged_count: cython.longlong,
        covering_loopback_edges: StructuredAstValue,
        in_loop_insertion_index: object,
    ) -> cython.longlong:
        """Insert inside the loop when a covering loopback edge proves it."""
        loop_body_statements: object
        if not (
            tagged_count > 0 and covering_loopback_edges and in_loop_insertion_index is not None
        ):
            return 0
        loop_body_statements = getattr(
            getattr(stmt, "body", None),
            "statements",
            None,
        )
        if not isinstance(loop_body_statements, list):
            return 0
        loop_body_statements.insert(in_loop_insertion_index, self.assignment)
        removed = _remove_duplicate_stack_move_assignments_8616(
            stmt,
            self.project,
            self.ins_addr,
            self.dst_cvar,
            self.source_expr,
            self.assignment,
        )
        if removed != tagged_count:
            raise AssertionError("tagged stack-move count changed during in-loop relocation")
        return removed

    def _try_before_loop_relocate_8616(
        self,
        statements: object,
        index: cython.longlong,
        stmt: StructuredAstValue,
        tagged_count: cython.longlong,
        condition_range: object,
        store_candidates: StructuredAstValue,
        machine_loop_after_store: cython.bint,
    ) -> cython.longlong:
        """Relocate the tagged copy just before the loop when proven safe."""
        condition_store_before = condition_range is not None and any(
            candidate < condition_range[0] for candidate in iter(store_candidates)
        )
        if not (
            tagged_count > 0
            and (condition_store_before or machine_loop_after_store)
            and _node_reads_stack_cvar_8616(stmt, self.dst_cvar)
        ):
            return 0
        removed = _remove_tagged_stack_move_assignments_8616(
            stmt,
            self.project,
            self.ins_addr,
            self.dst_cvar,
            self.source_expr,
        )
        if removed != tagged_count:
            raise AssertionError("tagged stack-move count changed during relocation")
        if _list_has_stack_move_assignment_8616(
            statements[:index],
            self.dst_cvar,
            self.source_expr,
        ):
            return removed
        insertion_index = self._relocated_insertion_index_8616(statements, index)
        statements.insert(insertion_index, self.assignment)
        return removed

    @cython.ccall
    def _relocated_insertion_index_8616(
        self, statements: object, index: cython.longlong
    ) -> cython.longlong:
        """Walk back over previously relocated stores of a later origin."""
        previous_origin: object
        previous_tags: object
        insertion_index = index
        while insertion_index > 0:
            previous_tags = copy_structured_tags_8616(
                getattr(statements[insertion_index - 1], "tags", None)
            )
            if previous_tags is None:
                break
            previous_origin = previous_tags.get("inertia_relocated_from_ins_addr")
            if not isinstance(previous_origin, int):
                break
            if previous_origin <= self.ins_addr:
                break
            insertion_index -= 1
        return insertion_index

    @cython.ccall
    def _visit_control_links_8616(self, node: StructuredAstValue) -> cython.longlong:
        """Recurse into bodies, else branches, and condition/body pairs."""
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node"):
            nested = self.visit(getattr(node, attr, None))
            if nested:
                return nested
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                nested = self.visit(body)
                if nested:
                    return nested
        return 0


@cython.ccall
def _relocate_tagged_stack_move_before_proven_loop_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    function: StructuredAstValue,
    ins_addr: cython.longlong,
    dst_cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
    assignment: StructuredAstValue,
) -> cython.longlong:
    """Restore an exact tagged stack definition at its binary-proven loop scope."""
    relocater = _TaggedLoopMoveRelocater8616(
        project=project,
        function=function,
        ins_addr=ins_addr,
        dst_cvar=dst_cvar,
        source_expr=source_expr,
        assignment=assignment,
        backward_edges=_function_backward_jump_edges_8616(function, project, ins_addr),
        seen=set(),
    )
    return relocater.visit(root)



@cython.ccall
def _collect_later_stack_update_candidates_8616(
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
    function: StructuredAstValue,
    fact: DirectStackMoveFact8616,
) -> object:
    """Collect same-block stack updates that follow the move instruction."""
    update_cvar: object
    update_source: object
    update_fact: object
    update_candidates: list[
        tuple[DirectStackUpdateFact8616, StructuredAstValue, StructuredAstValue]
    ] = []
    for update_fact in _direct_stack_update_instruction_facts_8616(project, function):
        same_block = _strict_same_instruction_block_8616(
            project,
            function,
            update_fact.ins_addr,
            fact.ins_addr,
        )
        if update_fact.ins_addr <= fact.ins_addr or not same_block:
            continue
        update_cvar = _resolve_direct_stack_update_cvar_8616(
            codegen,
            update_fact.offset,
            update_fact.width,
        )
        if (
            update_cvar is None
            or not isinstance(fact.source_index_offset, int)
            or operator.ne(fact.source_index_offset, update_fact.offset)
        ):
            continue
        update_source = _direct_stack_update_source_expr_8616(
            codegen,
            update_fact,
        )
        if update_source is not None:
            update_candidates.append((update_fact, update_cvar, update_source))
    return update_candidates


def _locate_move_update_positions_8616(
    root: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_expr: StructuredAstValue,
    source_expr: StructuredAstValue,
    update_cvar: StructuredAstValue,
    update_fact: StructuredAstValue,
    update_source: StructuredAstValue,
) -> tuple[
    list[tuple[cython.longlong, list[StructuredAstValue], cython.longlong]],
    list[tuple[cython.longlong, list[StructuredAstValue], cython.longlong]],
]:
    """Return render-order locations of the move and update assignments."""
    index: object
    node: object
    statement: object
    move_locations: list[tuple[cython.longlong, list[StructuredAstValue], cython.longlong]] = []
    update_locations: list[tuple[cython.longlong, list[StructuredAstValue], cython.longlong]] = []
    render_order = 0
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        statements = node.statements
        for index, statement in enumerate(statements):
            if _is_same_stack_move_assignment_8616(
                statement,
                dst_expr,
                source_expr,
            ):
                move_locations.append((render_order, statements, index))
            if _is_same_stack_update_assignment_8616(
                statement,
                update_cvar,
                update_fact.delta,
                update_source,
                update_fact.operation,
            ):
                update_locations.append((render_order, statements, index))
            render_order += 1
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE") and (
            any(location[1] is statements for location in iter(move_locations))
            or any(location[1] is statements for location in iter(update_locations))
        ):
            log.warning(
                "[direct-stack-move-order] move=%#x container=%#x",
                fact.ins_addr,
                id(node),
            )
    return move_locations, update_locations


def _restore_same_block_stack_move_order_8616(
    root: StructuredAstValue,
    codegen: StructuredCodegenValue,
    project: AngrProjectValue,
    function: StructuredAstValue,
    fact: DirectStackMoveFact8616,
    dst_expr: StructuredAstValue,
    source_expr: StructuredAstValue,
) -> cython.bint:
    """Restore a same-block aggregate read before its later stack-slot update."""
    moved: object
    update_candidates = _collect_later_stack_update_candidates_8616(
        codegen, project, function, fact
    )
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[direct-stack-move-order] move=%#x updates=%r",
            fact.ins_addr,
            tuple(
                (candidate.ins_addr, candidate.offset, candidate.delta)
                for candidate, _cvar, _source in iter(update_candidates)
            ),
        )
    if len(update_candidates) != 1:
        return False
    update_fact, update_cvar, update_source = update_candidates[0]
    move_locations, update_locations = _locate_move_update_positions_8616(
        root, fact, dst_expr, source_expr, update_cvar, update_fact, update_source
    )
    if (
        len(move_locations) != 1
        or len(update_locations) != 1
        or update_locations[0][0] >= move_locations[0][0]
    ):
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-move-order] move=%#x move_locations=%d update_locations=%d",
                fact.ins_addr,
                len(move_locations),
                len(update_locations),
            )
        return False
    _move_order, move_statements, move_index = move_locations[0]
    _update_order, update_statements, update_index = update_locations[0]
    moved = move_statements.pop(move_index)
    if move_statements is update_statements and move_index < update_index:
        update_index -= 1
    update_statements.insert(update_index, moved)
    return True



@cython.ccall
def _first_transparent_assignment_8616(stmt: object, seen: object = None) -> StructuredAstValue:
    found: object
    attr: object
    child: object
    if seen is None:
        seen = set()
    if stmt is None or id(stmt) in seen:
        return None
    seen.add(id(stmt))
    if isinstance(stmt, structured_c.CAssignment):
        return stmt
    for attr in ("initializer", "init", "iterator", "iteration"):
        if hasattr(stmt, attr):
            with contextlib.suppress(Exception):
                found = _first_transparent_assignment_8616(getattr(stmt, attr), seen)
                if found is not None:
                    return found
    if not isinstance(stmt, structured_c.CStatements):
        return None
    for child in _boundary_tuple_8616(getattr(stmt, "statements", ()) or ()):
        found = _first_transparent_assignment_8616(child, seen)
        if found is not None:
            return found
    return None


@cython.ccall
def _last_transparent_assignment_8616(stmt: object, seen: object = None) -> StructuredAstValue:
    found: object
    attr: object
    child: object
    if seen is None:
        seen = set()
    if stmt is None or id(stmt) in seen:
        return None
    seen.add(id(stmt))
    if isinstance(stmt, structured_c.CAssignment):
        return stmt
    for attr in ("iteration", "iterator", "init", "initializer"):
        if hasattr(stmt, attr):
            with contextlib.suppress(Exception):
                found = _last_transparent_assignment_8616(getattr(stmt, attr), seen)
                if found is not None:
                    return found
    if not isinstance(stmt, structured_c.CStatements):
        return None
    for child in reversed(_boundary_tuple_8616(getattr(stmt, "statements", ()) or ())):
        found = _last_transparent_assignment_8616(child, seen)
        if found is not None:
            return found
    return None


@cython.ccall
def _insertion_point_has_stack_move_assignment_8616(
    statements: object,
    insert_index: cython.longlong,
    dst_cvar: StructuredAstValue,
    source_expr: StructuredAstValue,
) -> cython.bint:
    if insert_index > 0:
        previous_assignment = _last_transparent_assignment_8616(statements[insert_index - 1])
        if _is_same_stack_move_assignment_8616(previous_assignment, dst_cvar, source_expr):
            return True
    if insert_index < len(statements):
        next_assignment = _first_transparent_assignment_8616(statements[insert_index])
        if _is_same_stack_move_assignment_8616(next_assignment, dst_cvar, source_expr):
            return True
    return False


@cython.dataclasses.dataclass
class _InsertAfterNearestPreceding8616:
    """Find and use the nearest preceding tagged statement eligible for insertion."""

    root: StructuredAstValue
    project: StructuredAstValue
    ins_addr: StructuredAstValue
    function: StructuredAstValue
    require_known_block: StructuredAstValue
    dst_cvar: StructuredAstValue
    source_expr: StructuredAstValue
    seen: StructuredAstValue
    best: StructuredAstValue = None

    @cython.ccall
    def visit(self, node: object, depth: cython.longlong) -> None:
        """Find the nearest preceding tagged statement eligible for insertion."""
        statements: object
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list) and self._visit_statements_8616(statements, depth):
            return
        self._visit_control_links_8616(node, depth)

    @cython.ccall
    def _same_block_8616(self, stmt_addr: cython.longlong) -> cython.bint:
        """Return whether the candidate predecessor shares the target block."""
        if self.function is None:
            return not self.require_known_block
        if self.require_known_block:
            return _strict_same_instruction_block_8616(
                self.project, self.function, stmt_addr, self.ins_addr
            )
        return _same_instruction_block_8616(self.project, self.function, stmt_addr, self.ins_addr)

    @cython.ccall
    def _visit_statements_8616(self, statements: object, depth: cython.longlong) -> cython.bint:
        """Score each preceding tagged statement; True aborts on existing update."""
        index: object
        stmt: object
        if _list_has_stack_move_assignment_8616(statements, self.dst_cvar, self.source_expr):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return True
        for index, stmt in enumerate(tuple(statements)):
            self._score_statement_8616(statements, index, stmt, depth)
            self.visit(stmt, depth + 1)
        return False

    @cython.ccall
    def _score_statement_8616(
        self,
        statements: object,
        index: cython.longlong,
        stmt: StructuredAstValue,
        depth: cython.longlong,
    ) -> None:
        """Update the best insertion point when this predecessor is nearer."""
        stmt_addr = _preceding_instruction_addr_in_node_8616(stmt, self.project, self.ins_addr, set())
        if not (isinstance(stmt_addr, int) and stmt_addr < self.ins_addr):
            return
        same_block = self._same_block_8616(stmt_addr)
        if not same_block and os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-mov-insert-after] skip predecessor different-block ins=%#x pred=%#x dst=%s",
                self.ins_addr,
                stmt_addr,
                _stack_cvar_identity_8616(self.dst_cvar),
            )
        if same_block and (
            self.best is None
            or stmt_addr > self.best[0]
            or (operator.eq(stmt_addr, self.best[0]) and depth > self.best[1])
        ):
            self.best = (
                stmt_addr,
                depth,
                statements,
                index,
                isinstance(
                    stmt, (structured_c.CForLoop, structured_c.CWhileLoop, structured_c.CDoWhileLoop)
                ),
            )

    @cython.ccall
    def _visit_control_links_8616(self, node: StructuredAstValue, depth: cython.longlong) -> None:
        """Recurse into loop bodies, else branches, and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                self.visit(child, depth + 1)
        for attr in ("condition_and_nodes",):
            with contextlib.suppress(Exception):
                pairs = getattr(node, attr, None)
            if not pairs:
                continue
            for _condition, body in tuple(pairs):
                self.visit(body, depth + 1)


@cython.ccall
def _insert_after_nearest_preceding_tagged_statement_8616(
    root: StructuredAstValue,
    project: StructuredAstValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
    *,
    function: StructuredAstValue | None = None,
    require_known_block: cython.bint = False,
    refuse_loop_container_predecessor: cython.bint = False,
) -> cython.bint:
    inserter = _InsertAfterNearestPreceding8616(
        root=root,
        project=project,
        ins_addr=ins_addr,
        function=function,
        require_known_block=require_known_block,
        dst_cvar=getattr(assignment, "lhs", None),
        source_expr=getattr(assignment, "rhs", None),
        seen=set(),
    )
    inserter.visit(root, 0)
    if inserter.best is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-mov-insert-after] no predecessor ins=%#x dst=%s source=%s",
                ins_addr,
                _stack_cvar_identity_8616(inserter.dst_cvar),
                _stack_cvar_identity_8616(inserter.source_expr),
            )
        return False
    _stmt_addr, _depth, statements, index, stmt_is_loop = inserter.best
    if refuse_loop_container_predecessor and stmt_is_loop:
        return False
    if _insertion_point_has_stack_move_assignment_8616(
        statements, index + 1, inserter.dst_cvar, inserter.source_expr
    ):
        root._inertia_stack_mov_assignment_already_present_8616 = True
        return False
    statements.insert(index + 1, assignment)
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[direct-stack-mov-insert-after] insert ins=%#x pred=%#x depth=%d dst=%s source=%s",
            ins_addr,
            _stmt_addr,
            _depth,
            _stack_cvar_identity_8616(inserter.dst_cvar),
            _stack_cvar_identity_8616(inserter.source_expr),
        )
    return True



@cython.ccall
def _insert_between_structured_siblings_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
) -> cython.bint:
    """Insert only when one unique structured sibling boundary encloses the instruction."""
    left_range: object
    right_range: object
    node: object
    if not isinstance(assignment, structured_c.CAssignment):
        return False
    candidates: list[tuple[list[StructuredAstValue], cython.longlong]] = []
    for node in _iter_structured_c_nodes_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        statements = node.statements
        for index in range(len(statements) - 1):
            left_range = _instruction_addr_range_in_node_8616(
                statements[index],
                project,
                ins_addr,
            )
            right_range = _instruction_addr_range_in_node_8616(
                statements[index + 1],
                project,
                ins_addr,
            )
            if (
                left_range is not None
                and right_range is not None
                and left_range[1] < ins_addr < right_range[0]
            ):
                candidates.append((statements, index + 1))
    if len(candidates) != 1:
        return False
    statements, insertion_index = candidates[0]
    if _insertion_point_has_stack_move_assignment_8616(
        statements,
        insertion_index,
        assignment.lhs,
        assignment.rhs,
    ):
        root._inertia_stack_mov_assignment_already_present_8616 = True
        return False
    statements.insert(insertion_index, assignment)
    return True


@cython.ccall
def _direct_call_addr_before_stack_store_8616(
    project: AngrProjectValue, function: object, stmt_addr: cython.longlong, store_addr: cython.longlong
) -> int | None:
    best: object
    addr: object
    insn: object
    if function is None or stmt_addr >= store_addr:
        return None
    insn_by_addr = _instruction_by_addr_map_8616(project, function)
    best = None
    for addr, insn in insn_by_addr.items():
        if not (addr < store_addr):
            continue
        if getattr(insn, "id", None) not in {X86_INS_CALL, X86_INS_LCALL}:
            continue
        if not _same_instruction_block_8616(project, function, addr, store_addr):
            continue
        if best is None or addr > best:
            best = addr
    if best is None or not (best < stmt_addr < store_addr):
        return None
    return best


@cython.ccall
def _dirty_expr_key_8616(node: StructuredAstValue) -> object:
    dirty: object
    expr_idx: object
    value: object
    attr: object
    if node.__class__.__name__ != "CDirtyExpression":
        return None
    dirty = getattr(node, "dirty", None)
    for attr in ("varid", "idx", "oident"):
        value = getattr(dirty, attr, None)
        if isinstance(value, (int, str)):
            return (f"dirty_{attr}", value)
    expr_idx = getattr(node, "idx", None)
    if isinstance(expr_idx, (int, str)):
        return ("dirty_expr", expr_idx)
    return None


@cython.ccall
def _c_lvalue_key_8616(node: StructuredAstValue) -> object:
    name: object
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CVariable):
        variable = node.variable
        if isinstance(variable, SimStackVariable):
            offset = _canonical_stack_offset_8616(variable.offset)
            if isinstance(offset, int):
                return ("stack", offset)
            return None
        if isinstance(variable, SimMemoryVariable):
            addr = variable.addr
            if isinstance(addr, int):
                return ("memory", addr)
            return None
        if isinstance(variable, SimRegisterVariable):
            name = variable.name
            if isinstance(name, str) and name:
                return ("register", name)
            reg = variable.reg
            if isinstance(reg, int):
                return ("register_offset", reg)
        name = getattr(variable, "name", None)
        if isinstance(name, str) and name:
            return ("variable_name", name)
        return ("variable", id(variable))
    return _dirty_expr_key_8616(node)


_LVALUE_KEY_CHILD_ATTRS_8616 = (
    "rhs",
    "operand",
    "expr",
    "condition",
    "cond",
    "iftrue",
    "iffalse",
    "initializer",
    "init",
    "iterator",
    "iteration",
    "body",
    "else_node",
    "statements",
    "args",
    "operands",
)


def _scan_lvalue_key_value_8616(
    value: StructuredAstValue,
    key: object,
    seen: object,
    exclude_node_id: int | None,
) -> cython.bint:
    """Scan a child attribute value for an lvalue-key read."""
    if isinstance(value, (list, tuple)):
        return any(
            _scan_lvalue_key_value_8616(item, key, seen, exclude_node_id) for item in builtins.iter(tuple(value))
        )
    return _c_node_reads_lvalue_key_8616(value, key, seen=seen, exclude_node_id=exclude_node_id)


@cython.ccall
def _lvalue_key_attrs_read_8616(
    node: StructuredAstValue,
    key: object,
    seen: object,
    exclude_node_id: int | None,
) -> cython.bint:
    """Scan the lvalue-reader child attributes for a key read."""
    value: object
    attr: object
    for attr in _LVALUE_KEY_CHILD_ATTRS_8616:
        value = getattr(node, attr, None)
        if _scan_lvalue_key_value_8616(value, key, seen, exclude_node_id):
            return True
    return False


@cython.ccall
def _lvalue_key_pairs_read_8616(
    node: StructuredAstValue,
    key: object,
    seen: object,
    exclude_node_id: int | None,
) -> cython.bint:
    """Scan condition/body pairs for an lvalue-key read."""
    pairs: object
    body: object
    condition: object
    pairs = getattr(node, "condition_and_nodes", None)
    if not pairs:
        return False
    for condition, body in tuple(pairs):
        if _c_node_reads_lvalue_key_8616(
            condition,
            key,
            seen=seen,
            exclude_node_id=exclude_node_id,
        ):
            return True
        if _c_node_reads_lvalue_key_8616(
            body,
            key,
            seen=seen,
            exclude_node_id=exclude_node_id,
        ):
            return True
    return False


@cython.ccall
def _c_node_reads_lvalue_key_8616(
    node: object,
    key: object,
    *,
    seen: object = None,
    exclude_node_id: int | None = None,
) -> cython.bint:
    if node is None:
        return False
    if seen is None:
        seen = set()
    node_id = id(node)
    if isinstance(exclude_node_id, int) and node_id == exclude_node_id:
        return False
    if node_id in seen:
        return False
    seen.add(node_id)
    if isinstance(node, structured_c.CVariable) and operator.eq(_c_lvalue_key_8616(node), key):
        return True
    if operator.eq(_dirty_expr_key_8616(node), key):
        return True
    if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
        return False
    if _lvalue_key_attrs_read_8616(node, key, seen, exclude_node_id):
        return True
    return _lvalue_key_pairs_read_8616(node, key, seen, exclude_node_id)



@cython.ccall
def _rhs_is_pure_register_artifact_expr_8616(rhs: StructuredAstValue) -> cython.bint:
    node: object
    for node in _iter_structured_c_nodes_8616(rhs):
        if isinstance(node, structured_c.CFunctionCall):
            return False
        if isinstance(node, structured_c.CUnaryOp) and getattr(node, "op", None) == "Dereference":
            return False
        if isinstance(node, structured_c.CVariable) and isinstance(getattr(node, "variable", None), SimMemoryVariable):
            return False
    return True


def _assignment_is_disposable_call_cleanup_artifact_8616(
    stmt: StructuredAstValue, following_statements: object
) -> cython.bint:
    lhs_key: object
    if not isinstance(stmt, structured_c.CAssignment):
        return False
    lhs = _strip_casts_8616(stmt.lhs)
    if isinstance(lhs, structured_c.CVariable) and isinstance(
        getattr(lhs, "variable", None),
        (SimStackVariable, SimMemoryVariable),
    ):
        return False
    lhs_key = _c_lvalue_key_8616(lhs)
    if lhs_key is None:
        return False
    rhs = stmt.rhs
    if not _rhs_is_pure_register_artifact_expr_8616(rhs):
        return False
    return not any(_c_node_reads_lvalue_key_8616(candidate, lhs_key) for candidate in iter(following_statements))


@cython.dataclasses.dataclass
class _PostCallCleanupReplacer8616:
    """Replace the best disposable call-cleanup artifact before a stack move."""

    root: StructuredAstValue
    project: StructuredAstValue
    function: StructuredAstValue
    ins_addr: StructuredAstValue
    seen: StructuredAstValue
    best: StructuredAstValue = None

    @cython.ccall
    def visit(self, node: object, depth: cython.longlong) -> None:
        """Find the nearest disposable cleanup artifact in the same block."""
        statements: object
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            self._visit_statements_8616(statements, depth)
        self._visit_control_links_8616(node, depth)

    @cython.ccall
    def _cleanup_candidate_addr_8616(
        self,
        stmt: StructuredAstValue,
        statements: object,
        index: cython.longlong,
    ) -> int | None:
        """Return the statement address when it is a disposable artifact."""
        stmt_addr = _statement_instruction_addr_8616(stmt, self.project, self.ins_addr)
        if not isinstance(stmt_addr, int) or not (stmt_addr < self.ins_addr):
            return None
        if not _same_instruction_block_8616(self.project, self.function, stmt_addr, self.ins_addr):
            return None
        if (
            _direct_call_addr_before_stack_store_8616(
                self.project, self.function, stmt_addr, self.ins_addr
            )
            is None
        ):
            return None
        following = tuple(statements[index + 1 :])
        if not _assignment_is_disposable_call_cleanup_artifact_8616(stmt, following):
            return None
        return stmt_addr

    @cython.ccall
    def _visit_statements_8616(self, statements: object, depth: cython.longlong) -> None:
        """Score each cleanup-artifact candidate and recurse."""
        stmt_addr: object
        index: object
        stmt: object
        for index, stmt in enumerate(tuple(statements)):
            stmt_addr = self._cleanup_candidate_addr_8616(stmt, statements, index)
            if stmt_addr is not None and (
                self.best is None
                or stmt_addr > self.best[0]
                or (operator.eq(stmt_addr, self.best[0]) and depth > self.best[1])
            ):
                self.best = (stmt_addr, depth, statements, index)
            self.visit(stmt, depth + 1)

    @cython.ccall
    def _visit_control_links_8616(self, node: StructuredAstValue, depth: cython.longlong) -> None:
        """Recurse into loop bodies, else branches, and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                self.visit(child, depth + 1)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.visit(body, depth + 1)


@cython.ccall
def _replace_post_call_cleanup_artifact_before_stack_move_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    function: StructuredAstValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
) -> cython.bint:
    dst_cvar: object
    source_expr: object
    replacer = _PostCallCleanupReplacer8616(
        root=root,
        project=project,
        function=function,
        ins_addr=ins_addr,
        seen=set(),
    )
    replacer.visit(root, 0)
    if replacer.best is None:
        return False
    _stmt_addr, _depth, statements, index = replacer.best
    dst_cvar = getattr(assignment, "lhs", None)
    source_expr = getattr(assignment, "rhs", None)
    if _insertion_point_has_stack_move_assignment_8616(statements, index, dst_cvar, source_expr):
        root._inertia_stack_mov_assignment_already_present_8616 = True
        return False
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[direct-stack-mov-replace-cleanup] replace cleanup ins=%#x artifact=%#x dst=%s source=%s",
            ins_addr,
            _stmt_addr,
            _stack_cvar_identity_8616(dst_cvar),
            _stack_cvar_identity_8616(source_expr),
        )
    statements[index] = assignment
    return True



@cython.dataclasses.dataclass
class _DoWhileConditionInserter8616:
    """Insert a stack move before a proven do-while condition."""

    root: StructuredAstValue
    project: StructuredAstValue
    ins_addr: StructuredAstValue
    assignment: StructuredAstValue
    dst_cvar: StructuredAstValue
    source_expr: StructuredAstValue
    seen: StructuredAstValue

    @cython.ccall
    def visit(self, node: object) -> cython.bint:
        """Walk the tree, appending at a matching do-while body tail."""
        result: object
        if node is None or id(node) in self.seen:
            return False
        self.seen.add(id(node))
        result = self._try_do_while_append_8616(node)
        if result is not None:
            return result
        return self._visit_children_8616(node)

    @cython.ccall
    def _try_do_while_append_8616(self, node: StructuredAstValue) -> bool | None:
        """Append to the body when the update sits between body and condition."""
        body: object
        body_range: object
        body_statements: object
        condition: object
        condition_range: object
        body = getattr(node, "body", None)
        condition = getattr(node, "condition", None)
        if not (
            body is not None
            and condition is not None
            and node.__class__.__name__ == "CDoWhileLoop"
        ):
            return None
        body_range = _instruction_addr_range_in_node_8616(body, self.project, self.ins_addr, set())
        condition_range = _instruction_addr_range_in_node_8616(
            condition, self.project, self.ins_addr, set()
        )
        body_statements = getattr(body, "statements", None)
        if not (
            body_range is not None
            and condition_range is not None
            and isinstance(body_statements, list)
            and body_range[1] < self.ins_addr < condition_range[0]
        ):
            return None
        if _insertion_point_has_stack_move_assignment_8616(
            body_statements,
            len(body_statements),
            self.dst_cvar,
            self.source_expr,
        ):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return False
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-mov-insert-do-condition] insert ins=%#x body_max=%#x "
                "cond_min=%#x dst=%s source=%s",
                self.ins_addr,
                body_range[1],
                condition_range[0],
                _stack_cvar_identity_8616(self.dst_cvar),
                _stack_cvar_identity_8616(self.source_expr),
            )
        body_statements.append(self.assignment)
        return True

    @cython.ccall
    def _visit_children_8616(self, node: StructuredAstValue) -> cython.bint:
        """Recurse into statements, loop bodies, else branches, and pairs."""
        child: object
        pairs: object
        statements: object
        _condition: object
        attr: object
        body: object
        stmt: object
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for stmt in tuple(statements):
                if self.visit(stmt):
                    return True
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None and self.visit(child):
                return True
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                if self.visit(body):
                    return True
        return False


@cython.ccall
def _insert_before_do_while_condition_8616(
    root: StructuredAstValue, project: AngrProjectValue, ins_addr: cython.longlong, assignment: StructuredAstValue
) -> cython.bint:
    inserter = _DoWhileConditionInserter8616(
        root=root,
        project=project,
        ins_addr=ins_addr,
        assignment=assignment,
        dst_cvar=getattr(assignment, "lhs", None),
        source_expr=getattr(assignment, "rhs", None),
        seen=set(),
    )
    return inserter.visit(root)



@cython.dataclasses.dataclass
class _GuardedBodyStartInserter8616:
    """Insert a stack move at a proven guarded-body start for the target."""

    root: StructuredAstValue
    project: StructuredAstValue
    ins_addr: StructuredAstValue
    assignment: StructuredAstValue
    dst_cvar: StructuredAstValue
    source_expr: StructuredAstValue
    seen: StructuredAstValue

    @cython.ccall
    def visit(self, node: object) -> cython.bint:
        """Walk the tree, inserting at a proven guarded body start."""
        result: object
        if node is None or id(node) in self.seen:
            return False
        self.seen.add(id(node))
        result = self._visit_pairs_8616(node)
        if result is not None:
            return result
        return self._visit_children_8616(node)

    @cython.ccall
    def _visit_pairs_8616(self, node: StructuredAstValue) -> bool | None:
        """Try each condition/body pair; None means fall through to children."""
        pairs: object
        result: object
        body: object
        condition: object
        pairs = getattr(node, "condition_and_nodes", None)
        if not pairs:
            return None
        for condition, body in tuple(pairs):
            result = self._try_guarded_pair_8616(condition, body)
            if result is not None:
                return result
        return None

    @cython.ccall
    def _guard_match_8616(
        self,
        condition: StructuredAstValue,
        body_statements: StructuredAstValue,
        condition_range: object,
        body_range: object,
    ) -> cython.bint:
        """Return whether the guarded body range covers the target update."""
        if not isinstance(body_statements, list) or body_range is None:
            return False
        range_match = (
            condition_range is not None and condition_range[1] < int(self.ins_addr) < body_range[0]
        ) or (
            condition_range is None and int(self.ins_addr) <= body_range[0] <= int(self.ins_addr) + 0x10
        )
        if not range_match:
            return False
        return _node_reads_stack_cvar_8616(condition, self.dst_cvar)

    @cython.ccall
    def _try_guarded_pair_8616(
        self,
        condition: StructuredAstValue,
        body: StructuredAstValue,
    ) -> bool | None:
        """Insert at a matching guarded body start or recurse into the body."""
        body_range: object
        body_statements: object
        condition_range: object
        body_statements = getattr(body, "statements", None)
        condition_range = _instruction_addr_range_in_node_8616(condition, self.project, self.ins_addr, set())
        body_range = _instruction_addr_range_in_node_8616(body, self.project, self.ins_addr, set())
        if not self._guard_match_8616(condition, body_statements, condition_range, body_range):
            return True if self.visit(body) else None
        assert isinstance(body_statements, list) and body_range is not None
        if _insertion_point_has_stack_move_assignment_8616(
            body_statements, 0, self.dst_cvar, self.source_expr
        ):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return False
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-mov-insert-if-body-start] insert ins=%#x cond_max=%#x "
                "body_min=%#x dst=%s source=%s",
                self.ins_addr,
                condition_range[1] if condition_range is not None else -1,
                body_range[0],
                _stack_cvar_identity_8616(self.dst_cvar),
                _stack_cvar_identity_8616(self.source_expr),
            )
        body_statements.insert(0, self.assignment)
        return True

    @cython.ccall
    def _visit_children_8616(self, node: StructuredAstValue) -> cython.bint:
        """Recurse into statements, loop bodies, and else branches."""
        child: object
        statements: object
        attr: object
        stmt: object
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for stmt in tuple(statements):
                if self.visit(stmt):
                    return True
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None and self.visit(child):
                return True
        return False


@cython.ccall
def _insert_at_guarded_body_start_for_target_stack_move_8616(
    root: StructuredAstValue, project: AngrProjectValue, ins_addr: cython.longlong, assignment: StructuredAstValue
) -> cython.bint:
    inserter = _GuardedBodyStartInserter8616(
        root=root,
        project=project,
        ins_addr=ins_addr,
        assignment=assignment,
        dst_cvar=getattr(assignment, "lhs", None),
        source_expr=getattr(assignment, "rhs", None),
        seen=set(),
    )
    return inserter.visit(root)



@cython.ccall
def _is_conditional_jcc_insn_8616(insn: StructuredAstValue) -> cython.bint:
    """Check for a conditional jump mnemonic (not jmp)."""
    mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
    return mnemonic.startswith("j") and mnemonic != "jmp"


def _jcc_branch_indexes_8616(insns: object, jcc_addr: cython.longlong) -> tuple[cython.longlong, ...]:
    """Find instruction indexes that could carry the requested jcc address."""
    return tuple(
        index
        for index, wrapper in builtins.iter(enumerate(insns))
        if (
            isinstance(getattr(getattr(wrapper, "insn", wrapper), "address", None), int)
            and abs(int(getattr(wrapper, "insn", wrapper).address) - jcc_addr) <= 8
            and _is_conditional_jcc_insn_8616(getattr(wrapper, "insn", wrapper))
        )
    )


@cython.ccall
def _single_imm_operand_8616(insn: StructuredAstValue) -> int | None:
    """Return the immediate of a single-operand instruction, or None."""
    imm: object
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 1 or operator.ne(getattr(operands[0], "type", None), X86_OP_IMM):
        return None
    imm = getattr(operands[0], "imm", None)
    return imm if isinstance(imm, int) else None


@cython.ccall
def _jcc_merge_addr_8616(insns: object, index: cython.longlong, else_start: cython.longlong) -> int | None:
    """Scan past else_start for the first unconditional-jump merge target."""
    candidate: object
    candidate_addr: object
    target: object
    candidate_wrapper: object
    for candidate_wrapper in insns[index + 2 :]:
        candidate = getattr(candidate_wrapper, "insn", candidate_wrapper)
        candidate_addr = getattr(candidate, "address", None)
        if not isinstance(candidate_addr, int):
            continue
        if candidate_addr >= else_start:
            break
        if str(getattr(candidate, "mnemonic", "") or "").lower() != "jmp":
            continue
        target = _single_imm_operand_8616(candidate)
        if target is not None:
            return target
    return None


def _conditional_branch_ranges_for_jcc_8616(
    project: StructuredAstValue, function: object, jcc_addr: cython.longlong
) -> object:
    insn: object
    next_insn: object
    index: object
    blocks = tuple(_direct_global_update_blocks_8616(project, function)) if function is not None else ()
    insns = _dedup_sorted_capstone_insns_by_addr_8616(
        wrapper for block in iter(blocks) for wrapper in builtins.iter(_capstone_insns_for_direct_global_update_8616(project, block))
    )
    jcc_indexes = _jcc_branch_indexes_8616(insns, jcc_addr)
    if len(jcc_indexes) != 1:
        return None
    for index in jcc_indexes:
        insn = getattr(insns[index], "insn", insns[index])
        if not _is_conditional_jcc_insn_8616(insn):
            return None
        then_start = _single_imm_operand_8616(insn)
        if not isinstance(then_start, int) or index + 1 >= len(insns):
            return None
        next_insn = getattr(insns[index + 1], "insn", insns[index + 1])
        if str(getattr(next_insn, "mnemonic", "") or "").lower() != "jmp":
            return None
        else_start = _single_imm_operand_8616(next_insn)
        if not isinstance(else_start, int):
            return None
        merge_addr = _jcc_merge_addr_8616(insns, index, else_start)
        return then_start, else_start, merge_addr
    return None


@cython.dataclasses.dataclass
class _CondBranchMoveInserter8616:
    """Insert a decoded stack move into the innermost CFG-proven branch."""

    root: StructuredAstValue
    project: StructuredAstValue
    function: StructuredAstValue
    ins_addr: StructuredAstValue
    assignment: StructuredAstValue
    dst_cvar: StructuredAstValue
    source_expr: StructuredAstValue
    relocate_tagged_assignment: StructuredAstValue
    seen: StructuredAstValue

    @cython.ccall
    def _maybe_insert_8616(self, branch: StructuredAstValue, statements: object) -> cython.bint:
        """Insert at branch start unless the same assignment is already present."""
        if self.relocate_tagged_assignment and not self._relocate_tagged_8616(branch, statements):
            return False
        if _insertion_point_has_stack_move_assignment_8616(
            statements, 0, self.dst_cvar, self.source_expr
        ):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return False
        statements.insert(0, self.assignment)
        if self.relocate_tagged_assignment:
            _remove_duplicate_stack_move_assignments_8616(
                self.root,
                self.project,
                self.ins_addr,
                self.dst_cvar,
                self.source_expr,
                self.assignment,
            )
        return True

    @cython.ccall
    def _relocate_tagged_8616(self, branch: StructuredAstValue, statements: object) -> cython.bint:
        """Remove the unique tagged copy so the branch insert relocates it."""
        tagged_count = _removable_tagged_stack_move_assignment_count_8616(
            self.root,
            self.project,
            self.ins_addr,
            self.dst_cvar,
            self.source_expr,
        )
        branch_tagged_count = _removable_tagged_stack_move_assignment_count_8616(
            branch,
            self.project,
            self.ins_addr,
            self.dst_cvar,
            self.source_expr,
        )
        if tagged_count != 1:
            return False
        first_statement_is_exact = bool(
            statements
            and isinstance(statements[0], structured_c.CAssignment)
            and _is_same_stack_move_assignment_8616(
                statements[0],
                self.dst_cvar,
                self.source_expr,
            )
            and _node_has_instruction_address_8616(
                statements[0],
                self.project,
                self.ins_addr,
            )
        )
        if branch_tagged_count == tagged_count and first_statement_is_exact:
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return False
        removed = _remove_tagged_stack_move_assignments_8616(
            self.root,
            self.project,
            self.ins_addr,
            self.dst_cvar,
            self.source_expr,
        )
        if removed != tagged_count:
            raise AssertionError("tagged branch stack-move count changed during relocation")
        return True

    @cython.ccall
    def visit(self, node: object) -> cython.bint:
        """Walk conditionals and insert into the machine-proven branch range."""
        if node is None or id(node) in self.seen:
            return False
        self.seen.add(id(node))
        if self._visit_conditional_pairs_8616(node):
            return True
        return self._visit_children_8616(node)

    @cython.ccall
    def _visit_conditional_pairs_8616(self, node: StructuredAstValue) -> cython.bint:
        """Handle each condition/body pair of a conditional node."""
        pairs: object
        body: object
        condition: object
        pairs = getattr(node, "condition_and_nodes", None)
        if not pairs:
            return False
        for condition, body in tuple(pairs):
            if self._visit_branch_pair_8616(node, condition, body):
                return True
        return False

    @cython.ccall
    def _branch_target_8616(
        self,
        node: StructuredAstValue,
        body: StructuredAstValue,
        then_start: cython.longlong,
        else_start: cython.longlong,
        merge_addr: object,
    ) -> object:
        """Pick the proven branch arm containing this instruction."""
        body_statements: object
        else_node: object
        else_statements: object
        body_statements = getattr(body, "statements", None)
        else_node = getattr(node, "else_node", None)
        else_statements = getattr(else_node, "statements", None)
        if isinstance(body_statements, list) and then_start <= int(self.ins_addr) < else_start:
            return body, body_statements
        if (
            isinstance(else_statements, list)
            and else_start <= int(self.ins_addr)
            and (merge_addr is None or int(self.ins_addr) < merge_addr)
        ):
            return else_node, else_statements
        return None

    @cython.ccall
    def _visit_branch_pair_8616(
        self,
        node: StructuredAstValue,
        condition: StructuredAstValue,
        body: StructuredAstValue,
    ) -> cython.bint:
        """Resolve the jcc range for one pair and insert into its target arm."""
        ranges: object
        target: object
        jcc_addr = _preceding_instruction_addr_in_node_8616(condition, self.project, self.ins_addr, set())
        if not isinstance(jcc_addr, int):
            return False
        ranges = _conditional_branch_ranges_for_jcc_8616(self.project, self.function, jcc_addr)
        if ranges is None:
            return False
        then_start, else_start, merge_addr = ranges
        target = self._branch_target_8616(node, body, then_start, else_start, merge_addr)
        if target is not None:
            target_node, target_statements = target
            if self.visit(target_node):
                return True
            return self._maybe_insert_8616(target_node, target_statements)
        if self.visit(body):
            return True
        return self.visit(getattr(node, "else_node", None))

    @cython.ccall
    def _visit_children_8616(self, node: StructuredAstValue) -> cython.bint:
        """Recurse into statements, loop bodies, and else branches."""
        child: object
        statements: object
        attr: object
        stmt: object
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for stmt in tuple(statements):
                if self.visit(stmt):
                    return True
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None and self.visit(child):
                return True
        return False


@cython.ccall
def _insert_into_conditional_branch_for_direct_stack_move_8616(
    root: StructuredAstValue,
    project: StructuredAstValue,
    function: StructuredAstValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
    *,
    relocate_tagged_assignment: cython.bint = False,
) -> cython.bint:
    """Insert a decoded stack move into the innermost CFG-proven branch."""
    inserter = _CondBranchMoveInserter8616(
        root=root,
        project=project,
        function=function,
        ins_addr=ins_addr,
        assignment=assignment,
        dst_cvar=getattr(assignment, "lhs", None),
        source_expr=getattr(assignment, "rhs", None),
        relocate_tagged_assignment=relocate_tagged_assignment,
        seen=set(),
    )
    return inserter.visit(root)



def _sequence_has_control_flow_8616(sequence: object) -> cython.bint:
    """Check whether a candidate sequence contains a control-flow instruction."""
    return any(
        X86_GRP_JUMP in frozenset(getattr(item, "groups", ()) or ())
        or X86_GRP_RET in frozenset(getattr(item, "groups", ()) or ())
        or getattr(item, "id", None) in {X86_INS_CALL, X86_INS_LCALL, X86_INS_RET}
        for item in iter(sequence)
    )


@cython.ccall
def _sequence_starts_in_block_8616(
    block_insns: object,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    sequence_starts: object,
) -> None:
    """Record backward-reachable sequence starts for one block."""
    tagged_addr: object
    comparable_addr: object
    fact_index: object
    insn: object
    comparable_addrs_list: list[int | None] = []
    for insn in block_insns:
        tagged_addr = getattr(insn, "address", None)
        comparable_addrs_list.append(
            _comparable_instruction_addr_8616(project, tagged_addr, ins_addr)
            if isinstance(tagged_addr, int)
            else None
        )
    comparable_addrs = tuple(comparable_addrs_list)
    for fact_index, comparable_addr in enumerate(comparable_addrs):
        if operator.ne(comparable_addr, int(ins_addr)):
            continue
        sequence_starts.add(int(ins_addr))
        for start_index in range(fact_index - 1, -1, -1):
            start_addr = comparable_addrs[start_index]
            if not isinstance(start_addr, int) or int(ins_addr) - start_addr > 16:
                break
            sequence = block_insns[start_index : fact_index + 1]
            if _sequence_has_control_flow_8616(sequence):
                break
            sequence_starts.add(start_addr)


@cython.ccall
def _loopback_edge_for_jump_8616(
    insn: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    sequence_starts: object,
) -> object:
    """Return the proven (sequence entry, backedge jump) edge for one jump."""
    jump_addr: object
    target: object
    jump_addr = getattr(insn, "address", None)
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if not isinstance(jump_addr, int) or len(operands) != 1:
        return None
    operand = operands[0]
    target = getattr(operand, "imm", None)
    if operator.ne(int(getattr(operand, "type", -1)), X86_OP_IMM) or not isinstance(target, int):
        return None
    comparable_jump = _comparable_instruction_addr_8616(project, jump_addr, ins_addr)
    comparable_target = _comparable_instruction_addr_8616(project, target, ins_addr)
    if (
        comparable_target in sequence_starts
        and isinstance(comparable_jump, int)
        and comparable_jump > int(ins_addr)
    ):
        return comparable_target, comparable_jump
    return None


def _instruction_sequence_loopback_edges_8616(
    function: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
) -> object:
    """Return proven ``(sequence entry, backedge jump)`` pairs for an instruction fact."""
    capstone: object
    edge: object
    block: object
    insn: object
    sequence_starts: set[cython.longlong] = set()
    jump_insns: list[StructuredAstValue] = []
    for block in _boundary_tuple_8616(getattr(function, "blocks", ()) or ()):
        capstone = getattr(block, "capstone", None)
        block_insns = tuple(
            getattr(wrapped, "insn", wrapped)
            for wrapped in builtins.iter(_boundary_tuple_8616(getattr(capstone, "insns", ()) or ()))
        )
        _sequence_starts_in_block_8616(block_insns, project, ins_addr, sequence_starts)
        for insn in block_insns:
            if X86_GRP_JUMP not in frozenset(getattr(insn, "groups", ()) or ()):
                continue
            jump_insns.append(insn)
    edges: list[tuple[cython.longlong, cython.longlong]] = []
    for insn in jump_insns:
        edge = _loopback_edge_for_jump_8616(insn, project, ins_addr, sequence_starts)
        if edge is not None:
            edges.append(edge)
    proven_edges = tuple(dict.fromkeys(edges))
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[direct-stack-move-loopback] ins=%#x sequence_starts=%r edges=%r",
            ins_addr,
            tuple(sorted(sequence_starts)),
            proven_edges,
        )
    return proven_edges


@cython.ccall
def _function_backward_jump_edges_8616(
    function: StructuredAstValue,
    project: AngrProjectValue,
    reference_addr: cython.longlong,
) -> tuple[tuple[cython.longlong, cython.longlong], ...]:
    """Return immediate backward-jump edges in coordinates comparable to a fact address."""
    capstone: object
    insn: object
    jump_addr: object
    target: object
    block: object
    wrapped: object
    edges: list[tuple[cython.longlong, cython.longlong]] = []
    for block in _boundary_tuple_8616(getattr(function, "blocks", ()) or ()):
        capstone = getattr(block, "capstone", None)
        for wrapped in _boundary_tuple_8616(getattr(capstone, "insns", ()) or ()):
            insn = getattr(wrapped, "insn", wrapped)
            if X86_GRP_JUMP not in frozenset(getattr(insn, "groups", ()) or ()):
                continue
            jump_addr = getattr(insn, "address", None)
            operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
            if not isinstance(jump_addr, int) or len(operands) != 1:
                continue
            operand = operands[0]
            target = getattr(operand, "imm", None)
            if operator.ne(int(getattr(operand, "type", -1)), X86_OP_IMM) or not isinstance(target, int):
                continue
            comparable_jump = _comparable_instruction_addr_8616(project, jump_addr, reference_addr)
            comparable_target = _comparable_instruction_addr_8616(project, target, reference_addr)
            if (
                isinstance(comparable_jump, int)
                and isinstance(comparable_target, int)
                and comparable_target < comparable_jump
            ):
                edges.append((comparable_target, comparable_jump))
    return tuple(dict.fromkeys(edges))


@cython.ccall
def _function_has_loopback_to_instruction_8616(
    function: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
) -> cython.bint:
    """Return whether binary control flow repeats a straight-line sequence ending at a fact."""
    return bool(_instruction_sequence_loopback_edges_8616(function, project, ins_addr))


@cython.dataclasses.dataclass
class _DoWhileBodyStartInserter8616:
    """Insert a proven loop-entry move when a binary backedge repeats it."""

    root: StructuredAstValue
    project: StructuredAstValue
    ins_addr: StructuredAstValue
    assignment: StructuredAstValue
    dst_cvar: StructuredAstValue
    source_expr: StructuredAstValue
    proven_loopback_edges: StructuredAstValue
    condition_reading_do_loop_ids: StructuredAstValue
    rendered_do_loop_ids: StructuredAstValue
    rendered_seen: StructuredAstValue
    seen: StructuredAstValue

    @cython.ccall
    def collect_rendered_do_loops(self, node: object) -> None:
        """Collect executable do loops without following compatibility fields."""
        cases: object
        pairs: object
        statements: object
        _case_value: object
        _condition: object
        attr: object
        body: object
        statement: object
        if node is None or id(node) in self.rendered_seen:
            return
        self.rendered_seen.add(id(node))
        if node.__class__.__name__ == "CDoWhileLoop" and _node_reads_stack_cvar_8616(
            getattr(node, "condition", None), self.dst_cvar
        ):
            self.rendered_do_loop_ids.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for statement in tuple(statements):
                self.collect_rendered_do_loops(statement)
        for attr in ("body", "else_node"):
            self.collect_rendered_do_loops(getattr(node, attr, None))
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.collect_rendered_do_loops(body)
        cases = getattr(node, "cases", None)
        if cases:
            for _case_value, body in tuple(cases):
                self.collect_rendered_do_loops(body)
        self.collect_rendered_do_loops(getattr(node, "default", None))

    @cython.ccall
    def visit(self, node: object) -> cython.bint:
        """Walk the tree; a CDoWhileLoop match inserts, aborts, or recurses."""
        result: object
        if node is None or id(node) in self.seen:
            return False
        self.seen.add(id(node))
        result = self._try_do_while_insert_8616(node)
        if result is not None:
            return result
        return self._visit_children_8616(node)

    @cython.ccall
    def _repeated_prefix_count_8616(self, body_statements: StructuredAstValue) -> cython.longlong:
        """Count leading body statements already emitted for this update."""
        statement_addr: object
        tags: object
        statement: object
        repeated_prefix_count = 0
        if isinstance(body_statements, list):
            for statement in body_statements:
                tags = copy_structured_tags_8616(getattr(statement, "tags", None))
                statement_addr = tags.get("ins_addr") if tags is not None else None
                if not isinstance(statement_addr, int) and tags is not None:
                    statement_addr = tags.get("inertia_relocated_from_ins_addr")
                comparable_addr = (
                    _comparable_instruction_addr_8616(self.project, statement_addr, self.ins_addr)
                    if isinstance(statement_addr, int)
                    else None
                )
                if not isinstance(statement, structured_c.CAssignment) or not isinstance(comparable_addr, int):
                    break
                if comparable_addr > int(self.ins_addr):
                    break
                repeated_prefix_count += 1
        return repeated_prefix_count

    def _post_prefix_body_range_8616(
        self,
        body_statements: StructuredAstValue,
        repeated_prefix_count: cython.longlong,
    ) -> object:
        """Merge instruction ranges of the body tail after the repeated prefix."""
        body_ranges = tuple(
            candidate_range
            for statement in iter((
                body_statements[repeated_prefix_count:] if isinstance(body_statements, list) else ()
            ))
            if (
                candidate_range := _instruction_addr_range_in_node_8616(
                    statement,
                    self.project,
                    self.ins_addr,
                    set(),
                )
            )
            is not None
        )
        return (
            (min(item[0] for item in iter(body_ranges)), max(item[1] for item in iter(body_ranges)))
            if body_ranges
            else None
        )

    def _ordered_condition_8616(
        self,
        body_range: object,
        condition_range: object,
    ) -> cython.bint:
        """Return whether the body provably precedes the tagged condition."""
        exact_edge_covers_boundary = condition_range is not None and any(
            entry <= int(self.ins_addr) < condition_range[0] and jump >= condition_range[1]
            for entry, jump in iter(self.proven_loopback_edges)
        )
        return (
            body_range is not None
            and condition_range is not None
            and self.ins_addr < condition_range[0]
            and body_range[1] <= condition_range[0]
            and exact_edge_covers_boundary
        )

    @cython.ccall
    def _unique_unmapped_condition_8616(
        self,
        node: StructuredAstValue,
        body_range: object,
        condition_range: object,
    ) -> cython.bint:
        """Return whether this is the unique do loop with an unmapped condition."""
        return (
            body_range is not None
            and condition_range is None
            and operator.eq(self.condition_reading_do_loop_ids, frozenset({id(node)}))
            and self.ins_addr <= body_range[1]
        )

    @cython.ccall
    def _try_do_while_insert_8616(self, node: StructuredAstValue) -> bool | None:
        """Try inserting at a do-while body start; None means keep walking."""
        body: object
        body_range: object
        body_statements: object
        condition: object
        body = getattr(node, "body", None)
        condition = getattr(node, "condition", None)
        if not (body is not None and condition is not None and node.__class__.__name__ == "CDoWhileLoop"):
            return None
        body_statements = getattr(body, "statements", None)
        repeated_prefix_count = self._repeated_prefix_count_8616(body_statements)
        body_range = self._post_prefix_body_range_8616(body_statements, repeated_prefix_count)
        condition_range = _instruction_addr_range_in_node_8616(
            condition, self.project, self.ins_addr, set()
        )
        ordered_condition = self._ordered_condition_8616(body_range, condition_range)
        unique_unmapped_condition = self._unique_unmapped_condition_8616(
            node, body_range, condition_range
        )
        self._debug_do_while_refusal_8616(
            node, condition, body_range, condition_range, ordered_condition, unique_unmapped_condition
        )
        if not (
            body_range is not None
            and isinstance(body_statements, list)
            and (ordered_condition or unique_unmapped_condition)
            and _node_reads_stack_cvar_8616(condition, self.dst_cvar)
        ):
            return None
        insertion_index = repeated_prefix_count
        if _insertion_point_has_stack_move_assignment_8616(
            body_statements,
            insertion_index,
            self.dst_cvar,
            self.source_expr,
        ):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return False
        self._debug_do_while_insert_8616(body_range, condition_range)
        body_statements.insert(insertion_index, self.assignment)
        return True

    @cython.ccall
    def _debug_do_while_refusal_8616(
        self,
        node: StructuredAstValue,
        condition: StructuredAstValue,
        body_range: object,
        condition_range: object,
        ordered_condition: cython.bint,
        unique_unmapped_condition: cython.bint,
    ) -> None:
        """Emit optional debug noise when a do-while match is refused."""
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE") and not (
            ordered_condition or unique_unmapped_condition
        ):
            log.warning(
                "[direct-stack-mov-insert-do-body-start] refuse ins=%#x loop=%#x loops=%d "
                "body_range=%r condition_range=%r reads_dst=%s",
                self.ins_addr,
                id(node),
                len(self.condition_reading_do_loop_ids),
                body_range,
                condition_range,
                _node_reads_stack_cvar_8616(condition, self.dst_cvar),
            )

    @cython.ccall
    def _debug_do_while_insert_8616(
        self,
        body_range: object,
        condition_range: object,
    ) -> None:
        """Emit optional debug noise for a do-while insertion."""
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            condition_min = condition_range[0] if condition_range is not None else -1
            log.warning(
                "[direct-stack-mov-insert-do-body-start] insert ins=%#x body_min=%#x "
                "cond_min=%#x dst=%s source=%s",
                self.ins_addr,
                body_range[0] if body_range is not None else -1,
                condition_min,
                _stack_cvar_identity_8616(self.dst_cvar),
                _stack_cvar_identity_8616(self.source_expr),
            )

    @cython.ccall
    def _visit_children_8616(self, node: StructuredAstValue) -> cython.bint:
        """Recurse into statements, loop bodies, else branches, and pairs."""
        child: object
        pairs: object
        statements: object
        _condition: object
        attr: object
        body: object
        stmt: object
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for stmt in tuple(statements):
                if self.visit(stmt):
                    return True
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None and self.visit(child):
                return True
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                if self.visit(body):
                    return True
        return False


@cython.ccall
def _insert_at_do_while_body_start_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    function: StructuredAstValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
    *,
    proven_loopback_edges: object = (),
) -> cython.bint:
    """Insert a proven loop-entry move when a binary backedge repeats it."""
    dst_cvar: object
    dst_cvar = getattr(assignment, "lhs", None)
    if not proven_loopback_edges:
        proven_loopback_edges = _instruction_sequence_loopback_edges_8616(
            function,
            project,
            ins_addr,
        )
    if not proven_loopback_edges:
        return False
    inserter = _DoWhileBodyStartInserter8616(
        root=root,
        project=project,
        ins_addr=ins_addr,
        assignment=assignment,
        dst_cvar=dst_cvar,
        source_expr=getattr(assignment, "rhs", None),
        proven_loopback_edges=proven_loopback_edges,
        condition_reading_do_loop_ids=frozenset(),
        rendered_do_loop_ids=set(),
        rendered_seen=set(),
        seen=set(),
    )
    inserter.collect_rendered_do_loops(root)
    inserter.condition_reading_do_loop_ids = frozenset(inserter.rendered_do_loop_ids)
    return inserter.visit(root)



@cython.dataclasses.dataclass
class _LoopBodyStartInserter8616:
    """Insert a proven stack effect at the matching structured loop boundary."""

    root: StructuredAstValue
    project: StructuredAstValue
    ins_addr: StructuredAstValue
    assignment: StructuredAstValue
    dst_cvar: StructuredAstValue
    source_expr: StructuredAstValue
    proven_loopback_edges: StructuredAstValue
    repeated_sequence_entry: StructuredAstValue
    seen: StructuredAstValue
    best_untagged_tail: StructuredAstValue = None

    def _body_has_loopback_to_update_8616(self, body_range: object) -> cython.bint:
        """Return whether the loop body provably jumps back to the update."""
        start, end = body_range
        if not isinstance(start, int) or not isinstance(end, int) or end < start:
            return False
        if self.proven_loopback_edges:
            return any(
                entry <= int(self.ins_addr) < start and jump >= end
                for entry, jump in iter(self.proven_loopback_edges)
            )
        return self._bytes_jump_back_to_update_8616(start, end)

    @cython.ccall
    def _bytes_jump_back_to_update_8616(self, start: cython.longlong, end: cython.longlong) -> cython.bint:
        """Disassemble the body range looking for a jump back to the update."""
        item: object
        try:
            code = bytes(self.project.loader.memory.load(start, min(max(end - start + 8, 1), 0x200)))
            capstone = self.project.arch.capstone
        except Exception:
            return False
        target_addrs = _candidate_ins_addrs_8616(self.project, int(self.ins_addr))
        try:
            insns = tuple(capstone.disasm(code, start))
        except Exception:
            return False
        for item in insns:
            if self._insn_jumps_to_update_8616(item, start, end, target_addrs):
                return True
        return False

    @staticmethod
    def _insn_jumps_to_update_8616(
        item: StructuredAstValue, start: cython.longlong, end: cython.longlong, target_addrs: StructuredAstValue
    ) -> cython.bint:
        """Return whether one disassembled instruction jumps to the update."""
        addr: object
        target: object
        addr = getattr(item, "address", None)
        if not isinstance(addr, int) or addr < start or addr > end + 8:
            return False
        if str(getattr(item, "mnemonic", "") or "").lower() not in {"jmp", "ljmp"}:
            return False
        operands = _boundary_tuple_8616(getattr(item, "operands", ()) or ())
        if len(operands) != 1 or operator.ne(int(getattr(operands[0], "type", -1)), X86_OP_IMM):
            return False
        target = getattr(operands[0], "imm", None)
        return isinstance(target, int) and int(target) in target_addrs

    @cython.ccall
    def _mark_already_present_8616(self) -> cython.bint:
        """Record that an equivalent update already exists at the point."""
        self.root._inertia_stack_update_assignment_already_present_8616 = True
        return False

    @cython.ccall
    def _insert_body_start_8616(
        self,
        body_statements: object,
        insert_index: cython.longlong,
        debug_message: object,
        debug_values: object,
    ) -> cython.bint:
        """Insert at a proven body position after checking for an existing update."""
        if _insertion_point_has_stack_move_assignment_8616(
            body_statements,
            insert_index,
            self.dst_cvar,
            self.source_expr,
        ):
            return self._mark_already_present_8616()
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                debug_message,
                *debug_values,
                _stack_cvar_identity_8616(self.dst_cvar),
            )
        body_statements.insert(insert_index, self.assignment)
        return True

    @cython.ccall
    def visit(self, node: object, depth: cython.longlong = 0) -> cython.bint:
        """Find a loop body start or tail insertion point for a proven stack update."""
        body: object
        body_statements: object
        condition: object
        result: object
        if node is None or id(node) in self.seen:
            return False
        self.seen.add(id(node))
        body = getattr(node, "body", None)
        condition = getattr(node, "condition", None)
        body_statements = getattr(body, "statements", None)
        if body is not None and condition is not None and node.__class__.__name__ != "CDoWhileLoop":
            body_range = _instruction_addr_range_in_node_8616(body, self.project, self.ins_addr, set())
            condition_range = _instruction_addr_range_in_node_8616(condition, self.project, self.ins_addr, set())
            self._debug_loop_ranges_8616(node, condition_range, body_range)
            result = self._try_tagged_loop_body_8616(body_statements, body_range, condition_range)
            if result is None:
                result = self._try_untagged_while_tail_8616(
                    node, body_statements, body_range, condition_range, depth
                )
            if result is None:
                result = self._try_repeated_sequence_8616(node, body_statements, depth)
            if result is None:
                result = self._try_contained_insert_8616(body_statements, body_range, depth)
            if result is not None:
                return result
        return self._visit_children_8616(node, depth)

    @cython.ccall
    def _debug_loop_ranges_8616(
        self,
        node: StructuredAstValue,
        condition_range: object,
        body_range: object,
    ) -> None:
        """Emit optional debug noise for loop range matching."""
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-update-loop-body-start-check] ins=%#x loop=%s cond_range=%s body_range=%s dst=%s",
                self.ins_addr,
                node.__class__.__name__,
                condition_range,
                body_range,
                _stack_cvar_identity_8616(self.dst_cvar),
            )

    @cython.ccall
    def _try_tagged_loop_body_8616(
        self,
        body_statements: StructuredAstValue,
        body_range: object,
        condition_range: object,
    ) -> bool | None:
        """Insert at the start/tail of a tagged loop body spanning the update."""
        if not (
            isinstance(body_statements, list)
            and body_range is not None
            and condition_range is not None
            and condition_range[1] < int(self.ins_addr) < body_range[0]
        ):
            return None
        insert_index = (
            0
            if self.repeated_sequence_entry
            else len(body_statements) if self._body_has_loopback_to_update_8616(body_range) else 0
        )
        return self._insert_body_start_8616(
            body_statements,
            insert_index,
            "[direct-stack-update-insert-loop-body] insert ins=%#x index=%d "
            "cond_max=%#x body_min=%#x dst=%s",
            (self.ins_addr, insert_index, condition_range[1], body_range[0]),
        )

    @cython.ccall
    def _try_untagged_while_tail_8616(
        self,
        node: StructuredAstValue,
        body_statements: StructuredAstValue,
        body_range: object,
        condition_range: object,
        depth: cython.longlong,
    ) -> bool | None:
        """Handle while(true)-style loops without a tagged condition range."""
        if not (
            node.__class__.__name__ == "CWhileLoop"
            and isinstance(body_statements, list)
            and body_range is not None
            and condition_range is None
        ):
            return None
        if int(self.ins_addr) < body_range[0] and self._body_has_loopback_to_update_8616(body_range):
            insert_index = 0 if self.repeated_sequence_entry else len(body_statements)
            if _insertion_point_has_stack_move_assignment_8616(
                body_statements,
                insert_index,
                self.dst_cvar,
                self.source_expr,
            ):
                return self._mark_already_present_8616()
            body_statements.insert(insert_index, self.assignment)
            return True
        # Guard-style while(true) loops often have no tagged condition; the
        # body guard ranges still prove the nearest following stack update
        # belongs at the loop tail before the implicit loopback.
        gap = int(self.ins_addr) - int(body_range[1])
        if 0 < gap <= 16:
            candidate = (gap, depth, body_statements, len(body_statements))
            if (
                self.best_untagged_tail is None
                or gap < self.best_untagged_tail[0]
                or (operator.eq(gap, self.best_untagged_tail[0]) and depth > self.best_untagged_tail[1])
            ):
                self.best_untagged_tail = candidate
        return None

    @cython.ccall
    def _try_repeated_sequence_8616(
        self,
        node: StructuredAstValue,
        body_statements: StructuredAstValue,
        depth: cython.longlong,
    ) -> bool | None:
        """Prefer the deepest matching loop for repeated sequence entries."""
        read_before_definition_index: object
        stmt: object
        if not (
            self.repeated_sequence_entry
            and self.proven_loopback_edges
            and isinstance(body_statements, list)
        ):
            return None
        # Prefer the deepest matching loop. The exact tagged definition
        # and typed stack read below prevent scope- or name-based hoists.
        for stmt in tuple(body_statements):
            if self.visit(stmt, depth + 1):
                return True
        read_before_definition_index = _loop_body_insertion_index_before_tagged_stack_move_8616(
            node,
            self.project,
            self.ins_addr,
            self.dst_cvar,
            self.source_expr,
        )
        if read_before_definition_index is None:
            return None
        return self._insert_body_start_8616(
            body_statements,
            read_before_definition_index,
            "[direct-stack-update-insert-before-read] insert ins=%#x index=%d dst=%s",
            (self.ins_addr, read_before_definition_index),
        )

    @cython.ccall
    def _try_contained_insert_8616(
        self,
        body_statements: StructuredAstValue,
        body_range: object,
        depth: cython.longlong,
    ) -> bool | None:
        """Insert before the next tagged statement inside the containing loop."""
        index: object
        stmt: object
        if not (
            isinstance(body_statements, list)
            and body_range is not None
            and body_range[0] <= int(self.ins_addr) <= body_range[1]
        ):
            return None
        for stmt in tuple(body_statements):
            if self.visit(stmt, depth + 1):
                return True
        for index, stmt in enumerate(tuple(body_statements)):
            stmt_addr = _following_instruction_addr_in_node_8616(stmt, self.project, self.ins_addr, set())
            if isinstance(stmt_addr, int) and stmt_addr > int(self.ins_addr):
                return self._insert_body_start_8616(
                    body_statements,
                    index,
                    "[direct-stack-update-insert-loop-contained] insert ins=%#x stmt_addr=%#x dst=%s",
                    (self.ins_addr, stmt_addr),
                )
        return None

    @cython.ccall
    def _visit_children_8616(self, node: StructuredAstValue, depth: cython.longlong) -> cython.bint:
        """Recurse into statements, loop bodies, else branches, and pairs."""
        child: object
        pairs: object
        statements: object
        _condition: object
        attr: object
        guarded_body: object
        stmt: object
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            for stmt in tuple(statements):
                if self.visit(stmt, depth + 1):
                    return True
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None and self.visit(child, depth + 1):
                return True
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, guarded_body in tuple(pairs):
                if self.visit(guarded_body, depth + 1):
                    return True
        return False


@cython.ccall
def _insert_at_loop_body_start_after_condition_8616(
    root: StructuredAstValue,
    project: StructuredAstValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
    *,
    proven_loopback_edges: object = (),
    repeated_sequence_entry: cython.bint = False,
) -> cython.bint:
    """Insert a proven stack effect at the matching structured loop boundary."""
    inserter = _LoopBodyStartInserter8616(
        root=root,
        project=project,
        ins_addr=ins_addr,
        assignment=assignment,
        dst_cvar=getattr(assignment, "lhs", None),
        source_expr=getattr(assignment, "rhs", None),
        proven_loopback_edges=proven_loopback_edges,
        repeated_sequence_entry=repeated_sequence_entry,
        seen=set(),
    )
    if inserter.visit(root):
        return True
    if inserter.best_untagged_tail is None:
        return False
    _gap, _depth, body_statements, insert_index = inserter.best_untagged_tail
    if _insertion_point_has_stack_move_assignment_8616(
        body_statements, insert_index, inserter.dst_cvar, inserter.source_expr
    ):
        root._inertia_stack_update_assignment_already_present_8616 = True
        return False
    body_statements.insert(insert_index, assignment)
    return True



_FOLLOWING_ADDR_CHILD_ATTRS_8616 = (
    "statements",
    "lhs",
    "rhs",
    "operand",
    "expr",
    "stmts",
    "init",
    "initializer",
    "condition",
    "cond",
    "iftrue",
    "iffalse",
    "iteration",
    "iterator",
    "body",
    "else_node",
)


@cython.ccall
def _consider_following_addr_8616(
    value: StructuredAstValue,
    best: object,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    seen: object,
) -> int | None:
    """Fold one child candidate into the current best following address."""
    candidate = _following_instruction_addr_in_node_8616(value, project, ins_addr, seen)
    if isinstance(candidate, int) and (best is None or candidate < best):
        return candidate
    return best


@cython.ccall
def _following_addr_in_attrs_8616(
    node: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    seen: object,
    best: int | None,
) -> int | None:
    """Scan child-bearing attributes for nearer following addresses."""
    value: object
    attr: object
    item: object
    for attr in _FOLLOWING_ADDR_CHILD_ATTRS_8616:
        if not hasattr(node, attr):
            continue
        with contextlib.suppress(Exception):
            value = getattr(node, attr)
        if isinstance(value, (list, tuple)):
            for item in tuple(value):
                best = _consider_following_addr_8616(item, best, project, ins_addr, seen)
        elif value is not None:
            best = _consider_following_addr_8616(value, best, project, ins_addr, seen)
    return best


@cython.ccall
def _following_instruction_addr_in_node_8616(
    node: object, project: AngrProjectValue, ins_addr: cython.longlong, seen: object
) -> int | None:
    condition_and_nodes: object
    body: object
    condition: object
    if node is None or id(node) in seen:
        return None
    seen.add(id(node))
    best = _statement_instruction_addr_8616(node, project, ins_addr)
    if not isinstance(best, int) or best <= ins_addr:
        best = None
    best = _following_addr_in_attrs_8616(node, project, ins_addr, seen, best)
    condition_and_nodes = getattr(node, "condition_and_nodes", None)
    if condition_and_nodes:
        for condition, body in tuple(condition_and_nodes):
            best = _consider_following_addr_8616(condition, best, project, ins_addr, seen)
            best = _consider_following_addr_8616(body, best, project, ins_addr, seen)
    return best



@cython.dataclasses.dataclass
class _InsertBeforeNearestFollowingTagged8616:
    """Find and use the nearest following tagged statement eligible for insertion."""

    root: StructuredAstValue
    project: StructuredAstValue
    ins_addr: StructuredAstValue
    ignore_existing_assignment: StructuredAstValue
    prefer_loop_container: StructuredAstValue
    dst_cvar: StructuredAstValue
    source_expr: StructuredAstValue
    seen: StructuredAstValue
    best: StructuredAstValue = None

    @cython.ccall
    def visit(self, node: object, depth: cython.longlong) -> None:
        """Find the nearest following tagged statement eligible for insertion."""
        statements: object
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list) and self._visit_statements_8616(statements, depth):
            return
        self._visit_control_links_8616(node, depth)

    @cython.ccall
    def _visit_statements_8616(self, statements: object, depth: cython.longlong) -> cython.bint:
        """Score each statement and stop early when the update already exists."""
        index: object
        stmt: object
        if not self.ignore_existing_assignment and _list_has_stack_move_assignment_8616(
            statements, self.dst_cvar, self.source_expr
        ):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return True
        for index, stmt in enumerate(tuple(statements)):
            stmt_addr = _following_instruction_addr_in_node_8616(stmt, self.project, self.ins_addr, set())
            if isinstance(stmt_addr, int):
                distance = stmt_addr - self.ins_addr
                if distance > 0:
                    stmt_is_loop = isinstance(
                        stmt,
                        (structured_c.CForLoop, structured_c.CWhileLoop, structured_c.CDoWhileLoop),
                    )
                    self._update_best_8616(distance, depth, statements, index, stmt_is_loop)
            self.visit(stmt, depth + 1)
        return False

    @cython.ccall
    def _update_best_8616(
        self,
        distance: cython.longlong,
        depth: cython.longlong,
        statements: object,
        index: cython.longlong,
        stmt_is_loop: cython.bint,
    ) -> None:
        """Replace the best insertion point when this candidate is nearer."""
        replace_best = self.best is None or distance < self.best[0]
        if self.best is not None and operator.eq(distance, self.best[0]):
            best_is_loop = self.best[4]
            replace_best = depth > self.best[1]
            if self.prefer_loop_container and best_is_loop and not stmt_is_loop:
                replace_best = False
            elif self.prefer_loop_container and stmt_is_loop and depth > self.best[1]:
                replace_best = True
        if replace_best:
            self.best = (distance, depth, statements, index, stmt_is_loop)

    @cython.ccall
    def _visit_control_links_8616(self, node: StructuredAstValue, depth: cython.longlong) -> None:
        """Recurse into loop bodies, else branches, and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                self.visit(child, depth + 1)
        for attr in ("condition_and_nodes",):
            with contextlib.suppress(Exception):
                pairs = getattr(node, attr, None)
            if not pairs:
                continue
            for _condition, body in tuple(pairs):
                self.visit(body, depth + 1)


@cython.ccall
def _insert_before_nearest_following_tagged_statement_8616(
    root: StructuredAstValue,
    project: StructuredAstValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
    *,
    ignore_existing_assignment: cython.bint = False,
    prefer_loop_container: cython.bint = False,
) -> cython.bint:
    visitor = _InsertBeforeNearestFollowingTagged8616(
        root=root,
        project=project,
        ins_addr=ins_addr,
        ignore_existing_assignment=ignore_existing_assignment,
        prefer_loop_container=prefer_loop_container,
        dst_cvar=getattr(assignment, "lhs", None),
        source_expr=getattr(assignment, "rhs", None),
        seen=set(),
    )
    visitor.visit(root, 0)
    if visitor.best is None:
        return False
    _distance, _depth, statements, index, _stmt_is_loop = visitor.best
    if _insertion_point_has_stack_move_assignment_8616(statements, index, visitor.dst_cvar, visitor.source_expr):
        root._inertia_stack_mov_assignment_already_present_8616 = True
        return False
    statements.insert(index, assignment)
    return True



_NODE_READ_CHILD_ATTRS_8616 = (
    "condition",
    "cond",
    "lhs",
    "rhs",
    "operand",
    "expr",
    "variable",
    "index",
    "iftrue",
    "iffalse",
    "body",
    "else_node",
    "args",
    "operands",
    "statements",
)


def _scan_node_value_reads_leaf_8616(
    value: StructuredAstValue,
    leaf_pred: StructuredAstValue,
    seen: object,
) -> cython.bint:
    """Scan a child attribute value (scalar, list, or nested tuple) for a leaf read."""
    if isinstance(value, (list, tuple)):
        return any(
            _scan_node_value_reads_leaf_8616(item, leaf_pred, seen) for item in builtins.iter(tuple(value))
        )
    return _node_reads_leaf_8616(value, leaf_pred, seen=seen)


@cython.ccall
def _node_attrs_read_leaf_8616(
    node: StructuredAstValue,
    leaf_pred: StructuredAstValue,
    seen: object,
) -> cython.bint:
    """Scan the known child-bearing attributes for a leaf read."""
    value: object
    attr: object
    for attr in _NODE_READ_CHILD_ATTRS_8616:
        value = None
        with contextlib.suppress(Exception):
            value = getattr(node, attr, None)
        if _scan_node_value_reads_leaf_8616(value, leaf_pred, seen):
            return True
    return False


@cython.ccall
def _node_reads_leaf_8616(
    node: object,
    leaf_pred: StructuredAstValue,
    *,
    seen: object = None,
) -> cython.bint:
    """Return whether a structured-C node reads a leaf matching the predicate."""
    if node is None:
        return False
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return False
    seen.add(node_id)
    if isinstance(node, structured_c.CVariable):
        return bool(leaf_pred(node))
    if isinstance(node, structured_c.CAssignment):
        return _node_reads_leaf_8616(node.rhs, leaf_pred, seen=seen)
    if not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
        return False
    if _node_attrs_read_leaf_8616(node, leaf_pred, seen):
        return True
    return _node_pairs_read_leaf_8616(node, leaf_pred, seen)


@cython.ccall
def _node_pairs_read_leaf_8616(
    node: StructuredAstValue,
    leaf_pred: StructuredAstValue,
    seen: object,
) -> cython.bint:
    """Scan condition/body pairs for a leaf read."""
    pairs: object
    body: object
    condition: object
    pairs = None
    with contextlib.suppress(Exception):
        pairs = getattr(node, "condition_and_nodes", None)
    if not pairs:
        return False
    for condition, body in tuple(pairs):
        if _node_reads_leaf_8616(condition, leaf_pred, seen=seen) or _node_reads_leaf_8616(
            body,
            leaf_pred,
            seen=seen,
        ):
            return True
    return False


def _node_reads_stack_cvar_8616(
    node: StructuredAstValue, target_cvar: StructuredAstValue, *, seen: object = None
) -> cython.bint:
    return _node_reads_leaf_8616(
        node, lambda leaf: _same_stack_cvar_8616(leaf, target_cvar), seen=seen
    )


def _node_reads_generated_stack_cvar_name_8616(
    node: StructuredAstValue, target_cvar: StructuredAstValue, *, seen: object = None
) -> cython.bint:
    target_names = _generated_stack_cvar_names_8616(target_cvar)
    if not target_names:
        return False
    return _node_reads_leaf_8616(
        node, lambda leaf: bool(target_names & _structured_cvar_names_8616(leaf)), seen=seen
    )



@cython.ccall
def _same_register_cvar_name_8616(node: StructuredAstValue, reg_name: object) -> cython.bint:
    return bool(operator.eq(_cvar_register_name_8616(node), reg_name))


_REGISTER_READ_CHILD_ATTRS_8616 = (
    "condition",
    "cond",
    "lhs",
    "rhs",
    "operand",
    "expr",
    "iftrue",
    "iffalse",
    "body",
    "else_node",
    "args",
    "operands",
    "statements",
)


def _scan_register_name_value_8616(
    value: StructuredAstValue,
    reg_name: object,
    seen: object,
    memo: object,
) -> cython.bint:
    """Scan a child attribute value for a register read, memoizing shared subtrees."""
    if isinstance(value, (list, tuple)):
        return any(
            _scan_register_name_value_8616(item, reg_name, seen, memo) for item in builtins.iter(tuple(value))
        )
    return _node_reads_register_name_8616(value, reg_name, seen=seen, memo=memo)


@cython.ccall
def _register_name_attrs_read_8616(
    node: StructuredAstValue,
    reg_name: object,
    seen: object,
    memo: object,
) -> cython.bint:
    """Scan the register-reader child attributes for a register read."""
    value: object
    attr: object
    for attr in _REGISTER_READ_CHILD_ATTRS_8616:
        value = None
        with contextlib.suppress(Exception):
            value = getattr(node, attr, None)
        if _scan_register_name_value_8616(value, reg_name, seen, memo):
            return True
    return False


def _register_name_pairs_read_8616(
    node: StructuredAstValue,
    reg_name: object,
    seen: object,
    memo: object,
) -> cython.bint:
    """Scan condition/body pairs for a register read."""
    pairs: object
    pairs = None
    with contextlib.suppress(Exception):
        pairs = getattr(node, "condition_and_nodes", None)
    if not pairs:
        return False
    return any(
        _node_reads_register_name_8616(condition, reg_name, seen=seen, memo=memo)
        or _node_reads_register_name_8616(body, reg_name, seen=seen, memo=memo)
        for condition, body in builtins.iter(tuple(pairs))
    )


@cython.ccall
def _node_reads_register_name_8616(
    node: object,
    reg_name: object,
    *,
    seen: object = None,
    memo: object = None,
) -> cython.bint:
    """Return whether one C-AST node reads a register, memoizing shared subtrees."""
    if node is None:
        return False
    if seen is None:
        seen = set()
    node_id = id(node)
    if memo is not None and node_id in memo:
        return memo[node_id]
    if node_id in seen:
        return False
    seen.add(node_id)
    if isinstance(node, structured_c.CVariable):
        result = _same_register_cvar_name_8616(node, reg_name)
    elif isinstance(node, structured_c.CAssignment):
        result = _node_reads_register_name_8616(node.rhs, reg_name, seen=seen, memo=memo)
    elif not type(node).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
        result = False
    else:
        result = _register_name_attrs_read_8616(node, reg_name, seen, memo) or _register_name_pairs_read_8616(
            node, reg_name, seen, memo
        )
    if memo is not None:
        memo[node_id] = result
    return result


@cython.ccall
def _is_same_register_move_assignment_8616(
    stmt: StructuredAstValue, reg_name: object, source_expr: StructuredAstValue
) -> cython.bint:
    return (
        isinstance(stmt, structured_c.CAssignment)
        and _same_register_cvar_name_8616(getattr(stmt, "lhs", None), reg_name)
        and _same_stack_move_rhs_8616(getattr(stmt, "rhs", None), source_expr)
    )


@cython.ccall
def _insertion_point_has_register_move_assignment_8616(
    statements: object,
    insert_index: cython.longlong,
    reg_name: object,
    source_expr: StructuredAstValue,
) -> cython.bint:
    if insert_index > 0 and _is_same_register_move_assignment_8616(statements[insert_index - 1], reg_name, source_expr):
        return True
    return bool(insert_index < len(statements) and _is_same_register_move_assignment_8616(statements[insert_index], reg_name, source_expr))


@cython.dataclasses.dataclass
class _InsertBeforeFirstRegisterUse8616:
    """Place a proven reload only at a consumer carrying its instruction origin."""

    reg_name: StructuredAstValue
    register_width: StructuredAstValue
    project: StructuredAstValue
    ins_addr: StructuredAstValue
    root: StructuredAstValue
    source_expr: StructuredAstValue
    codegen: StructuredAstValue
    seen: StructuredAstValue

    @cython.ccall
    def visit(self, node: object) -> cython.bint:
        """Keep unrelated earlier reads intact when a register name is reused."""
        statements: object
        if node is None or id(node) in self.seen:
            return False
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list) and self._visit_statements_8616(statements):
            return True
        return self._visit_control_links_8616(node)

    @cython.ccall
    def _visit_statements_8616(self, statements: object) -> cython.bint:
        """Insert before the first statement that reads the register at this instruction."""
        cvar: object
        nested_statements: object
        index: object
        stmt: object
        for index, stmt in enumerate(tuple(statements)):
            nested_statements = getattr(stmt, "statements", None)
            if (
                isinstance(stmt, (structured_c.CForLoop, structured_c.CWhileLoop, structured_c.CDoWhileLoop))
                or isinstance(nested_statements, list)
            ) and self.visit(stmt):
                return True
            cvar = (
                instruction_local_register_read_8616(stmt, self.reg_name, self.register_width)
                if _node_has_instruction_address_8616(stmt, self.project, self.ins_addr)
                else None
            )
            if cvar is not None:
                if _insertion_point_has_register_move_assignment_8616(
                    statements, index, self.reg_name, self.source_expr
                ):
                    self.root._inertia_stack_mov_assignment_already_present_8616 = True
                    return True
                assignment = structured_c.CAssignment(
                    cvar, self.source_expr, codegen=self.codegen, tags={"ins_addr": self.ins_addr}
                )
                statements.insert(index, assignment)
                return True
            if self.visit(stmt):
                return True
        return False

    @cython.ccall
    def _visit_control_links_8616(self, node: StructuredAstValue) -> cython.bint:
        """Recurse into bodies, else branches, and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node"):
            child = None
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if self.visit(child):
                return True
        pairs = None
        with contextlib.suppress(Exception):
            pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                if self.visit(body):
                    return True
        return False


@cython.ccall
def _insert_before_first_register_cvar_use_8616(
    root: StructuredAstValue, reg_name: object, source_expr: StructuredAstValue, codegen: StructuredAstValue,
    *, project: AngrProjectValue, ins_addr: cython.longlong, register_width: cython.longlong,
) -> cython.bint:
    """Place a proven reload only at a consumer carrying its instruction origin."""
    visitor = _InsertBeforeFirstRegisterUse8616(
        reg_name=reg_name,
        register_width=register_width,
        project=project,
        ins_addr=ins_addr,
        root=root,
        source_expr=source_expr,
        codegen=codegen,
        seen=set(),
    )
    return visitor.visit(root)



@cython.dataclasses.dataclass
class _InsertBeforeFirstStackUse8616:
    """Closure-state walker extracted from a nested `visit`-style def."""

    assignment: StructuredAstValue
    dst_cvar: StructuredAstValue
    ignore_existing_assignment: StructuredAstValue
    prefer_outer_control_read: StructuredAstValue
    root: StructuredAstValue
    seen: StructuredAstValue
    source_expr: StructuredAstValue

    @cython.ccall
    def visit(self, node: object, path: object = "root") -> cython.bint:
        """Insert a stack assignment before the first visible stack read."""
        statements: object
        if node is None or id(node) in self.seen:
            return False
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list) and self._visit_statements_8616(node, statements, path):
            return True
        return self._visit_control_links_8616(node, path)

    @cython.ccall
    def _visit_statements_8616(
        self,
        node: StructuredAstValue,
        statements: object,
        path: object,
    ) -> cython.bint:
        """Scan a statement list for the first readable stack-cvar use point."""
        condition_and_nodes: object
        nested_statements: object
        index: object
        stmt: object
        if not self.ignore_existing_assignment and _list_has_stack_move_assignment_8616(
            statements, self.dst_cvar, self.source_expr
        ):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return True
        for index, stmt in enumerate(tuple(statements)):
            item_path = f"{path}.{index}"
            nested_statements = getattr(stmt, "statements", None)
            condition_and_nodes = getattr(stmt, "condition_and_nodes", None)
            if isinstance(
                stmt, (structured_c.CForLoop, structured_c.CWhileLoop, structured_c.CDoWhileLoop)
            ) and self.visit(stmt, item_path):
                return True
            if condition_and_nodes:
                if self._visit_condition_stmt_8616(statements, index, item_path, stmt, condition_and_nodes):
                    return True
                continue
            if isinstance(nested_statements, list) and self.visit(stmt, item_path):
                return True
            if _node_reads_stack_cvar_8616(stmt, self.dst_cvar) or _node_reads_generated_stack_cvar_name_8616(
                stmt,
                self.dst_cvar,
            ):
                if self._try_insert_at_index_8616(statements, index, item_path, stmt):
                    return True
            elif self.visit(stmt, item_path):
                return True
        return False

    @cython.ccall
    def _visit_condition_stmt_8616(
        self,
        statements: object,
        index: cython.longlong,
        item_path: object,
        stmt: StructuredAstValue,
        condition_and_nodes: StructuredAstValue,
    ) -> cython.bint:
        """Handle a condition-paired statement: insert before a reading condition or recurse."""
        if self._condition_reads_dst_8616(stmt, condition_and_nodes):
            return self._try_insert_at_index_8616(statements, index, item_path, stmt)
        return self.visit(stmt, item_path)

    def _condition_reads_dst_8616(self, stmt: StructuredAstValue, condition_and_nodes: StructuredAstValue) -> cython.bint:
        """Check whether the paired conditions or the statement read the target cvar."""
        return any(
            _node_reads_stack_cvar_8616(condition, self.dst_cvar)
            or _node_reads_generated_stack_cvar_name_8616(condition, self.dst_cvar)
            for condition, _body in builtins.iter(tuple(condition_and_nodes))
            if condition is not None
        ) or (
            self.prefer_outer_control_read
            and (
                _node_reads_stack_cvar_8616(stmt, self.dst_cvar)
                or _node_reads_generated_stack_cvar_name_8616(stmt, self.dst_cvar)
            )
        )

    @cython.ccall
    def _try_insert_at_index_8616(
        self,
        statements: object,
        index: cython.longlong,
        item_path: object,
        stmt: StructuredAstValue,
    ) -> cython.bint:
        """Insert the assignment at ``index`` unless an identical store already sits there."""
        if _insertion_point_has_stack_move_assignment_8616(statements, index, self.dst_cvar, self.source_expr):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return True
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-mov-insert] stack before first use path=%s stmt=%s dst=%s",
                item_path,
                type(stmt).__name__,
                _stack_cvar_identity_8616(self.dst_cvar),
            )
        statements.insert(index, self.assignment)
        return True

    @cython.ccall
    def _visit_control_links_8616(self, node: StructuredAstValue, path: object) -> cython.bint:
        """Recurse into loop bodies, else branches, and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        pair_index: object
        for attr in ("body", "else_node"):
            child = None
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if self.visit(child, f"{path}.{attr}"):
                return True
        pairs = None
        with contextlib.suppress(Exception):
            pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for pair_index, (_condition, body) in enumerate(tuple(pairs)):
                if self.visit(body, f"{path}.condition_and_nodes.{pair_index}.body"):
                    return True
        return False




@cython.ccall
def _insert_before_first_stack_cvar_use_8616(
    root: StructuredAstValue,
    assignment: StructuredAstValue,
    *,
    prefer_outer_control_read: cython.bint = False,
    ignore_existing_assignment: cython.bint = False,
) -> cython.bint:
    dst_cvar: object
    source_expr: object
    dst_cvar = getattr(assignment, "lhs", None)
    source_expr = getattr(assignment, "rhs", None)
    seen: set[cython.longlong] = set()

    visitor = _InsertBeforeFirstStackUse8616(
        assignment=assignment,
        dst_cvar=dst_cvar,
        ignore_existing_assignment=ignore_existing_assignment,
        prefer_outer_control_read=prefer_outer_control_read,
        root=root,
        seen=seen,
        source_expr=source_expr,
    )
    return visitor.visit(root)



@cython.dataclasses.dataclass
class _InsertBeforeFirstStackOffsetUse8616:
    """Closure-state walker extracted from a nested `visit`-style def."""

    assignment: StructuredAstValue
    dst_cvar: StructuredAstValue
    root: StructuredAstValue
    seen: StructuredAstValue
    source_expr: StructuredAstValue
    target_offset: StructuredAstValue

    @cython.ccall
    def visit(self, node: object) -> cython.bint:
        """Insert a stack assignment before the first read of a raw stack offset."""
        statements: object
        if node is None or id(node) in self.seen:
            return False
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list) and self._visit_statements_8616(statements):
            return True
        return self._visit_control_links_8616(node)

    @cython.ccall
    def _visit_statements_8616(self, statements: object) -> cython.bint:
        """Scan a statement list for the first offset-reading statement."""
        nested_statements: object
        index: object
        stmt: object
        if _list_has_stack_move_assignment_8616(statements, self.dst_cvar, self.source_expr):
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            return True
        for index, stmt in enumerate(tuple(statements)):
            if isinstance(
                stmt, (structured_c.CForLoop, structured_c.CWhileLoop, structured_c.CDoWhileLoop)
            ) and self.visit(stmt):
                return True
            nested_statements = getattr(stmt, "statements", None)
            if isinstance(nested_statements, list) and self.visit(stmt):
                return True
            if _expr_reads_stack_offset_8616(stmt, self.target_offset):
                if _insertion_point_has_stack_move_assignment_8616(statements, index, self.dst_cvar, self.source_expr):
                    self.root._inertia_stack_mov_assignment_already_present_8616 = True
                    return True
                statements.insert(index, self.assignment)
                return True
            if self.visit(stmt):
                return True
        return False

    @cython.ccall
    def _visit_control_links_8616(self, node: StructuredAstValue) -> cython.bint:
        """Recurse into loop bodies, else branches, and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node"):
            child = None
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if self.visit(child):
                return True
        pairs = None
        with contextlib.suppress(Exception):
            pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                if self.visit(body):
                    return True
        return False



@cython.ccall
def _insert_before_first_stack_offset_use_8616(
    root: StructuredAstValue, assignment: StructuredAstValue, target_offset: cython.longlong
) -> cython.bint:
    dst_cvar: object
    source_expr: object
    dst_cvar = getattr(assignment, "lhs", None)
    source_expr = getattr(assignment, "rhs", None)
    seen: set[cython.longlong] = set()

    visitor = _InsertBeforeFirstStackOffsetUse8616(
        assignment=assignment,
        dst_cvar=dst_cvar,
        root=root,
        seen=seen,
        source_expr=source_expr,
        target_offset=target_offset,
    )
    return visitor.visit(root)



@cython.dataclasses.dataclass
class _InsertGlobalUpdateBeforeNearest8616:
    """Closure-state walker extracted from a nested `visit`-style def."""

    best: StructuredAstValue
    delta: StructuredAstValue
    dst_cvar: StructuredAstValue
    ins_addr: StructuredAstValue
    project: StructuredAstValue
    root: StructuredAstValue
    seen: StructuredAstValue

    @cython.ccall
    def visit(self, node: object, depth: cython.longlong) -> None:
        """Record the closest following tagged insertion point."""
        statements: object
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list) and self._visit_statements_8616(statements, depth):
            return
        self._visit_control_links_8616(node, depth)

    @cython.ccall
    def _visit_statements_8616(self, statements: object, depth: cython.longlong) -> cython.bint:
        """Score each statement position as a candidate insertion point."""
        index: object
        stmt: object
        if _list_has_global_update_assignment_for_insn_8616(statements, self.project, self.dst_cvar, self.delta, self.ins_addr):
            self.root._inertia_global_update_assignment_already_present_8616 = True
            return True
        for index, stmt in enumerate(tuple(statements)):
            stmt_addr = _following_instruction_addr_in_node_8616(stmt, self.project, self.ins_addr, set())
            if isinstance(stmt_addr, int):
                distance = stmt_addr - self.ins_addr
                if distance > 0 and (
                    self.best is None or distance < self.best[0] or (operator.eq(distance, self.best[0]) and depth > self.best[1])
                ):
                    self.best = (distance, depth, statements, index)
            self.visit(stmt, depth + 1)
        return False

    @cython.ccall
    def _visit_control_links_8616(self, node: StructuredAstValue, depth: cython.longlong) -> None:
        """Recurse into loop bodies, else branches, and condition/body pairs."""
        child: object
        pairs: object
        _condition: object
        attr: object
        body: object
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            with contextlib.suppress(Exception):
                child = getattr(node, attr, None)
            if child is not None:
                self.visit(child, depth + 1)
        with contextlib.suppress(Exception):
            pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                self.visit(body, depth + 1)



@cython.ccall
def _insert_global_update_before_nearest_following_tagged_statement_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
    *,
    delta: cython.longlong,
) -> cython.bint:
    dst_cvar: object
    best: object = None
    dst_cvar = getattr(assignment, "lhs", None)
    seen: set[cython.longlong] = set()

    visitor = _InsertGlobalUpdateBeforeNearest8616(
        best=best,
        delta=delta,
        dst_cvar=dst_cvar,
        ins_addr=ins_addr,
        project=project,
        root=root,
        seen=seen,
    )
    visitor.visit(root, 0)
    if visitor.best is None:
        return False
    _distance, _depth, statements, index = visitor.best
    if _insertion_point_has_global_update_assignment_8616(statements, index, project, dst_cvar, delta, ins_addr):
        root._inertia_global_update_assignment_already_present_8616 = True
        return False
    statements.insert(index, assignment)
    return True



@cython.dataclasses.dataclass
class _GlobalLoopCollector8616:
    """Collect loops that contain the target instruction, tracking ancestor ranges."""

    project: StructuredAstValue
    ins_addr: cython.longlong
    fact_candidates: StructuredAstValue
    loops: StructuredAstValue
    seen: StructuredAstValue
    loop_types: StructuredAstValue

    def collect(
        self,
        node: object,
        depth: cython.longlong,
        ancestors: object,
    ) -> None:
        """Collect loops through the dynamic third-party structured-C boundary."""
        loop_range: object
        _condition: object
        body: object
        statement: object
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        next_ancestors = ancestors
        if isinstance(node, self.loop_types):
            loop_range = _instruction_addr_range_in_node_8616(node, self.project, self.ins_addr)
            condition_range = _instruction_addr_range_in_node_8616(node.condition, self.project, self.ins_addr)
            if loop_range is not None and any(
                loop_range[0] <= candidate <= loop_range[1] for candidate in iter(self.fact_candidates)
            ):
                self.loops.append((depth, node, loop_range, condition_range, ancestors))
            if loop_range is not None:
                next_ancestors = (*ancestors, (loop_range, condition_range))

        if isinstance(node, structured_c.CStatements):
            for statement in tuple(node.statements):
                self.collect(statement, depth + 1, next_ancestors)
            return
        if isinstance(node, self.loop_types):
            self.collect(node.body, depth + 1, next_ancestors)
            return
        if isinstance(node, structured_c.CIfElse):
            for _condition, body in tuple(node.condition_and_nodes):
                self.collect(body, depth + 1, next_ancestors)
            self.collect(node.else_node, depth + 1, next_ancestors)


@cython.ccall
def _edge_covers_ancestor_8616(
    edge: object,
    ancestor: object,
) -> cython.bint:
    """Return whether an edge proves an ancestor rather than this loop."""
    ancestor_condition: object
    ancestor_range, ancestor_condition = ancestor
    repeated_start = ancestor_condition[0] if ancestor_condition is not None else ancestor_range[0]
    entry, jump = edge
    return entry <= repeated_start and jump >= ancestor_range[1]


def _loop_body_insertion_candidates_8616(
    body: StructuredAstValue,
    body_statements: object,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    local_edges: object,
) -> object:
    """Collect (distance, index) insertion candidates inside the loop body."""
    index: object
    statement: object
    insertion_candidates: list[tuple[cython.longlong, cython.longlong]] = []
    if isinstance(body_statements, list):
        for index, statement in enumerate(tuple(body_statements)):
            following_addr = _following_instruction_addr_in_node_8616(statement, project, ins_addr, set())
            if not isinstance(following_addr, int):
                continue
            if any(entry <= following_addr <= jump for entry, jump in iter(local_edges)):
                insertion_candidates.append((following_addr - ins_addr, index))
    else:
        following_addr = _following_instruction_addr_in_node_8616(body, project, ins_addr, set())
        if isinstance(following_addr, int) and any(
            entry <= following_addr <= jump for entry, jump in iter(local_edges)
        ):
            insertion_candidates.append((following_addr - ins_addr, 0))
    return insertion_candidates


@cython.ccall
def _insert_assignment_into_loop_body_8616(
    root: StructuredAstValue,
    loop: StructuredAstValue,
    body: StructuredAstValue,
    body_statements: object,
    insertion_index: cython.longlong,
    assignment: StructuredAstValue,
    project: AngrProjectValue,
    ins_addr: cython.longlong,
    delta: cython.longlong,
) -> DirectGlobalLoopInsertionStatus8616:
    """Insert the assignment at the proven in-body position."""
    dst_cvar = assignment.lhs
    if isinstance(body_statements, list):
        if _list_has_global_update_assignment_for_insn_8616(
            body_statements,
            project,
            dst_cvar,
            delta,
            ins_addr,
        ):
            root._inertia_global_update_assignment_already_present_8616 = True
            return DirectGlobalLoopInsertionStatus8616.NOT_APPLICABLE
        body_statements.insert(insertion_index, assignment)
    else:
        loop.body = structured_c.CStatements([assignment, body], codegen=assignment.codegen)
    return DirectGlobalLoopInsertionStatus8616.INSERTED


def _insert_global_update_in_proven_loop_8616(
    root: StructuredAstValue,
    project: AngrProjectValue,
    function: StructuredAstValue,
    ins_addr: cython.longlong,
    assignment: StructuredAstValue,
    *,
    delta: cython.longlong,
) -> DirectGlobalLoopInsertionStatus8616:
    """Insert a repeated global effect only in its deepest binary-proven loop."""
    loop_types = (structured_c.CForLoop, structured_c.CWhileLoop, structured_c.CDoWhileLoop)
    fact_candidates = _candidate_function_ins_addrs_8616(
        project,
        function,
        ins_addr,
    )
    loops: list[
        tuple[
            cython.longlong,
            StructuredAstValue,
            tuple[cython.longlong, cython.longlong],
            tuple[int, int] | None,
            tuple[tuple[tuple[cython.longlong, cython.longlong], tuple[int, int] | None], ...],
        ]
    ] = []
    seen: set[cython.longlong] = set()
    collector = _GlobalLoopCollector8616(
        project=project,
        ins_addr=ins_addr,
        fact_candidates=fact_candidates,
        loops=loops,
        seen=seen,
        loop_types=loop_types,
    )
    collector.collect(root, 0, ())
    if not loops:
        return DirectGlobalLoopInsertionStatus8616.NOT_APPLICABLE

    _depth, loop, loop_range, condition_range, ancestors = max(loops, key=lambda item: item[0])
    covering_edges = _structured_loopback_edges_covering_instruction_8616(
        function,
        project,
        ins_addr,
        loop_range,
        condition_range,
    )
    local_edges = tuple(
        edge
        for edge in iter(covering_edges)
        if not any(_edge_covers_ancestor_8616(edge, ancestor) for ancestor in iter(ancestors))
    )
    if not local_edges:
        return DirectGlobalLoopInsertionStatus8616.REFUSED_UNPROVEN_NESTED_SCOPE

    body = loop.body
    body_statements = body.statements if isinstance(body, structured_c.CStatements) else None
    insertion_candidates = _loop_body_insertion_candidates_8616(
        body,
        body_statements,
        project,
        ins_addr,
        local_edges,
    )
    insertion_candidates = [candidate for candidate in iter(insertion_candidates) if candidate[0] > 0]
    if not insertion_candidates:
        return DirectGlobalLoopInsertionStatus8616.REFUSED_UNPROVEN_NESTED_SCOPE

    _distance, insertion_index = min(insertion_candidates)
    return _insert_assignment_into_loop_body_8616(
        root,
        loop,
        body,
        body_statements,
        insertion_index,
        assignment,
        project,
        ins_addr,
        delta,
    )



def _direct_global_update_ordered_insns_8616(
    project: AngrProjectValue, function: StructuredAstValue
) -> object:
    """Return one deterministic instruction per address from dynamic angr blocks.

    ``_direct_global_update_blocks_8616`` may combine CFG blocks with a linear
    decode of the same function.  Consumers reason about adjacent machine
    instructions, so duplicate addresses must be collapsed before ordering.
    """
    address: object
    insn: object
    block: object
    wrapper: object
    by_address: dict[cython.longlong, StructuredAstValue] = {}
    for block in _direct_global_update_blocks_8616(project, function):
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = getattr(wrapper, "insn", wrapper)
            address = getattr(insn, "address", None)
            if isinstance(address, int):
                by_address.setdefault(address, insn)
    return _boundary_tuple_8616(by_address[address] for address in builtins.iter(sorted(by_address)))


@cython.ccall
def _direct_global_update_has_adjacent_high_carry_8616(
    project: AngrProjectValue,
    function: StructuredAstValue,
    fact: DirectGlobalUpdateFact8616,
) -> cython.bint:
    """Prove that a low-word update continues into its adjacent high word."""
    expected_high_id: object
    low_id: object
    low_size: object
    index: object
    low_insn: object
    insns = _direct_global_update_ordered_insns_8616(project, function)
    for index, low_insn in enumerate(insns[:-1]):
        if operator.ne(getattr(low_insn, "address", None), fact.ins_addr):
            continue
        low_id = getattr(low_insn, "id", None)
        if not isinstance(low_id, int):
            return False
        expected_high_id = {
            X86_INS_ADD: X86_INS_ADC,
            X86_INS_SUB: X86_INS_SBB,
        }.get(low_id)
        if expected_high_id is None:
            return False
        high_insn = insns[index + 1]
        low_size = getattr(low_insn, "size", None)
        if (
            not isinstance(low_size, int)
            or low_size <= 0
            or operator.ne(getattr(high_insn, "address", None), fact.ins_addr + low_size)
            or operator.ne(getattr(high_insn, "id", None), expected_high_id)
        ):
            return False
        high_operands = _boundary_tuple_8616(
            getattr(high_insn, "operands", ()) or ()
        )
        if len(high_operands) != 2:
            return False
        high_slot = _direct_global_mem_operand_offset_width_8616(
            high_operands[0]
        )
        return (
            high_slot == (((fact.displacement & 0xFFFF) + 2) & 0xFFFF, 2)
            and operator.eq(getattr(high_operands[1], "type", None), X86_OP_IMM)
            and int(getattr(high_operands[1], "imm", 1) or 0) == 0
        )
    return False


@cython.ccall
def _operand_is_stack_memory_8616(operand: StructuredAstValue) -> cython.bint:
    base: object
    index: object
    mem: object
    if operator.ne(getattr(operand, "type", None), X86_OP_MEM):
        return False
    mem = getattr(operand, "mem", None)
    if mem is None:
        return False
    base = getattr(mem, "base", X86_REG_INVALID)
    index = getattr(mem, "index", X86_REG_INVALID)
    return base in {X86_REG_BP, X86_REG_SP} and index in {0, X86_REG_INVALID}


def _setup_prefix_instruction_is_nonsemantic_8616(project: AngrProjectValue, insn: StructuredAstValue) -> cython.bint:
    insn_id: object
    target: object
    insn_id = getattr(insn, "id", None)
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if insn_id in {X86_INS_PUSH, X86_INS_POP}:
        return all(getattr(operand, "type", None) in {X86_OP_REG, X86_OP_IMM} for operand in iter(operands))
    if operator.eq(insn_id, X86_INS_MOV):
        return all(
            operator.ne(getattr(operand, "type", None), X86_OP_MEM) or _operand_is_stack_memory_8616(operand)
            for operand in iter(operands)
        )
    if insn_id in {X86_INS_ADD, X86_INS_SUB}:
        if len(operands) != 2 or operator.ne(getattr(operands[0], "type", None), X86_OP_REG):
            return False
        return getattr(operands[0], "reg", None) in {X86_REG_SP, X86_REG_BP}
    if insn_id in {X86_INS_CALL, X86_INS_LCALL}:
        if len(operands) != 1:
            return False
        target = _direct_call_target_from_operand_8616(operands[0])
        if target is None:
            return False
        callee_name, _callee, _resolved_target = _callee_name_for_direct_stack_move_8616(project, target)
        return _is_stack_probe_helper_name_for_linear_lowering_8616(callee_name)
    return False


@cython.ccall
def _direct_global_update_can_insert_at_body_start_8616(
    project: AngrProjectValue, function: StructuredAstValue, fact: DirectGlobalUpdateFact8616
) -> cython.bint:
    ins_addr: object
    insn: object
    insns = _direct_global_update_ordered_insns_8616(project, function)
    if not insns:
        return False
    found_fact = False
    for insn in insns:
        ins_addr = getattr(insn, "address", None)
        if not isinstance(ins_addr, int):
            continue
        if operator.eq(ins_addr, fact.ins_addr):
            found_fact = True
            break
        if ins_addr > fact.ins_addr:
            break
        if not _setup_prefix_instruction_is_nonsemantic_8616(project, insn):
            return False
    return found_fact


@cython.ccall
def _insert_global_update_at_body_start_8616(
    root: StructuredAstValue, project: AngrProjectValue, assignment: StructuredAstValue, *, delta: cython.longlong, ins_addr: cython.longlong
) -> cython.bint:
    dst_cvar: object
    statements: object
    statements = getattr(root, "statements", None)
    if not isinstance(statements, list):
        return False
    dst_cvar = getattr(assignment, "lhs", None)
    if _list_has_global_update_assignment_for_insn_8616(statements, project, dst_cvar, delta, ins_addr):
        root._inertia_global_update_assignment_already_present_8616 = True
        return False
    if _tree_has_untagged_global_update_assignment_8616(root, dst_cvar, delta):
        root._inertia_global_update_assignment_already_present_8616 = True
        return False
    statements.insert(0, assignment)
    return True


def _debug_global_update_insn_dump_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    function: StructuredAstValue,
    facts: StructuredAstValue,
) -> None:
    """Emit the optional INERTIA_DEBUG_GLOBAL_UPDATE instruction summary."""
    insn: object
    block: object
    wrapper: object
    blocks = _direct_global_update_blocks_8616(project, function)
    insn_debug = []
    for block in blocks:
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block)[:8]:
            insn = getattr(wrapper, "insn", wrapper)
            insn_debug.append(
                (
                    getattr(insn, "address", None),
                    getattr(insn, "id", None),
                    getattr(insn, "mnemonic", None),
                    len(_boundary_tuple_8616(getattr(insn, "operands", ()) or ())),
                )
            )
    print(
        "[dbg-global-update] "
        f"func={getattr(function, 'addr', None)!r} "
        f"cfunc={getattr(getattr(codegen, 'cfunc', None), 'addr', None)!r} "
        f"blocks={_boundary_tuple_8616(getattr(block, 'addr', None) for block in iter(blocks))!r} "
        f"insns={tuple(insn_debug)!r} "
        f"facts={facts!r}",
        file=sys.stderr,
        flush=True,
    )


@cython.ccall
def _republish_codegen_root_8616(codegen: StructuredAstValue, root: StructuredAstValue) -> None:
    """Publish the rewritten root on every cfunc projection."""
    with contextlib.suppress(Exception):
        codegen.cfunc.body = root
    with contextlib.suppress(Exception):
        codegen.cfunc.statements = root
    with contextlib.suppress(Exception):
        codegen.cfunc.stmt = root
    with contextlib.suppress(Exception):
        codegen.cfunc.statements = root
    with contextlib.suppress(Exception):
        codegen.cfunc.stmt = root


@cython.dataclasses.dataclass
class _GlobalIncdecRun8616:
    """Materialize direct no-base/no-index real-mode global INC/DEC effects."""

    codegen: StructuredAstValue
    project: StructuredAstValue
    function: StructuredAstValue
    root: StructuredAstValue
    stats: object
    changed: cython.bint = False
    addr: cython.longlong = 0
    width: cython.longlong = 0
    delta: cython.longlong = 0
    name: str = ""
    cvar: StructuredAstValue = None

    @cython.ccall
    def _record_storage_identity_8616(self, ins_addr: cython.longlong) -> None:
        """Retain the exact DS object after new or prior materialization."""
        record_global_storage_identity_fact_8616(
            self.codegen,
            GlobalStorageIdentityFact8616(
                space=MemSpace.DS,
                offset=self.addr,
                width=self.width,
                name=self.name,
                evidence_addr=ins_addr,
                kind=StorageIdentityEvidenceKind8616.DIRECT_GLOBAL_UPDATE,
            ),
        )

    @cython.ccall
    def _build_fact_cvar_8616(self, fact: DirectGlobalUpdateFact8616) -> StructuredAstValue:
        """Name the global, rename generated cvars, and build the carrier cvar."""
        unified: object
        variables_in_use: object
        self.addr = fact.displacement & 0xFFFF
        self.width = fact.width if fact.width in {1, 2} else 2
        self.delta = fact.delta
        self.stats["classified_fact_count"] = int(self.stats.get("classified_fact_count", 0) or 0) + 1
        name = _direct_global_update_name_8616(
            self.project, getattr(getattr(self.codegen, "cfunc", None), "addr", None), self.addr
        )
        self.name = _preferred_same_addr_global_name_8616(self.root, self.addr, self.width, name)
        renamed_count = _rename_generated_same_addr_global_cvars_8616(self.root, self.addr, self.width, self.name)
        if renamed_count:
            self.changed = True
        variable = SimMemoryVariable(
            self.addr, self.width, name=self.name, region=getattr(getattr(self.codegen, "cfunc", None), "addr", None)
        )
        cvar = structured_c.CVariable(
            variable,
            unified_variable=variable,
            variable_type=_type_for_access_width_8616(self.width),
            codegen=self.codegen,
            tags={"ins_addr": fact.ins_addr},
        )
        variables_in_use = getattr(self.codegen.cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified = getattr(self.codegen.cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    @cython.ccall
    def _replacement_factory_8616(self, tags: StructuredAstValue) -> StructuredAstValue:
        """Build the update assignment for a tagged node."""
        rhs = structured_c.CBinaryOp(
            "Add" if self.delta > 0 else "Sub",
            self.cvar,
            structured_c.CConstant(abs(int(self.delta)), _type_for_access_width_8616(self.width), codegen=self.codegen),
            codegen=self.codegen,
        )
        return structured_c.CAssignment(self.cvar, rhs, codegen=self.codegen, tags=tags)

    @cython.ccall
    def _count_already_materialized_8616(self) -> None:
        """Count one already-materialized consumed fact."""
        self.stats["already_materialized_count"] = int(
            self.stats.get("already_materialized_count", 0) or 0
        ) + 1
        self.stats["consumed_fact_count"] = int(
            self.stats.get("consumed_fact_count", 0) or 0
        ) + 1

    @cython.ccall
    def _already_materialized_8616(
        self,
        fact: DirectGlobalUpdateFact8616,
        fact_key: DirectGlobalUpdateFact8616,
        consumed_facts: object,
    ) -> cython.bint:
        """Handle facts whose update already exists in the structured tree."""
        if (
            _direct_global_update_has_adjacent_high_carry_8616(
                self.project,
                self.function,
                fact,
            )
            and _tree_has_covering_dword_update_assignment_for_insn_8616(
                self.root,
                self.project,
                addr=self.addr,
                delta=self.delta,
                ins_addr=fact.ins_addr,
            )
        ):
            consumed_facts.add(fact_key)
            self._record_storage_identity_8616(fact.ins_addr)
            self._count_already_materialized_8616()
            return True
        if fact_key in consumed_facts and _tree_has_global_update_assignment_for_insn_8616(
            self.root, self.project, self.cvar, self.delta, fact.ins_addr
        ):
            self._record_storage_identity_8616(fact.ins_addr)
            self._count_already_materialized_8616()
            if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
                print(
                    f"[dbg-global-update] consumed-fact-present ins={fact.ins_addr:#x} addr={self.addr:#x} name={self.name}",
                    file=sys.stderr,
                    flush=True,
                )
            return True
        if _tree_has_global_update_assignment_for_insn_8616(self.root, self.project, self.cvar, self.delta, fact.ins_addr):
            consumed_facts.add(fact_key)
            self._record_storage_identity_8616(fact.ins_addr)
            self._count_already_materialized_8616()
            if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
                print(
                    f"[dbg-global-update] already-in-tree ins={fact.ins_addr:#x} addr={self.addr:#x} name={self.name}",
                    file=sys.stderr,
                    flush=True,
                )
            return True
        return False

    @cython.ccall
    def _insert_fallback_8616(
        self, fact: DirectGlobalUpdateFact8616, inserted_assignment: StructuredAstValue
    ) -> tuple[cython.bint, StructuredAstValue]:
        """Try loop, tagged-statement, and body-start insertion in order."""
        loop_status = _insert_global_update_in_proven_loop_8616(
            self.root,
            self.project,
            self.function,
            fact.ins_addr,
            inserted_assignment,
            delta=self.delta,
        )
        if loop_status is DirectGlobalLoopInsertionStatus8616.INSERTED:
            self.stats["loop_inserted_count"] = int(self.stats.get("loop_inserted_count", 0) or 0) + 1
            return True, DirectGlobalUpdateMaterializationKind8616.INSERTED_IN_PROVEN_LOOP
        materialized_by = None
        materialized = False
        if loop_status is DirectGlobalLoopInsertionStatus8616.NOT_APPLICABLE:
            materialized = _insert_global_update_before_nearest_following_tagged_statement_8616(
                self.root,
                self.project,
                fact.ins_addr,
                inserted_assignment,
                delta=self.delta,
            )
        if materialized:
            materialized_by = DirectGlobalUpdateMaterializationKind8616.INSERTED_BEFORE_NEXT_TAGGED_STATEMENT
            self.stats["inserted_count"] = int(self.stats.get("inserted_count", 0) or 0) + 1
        elif (
            loop_status is DirectGlobalLoopInsertionStatus8616.NOT_APPLICABLE
            and _direct_global_update_can_insert_at_body_start_8616(self.project, self.function, fact)
        ):
            materialized = _insert_global_update_at_body_start_8616(
                self.root,
                self.project,
                inserted_assignment,
                delta=self.delta,
                ins_addr=fact.ins_addr,
            )
            if materialized:
                materialized_by = DirectGlobalUpdateMaterializationKind8616.INSERTED_AT_BODY_START
                self.stats["body_start_inserted_count"] = int(self.stats.get("body_start_inserted_count", 0) or 0) + 1
        return materialized, materialized_by

    @cython.ccall
    def _fail_materialization_8616(self, fact: DirectGlobalUpdateFact8616) -> None:
        """Count the failure or mark the update as already present."""
        if bool(getattr(self.root, "_inertia_global_update_assignment_already_present_8616", False)):
            self._record_storage_identity_8616(fact.ins_addr)
            self.stats["already_materialized_count"] = int(self.stats.get("already_materialized_count", 0) or 0) + 1
            if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
                print(
                    f"[dbg-global-update] already-present ins={fact.ins_addr:#x} addr={self.addr:#x} name={self.name}",
                    file=sys.stderr,
                    flush=True,
                )
            return
        self.stats["failure_count"] = int(self.stats.get("failure_count", 0) or 0) + 1
        if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
            print(
                "[dbg-global-update] failed-materialize "
                f"ins={fact.ins_addr:#x} addr={self.addr:#x} name={self.name} stats={self.stats!r}",
                file=sys.stderr,
                flush=True,
            )

    @cython.ccall
    def _publish_materialized_8616(
        self, fact: DirectGlobalUpdateFact8616, materialized_by: object
    ) -> None:
        """Record declarations, evidence, and identity for a materialized fact."""
        record_global_declaration_spec_8616(
            self.codegen,
            ctype=ctype_for_global_width_8616(self.width),
            name=self.name,
            array_len=None,
        )
        evidence = _boundary_tuple_8616(getattr(self.codegen, "_inertia_direct_global_update_evidence_8616", ()) or ())
        self.codegen._inertia_direct_global_update_evidence_8616 = tuple(
            dict.fromkeys(
                tuple(evidence) + ((("displacement", self.addr), ("width", self.width), ("delta", self.delta), ("ins_addr", fact.ins_addr), ("name", self.name)),)
            )
        )
        self._record_storage_identity_8616(fact.ins_addr)
        self.stats["materialized_count"] = int(self.stats.get("materialized_count", 0) or 0) + 1
        if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
            print(
                "[dbg-global-update] materialized "
                f"kind={materialized_by.name if materialized_by is not None else None} "
                f"ins={fact.ins_addr:#x} addr={self.addr:#x} name={self.name} stats={self.stats!r}",
                file=sys.stderr,
                flush=True,
            )

    def _materialize_fact_8616(
        self,
        fact: DirectGlobalUpdateFact8616,
        consumed_facts: object,
    ) -> None:
        """Materialize one INC/DEC fact through replace-then-insert ordering."""
        materialized_by: object
        self.cvar = self._build_fact_cvar_8616(fact)
        fact_key = DirectGlobalUpdateFact8616(self.addr, self.width, int(self.delta), int(fact.ins_addr))
        if self._already_materialized_8616(fact, fact_key, consumed_facts):
            return
        self.root._inertia_global_update_assignment_already_present_8616 = False
        materialized = _replace_tagged_assignment_8616(
            self.root,
            self.project,
            fact.ins_addr,
            self._replacement_factory_8616,
            remove_duplicate_tagged_assignments=True,
            already_materialized_predicate=lambda node: (
                _is_same_global_update_assignment_8616(node, self.cvar, self.delta)
            ),
            already_materialized_attr="_inertia_global_update_assignment_already_present_8616",
        )
        materialized_by = (
            DirectGlobalUpdateMaterializationKind8616.REPLACED_TAGGED_ASSIGNMENT if materialized else None
        )
        if materialized:
            self.stats["replaced_count"] = int(self.stats.get("replaced_count", 0) or 0) + 1
        else:
            inserted_assignment = self._replacement_factory_8616({"ins_addr": fact.ins_addr})
            materialized, kind = self._insert_fallback_8616(fact, inserted_assignment)
            if materialized_by is None:
                materialized_by = kind
        if not materialized:
            self._fail_materialization_8616(fact)
            return
        consumed_facts.add(fact_key)
        self._publish_materialized_8616(fact, materialized_by)
        self.changed = True


@cython.ccall
def _resolve_update_function_8616(
    codegen: StructuredAstValue, project: StructuredAstValue, function: object
) -> StructuredAstValue:
    """Resolve the angr function for the active cfunc when not supplied."""
    func_addr: object
    if function is None:
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    return function


@cython.ccall
def _global_update_stats_8616(codegen: StructuredAstValue) -> object:
    """Return the codegen-owned global-update stats bucket, creating it once."""
    stats: object
    stats = getattr(codegen, "_inertia_direct_global_update_lowering_8616", None)
    if not isinstance(stats, dict):
        stats = {
            "raw_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "replaced_count": 0,
            "loop_inserted_count": 0,
            "inserted_count": 0,
            "body_start_inserted_count": 0,
            "already_materialized_count": 0,
            "consumed_fact_count": 0,
            "failure_count": 0,
        }
        codegen._inertia_direct_global_update_lowering_8616 = stats
    return stats


@cython.ccall
def _consumed_global_update_facts_8616(codegen: StructuredAstValue) -> object:
    """Return the codegen-owned consumed-fact set, creating it once."""
    consumed_facts: object
    consumed_facts = getattr(codegen, "_inertia_consumed_direct_global_update_facts_8616", None)
    if not isinstance(consumed_facts, set):
        consumed_facts = set()
        codegen._inertia_consumed_direct_global_update_facts_8616 = consumed_facts
    return consumed_facts


@cython.ccall
def materialize_direct_global_incdec_instructions_8616(
    codegen: StructuredAstValue, project: StructuredAstValue | None = None, function: StructuredAstValue | None = None
) -> cython.bint:
    """Materialize direct no-base/no-index real-mode global INC/DEC effects."""
    root: object
    fact: object
    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-mov] unavailable project=%s root=%s",
                project is not None,
                root is not None,
            )
        return False
    function = _resolve_update_function_8616(codegen, project, function)
    if function is None:
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-mov] function unavailable cfunc_addr=%r",
                getattr(getattr(codegen, "cfunc", None), "addr", None),
            )
        return False

    stats = _global_update_stats_8616(codegen)
    facts = _direct_global_update_instruction_facts_8616(project, function)
    if os.environ.get("INERTIA_DEBUG_GLOBAL_UPDATE") == "1":
        _debug_global_update_insn_dump_8616(codegen, project, function, facts)
    stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + len(facts)
    if not facts:
        return False

    run = _GlobalIncdecRun8616(
        codegen=codegen,
        project=project,
        function=function,
        root=root,
        stats=stats,
    )
    consumed_facts = _consumed_global_update_facts_8616(codegen)
    for fact in facts:
        run._materialize_fact_8616(fact, consumed_facts)

    if run.changed:
        _republish_codegen_root_8616(codegen, root)
    return run.changed


@cython.ccall
def _stack_update_stats_8616(codegen: StructuredAstValue) -> object:
    """Return the codegen-owned stack-update stats bucket, creating it once."""
    stats: object
    stats = getattr(codegen, "_inertia_direct_stack_update_lowering_8616", None)
    if not isinstance(stats, dict):
        stats = {
            "raw_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "failure_count": 0,
            "refused_count": 0,
            "conflicting_tagged_assignment_removed_count": 0,
        }
        codegen._inertia_direct_stack_update_lowering_8616 = stats
    return stats


@cython.dataclasses.dataclass
class _StackIncdecRun8616:
    """Materialize direct BP-relative stack INC/DEC effects at their tagged C node."""

    codegen: StructuredAstValue
    project: StructuredAstValue
    function: StructuredAstValue
    root: StructuredAstValue
    stats: object
    debug_stack_noise: cython.bint
    changed: cython.bint = False
    query_index: StructuredAstValue = None
    fact: StructuredAstValue = None
    width: cython.longlong = 2
    cvar: StructuredAstValue = None
    source_expr: StructuredAstValue = None
    rendered_assignment_ids: object = None

    @cython.ccall
    def _replacement_factory_8616(self, tags: StructuredAstValue) -> StructuredAstValue:
        """Build the stack-update assignment for a tagged node."""
        return _direct_stack_update_assignment_8616(
            self.codegen,
            self.cvar,
            self.width,
            self.fact.delta,
            tags=tags,
            source_expr=self.source_expr,
            operation=self.fact.operation,
        )

    @cython.ccall
    def _has_rendered_owner_8616(self, node: StructuredAstValue) -> cython.bint:
        """Use one ownership index for this mutable replacement attempt."""
        if self.rendered_assignment_ids is None:
            self.rendered_assignment_ids = _rendered_stack_update_assignment_ids_8616(
                self.query_index.nodes
            )
        return id(node) in self.rendered_assignment_ids

    @cython.ccall
    def _already_materialized_predicate_8616(self, node: StructuredAstValue) -> cython.bint:
        return self._has_rendered_owner_8616(node) and _is_same_stack_update_assignment_8616(
            node, self.cvar, self.fact.delta, self.source_expr, operation=self.fact.operation
        )

    def _try_existing_assignment_8616(self, facts: StructuredAstValue) -> cython.bint:
        """Accept an existing equivalent update assignment with matching semantics."""
        semantic_fact_count = sum(
            1
            for candidate in iter(facts)
            if _same_direct_stack_update_semantics_8616(candidate, self.fact)
        )
        materialized = _has_existing_stack_update_assignment_8616(
            self.root,
            self.project,
            self.fact,
            self.cvar,
            self.source_expr,
            expected_semantic_count=semantic_fact_count,
            query_index=self.query_index,
        )
        if self.debug_stack_noise:
            log.warning(
                "[direct-stack-update-path] ins=%#x existing=%s semantic_count=%d",
                self.fact.ins_addr,
                materialized,
                semantic_fact_count,
            )
        return materialized

    @cython.ccall
    def _try_materialize_8616(self, facts: StructuredAstValue) -> tuple[cython.bint, cython.bint]:
        """Run the ordered materialization chain for one fact."""
        self.root._inertia_stack_update_assignment_already_present_8616 = False
        loop_iterator_result = _materialize_proven_stack_update_loop_iterator_8616(
            self.root,
            self.project,
            self.function,
            self.fact,
            self.cvar,
            self.source_expr,
            self._replacement_factory_8616,
            query_index=self.query_index,
        )
        materialized = loop_iterator_result.matched
        fact_changed = loop_iterator_result.changed
        if self.debug_stack_noise:
            log.warning(
                "[direct-stack-update-path] ins=%#x loop_iterator matched=%s changed=%s",
                self.fact.ins_addr,
                loop_iterator_result.matched,
                loop_iterator_result.changed,
            )
        if not materialized:
            materialized = _replace_proven_while_stack_update_8616(
                self.root,
                self.project,
                self.function,
                self.fact,
                self.cvar,
                self._replacement_factory_8616,
                query_index=self.query_index,
            )
            fact_changed = materialized
        if not materialized:
            materialized = self._try_existing_assignment_8616(facts)
        if materialized:
            fact_changed = self._remove_conflicting_8616() or fact_changed
        materialized, fact_changed = self._replacement_chain_8616(materialized, fact_changed)
        return materialized, fact_changed

    @cython.ccall
    def _remove_conflicting_8616(self) -> cython.bint:
        """Drop conflicting tagged duplicates after materialization."""
        removed_count = _remove_conflicting_tagged_stack_update_assignments_8616(
            self.root,
            self.project,
            self.fact,
            query_index=self.query_index,
        )
        self.stats["conflicting_tagged_assignment_removed_count"] = int(
            self.stats.get("conflicting_tagged_assignment_removed_count", 0) or 0
        ) + removed_count
        return removed_count > 0

    @cython.ccall
    def _replacement_chain_8616(self, materialized: cython.bint, fact_changed: cython.bint) -> object:
        """Continue the ordered replacement chain after loop/existing arms."""
        if not materialized and self.fact.operation is DirectStackUpdateOp8616.ARITHMETIC:
            materialized = _replace_stack_update_loop_iterator_8616(
                self.root,
                self.cvar,
                self.width,
                self.fact.delta,
                self._replacement_factory_8616,
                source_expr=self.source_expr,
                query_index=self.query_index,
            )
            fact_changed = materialized
        if not materialized and self.root._inertia_stack_update_assignment_already_present_8616:
            materialized = True
        if not materialized:
            materialized = _replace_tagged_assignment_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self._replacement_factory_8616,
                allow_tagged_iterator_expression=True,
                remove_duplicate_tagged_assignments=True,
                already_materialized_predicate=self._already_materialized_predicate_8616,
                already_materialized_attr="_inertia_stack_update_assignment_already_present_8616",
                candidate_position_predicate=self._has_rendered_owner_8616,
            )
            fact_changed = materialized
        if not materialized:
            materialized = _replace_unique_tagged_dirty_stack_update_8616(
                self.root,
                self.project,
                self.fact,
                self.cvar,
                self._replacement_factory_8616,
                query_index=self.query_index,
            )
            fact_changed = materialized
        if not materialized and self.root._inertia_stack_update_assignment_already_present_8616:
            materialized = True
        return self._insert_chain_8616(materialized, fact_changed)

    @cython.ccall
    def _insert_chain_8616(self, materialized: cython.bint, fact_changed: cython.bint) -> tuple[cython.bint, cython.bint]:
        """Run the insertion arms for arithmetic facts that did not replace."""
        if not materialized and self.fact.operation is DirectStackUpdateOp8616.ARITHMETIC:
            inserted_assignment = self._replacement_factory_8616({"ins_addr": self.fact.ins_addr})
            materialized = _insert_at_loop_body_start_after_condition_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                inserted_assignment,
            )
            fact_changed = materialized
        if not materialized and self.fact.operation is DirectStackUpdateOp8616.ARITHMETIC:
            inserted_assignment = self._replacement_factory_8616({"ins_addr": self.fact.ins_addr})
            materialized = _insert_before_nearest_following_tagged_statement_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                inserted_assignment,
            )
            fact_changed = materialized
        elif not materialized:
            self.stats["refused_count"] = int(self.stats.get("refused_count", 0) or 0) + 1
        return materialized, fact_changed

    @cython.ccall
    def _record_materialized_8616(self) -> None:
        """Publish the materialization evidence entry for one fact."""
        self.stats["materialized_count"] = int(self.stats.get("materialized_count", 0) or 0) + 1
        evidence = _boundary_tuple_8616(getattr(self.codegen, "_inertia_direct_stack_update_evidence_8616", ()) or ())
        fact = self.fact
        self.codegen._inertia_direct_stack_update_evidence_8616 = _boundary_tuple_8616(
            dict.fromkeys(
                tuple(evidence) + ((("offset", fact.offset), ("width", self.width), ("delta", fact.delta), ("source_kind", fact.source_kind), ("source_value", fact.source_value), ("source_offset", fact.source_offset), ("source_base_offset", fact.source_base_offset), ("source_index_offset", fact.source_index_offset), ("source_index_scale", fact.source_index_scale), ("operation", fact.operation), ("ins_addr", fact.ins_addr), ("name", getattr(getattr(self.cvar, "variable", None), "name", None))),)
            )
        )

    @cython.ccall
    def materialize_fact_8616(self, fact: StructuredAstValue, facts: StructuredAstValue) -> None:
        """Materialize one stack-update fact, tracking per-fact change."""
        self.fact = fact
        self.rendered_assignment_ids = None
        if self.debug_stack_noise:
            log.warning(
                "[direct-stack-update] fact ins=%#x offset=%s delta=%s op=%s",
                fact.ins_addr,
                fact.offset,
                fact.delta,
                fact.operation.name,
            )
        self.width = fact.width if fact.width in {1, 2} else 2
        self.stats["classified_fact_count"] = int(self.stats.get("classified_fact_count", 0) or 0) + 1
        self.cvar = _resolve_direct_stack_update_cvar_8616(self.codegen, fact.offset, self.width)
        self.source_expr = _direct_stack_update_source_expr_8616(self.codegen, fact)
        if self.cvar is None or self.source_expr is None:
            self.stats["failure_count"] = int(self.stats.get("failure_count", 0) or 0) + 1
            return
        materialized, fact_changed = self._try_materialize_8616(facts)
        if not materialized:
            if self.root._inertia_stack_update_assignment_already_present_8616:
                return
            self.stats["failure_count"] = int(self.stats.get("failure_count", 0) or 0) + 1
            return
        self._record_materialized_8616()
        self.changed = fact_changed or self.changed
        if fact_changed:
            self.query_index = StructuredAstQueryIndex8616.build(self.root)


@cython.ccall
def _filtered_stack_update_facts_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    function: StructuredAstValue,
    stats: object,
    debug_stack_noise: cython.bint,
    root: StructuredAstValue,
) -> StructuredAstValue:
    """Collect the stack-update facts filtered for the active function."""
    if debug_stack_noise:
        log.warning(
            "[direct-stack-update] start function=%#x root=%s",
            getattr(function, "addr", -1) or -1,
            type(root).__name__,
        )
    facts = _filter_direct_stack_update_facts_for_active_function_8616(
        project,
        function,
        _direct_stack_update_instruction_facts_8616(project, function),
    )
    stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + len(facts)
    return facts


@cython.ccall
def materialize_direct_stack_incdec_instructions_8616(
    codegen: StructuredAstValue, project: StructuredAstValue | None = None, function: StructuredAstValue | None = None
) -> cython.bint:
    """Materialize direct BP-relative stack INC/DEC effects at their tagged C node."""
    root: object
    fact: object
    debug_stack_noise = bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))
    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        if debug_stack_noise:
            log.warning("[direct-stack-update] unavailable project_or_root changed=False")
        return False
    function = _resolve_update_function_8616(codegen, project, function)
    if function is None:
        if debug_stack_noise:
            log.warning("[direct-stack-update] unavailable function changed=False")
        return False

    stats = _stack_update_stats_8616(codegen)
    facts = _filtered_stack_update_facts_8616(codegen, project, function, stats, debug_stack_noise, root)
    if not facts:
        if debug_stack_noise:
            log.warning(
                "[direct-stack-update] function=%#x facts=0 changed=False stats=%r",
                getattr(function, "addr", -1) or -1,
                stats,
            )
        _record_direct_stack_update_lane_8616(codegen, stats)
        return False

    run = _StackIncdecRun8616(
        codegen=codegen,
        project=project,
        function=function,
        root=root,
        stats=stats,
        debug_stack_noise=debug_stack_noise,
        query_index=StructuredAstQueryIndex8616.build(root),
    )
    for fact in facts:
        run.materialize_fact_8616(fact, facts)

    if run.changed:
        with contextlib.suppress(Exception):
            codegen.cfunc.body = root
        with contextlib.suppress(Exception):
            codegen.cfunc.statements = root
        with contextlib.suppress(Exception):
            codegen.cfunc.stmt = root
    _record_direct_stack_update_lane_8616(codegen, stats)
    return run.changed


def materialize_direct_stack_mov_instructions_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue | None = None,
    function: StructuredAstValue | None = None,
    *,
    allow_stack_slot_fallback: cython.bint = True,
    source_kinds: object = None,
    materialize_reloads: cython.bint = True,
) -> cython.bint:
    """Execute direct stack MOV lowering through its exact replay contract."""
    options = DirectStackReplayOptions8616(
        allow_stack_slot_fallback=allow_stack_slot_fallback,
        source_kind_values=(
            None
            if source_kinds is None
            else tuple(sorted(source_kind.value for source_kind in iter(source_kinds)))
        ),
        materialize_reloads=materialize_reloads,
    )
    return bool(
        execute_direct_stack_replay_8616(
            codegen,
            project,
            function,
            options,
            lambda resolved_function: DirectStackMaterializationResult8616(
                changed=_materialize_direct_stack_mov_instructions_impl_8616(
                    codegen,
                    project=project,
                    function=resolved_function,
                    allow_stack_slot_fallback=allow_stack_slot_fallback,
                    source_kinds=source_kinds,
                    materialize_reloads=materialize_reloads,
                )
            ),
        )
    )


@cython.dataclasses.dataclass
class _DirectStackReloadFrame8616:
    """Shared per-pass state for register-reload materialization."""

    register_use_missing: object = field(default_factory=set)
    query_index: StructuredAstValue = None
    candidate_index: StructuredAstValue = None
    register_names: frozenset[str] = frozenset()
    timers: object = field(
        default_factory=lambda: {
            "tagged_reload_match": 0.0,
            "register_use_insert": 0.0,
            "visible_guard": 0.0,
        }
    )


@cython.dataclasses.dataclass
class _DirectStackMovRun8616:
    """One direct-stack-MOV materialization pass over a structured function.

    Per-fact state lives on ``self`` and follows the original flat block
    scope: values assigned by one iteration remain visible to the next,
    exactly as loop-body locals did before the split.
    """

    codegen: StructuredAstValue
    project: StructuredAstValue
    function: StructuredAstValue
    root: StructuredAstValue
    stats: object
    debug_stack_noise: cython.bint
    facts: object
    allow_stack_slot_fallback: cython.bint
    materialize_reloads: cython.bint
    allow_unscoped_fallback_insert: cython.bint
    signed_idiv_remainder_fact_count: cython.longlong
    materialized_fact_keys: object
    materialized_facts: object
    source_expr_by_store_ins_addr: object
    changed: cython.bint = False
    lane_stats_before: object = field(default_factory=dict)
    timers: object = field(default_factory=dict)
    # Per-fact frame fields (assigned each iteration; not reset).
    fact: DirectStackMoveFact8616 | None = None
    fact_key: StructuredAstValue = None
    indexed_destination: cython.bint = False
    dst_cvar: StructuredAstValue = None
    dst_expr: StructuredAstValue = None
    source_expr: StructuredAstValue = None
    authoritative_wide_materialized: cython.bint = False
    materialized: cython.bint = False
    idiv_visible_guard_inserted: cython.bint = False
    inverse_pruned: StructuredAstValue = None
    call_statement_source_expr: StructuredAstValue = None
    call_order_reconciled: StructuredAstValue = None
    carrier_pruned: StructuredAstValue = None
    decomposition_pruned: StructuredAstValue = None
    current_type: StructuredAstValue = None
    dst_variable: StructuredAstValue = None
    fallback_assignment: StructuredAstValue = None
    relocated_assignment: StructuredAstValue = None
    relocated_count: cython.longlong = 0
    replay_pruned: StructuredAstValue = None
    source_type: StructuredAstValue = None
    tags: StructuredAstValue = None
    unified: StructuredAstValue = None
    visible_assignment: StructuredAstValue = None
    auxiliary_insert_count: cython.longlong = 0
    signed_idiv_assignment_present: cython.bint = False
    projected_segmented_source_present: cython.bint = False
    idiv_call_statement_materialized: cython.bint = False

    def _fact_begin_8616(self) -> cython.bint:
        """Prepare destination/source expressions for one direct-stack-MOV fact."""
        assert self.fact is not None
        self.root._inertia_stack_mov_assignment_already_present_8616 = False
        self.fact_key = _direct_stack_move_fact_key_8616(self.fact)
        self.indexed_destination = any(
            isinstance(index, int)
            for index in iter((
                self.fact.dst_index_global_displacement,
                self.fact.dst_index_stack_offset,
                self.fact.dst_index_immediate,
            ))
        )
        self.dst_cvar = (
            _resolve_existing_direct_stack_owner_cvar_8616(
                self.codegen,
                self.fact.dst_offset,
                self.fact.width,
                require_wider_owner=True,
            )
            if self.indexed_destination
            else None
        )
        if self.dst_cvar is None:
            self.dst_cvar = _resolve_direct_stack_update_cvar_8616(self.codegen, self.fact.dst_offset, self.fact.width)
        self.dst_expr = (
            _direct_stack_move_destination_expr_8616(self.codegen, self.fact, self.dst_cvar) if self.dst_cvar is not None else None
        )
        self.source_expr = _direct_stack_move_source_expr_8616(self.codegen, self.fact, self.dst_cvar)
        if self.dst_cvar is None or self.dst_expr is None or self.source_expr is None:
            self.stats["failure_count"] = int(self.stats.get("failure_count", 0) or 0) + 1
            return True
        self.authoritative_wide_materialized = False
        return False

    def _fact_wide_call_return_arm_8616(self) -> cython.bint:
        """Materialize the authoritative wide call-return stack-arith arm."""
        assert self.fact is not None
        if self.fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH:
            required_addresses = (
                self.fact.source_call_target,
                self.fact.source_call_ins_addr,
                self.fact.source_low_arith_ins_addr,
                self.fact.source_high_arith_ins_addr,
                self.fact.dst_high_ins_addr,
                self.fact.source_offset,
            )
            if not all(isinstance(address, int) for address in iter(required_addresses)):
                self.stats["failure_count"] = int(self.stats.get("failure_count", 0) or 0) + 1
                return True
            ownership = classify_authoritative_wide_call_output_projection_8616(

                self.codegen,
                callsite_addr=cast(int, self.fact.source_call_ins_addr),
                target_addr=cast(int, self.fact.source_call_target),
                kind=CarryBorrowKind8616.ADD_WITH_CARRY,
                source_offset=cast(int, self.fact.source_offset),
                destination_offset=self.fact.dst_offset,
                low_arithmetic_addr=cast(int, self.fact.source_low_arith_ins_addr),
                high_arithmetic_addr=cast(int, self.fact.source_high_arith_ins_addr),
                low_store_addr=self.fact.ins_addr,
                high_store_addr=cast(int, self.fact.dst_high_ins_addr),
            )
            if ownership.blocks_legacy_materialization:
                if not ownership.materialized:
                    self.stats["failure_count"] = int(self.stats.get("failure_count", 0) or 0) + 1
                    return True
                self.stats["authoritative_wide_owner_count"] = (
                    int(self.stats.get("authoritative_wide_owner_count", 0) or 0) + 1
                )
                self.authoritative_wide_materialized = True
        return False

    @cython.ccall
    def _stack_slot_type_rebind_allowed_8616(self) -> cython.bint:
        """Shared width/destination gate for short-signed stack-slot type rebinding."""
        assert self.fact is not None
        return (
            self.fact.width == 2
            and isinstance(self.dst_expr, structured_c.CVariable)
            and _prototype_arg_type_for_bp_offset_8616(self.codegen, self.fact.dst_offset) is None
        )

    @cython.ccall
    def _fact_stack_slot_sub_type_rebind_8616(self) -> None:
        """Rebind short-signed types for proven stack-slot subtraction stores."""
        assert self.fact is not None
        if (
            self.fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR
            and self.fact.source_op is DirectStackMoveExpressionOp8616.SUB
            and self.fact.source_offset is not None
            and self._stack_slot_type_rebind_allowed_8616()
        ):
            self.source_type = _prototype_arg_type_for_bp_offset_8616(self.codegen, self.fact.source_offset)
            if isinstance(self.source_type, SimTypeShort) and bool(self.source_type.signed):
                self.source_type = _bind_type_to_codegen_arch_8616(self.codegen, self.source_type)
                if isinstance(self.source_expr, structured_c.CVariable):
                    self.source_expr.variable_type = self.source_type
                self.dst_expr.variable_type = self.source_type
            self.current_type = self.dst_expr.variable_type
            if not isinstance(self.current_type, SimTypeShort) or not bool(self.current_type.signed):
                self.dst_expr.variable_type = _bind_type_to_codegen_arch_8616(self.codegen, SimTypeShort(True))
                self.unified = getattr(getattr(self.codegen, "cfunc", None), "unified_local_vars", None)
                if isinstance(self.unified, dict):
                    self.dst_variable = self.dst_expr.variable
                    if self.dst_variable is not None:
                        self.unified[self.dst_variable] = {(self.dst_expr, self.dst_expr.variable_type)}

    @cython.ccall
    def _fact_stack_slot_type_rebind_8616(self) -> None:
        """Rebind short-signed types for proven stack-slot stores."""
        assert self.fact is not None
        if (
            self.fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT
            and self._stack_slot_type_rebind_allowed_8616()
            and self.fact.source_offset is not None
            and self.fact.source_offset > 2
        ):
            self.source_type = _prototype_arg_type_for_bp_offset_8616(self.codegen, self.fact.source_offset)
            if isinstance(self.source_type, SimTypeShort) and bool(self.source_type.signed):
                self.source_type = _bind_type_to_codegen_arch_8616(self.codegen, self.source_type)
                if isinstance(self.source_expr, structured_c.CVariable):
                    self.source_expr.variable_type = self.source_type
                self.current_type = self.dst_expr.variable_type
                if not isinstance(self.current_type, SimTypeShort) or not bool(self.current_type.signed):
                    self.dst_expr.variable_type = self.source_type
                self.unified = getattr(getattr(self.codegen, "cfunc", None), "unified_local_vars", None)
                if isinstance(self.unified, dict):
                    self.dst_variable = self.dst_expr.variable
                    if self.dst_variable is not None:
                        self.unified[self.dst_variable] = {(self.dst_expr, self.dst_expr.variable_type)}

    @cython.ccall
    def _fact_inverse_prune_8616(self) -> None:
        """Prune inverse stack-move artifacts produced by this definition."""
        assert self.fact is not None
        self.inverse_pruned = _prune_inverse_stack_move_artifacts_8616(self.root, self.facts, self.fact, self.dst_cvar, self.source_expr)
        if self.inverse_pruned:
            self.stats["inverse_artifact_pruned_count"] = (
                int(self.stats.get("inverse_artifact_pruned_count", 0) or 0) + self.inverse_pruned
            )
            self.changed = True

    @cython.ccall
    def _fact_already_materialized_8616(self) -> cython.bint:
        """Skip or reconcile facts whose materialized form is already present."""
        if not (self.fact_key in self.materialized_fact_keys and not self.authoritative_wide_materialized):
            return False
        if self._fact_zero_arg_call_return_arm_8616():
            return True
        if self._fact_wide_return_reconcile_8616():
            return True
        if self._fact_signed_idiv_reconcile_8616():
            return True
        self._fact_replay_reconcile_8616()
        self._fact_semantic_cast_reconcile_8616()
        if self._fact_stale_evidence_recheck_8616():
            return True
        self.stats["stale_evidence_rematerialized_count"] = (
            int(self.stats.get("stale_evidence_rematerialized_count", 0) or 0) + 1
        )
        return False

    @cython.ccall
    def _fact_zero_arg_call_return_arm_8616(self) -> cython.bint:
        """Consume a zero-arg call-return fact already present in the tree."""
        assert self.fact is not None
        if (
            self.fact.source_kind
            is DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN
            and _tree_has_zero_arg_call_return_assignment_8616(
                self.root,
                self.project,
                self.fact,
                self.dst_cvar,
            )
        ):
            self.stats["already_materialized_count"] = (
                int(self.stats.get("already_materialized_count", 0) or 0) + 1
            )
            self.materialized_facts.append(self.fact)
            self.source_expr_by_store_ins_addr[int(self.fact.ins_addr)] = self.source_expr
            return True
        return False

    @cython.ccall
    def _fact_wide_return_reconcile_8616(self) -> cython.bint:
        """Reconcile an already-materialized wide call-return assignment."""
        assert self.fact is not None
        if self.fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH:
            reconciled, self.replay_pruned = _reconcile_materialized_wide_call_return_assignment_8616(
                self.root,
                self.project,
                self.fact,
                self.dst_cvar,
            )
            if reconciled:
                self.stats["already_materialized_count"] = (
                    int(self.stats.get("already_materialized_count", 0) or 0) + 1
                )
                if self.replay_pruned:
                    self.stats["wide_call_replay_pruned_count"] = (
                        int(self.stats.get("wide_call_replay_pruned_count", 0) or 0)
                        + self.replay_pruned
                    )
                    self.changed = True
                self.materialized_facts.append(self.fact)
                self.source_expr_by_store_ins_addr[int(self.fact.ins_addr)] = self.source_expr
                return True
        return False

    @cython.ccall
    def _fact_signed_idiv_reconcile_8616(self) -> cython.bint:
        """Reconcile an already-materialized signed-idiv call order."""
        assert self.fact is not None
        if self.fact.source_kind is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER:
            self.call_order_reconciled, self.replay_pruned = (
                _reconcile_materialized_signed_idiv_call_order_8616(
                    self.root,
                    self.project,
                    self.codegen,
                    self.fact,
                    self.dst_cvar,
                )
            )
            if self.call_order_reconciled:
                self.stats["idiv_call_statement_materialized_count"] = (
                    int(
                        self.stats.get(
                            "idiv_call_statement_materialized_count",
                            0,
                        )
                        or 0
                    )
                    + 1
                )
                if self.replay_pruned:
                    self.stats["idiv_duplicate_store_pruned_count"] = (
                        int(
                            self.stats.get(
                                "idiv_duplicate_store_pruned_count",
                                0,
                            )
                            or 0
                        )
                        + self.replay_pruned
                    )
                self.changed = True
        return False

    @cython.ccall
    def _fact_replay_reconcile_8616(self) -> None:
        """Decide whether to replay reconciliation for idiv or segmented sources."""
        assert self.fact is not None
        self.signed_idiv_assignment_present = _tree_has_materialized_signed_idiv_remainder_8616(
            self.root,
            self.fact,
            self.dst_cvar,
        )
        self.projected_segmented_source_present = bool(
            self.fact.source_kind is DirectStackMoveSourceKind8616.SEGMENTED_MEMORY
            and self.fact.source_segment_name == "ds"
            and isinstance(self.fact.source_displacement, int)
            and isinstance(self.fact.source_index_offset, int)
            and isinstance(self.fact.source_index_shift, int)
            and isinstance(self.fact.source_access_width, int)
            and projected_segmented_stack_assignment_present_8616(
                self.codegen,
                self.root,
                SegmentedStackSourceProjection8616(
                    instruction_addr=self.fact.ins_addr,
                    destination_machine_bp_offset=self.fact.dst_offset,
                    destination_width=self.fact.width,
                    source_displacement=self.fact.source_displacement,
                    source_index_machine_bp_offset=self.fact.source_index_offset,
                    source_index_byte_scale=1 << self.fact.source_index_shift,
                    source_access_width=self.fact.source_access_width,
                ),
            )
        )
        replay_reconciled = False
        if not self.signed_idiv_assignment_present and not self.projected_segmented_source_present:
            replay_reconciled = _replace_tagged_statement_assignment_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.replacement_factory_8616,
                remove_duplicate_tagged_assignments=True,
            )
        if replay_reconciled:
            self.stats["stale_evidence_rematerialized_count"] = (
                int(self.stats.get("stale_evidence_rematerialized_count", 0) or 0) + 1
            )
            self.changed = True

    def _fact_semantic_cast_reconcile_8616(self) -> None:
        """Reconcile semantic-cast sources with their materialized forms."""
        assert self.fact is not None
        if isinstance(self.source_expr, CSemanticCast8616):
            cast_result = reconcile_required_assignment_cast_8616(
                self.root,
                self.replacement_factory_8616({"ins_addr": self.fact.ins_addr}),
                same_destination=_same_stack_cvar_8616,
                same_source=lambda actual, expected: (
                    _same_stack_move_rhs_8616(actual, expected)
                    or _same_stack_low_half_cvar_8616(expected, actual)
                ),
            )
            self.stats["semantic_cast_candidate_count"] = (
                int(self.stats.get("semantic_cast_candidate_count", 0) or 0)
                + cast_result.candidate_count
            )
            self.stats["semantic_cast_assignment_count"] = (
                int(self.stats.get("semantic_cast_assignment_count", 0) or 0)
                + cast_result.assignment_count
            )
            self.stats["semantic_cast_destination_count"] = (
                int(self.stats.get("semantic_cast_destination_count", 0) or 0)
                + cast_result.destination_count
            )
            if cast_result.changed:
                self.stats["semantic_cast_reconciled_count"] = (
                    int(self.stats.get("semantic_cast_reconciled_count", 0) or 0)
                    + 1
                )
                self.changed = True
            elif (
                cast_result.status
                is RequiredAssignmentCastReconcileStatus8616.ALREADY_PRESENT
            ):
                self.stats["semantic_cast_already_present_count"] = (
                    int(
                        self.stats.get(
                            "semantic_cast_already_present_count",
                            0,
                        )
                        or 0
                    )
                    + 1
                )
            elif (
                cast_result.status
                is RequiredAssignmentCastReconcileStatus8616.AMBIGUOUS
            ):
                self.stats["semantic_cast_ambiguous_count"] = (
                    int(self.stats.get("semantic_cast_ambiguous_count", 0) or 0)
                    + 1
                )
            elif (
                cast_result.status
                is RequiredAssignmentCastReconcileStatus8616.NO_MATCH
            ):
                self.stats["semantic_cast_no_match_count"] = (
                    int(self.stats.get("semantic_cast_no_match_count", 0) or 0)
                    + 1
                )

    @cython.ccall
    def _fact_stale_evidence_recheck_8616(self) -> cython.bint:
        """Recheck stale evidence and rematerialize when the write vanished."""
        assert self.fact is not None
        if _tree_has_stack_move_assignment_8616(
            self.root,
            self.dst_expr,
            self.source_expr,
        ) or self.signed_idiv_assignment_present or self.projected_segmented_source_present:
            if (
                self.fact.source_kind
                is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
            ):
                self.auxiliary_insert_count = (
                    _prune_signed_idiv_auxiliary_insert_8616(
                        self.root,
                        self.project,
                        self.fact,
                    )
                )
                if self.auxiliary_insert_count:
                    self.stats["idiv_auxiliary_insert_pruned_count"] = (
                        int(
                            self.stats.get(
                                "idiv_auxiliary_insert_pruned_count",
                                0,
                            )
                            or 0
                        )
                        + self.auxiliary_insert_count
                    )
                    self.changed = True
            if self.fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH:
                self.carrier_pruned = _prune_wide_call_return_carriers_8616(
                    self.root,
                    self.project,
                    self.fact,
                    self.dst_cvar,
                )
                if self.carrier_pruned:
                    self.stats["wide_call_carrier_pruned_count"] = (
                        int(self.stats.get("wide_call_carrier_pruned_count", 0) or 0) + self.carrier_pruned
                    )
                    self.changed = True
                self.decomposition_pruned = _prune_wide_call_return_decomposition_8616(
                    self.root,
                    self.project,
                    self.fact,
                )
                if self.decomposition_pruned:
                    self.stats["wide_call_decomposition_pruned_count"] = (
                        int(self.stats.get("wide_call_decomposition_pruned_count", 0) or 0)
                        + self.decomposition_pruned
                    )
                    self.changed = True
            if (
                self.fact.source_kind is DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT
                and _restore_same_block_stack_move_order_8616(
                    self.root,
                    self.codegen,
                    self.project,
                    self.function,
                    self.fact,
                    self.dst_expr,
                    self.source_expr,
                )
            ):
                self.stats["same_block_stack_move_order_restored_count"] = (
                    int(self.stats.get("same_block_stack_move_order_restored_count", 0) or 0) + 1
                )
                self.changed = True
            self.stats["already_materialized_count"] = int(self.stats.get("already_materialized_count", 0) or 0) + 1
            self.materialized_facts.append(self.fact)
            self.source_expr_by_store_ins_addr[int(self.fact.ins_addr)] = self.source_expr
            return True
        return False

    @cython.ccall
    def _fact_classified_8616(self) -> None:
        """Record the fact as classified and seed materialization state."""
        self.stats["classified_fact_count"] = int(self.stats.get("classified_fact_count", 0) or 0) + 1
        self.materialized = self.authoritative_wide_materialized

        self.idiv_visible_guard_inserted = False

    @cython.ccall
    def _fact_stack_slot_expr_arm_8616(self) -> None:
        """Materialize STACK_SLOT_EXPR facts into structured stack stores."""
        call_assignment: object
        placement_service: object
        assert self.fact is not None
        if self.fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_EXPR:
            if self.allow_stack_slot_fallback:
                self.visible_assignment = _direct_stack_move_assignment_8616(
                    self.codegen,
                    self.dst_cvar,
                    self.source_expr,
                    tags={"ins_addr": self.fact.ins_addr},
                )
                placement_service = getattr(
                    self.codegen,
                    "_inertia_direct_stack_move_branch_placement_service_8616",
                    None,
                )
                if callable(placement_service):
                    self.materialized = bool(placement_service(self.fact, self.visible_assignment))
                if (
                    not self.materialized
                    and _direct_stack_move_is_before_known_precontrol_8616(
                        self.root,
                        self.project,
                        self.function,
                        self.fact.ins_addr,
                    )
                ):
                    self.materialized = _replace_precontrol_stack_assignment_8616(
                        self.root,
                        self.dst_cvar,
                        self.visible_assignment,
                        insert_before_control_when_no_match=True,
                    )
                if not self.materialized and _insert_before_first_stack_cvar_use_8616(
                    self.root,
                    self.visible_assignment,
                    prefer_outer_control_read=True,
                ):
                    self.materialized = True
                    self.changed = True
            self.materialized = (
                _replace_tagged_statement_assignment_8616(
                    self.root,
                    self.project,
                    self.fact.ins_addr,
                    self.replacement_factory_8616,
                )
                or self.materialized
            )
        elif self.fact.source_kind in {
            DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN,
            DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH,
        }:
            # A call-return stack store consumes the call carrier. Generic
            # replacement would retain that carrier and duplicate the call.
            if not self.materialized:
                call_assignment = _replace_tagged_call_statement_with_stack_assignment_8616(
                    self.root,
                    self.project,
                    self.fact.source_call_ins_addr,
                    self.fact.source_call_name,
                    self.replacement_factory_8616,
                    call_target=self.fact.source_call_target,
                )
                self.materialized = call_assignment is not None
                if self.materialized:
                    counter = (
                        "zero_arg_call_return_statement_materialized_count"
                        if self.fact.source_kind is DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN
                        else "wide_call_statement_materialized_count"
                    )
                    self.stats[counter] = int(self.stats.get(counter, 0) or 0) + 1
                    self.changed = True
        else:
            self.visible_assignment = self.replacement_factory_8616({"ins_addr": self.fact.ins_addr})
            placement_service = getattr(
                self.codegen,
                "_inertia_direct_stack_move_branch_placement_service_8616",
                None,
            )
            self.materialized = bool(
                callable(placement_service)
                and placement_service(self.fact, self.visible_assignment)
            )
            tagged_materialized = (
                False
                if self.materialized
                else _replace_tagged_statement_assignment_8616(
                    self.root,
                    self.project,
                    self.fact.ins_addr,
                    self.replacement_factory_8616,
                    remove_duplicate_tagged_assignments=True,
                )
            )
            self.materialized = tagged_materialized or self.materialized
            if (
                tagged_materialized
                and self.fact.source_kind
                in {
                    DirectStackMoveSourceKind8616.STACK_SLOT,
                    DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
                }
                and _insert_into_conditional_branch_for_direct_stack_move_8616(
                    self.root,
                    self.project,
                    self.function,
                    self.fact.ins_addr,
                    self.replacement_factory_8616({"ins_addr": self.fact.ins_addr}),
                    relocate_tagged_assignment=True,
                )
            ):
                self.stats["conditional_branch_relocated_count"] = (
                    int(self.stats.get("conditional_branch_relocated_count", 0) or 0) + 1
                )
                self.changed = True

    @cython.ccall
    def _fact_signed_idiv_arm_8616(self) -> cython.bint:
        """Materialize SIGNED_IDIV_REMAINDER facts with call-statement bridging."""
        assert self.fact is not None
        if self.fact.source_kind is not DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER:
            return False
        self.call_statement_source_expr = self.source_expr
        if not _expr_contains_function_call_8616(self.call_statement_source_expr):
            self.call_statement_source_expr = _direct_stack_move_source_expr_8616(
                self.codegen,
                self.fact,
                self.dst_cvar,
                reuse_call_result=False,
            )
        self.idiv_call_statement_materialized = False
        self._idiv_call_statement_materialize_8616()
        self._idiv_direct_materialize_8616()
        self._idiv_guard_or_recheck_8616()
        self._idiv_artifact_tail_8616()
        self._idiv_finalize_8616()
        return False

    @cython.ccall
    def _idiv_call_statement_materialize_8616(self) -> None:
        """Bridge the signed-idiv call statement into a stack assignment."""
        idiv_call_assignment: object
        assert self.fact is not None
        if self.call_statement_source_expr is not None and _expr_contains_function_call_8616(self.call_statement_source_expr):
            idiv_call_assignment = _replace_tagged_call_statement_with_stack_assignment_8616(
                self.root,
                self.project,
                self.fact.source_call_ins_addr,
                self.fact.source_call_name,
                self.call_statement_replacement_factory_8616,
                call_target=self.fact.source_call_target,
            )
            self.idiv_call_statement_materialized = idiv_call_assignment is not None
            if self.idiv_call_statement_materialized:
                self.stats["idiv_call_statement_materialized_count"] = (
                    int(self.stats.get("idiv_call_statement_materialized_count", 0) or 0) + 1
                )
                duplicate_store_count = (
                    _remove_consumed_signed_idiv_store_assignments_8616(
                        self.root,
                        self.project,
                        self.fact,
                        self.dst_cvar,
                        idiv_call_assignment,
                    )
                )
                duplicate_store_count += _remove_duplicate_stack_move_assignments_8616(
                    self.root,
                    self.project,
                    self.fact.ins_addr,
                    self.dst_cvar,
                    self.call_statement_source_expr,
                    idiv_call_assignment,
                )
                if duplicate_store_count:
                    self.stats["idiv_duplicate_store_pruned_count"] = (
                        int(self.stats.get("idiv_duplicate_store_pruned_count", 0) or 0)
                        + duplicate_store_count
                    )
                self.materialized = True
                self.changed = True

    @cython.ccall
    def _idiv_direct_materialize_8616(self) -> None:
        """Materialize the signed-idiv remainder when no call statement was bridged."""
        artifact_materialized: object
        if not self.idiv_call_statement_materialized:
            artifact_materialized = _replace_signed_idiv_remainder_artifact_assignment_8616(
                self.root,
                self.dst_cvar,
                self.replacement_factory_8616,
                allow_unique_stack_lhs_bridge=self.signed_idiv_remainder_fact_count == 1,
            )
            if artifact_materialized is not None:
                self.stats["idiv_artifact_materialized_count"] = (
                    int(self.stats.get("idiv_artifact_materialized_count", 0) or 0) + 1
                )
                if (
                    artifact_materialized
                    is DirectStackMoveArtifactReplacementKind8616.UNIQUE_SIGNED_IDIV_STACK_ARTIFACT
                ):
                    self.stats["idiv_artifact_stack_lhs_bridge_count"] = (
                        int(self.stats.get("idiv_artifact_stack_lhs_bridge_count", 0) or 0) + 1
                    )
                self.materialized = True

    @cython.ccall
    def _idiv_guard_or_recheck_8616(self) -> None:
        """Apply the visible-guard placement for the signed-idiv remainder."""
        assert self.fact is not None
        if not self.materialized:
            self.visible_assignment = _direct_stack_move_assignment_8616(
                self.codegen,
                self.dst_cvar,
                self.source_expr,
                tags={"ins_addr": self.fact.ins_addr},
            )
            if _insert_before_first_stack_cvar_use_8616(
                self.root,
                self.visible_assignment,
                ignore_existing_assignment=True,
            ):
                self.stats["idiv_remainder_visible_use_guard_count"] = (
                    int(self.stats.get("idiv_remainder_visible_use_guard_count", 0) or 0) + 1
                )
                self.idiv_visible_guard_inserted = True
                self.materialized = True
                self.changed = True

    @cython.ccall
    def _idiv_artifact_tail_8616(self) -> None:
        """Record signed-idiv artifact counters for the materialization arm."""
        assert self.fact is not None
        if (
            self.materialized
            and not self.idiv_visible_guard_inserted
            and not self.idiv_call_statement_materialized
            and not _expr_contains_function_call_8616(self.source_expr)
        ):
            self.visible_assignment = _direct_stack_move_assignment_8616(
                self.codegen,
                self.dst_cvar,
                self.source_expr,
                tags={"ins_addr": self.fact.ins_addr},
            )
            if _insert_before_first_stack_cvar_use_8616(
                self.root,
                self.visible_assignment,
                ignore_existing_assignment=True,
            ):
                self.stats["idiv_remainder_visible_use_guard_count"] = (
                    int(self.stats.get("idiv_remainder_visible_use_guard_count", 0) or 0) + 1
                )
                self.changed = True

    @cython.ccall
    def _idiv_finalize_8616(self) -> None:
        """Finalize the signed-idiv arm bookkeeping."""
        assert self.fact is not None
        if self.materialized:
            self.auxiliary_insert_count = _prune_signed_idiv_auxiliary_insert_8616(
                self.root,
                self.project,
                self.fact,
            )
            if self.auxiliary_insert_count:
                self.stats["idiv_auxiliary_insert_pruned_count"] = (
                    int(self.stats.get("idiv_auxiliary_insert_pruned_count", 0) or 0)
                    + self.auxiliary_insert_count
                )
                self.changed = True

    @cython.ccall
    def _fact_generic_materialize_8616(self) -> cython.bint:
        """Materialize facts that still need a direct assignment."""
        if not self.materialized:
            if self._fact_reconcile_existing_assignment_8616():
                return True
            self._fact_tagged_fallback_gate_8616()
            self._fact_immediate_source_arm_8616()
            self._fact_kind_fallback_chain_8616()
        return False

    @cython.ccall
    def _fact_reconcile_existing_assignment_8616(self) -> cython.bint:
        """Consume a fact whose stack-move assignment already exists in the tree."""
        assert self.fact is not None
        if _tree_has_stack_move_assignment_8616(self.root, self.dst_expr, self.source_expr) or (
            self.fact.source_kind
            is DirectStackMoveSourceKind8616.ZERO_ARG_CALL_RETURN
            and _tree_has_zero_arg_call_return_assignment_8616(
                self.root,
                self.project,
                self.fact,
                self.dst_cvar,
            )
        ):
            if self.fact.source_kind is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER:
                self.call_order_reconciled, self.replay_pruned = (
                    _reconcile_materialized_signed_idiv_call_order_8616(
                        self.root,
                        self.project,
                        self.codegen,
                        self.fact,
                        self.dst_cvar,
                    )
                )
                if self.call_order_reconciled:
                    self.stats["idiv_call_statement_materialized_count"] = (
                        int(self.stats.get("idiv_call_statement_materialized_count", 0) or 0)
                        + 1
                    )
                    if self.replay_pruned:
                        self.stats["idiv_duplicate_store_pruned_count"] = (
                            int(self.stats.get("idiv_duplicate_store_pruned_count", 0) or 0)
                            + self.replay_pruned
                        )
                    self.changed = True
                self.auxiliary_insert_count = _prune_signed_idiv_auxiliary_insert_8616(
                    self.root,
                    self.project,
                    self.fact,
                )
                if self.auxiliary_insert_count:
                    self.stats["idiv_auxiliary_insert_pruned_count"] = (
                        int(self.stats.get("idiv_auxiliary_insert_pruned_count", 0) or 0)
                        + self.auxiliary_insert_count
                    )
                    self.changed = True
            if (
                self.fact.source_kind
                in {
                    DirectStackMoveSourceKind8616.STACK_SLOT,
                    DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
                }
                and _insert_into_conditional_branch_for_direct_stack_move_8616(
                    self.root,
                    self.project,
                    self.function,
                    self.fact.ins_addr,
                    self.replacement_factory_8616({"ins_addr": self.fact.ins_addr}),
                    relocate_tagged_assignment=True,
                )
            ):
                self.stats["conditional_branch_relocated_count"] = (
                    int(self.stats.get("conditional_branch_relocated_count", 0) or 0) + 1
                )
                self.changed = True
            if (
                self.fact.source_kind is DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT
                and _restore_same_block_stack_move_order_8616(
                    self.root,
                    self.codegen,
                    self.project,
                    self.function,
                    self.fact,
                    self.dst_expr,
                    self.source_expr,
                )
            ):
                self.stats["same_block_stack_move_order_restored_count"] = (
                    int(self.stats.get("same_block_stack_move_order_restored_count", 0) or 0) + 1
                )
                self.changed = True
            if (
                self.fact.source_kind
                in {
                    DirectStackMoveSourceKind8616.IMMEDIATE,
                    DirectStackMoveSourceKind8616.STACK_SLOT,
                    DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
                    DirectStackMoveSourceKind8616.GLOBAL_EXPR,
                    DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
                }
                and not _function_has_loopback_to_instruction_8616(self.function, self.project, self.fact.ins_addr)
            ):
                self.relocated_assignment = _direct_stack_move_assignment_8616(
                    self.codegen,
                    self.dst_cvar,
                    self.source_expr,
                    tags={"inertia_relocated_from_ins_addr": self.fact.ins_addr},
                )
                self.relocated_count = _relocate_tagged_stack_move_before_proven_loop_8616(
                    self.root,
                    self.project,
                    self.function,
                    self.fact.ins_addr,
                    self.dst_cvar,
                    self.source_expr,
                    self.relocated_assignment,
                )
                if self.relocated_count:
                    self.stats["read_before_tagged_assignment_relocated_count"] = (
                        int(self.stats.get("read_before_tagged_assignment_relocated_count", 0) or 0)
                        + self.relocated_count
                    )
                    self.changed = True
            self.root._inertia_stack_mov_assignment_already_present_8616 = True
            self.stats["already_materialized_count"] = int(self.stats.get("already_materialized_count", 0) or 0) + 1
            self.materialized_facts.append(self.fact)
            self.materialized_fact_keys.add(self.fact_key)
            _record_direct_stack_move_evidence_8616(self.codegen, self.fact)
            self.source_expr_by_store_ins_addr[int(self.fact.ins_addr)] = self.source_expr
            return True
        return False

    @cython.ccall
    def _fact_tagged_fallback_gate_8616(self) -> None:
        """Apply the tagged-statement placement gate before direct insertion."""
        assert self.fact is not None
        if _tree_has_assignment_for_instruction_addr_8616(self.root, self.project, self.fact.ins_addr):
            self.stats["tagged_non_stack_assignment_conflict_count"] = (
                int(self.stats.get("tagged_non_stack_assignment_conflict_count", 0) or 0) + 1
            )
        self.fallback_assignment = _direct_stack_move_assignment_8616(
            self.codegen,
            self.dst_expr,
            self.source_expr,
            tags={"ins_addr": self.fact.ins_addr},
        )

    @cython.ccall
    def _fact_immediate_source_arm_8616(self) -> None:
        """Place IMMEDIATE-source stores around proven loop/precontrol positions."""
        branch_placement_service: object
        assert self.fact is not None
        if self.fact.source_kind in {
            DirectStackMoveSourceKind8616.STACK_SLOT,
            DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
            DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR,
            DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
        }:
            # Dynamic service boundary: Structuring owns CFG placement,
            # while Lowering owns the exact assignment passed to it.
            branch_placement_service = getattr(
                self.codegen,
                "_inertia_direct_stack_move_branch_placement_service_8616",
                None,
            )
            if callable(branch_placement_service):
                self.materialized = bool(
                    branch_placement_service(self.fact, self.fallback_assignment)
                )

    @cython.ccall
    def _fact_kind_fallback_chain_8616(self) -> None:
        """Run the per-source-kind fallback placement chain."""
        assert self.fact is not None
        if self.fact.source_kind is DirectStackMoveSourceKind8616.IMMEDIATE:
            self._fallback_immediate_arm_8616()
        elif self.fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH:
            self._fallback_wide_call_arm_8616()
        elif self.fact.source_kind in {DirectStackMoveSourceKind8616.STACK_SLOT, DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT} and self.allow_stack_slot_fallback:
            self._fallback_stack_slot_arm_8616()
        elif self.fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT_EXPR and self.allow_stack_slot_fallback:
            self._fallback_stack_slot_expr_arm_8616()
        elif self.fact.source_kind in {DirectStackMoveSourceKind8616.GLOBAL_EXPR, DirectStackMoveSourceKind8616.GLOBAL_MINUS_STACK_SLOT, DirectStackMoveSourceKind8616.GLOBAL_MINUS_SEGMENTED_MEMORY} and self.allow_stack_slot_fallback:
            self._fallback_global_expr_arm_8616()
        elif self.fact.source_kind is DirectStackMoveSourceKind8616.SEGMENTED_MEMORY:
            self._fallback_segmented_refusal_8616()

    @cython.ccall
    def _fallback_immediate_arm_8616(self) -> None:
        """Run the IMMEDIATE fallback placement chain."""
        assert self.fact is not None
        repeats_at_loop_entry = _function_has_loopback_to_instruction_8616(
            self.function, self.project, self.fact.ins_addr
        )
        is_proven_precontrol = _direct_stack_move_is_before_known_precontrol_8616(
            self.root, self.project, self.function, self.fact.ins_addr
        )
        if repeats_at_loop_entry:
            self.materialized = _insert_at_do_while_body_start_8616(
                self.root,
                self.project,
                self.function,
                self.fact.ins_addr,
                self.fallback_assignment,
            )
        elif is_proven_precontrol:
            self.materialized = _insert_before_first_stack_cvar_use_8616(self.root, self.fallback_assignment)
            if not self.materialized:
                self.materialized = _replace_precontrol_stack_assignment_8616(
                    self.root,
                    self.dst_cvar,
                    self.fallback_assignment,
                    insert_before_control_when_no_match=True,
                )
        if not self.materialized and not is_proven_precontrol:
            self.materialized = _insert_into_conditional_branch_for_direct_stack_move_8616(
                self.root,
                self.project,
                self.function,
                self.fact.ins_addr,
                self.fallback_assignment,
            )
        if not self.materialized and _direct_stack_move_is_before_first_control_8616(
            self.root, self.project, self.fact.ins_addr
        ):
            self.materialized = _replace_precontrol_stack_assignment_8616(
                self.root,
                self.dst_cvar,
                self.fallback_assignment,
                insert_before_control_when_no_match=is_proven_precontrol,
            )
        if not self.materialized:
            self.materialized = _insert_after_nearest_preceding_tagged_statement_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.fallback_assignment,
                function=self.function,
                require_known_block=True,
            )
        if not self.materialized and self.allow_unscoped_fallback_insert:
            self.materialized = _insert_before_nearest_following_tagged_statement_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.fallback_assignment,
            )

    @cython.ccall
    def _fallback_wide_call_arm_8616(self) -> None:
        """Run the WIDE_CALL_RETURN_STACK_ARITH fallback placement."""
        self.materialized = _replace_precontrol_stack_assignment_8616(
            self.root,
            self.dst_cvar,
            self.fallback_assignment,
            allow_low_half_lhs=True,
        )

    @cython.ccall
    def _fallback_stack_slot_arm_8616(self) -> None:
        """Run the STACK_SLOT/STACK_AGGREGATE_ELEMENT fallback chain."""
        assert self.fact is not None
        if not self.materialized:
            self.materialized = _insert_at_do_while_body_start_8616(
                self.root,
                self.project,
                self.function,
                self.fact.ins_addr,
                self.fallback_assignment,
            )
        if _direct_stack_move_is_before_known_precontrol_8616(self.root, self.project, self.function, self.fact.ins_addr):
            self.materialized = self.materialized or _replace_precontrol_stack_assignment_8616(
                self.root, self.dst_cvar, self.fallback_assignment, insert_before_control_when_no_match=True
            )
        if not self.materialized:
            self.materialized = _replace_post_call_cleanup_artifact_before_stack_move_8616(
                self.root,
                self.project,
                self.function,
                self.fact.ins_addr,
                self.fallback_assignment,
            )
        if not self.materialized:
            self.materialized = _insert_at_guarded_body_start_for_target_stack_move_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.fallback_assignment,
            )
        if not self.materialized:
            self.materialized = _insert_after_nearest_preceding_tagged_statement_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.fallback_assignment,
                function=self.function,
                require_known_block=True,
                refuse_loop_container_predecessor=True,
            )
        if not self.materialized:
            self.materialized = _insert_before_do_while_condition_8616(
                self.root, self.project, self.fact.ins_addr, self.fallback_assignment
            )
        if not self.materialized:
            self.materialized = _insert_before_nearest_following_tagged_statement_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.fallback_assignment,
                prefer_loop_container=True,
            )
        if not self.materialized:
            self.materialized = _insert_before_first_stack_cvar_use_8616(
                self.root,
                self.fallback_assignment,
            )
        if not self.materialized and self.allow_unscoped_fallback_insert:
            self.materialized = _insert_after_nearest_preceding_tagged_statement_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.fallback_assignment,
                function=self.function,
            )

    @cython.ccall
    def _fallback_stack_slot_expr_arm_8616(self) -> None:
        """Run the STACK_SLOT_EXPR fallback placement chain."""
        assert self.fact is not None
        if _direct_stack_move_is_before_known_precontrol_8616(self.root, self.project, self.function, self.fact.ins_addr):
            self.materialized = _replace_precontrol_stack_assignment_8616(
                self.root,
                self.dst_cvar,
                self.fallback_assignment,
                insert_before_control_when_no_match=True,
            )
        if not self.materialized:
            self.materialized = _insert_before_first_stack_cvar_use_8616(self.root, self.fallback_assignment)
        if not self.materialized and self.allow_unscoped_fallback_insert:
            self.materialized = _insert_before_nearest_following_tagged_statement_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.fallback_assignment,
            )

    @cython.ccall
    def _fallback_global_expr_arm_8616(self) -> None:
        """Run the GLOBAL_* fallback placement chain."""
        assert self.fact is not None
        self.materialized = _insert_between_structured_siblings_8616(
            self.root,
            self.project,
            self.fact.ins_addr,
            self.fallback_assignment,
        )
        if (
            not self.materialized
            and _direct_stack_move_is_before_known_precontrol_8616(
                self.root,
                self.project,
                self.function,
                self.fact.ins_addr,
            )
        ):
            self.materialized = _replace_precontrol_stack_assignment_8616(
                self.root,
                self.dst_cvar,
                self.fallback_assignment,
                insert_before_control_when_no_match=True,
            )
        if not self.materialized:
            self.materialized = _insert_before_first_stack_cvar_use_8616(self.root, self.fallback_assignment)
        if not self.materialized and self.allow_unscoped_fallback_insert:
            self.materialized = _insert_before_nearest_following_tagged_statement_8616(
                self.root,
                self.project,
                self.fact.ins_addr,
                self.fallback_assignment,
            )

    @cython.ccall
    def _fallback_segmented_refusal_8616(self) -> None:
        """Refuse unscoped segmented-memory placement."""
        # Structuring owns CFG scope through the placement service above.
        # Refuse here when no exact owner accepted the Lowering-built value.
        self.stats["segmented_memory_scope_refused_count"] = (
            int(self.stats.get("segmented_memory_scope_refused_count", 0) or 0)
            + int(not self.materialized)
        )

    @cython.ccall
    def _fact_materialize_fallback_8616(self) -> cython.bint:
        """Apply the last-resort materialization fallback for a fact."""
        assert self.fact is not None
        if not self.materialized:
            if bool(getattr(self.root, "_inertia_stack_mov_assignment_already_present_8616", False)):
                self.stats["already_materialized_count"] = int(self.stats.get("already_materialized_count", 0) or 0) + 1
                self.materialized_facts.append(self.fact)
                self.source_expr_by_store_ins_addr[int(self.fact.ins_addr)] = self.source_expr
                return True
            self.stats["failure_count"] = int(self.stats.get("failure_count", 0) or 0) + 1
            if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
                log.warning(
                    "[direct-stack-mov] refused ins=%#x dst=%s source_kind=%s source_value=%s "
                    "source_offset=%s reads_dst=%s reasons=%s",
                    self.fact.ins_addr,
                    _stack_cvar_identity_8616(self.dst_cvar),
                    self.fact.source_kind.name,
                    self.fact.source_value,
                    self.fact.source_offset,
                    _node_reads_stack_cvar_8616(self.root, self.dst_cvar),
                    getattr(self.root, "_inertia_stack_mov_refused_reasons_8616", ()),
                )
            return True
        return False

    @cython.ccall
    def _fact_aggregate_order_restore_8616(self) -> None:
        """Restore same-block stack-move ordering for aggregate elements."""
        assert self.fact is not None
        if (
            self.fact.source_kind is DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT
            and _restore_same_block_stack_move_order_8616(
                self.root,
                self.codegen,
                self.project,
                self.function,
                self.fact,
                self.dst_expr,
                self.source_expr,
            )
        ):
            self.stats["same_block_stack_move_order_restored_count"] = (
                int(self.stats.get("same_block_stack_move_order_restored_count", 0) or 0) + 1
            )
            self.changed = True

    @cython.ccall
    def _fact_immediate_group_arm_8616(self) -> None:
        """Handle immediate and aggregate source-kind materialization details."""
        assert self.fact is not None
        if self.fact.source_kind in {
            DirectStackMoveSourceKind8616.IMMEDIATE,
            DirectStackMoveSourceKind8616.STACK_SLOT,
            DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
            DirectStackMoveSourceKind8616.GLOBAL_EXPR,
            DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
        } and not _function_has_loopback_to_instruction_8616(self.function, self.project, self.fact.ins_addr):
            self.relocated_assignment = _direct_stack_move_assignment_8616(
                self.codegen,
                self.dst_cvar,
                self.source_expr,
                tags={"inertia_relocated_from_ins_addr": self.fact.ins_addr},
            )
            self.relocated_count = _relocate_tagged_stack_move_before_proven_loop_8616(
                self.root,
                self.project,
                self.function,
                self.fact.ins_addr,
                self.dst_cvar,
                self.source_expr,
                self.relocated_assignment,
            )
            if self.relocated_count:
                self.stats["read_before_tagged_assignment_relocated_count"] = (
                    int(self.stats.get("read_before_tagged_assignment_relocated_count", 0) or 0) + self.relocated_count
                )
                self.changed = True

    @cython.ccall
    def _fact_sign_extend_guard_8616(self) -> None:
        """Insert visible-use guards for sign-extended stack-slot stores."""
        assert self.fact is not None
        if (
            self.fact.source_kind is DirectStackMoveSourceKind8616.STACK_SLOT
            and self.allow_stack_slot_fallback
            and self.fact.source_sign_extend
            and isinstance(self.fact.source_access_width, int)
            and self.fact.source_access_width < self.fact.width
        ):
            self.visible_assignment = _direct_stack_move_assignment_8616(
                self.codegen,
                self.dst_cvar,
                self.source_expr,
                tags={"ins_addr": self.fact.ins_addr},
            )
            target_offset = _c_expr_stack_offset_8616(self.dst_cvar)
            visible_assignment_available = (
                _insert_before_first_stack_offset_use_8616(self.root, self.visible_assignment, target_offset)
                if isinstance(target_offset, int) and _expr_reads_stack_offset_8616(self.root, target_offset)
                else False
            )
            if visible_assignment_available:
                self.stats["visible_use_guard_count"] = int(self.stats.get("visible_use_guard_count", 0) or 0) + 1
                self.changed = True

    @cython.ccall
    def _fact_wide_arith_carrier_prune_8616(self) -> None:
        """Prune obsolete wide call-return carriers after materialization."""
        assert self.fact is not None
        if self.fact.source_kind is DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH:
            self.carrier_pruned = _prune_wide_call_return_carriers_8616(
                self.root,
                self.project,
                self.fact,
                self.dst_cvar,
            )
            if self.carrier_pruned:
                self.stats["wide_call_carrier_pruned_count"] = (
                    int(self.stats.get("wide_call_carrier_pruned_count", 0) or 0) + self.carrier_pruned
                )
                self.changed = True
            self.decomposition_pruned = _prune_wide_call_return_decomposition_8616(
                self.root,
                self.project,
                self.fact,
            )
            if self.decomposition_pruned:
                self.stats["wide_call_decomposition_pruned_count"] = (
                    int(self.stats.get("wide_call_decomposition_pruned_count", 0) or 0)
                    + self.decomposition_pruned
                )
                self.changed = True
            rebound_count = _rebind_low_half_stack_reads_to_wide_cvar_8616(self.root, self.dst_cvar)
            if rebound_count:
                self.stats["wide_low_half_read_rebound_count"] = (
                    int(self.stats.get("wide_low_half_read_rebound_count", 0) or 0) + rebound_count
                )
                self.changed = True

    @cython.ccall
    def _fact_finalize_8616(self) -> None:
        """Commit materialization counters and evidence for one fact."""
        assert self.fact is not None
        self.stats["materialized_count"] = int(self.stats.get("materialized_count", 0) or 0) + 1
        self.materialized_facts.append(self.fact)
        self.materialized_fact_keys.add(self.fact_key)
        self.source_expr_by_store_ins_addr[int(self.fact.ins_addr)] = self.source_expr
        _record_direct_stack_move_evidence_8616(self.codegen, self.fact)
        self.changed = True

    @cython.ccall
    def replacement_factory_8616(
        self,
        tags: StructuredAstValue,
        *,
        _dst_cvar: StructuredAstValue = None,
        _source_expr: StructuredAstValue = None,
    ) -> StructuredAstValue:
        """Build the exact assignment for one binary-proven stack MOV."""
        return _direct_stack_move_assignment_8616(
            self.codegen,
            self.dst_expr if _dst_cvar is None else _dst_cvar,
            self.source_expr if _source_expr is None else _source_expr,
            tags=tags,
        )

    @cython.ccall
    def call_statement_replacement_factory_8616(
        self,
        tags: StructuredAstValue,
        *,
        _dst_cvar: StructuredAstValue = None,
        _source_expr: StructuredAstValue = None,
    ) -> StructuredAstValue:
        """Build the stack assignment that replaces the signed-idiv call statement."""
        return _direct_stack_move_assignment_8616(
            self.codegen,
            self.dst_cvar if _dst_cvar is None else _dst_cvar,
            self.call_statement_source_expr if _source_expr is None else _source_expr,
            tags=tags,
        )

    @cython.ccall
    def process_facts_8616(self) -> None:
        """Advance each recovered fact through the materialization arms."""
        fact: object
        self.timers["fact_loop_started"] = time.perf_counter()
        for fact in self.facts:
            self.fact = fact
            if self._fact_begin_8616():
                continue
            if self._fact_wide_call_return_arm_8616():
                continue
            self._fact_stack_slot_sub_type_rebind_8616()
            self._fact_stack_slot_type_rebind_8616()
            self._fact_inverse_prune_8616()
            if self._fact_already_materialized_8616():
                continue
            self._fact_classified_8616()
            self._fact_stack_slot_expr_arm_8616()
            self._fact_signed_idiv_arm_8616()
            if self._fact_generic_materialize_8616():
                continue
            if self._fact_materialize_fallback_8616():
                continue
            self._fact_aggregate_order_restore_8616()
            self._fact_immediate_group_arm_8616()
            self._fact_sign_extend_guard_8616()
            self._fact_wide_arith_carrier_prune_8616()
            self._fact_finalize_8616()
        self.timers["fact_loop"] = time.perf_counter() - self.timers["fact_loop_started"]

    @cython.ccall
    def _reload_fact_head_8616(
        self,
        reload_fact: DirectStackReloadFact8616,
        frame: _DirectStackReloadFrame8616,
    ) -> object:
        """Classify one reload fact and resolve its source cvar."""
        source_cvar: object
        self.stats["reload_classified_fact_count"] = int(self.stats.get("reload_classified_fact_count", 0) or 0) + 1
        source_fact = _materialized_store_fact_for_reload_8616(
            reload_fact,
            tuple(self.materialized_facts),
        )
        source_cvar = _resolve_direct_stack_update_cvar_8616(self.codegen, reload_fact.source_offset, reload_fact.width)
        if source_cvar is None:
            self.stats["reload_failure_count"] = int(self.stats.get("reload_failure_count", 0) or 0) + 1
            return None
        reload_step_started = time.perf_counter()
        reload_placement = _replace_tagged_register_reload_assignment_8616(
            self.root,
            self.project,
            reload_fact,
            source_cvar,
            candidate_index=frame.candidate_index,
        )
        frame.timers["tagged_reload_match"] += time.perf_counter() - reload_step_started
        materialized_reload = reload_placement.present
        return source_fact, source_cvar, materialized_reload, reload_placement

    @cython.ccall
    def _reload_stack_slot_attempt_8616(
        self,
        reload_fact: DirectStackReloadFact8616,
        source_fact: object,
        source_cvar: StructuredAstValue,
        materialized_reload: cython.bint,
        reload_placement: StructuredAstValue,
        frame: _DirectStackReloadFrame8616,
    ) -> tuple[cython.bint, StructuredAstValue]:
        """Attempt register-use insertion and visible-guard fallback for a stack-slot reload."""
        reload_expr: object
        source_expr: object
        source_expr = self.source_expr_by_store_ins_addr.get(int(reload_fact.source_store_ins_addr))
        stale_source_expr = _stack_slot_has_intervening_direct_update_8616(
            self.project,
            self.function,
            offset=reload_fact.source_offset,
            width=reload_fact.width,
            start_ins_addr=reload_fact.source_store_ins_addr,
            end_ins_addr=reload_fact.ins_addr,
        )
        preserve_stack_identity = reload_fact.source_kind in {
            DirectStackMoveSourceKind8616.STACK_SLOT,
            DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
        }
        reload_expr = (
            source_cvar
            if stale_source_expr or preserve_stack_identity
            else source_expr
        )
        if (
            reload_expr is not None
            and isinstance(reload_fact.dst_reg_name, str)
            and reload_fact.dst_reg_name not in frame.register_use_missing
        ):
            if reload_fact.dst_reg_name not in frame.register_names:
                inserted_reload = False
                self.stats["reload_register_use_absence_skip_count"] = (
                    int(self.stats.get("reload_register_use_absence_skip_count", 0) or 0) + 1
                )
            else:
                reload_step_started = time.perf_counter()
                inserted_reload = _insert_before_first_register_cvar_use_8616(
                    self.root,
                    reload_fact.dst_reg_name,
                    reload_expr,
                    self.codegen,
                    project=self.project,
                    register_width=reload_fact.width,
                    ins_addr=reload_fact.ins_addr,
                )
                frame.timers["register_use_insert"] += time.perf_counter() - reload_step_started
            if inserted_reload:
                reload_placement = _DirectStackReloadPlacement8616.MATERIALIZED
                materialized_reload = True
            if (
                not materialized_reload
                and not stale_source_expr
                and source_expr is not None
                and not _expr_contains_function_call_8616(source_expr)
                and isinstance(reload_fact.source_offset, int)
            ):
                reload_step_started = time.perf_counter()
                visible_guard_present = _tree_has_stack_move_assignment_8616(
                    self.root,
                    source_cvar,
                    source_expr,
                ) or (
                    source_fact is not None
                    and _tree_has_materialized_signed_idiv_remainder_8616(
                        self.root,
                        source_fact,
                        source_cvar,
                    )
                )
                frame.timers["visible_guard"] += time.perf_counter() - reload_step_started
                if visible_guard_present:
                    reload_placement = _DirectStackReloadPlacement8616.ALREADY_PRESENT
                    materialized_reload = True
                    self.stats["reload_stack_slot_visible_guard_already_present_count"] = (
                        int(self.stats.get("reload_stack_slot_visible_guard_already_present_count", 0) or 0) + 1
                    )
                else:
                    fallback_assignment = _direct_stack_move_assignment_8616(
                        self.codegen,
                        source_cvar,
                        source_expr,
                        tags={"ins_addr": reload_fact.source_store_ins_addr},
                    )
                    inserted_reload = _insert_before_nearest_following_tagged_statement_8616(
                        self.root,
                        self.project,
                        reload_fact.ins_addr,
                        fallback_assignment,
                        ignore_existing_assignment=True,
                    )
                    if inserted_reload:
                        reload_placement = _DirectStackReloadPlacement8616.MATERIALIZED
                        materialized_reload = True
                        self.stats["reload_stack_slot_visible_guard_count"] = (
                            int(self.stats.get("reload_stack_slot_visible_guard_count", 0) or 0) + 1
                        )
                    elif bool(getattr(self.root, "_inertia_stack_mov_assignment_already_present_8616", False)):
                        reload_placement = _DirectStackReloadPlacement8616.ALREADY_PRESENT
                        materialized_reload = True
                        self.stats["reload_stack_slot_visible_guard_already_present_count"] = (
                            int(self.stats.get("reload_stack_slot_visible_guard_already_present_count", 0) or 0) + 1
                        )
            if not materialized_reload:
                frame.register_use_missing.add(reload_fact.dst_reg_name)
                self.stats["reload_missing_register_use_cached_count"] = (
                    int(self.stats.get("reload_missing_register_use_cached_count", 0) or 0) + 1
                )
        elif isinstance(reload_fact.dst_reg_name, str) and reload_fact.dst_reg_name in frame.register_use_missing:
            self.stats["reload_missing_register_use_cache_hit_count"] = (
                int(self.stats.get("reload_missing_register_use_cache_hit_count", 0) or 0) + 1
            )
        return materialized_reload, reload_placement

    def _reload_debug_refusal_8616(self, reload_fact: DirectStackReloadFact8616) -> None:
        """Emit the reload refusal diagnostic when stack noise debugging is on."""
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            candidates = _boundary_tuple_8616(
                dict.fromkeys(
                    (
                        type(getattr(node, "variable", None)).__name__,
                        getattr(getattr(node, "variable", None), "name", None),
                        _cvar_register_name_8616(node),
                        _stack_cvar_identity_8616(node),
                    )
                    for node in builtins.iter(_iter_structured_c_nodes_8616(self.root))
                    if isinstance(node, structured_c.CVariable)
                )
            )[:16]
            log.warning(
                "[direct-stack-mov-reload] refused ins=%#x src_offset=%s width=%s "
                "dst_reg=%s source_store=%#x candidates=%r",
                reload_fact.ins_addr,
                reload_fact.source_offset,
                reload_fact.width,
                reload_fact.dst_reg_name,
                reload_fact.source_store_ins_addr,
                candidates,
            )

    @cython.ccall
    def _reload_commit_8616(
        self,
        reload_fact: DirectStackReloadFact8616,
        materialized_reload: cython.bint,
        reload_placement: StructuredAstValue,
        frame: _DirectStackReloadFrame8616,
    ) -> None:
        """Commit reload placement counters or record the refusal evidence."""
        if materialized_reload:
            if frame.candidate_index is not None and reload_placement.changed:
                frame.candidate_index.record(_candidate_ins_addrs_8616(self.project, reload_fact.ins_addr))
            if reload_placement.changed:
                self.stats["reload_materialized_count"] = int(self.stats.get("reload_materialized_count", 0) or 0) + 1
                self.changed = True
            else:
                self.stats["reload_already_materialized_count"] = (
                    int(self.stats.get("reload_already_materialized_count", 0) or 0) + 1
                )
        else:
            self.stats["reload_failure_count"] = int(self.stats.get("reload_failure_count", 0) or 0) + 1
            self._reload_debug_refusal_8616(reload_fact)

    @cython.ccall
    def _recover_reload_facts_8616(
        self,
    ) -> tuple[tuple[DirectStackReloadFact8616, ...], _DirectStackReloadFrame8616]:
        """Recover register-reload facts and build the shared reload frame."""
        reload_recovery_started = time.perf_counter()
        reload_facts = (
            _direct_stack_reload_instruction_facts_8616(self.project, self.function, tuple(self.materialized_facts))
            if self.materialize_reloads
            else ()
        )
        self.timers["reload_recovery"] = time.perf_counter() - reload_recovery_started
        if not self.materialize_reloads:
            self.stats["reload_recovery_skipped_count"] = int(self.stats.get("reload_recovery_skipped_count", 0) or 0) + 1
        self.stats["reload_raw_fact_count"] = int(self.stats.get("reload_raw_fact_count", 0) or 0) + len(reload_facts)
        frame = _DirectStackReloadFrame8616()
        frame.query_index = StructuredAstQueryIndex8616.build(self.root) if reload_facts else None
        frame.candidate_index = (
            TaggedAssignmentAddressIndex8616.from_query_index(frame.query_index)
            if frame.query_index is not None
            else None
        )
        frame.register_names = (
            register_cvar_names_8616(frame.query_index.variables)
            if frame.query_index is not None
            else frozenset()
        )
        return reload_facts, frame

    @cython.ccall
    def _process_reload_facts_8616(
        self,
        reload_facts: object,
        frame: _DirectStackReloadFrame8616,
    ) -> None:
        """Materialize each recovered register-reload fact."""
        head: object
        reload_fact: object
        reload_loop_started = time.perf_counter()
        for reload_fact in reload_facts:
            head = self._reload_fact_head_8616(reload_fact, frame)
            if head is None:
                continue
            source_fact, source_cvar, materialized_reload, reload_placement = head
            if (
                not materialized_reload
                and reload_fact.source_kind is not DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT
            ):
                materialized_reload, reload_placement = self._reload_stack_slot_attempt_8616(
                    reload_fact,
                    source_fact,
                    source_cvar,
                    materialized_reload,
                    reload_placement,
                    frame,
                )
            elif not materialized_reload:
                self.stats["aggregate_reload_unscoped_fallback_refused_count"] = (
                    int(self.stats.get("aggregate_reload_unscoped_fallback_refused_count", 0) or 0) + 1
                )
            self._reload_commit_8616(reload_fact, materialized_reload, reload_placement, frame)
        self.timers["reload_loop"] = time.perf_counter() - reload_loop_started
        if frame.candidate_index is not None:
            # Dynamic angr/codegen boundary: publish immutable optimization accounting.
            self.codegen._inertia_direct_stack_reload_query_index_stats_8616 = frame.candidate_index.stats()

    @cython.ccall
    def _epilogue_publish_8616(self) -> None:
        """Replay pending branch-ownership edits and publish the rewritten root."""
        branch_ownership_replay: object
        # Dynamic angr/codegen boundary: Structuring binds this replay so Lowering
        # can preserve value facts without owning conditional AST placement.
        branch_ownership_replay = getattr(
            self.codegen,
            "_inertia_direct_stack_move_branch_ownership_replay_8616",
            None,
        )
        ownership_replay_started = time.perf_counter()
        if callable(branch_ownership_replay):
            self.changed = bool(branch_ownership_replay()) or self.changed
        self.timers["ownership_replay"] = time.perf_counter() - ownership_replay_started
        if self.changed:
            with contextlib.suppress(Exception):
                self.codegen.cfunc.body = self.root
            with contextlib.suppress(Exception):
                self.codegen._inertia_force_codegen_regeneration_8616 = True

    def _epilogue_debug_summary_8616(self) -> None:
        """Emit the per-function materialization summary when enabled."""
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            fact_summary = _boundary_tuple_8616(
                (
                    getattr(fact.source_kind, "name", str(fact.source_kind)),
                    fact.dst_offset,
                    fact.width,
                    fact.source_value,
                    fact.source_offset,
                    fact.source_immediate,
                    fact.source_access_width,
                    fact.source_sign_extend,
                    fact.ins_addr,
                )
                for fact in iter(self.facts)
            )
            log.warning(
                "[direct-stack-mov] function=%#x codegen=%#x facts=%d materialized=%d failures=%d "
                "call_reused=%d idiv_call_stmt=%d idiv_artifact=%d idiv_bridge=%d "
                "idiv_seen=%s idiv_candidates=%s idiv_exact=%s "
                "idiv_rej_dst=%s idiv_rej_mem=%s idiv_rej_used=%s idiv_rej_nokey=%s idiv_refusal=%s "
                "known=%d stale=%d casts=%d casts_present=%d "
                "cast_assignments=%d cast_destinations=%d "
                "cast_candidates=%d cast_no_match=%d cast_ambiguous=%d "
                "visible_guards=%d reloads=%d "
                "reload_materialized=%d reload_failures=%d changed=%s fact_summary=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", -1) or -1,
                id(self.codegen),
                len(self.facts),
                int(self.stats.get("materialized_count", 0) or 0),
                int(self.stats.get("failure_count", 0) or 0),
                int(self.stats.get("call_result_reused_count", 0) or 0),
                int(self.stats.get("idiv_call_statement_materialized_count", 0) or 0),
                int(self.stats.get("idiv_artifact_materialized_count", 0) or 0),
                int(self.stats.get("idiv_artifact_stack_lhs_bridge_count", 0) or 0),
                getattr(self.root, "_inertia_signed_idiv_artifact_seen_count_8616", None),
                getattr(self.root, "_inertia_signed_idiv_artifact_candidate_count_8616", None),
                getattr(self.root, "_inertia_signed_idiv_artifact_exact_candidate_count_8616", None),
                getattr(self.root, "_inertia_signed_idiv_artifact_reject_dst_read_count_8616", None),
                getattr(self.root, "_inertia_signed_idiv_artifact_reject_memory_lhs_count_8616", None),
                getattr(self.root, "_inertia_signed_idiv_artifact_reject_used_lhs_count_8616", None),
                getattr(self.root, "_inertia_signed_idiv_artifact_reject_no_lhs_key_count_8616", None),
                getattr(self.root, "_inertia_signed_idiv_artifact_refusal_8616", None),
                int(self.stats.get("already_materialized_count", 0) or 0),
                int(self.stats.get("stale_evidence_rematerialized_count", 0) or 0),
                int(self.stats.get("semantic_cast_reconciled_count", 0) or 0),
                int(self.stats.get("semantic_cast_already_present_count", 0) or 0),
                int(self.stats.get("semantic_cast_assignment_count", 0) or 0),
                int(self.stats.get("semantic_cast_destination_count", 0) or 0),
                int(self.stats.get("semantic_cast_candidate_count", 0) or 0),
                int(self.stats.get("semantic_cast_no_match_count", 0) or 0),
                int(self.stats.get("semantic_cast_ambiguous_count", 0) or 0),
                int(self.stats.get("visible_use_guard_count", 0) or 0),
                int(self.stats.get("reload_raw_fact_count", 0) or 0),
                int(self.stats.get("reload_materialized_count", 0) or 0),
                int(self.stats.get("reload_failure_count", 0) or 0),
                self.changed,
                fact_summary,
            )

    @cython.ccall
    def _epilogue_finish_8616(self, reload_fact_count: cython.longlong) -> None:
        """Record semantic lanes and emit the optional timing breakdown."""
        _record_direct_stack_move_lanes_8616(
            self.codegen,
            self.stats,
            prior_stats=self.lane_stats_before,
            current_raw_fact_count=len(self.facts),
        )
        if os.environ.get("INERTIA_DEBUG_TIMING") and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            timers = self.timers
            print(
                f"[{time.strftime('%H:%M:%S')}] direct-stack MOV components: "
                f"facts={len(self.facts)} reloads={reload_fact_count} "
                f"prepare={timers['prepare']:.3f} recovery={timers['recovery']:.3f} "
                f"match={timers['fact_loop']:.3f} prune={timers['unsupported_prune']:.3f} "
                f"reload_recovery={timers['reload_recovery']:.3f} reload_match={timers['reload_loop']:.3f} "
                f"reload_tagged={timers.get('tagged_reload_match', 0.0):.3f} "
                f"reload_register_use={timers.get('register_use_insert', 0.0):.3f} "
                f"reload_visible_guard={timers.get('visible_guard', 0.0):.3f} "
                f"ownership={timers['ownership_replay']:.3f} "
                f"cleanup={time.perf_counter() - timers['cleanup_started']:.3f} "
                f"total={time.perf_counter() - timers['started']:.3f}",
                file=sys.stderr,
                flush=True,
            )

    @cython.ccall
    def epilogue_8616(self) -> None:
        """Prune unsupported stores, recover reloads, and publish results."""
        cleanup_started = time.perf_counter()
        self.timers["cleanup_started"] = cleanup_started
        pruned_unsupported = _prune_unsupported_function_pointer_stack_move_assignments_8616(
            self.root, self.codegen, self.facts
        )
        if pruned_unsupported:
            self.stats["unsupported_function_pointer_assignment_pruned_count"] = (
                int(self.stats.get("unsupported_function_pointer_assignment_pruned_count", 0) or 0) + pruned_unsupported
            )
            self.changed = True
        self.timers["unsupported_prune"] = time.perf_counter() - cleanup_started
        reload_facts, frame = self._recover_reload_facts_8616()
        self._process_reload_facts_8616(reload_facts, frame)
        self._epilogue_publish_8616()
        self._epilogue_debug_summary_8616()
        self._epilogue_finish_8616(len(reload_facts))


@cython.ccall
def _direct_stack_move_stats_8616(codegen: StructuredAstValue) -> object:
    """Return (creating when absent) the direct-stack-MOV counter surface."""
    stats: object
    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(stats, dict):
        stats = {
            "raw_fact_count": 0,
            "classified_fact_count": 0,
            "materialized_count": 0,
            "already_materialized_count": 0,
            "failure_count": 0,
            "call_result_reused_count": 0,
            "idiv_artifact_materialized_count": 0,
            "idiv_artifact_stack_lhs_bridge_count": 0,
            "reload_raw_fact_count": 0,
            "reload_classified_fact_count": 0,
            "reload_materialized_count": 0,
            "reload_failure_count": 0,
        }
        codegen._inertia_direct_stack_move_lowering_8616 = stats
    return stats


@cython.ccall
def _prepare_direct_stack_mov_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    function: StructuredAstValue,
) -> cython.bint:
    """Prune prologue writes and materialize stack aggregate objects."""
    frame_prologue_changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )
    aggregate_changed = materialize_stack_aggregate_objects_8616(
        codegen,
        project,
        function,
        instructions=_direct_global_update_ordered_insns_8616(project, function),
    )
    return frame_prologue_changed or aggregate_changed


def _recover_direct_stack_move_facts_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    function: StructuredAstValue,
    stats: object,
    source_kinds: object,
) -> tuple[tuple[DirectStackMoveFact8616, ...], cython.double]:
    """Recover, merge, and private-source-filter direct-stack-MOV facts."""
    fact_recovery_started = time.perf_counter()
    facts = _direct_stack_move_instruction_facts_for_codegen_8616(
        codegen,
        project,
        function,
    )
    if source_kinds is not None:
        facts = tuple(fact for fact in iter(facts) if fact.source_kind in source_kinds)
    fact_recovery_elapsed = time.perf_counter() - fact_recovery_started
    existing_typed_facts = tuple(
        fact
        for fact in builtins.iter(_boundary_tuple_8616(
            getattr(codegen, "_inertia_direct_stack_move_facts_8616", ()) or ()
        ))
        if isinstance(fact, DirectStackMoveFact8616)
    )
    codegen._inertia_direct_stack_move_facts_8616 = tuple(
        dict.fromkeys(existing_typed_facts + facts)
    )
    stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + len(facts)
    required_facts = tuple(fact for fact in iter(facts) if not alias_proves_private_stack_source_8616(codegen, fact.ins_addr))
    stats["private_write_elided_count"] = int(stats.get("private_write_elided_count", 0) or 0) + len(facts) - len(required_facts)
    return required_facts, fact_recovery_elapsed


@cython.ccall
def _direct_stack_mov_empty_facts_8616(
    codegen: StructuredAstValue,
    function: StructuredAstValue,
    stats: object,
    aggregate_changed: cython.bint,
    debug_stack_noise: cython.bint,
) -> cython.bint:
    """Handle the no-recovered-facts early return with lane accounting."""
    if debug_stack_noise:
        log.warning(
            "[direct-stack-mov] function=%#x facts=0 changed=False stats=%r",
            getattr(function, "addr", -1) or -1,
            stats,
        )
    _record_direct_stack_move_lanes_8616(codegen, stats)
    return aggregate_changed


def _materialize_direct_stack_mov_instructions_impl_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue | None = None,
    function: StructuredAstValue | None = None,
    *,
    allow_stack_slot_fallback: cython.bint = True,
    source_kinds: object = None,
    materialize_reloads: cython.bint = True,
) -> cython.bint:
    """Materialize direct BP-relative MOV stores and optional register reloads."""
    func_addr: object
    root: object
    started = time.perf_counter()
    debug_stack_noise = bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))
    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        if debug_stack_noise:
            log.warning("[direct-stack-mov] unavailable project_or_root changed=False")
        return False
    if function is None:
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        if debug_stack_noise:
            log.warning("[direct-stack-mov] unavailable function changed=False")
        return False

    aggregate_changed = _prepare_direct_stack_mov_8616(codegen, project, function)
    preparation_elapsed = time.perf_counter() - started

    stats = _direct_stack_move_stats_8616(codegen)
    lane_stats_before = {
        name: _stat_counter_8616(stats, name)
        for name in iter((
            "raw_fact_count",
            "classified_fact_count",
            "materialized_count",
            "already_materialized_count",
            "failure_count",
        ))
    }

    if debug_stack_noise:
        log.warning(
            "[direct-stack-mov] start function=%#x root=%s",
            getattr(function, "addr", -1) or -1,
            type(root).__name__,
        )
    facts, fact_recovery_elapsed = _recover_direct_stack_move_facts_8616(
        codegen,
        project,
        function,
        stats,
        source_kinds,
    )
    if not facts:
        return _direct_stack_mov_empty_facts_8616(
            codegen,
            function,
            stats,
            aggregate_changed,
            debug_stack_noise,
        )

    fallback_decision = _direct_stack_move_fallback_decision_8616(root)
    allow_unscoped_fallback_insert = fallback_decision is DirectStackMoveFallbackDecision8616.SAFE_TO_INSERT
    if not allow_unscoped_fallback_insert:
        stats["structured_scope_fallback_refused_count"] = (
            int(stats.get("structured_scope_fallback_refused_count", 0) or 0) + 1
        )
    signed_idiv_remainder_fact_count = sum(
        1 for candidate in iter(facts) if candidate.source_kind is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
    )
    run = _DirectStackMovRun8616(
        codegen=codegen,
        project=project,
        function=function,
        root=root,
        stats=stats,
        debug_stack_noise=debug_stack_noise,
        facts=facts,
        allow_stack_slot_fallback=allow_stack_slot_fallback,
        materialize_reloads=materialize_reloads,
        allow_unscoped_fallback_insert=allow_unscoped_fallback_insert,
        signed_idiv_remainder_fact_count=signed_idiv_remainder_fact_count,
        materialized_fact_keys=set(_direct_stack_move_materialized_fact_keys_8616(codegen)),
        materialized_facts=[],
        source_expr_by_store_ins_addr={},
        changed=aggregate_changed,
        lane_stats_before=lane_stats_before,
        timers={
            "started": started,
            "prepare": preparation_elapsed,
            "recovery": fact_recovery_elapsed,
        },
    )
    run.process_facts_8616()
    run.epilogue_8616()
    return run.changed


@cython.ccall
def _candidate_functions_for_indexed_stack_facts_8616(codegen: StructuredAstValue, project: StructuredAstValue) -> StructuredAstValue:
    return _candidate_functions_for_stack_facts_8616(codegen, project)


@cython.ccall
def _indexed_bp_operand_stack_slot_8616(operand: StructuredAstValue) -> object:
    """Return ``(displacement, access size)`` for a ``[bp+index+disp]`` operand."""
    mem: object
    if operator.ne(int(getattr(operand, "type", -1)), X86_OP_MEM):
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    if operator.ne(int(getattr(mem, "base", 0) or 0), X86_REG_BP):
        return None
    index_reg = int(getattr(mem, "index", 0) or 0)
    if index_reg in {0, X86_REG_INVALID}:
        return None
    displacement = _canonical_stack_offset_8616(int(getattr(mem, "disp", 0) or 0))
    if not isinstance(displacement, int):
        return None
    size = int(getattr(operand, "size", 0) or 0)
    return displacement, size if size > 0 else 0


@cython.ccall
def _indexed_bp_stack_fact_sizes_8616(codegen: StructuredAstValue, project: StructuredAstValue) -> object:
    cached: object
    capstone: object
    slot: object
    block: object
    function: object
    insn: object
    operand: object
    cached = getattr(codegen, "_inertia_indexed_bp_stack_access_facts_8616", None)
    if isinstance(cached, dict):
        return cached

    collected: dict[cython.longlong, set[cython.longlong]] = {}
    for function in _candidate_functions_for_indexed_stack_facts_8616(codegen, project):
        for block in _boundary_tuple_8616(getattr(function, "blocks", ()) or ()):
            capstone = getattr(block, "capstone", None)
            for insn in _boundary_tuple_8616(getattr(capstone, "insns", ()) or ()):
                for operand in _boundary_tuple_8616(getattr(insn, "operands", ()) or ()):
                    slot = _indexed_bp_operand_stack_slot_8616(operand)
                    if slot is None:
                        continue
                    displacement, size = slot
                    collected.setdefault(displacement, set()).add(size)

    facts = {disp: frozenset(sizes) for disp, sizes in builtins.iter(sorted(tuple(collected.items())))}
    codegen._inertia_indexed_bp_stack_access_facts_8616 = facts
    codegen._inertia_indexed_bp_stack_address_raw_fact_count_8616 = len(facts)
    return facts


@cython.ccall
def _flatten_indexed_stack_address_terms_8616(
    node: StructuredAstValue,
) -> object:
    current: object
    exiting: object
    sign: object
    terms: list[tuple[cython.longlong, StructuredAstValue]] = []
    pending: list[tuple[StructuredAstValue, cython.longlong, cython.bint]] = [(node, 1, False)]
    active: set[cython.longlong] = set()
    while pending:
        current, sign, exiting = pending.pop()
        current = _strip_casts_8616(current)
        if current is None:
            return None
        if exiting:
            active.discard(id(current))
            continue
        current_id = id(current)
        if current_id in active:
            return None
        if len(active) > 1024:
            return None
        active.add(current_id)
        pending.append((current, sign, True))
        if isinstance(current, structured_c.CBinaryOp) and current.op == "Add":
            pending.append((current.rhs, sign, False))
            pending.append((current.lhs, sign, False))
            continue
        if isinstance(current, structured_c.CBinaryOp) and current.op == "Sub":
            pending.append((current.rhs, -sign, False))
            pending.append((current.lhs, sign, False))
            continue
        if isinstance(current, structured_c.CUnaryOp) and current.op == "Reference":
            operand = _strip_casts_8616(current.operand)
            if isinstance(operand, structured_c.CIndexedVariable):
                pending.append((operand.index, sign, False))
                continue
        terms.append((sign, current))
    return tuple(terms)


@cython.ccall
def _signed_16bit_term_value_8616(sign: cython.longlong, value: cython.longlong) -> cython.longlong:
    return int(_canonical_stack_offset_8616((int(sign) * int(value)) & 0xFFFF))


@cython.ccall
def _stack_cvar_displacement_8616(codegen: StructuredAstValue, node: StructuredAstValue) -> int | None:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimStackVariable):
        return None
    offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return _canonical_stack_offset_8616(offset) if isinstance(offset, int) else None


@cython.ccall
def _indexed_bp_term_displacement_8616(
    codegen: StructuredAstValue, sign: cython.longlong, term: StructuredAstValue
) -> int | None:
    """Resolve one signed term to a canonical BP-stack displacement."""
    value: object
    value = _constant_value_8616(term)
    if value is not None:
        return _signed_16bit_term_value_8616(sign, value)
    if sign == 1:
        return _stack_cvar_displacement_8616(codegen, term)
    return None


@cython.ccall
def _infer_indexed_access_width_8616(
    residual_terms: object,
    sizes: object,
) -> int | None:
    """Infer the indexed access width from residual constants and fact sizes."""
    value: object
    sign: object
    term: object
    constant_residual = 0
    for sign, term in residual_terms:
        value = _constant_value_8616(term)
        if value is not None:
            constant_residual += int(sign) * int(value)
    if constant_residual % 2 or 1 in sizes:
        return 1
    return 2 if 2 in sizes else None


def _match_indexed_bp_stack_address_terms_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    terms: object,
    *,
    width: object,
) -> RealModeIndexedStackAddress8616 | None:
    displacement: object
    matched_index: object
    normalized_terms: object
    index: object
    sign: object
    term: object
    fact_sizes = _indexed_bp_stack_fact_sizes_8616(codegen, project)
    if not fact_sizes:
        return None
    matched_index = None
    matched_displacement: int | None = None
    for index, (sign, term) in enumerate(terms):
        displacement = _indexed_bp_term_displacement_8616(codegen, sign, term)
        if displacement is None or displacement not in fact_sizes:
            continue
        matched_index = index
        matched_displacement = displacement
        break
    if matched_index is None or not isinstance(matched_displacement, int):
        return None

    residual_terms = tuple(term for index, term in builtins.iter(enumerate(terms)) if operator.ne(index, matched_index))
    normalized_terms = consume_indexed_stack_frame_terms_8616(
        codegen, residual_terms,
        segment_name=lambda term: _segment_base_name_8616(term, project, codegen),
    )
    if normalized_terms is None:
        return None
    residual_terms = normalized_terms
    if width is None:
        width = _infer_indexed_access_width_8616(
            residual_terms, fact_sizes.get(matched_displacement, frozenset())
        )
    return RealModeIndexedStackAddress8616(
        base_displacement=matched_displacement,
        residual_terms=residual_terms,
        width=width,
    )


@cython.ccall
def _match_indexed_bp_stack_address_8616(project: StructuredAstValue, codegen: StructuredAstValue, node: StructuredAstValue) -> RealModeIndexedStackAddress8616 | None:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None
    terms = _flatten_indexed_stack_address_terms_8616(getattr(node, "operand", None))
    if not terms:
        return None
    width = _dereference_access_width_bytes_8616(node)
    return _match_indexed_bp_stack_address_terms_8616(codegen, project, terms, width=width)


@cython.ccall
def _match_indexed_bp_stack_pointer_8616(project: StructuredAstValue, codegen: StructuredAstValue, node: StructuredAstValue) -> RealModeIndexedStackAddress8616 | None:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    call_name = _call_name_from_expr_8616(node)
    if call_name not in {"SEG_PTR", "MK_FP"}:
        return None
    args = _boundary_tuple_8616(node.args or ())
    if len(args) != 2:
        return None
    segment_name = _segment_base_name_8616(args[0], project, codegen)
    if segment_name not in {"ss", "ds"}:
        return None
    terms = _flatten_indexed_stack_address_terms_8616(args[1])
    if not terms:
        return None
    return _match_indexed_bp_stack_address_terms_8616(codegen, project, terms, width=1)


@cython.ccall
def _term_expr_with_sign_8616(codegen: StructuredAstValue, sign: cython.longlong, term: StructuredAstValue) -> StructuredAstValue:
    value: object
    value = _constant_value_8616(term)
    if value is not None:
        signed_value = int(sign) * int(value)
        return structured_c.CConstant(
            signed_value,
            SimTypeShort(signed=signed_value < 0),
            codegen=codegen,
        )
    if sign == 1:
        return term
    return structured_c.CBinaryOp(
        "Sub",
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        term,
        codegen=codegen,
    )


@cython.ccall
def _residual_terms_expr_8616(codegen: StructuredAstValue, terms: object) -> StructuredAstValue:
    expr: object
    sign: object
    term: object
    expr = None
    for sign, term in terms:
        term_expr = _term_expr_with_sign_8616(codegen, sign, term)
        expr = term_expr if expr is None else structured_c.CBinaryOp("Add", expr, term_expr, codegen=codegen)
    return expr


@cython.ccall
def _materialize_indexed_bp_stack_pointer_8616(project: StructuredAstValue, codegen: StructuredAstValue, access: RealModeIndexedStackAddress8616) -> StructuredAstValue:
    """Build an addressable stack pointer whose arithmetic stays byte-scaled."""
    base_cvar: object
    residual: object
    base_cvar = stack_cvar_for_stable_ss_linear_access_8616(
        codegen,
        RealModeLinearStackAccess8616(access.base_displacement, 1),
        require_lvalue=True,
    )
    if base_cvar is None:
        return None
    byte_ptr_type = SimTypePointer(SimTypeChar(False, label="unsigned char")).with_arch(project.arch)
    addr_expr = CSemanticCast8616(
        None,
        byte_ptr_type,
        structured_c.CUnaryOp("Reference", base_cvar, codegen=codegen),
        codegen=codegen,
    )
    residual = _residual_terms_expr_8616(codegen, access.residual_terms)
    if residual is not None:
        addr_expr = structured_c.CBinaryOp("Add", addr_expr, residual, codegen=codegen)
    codegen._inertia_indexed_bp_stack_address_materialized_count_8616 = (
        int(getattr(codegen, "_inertia_indexed_bp_stack_address_materialized_count_8616", 0) or 0) + 1
    )
    return addr_expr


@cython.ccall
def _materialize_indexed_bp_stack_address_8616(project: StructuredAstValue, codegen: StructuredAstValue, access: RealModeIndexedStackAddress8616) -> StructuredAstValue:
    """Preserve the proven load width even when cosmetic casts are hidden."""
    addr_expr: object
    width = access.width if isinstance(access.width, int) and access.width > 0 else 1
    addr_expr = _materialize_indexed_bp_stack_pointer_8616(project, codegen, access)
    if addr_expr is None:
        return None
    access_type = SimTypeChar(False, label="unsigned char") if width == 1 else _type_for_access_width_8616(width)
    access_ptr_type = SimTypePointer(access_type).with_arch(project.arch)
    cast_addr = CSemanticCast8616(None, access_ptr_type, addr_expr, codegen=codegen)
    deref = structured_c.CUnaryOp("Dereference", cast_addr, codegen=codegen)
    with contextlib.suppress(Exception):
        cast(Any, deref).type = access_type
    return deref

@cython.dataclasses.dataclass
class _SSLinearLowerRun8616:
    """One SS-linear stack-dereference lowering pass over a structured tree.

    Carries the instruction-access index cache, the evidence lane, and the
    candidate/materialized/refused counters shared by the transform walkers.
    """

    codegen: StructuredAstValue
    project: StructuredAstValue
    instruction_bp_access_lane: SemanticLaneState
    instruction_bp_access_index: InstructionBpStackAccessIndex8616 | None = None
    changed: cython.bint = False
    candidate_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    refused_count: cython.longlong = 0
    node_count_cell: cython.longlong = 0
    seen: object = field(default_factory=set)


    @cython.ccall
    def _instruction_bp_stack_access_8616(self, 
        node: StructuredAstValue,
        shaped_access: RealModeLinearStackAccess8616,
        *, require_lvalue: cython.bint,
    ) -> object:
        """Bind one SS-shaped access to its exact direct BP instruction operand."""
        access_index: object
        exact: object
        source_addrs = instruction_addrs_from_node_8616(node)
        if not source_addrs:
            return None
        access_index = self._bp_access_index_8616()
        if access_index is None:
            return None
        exact = select_instruction_bp_stack_access_8616(
            access_index,
            source_addrs,
            displacement=shaped_access.displacement,
            size=shaped_access.width if isinstance(shaped_access.width, int) else 0,
            kind=StackMemoryAliasFactKind8616.STORE if require_lvalue else StackMemoryAliasFactKind8616.LOAD,
        )
        if exact is None:
            return None
        shaped_width = shaped_access.width if isinstance(shaped_access.width, int) else 0
        owner_hint = self._logical_owner_hint_8616(source_addrs, shaped_access, shaped_width, exact)
        exact = self._projected_exact_access_8616(source_addrs, shaped_access, shaped_width, exact)
        if exact is None:
            return None
        self.instruction_bp_access_lane.raw += 1
        self.instruction_bp_access_lane.normalized += 1
        size = exact.size
        width = shaped_access.width if isinstance(shaped_access.width, int) and shaped_access.width > 0 else size
        logical_same_base_owner = bool(
            exact.evidence is InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS
            and size > width > 0
        )
        if size > 0 and width > 0 and size != width and not logical_same_base_owner:
            return None
        self.instruction_bp_access_lane.classified += 1
        return exact, owner_hint

    @cython.ccall
    def _bp_access_index_8616(self) -> StructuredAstValue | None:
        """Lazily build the instruction-level BP access index, or None."""
        if self.instruction_bp_access_index is None:
            try:
                source_alias = self.codegen._inertia_stack_memory_ssa_alias_artifact
            except AttributeError:
                return None
            if not isinstance(source_alias, StackMemorySSAAliasArtifact8616):
                return None
            self.instruction_bp_access_index = ensure_instruction_bp_stack_access_index_8616(
                self.codegen,
                source_alias,
            )
        return self.instruction_bp_access_index

    @cython.ccall
    def _logical_owner_hint_8616(
        self,
        source_addrs: StructuredAstValue,
        shaped_access: RealModeLinearStackAccess8616,
        shaped_width: cython.longlong,
        exact: StructuredAstValue,
    ) -> StackValueOwnerHint8616 | None:
        """Derive the owner-range hint from logical-access candidates."""
        assert self.instruction_bp_access_index is not None
        logical_owner_ranges = {
            StackValueOwnerHint8616(candidate.displacement, candidate.size)
            for source_addr in iter(source_addrs)
            for candidate in builtins.iter(self.instruction_bp_access_index.by_instruction_addr.get(
                source_addr,
                (),
            ))
            if candidate.evidence
            is InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS
            and candidate.kind is exact.kind
            and candidate.displacement <= shaped_access.displacement
            and candidate.displacement + candidate.size
            >= shaped_access.displacement + shaped_width
        }
        if len(logical_owner_ranges) == 1:
            return next(iter(logical_owner_ranges))
        if exact.evidence is InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS:
            return StackValueOwnerHint8616(exact.displacement, exact.size)
        return None

    @cython.ccall
    def _projected_exact_access_8616(
        self,
        source_addrs: StructuredAstValue,
        shaped_access: RealModeLinearStackAccess8616,
        shaped_width: cython.longlong,
        exact: StructuredAstValue,
    ) -> StructuredAstValue | None:
        """Refine a logical access to the projected execution slice, or None to refuse."""
        assert self.instruction_bp_access_index is not None
        if not (
            exact.evidence is InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS
            and operator.ne(exact.displacement, shaped_access.displacement)
            and shaped_width > 0
        ):
            return exact
        entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(
            self.codegen,
            exact.displacement,
            exact.size,
        )
        relative_offset = (
            shaped_access.displacement - entry_sp_offset
            if isinstance(entry_sp_offset, int)
            else -1
        )
        projected_displacement = exact.displacement + relative_offset
        if not 0 <= relative_offset <= exact.size - shaped_width:
            return None
        if not relative_offset:
            return exact
        projected = {
            candidate
            for source_addr in iter(source_addrs)
            for candidate in builtins.iter(self.instruction_bp_access_index.by_instruction_addr.get(
                source_addr,
                (),
            ))
            if candidate.evidence
            is InstructionBpStackAccessEvidence8616.EXECUTION_SLICE
            and operator.eq(candidate.displacement, projected_displacement)
            and operator.eq(candidate.size, shaped_width)
            and candidate.kind is exact.kind
        }
        if len(projected) != 1:
            return None
        return next(iter(projected))

    @cython.ccall
    def transform(self, node: StructuredAstValue, *, require_lvalue: cython.bint = False) -> StructuredAstValue:
        """Materialize proven SS accesses without substituting read projections for writes."""
        out: object
        stripped_node = _strip_casts_8616(node)
        if isinstance(stripped_node, structured_c.CFunctionCall):
            self._transform_call_args_8616(stripped_node)
        if not (
            (isinstance(stripped_node, structured_c.CUnaryOp) and stripped_node.op == "Dereference")
            or isinstance(stripped_node, structured_c.CFunctionCall)
        ):
            return node
        self.candidate_count += 1
        if isinstance(stripped_node, structured_c.CUnaryOp) and stripped_node.op == "Dereference":
            out = self._transform_deref_8616(node, stripped_node, require_lvalue=require_lvalue)
            if out is not None:
                return out
        elif isinstance(stripped_node, structured_c.CFunctionCall):
            out = self._transform_indexed_pointer_8616(stripped_node)
            if out is not None:
                return out
        self.refused_count += 1
        return node

    @cython.ccall
    def _transform_call_args_8616(self, stripped_node: StructuredAstValue) -> None:
        """Rewrite non-pointer intrinsic call arguments in place."""
        arg: object
        index: object
        if isinstance(stripped_node, structured_c.CFunctionCall):
            call_name = _call_name_from_expr_8616(stripped_node)
            if call_name not in {"SEG_PTR", "MK_FP"}:
                args = stripped_node.args
                if isinstance(args, list):
                    for index, arg in enumerate(tuple(args)):
                        replacement = self.transform(arg)
                        if replacement is not arg:
                            args[index] = replacement
                            self.changed = True
                elif isinstance(args, tuple):
                    new_args = []
                    args_changed = False
                    for arg in args:
                        replacement = self.transform(arg)
                        if replacement is not arg:
                            args_changed = True
                        new_args.append(replacement)
                    if args_changed:
                        stripped_node.args = tuple(new_args)
                        self.changed = True

    @cython.ccall
    def _transform_deref_8616(
        self,
        node: StructuredAstValue,
        stripped_node: StructuredAstValue,
        *,
        require_lvalue: cython.bint,
    ) -> StructuredAstValue | None:
        """Materialize a proven ``Dereference`` SS access; ``None`` means fall through."""
        access: object
        cvar: object
        instruction_access: object
        instruction_selection: object
        materialized: object
        access = match_stable_ss_linear_stack_access_8616(stripped_node, self.project, self.codegen)
        if access is not None:
            if not _has_stack_storage_evidence_for_displacement_8616(
                self.codegen,
                access.displacement,
                access.width,
            ):
                materialized = self._materialize_indexed_deref_8616(stripped_node)
                if materialized is not None:
                    return materialized
            instruction_selection = self._instruction_bp_stack_access_8616(
                stripped_node,
                access,
                require_lvalue=require_lvalue,
            )
            instruction_access = (
                instruction_selection[0]
                if instruction_selection is not None
                else None
            )
            owner_hint = (
                instruction_selection[1]
                if instruction_selection is not None
                else None
            )
            if instruction_access is not None:
                access = RealModeLinearStackAccess8616(
                    displacement=instruction_access.displacement,
                    width=instruction_access.size,
                )
            cvar = stack_cvar_for_stable_ss_linear_access_8616(
                self.codegen,
                access,
                instruction_access=instruction_access,
                owner_hint=owner_hint,
                require_lvalue=require_lvalue,
            )
            if cvar is None:
                if instruction_access is not None:
                    self.instruction_bp_access_lane.failures += 1
                self.refused_count += 1
                return node
            if instruction_access is not None:
                self.instruction_bp_access_lane.materialized += 1
            self.changed = True
            self.materialized_count += 1
            return cvar
        return self._materialize_indexed_deref_8616(stripped_node)

    @cython.ccall
    def _materialize_indexed_deref_8616(self, stripped_node: StructuredAstValue) -> StructuredAstValue | None:
        """Materialize a proven indexed BP stack address; ``None`` means fall through."""
        indexed_access: object
        materialized: object
        indexed_access = _match_indexed_bp_stack_address_8616(self.project, self.codegen, stripped_node)
        if indexed_access is None:
            return None
        materialized = _materialize_indexed_bp_stack_address_8616(self.project, self.codegen, indexed_access)
        if materialized is None:
            return None
        self.changed = True
        self.materialized_count += 1
        return materialized

    @cython.ccall
    def _transform_indexed_pointer_8616(self, stripped_node: StructuredAstValue) -> StructuredAstValue | None:
        """Materialize a proven indexed BP stack pointer call; ``None`` means fall through."""
        indexed_pointer: object
        materialized: object
        indexed_pointer = _match_indexed_bp_stack_pointer_8616(self.project, self.codegen, stripped_node)
        if indexed_pointer is not None:
            materialized = _materialize_indexed_bp_stack_pointer_8616(self.project, self.codegen, indexed_pointer)
            if materialized is not None:
                self.changed = True
                self.materialized_count += 1
                return materialized
        return None


    @cython.ccall
    def replace_children(self, node: StructuredAstValue) -> cython.bint:
        """Visit expression-bearing fields, including loads returned directly."""
        attr: object
        if not _structured_codegen_node_8616(node):
            return False
        self.node_count_cell += 1
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE") and self.node_count_cell % 500 == 0:
            print(f"[lower_ss_linear] tree walk: {self.node_count_cell} nodes", file=sys.stderr, flush=True)
        if id(node) in self.seen:
            return False
        self.seen.add(id(node))
        local_changed = False
        for attr in (
            "statements", "lhs", "rhs", "operand", "variable", "index", "expr", "stmts",
            "init", "initializer", "condition", "cond", "iftrue", "iffalse", "iteration",
            "iterator", "body", "else_node", "retval", "switch", "cases", "default",
        ):
            if self._replace_named_child_8616(node, attr):
                local_changed = True
        if self._replace_condition_pairs_8616(node):
            local_changed = True
        return local_changed

    @cython.ccall
    def _replace_named_child_8616(self, node: StructuredAstValue, attr: object) -> cython.bint:
        """Transform one named child field (dict, sequence, or scalar)."""
        value: object
        if not hasattr(node, attr):
            return False
        value = getattr(node, attr)
        if isinstance(value, dict):
            return self._replace_dict_children_8616(value)
        if isinstance(value, (list, tuple)):
            return self._replace_seq_children_8616(node, attr, value)
        return value is not None and self._replace_scalar_child_8616(node, attr, value)

    @cython.ccall
    def _replace_dict_children_8616(self, value: object) -> cython.bint:
        """Transform each dict-valued child in place."""
        item: object
        key: object
        local_changed = False
        for key, item in tuple(value.items()):
            replacement = self.transform(item)
            if replacement is not item:
                value[key] = replacement
                local_changed = True
            if self.replace_children(value[key]):
                local_changed = True
        return local_changed

    @cython.ccall
    def _replace_seq_children_8616(self, node: StructuredAstValue, attr: object, value: StructuredAstValue) -> cython.bint:
        """Transform list/tuple-valued children, writing back tuples."""
        index: object
        item: object
        local_changed = False
        if isinstance(value, list):
            for index, item in enumerate(tuple(value)):
                replacement = self.transform(item)
                if replacement is not item:
                    value[index] = replacement
                    local_changed = True
                if self.replace_children(value[index]):
                    local_changed = True
        elif isinstance(value, tuple):
            new_items = []
            tuple_changed = False
            for item in value:
                replacement = self.transform(item)
                if replacement is not item:
                    tuple_changed = True
                if self.replace_children(replacement):
                    tuple_changed = True
                new_items.append(replacement)
            if tuple_changed:
                setattr(node, attr, tuple(new_items))
                local_changed = True
        return local_changed

    @cython.ccall
    def _replace_scalar_child_8616(self, node: StructuredAstValue, attr: object, value: StructuredAstValue) -> cython.bint:
        """Transform a scalar child field and recurse into it."""
        replacement = self.transform(
            value, require_lvalue=isinstance(node, structured_c.CAssignment) and attr == "lhs",
        )
        local_changed = False
        if replacement is not value:
            setattr(node, attr, replacement)
            local_changed = True
            value = replacement
        if self.replace_children(value):
            local_changed = True
        return local_changed

    @cython.ccall
    def _replace_condition_pairs_8616(self, node: StructuredAstValue) -> cython.bint:
        """Transform structured condition/body pairs on the node."""
        condition_and_nodes: object
        body: object
        cond: object
        local_changed = False
        condition_and_nodes = getattr(node, "condition_and_nodes", None)
        if condition_and_nodes:
            new_pairs = []
            pair_changed = False
            for cond, body in condition_and_nodes:
                new_cond = (
                    self.transform(cond)
                    if _structured_codegen_node_8616(cond)
                    else cond
                )
                new_body = (
                    self.transform(body)
                    if _structured_codegen_node_8616(body)
                    else body
                )
                if new_cond is not cond:
                    pair_changed = True
                    local_changed = True
                if new_body is not body:
                    pair_changed = True
                    local_changed = True
                if self.replace_children(new_cond):
                    local_changed = True
                if self.replace_children(new_body):
                    local_changed = True
                new_pairs.append((new_cond, new_body))
            if pair_changed:
                cast(Any, node).condition_and_nodes = new_pairs
        return local_changed


    @cython.ccall
    def _publish_counters_8616(self) -> None:
        """Publish pass counters to the codegen surface and debug stats."""
        debug_stats: object
        codegen = self.codegen
        codegen._inertia_ss_linear_candidate_count = (
            int(getattr(codegen, "_inertia_ss_linear_candidate_count", 0) or 0) + self.candidate_count
        )
        codegen._inertia_ss_linear_materialized_count = (
            int(getattr(codegen, "_inertia_ss_linear_materialized_count", 0) or 0) + self.materialized_count
        )
        codegen._inertia_ss_linear_refused_count = (
            int(getattr(codegen, "_inertia_ss_linear_refused_count", 0) or 0) + self.refused_count
        )
        debug_stats = getattr(codegen, "_inertia_stack_lowering_debug", None)
        if isinstance(debug_stats, dict):
            debug_stats["ss_linear_candidates"] = int(debug_stats.get("ss_linear_candidates", 0) or 0) + self.candidate_count
            debug_stats["ss_linear_materialized"] = (
                int(debug_stats.get("ss_linear_materialized", 0) or 0) + self.materialized_count
            )
            debug_stats["ss_linear_refused"] = int(debug_stats.get("ss_linear_refused", 0) or 0) + self.refused_count
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[ss-linear-lowering] function=%#x candidates=%d materialized=%d refused=%d changed=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                self.candidate_count,
                self.materialized_count,
                self.refused_count,
                self.changed,
            )


@cython.ccall
def lower_stable_ss_linear_stack_dereferences_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue | None = None,
    function: StructuredAstValue | None = None,
) -> cython.bint:
    """Replace stable SS real-mode linear dereferences with stack variables."""
    root: object
    if project is None:
        project = getattr(codegen, "project", None)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    codegen._inertia_assignment_maps = None
    codegen._inertia_stack_offset_cache = None

    word_load_result = materialize_stack_word_load_recompositions_8616(
        codegen,
        root,
    )
    if word_load_result.root is not root:
        codegen.cfunc.statements = word_load_result.root
        root = word_load_result.root
    instruction_bp_access_lane = SemanticLaneState(name="instruction_bp_stack_access")
    codegen._inertia_instruction_bp_stack_access_lane_8616 = instruction_bp_access_lane

    run = _SSLinearLowerRun8616(
        codegen=codegen,
        project=project,
        instruction_bp_access_lane=instruction_bp_access_lane,
        changed=bool(word_load_result.changed),
    )
    if run.replace_children(root):
        run.changed = True
    if _apply_annotation_names_to_existing_stack_cvars_8616(codegen):
        run.changed = True
    run._publish_counters_8616()
    instruction_bp_access_lane.assert_closed_loop(layer="lowering")
    return run.changed


__all__ = (
    "DirectGlobalUpdateFact8616",
    "DirectStackMoveFact8616",
    "DirectStackUpdateFact8616",
    "DirectStackWriteClassification8616",
    "DirectStackWriteInventory8616",
    "DirectStackWriteSite8616",
    "RealModeLinearGlobalAddress8616",
    "RealModeLinearStackAccess8616",
    "_direct_stack_move_materialized_ins_addrs_8616",
    "lower_stable_ds_es_linear_global_addresses_8616",
    "lower_stable_ds_es_linear_global_dereferences_8616",
    "lower_stable_ss_linear_stack_dereferences_8616",
    "match_stable_ds_es_linear_global_access_8616",
    "match_stable_ds_es_linear_global_address_8616",
    "match_stable_ss_linear_stack_access_8616",
    "materialize_direct_global_incdec_instructions_8616",
    "materialize_direct_stack_incdec_instructions_8616",
    "materialize_direct_stack_mov_instructions_8616",
    "prune_callee_saved_stack_spills_8616",
    "prune_materialized_call_push_stack_assignments_8616",
)
