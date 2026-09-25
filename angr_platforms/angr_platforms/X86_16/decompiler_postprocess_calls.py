"""Legacy callsite cleanup and materialization bridge.

Layer: Rewrite/Postprocess cleanup.
Responsibility: consume structured callsite evidence as a guarded compatibility shim.

This module currently normalizes rendered call targets, attaches callsite
summaries, materializes stack arguments, repairs some missing direct calls, and
prunes call-argument remnants. Some of that is valid late cleanup, but much of
it is migration debt from semantics that should already be explicit before C
rewrite.

Dynamic boundary: angr codegen and C AST nodes expose third-party attributes at
runtime, so access to those objects remains guarded. `CallsiteSummary8616`,
typed evidence records, enums, and materialization state are owned contracts;
they must use direct attributes so contract drift fails clearly.
Accepted logical-shape publication is owned by Lowering, not this bridge.
Whole-function return-carrier use checks are also Lowering-owned: this bridge
only consumes their veto before its legacy destination fold. Move that fold
out of this module during migration; do not add liveness recovery here.

Ownership rule:
- This file is a compatibility migration shim.
- It should only consume already-proven evidence from earlier pipeline layers.
- If this layer is implemented in alias/IR/structuring/lowering and the caller
  can no longer prove anything missing, delete this module's semantic repairs
  and keep only tiny, evidence-gated cleanup.
- If this module becomes a source of branch/stack/call truth, it is no longer in
  the right layer.

Allowed work in this file:
- consume callsite summaries, source/COD labels, prototypes, and stack-probe
  facts that were already collected elsewhere;
- normalize call node names and metadata without changing call semantics;
- prune duplicate carrier artifacts only when the consumed evidence is recorded
  and tail validation accepts the change.

Debt that must move earlier:
- call target discovery belongs in CFG/function recovery and callsite summary;
- argument value and pointer/value-class recovery belongs in IR/alias/stack
  lowering, not rendered-call repair;
- stack-probe and helper signatures belong in compiler-helper semantics;
- source/COD call floors are optional evidence gates, not primary recovery.

Do not add new source-text, symbol-name, or sequence-shaped call recovery here.
New fixes must make the binary evidence explicit in the owning layer, then let
this module consume that structured evidence. Missing proof means keep the ugly
call and let validation/reporting expose the gap.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from copy import copy
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CDirtyExpression,
    CFunctionCall,
    CIndexedVariable,
    CTypeCast,
    CUnaryOp,
)
from angr.sim_type import SimType, SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from inertia_decompiler.telemetry import span

from .analysis_helpers import (
    CallTargetKind8616,
    CallTargetSeed,
    collect_neighbor_call_targets,
    patch_direct_call_sites,
    preferred_known_helper_signature_decl,
)
from .annotations import ANNOTATION_KEY, _parse_c_prototype_8616
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_argument_value_sources import (
    call_argument_stack_value_source_8616,
)
from .callsite_pointer_values import consume_near_pointer_argument_value_8616
from .callsite_stack_metadata import (
    _generic_stack_carrier_keys_8616,
    _stack_carrier_key_8616,
    prune_materialized_callsite_segment_metadata_8616,
)
from .callsite_summary import (
    CallerReturnUseVerdict8616,
    CallsitePushExprOp8616,
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
    CallsiteTargetInventory8616,
    StructuredCallKind8616,
    bind_structured_callsite_identity_8616,
    known_helper_abi_widths_8616,
    logical_argument_widths_from_callsite_8616,
    structured_call_kind_8616,
    structured_callsite_addr_8616,
    structured_callsite_target_addr_8616,
    summarize_x86_16_callsite,
)
from .callsite_summary_program import (
    retained_program_callsite_summary_inventory_8616,
)
from .cod_extract import extract_cod_proc_metadata
from .codegen_metadata import set_codegen_sequence_attr
from .compiler_helpers import is_x86_16_stack_probe_helper_at_8616, is_x86_16_stack_probe_name_8616
from .decompiler_postprocess import _normalize_arg_names_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _match_bp_stack_dereference_8616,
    _match_bp_stack_load_8616,
    _match_real_mode_linear_expr_8616,
    _match_real_mode_segmented_store_shape_8616,
    _match_segmented_dereference_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
)
from .frontend_block_inventory import decoded_function_callsite_addresses_8616
from .lowering.call_argument_call_preservation import classify_call_argument_call_preservation_8616
from .lowering.call_argument_expression import (
    CALL_ARGUMENT_INTEGER_OPERATION_NAMES_8616,
    CALL_ARGUMENT_SOURCE_OPERATION_NAMES_8616,
    call_argument_has_materialized_object_address_8616,
    materialize_call_argument_operations_8616,
)
from .lowering.call_argument_semantic_gap import (
    has_call_argument_semantic_gap_8616,
    has_literal_push_stack_carrier_8616,
)
from .lowering.call_argument_semantic_token import (
    call_argument_semantic_token_8616 as _call_arg_semantic_key_8616,
)
from .lowering.call_argument_shape import (
    CallerStackObject8616,
    LogicalArgumentShapeEvidence8616,
    LogicalArgumentShapeEvidenceSource8616,
    ProtectedCallArgumentStore8616,
    accounted_target_prototype_shape_evidence_8616,
    accounted_variadic_target_shape_evidence_8616,
    carry_forward_logical_call_argument_shape_8616,
    classify_callsite_zero_argument_ownership_8616,
    exact_call_return_pair_shape_evidence_8616,
    exact_caller_stack_object_for_word_pair_8616,
    exact_caller_stack_object_shape_evidence_8616,
    reconcile_materialized_call_argument_shape_8616,
)
from .lowering.call_argument_shape_publication import publish_reconciled_call_argument_shape_8616
from .lowering.call_argument_stack_sources import (
    PushStoreWidthVerdict8616,
    call_argument_source_requires_exact_address_identity_8616,
    call_argument_stack_variable_offset_8616,
    classify_push_store_width_8616,
    containing_stack_cvariable_8616,
    iter_stack_cvariable_candidates_8616,
    materialize_call_argument_stack_cvariable_8616,
    outgoing_call_stack_carrier_offset_8616,
)
from .lowering.call_return_selectors import is_scalar_ax_call_return_8616
from .lowering.call_return_stack_bindings import call_result_escapes_group_8616
from .lowering.callsite_inventory_presence import represented_callsite_addrs_8616
from .lowering.function_pointer_parameters import materialize_function_pointer_parameters_8616
from .lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    _is_consumed_push_ss_store_lhs_8616,
    _stack_offset_from_expr_8616,
    match_stable_ds_es_linear_global_access_8616,
    prune_call_return_frame_stack_assignments_8616,
    prune_materialized_call_push_stack_assignments_8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from .lowering.runtime_call_results import (
    RuntimeCallResultVerdict8616,
    materialize_runtime_call_result_read_8616,
)
from .lowering.segmented_global_loads import (
    _collect_direct_global_symbol_refs_8616,
    _collect_synthetic_direct_global_symbol_refs_8616,
    _make_direct_global_symbol_expr_8616,
    _merge_direct_global_symbol_refs_8616,
)
from .lowering.stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from .pipeline.errors import PipelineHardError
from .postprocess.call_argument_transaction import (
    CallArgumentMutationResult8616,
    accepted_call_argument_mutation_8616,
    refused_call_argument_mutation_8616,
)
from .stack_probe_fact_trace import (
    ensure_stack_probe_fact_stats_8616,
    record_callsite_summary_fact_8616,
    record_callsite_summary_map_facts_8616,
    record_stack_arg_materialization_8616,
)
from .structuring.simple_loop_recovery import _function_instruction_summaries_8616

__all__ = [
    "_attach_callsite_summaries_8616",
    "_bind_call_return_frame_argument_lowerer_8616",
    "_bind_call_target_identity_consumer_8616",
    "_bind_callee_pointer_argument_classifier_8616",
    "_bind_fixed_stack_probe_frame_lowerer_8616",
    "_bind_function_result_observation_provider_8616",
    "_bind_segment_address_provenance_attacher_8616",
    "_bind_segment_push_source_lowerer_8616",
    "_materialize_callsite_prototypes_8616",
    "_materialize_callsite_stack_arguments_8616",
    "_materialize_stdlib_call_chains_8616",
    "_normalize_call_target_names_8616",
    "_prune_scalar_global_high_byte_call_arg_remnants_8616",
    "_recover_missing_direct_calls_from_evidence_8616",
    "_replay_call_target_identity_consumer_8616",
    "prune_consumed_segmented_stack_byte_arg_stores_8616",
    "replay_callsite_stack_arguments_after_regeneration_8616",
]

type AngrProjectValue = Any
type AngrFunctionValue = Any
type StructuredCodegenValue = Any
type StructuredAstValue = Any

_SUB_TARGET_RE = re.compile(r"^(?:sub_|0x)(?P<addr>[0-9a-fA-F]+)$")
_NAMESPACED_TARGET_RE = re.compile(r"^::0x(?P<addr>[0-9a-fA-F]+)::")
log: logging.Logger = logging.getLogger(__name__)
_RUNTIME_SEGMENT_HELPERS_8616 = frozenset(
    {"SEG_U8", "SEG_U16", "SEG_U32", "MK_FP", "SEG_PTR", "MEM_U8", "MEM_U16", "MEM_U32"}
)


class SegmentPushSourceLowerer8616(Protocol):
    """Types/Lowering service used to materialize one proven segment PUSH."""

    def __call__(
        self,
        segment_name: str,
        *,
        codegen: object,
        variable_type: SimType | None,
        function_addr: int,
    ) -> structured_c.CVariable | None:
        """Return the explicit runtime-state C carrier for a proven segment source."""


class SegmentAddressProvenanceAttacher8616(Protocol):
    """Types/Lowering service preserving exact callsite PUSH provenance."""

    def __call__(self, args: tuple[object, ...], instruction_addrs: tuple[int, ...]) -> None:
        """Attach exact source sites without recovering new call semantics."""


class FixedStackProbeFrameLowerer8616(Protocol):
    """Types/Lowering service for consuming proven fixed stack probes."""

    def __call__(self, codegen: object) -> bool:
        """Return whether a proven fixed probe was lowered into C locals."""
        ...


class FunctionResultObservationProvider8616(Protocol):
    """Types/Lowering service for one closed caller-result observation."""

    def __call__(self, project: object, function_addr: int) -> CallerReturnUseVerdict8616 | None:
        """Return whether binary callers provably use or ignore the result."""
        ...


class CallTargetIdentityConsumer8616(Protocol):
    """Types/Lowering service for replaying proven direct-call identities."""

    def __call__(
        self,
        project: object,
        codegen: object,
    ) -> bool:
        """Apply only call-target identities already proven by typed evidence."""
        ...


class CallArgumentRematerializationClassifier8616(Protocol):
    """Types/Lowering service for rejecting unresolved call arguments."""

    def __call__(self, argument: object) -> bool:
        """Return whether closed Lowering evidence requires rematerialization."""
        ...


type CallArgumentSetupLivenessClassifier8616 = Callable[
    [tuple[StructuredAstValue, ...] | None, frozenset[tuple[StructuredAstValue, ...]]],
    bool,
]


class CallsiteArgumentReplayConsumer8616(Protocol):
    """Structuring service that reapplies typed arguments after regeneration."""

    def __call__(
        self,
        project: object,
        codegen: object,
        *,
        preserve_setup: bool = False,
    ) -> bool:
        """Replay already-proven callsite facts onto the current C AST."""
        ...


class CallReturnFrameArgumentLowerer8616(Protocol):
    """Types/Lowering service consuming exact CALL-frame argument projections."""

    def __call__(self, project: object, codegen: object) -> bool:
        """Consume only Semantics-proven machine return-frame arguments."""
        ...


class CalleePointerArgumentClassifier8616(Protocol):
    """Types/Lowering service for one binary-proven pointer argument class."""

    def __call__(
        self,
        project: object,
        callee_name: str,
        argument_index: int,
    ) -> bool:
        """Return whether callee machine evidence proves a pointer argument."""
        ...


class _CalleePointerArgumentClassifierCarrier8616(Protocol):
    """Owned project extension carrying the lowering classifier service."""

    _inertia_callee_pointer_argument_classifier_8616: CalleePointerArgumentClassifier8616


class _CallsiteMaterializationControlCarrier8616(Protocol):
    """Typed Inertia call-materialization state carried by an angr codegen object."""

    _inertia_callsite_materialization_stats: CallsiteMaterializationStats
    _inertia_callsite_disable_consumed_arg_store_prune_8616: bool
    _inertia_callsite_consumed_arg_store_prune_refused_by_context_8616: int
    _inertia_callsite_disable_stack_probe_setup_prune_8616: bool
    _inertia_callsite_stack_probe_setup_prune_refused_by_context_8616: int
    _inertia_callsite_arg_regen_replay_active_8616: bool
    _inertia_postprocess_changed: bool
    _inertia_callsite_regen_replay_conservative_no_prune_8616: int
    _inertia_callsite_return_exprs_8616: dict[int, StructuredAstValue]
    _inertia_call_target_identity_consumer_8616: CallTargetIdentityConsumer8616
    _inertia_call_argument_rematerialization_classifier_8616: CallArgumentRematerializationClassifier8616
    _inertia_call_argument_setup_liveness_classifier_8616: CallArgumentSetupLivenessClassifier8616
    _inertia_callsite_argument_replay_consumer_8616: CallsiteArgumentReplayConsumer8616
    _inertia_segment_address_provenance_attacher_8616: SegmentAddressProvenanceAttacher8616
    _inertia_segment_push_source_lowerer_8616: SegmentPushSourceLowerer8616
    _inertia_fixed_stack_probe_frame_lowerer_8616: FixedStackProbeFrameLowerer8616
    _inertia_call_return_frame_argument_lowerer_8616: CallReturnFrameArgumentLowerer8616
    _inertia_function_result_observation_provider_8616: FunctionResultObservationProvider8616


def _bind_callee_pointer_argument_classifier_8616(
    project: object,
    classifier: CalleePointerArgumentClassifier8616,
) -> None:
    """Bind the Types/Lowering pointer-class service at the project boundary."""
    carrier = cast(_CalleePointerArgumentClassifierCarrier8616, project)
    carrier._inertia_callee_pointer_argument_classifier_8616 = classifier


def _bound_callee_pointer_argument_is_proven_8616(
    project: object,
    callee_name: str,
    argument_index: int,
) -> bool:
    """Consume the bound lowering classifier without owning pointer recovery."""
    try:
        classifier = cast(
            _CalleePointerArgumentClassifierCarrier8616,
            project,
        )._inertia_callee_pointer_argument_classifier_8616
    except AttributeError:
        return False
    return classifier(project, callee_name, argument_index)


def _bind_call_target_identity_consumer_8616(
    codegen: StructuredCodegenValue,
    consumer: CallTargetIdentityConsumer8616,
) -> None:
    """Bind the Types/Lowering call-target service at the dynamic codegen boundary."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_call_target_identity_consumer_8616 = consumer


def _bind_call_argument_rematerialization_classifier_8616(
    codegen: StructuredCodegenValue,
    classifier: CallArgumentRematerializationClassifier8616,
) -> None:
    """Bind the Types/Lowering argument-state classifier at the codegen boundary."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_call_argument_rematerialization_classifier_8616 = classifier


def _bind_call_argument_setup_liveness_classifier_8616(
    codegen: StructuredCodegenValue,
    classifier: CallArgumentSetupLivenessClassifier8616,
) -> None:
    """Bind the Types/Lowering setup-liveness service at the codegen boundary."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_call_argument_setup_liveness_classifier_8616 = classifier


def _bind_callsite_argument_replay_consumer_8616(
    codegen: StructuredCodegenValue,
    consumer: CallsiteArgumentReplayConsumer8616,
) -> None:
    """Bind the Structuring-owned replay service at the codegen boundary."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_callsite_argument_replay_consumer_8616 = consumer


def _replay_bound_callsite_argument_consumer_8616(
    project: object,
    codegen: StructuredCodegenValue,
    *,
    preserve_setup: bool = False,
) -> bool:
    """Invoke the required Structuring owner after a core AST regeneration."""
    try:
        consumer = cast(
            _CallsiteMaterializationControlCarrier8616,
            codegen,
        )._inertia_callsite_argument_replay_consumer_8616
    except AttributeError as ex:
        raise PipelineHardError(
            "Structuring-owned callsite argument replay is not bound; "
            "refusing Rewrite-layer semantic repair"
        ) from ex
    if preserve_setup:
        return bool(consumer(project, codegen, preserve_setup=True))
    return bool(consumer(project, codegen))


def _bound_call_argument_requires_rematerialization_8616(
    codegen: StructuredCodegenValue,
    argument: object,
) -> bool:
    """Consume the bound Lowering verdict without classifying arguments here."""
    try:
        classifier = cast(
            _CallsiteMaterializationControlCarrier8616,
            codegen,
        )._inertia_call_argument_rematerialization_classifier_8616
    except AttributeError:
        return False
    return classifier(argument)


def _replay_call_target_identity_consumer_8616(
    project: AngrProjectValue,
    codegen: StructuredCodegenValue,
) -> bool:
    """Replay the bound Types/Lowering target consumer after call AST rebuilding."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    try:
        consumer = carrier._inertia_call_target_identity_consumer_8616
    except AttributeError as exc:
        raise PipelineHardError(
            "call-target identity replay requires a Structuring-bound Types/Lowering consumer",
            layer="rewrite:callsite_compatibility",
        ) from exc
    return bool(consumer(project, codegen))


def _bind_segment_push_source_lowerer_8616(
    codegen: StructuredCodegenValue,
    lowerer: SegmentPushSourceLowerer8616,
) -> None:
    """Bind the Types/Lowering segment-source service at the dynamic codegen boundary."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_segment_push_source_lowerer_8616 = lowerer


def _bind_segment_address_provenance_attacher_8616(
    codegen: StructuredCodegenValue,
    attacher: SegmentAddressProvenanceAttacher8616,
) -> None:
    """Bind the Types/Lowering segment-address provenance service."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_segment_address_provenance_attacher_8616 = attacher


def _bind_fixed_stack_probe_frame_lowerer_8616(
    codegen: StructuredCodegenValue,
    lowerer: FixedStackProbeFrameLowerer8616,
) -> None:
    """Bind the Types/Lowering fixed stack-probe consumer."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_fixed_stack_probe_frame_lowerer_8616 = lowerer


def _bind_call_return_frame_argument_lowerer_8616(
    codegen: StructuredCodegenValue,
    lowerer: CallReturnFrameArgumentLowerer8616,
) -> None:
    """Bind the Types/Lowering CALL-frame argument consumer."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_call_return_frame_argument_lowerer_8616 = lowerer


def _replay_call_return_frame_argument_lowerer_8616(
    project: object,
    codegen: StructuredCodegenValue,
) -> bool:
    """Replay the bound CALL-frame consumer after summaries and tags converge."""
    try:
        lowerer = cast(
            _CallsiteMaterializationControlCarrier8616,
            codegen,
        )._inertia_call_return_frame_argument_lowerer_8616
    except AttributeError:
        # Unit-level compatibility callers may exercise this bridge without
        # the Structuring stage. Missing ownership means no semantic change.
        return False
    return bool(lowerer(project, codegen))


def _bind_function_result_observation_provider_8616(
    codegen: StructuredCodegenValue,
    provider: FunctionResultObservationProvider8616,
) -> None:
    """Bind the Types/Lowering caller-result evidence service."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    carrier._inertia_function_result_observation_provider_8616 = provider


def _bound_function_result_observation_8616(
    project: object,
    codegen: StructuredCodegenValue,
    function_addr: int,
) -> CallerReturnUseVerdict8616 | None:
    """Consume caller-result evidence without recovering it in postprocess."""
    try:
        provider = cast(
            _CallsiteMaterializationControlCarrier8616,
            codegen,
        )._inertia_function_result_observation_provider_8616
    except AttributeError:
        return None
    return provider(project, function_addr)


def _replay_fixed_stack_probe_frame_lowerer_8616(codegen: StructuredCodegenValue) -> bool:
    """Replay the bound Lowering consumer without owning its semantic proof."""
    try:
        lowerer = cast(
            _CallsiteMaterializationControlCarrier8616,
            codegen,
        )._inertia_fixed_stack_probe_frame_lowerer_8616
    except AttributeError:
        return False
    return lowerer(codegen)


def _ensure_callsite_materialization_controls_8616(
    codegen: StructuredCodegenValue,
) -> _CallsiteMaterializationControlCarrier8616:
    """Initialize and return the owned call-materialization control contract."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    for attr, default in (
        ("_inertia_callsite_disable_consumed_arg_store_prune_8616", False),
        ("_inertia_callsite_consumed_arg_store_prune_refused_by_context_8616", 0),
        ("_inertia_callsite_disable_stack_probe_setup_prune_8616", False),
        ("_inertia_callsite_stack_probe_setup_prune_refused_by_context_8616", 0),
        ("_inertia_callsite_arg_regen_replay_active_8616", False),
        ("_inertia_postprocess_changed", False),
        ("_inertia_callsite_regen_replay_conservative_no_prune_8616", 0),
    ):
        try:
            getattr(carrier, attr)
        except AttributeError:
            setattr(carrier, attr, default)
    try:
        return_exprs = carrier._inertia_callsite_return_exprs_8616
    except AttributeError:
        carrier._inertia_callsite_return_exprs_8616 = {}
    else:
        if not isinstance(return_exprs, dict):
            raise TypeError("callsite return-expression state must be a dict")
    return carrier


def _callsite_summary_inventory_8616(
    codegen: StructuredCodegenValue,
) -> dict[int, CallsiteSummary8616]:
    """Return the authoritative callsite inventory after validating its owned contract."""
    try:
        inventory = codegen._inertia_callsite_summary_inventory_8616
    except AttributeError:
        return {}
    if not isinstance(inventory, dict):
        raise TypeError("callsite summary inventory carrier must be a dict")
    for callsite_addr, summary in inventory.items():
        if not isinstance(callsite_addr, int) or not isinstance(summary, CallsiteSummary8616):
            raise TypeError("callsite summary inventory contains an invalid owned contract")
        if summary.callsite_addr != callsite_addr:
            raise TypeError(
                "callsite summary inventory key does not match the summary callsite address"
            )
    return inventory


def _tail_call_summary_from_seed_8616(seed: CallTargetSeed | None) -> CallsiteSummary8616 | None:
    """Project one frontend-proven external tail transfer into callsite evidence."""
    if seed is None or seed.kind not in {
        CallTargetKind8616.DIRECT_NEAR_TAIL_JUMP,
        CallTargetKind8616.DIRECT_FAR_TAIL_JUMP,
        CallTargetKind8616.STORED_NEAR_TAIL_JUMP,
    }:
        return None
    return CallsiteSummary8616(
        seed.callsite_addr,
        seed.target_addr,
        None,
        seed.kind.value,
        0,
        (),
        0,
        None,
        False,
    )


class CallsiteAliasArtifactDecision8616(Enum):
    """Evidence decision for pre-call stack-source alias artifacts."""

    PRUNE_BINARY_PUSH_EXPR_ALIAS = "prune_binary_push_expr_alias"
    KEEP_NO_BINARY_PUSH_EXPR_EVIDENCE = "keep_no_binary_push_expr_evidence"


class CallsiteMaterializationDecision8616(Enum):
    """Record the outcome of one guarded callsite materialization attempt."""

    CACHE_HIT = "cache_hit"
    PROCESSED_CHANGED = "processed_changed"
    PROCESSED_NO_CHANGE = "processed_no_change"
    REFUSED_NO_LIVE_SUMMARIZED_CALL = "refused_no_live_summarized_call"
    REFUSED_POINTER_MEMORY = "refused_pointer_memory"
    NOT_APPLICABLE = "not_applicable"


def _source_call_floor_enabled_8616() -> bool:
    return False


def _single_function_context_measuring_enabled_8616() -> bool:
    return os.environ.get("INERTIA_MEASURE_SINGLE_FUNCTION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}


def _structured_root_8616(cfunc: StructuredAstValue) -> StructuredAstValue:
    """Return the current codegen root before falling back to legacy body state."""
    # Dynamic angr boundary: ``statements`` is the canonical root updated by
    # lowering, while ``body`` may still reference the pre-lowering tree.
    statements = getattr(cfunc, "statements", None)
    if statements is not None:
        return statements
    body = getattr(cfunc, "body", None)
    return body if body is not None else cfunc


def _has_live_summarized_call_8616(
    root: StructuredAstValue,
    summary_map: Mapping[int, CallsiteSummary8616],
) -> bool:
    """Return whether the current AST still contains a summary-bound call."""
    return any(
        isinstance(node, CFunctionCall) and id(node) in summary_map
        for node in (root, *_iter_c_nodes_deep_8616(root))
    )


def _boundary_tuple_8616(value: StructuredAstValue) -> tuple[StructuredAstValue, ...]:
    """Normalize an optional dynamic angr collection to a typed tuple."""
    return tuple(value or ())


def _materialize_stdlib_call_chains_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:

    return __materialize_stdlib_call_chains_8616___impl(codegen=codegen)


def __materialize_stdlib_call_chains_8616___impl(*, codegen: StructuredAstValue) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    root = _structured_root_8616(cfunc)
    statements = getattr(root, "statements", None)
    if not isinstance(statements, list):
        return False




    changed = False
    idx = 0
    while idx + 1 < len(statements):
        first = statements[idx]
        second = statements[idx + 1]
        # Recover common C stdlib seeding chain when argument materialization
        # lost producer-consumer linkage between time() and srand().
        if __materialize_stdlib_call_chains_8616___is_zero_arg_call(first, "srand") and __materialize_stdlib_call_chains_8616___is_zero_arg_call(second, "time"):
            srand_call = getattr(first, "expr", None)
            time_call = getattr(second, "expr", None)
            if isinstance(srand_call, CFunctionCall) and isinstance(time_call, CFunctionCall):
                srand_call.args = [time_call]
                del statements[idx + 1]
                changed = True
                continue
        if __materialize_stdlib_call_chains_8616___is_zero_arg_call(first, "time") and __materialize_stdlib_call_chains_8616___is_zero_arg_call(second, "srand"):
            srand_call = getattr(second, "expr", None)
            time_call = getattr(first, "expr", None)
            if isinstance(srand_call, CFunctionCall) and isinstance(time_call, CFunctionCall):
                srand_call.args = [time_call]
                del statements[idx]
                changed = True
                continue
        idx += 1
    return changed



def __materialize_stdlib_call_chains_8616___call_name(stmt: StructuredAstValue) -> str | None:
    expr = getattr(stmt, "expr", None)
    if not isinstance(expr, CFunctionCall):
        return None
    name = normalize_callee_name_8616(_call_node_name_8616(expr))
    return name if isinstance(name, str) and name else None



def __materialize_stdlib_call_chains_8616___is_zero_constant(expr: StructuredAstValue) -> bool:
    value = getattr(expr, "value", None)
    if isinstance(value, int):
        return value == 0
    return type(expr).__name__ == "CConstant" and getattr(expr, "value", None) == 0



def __materialize_stdlib_call_chains_8616___is_zero_arg_call(stmt: StructuredAstValue, target_name: str) -> bool:
    expr = getattr(stmt, "expr", None)
    if not isinstance(expr, CFunctionCall):
        return False
    name = __materialize_stdlib_call_chains_8616___call_name(stmt)
    if name != target_name:
        return False
    args = _boundary_tuple_8616(expr.args or ())
    return len(args) == 1 and __materialize_stdlib_call_chains_8616___is_zero_constant(args[0])



def _sync_cfunc_root_statements_8616(
    cfunc: StructuredAstValue, root: StructuredAstValue, root_statements: StructuredAstValue
) -> None:

    return __sync_cfunc_root_statements_8616___impl(cfunc=cfunc, root=root, root_statements=root_statements)


def __sync_cfunc_root_statements_8616___impl(*, cfunc: StructuredAstValue, root: StructuredAstValue, root_statements: StructuredAstValue) -> None:
    cfunc_statements = getattr(cfunc, "statements", None)
    cfunc_body = getattr(cfunc, "body", None)
    body_statements = getattr(cfunc_body, "statements", None)
    if root is not cfunc and isinstance(root_statements, (list, tuple)):
        if hasattr(root, "statements"):
            with contextlib.suppress(Exception):
                cfunc.body = root
        if cfunc_statements is not root and hasattr(root, "c_repr_chunks"):
            with contextlib.suppress(Exception):
                cfunc.statements = root
        elif isinstance(cfunc_statements, (list, tuple)) and cfunc_statements is not root_statements:
            cfunc.statements = (
                list(root_statements) if isinstance(cfunc_statements, list) else tuple(root_statements)
            )
        if (
            cfunc_body is not None
            and isinstance(body_statements, (list, tuple))
            and body_statements is not root_statements
        ):
            cfunc_body.statements = (
                list(root_statements) if isinstance(body_statements, list) else tuple(root_statements)
            )



def _missing_calls_from_sequences_8616(
    source_call_names: list[str],
    expected_names: list[str],
    present_names: list[str],
) -> tuple[list[str], list[str]]:

    return __missing_calls_from_sequences_8616___impl(expected_names=expected_names, present_names=present_names, source_call_names=source_call_names)


def __missing_calls_from_sequences_8616___impl(*, expected_names: list[str], present_names: list[str], source_call_names: list[str]) -> tuple[list[str], list[str]]:
    expected_sequence = [
        (normalize_callee_name_8616(name) or name)
        for name in expected_names
        if isinstance(name, str) and name and name != "aNchkstk"
    ]
    source_sequence = [
        (normalize_callee_name_8616(name) or name)
        for name in source_call_names
        if isinstance(name, str) and name and name != "aNchkstk"
    ]
    actual_sequence = [
        (normalize_callee_name_8616(name) or name)
        for name in present_names
        if isinstance(name, str) and name and name != "aNchkstk"
    ]
    ordered_requirement = list(expected_sequence or source_sequence)
    required_counts = Counter(ordered_requirement)
    for name, count in Counter(source_sequence).items():
        if count > required_counts.get(name, 0):
            required_counts[name] = count
            ordered_requirement.extend(name for _ in range(count - ordered_requirement.count(name)))
    present_counts = Counter(actual_sequence)
    missing: list[str] = []
    for name in ordered_requirement:
        if missing.count(name) >= max(0, required_counts.get(name, 0) - present_counts.get(name, 0)):
            continue
        missing.append(name)
    return ordered_requirement, missing



def _adopt_source_name_for_target_8616(
    project: StructuredAstValue,
    target_addr: int,
    normalized: str | None,
    source_sequence: list[str],
) -> str | None:
    """Adopt the first source name matching the call target when the name is unknown."""
    for source_name in source_sequence:
        if _source_name_matches_target_8616(project, target_addr, source_name):
            if not isinstance(normalized, str) or _call_name_is_unknown_8616(normalized):
                return source_name
            break
    return normalized


def _adopt_arg_count_matched_source_name_8616(
    node: StructuredAstValue,
    summary: CallsiteSummary8616,
    source_sequence: list[str],
    source_idx: int,
    normalized: str | None,
) -> tuple[str | None, int]:
    """Adopt the pending source name when its known arity matches."""
    expected_arg_count = _expected_arg_count_for_known_callee_8616(source_sequence[source_idx])
    summary_arg_count = int(summary.arg_count or 0)
    current_arg_count = len(_boundary_tuple_8616(getattr(node, "args", ()) or ()))
    if (
        isinstance(expected_arg_count, int)
        and expected_arg_count >= 0
        and (summary_arg_count == expected_arg_count or current_arg_count == expected_arg_count)
    ):
        return source_sequence[source_idx], source_idx + 1
    return normalized, source_idx


def _resolve_present_call_name_8616(
    project: StructuredAstValue,
    node: StructuredAstValue,
    summary: CallsiteSummary8616 | None,
    source_sequence: list[str],
    source_idx: int,
) -> tuple[str | None, int]:
    """Resolve one call node's present name and advance the source scan."""
    normalized = normalize_callee_name_8616(_call_node_name_8616(node) or "") or _call_node_name_8616(node)
    target_addr = summary.target_addr if summary is not None else None
    if isinstance(target_addr, int) and (
        not isinstance(normalized, str) or _call_name_is_unknown_8616(normalized)
    ):
        summary_name = _semantic_call_name_from_summary_8616(project, summary, normalized)
        if isinstance(summary_name, str) and summary_name and not _call_name_is_unknown_8616(summary_name):
            normalized = summary_name
    if isinstance(target_addr, int):
        normalized = _adopt_source_name_for_target_8616(project, target_addr, normalized, source_sequence)
    if (
        isinstance(normalized, str)
        and source_idx < len(source_sequence)
        and normalized == source_sequence[source_idx]
    ):
        source_idx += 1
    elif (
        isinstance(normalized, str)
        and _call_name_is_unknown_8616(normalized)
        and summary is not None
        and source_idx < len(source_sequence)
    ):
        normalized, source_idx = _adopt_arg_count_matched_source_name_8616(
            node, summary, source_sequence, source_idx, normalized
        )
    return normalized, source_idx


def _structured_present_call_names_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    root: StructuredAstValue,
    source_call_names: list[str],
) -> list[str]:

    return __structured_present_call_names_8616___impl(codegen=codegen, project=project, root=root, source_call_names=source_call_names)


def __structured_present_call_names_8616___impl(*, codegen: StructuredAstValue, project: StructuredAstValue, root: StructuredAstValue, source_call_names: list[str]) -> list[str]:
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if isinstance(summary_map, dict):
        _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    else:
        summary_map = {}

    source_sequence = [
        normalize_callee_name_8616(name) or name
        for name in source_call_names
        if isinstance(name, str) and name and name != "aNchkstk"
    ]
    source_idx = 0
    present_names: list[str] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
            continue
        summary = summary_map.get(id(node))
        normalized, source_idx = _resolve_present_call_name_8616(
            project, node, summary, source_sequence, source_idx
        )
        if isinstance(normalized, str) and normalized and normalized != "aNchkstk":
            present_names.append(normalized)
    return present_names



def _ordered_missing_from_source_8616(source_sequence: list[str], missing: list[str]) -> list[str]:
    missing_counts = Counter(missing)
    if not source_sequence:
        return list(missing)
    ordered_missing: list[str] = []
    for name in source_sequence:
        if missing_counts.get(name, 0) > 0:
            ordered_missing.append(name)
            missing_counts[name] -= 1
    for name, count in missing_counts.items():
        if count > 0:
            ordered_missing.extend([name] * count)
    return ordered_missing


def _debug_loop_relocate_precheck_8616(
    *,
    debug_enabled: bool,
    context_tag: str,
    func_addr: int,
    ordered_missing: list[str],
    current_statements: StructuredAstValue,
) -> None:
    if not debug_enabled:
        return
    stmt_kinds = []
    for stmt in list(current_statements)[:12]:
        body = getattr(stmt, "body", None)
        body_statements = getattr(body, "statements", None)
        stmt_kinds.append(
            (
                type(stmt).__name__,
                bool(hasattr(stmt, "condition") or hasattr(stmt, "cond")),
                type(body).__name__ if body is not None else None,
                len(body_statements) if isinstance(body_statements, (list, tuple)) else None,
            )
        )
    loop_body_details = []
    for stmt in list(current_statements)[:12]:
        if not isinstance(stmt, structured_c.CForLoop):
            continue
        body = getattr(stmt, "body", None)
        body_statements = list(getattr(body, "statements", ()) or ())
        for bstmt in body_statements[:6]:
            expr = getattr(bstmt, "expr", None)
            loop_body_details.append((type(bstmt).__name__, type(expr).__name__, repr(expr)[:120]))
    log.warning(
        "[call-recover] context=%s loop-relocate precheck addr=%#x source_sequence=%r top=%r loop_body=%r",
        context_tag,
        func_addr,
        ordered_missing,
        stmt_kinds,
        loop_body_details,
    )


def _match_expected_call_stmt_indexes_8616(
    mutable_statements: StructuredAstValue, ordered_missing: list[str]
) -> tuple[int | None, list[str], list[int]]:

    return __match_expected_call_stmt_indexes_8616___impl(mutable_statements=mutable_statements, ordered_missing=ordered_missing)


def __match_expected_call_stmt_indexes_8616___impl(*, mutable_statements: StructuredAstValue, ordered_missing: list[str]) -> tuple[int | None, list[str], list[int]]:
    first_return_idx = None
    for idx, stmt in enumerate(mutable_statements):
        if isinstance(stmt, structured_c.CReturn):
            first_return_idx = idx
            break
    scan_slice = (
        list(enumerate(mutable_statements[first_return_idx + 1 :], start=first_return_idx + 1))
        if first_return_idx is not None
        else list(enumerate(mutable_statements))
    )
    call_stmt_indexes: list[int] = []
    call_stmt_names: list[str] = []
    for idx, stmt in scan_slice:
        expr = getattr(stmt, "expr", None)
        if not isinstance(expr, CFunctionCall):
            continue
        normalized = normalize_callee_name_8616(_call_node_name_8616(expr)) or _call_node_name_8616(expr)
        if not isinstance(normalized, str) or not normalized:
            continue
        call_stmt_indexes.append(idx)
        call_stmt_names.append(normalized)
    expected = [name for name in ordered_missing if isinstance(name, str) and name]
    matched_call_stmt_indexes: list[int] = []
    if expected:
        exp_i = 0
        for rel_i, call_name in enumerate(call_stmt_names):
            if exp_i >= len(expected):
                break
            if call_name == expected[exp_i]:
                matched_call_stmt_indexes.append(call_stmt_indexes[rel_i])
                exp_i += 1
    return first_return_idx, call_stmt_names, matched_call_stmt_indexes



def _relocate_recovered_calls_into_loops_8616(
    *,
    debug_enabled: bool,
    context_tag: str,
    func_addr: int,
    ordered_missing: list[str],
    root: StructuredAstValue,
    root_statements: StructuredAstValue,
    cfunc: StructuredAstValue,
) -> bool:

    return __relocate_recovered_calls_into_loops_8616___impl(cfunc=cfunc, context_tag=context_tag, debug_enabled=debug_enabled, func_addr=func_addr, ordered_missing=ordered_missing, root=root, root_statements=root_statements)


def __relocate_recovered_calls_into_loops_8616___impl(*, cfunc: StructuredAstValue, context_tag: str, debug_enabled: bool, func_addr: int, ordered_missing: list[str], root: StructuredAstValue, root_statements: StructuredAstValue) -> bool:
    current_statements = getattr(root, "statements", None)
    if not isinstance(current_statements, (list, tuple)):
        current_statements = root_statements
    empty_loop_bodies = _empty_loop_bodies_8616(current_statements)
    _debug_loop_relocate_precheck_8616(
        debug_enabled=debug_enabled,
        context_tag=context_tag,
        func_addr=func_addr,
        ordered_missing=ordered_missing,
        current_statements=current_statements,
    )
    if not empty_loop_bodies:
        return False
    mutable_statements = list(current_statements)
    first_return_idx, call_stmt_names, matched_call_stmt_indexes = _match_expected_call_stmt_indexes_8616(
        mutable_statements, ordered_missing
    )
    expected = [name for name in ordered_missing if isinstance(name, str) and name]
    if debug_enabled:
        log.warning(
            "[call-recover] context=%s loop-relocate candidates addr=%#x first_return_idx=%r calls=%r expected=%r matched=%r",
            context_tag,
            func_addr,
            first_return_idx,
            call_stmt_names,
            expected,
            matched_call_stmt_indexes,
        )
    if not expected or len(matched_call_stmt_indexes) != len(expected):
        return False
    target_bodies = list(empty_loop_bodies)
    move_count = min(len(expected), len(matched_call_stmt_indexes))
    for rel_idx in range(move_count):
        stmt_idx = matched_call_stmt_indexes[rel_idx]
        body_idx = min(rel_idx, len(target_bodies) - 1)
        body = target_bodies[body_idx]
        body_statements = list(getattr(body, "statements", ()) or ())
        body_statements.append(mutable_statements[stmt_idx])
        body.statements = body_statements
    remove_indexes = set(matched_call_stmt_indexes[:move_count])
    mutable_statements = [stmt for idx, stmt in enumerate(mutable_statements) if idx not in remove_indexes]
    if (
        first_return_idx is not None
        and first_return_idx < len(mutable_statements)
        and isinstance(mutable_statements[first_return_idx], structured_c.CReturn)
    ):
        del mutable_statements[first_return_idx]
    if debug_enabled:
        log.warning(
            "[call-recover] context=%s loop-relocate applied addr=%#x moved=%d",
            context_tag,
            func_addr,
            move_count,
        )
    updated_statements = mutable_statements if isinstance(root_statements, list) else tuple(mutable_statements)
    root.statements = updated_statements
    _sync_cfunc_root_statements_8616(cfunc, root, updated_statements)
    return True



def _count_non_probe_callsites_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    function: StructuredAstValue,
    get_call_sites: StructuredAstValue,
    target_by_callsite: dict[int, int],
) -> bool:
    """Count decoded callsites that do not resolve to stack-probe helpers."""
    callsite_addrs = tuple(
        sorted(
            {
                *cast(Iterable[int], get_call_sites() or ()),
                *target_by_callsite,
            }
        )
    )
    codegen._inertia_call_recovery_callsite_count_8616 = len(callsite_addrs)
    if not callsite_addrs:
        return False
    get_call_target = getattr(function, "get_call_target", None)
    if not callable(get_call_target):
        return True
    non_probe_count = 0
    for callsite_addr in callsite_addrs:
        target = target_by_callsite.get(callsite_addr)
        if target is None:
            target = get_call_target(callsite_addr)
        if not isinstance(target, int):
            non_probe_count += 1
            continue
        callee = _lookup_callee_function_8616(project, target)
        callee_name = getattr(callee, "name", None)
        if not _is_stack_probe_call_name_8616(callee_name if isinstance(callee_name, str) else None):
            non_probe_count += 1
    codegen._inertia_call_recovery_non_probe_callsite_count_8616 = non_probe_count
    return bool(non_probe_count)


def _function_has_direct_call_instruction_evidence_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Return whether the current function has a decoded call-like target."""
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return True
    function = _current_callsite_function_8616(project, func_addr)
    if function is None:
        return True
    target_by_callsite = {
        seed.callsite_addr: seed.target_addr for seed in collect_neighbor_call_targets(function)
    }
    get_call_sites = getattr(function, "get_call_sites", None)
    if callable(get_call_sites):
        with contextlib.suppress(Exception):
            return _count_non_probe_callsites_8616(project, codegen, function, get_call_sites, target_by_callsite)
    summaries = _function_instruction_summaries_8616(project, function)
    if not summaries:
        return True
    return any(str(summary.mnemonic).lower() in {"call", "lcall"} for summary in summaries)


def _current_callsite_function_8616(project: StructuredAstValue, func_addr: int) -> StructuredAstValue | None:
    """Return the prepared function object that owns current callsite evidence.

    Single-function recovery may expand a function with grouped CFG fragments
    before decompilation.  The stale KB function at the same address can then
    miss decoded direct calls from those fragments, so callsite consumers must
    prefer the prepared object published by the CLI and fall back to the KB only
    when no matching prepared object exists.
    """
    prepared = getattr(project, "_inertia_current_decompile_function_8616", None)
    if prepared is not None and getattr(prepared, "addr", None) == func_addr:
        return prepared
    with contextlib.suppress(Exception):
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is not None:
            return functions.function(addr=func_addr, create=False)
    return None


def _present_call_names_from_nodes_8616(root: StructuredAstValue) -> list[str]:
    """Collect normalized call names directly from structured call nodes."""
    present_names: list[str] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        for raw in (
            node.callee_target,
            getattr(node.callee_func, "name", None),
            getattr(node, "callee", None),
        ):
            if isinstance(raw, str) and raw:
                normalized = normalize_callee_name_8616(raw) or raw
                present_names.append(normalized)
                break
    return present_names


def _missing_calls_for_recovery_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    root: StructuredAstValue,
    source_call_names: list[str],
    expected_names: list[str],
) -> tuple[list[str], list[str]]:
    """Compute source-ordered calls missing from the structured output."""
    present_names = _structured_present_call_names_8616(project, codegen, root, source_call_names)
    if not present_names:
        present_names = _present_call_names_from_nodes_8616(root)
    return _missing_calls_from_sequences_8616(
        source_call_names, expected_names, present_names
    )


def _recover_missing_direct_calls_from_evidence_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:

    return __recover_missing_direct_calls_from_evidence_8616___impl(codegen=codegen, project=project)


def _recovered_calls_debug_log_8616(
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    context_tag: StructuredAstValue,
    ordered_missing: StructuredAstValue,
    root: StructuredAstValue,
) -> None:
    cfunc_calls = []
    cfunc_root_now = _structured_root_8616(cfunc)
    for node in _iter_c_nodes_deep_8616(cfunc_root_now):
        if isinstance(node, CFunctionCall):
            cfunc_calls.append(_call_node_name_8616(node))
    log.warning(
        "[call-recover] context=%s function=%#x codegen_id=%#x recovered=%r root=%s root_id=%#x cfunc_root=%s cfunc_root_id=%#x calls=%r",
        context_tag,
        getattr(cfunc, "addr", 0) or 0,
        id(codegen),
        ordered_missing,
        type(root).__name__,
        id(root),
        type(cfunc_root_now).__name__,
        id(cfunc_root_now),
        cfunc_calls,
    )


def _resolve_missing_call_set_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    root: StructuredAstValue,
    inventory_missing: StructuredAstValue,
    source_call_names: StructuredAstValue,
    expected_names: StructuredAstValue,
    expected_summary_by_name: StructuredAstValue,
) -> tuple[list[str], StructuredAstValue, StructuredAstValue]:
    if inventory_missing is not None:
        missing, expected_summary_by_name = inventory_missing
        return ([], missing, expected_summary_by_name)
    source_sequence, missing = _missing_calls_for_recovery_8616(
        project, codegen, root, source_call_names, expected_names
    )
    return (source_sequence, missing, expected_summary_by_name)


def _recover_call_evidence_gate_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    context_tag: str,
    debug_enabled: bool,
) -> bool:
    """Whether direct-call instruction evidence exists; records the skip otherwise."""
    if _function_has_direct_call_instruction_evidence_8616(project, codegen):
        return True
    codegen._inertia_call_recovery_skipped_no_call_instructions_8616 = (
        int(getattr(codegen, "_inertia_call_recovery_skipped_no_call_instructions_8616", 0) or 0) + 1
    )
    if debug_enabled:
        log.warning("[call-recover] context=%s skip=no-call-instructions", context_tag)
    return False


def _recover_debug_skip_8616(
    context_tag: str,
    func_addr: int,
    codegen: StructuredAstValue,
    reason: str,
    debug_enabled: bool,
) -> None:
    """Emit the standard call-recovery skip log when enabled."""
    if debug_enabled:
        log.warning(
            "[call-recover] context=%s skip=%s addr=%#x codegen_id=%#x",
            context_tag,
            reason,
            func_addr,
            id(codegen),
        )


def __recover_missing_direct_calls_from_evidence_8616___impl(*, codegen: StructuredAstValue, project: StructuredAstValue) -> bool:
    debug_enabled = bool(os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"))
    context_tag = getattr(codegen, "_inertia_call_recover_context", "postprocess")
    if not _recover_call_evidence_gate_8616(project, codegen, context_tag, debug_enabled):
        return False
    prepared = _prepare_call_recovery_context_8616(
        project, codegen, debug_enabled=debug_enabled, context_tag=context_tag
    )
    if prepared is None:
        return False
    cfunc, root, root_statements, func_addr, function = prepared

    inventory_missing = _missing_calls_from_owned_inventory_8616(project, codegen, root)
    expected_names, expected_summary_by_name, source_call_names = _recover_expected_calls_8616(
        project, cfunc, function, func_addr
    )

    if not expected_names:
        _recover_debug_skip_8616(context_tag, func_addr, codegen, "no-expected-names", debug_enabled)
        return False

    source_sequence, missing, expected_summary_by_name = _resolve_missing_call_set_8616(
        project, codegen, root, inventory_missing, source_call_names, expected_names,
        expected_summary_by_name,
    )
    if not missing:
        _sync_cfunc_root_statements_8616(cfunc, root, root_statements)
        _recover_debug_skip_8616(context_tag, func_addr, codegen, "no-missing", debug_enabled)
        return False

    summary_map = dict(getattr(codegen, "_inertia_callsite_summaries", {}) or {})
    mutable_statements = list(root_statements)
    changed = False
    first_empty_loop_body = _first_empty_loop_body_8616(mutable_statements)
    # Preserve source call ordering when recovering missing calls.
    # Build a replay queue by scanning source order and selecting only calls that
    # still need insertion according to `missing` multiset.
    ordered_missing = _ordered_missing_from_source_8616(source_sequence, missing)

    changed, mutable_statements = _insert_missing_calls_8616(
        project=project,
        codegen=codegen,
        mutable_statements=mutable_statements,
        ordered_missing=ordered_missing,
        source_sequence=source_sequence,
        expected_summary_by_name=expected_summary_by_name,
        summary_map=summary_map,
        first_empty_loop_body=first_empty_loop_body,
    )
    if changed:
        updated_statements = mutable_statements if isinstance(root_statements, list) else tuple(mutable_statements)
        root.statements = updated_statements
        _sync_cfunc_root_statements_8616(cfunc, root, updated_statements)
        if debug_enabled:
            _recovered_calls_debug_log_8616(
                codegen, cfunc, context_tag, ordered_missing, root
            )
        codegen._inertia_callsite_summaries = summary_map
        codegen._inertia_direct_call_floor_recovered_count = int(
            getattr(codegen, "_inertia_direct_call_floor_recovered_count", 0)
        ) + len(missing)
    if source_sequence and _relocate_recovered_calls_into_loops_8616(
        debug_enabled=debug_enabled,
        context_tag=context_tag,
        func_addr=func_addr,
        ordered_missing=ordered_missing,
        root=root,
        root_statements=root_statements,
        cfunc=cfunc,
    ):
        changed = True
    return changed



def _missing_calls_from_owned_inventory_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    root: StructuredAstValue,
) -> tuple[list[str], dict[str, list[CallsiteSummary8616]]] | None:
    """Return missing calls by exact owned callsite identity when available."""
    inventory = _callsite_summary_inventory_8616(codegen)
    if not inventory:
        return None
    call_nodes = tuple(
        node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CFunctionCall)
    )
    try:
        attached_summaries = codegen._inertia_callsite_summaries
    except AttributeError:
        attached_summaries = None
    represented = represented_callsite_addrs_8616(call_nodes, attached_summaries)
    if os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
        log.warning(
            "[call-recover] owned-inventory=%r represented=%r",
            tuple(sorted(inventory)),
            tuple(sorted(represented)),
        )
    names: list[str] = []
    summaries_by_name: dict[str, list[CallsiteSummary8616]] = {}
    for callsite_addr, summary in sorted(inventory.items()):
        if callsite_addr in represented or summary.stack_probe_helper:
            continue
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            continue
        callee = _lookup_callee_function_8616(project, target_addr, allow_containing=False)
        callee_name = getattr(callee, "name", None)
        if not isinstance(callee_name, str) or not callee_name:
            callee_name = _sidecar_label_for_target_8616(project, target_addr)
        if not isinstance(callee_name, str) or not callee_name:
            callee_name = f"sub_{target_addr:x}"
        if callee_name in _RUNTIME_SEGMENT_HELPERS_8616:
            continue
        normalized_name = normalize_callee_name_8616(callee_name) or callee_name
        names.append(normalized_name)
        summaries_by_name.setdefault(normalized_name, []).append(summary)
    return names, summaries_by_name


def _prepare_call_recovery_context_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    debug_enabled: bool,
    context_tag: str,
) -> tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue, int, StructuredAstValue] | None:

    return __prepare_call_recovery_context_8616___impl(codegen=codegen, context_tag=context_tag, debug_enabled=debug_enabled, project=project)


def __prepare_call_recovery_context_8616___impl(*, codegen: StructuredAstValue, context_tag: str, debug_enabled: bool, project: StructuredAstValue) -> tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue, int, StructuredAstValue] | None:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        if debug_enabled:
            log.warning("[call-recover] context=%s skip=no-cfunc codegen_id=%#x", context_tag, id(codegen))
        return None
    root = _structured_root_8616(cfunc)
    root_statements = getattr(root, "statements", None)
    if not isinstance(root_statements, (list, tuple)):
        if debug_enabled:
            log.warning(
                "[call-recover] context=%s skip=bad-root-statements codegen_id=%#x root=%s root_statements=%s",
                context_tag,
                id(codegen),
                type(root).__name__,
                type(root_statements).__name__ if root_statements is not None else "None",
            )
        return None
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        if debug_enabled:
            log.warning("[call-recover] context=%s skip=bad-func-addr codegen_id=%#x", context_tag, id(codegen))
        return None
    function = _current_callsite_function_8616(project, func_addr)
    if function is None:
        if debug_enabled:
            log.warning(
                "[call-recover] context=%s skip=no-kb-function addr=%r codegen_id=%#x",
                context_tag,
                func_addr,
                id(codegen),
            )
        return None
    return cfunc, root, root_statements, func_addr, function



def _expected_callee_name_8616(project: StructuredAstValue, target: int) -> str | None:
    """Resolve a non-helper callee name for the call target."""
    callee = _lookup_callee_function_8616(project, target, allow_containing=False)
    callee_name = getattr(callee, "name", None)
    if not isinstance(callee_name, str) or not callee_name:
        callee_name = _sidecar_label_for_target_8616(project, target)
    if not isinstance(callee_name, str) or not callee_name or callee_name in _RUNTIME_SEGMENT_HELPERS_8616:
        return None
    return callee_name


def _expected_callsite_names_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    callsite_addrs: tuple[int, ...],
    target_by_callsite: dict[int, int],
    tail_callsite_addrs: set[int],
) -> tuple[
    list[str],
    list[str],
    dict[str, list[CallsiteSummary8616]],
    list[CallsiteSummary8616],
]:
    """Enumerate expected call names and summaries from decoded callsites."""
    expected_names: list[str] = []
    tail_names: list[str] = []
    expected_summary_by_name: dict[str, list[CallsiteSummary8616]] = {}
    callsite_summaries: list[CallsiteSummary8616] = []
    for callsite_addr in callsite_addrs:
        target = target_by_callsite.get(callsite_addr)
        if target is None:
            target = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
        if not isinstance(target, int):
            continue
        summary = summarize_x86_16_callsite(function, callsite_addr)
        if summary is not None:
            callsite_summaries.append(summary)
        callee_name = _expected_callee_name_8616(project, target)
        if callee_name is None:
            continue
        normalized_name = normalize_callee_name_8616(callee_name) or callee_name
        expected_names.append(normalized_name)
        if callsite_addr in tail_callsite_addrs:
            tail_names.append(normalized_name)
        if summary is not None:
            expected_summary_by_name.setdefault(normalized_name, []).append(summary)
    return expected_names, tail_names, expected_summary_by_name, callsite_summaries


def _source_floor_expected_names_8616(
    project: StructuredAstValue,
    cfunc: StructuredAstValue,
    func_addr: int,
    tail_names: list[str],
    callsite_summaries: list[CallsiteSummary8616],
) -> tuple[list[str], list[str] | None, dict[str, list[CallsiteSummary8616]] | None]:
    """Rebuild expected names from COD source order when the floor is enabled."""
    source_call_names = list(_cod_source_call_names_8616(project, func_addr))
    if not source_call_names:
        source_call_names = list(_cod_source_call_names_for_symbol_8616(project, getattr(cfunc, "name", None)))
    if not source_call_names:
        return source_call_names, None, None
    expected_names = [
        source_name for source_name in source_call_names if isinstance(source_name, str) and source_name
    ]
    expected_names.extend(tail_names)
    summaries_by_name = None
    if len(callsite_summaries) == len(expected_names):
        summaries_by_name = {}
        for source_name, summary in zip(expected_names, callsite_summaries, strict=False):
            summaries_by_name.setdefault(source_name, []).append(summary)
    return source_call_names, expected_names, summaries_by_name


def _recover_expected_calls_8616(
    project: StructuredAstValue,
    cfunc: StructuredAstValue,
    function: StructuredAstValue,
    func_addr: int,
) -> tuple[
    list[str],
    dict[str, list[CallsiteSummary8616]],
    list[str],
]:

    return __recover_expected_calls_8616___impl(cfunc=cfunc, func_addr=func_addr, function=function, project=project)


def __recover_expected_calls_8616___impl(*, cfunc: StructuredAstValue, func_addr: int, function: StructuredAstValue, project: StructuredAstValue) -> tuple[
    list[str],
    dict[str, list[CallsiteSummary8616]],
    list[str],
]:
    expected_names: list[str] = []
    expected_summary_by_name: dict[str, list[CallsiteSummary8616]] = {}
    target_seeds = collect_neighbor_call_targets(function)
    target_by_callsite = {seed.callsite_addr: seed.target_addr for seed in target_seeds}
    tail_callsite_addrs = {
        seed.callsite_addr
        for seed in target_seeds
        if seed.kind
        in {
            CallTargetKind8616.DIRECT_NEAR_TAIL_JUMP,
            CallTargetKind8616.DIRECT_FAR_TAIL_JUMP,
            CallTargetKind8616.STORED_NEAR_TAIL_JUMP,
        }
    }
    tail_names: list[str] = []
    callsite_addrs = _boundary_tuple_8616(
        sorted(
            {
                *getattr(function, "get_call_sites", list)(),
                *target_by_callsite,
            }
        )
    )
    callsite_summaries: list[CallsiteSummary8616] = []
    expected_names, tail_names, expected_summary_by_name, callsite_summaries = (
        _expected_callsite_names_8616(
            project, function, callsite_addrs, target_by_callsite, tail_callsite_addrs
        )
    )
    source_call_names: list[str] = []
    if _source_call_floor_enabled_8616():
        source_call_names, floor_names, floor_summaries = _source_floor_expected_names_8616(
            project, cfunc, func_addr, tail_names, callsite_summaries
        )
        if floor_names is not None:
            expected_names = floor_names
        if floor_summaries is not None:
            expected_summary_by_name = floor_summaries
    if os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
        log.warning(
            "[call-recover] expected addr=%#x cfunc_name=%r delta=%r expected=%r source=%r",
            func_addr,
            getattr(cfunc, "name", None),
            getattr(project, "_inertia_original_linear_delta", None),
            expected_names,
            source_call_names,
        )
    return expected_names, expected_summary_by_name, source_call_names



def _summary_looks_loop_carried_arg_8616(summary: CallsiteSummary8616 | None) -> bool:
    """Return whether binary push evidence reads a BP-relative value."""
    if summary is None:
        return False
    for source in summary.push_arg_sources:
        if not isinstance(source, tuple) or len(source) < 2:
            continue
        base, displacement = source[:2]
        if base == "bp" and isinstance(displacement, int):
            return True
    return False


def _insert_missing_calls_8616(
    *,
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    mutable_statements: list[StructuredAstValue],
    ordered_missing: list[str],
    source_sequence: list[str],
    expected_summary_by_name: dict[str, list[CallsiteSummary8616]],
    summary_map: dict[int, CallsiteSummary8616],
    first_empty_loop_body: StructuredAstValue,
) -> tuple[bool, list[StructuredAstValue]]:

    return __insert_missing_calls_8616___impl(codegen=codegen, expected_summary_by_name=expected_summary_by_name, first_empty_loop_body=first_empty_loop_body, mutable_statements=mutable_statements, ordered_missing=ordered_missing, project=project, source_sequence=source_sequence, summary_map=summary_map)


def __insert_missing_calls_8616___impl(*, codegen: StructuredAstValue, expected_summary_by_name: dict[str, list[CallsiteSummary8616]], first_empty_loop_body: StructuredAstValue, mutable_statements: list[StructuredAstValue], ordered_missing: list[str], project: StructuredAstValue, source_sequence: list[str], summary_map: dict[int, CallsiteSummary8616]) -> tuple[bool, list[StructuredAstValue]]:
    insert_at = len(mutable_statements)
    for idx, stmt in enumerate(mutable_statements):
        if isinstance(stmt, structured_c.CReturn):
            insert_at = idx
            break

    changed = False
    for idx, name in enumerate(ordered_missing):
        callee_func = project.kb.functions.function(name=name, create=False)
        seeded_args = _known_default_args_for_missing_8616(name, codegen)
        call_args = list(seeded_args) if isinstance(seeded_args, tuple) else []
        call = CFunctionCall(name, callee_func, call_args, codegen=codegen)
        call_stmt = structured_c.CExpressionStatement(call, codegen=codegen)
        inserted_in_loop = False
        summary_candidates = expected_summary_by_name.get(normalize_callee_name_8616(name) or name, [])
        preferred_summary = summary_candidates[0] if summary_candidates else None
        loop_carried_missing = _summary_looks_loop_carried_arg_8616(preferred_summary)
        if (
            (idx == 0 and source_sequence and source_sequence[0] == name) or loop_carried_missing
        ) and first_empty_loop_body is not None:
            loop_body_statements = list(
                cast(Iterable[StructuredAstValue], getattr(first_empty_loop_body, "statements", ()) or ())
            )
            loop_body_statements.append(call_stmt)
            first_empty_loop_body.statements = loop_body_statements
            inserted_in_loop = True
        if not inserted_in_loop:
            mutable_statements.insert(insert_at, call_stmt)
        if summary_candidates:
            summary_map[id(call)] = summary_candidates.pop(0)
        if not inserted_in_loop:
            insert_at += 1
        changed = True
    return changed, mutable_statements



def _first_empty_loop_body_8616(statements: StructuredAstValue) -> StructuredAstValue | None:
    for stmt in statements:
        body = getattr(stmt, "body", None)
        body_statements = getattr(body, "statements", None)
        if (
            isinstance(body_statements, (list, tuple))
            and len(body_statements) == 0
            # Loop-like nodes expose condition fields in structured_codegen nodes.
            and (hasattr(stmt, "condition") or hasattr(stmt, "cond"))
        ):
            return body
    return None


def _setup_cleanup_changed_8616(
    consumed_dirty_setup: StructuredAstValue, source_alias_artifacts: StructuredAstValue, scalar_high_byte_remnants: StructuredAstValue, farptr_high_byte_remnants: StructuredAstValue, pre_clobber_removed: StructuredAstValue, direct_push_source_stores_pruned: StructuredAstValue, materialized_stmt: StructuredAstValue, stmt: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        consumed_dirty_setup
    or source_alias_artifacts
    or scalar_high_byte_remnants
    or farptr_high_byte_remnants
    or pre_clobber_removed
    or direct_push_source_stores_pruned
    or materialized_stmt is not stmt
    )


def _arity_contract_extends_count_8616(
    arity_contract: StructuredAstValue, expected_arg_count: StructuredAstValue, push_arg_sources: StructuredAstValue, stack_cleanup: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        arity_contract.mode is CallArityMode8616.EXACT
    and isinstance(arity_contract.count, int)
    and (not isinstance(expected_arg_count, int) or arity_contract.count > expected_arg_count)
    and (
        not isinstance(push_arg_sources, tuple)
        or len(push_arg_sources) >= arity_contract.count
        or (isinstance(stack_cleanup, int) and stack_cleanup >= arity_contract.count * 2)
    )
    )


def _known_arg_count_override_ok_8616(
    expected_arg_count: StructuredAstValue, known_arg_count: StructuredAstValue, summary_arg_count: StructuredAstValue, has_strong_direct_push_sources: StructuredAstValue, stack_probe_seen: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        isinstance(expected_arg_count, int)
    and expected_arg_count > 0
    and isinstance(known_arg_count, int)
    and known_arg_count > expected_arg_count
    and summary_arg_count is not None
    and (summary_arg_count <= 0 or (summary_arg_count > 0 and stack_probe_seen))
    and not has_strong_direct_push_sources
    )


def _single_bp_push_source_8616(
    call: StructuredAstValue, is_stack_probe_helper: StructuredAstValue, expected_arg_count: StructuredAstValue, push_arg_sources: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        call is not None
    and not is_stack_probe_helper
    and isinstance(expected_arg_count, int)
    and expected_arg_count == 1
    and isinstance(push_arg_sources, tuple)
    and len(push_arg_sources) == 1
    and isinstance(push_arg_sources[0], tuple)
    and len(push_arg_sources[0]) >= 2
    and push_arg_sources[0][0] == "bp"
    and isinstance(push_arg_sources[0][1], int)
    )


def _strict_shape_remat_ok_8616(
    rematerialize_call_args: StructuredAstValue, call: StructuredAstValue, expected_arg_count: StructuredAstValue, has_exact_direct_push_sources: StructuredAstValue, has_safe_non_stack_fallback: StructuredAstValue, probe_seen_without_ss_address: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        call is not None
    and isinstance(expected_arg_count, int)
    and expected_arg_count > 0
    and rematerialize_call_args
    and (not probe_seen_without_ss_address or has_exact_direct_push_sources or has_safe_non_stack_fallback)
    )


def _protected_arg_is_source_immediate_8616(
    push_sources: StructuredAstValue, push_source: StructuredAstValue, current_arg: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        isinstance(push_sources, tuple)
    and isinstance(push_source, tuple)
    and len(push_source) >= 2
    and push_source[0] == "imm"
    and isinstance(push_source[1], int)
    and isinstance(current_arg, structured_c.CConstant)
    and getattr(current_arg, "value", None) == int(push_source[1])
    )


def _push_source_count_matches_8616(
    strict_arg_shape_applied: StructuredAstValue, expected_arg_count: StructuredAstValue, push_arg_sources: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        not strict_arg_shape_applied
    and isinstance(expected_arg_count, int)
    and expected_arg_count > 0
    and isinstance(push_arg_sources, tuple)
    and len(push_arg_sources) == expected_arg_count
    and any(source is not None for source in push_arg_sources)
    )


def _probe_fact_gate_ok_8616(
    strict_arg_shape_applied: StructuredAstValue, typed_stack_probe_materialization: StructuredAstValue, stack_probe_address_seen: StructuredAstValue, expected_arg_count: StructuredAstValue, stack_probe_seen: StructuredAstValue, typed_stack_probe_fact: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        not strict_arg_shape_applied
    and not typed_stack_probe_materialization
    and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
    and isinstance(expected_arg_count, int)
    and expected_arg_count > 0
    )


def _single_probe_fact_arg_gate_8616(
    stack_probe_seen: StructuredAstValue, strict_arg_shape_applied: StructuredAstValue, expected_arg_count: StructuredAstValue, typed_stack_probe_fact: StructuredAstValue, is_stack_probe_helper: StructuredAstValue, new_statements: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        not strict_arg_shape_applied
    and expected_arg_count == 1
    and typed_stack_probe_fact is not None
    and stack_probe_seen
    and not is_stack_probe_helper
    and len(new_statements) >= 1
    )


def _named_probe_fact_gate_8616(
    strict_arg_shape_applied: StructuredAstValue, expected_arg_count: StructuredAstValue, stack_probe_address_seen: StructuredAstValue, semantic_call_name: StructuredAstValue, call_name: StructuredAstValue, stack_probe_seen: StructuredAstValue, typed_stack_probe_fact: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        not strict_arg_shape_applied
    and (semantic_call_name is not None or call_name is not None)
    and isinstance(expected_arg_count, int)
    and expected_arg_count > 0
    and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
    )


def _remat_no_count_gate_8616(
    rematerialize_call_args: StructuredAstValue, call: StructuredAstValue, is_stack_probe_helper: StructuredAstValue, arg_count: StructuredAstValue, new_statements: StructuredAstValue,
) -> bool:
    """Predicate extracted from a callsite gate."""
    return (
        call is not None
    and not is_stack_probe_helper
    and (not isinstance(arg_count, int) or arg_count <= 0)
    and rematerialize_call_args
    and len(new_statements) >= 1
    )


def _push_source_is_sign_ext_word_pair_8616(low_source: StructuredAstValue, high_source: StructuredAstValue) -> bool:
    """Whether (low, high) is an EXPR sign-extension word pair."""
    return (
        isinstance(low_source, tuple)
        and isinstance(high_source, tuple)
        and len(high_source) == 3
        and high_source[0] == CallsitePushSourceKind8616.EXPR.value
        and isinstance(high_source[1], tuple)
        and high_source[1] == low_source
        and isinstance(high_source[2], tuple)
        and len(high_source[2]) == 1
        and high_source[2][0] == (CallsitePushExprOp8616.SIGN_EXT_HI.value, 16)
    )


def _push_source_is_immediate_word_pair_8616(low_source: StructuredAstValue, high_source: StructuredAstValue) -> bool:
    """Whether (low, high) is a pair of IMMEDIATE push sources."""
    return (
        isinstance(low_source, tuple)
        and isinstance(high_source, tuple)
        and len(low_source) >= 2
        and len(high_source) >= 2
        and low_source[0] == CallsitePushSourceKind8616.IMMEDIATE.value
        and high_source[0] == CallsitePushSourceKind8616.IMMEDIATE.value
        and isinstance(low_source[1], int)
        and isinstance(high_source[1], int)
    )


def _push_source_is_global_word_pair_8616(low_source: StructuredAstValue, high_source: StructuredAstValue) -> bool:
    """Whether (low, high) is a pair of adjacent 2-byte ``global`` push sources."""
    return (
        isinstance(low_source, tuple)
        and isinstance(high_source, tuple)
        and len(low_source) >= 3
        and len(high_source) >= 3
        and low_source[0] == "global"
        and high_source[0] == "global"
        and isinstance(low_source[1], int)
        and isinstance(high_source[1], int)
        and int(low_source[2]) == 2
        and int(high_source[2]) == 2
        and int(high_source[1]) == int(low_source[1]) + 2
    )



def _stmt_is_placeholder_8616(stmt: StructuredAstValue) -> bool:
    """Return whether a loop-body statement is a safe placeholder anchor."""
    if stmt is None:
        return True
    nested = getattr(stmt, "statements", None)
    if isinstance(nested, (list, tuple)):
        return all(_stmt_is_placeholder_8616(child) for child in nested)
    expr = getattr(stmt, "expr", None)
    if expr is None:
        return True
    if isinstance(expr, CFunctionCall):
        return False
    if isinstance(expr, CBinaryOp):
        # Keep conservative: loop bodies with binary expression side-effects
        # are not safe anchors.
        return False
    if isinstance(expr, structured_c.CAssignment):
        lhs = expr.lhs
        rhs = expr.rhs
        return bool(_same_c_expression_8616(lhs, rhs))
    # Unknown loop statement kind: refuse anchoring.
    return False


def _empty_loop_body_for_stmt_8616(stmt: StructuredAstValue) -> StructuredAstValue | None:
    """Return the statement body when it is a loop-shaped empty placeholder."""
    body = getattr(stmt, "body", None)
    body_statements = getattr(body, "statements", None)
    if not isinstance(body_statements, (list, tuple)):
        return None
    if not (hasattr(stmt, "condition") or hasattr(stmt, "cond")):
        return None
    if len(body_statements) == 0:
        return body
    if all(_stmt_is_placeholder_8616(body_stmt) for body_stmt in body_statements):
        return body
    return None


def _empty_loop_bodies_8616(statements: StructuredAstValue) -> list[StructuredAstValue]:
    bodies = []
    for stmt in statements:
        body = _empty_loop_body_for_stmt_8616(stmt)
        if body is not None:
            bodies.append(body)
    return bodies


@dataclass(slots=True)
class CallsiteMaterializationStats:
    """Evidence counters for late callsite materialization decisions."""

    callsite_materialization_attempt_count: int = 0
    callsite_materialization_cache_hit_count: int = 0
    callsite_materialization_cache_refused_count: int = 0
    no_live_summarized_call_refusal_count: int = 0
    callsite_count: int = 0
    call_target_fact_count: int = 0
    call_target_materialized_count: int = 0
    call_arg_fact_count: int = 0
    call_arg_materialized_count: int = 0
    bp_slot_arg_value_normalized_count: int = 0
    pointer_arg_materialized_count: int = 0
    push_order_reversed_count: int = 0
    physical_arg_width_override_count: int = 0
    direct_push_override_recent_store_count: int = 0
    consumed_outgoing_stack_placeholder_count: int = 0
    live_setup_definition_preserved_count: int = 0
    stale_target_rejected_count: int = 0
    known_prototype_arg_mismatch_count: int = 0
    has_push_arg_evidence_count: int = 0
    no_push_arg_evidence_count: int = 0
    source_proven_stack_probe_count: int = 0
    byte_merge_raw_fact_count: int = 0
    byte_merge_classified_fact_count: int = 0
    byte_merge_materialized_count: int = 0
    byte_merge_refused_count: int = 0
    failure_count: int = 0
    known_prototype_arg_mismatches: list[dict[str, StructuredAstValue]] = field(default_factory=list)

    @property
    def raw_fact_count(self: CallsiteMaterializationStats) -> int:
        """Return all raw callsite facts observed by this compatibility pass."""
        return int(self.callsite_count or 0) + int(self.byte_merge_raw_fact_count or 0)

    @property
    def normalized_fact_count(self: CallsiteMaterializationStats) -> int:
        """Return raw facts that were normalized into pass-owned evidence."""
        return int(self.callsite_count or 0) + int(self.byte_merge_classified_fact_count or 0)

    @property
    def classified_fact_count(self: CallsiteMaterializationStats) -> int:
        """Return normalized facts that were classified as usable evidence."""
        return (
            int(self.call_target_fact_count or 0)
            + int(self.call_arg_fact_count or 0)
            + int(self.byte_merge_classified_fact_count or 0)
        )

    @property
    def materialized_count(self: CallsiteMaterializationStats) -> int:
        """Return classified facts that were consumed into generated C."""
        return (
            int(self.call_target_materialized_count or 0)
            + int(self.call_arg_materialized_count or 0)
            + int(self.byte_merge_materialized_count or 0)
        )

    def evidence_counters(self: CallsiteMaterializationStats) -> dict[str, int]:
        """Return the architecture-mandated evidence loop counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": int(self.failure_count or 0),
        }

    def report_counters(self: CallsiteMaterializationStats) -> dict[str, StructuredAstValue]:
        """Return evidence counters plus detailed callsite report fields."""
        payload: dict[str, StructuredAstValue] = self.evidence_counters()
        payload.update(
            {
                "callsite_count": int(self.callsite_count or 0),
                "call_target_fact_count": int(self.call_target_fact_count or 0),
                "call_target_materialized_count": int(self.call_target_materialized_count or 0),
                "call_arg_fact_count": int(self.call_arg_fact_count or 0),
                "call_arg_materialized_count": int(self.call_arg_materialized_count or 0),
                "physical_arg_width_override_count": int(self.physical_arg_width_override_count or 0),
                "direct_push_override_recent_store_count": int(self.direct_push_override_recent_store_count or 0),
                "live_setup_definition_preserved_count": int(self.live_setup_definition_preserved_count or 0),
                "known_prototype_arg_mismatch_count": int(self.known_prototype_arg_mismatch_count or 0),
                "no_live_summarized_call_refusal_count": int(self.no_live_summarized_call_refusal_count or 0),
            }
        )
        return payload

    def fact_trace_counters(self: CallsiteMaterializationStats) -> dict[str, int]:
        """Return every counter mirrored into the stack-probe fact trace."""
        return {
            "callsite_materialization_attempt_count": self.callsite_materialization_attempt_count,
            "callsite_materialization_cache_hit_count": self.callsite_materialization_cache_hit_count,
            "callsite_materialization_cache_refused_count": self.callsite_materialization_cache_refused_count,
            "no_live_summarized_call_refusal_count": self.no_live_summarized_call_refusal_count,
            "callsite_count": self.callsite_count,
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "call_target_fact_count": self.call_target_fact_count,
            "call_target_materialized_count": self.call_target_materialized_count,
            "call_arg_fact_count": self.call_arg_fact_count,
            "call_arg_materialized_count": self.call_arg_materialized_count,
            "bp_slot_arg_value_normalized_count": self.bp_slot_arg_value_normalized_count,
            "pointer_arg_materialized_count": self.pointer_arg_materialized_count,
            "push_order_reversed_count": self.push_order_reversed_count,
            "consumed_outgoing_stack_placeholder_count": self.consumed_outgoing_stack_placeholder_count,
            "live_setup_definition_preserved_count": self.live_setup_definition_preserved_count,
            "stale_target_rejected_count": self.stale_target_rejected_count,
            "known_prototype_arg_mismatch_count": self.known_prototype_arg_mismatch_count,
            "has_push_arg_evidence_count": self.has_push_arg_evidence_count,
            "no_push_arg_evidence_count": self.no_push_arg_evidence_count,
            "source_proven_stack_probe_count": self.source_proven_stack_probe_count,
            "byte_merge_raw_fact_count": self.byte_merge_raw_fact_count,
            "byte_merge_classified_fact_count": self.byte_merge_classified_fact_count,
            "byte_merge_materialized_count": self.byte_merge_materialized_count,
            "byte_merge_refused_count": self.byte_merge_refused_count,
            "failure_count": self.failure_count,
        }


class CallArgSemanticKind8616(Enum):
    """Classify a recovered call argument by its proven semantic role."""

    UNKNOWN = "unknown"
    POINTER = "pointer"
    VALUE = "value"


class CallArityMode8616(Enum):
    """Describe whether a recovered call arity is exact or only a lower bound."""

    UNKNOWN = "unknown"
    EXACT = "exact"
    MINIMUM = "minimum"


class CallArgMaterializationGap8616(Enum):
    """Identify structured call-argument evidence left unconsumed."""

    SUMMARY_ARG_PROOF_UNCONSUMED = "summary_arg_proof_unconsumed"


@dataclass(frozen=True, slots=True)
class CallArityContract8616:
    """Carry the recovered call argument count and its proof strength."""

    count: int | None
    mode: CallArityMode8616 = CallArityMode8616.UNKNOWN


def _normalize_signature_value_8616(value: StructuredAstValue) -> StructuredAstValue:
    """Return a mutation-sensitive cache token for one boundary value."""
    if value is None or isinstance(value, (str, int, bool, float)):
        return value
    if isinstance(value, (tuple, list, frozenset, set)):
        normalized = tuple(_normalize_signature_value_8616(item) for item in value)
        return normalized if not isinstance(value, (set, frozenset)) else tuple(sorted(normalized, key=repr))
    if isinstance(value, dict):
        return tuple(
            (_normalize_signature_value_8616(key), _normalize_signature_value_8616(val))
            for key, val in sorted(value.items(), key=lambda pair: repr(pair[0]))
        )
    return type(value).__name__, id(value)


def _callsite_materialization_signature_8616(
    codegen: StructuredAstValue,
) -> tuple[StructuredAstValue, ...] | None:
    cfunc = getattr(codegen, "cfunc", None)
    root = _structured_root_8616(cfunc)
    if root is None:
        return (None,)
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        func_addr = None
    signatures: list[tuple[StructuredAstValue, ...]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
            continue
        summary = summary_map.get(id(node))
        if summary is None:
            continue
        argument_tokens = tuple(_call_arg_semantic_key_8616(argument) for argument in node.args or ())
        if any(token is None for token in argument_tokens):
            return None
        signatures.append(
            (
                _call_node_name_8616(node) or "",
                _normalize_signature_value_8616(summary.callsite_addr),
                _normalize_signature_value_8616(summary.target_addr),
                _normalize_signature_value_8616(summary.arg_count),
                argument_tokens,
                _normalize_signature_value_8616(_boundary_tuple_8616(summary.arg_widths or ())),
                _normalize_signature_value_8616(summary.stack_cleanup),
                _normalize_signature_value_8616(_boundary_tuple_8616(summary.push_arg_sources or ())),
                _normalize_signature_value_8616(_boundary_tuple_8616(summary.push_arg_instruction_addrs or ())),
            )
        )
    signatures.sort(key=repr)
    return ("func", func_addr, "calls", tuple(signatures))


def _set_callsite_materialization_decision_8616(
    codegen: StructuredAstValue,
    decision: CallsiteMaterializationDecision8616,
    *,
    changed: bool,
    signature: tuple[StructuredAstValue, ...] | None = None,
) -> None:
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    if decision is CallsiteMaterializationDecision8616.CACHE_HIT:
        stats.callsite_materialization_cache_hit_count += 1
        codegen._inertia_callsite_materialization_complete_8616 = True
        codegen._inertia_callsite_materialization_last_changed_8616 = False
    elif decision is CallsiteMaterializationDecision8616.REFUSED_POINTER_MEMORY:
        stats.callsite_materialization_cache_refused_count += 1
        codegen._inertia_callsite_materialization_complete_8616 = False
        codegen._inertia_callsite_materialization_last_changed_8616 = False
    elif decision is CallsiteMaterializationDecision8616.REFUSED_NO_LIVE_SUMMARIZED_CALL:
        stats.callsite_materialization_attempt_count += 1
        stats.callsite_materialization_cache_refused_count += 1
        stats.no_live_summarized_call_refusal_count += 1
        codegen._inertia_callsite_materialization_complete_8616 = False
        codegen._inertia_callsite_materialization_last_changed_8616 = False
    elif decision is CallsiteMaterializationDecision8616.NOT_APPLICABLE:
        stats.callsite_materialization_attempt_count += 1
        stats.callsite_materialization_cache_refused_count += 1
        codegen._inertia_callsite_materialization_complete_8616 = False
        codegen._inertia_callsite_materialization_last_changed_8616 = False
    else:
        stats.callsite_materialization_attempt_count += 1
        codegen._inertia_callsite_materialization_complete_8616 = True
        codegen._inertia_callsite_materialization_last_changed_8616 = bool(changed)
    if signature is not None:
        codegen._inertia_callsite_materialization_signature_8616 = signature
    codegen._inertia_callsite_materialization_last_decision_8616 = decision


_KNOWN_HELPER_ARG_KIND_CACHE_8616: dict[str, dict[int, CallArgSemanticKind8616]] = {}
def _ensure_callsite_materialization_stats_8616(codegen: StructuredAstValue) -> CallsiteMaterializationStats:
    """Initialize and return the owned callsite materialization statistics."""
    carrier = cast(_CallsiteMaterializationControlCarrier8616, codegen)
    try:
        stats = carrier._inertia_callsite_materialization_stats
    except AttributeError:
        stats = CallsiteMaterializationStats()
        carrier._inertia_callsite_materialization_stats = stats
    if not isinstance(stats, CallsiteMaterializationStats):
        raise TypeError("callsite materialization statistics must use CallsiteMaterializationStats")
    return stats


def _sync_callsite_materialization_stats_8616(codegen: StructuredAstValue) -> CallsiteMaterializationStats:
    """Mirror typed callsite counters into the shared evidence trace."""
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    raw = ensure_stack_probe_fact_stats_8616(codegen)
    raw.update(stats.fact_trace_counters())
    return stats


def _record_stack_probe_helper_target_fingerprints_8616(
    codegen: StructuredAstValue, *, summary: StructuredAstValue = None, call: StructuredAstValue = None
) -> None:
    target_addrs: set[int] = set()
    target_addr = summary.target_addr if summary is not None else None
    if isinstance(target_addr, int):
        target_addrs.add(target_addr)
    callee_func = getattr(call, "callee_func", None) if call is not None else None
    callee_addr = getattr(callee_func, "addr", None)
    if isinstance(callee_addr, int):
        target_addrs.add(callee_addr)
    if not target_addrs:
        return
    fingerprints: set[str] = set(
        cast(
            Iterable[str],
            getattr(codegen, "_inertia_stack_probe_helper_target_fingerprints_8616", ()) or (),
        )
    )
    for target in target_addrs:
        for candidate in (target, target & 0xFFFF):
            fingerprints.add(f"addr:{candidate:#x}")
            fingerprints.add(f"name:addr:{candidate:#x}")
    codegen._inertia_stack_probe_helper_target_fingerprints_8616 = tuple(sorted(fingerprints))


def _is_stack_probe_call_name_8616(name: str | None) -> bool:
    if not isinstance(name, str):
        return False
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    lowered = normalized.lower()
    return lowered in {
        "anchkstk",
        "chkstk",
        "_chkstk",
        "__chkstk",
        "__aNchkstk".lower(),
    }


def _lookup_iter_functions_8616(candidate_project: StructuredAstValue) -> StructuredAstValue:
    """Return the candidate project's function inventory as a tuple."""
    functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
    if functions is None:
        return ()
    values = getattr(functions, "values", None)
    if callable(values):
        try:
            return tuple(cast(Iterable[StructuredAstValue], values()))
        except Exception:
            return ()
    return ()


def _lookup_unique_near_target_8616(candidate_project: StructuredAstValue, candidate_addr: int) -> StructuredAstValue:
    """Return the unique function whose low 16-bit address matches the target."""
    if not (isinstance(candidate_addr, int) and 0 <= candidate_addr <= 0xFFFF):
        return None
    matches = []
    for function in _lookup_iter_functions_8616(candidate_project):
        func_addr = getattr(function, "addr", None)
        if isinstance(func_addr, int) and (func_addr & 0xFFFF) == candidate_addr:
            matches.append(function)
    if len(matches) == 1:
        return matches[0]
    return None


def _contains_function_addr_8616(
    containing: StructuredAstValue,
    candidate_addr: int,
    ceiling_addr: StructuredAstValue,
    *,
    allow_range: bool,
) -> bool:
    """Return whether the candidate address belongs to the containing function."""
    if containing is None:
        return False
    start_addr = getattr(containing, "addr", None)
    if not isinstance(start_addr, int):
        return allow_range is False
    if not isinstance(start_addr, int) or start_addr > candidate_addr:
        return False
    block_addrs = _boundary_tuple_8616(getattr(containing, "block_addrs_set", ()) or ())
    if candidate_addr in block_addrs:
        return True
    if start_addr == candidate_addr:
        return True
    if allow_range and callable(ceiling_addr):
        try:
            next_addr = ceiling_addr(start_addr + 1)
        except Exception as ex:
            log.debug(
                "ceiling_addr lookup failed target=%#x candidate_start=%#x: %s",
                candidate_addr,
                start_addr,
                ex,
            )
            next_addr = None
        if isinstance(next_addr, int):
            return start_addr <= candidate_addr < next_addr
    return False


def _lookup_exact_or_containing_8616(
    candidate_project: StructuredAstValue,
    candidate_addr: int,
    *,
    allow_containing: bool,
) -> StructuredAstValue:
    """Return an exact or range-containing function for the candidate address."""
    functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", lambda **_: None)
    function = lookup(addr=candidate_addr, create=False)
    floor_func = getattr(functions, "floor_func", None)
    ceiling_addr = getattr(functions, "ceiling_addr", None)

    if _contains_function_addr_8616(function, candidate_addr, ceiling_addr, allow_range=False):
        return function
    if not allow_containing or not callable(floor_func):
        return None
    try:
        containing = floor_func(candidate_addr)
    except Exception as ex:
        log.debug("floor_func lookup failed target=%#x: %s", candidate_addr, ex)
        containing = None
    if containing is None or not _contains_function_addr_8616(containing, candidate_addr, ceiling_addr, allow_range=True):
        return None
    return containing


def _lookup_callee_function_8616(
    project: StructuredAstValue, target_addr: int, *, allow_containing: bool = True
) -> StructuredAstValue:
    ordered_addrs = _candidate_linear_target_addrs_8616(project, target_addr)

    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        for candidate_addr in ordered_addrs:
            function = _lookup_exact_or_containing_8616(
                candidate_project, candidate_addr, allow_containing=allow_containing
            )
            if function is not None:
                return function
            function = _lookup_unique_near_target_8616(candidate_project, candidate_addr)
            if function is not None:
                return function
    return None


def _first_rebased_sidecar_label_8616(
    lookup_addrs: frozenset[int],
    target_addr: int,
    resolve: Callable[[int], StructuredAstValue],
) -> StructuredAstValue:
    """Return the first non-None label resolved from the non-target lookup addresses."""
    for lookup_addr in sorted(lookup_addrs - {target_addr}):
        rebased = resolve(lookup_addr)
        if rebased is not None:
            return rebased
    return None


def _sidecar_label_in_lookup_addrs_8616(
    target_addr: int,
    lookup_addrs: set[int],
    *,
    label_maps: tuple[StructuredAstValue, ...],
    metadata_items: tuple[StructuredAstValue, ...],
) -> str | None:
    """Resolve a unique sidecar label across the candidate lookup addresses."""
    exact_target = __sidecar_label_for_target_8616___exact_label(target_addr, label_maps=label_maps)
    if exact_target is not None:
        return exact_target
    exact_rebased = _first_rebased_sidecar_label_8616(
        lookup_addrs, target_addr,
        lambda addr: __sidecar_label_for_target_8616___exact_label(addr, label_maps=label_maps),
    )
    if exact_rebased is not None:
        return exact_rebased
    if any(__sidecar_label_for_target_8616___has_exact_label(lookup_addr, label_maps=label_maps) for lookup_addr in lookup_addrs):
        return None
    range_target = __sidecar_label_for_target_8616___containing_range_label(target_addr, metadata_items=metadata_items)
    if range_target is not None:
        return range_target
    target_offset = __sidecar_label_for_target_8616___unique_offset_label(target_addr & 0xFFFF, label_maps=label_maps)
    if target_offset is not None:
        return target_offset
    range_rebased = _first_rebased_sidecar_label_8616(
        lookup_addrs, target_addr,
        lambda addr: __sidecar_label_for_target_8616___containing_range_label(addr, metadata_items=metadata_items),
    )
    if range_rebased is not None:
        return range_rebased
    return _first_rebased_sidecar_label_8616(
        lookup_addrs, target_addr,
        lambda addr: __sidecar_label_for_target_8616___unique_offset_label(addr & 0xFFFF, label_maps=label_maps),
    )


def _project_main_object_min_addr_8616(project: StructuredAstValue) -> int | None:
    loader = getattr(project, "loader", None)
    main_object = getattr(loader, "main_object", None)
    min_addr = getattr(main_object, "min_addr", None)
    return int(min_addr) if isinstance(min_addr, int) else None


def _candidate_linear_target_addrs_8616(project: StructuredAstValue, target_addr: int) -> tuple[int, ...]:
    candidate_addrs = [target_addr]
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        candidate_addrs.append(target_addr + original_delta)
        rebased = target_addr - original_delta
        if rebased >= 0:
            candidate_addrs.append(rebased)
    if 0 <= target_addr <= 0xFFFF:
        for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
            image_base = _project_main_object_min_addr_8616(candidate_project)
            if isinstance(image_base, int):
                candidate_addrs.append(image_base + target_addr)
    ordered: list[int] = []
    for addr in candidate_addrs:
        if isinstance(addr, int) and addr not in ordered:
            ordered.append(addr)
    return tuple(ordered)


def _sidecar_label_for_target_8616(project: StructuredAstValue, target_addr: int) -> str | None:

    return __sidecar_label_for_target_8616___impl(project=project, target_addr=target_addr)


def __sidecar_label_for_target_8616___impl(*, project: StructuredAstValue, target_addr: int) -> str | None:
    if project is None or not isinstance(target_addr, int):
        return None

    label_maps = tuple(__sidecar_label_for_target_8616___label_maps(project=project))
    metadata_items = __sidecar_label_for_target_8616___metadata_items(project=project)
    if not label_maps and not metadata_items:
        return None

    lookup_addrs = {target_addr}
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        lookup_addrs.add(target_addr + original_delta)
        rebased = target_addr - original_delta
        if rebased >= 0:
            lookup_addrs.add(rebased)

    return _sidecar_label_in_lookup_addrs_8616(
        target_addr, lookup_addrs, label_maps=label_maps, metadata_items=metadata_items
    )



def __sidecar_label_for_target_8616___metadata_items(*, project: StructuredAstValue) -> tuple[StructuredAstValue, ...]:
    original_project = getattr(project, "_inertia_original_project", None)
    items = []
    for candidate_project in (project, original_project):
        if candidate_project is None:
            continue
        metadata = getattr(candidate_project, "_inertia_lst_metadata", None)
        if metadata is not None and metadata not in items:
            items.append(metadata)
    return tuple(items)



def __sidecar_label_for_target_8616___label_maps(*, project: StructuredAstValue) -> StructuredAstValue:
    original_project = getattr(project, "_inertia_original_project", None)
    for candidate_project in (project, original_project):
        if candidate_project is None:
            continue
        for labels in (
            getattr(getattr(candidate_project, "_inertia_lst_metadata", None), "code_labels", None),
            getattr(getattr(candidate_project, "kb", None), "labels", None),
        ):
            if labels is not None:
                yield labels



def __sidecar_label_for_target_8616___exact_label(addr: int, *, label_maps: tuple[StructuredAstValue, ...]) -> str | None:
    for labels in label_maps:
        label = getattr(labels, "get", lambda _addr: None)(addr)
        normalized = __sidecar_label_for_target_8616___normalized_label(label)
        if normalized is not None:
            return normalized
    return None



def __sidecar_label_for_target_8616___normalized_label(label: StructuredAstValue) -> str | None:
    if not isinstance(label, str) or not label:
        return None
    normalized = normalize_callee_name_8616(label.lstrip("_"))
    if isinstance(normalized, str) and normalized and not normalized.startswith("sub_"):
        return normalized
    return None



def __sidecar_label_for_target_8616___has_exact_label(addr: int, *, label_maps: tuple[StructuredAstValue, ...]) -> bool:
    """Return whether sidecar evidence names this exact address."""
    for labels in label_maps:
        label = getattr(labels, "get", lambda _addr: None)(addr)
        if isinstance(label, str) and label:
            return True
    return False



def __sidecar_label_for_target_8616___containing_range_label(addr: int, *, metadata_items: tuple[StructuredAstValue, ...]) -> str | None:
    matches: set[str] = set()
    for metadata in metadata_items:
        code_ranges = getattr(metadata, "code_ranges", None)
        code_labels = getattr(metadata, "code_labels", None)
        if not isinstance(code_ranges, dict) or not isinstance(code_labels, dict):
            continue
        for start_addr, code_span in code_ranges.items():
            if not isinstance(start_addr, int) or not isinstance(code_span, tuple) or len(code_span) != 2:
                continue
            start, end = code_span
            if not isinstance(start, int) or not isinstance(end, int) or not (start <= addr < end):
                continue
            normalized = __sidecar_label_for_target_8616___normalized_label(code_labels.get(start_addr) or code_labels.get(start))
            if normalized is not None:
                matches.add(normalized)
    return next(iter(matches)) if len(matches) == 1 else None



def __sidecar_label_for_target_8616___unique_offset_label(offset: int, *, label_maps: tuple[StructuredAstValue, ...]) -> str | None:
    matches: set[str] = set()
    for labels in label_maps:
        items = getattr(labels, "items", None)
        if not callable(items):
            continue
        try:
            iterable = tuple(cast(Iterable[tuple[StructuredAstValue, StructuredAstValue]], items()))
        except Exception:
            continue
        for label_addr, label_name in iterable:
            if not isinstance(label_addr, int) or (label_addr & 0xFFFF) != offset:
                continue
            normalized = __sidecar_label_for_target_8616___normalized_label(label_name)
            if normalized is not None:
                matches.add(normalized)
    return next(iter(matches)) if len(matches) == 1 else None



def _function_matches_target_addr_8616(function: StructuredAstValue, target_addr: int | None) -> bool:
    if function is None or not isinstance(target_addr, int):
        return False
    start_addr = getattr(function, "addr", None)
    if not isinstance(start_addr, int):
        return False
    if _target_addr_matches_near_or_linear_8616(start_addr, target_addr):
        return True
    block_addrs = _boundary_tuple_8616(getattr(function, "block_addrs_set", ()) or ())
    return any(_target_addr_matches_near_or_linear_8616(block_addr, target_addr) for block_addr in block_addrs)


def _function_name_matches_target_addr_8616(function: StructuredAstValue, target_addr: int | None) -> bool:
    if function is None or not isinstance(target_addr, int):
        return False
    for raw_name in (getattr(function, "name", None),):
        if not isinstance(raw_name, str):
            continue
        normalized = normalize_callee_name_8616(raw_name) or raw_name
        for candidate in (raw_name, normalized):
            match = _SUB_TARGET_RE.match(candidate)
            if match is None:
                match = _NAMESPACED_TARGET_RE.match(candidate)
            if match is None:
                continue
            with contextlib.suppress(ValueError):
                if _target_addr_matches_near_or_linear_8616(int(match.group("addr"), 16), target_addr):
                    return True
    return False


def _target_addr_matches_near_or_linear_8616(candidate_addr: int, target_addr: int) -> bool:
    if candidate_addr == target_addr:
        return True
    if not (isinstance(candidate_addr, int) and isinstance(target_addr, int)):
        return False
    # x86-16 near calls encode the callee IP. The project function database stores
    # rebased linear addresses, so match the low 16-bit offset when the summary
    # target is a near IP rather than a linear address.
    if 0 <= target_addr <= 0xFFFF:
        return (candidate_addr & 0xFFFF) == target_addr
    return False


def _project_label_at_addr_8616(project: StructuredAstValue, addr: int) -> str | None:
    for labels in (
        getattr(getattr(project, "_inertia_lst_metadata", None), "code_labels", None),
        getattr(getattr(project, "kb", None), "labels", None),
    ):
        if labels is None:
            continue
        with contextlib.suppress(Exception):
            label = labels.get(addr)
        if isinstance(label, str) and label.strip():
            normalized = normalize_callee_name_8616(label.lstrip("_"))
            return normalized or label.lstrip("_")
    return None


def _project_bytes_at_8616(project: StructuredAstValue, addr: int, size: int) -> bytes:
    memory = getattr(getattr(project, "loader", None), "memory", None)
    load = getattr(memory, "load", None)
    if not callable(load):
        return b""
    with contextlib.suppress(Exception):
        return bytes(cast(Any, load(addr, size)))
    return b""


def _looks_like_x86_16_function_prologue_8616(data: bytes) -> bool:
    return data.startswith((b"\x55\x8b\xec", b"\x55\x89\xe5"))


def _target_addr_has_labeled_function_prologue_8616(project: StructuredAstValue, target_addr: int) -> bool:
    candidate_addrs = _candidate_linear_target_addrs_8616(project, target_addr)
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        if candidate_project is None:
            continue
        for candidate_addr in candidate_addrs:
            if _project_label_at_addr_8616(candidate_project, candidate_addr) is None:
                continue
            if _looks_like_x86_16_function_prologue_8616(_project_bytes_at_8616(candidate_project, candidate_addr, 4)):
                return True
    return False


def _target_addr_is_recovered_function_entry_8616(project: StructuredAstValue, target_addr: int) -> bool:
    if project is None or not isinstance(target_addr, int):
        return False
    if _lookup_callee_function_8616(project, target_addr, allow_containing=False) is not None:
        return True
    candidate_addrs = _candidate_linear_target_addrs_8616(project, target_addr)
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", None)
        if not callable(lookup):
            continue
        for candidate_addr in candidate_addrs:
            with contextlib.suppress(Exception):
                function = lookup(addr=candidate_addr, create=False)
            if function is None:
                continue
            start_addr = getattr(function, "addr", None)
            if isinstance(start_addr, int) and start_addr == candidate_addr:
                return True
    return bool(_target_addr_has_labeled_function_prologue_8616(project, target_addr))


def _annotated_function_pointer_stack_offsets_8616(
    project: StructuredAstValue, cfunc: StructuredAstValue
) -> frozenset[int]:
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return frozenset()
    function = _current_callsite_function_8616(project, func_addr)
    info = getattr(function, "info", None) if function is not None else None
    annotations = info.get(ANNOTATION_KEY) if isinstance(info, dict) else None
    stack_vars = annotations.get("stack_vars") if isinstance(annotations, dict) else None
    if not isinstance(stack_vars, dict):
        return frozenset()
    offsets: set[int] = set()
    for raw_offset, spec in stack_vars.items():
        if not isinstance(raw_offset, int) or not isinstance(spec, dict):
            continue
        type_ = spec.get("type")
        if isinstance(type_, SimTypePointer) and isinstance(getattr(type_, "pts_to", None), SimTypeFunction):
            offsets.add(raw_offset)
    return frozenset(offsets)


def _candidate_projects_and_addrs_for_insn_8616(
    project: StructuredAstValue, ins_addr: int | None
) -> tuple[tuple[StructuredAstValue, int], ...]:
    if project is None or not isinstance(ins_addr, int):
        return ()
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    projects = tuple(candidate for candidate in (project, original_project) if candidate is not None)
    addrs = {ins_addr}
    if isinstance(original_delta, int):
        addrs.add(ins_addr + original_delta)
    return tuple((candidate_project, addr) for candidate_project in projects for addr in sorted(addrs))


_PUSH_SOURCE_OPS_8616 = frozenset({
    CallsitePushExprOp8616.ADC_SOURCE.value,
    CallsitePushExprOp8616.ADD_SOURCE.value,
    CallsitePushExprOp8616.SBB_SOURCE.value,
    CallsitePushExprOp8616.SUB_SOURCE.value,
})

_PUSH_COMMUTATIVE_OPS_8616 = {
    CallsitePushExprOp8616.ADD.value: "Add",
    CallsitePushExprOp8616.AND.value: "And",
    CallsitePushExprOp8616.OR.value: "Or",
    CallsitePushExprOp8616.XOR.value: "Xor",
    CallsitePushExprOp8616.MUL.value: "Mul",
}


def _mov_reg_imm_at_8616(candidate_project: StructuredAstValue, addr: int, expected: int) -> int | None:
    """Return the destination register of ``mov reg, imm`` at the address."""
    try:
        raw = bytes(candidate_project.loader.memory.load(addr, 3))
    except Exception:
        return None
    if len(raw) < 3:
        return None
    opcode = raw[0]
    if not 0xB8 <= opcode <= 0xBF:
        return None
    imm16 = int.from_bytes(raw[1:3], "little")
    if imm16 != expected:
        return None
    return opcode - 0xB8


def _mov_reg_imm_setup_matches_push_source_8616(
    project: StructuredAstValue, ins_addr: int | None, source: StructuredAstValue
) -> bool:
    if not (isinstance(source, tuple) and len(source) >= 2 and source[0] == "imm" and isinstance(source[1], int)):
        return False
    expected = int(source[1]) & 0xFFFF

    for candidate_project, candidate_ins_addr in _candidate_projects_and_addrs_for_insn_8616(project, ins_addr):
        reg = _mov_reg_imm_at_8616(candidate_project, candidate_ins_addr, expected)
        if reg is not None:
            return True
        reg = _mov_reg_imm_at_8616(candidate_project, candidate_ins_addr - 3, expected)
        if reg is None:
            continue
        try:
            push = bytes(candidate_project.loader.memory.load(candidate_ins_addr, 1))
        except Exception:
            continue
        if len(push) != 1:
            continue
        opcode = push[0]
        if not 0x50 <= opcode <= 0x57:
            continue
        if opcode - 0x50 == reg:
            return True
    return False


def _setup_shift_byte_variants_8616(variants: StructuredAstValue, op_name: str, op_value: int, reg: int, shift_modrm: dict) -> list[bytearray]:
    """Build byte-pattern variants for one push-op family."""
    next_variants: list[bytearray] = []
    modrm = shift_modrm[op_name]
    for raw in variants:
        if op_value == 1:
            next_variants.append(bytearray(raw + bytearray((0xD1, modrm | reg))))
        elif op_value <= 0xFF:
            next_variants.append(bytearray(raw + bytearray((0xC1, modrm | reg, op_value))))
    return next_variants


def _setup_neg_byte_variants_8616(variants: StructuredAstValue, op_name: str, op_value: int, reg: int) -> list[bytearray]:
    """Build byte-pattern variants for one push-op family."""
    next_variants: list[bytearray] = []
    for raw in variants:
        if op_value == 0:
            next_variants.append(bytearray(raw + bytearray((0xF7, 0xD8 | reg))))
    return next_variants


def _setup_add_byte_variants_8616(variants: StructuredAstValue, op_name: str, op_value: int, reg: int) -> list[bytearray]:
    """Build byte-pattern variants for one push-op family."""
    next_variants: list[bytearray] = []
    for raw in variants:
        if reg == 0:
            next_variants.append(
                bytearray(raw + bytearray((0x05, op_value & 0xFF, (op_value >> 8) & 0xFF)))
            )
        else:
            next_variants.append(
                bytearray(raw + bytearray((0x81, 0xC0 | reg, op_value & 0xFF, (op_value >> 8) & 0xFF)))
            )
        if op_value == 1:
            next_variants.append(bytearray(raw + bytearray((0x40 | reg,))))
    return next_variants


def _setup_sub_byte_variants_8616(variants: StructuredAstValue, op_name: str, op_value: int, reg: int) -> list[bytearray]:
    """Build byte-pattern variants for one push-op family."""
    next_variants: list[bytearray] = []
    for raw in variants:
        if reg == 0:
            next_variants.append(
                bytearray(raw + bytearray((0x2D, op_value & 0xFF, (op_value >> 8) & 0xFF)))
            )
        else:
            next_variants.append(
                bytearray(raw + bytearray((0x81, 0xE8 | reg, op_value & 0xFF, (op_value >> 8) & 0xFF)))
            )
        if op_value == 1:
            next_variants.append(bytearray(raw + bytearray((0x48 | reg,))))
    return next_variants



def _setup_op_byte_variants_8616(
    variants: Iterable[bytearray], op_name: str, op_value: int, reg: int
) -> list[bytearray] | None:
    """Expand byte-pattern variants for one expression operation."""
    op_value &= 0xFFFF
    next_variants: list[bytearray] = []
    shift_modrm = {
        CallsitePushExprOp8616.SHL.value: 0xE0,
        CallsitePushExprOp8616.SHR.value: 0xE8,
        CallsitePushExprOp8616.SAR.value: 0xF8,
    }
    if op_name in shift_modrm:
        return _setup_shift_byte_variants_8616(variants, op_name, op_value, reg, shift_modrm)
    if op_name == CallsitePushExprOp8616.NEG.value:
        return _setup_neg_byte_variants_8616(variants, op_name, op_value, reg)
    if op_name == CallsitePushExprOp8616.ADD.value:
        return _setup_add_byte_variants_8616(variants, op_name, op_value, reg)
    if op_name == CallsitePushExprOp8616.SUB.value:
        return _setup_sub_byte_variants_8616(variants, op_name, op_value, reg)
    return None
    return next_variants


def _setup_byte_variants_for_reg_8616(
    reg: int, bp_offset: int, ops: tuple[tuple[str, int], ...]
) -> tuple[bytes, ...]:
    """Return candidate setup-instruction byte patterns for the register."""
    variants = [bytearray((0x8B, 0x40 | (reg << 3) | 0x06, bp_offset & 0xFF))]
    for op_name, op_value in ops:
        next_variants = _setup_op_byte_variants_8616(variants, op_name, op_value, reg)
        if not next_variants:
            return ()
        variants = next_variants
    for raw in variants:
        raw.append(0x50 | reg)
    return tuple(bytes(raw) for raw in variants)


def _reg_setup_bytes_match_8616(
    candidate_project: StructuredAstValue,
    candidate_ins_addr: int,
    bp_offset: int,
    ops: tuple[StructuredAstValue, ...],
) -> bool:
    for reg in range(8):
        for expected in _setup_byte_variants_for_reg_8616(reg, bp_offset, ops):
            start = candidate_ins_addr - len(expected) + 1
            try:
                actual = bytes(candidate_project.loader.memory.load(start, len(expected)))
            except Exception:
                continue
            if actual == expected:
                return True
    return False


def _reg_expr_setup_matches_push_source_8616(
    project: StructuredAstValue, ins_addr: int | None, source: StructuredAstValue
) -> bool:
    if not (
        isinstance(source, tuple)
        and len(source) == 3
        and source[0] == "expr"
        and isinstance(source[1], tuple)
        and len(source[1]) >= 2
        and source[1][0] == "bp"
        and isinstance(source[1][1], int)
        and isinstance(source[2], tuple)
    ):
        return False
    bp_offset = int(source[1][1])
    ops = tuple(source[2])
    if not all(isinstance(op_name, str) and isinstance(op_value, int) for op_name, op_value in ops):
        return False
    if not -0x80 <= bp_offset <= 0x7F:
        return False

    if len(ops) == 1 and ops[0][0] == CallsitePushExprOp8616.MUL.value:
        factor = int(ops[0][1]) & 0xFFFF
        expected = bytes((0xB8, factor & 0xFF, (factor >> 8) & 0xFF, 0xF7, 0x6E, bp_offset & 0xFF, 0x50))
        for candidate_project, candidate_ins_addr in _candidate_projects_and_addrs_for_insn_8616(project, ins_addr):
            start = candidate_ins_addr - len(expected) + 1
            try:
                actual = bytes(candidate_project.loader.memory.load(start, len(expected)))
            except Exception:
                continue
            if actual == expected:
                return True
        return False

    for candidate_project, candidate_ins_addr in _candidate_projects_and_addrs_for_insn_8616(project, ins_addr):
        if _reg_setup_bytes_match_8616(candidate_project, candidate_ins_addr, bp_offset, ops):
            return True
    return False


def _direct_bp_push_instruction_matches_source_8616(
    project: StructuredAstValue,
    ins_addr: int | None,
    source: StructuredAstValue,
) -> bool:
    """Prove that an instruction is ``push word ptr [bp+offset]`` for a source."""
    if not (
        isinstance(source, tuple)
        and len(source) >= 2
        and source[0] == CallsitePushSourceKind8616.BP_VALUE.value
        and isinstance(source[1], int)
    ):
        return False
    bp_offset = int(source[1])
    if -0x80 <= bp_offset <= 0x7F:
        variants = (bytes((0xFF, 0x76, bp_offset & 0xFF)),)
    elif -0x8000 <= bp_offset <= 0x7FFF:
        variants = (bytes((0xFF, 0xB6, bp_offset & 0xFF, (bp_offset >> 8) & 0xFF)),)
    else:
        return False
    for candidate_project, candidate_ins_addr in _candidate_projects_and_addrs_for_insn_8616(project, ins_addr):
        for expected in variants:
            try:
                actual = bytes(candidate_project.loader.memory.load(candidate_ins_addr, len(expected)))
            except Exception:
                continue
            if actual == expected:
                return True
    return False


def _collect_bp_offsets_nested_8616(current: tuple, offsets: set[int]) -> None:
    """Accumulate BP offsets from the indexed/global/segmented push-source kinds."""
    source_kind = current[0]
    if source_kind == CallsitePushSourceKind8616.BP_INDEX_ADDRESS.value:
        if isinstance(current[1], int):
            offsets.add(int(current[1]))
        if len(current) >= 5 and isinstance(current[4], tuple):
            _collect_bp_offsets_8616(current[4], offsets)
        return
    if source_kind == CallsitePushSourceKind8616.GLOBAL_INDEX_VALUE.value and len(current) >= 4:
        if isinstance(current[3], tuple):
            _collect_bp_offsets_8616(current[3], offsets)
        return
    if (
        source_kind == CallsitePushSourceKind8616.SEGMENTED_INDIRECT_VALUE.value
        and len(current) == 4
        and isinstance(current[3], tuple)
    ):
        _collect_bp_offsets_8616(current[3], offsets)


def _collect_bp_offsets_8616(current: StructuredAstValue, offsets: set[int]) -> None:
    """Accumulate BP offsets read by a structured push-source expression."""
    if not isinstance(current, tuple) or len(current) < 2:
        return
    source_kind = current[0]
    if source_kind in {CallsitePushSourceKind8616.BP_VALUE.value, CallsitePushSourceKind8616.BP_ADDRESS.value}:
        if isinstance(current[1], int):
            offsets.add(int(current[1]))
        return
    if source_kind == CallsitePushSourceKind8616.EXPR.value and isinstance(current[1], tuple):
        _collect_bp_offsets_8616(current[1], offsets)
        return
    _collect_bp_offsets_nested_8616(current, offsets)


def _bp_offsets_from_push_source_8616(source: StructuredAstValue) -> frozenset[int]:
    """Return BP stack offsets read by a structured callsite push source."""
    offsets: set[int] = set()
    _collect_bp_offsets_8616(source, offsets)
    return frozenset(offsets)


def _expr_push_sources_for_bp_offset_8616(
    push_sources: tuple[StructuredAstValue, ...], offset: int
) -> tuple[tuple[StructuredAstValue, ...], ...]:
    """Select expression push sources proven to read a BP stack offset."""
    if not isinstance(push_sources, tuple):
        return ()
    matches: list[tuple[StructuredAstValue, ...]] = []
    for source in push_sources:
        if not (
            isinstance(source, tuple)
            and len(source) == 3
            and source[0] == CallsitePushSourceKind8616.EXPR.value
            and isinstance(source[1], tuple)
        ):
            continue
        if offset in _bp_offsets_from_push_source_8616(source):
            matches.append(source)
    return tuple(matches)


def _expr_push_sources_8616(
    push_sources: tuple[StructuredAstValue, ...],
) -> tuple[tuple[StructuredAstValue, ...], ...]:
    if not isinstance(push_sources, tuple):
        return ()
    return tuple(
        source
        for source in push_sources
        if isinstance(source, tuple)
        and len(source) == 3
        and source[0] == CallsitePushSourceKind8616.EXPR.value
        and isinstance(source[1], tuple)
    )


def _signature_arg_parts_and_variadic_8616(
    decl: str,
) -> tuple[tuple[str, ...], bool] | None:

    return __signature_arg_parts_and_variadic_8616___impl(decl=decl)


def __signature_arg_parts_and_variadic_8616___impl(*, decl: str) -> tuple[tuple[str, ...], bool] | None:
    m = re.search(r"\((?P<args>[^)]*)\)", decl)
    arg_text = m.group("args").strip() if m is not None else ""
    if not arg_text or arg_text == "void":
        return ((), False)
    parts = tuple(part.strip() for part in arg_text.split(",") if part.strip())
    if parts and parts[-1] == "...":
        return (parts[:-1], True)
    return (parts, False)



def _known_callee_arity_contract_8616(name: str) -> CallArityContract8616:

    return __known_callee_arity_contract_8616___impl(name=name)


def __known_callee_arity_contract_8616___impl(*, name: str) -> CallArityContract8616:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return CallArityContract8616(None)

    decl = preferred_known_helper_signature_decl(normalized)
    if isinstance(decl, str):
        parsed = _signature_arg_parts_and_variadic_8616(decl)
        if parsed is not None:
            parts, variadic = parsed
            return CallArityContract8616(
                len(parts),
                CallArityMode8616.MINIMUM if variadic else CallArityMode8616.EXACT,
            )

    table = {
        "aNchkstk": 0,
        "__aNchkstk": 0,
        "clock": 0,
        "memset": 3,
        "_memset": 3,
        "settextcolor": 1,
        "_settextcolor": 1,
        "settextposition": 2,
        "_settextposition": 2,
        "outtext": 1,
        "_outtext": 1,
        "outtextxy": 3,
        "_outtextxy": 3,
        "sprintf": 2,
        "_sprintf": 2,
        "settextrows": 1,
        "clearscreen": 1,
        "displaycursor": 1,
        "setvideomode": 1,
    }
    if normalized in table:
        return CallArityContract8616(table[normalized], CallArityMode8616.EXACT)
    return CallArityContract8616(None)



def _expected_arg_count_for_known_callee_8616(name: str) -> int | None:
    return _known_callee_arity_contract_8616(name).count


def _call_arity_contract_allows_count_8616(contract: CallArityContract8616, actual_count: int) -> bool:
    if not isinstance(contract.count, int):
        return True
    if contract.mode is CallArityMode8616.EXACT:
        return actual_count == contract.count
    if contract.mode is CallArityMode8616.MINIMUM:
        return actual_count >= contract.count
    return True


def _semantic_call_name_from_summary_8616(
    project: StructuredAstValue, summary: StructuredAstValue, fallback_name: str | None
) -> str | None:
    if summary is not None:
        target_addr = summary.target_addr
        if isinstance(target_addr, int):
            sidecar_name = normalize_callee_name_8616(_sidecar_label_for_target_8616(project, target_addr))
            if isinstance(sidecar_name, str) and sidecar_name and not sidecar_name.startswith("sub_"):
                return sidecar_name
    normalized = normalize_callee_name_8616(fallback_name) if isinstance(fallback_name, str) else None
    return normalized if isinstance(normalized, str) and normalized else fallback_name


def _expected_arg_count_for_call_8616(
    summary_arg_count: int | None,
    *,
    known_arg_count: int | None,
    prototype_arg_count: int | None,
) -> int | None:
    """Resolve expected call arity with summary evidence preferred over declarative hints.

    Summary data is authoritative when present and non-zero. A summary value of 0 is
    treated as explicit zero only when no stronger known/prototype arity is available.
    """
    if isinstance(summary_arg_count, int):
        if summary_arg_count > 0:
            return summary_arg_count
        return 0
    if isinstance(known_arg_count, int) and known_arg_count > 0:
        return known_arg_count
    if isinstance(prototype_arg_count, int) and prototype_arg_count > 0:
        return prototype_arg_count
    return None


def _push_source_width_for_arg_accounting_8616(source: StructuredAstValue) -> int | None:
    if not isinstance(source, tuple) or len(source) < 2:
        return None
    if len(source) >= 3 and isinstance(source[2], int) and source[2] > 0:
        return int(source[2])
    if source[0] in {
        "bp",
        "bp_addr",
        "bp_index_addr",
        "global",
        "global_index",
        "seg_indirect",
        "imm",
        "expr",
        "ret_reg",
        "seg",
        "ax",
        "bx",
        "cx",
        "dx",
        "di",
        "si",
    }:
        return 2
    return None


def _push_sources_total_width_for_arg_accounting_8616(sources: tuple[StructuredAstValue, ...]) -> int | None:
    if not isinstance(sources, tuple) or not sources:
        return None
    total = 0
    for source in sources:
        width = _push_source_width_for_arg_accounting_8616(source)
        if not isinstance(width, int):
            return None
        total += width
    return total


def _prototype_widths_account_for_push_sources_top_8616(
    widths: tuple[int, ...] | None, sources: tuple[StructuredAstValue, ...]
) -> bool:
    if not widths or not isinstance(sources, tuple) or not sources:
        return False
    source_total = _push_sources_total_width_for_arg_accounting_8616(sources)
    return isinstance(source_total, int) and source_total == sum(max(2, int(width)) for width in widths)


def _logical_arg_widths_for_summary_8616(
    summary: CallsiteSummary8616 | None,
) -> tuple[int, ...] | None:
    """Return validated logical widths carried by an owned callsite summary."""
    if summary is None or not summary.logical_arg_widths:
        return None
    push_sources = _boundary_tuple_8616(summary.push_arg_sources)
    logical_widths = summary.logical_arg_widths
    if not _prototype_widths_account_for_push_sources_top_8616(logical_widths, push_sources):
        return None
    return tuple(width for width in logical_widths if isinstance(width, int)) if all(
        isinstance(width, int) for width in logical_widths
    ) else None


def _logical_expected_arg_count_for_summary_8616(
    project: StructuredAstValue, node: StructuredAstValue, summary: CallsiteSummary8616
) -> int:
    push_sources = _boundary_tuple_8616(summary.push_arg_sources)
    logical_widths = _logical_arg_widths_for_summary_8616(summary)
    if logical_widths is not None:
        return len(logical_widths)
    summary_arg_count = summary.arg_count
    physical_count = (
        int(summary_arg_count)
        if isinstance(summary_arg_count, int) and summary_arg_count > 0
        else len(push_sources)
        if push_sources
        else 0
    )
    call_name = _call_node_name_8616(node) or ""
    known_contract = _known_callee_arity_contract_8616(call_name)
    known_widths = _known_helper_prototype_arg_widths_8616(project, call_name)
    if (
        known_widths is not None
        and _prototype_widths_account_for_push_sources_top_8616(known_widths, push_sources)
        and isinstance(known_contract.count, int)
        and known_contract.count == len(known_widths)
    ):
        return known_contract.count
    return physical_count


def _known_default_args_for_missing_8616(
    name: str, codegen: StructuredAstValue
) -> tuple[StructuredAstValue, ...] | None:
    """Compiler/runtime helper ABI defaults used when a known helper omits pushes."""
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return None
    defaults = {
        "clearscreen": (0,),
        "displaycursor": (0,),
        "setvideomode": (0xFFFF,),
    }
    values = defaults.get(normalized)
    if values is None:
        return None
    return tuple(structured_c.CConstant(value, SimTypeShort(False), codegen=codegen) for value in values)


def _prototype_call_arg_semantic_kind_8616(prototype: StructuredAstValue, arg_index: int) -> CallArgSemanticKind8616:
    args = getattr(prototype, "args", None)
    if not isinstance(args, (list, tuple)) or not (0 <= arg_index < len(args)):
        return CallArgSemanticKind8616.UNKNOWN
    arg_type = args[arg_index]
    if isinstance(arg_type, SimTypePointer):
        return CallArgSemanticKind8616.POINTER
    if arg_type is not None:
        return CallArgSemanticKind8616.VALUE
    return CallArgSemanticKind8616.UNKNOWN


def _callee_expects_pointer_arg_8616(
    name: str,
    arg_index: int,
    *,
    project: StructuredAstValue = None,
    prototype: StructuredAstValue = None,
    cod_path_hint: StructuredAstValue = None,
) -> bool:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return (
        _call_arg_semantic_kind_8616(
            normalized,
            arg_index,
            project=project,
            prototype=prototype,
            cod_path_hint=cod_path_hint,
        )
        is CallArgSemanticKind8616.POINTER
    )


def _call_arg_semantic_kind_8616(
    callee: str,
    arg_index: int,
    *,
    project: StructuredAstValue = None,
    prototype: StructuredAstValue = None,
    cod_path_hint: StructuredAstValue = None,
) -> CallArgSemanticKind8616:

    return __call_arg_semantic_kind_8616___impl(arg_index=arg_index, callee=callee, project=project, prototype=prototype)


def __call_arg_semantic_kind_8616___impl(*, arg_index: int, callee: str, project: StructuredAstValue, prototype: StructuredAstValue) -> CallArgSemanticKind8616:
    normalized = normalize_callee_name_8616(callee)
    if not isinstance(normalized, str):
        return CallArgSemanticKind8616.UNKNOWN
    cached = _KNOWN_HELPER_ARG_KIND_CACHE_8616.get(normalized)
    if cached is None:
        cached = {}
        decl = preferred_known_helper_signature_decl(normalized)
        if isinstance(decl, str):
            m = re.search(r"\((?P<args>[^)]*)\)", decl)
            arg_text = m.group("args").strip() if m is not None else ""
            if arg_text and arg_text != "void":
                parts = [part.strip() for part in arg_text.split(",") if part.strip()]
                for idx, part in enumerate(parts):
                    kind = (
                        CallArgSemanticKind8616.POINTER
                        if ("*" in part or "[" in part)
                        else CallArgSemanticKind8616.VALUE
                    )
                    cached[idx] = kind
        _KNOWN_HELPER_ARG_KIND_CACHE_8616[normalized] = cached
    helper_kind = cached.get(arg_index, CallArgSemanticKind8616.UNKNOWN)
    if helper_kind is not CallArgSemanticKind8616.UNKNOWN:
        return helper_kind
    if _bound_callee_pointer_argument_is_proven_8616(
        project,
        normalized,
        arg_index,
    ):
        return CallArgSemanticKind8616.POINTER
    return _prototype_call_arg_semantic_kind_8616(prototype, arg_index)



def _callee_name_should_yield_to_sidecar_8616(callee_func: StructuredAstValue, sidecar_label: str | None) -> bool:
    if callee_func is None or not isinstance(sidecar_label, str):
        return False
    callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if callee_name is None or callee_name.startswith("sub_"):
        return True
    if callee_name == sidecar_label:
        return False
    block_addrs = _boundary_tuple_8616(getattr(callee_func, "block_addrs_set", ()) or ())
    return len(block_addrs) == 0


def _cod_metadata_for_function_8616(project: SimpleNamespace, func_addr: int) -> StructuredAstValue | None:

    return __cod_metadata_for_function_8616___impl(func_addr=func_addr, project=project)


def _cod_project_variants_8616(
    project: SimpleNamespace,
    func_addr: int,
    original_project: StructuredAstValue,
    original_delta: StructuredAstValue,
) -> list[tuple[StructuredAstValue, tuple[int, ...]]]:
    """Return candidate (project, address) variants for COD metadata lookup."""
    project_addr_candidates = []
    if isinstance(original_delta, int):
        project_addr_candidates.append(func_addr + original_delta)
        rebased = func_addr - original_delta
        if rebased >= 0:
            project_addr_candidates.append(rebased)
    project_addr_candidates.append(func_addr)

    normalized_project_addr_candidates: list[int] = []
    for candidate in project_addr_candidates:
        if candidate not in normalized_project_addr_candidates:
            normalized_project_addr_candidates.append(candidate)

    project_variants: list[tuple[StructuredAstValue, tuple[int, ...]]] = [
        (project, tuple(normalized_project_addr_candidates))
    ]
    if original_project is not None:
        original_addr_candidates = [func_addr]
        if isinstance(original_delta, int):
            original_addr_candidates = [func_addr + original_delta]
        normalized_original_addr_candidates: list[int] = []
        for candidate in original_addr_candidates:
            if candidate >= 0 and candidate not in normalized_original_addr_candidates:
                normalized_original_addr_candidates.append(candidate)
        project_variants.append((original_project, tuple(normalized_original_addr_candidates)))
    return project_variants


def _cod_metadata_for_addr_8616(
    project: SimpleNamespace,
    candidate_project: StructuredAstValue,
    candidate_addr: int,
    lst_metadata: StructuredAstValue,
    cod_path: StructuredAstValue,
    binary_path: StructuredAstValue,
    cache: dict,
    fallback_addr: int,
) -> StructuredAstValue | None:
    """Resolve COD proc metadata for one candidate address."""
    function = getattr(getattr(candidate_project, "kb", None), "functions", None)
    function = getattr(function, "function", lambda **_: None)(addr=candidate_addr, create=False)
    function_name = getattr(function, "name", None)
    if not isinstance(function_name, str) or not function_name:
        function_name = _sidecar_label_for_target_8616(project, candidate_addr)
    if not isinstance(function_name, str) or not function_name:
        return None

    proc_kind = (getattr(lst_metadata, "cod_proc_kinds", {}).get(candidate_addr) or "NEAR").upper()
    name_candidates: list[str] = [function_name]
    if function_name.startswith("_"):
        stripped = function_name.lstrip("_")
        if stripped:
            name_candidates.append(stripped)
    else:
        name_candidates.append(f"_{function_name}")

    for candidate_name in name_candidates:
        cache_key = (str(cod_path), candidate_name, proc_kind)
        if cache_key in cache:
            return cache[cache_key]
        try:
            metadata = extract_cod_proc_metadata(Path(cod_path), candidate_name, proc_kind)
        except Exception as ex:
            log.debug(
                "COD metadata lookup failed path=%s candidate=%s kind=%s: %s",
                cod_path,
                candidate_name,
                proc_kind,
                ex,
            )
            continue
        cache[cache_key] = metadata
        if binary_path is not None:
            cache[(str(binary_path), fallback_addr, proc_kind)] = metadata
        return metadata
    return None


def __cod_metadata_for_function_8616___impl(*, func_addr: int, project: SimpleNamespace) -> StructuredAstValue | None:
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    project_variants = _cod_project_variants_8616(project, func_addr, original_project, original_delta)
    fallback_addr = (
        func_addr + original_delta
        if original_project is not None and isinstance(original_delta, int)
        else func_addr
    )

    for candidate_project, candidate_addrs in project_variants:
        lst_metadata = getattr(candidate_project, "_inertia_lst_metadata", None)
        cod_path = getattr(lst_metadata, "cod_path", None)
        if not cod_path:
            continue
        binary_path = getattr(
            getattr(getattr(candidate_project, "loader", None), "main_object", None), "binary", None
        )
        cache = getattr(candidate_project, "_inertia_sidecar_cod_metadata_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            candidate_project._inertia_sidecar_cod_metadata_cache = cache

        for candidate_addr in candidate_addrs:
            metadata = _cod_metadata_for_addr_8616(
                project,
                candidate_project,
                candidate_addr,
                lst_metadata,
                cod_path,
                binary_path,
                cache,
                fallback_addr,
            )
            if metadata is not None:
                return metadata
    return None



def _candidate_target_addrs_from_call_8616(node: StructuredAstValue) -> tuple[int, ...]:
    addrs: list[int] = []
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
        normalized = normalize_callee_name_8616(target)
        if not isinstance(normalized, str):
            continue
        match = _SUB_TARGET_RE.match(normalized)
        if match is None:
            match = _NAMESPACED_TARGET_RE.match(target)
        if match is None:
            continue
        try:
            addrs.append(int(match.group("addr"), 16))
        except ValueError:
            continue

    ordered: list[int] = []
    for addr in addrs:
        if addr not in ordered:
            ordered.append(addr)
    return tuple(ordered)


def _rename_call_node_from_sidecar_8616(project: StructuredAstValue, node: StructuredAstValue) -> bool:
    if project is None:
        return False
    renamed = False
    replacement = None
    for target_addr in _candidate_target_addrs_from_call_8616(node):
        replacement = _sidecar_label_for_target_8616(project, target_addr)
        if isinstance(replacement, str):
            break
    if not isinstance(replacement, str):
        return False

    callee_func = getattr(node, "callee_func", None)
    current_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    current_target = normalize_callee_name_8616(getattr(node, "callee_target", None))
    if callee_func is not None and (current_name is None or current_name.startswith("sub_")):
        callee_func.name = replacement
        renamed = True
    if current_target is None or current_target.startswith("sub_"):
        node.callee_target = replacement
        renamed = True
    return renamed


def _drop_detached_callee_func_8616(node: StructuredAstValue) -> bool:
    callee_func = getattr(node, "callee_func", None)
    if callee_func is None:
        return False

    # angr's renderer expects Function.project to be live. Exact-region and
    # regenerated trees can retain detached Function objects; preserve the
    # semantic target name and render through callee_target instead.
    module = getattr(type(callee_func), "__module__", "")
    if not isinstance(module, str) or "knowledge_plugins.functions" not in module:
        return False
    try:
        callee_project = getattr(callee_func, "project", None)
    except AssertionError:
        callee_project = None
    except Exception:
        callee_project = None
    if callee_project is not None:
        return False

    replacement = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if not isinstance(replacement, str) or not replacement:
        replacement = normalize_callee_name_8616(getattr(node, "callee_target", None))
    changed = False
    if isinstance(replacement, str) and replacement and getattr(node, "callee_target", None) != replacement:
        node.callee_target = replacement
        changed = True
    if getattr(node, "callee_func", None) is not None:
        node.callee_func = None
        changed = True
    return changed


def _call_node_name_8616(node: StructuredAstValue) -> str | None:
    callee_func = getattr(node, "callee_func", None)
    for raw in (
        getattr(callee_func, "name", None),
        getattr(node, "callee_target", None),
    ):
        normalized = normalize_callee_name_8616(raw)
        if isinstance(normalized, str) and normalized:
            return normalized
    return None


def _is_runtime_segment_helper_call_8616(node: StructuredAstValue) -> bool:
    tags = getattr(node, "tags", None)
    marker_name = tags.get("inertia_x86_16_runtime_segment_helper") if isinstance(tags, dict) else None
    if isinstance(marker_name, str) and marker_name.upper() in _RUNTIME_SEGMENT_HELPERS_8616:
        return True
    call_name = _call_node_name_8616(node)
    return isinstance(call_name, str) and call_name.upper() in _RUNTIME_SEGMENT_HELPERS_8616


def _segmented_stack_arg_store_lvalue_args_8616(
    expr: StructuredAstValue,
    project: StructuredAstValue,
    *,
    allow_raw_dereference: bool = True,
) -> tuple[StructuredAstValue, StructuredAstValue] | None:
    """Return segment helper arguments for SEG_U* stack-argument store lvalues."""
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CFunctionCall):
        call_name = _call_node_name_8616(node)
        if not isinstance(call_name, str) or call_name.upper() not in {"SEG_U8", "SEG_U16", "SEG_U32"}:
            return None
        args = _boundary_tuple_8616(node.args or ())
        return args if len(args) == 2 else None
    if not allow_raw_dereference:
        return None
    segment_name, offset_terms = _match_real_mode_segmented_store_shape_8616(node, project)
    if segment_name is None:
        return None
    return segment_name, tuple(term for _sign, term in offset_terms)


def prune_consumed_segmented_stack_byte_arg_stores_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Prune SS SEG_U* stores only after a materialized next-call arg consumes them."""
    debug_enabled = bool(os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS_VERBOSE"))


    cfunc = getattr(codegen, "cfunc", None)
    root = _structured_root_8616(cfunc)
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if root is None:
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("no-root", debug_enabled=debug_enabled)
        return False
    if not isinstance(summary_map, dict):
        summary_map = {}











    changed = False

    seen_container_ids: set[int] = set()

    if isinstance(root, list):
        changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_statement_list_8616(
            root, seen_container_ids=seen_container_ids, codegen=codegen, debug_enabled=debug_enabled,
            project=project, summary_map=summary_map,
        ) or changed
    else:
        root_statements = getattr(root, "statements", None)
        if not isinstance(root_statements, list):
            _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("root-statements-missing", root_type=type(root).__name__, debug_enabled=debug_enabled)
            return changed
        changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_statement_list_8616(
            root_statements, seen_container_ids=seen_container_ids, codegen=codegen, debug_enabled=debug_enabled,
            project=project, summary_map=summary_map,
        ) or changed
        if changed:
            _sync_cfunc_root_statements_8616(cfunc, root, root_statements)
    return changed


def _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_statement_list_8616(
    statements: list[StructuredAstValue],
    *,
    seen_container_ids: set[int],
    codegen: StructuredAstValue,
    debug_enabled: bool,
    project: StructuredAstValue,
    summary_map: StructuredAstValue,
) -> bool:
    """Prune consumed stores in one statement list; return whether anything changed."""
    container_id = id(statements)
    if container_id in seen_container_ids:
        return False
    seen_container_ids.add(container_id)
    changed = False
    pruned: list[StructuredAstValue] = []
    for idx, stmt in enumerate(statements):
        if _prune_consumed_segmented_stack_byte_arg_stores_8616___statement_is_consumed_store_8616(statements, idx, codegen=codegen, debug_enabled=debug_enabled, project=project, summary_map=summary_map):
            _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("pruned", idx=idx, stmt=str(stmt), next=str(statements[idx + 1]), debug_enabled=debug_enabled)
            changed = True
            codegen._inertia_consumed_segmented_stack_byte_arg_store_pruned_8616 = (
                int(getattr(codegen, "_inertia_consumed_segmented_stack_byte_arg_store_pruned_8616", 0) or 0) + 1
            )
            continue
        changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_nested_statement_lists_8616(
            stmt, seen_container_ids=seen_container_ids, codegen=codegen, debug_enabled=debug_enabled,
            project=project, summary_map=summary_map,
        ) or changed
        pruned.append(stmt)
    if len(pruned) != len(statements):
        statements[:] = pruned
    return changed


def _prune_consumed_segmented_stack_byte_arg_stores_8616___list_statements_8616(node: StructuredAstValue) -> StructuredAstValue:
    """Return the nested statement list of a container node, if it holds one."""
    return getattr(node, "statements", None)


def _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_maybe_8616(
    container: StructuredAstValue,
    node: StructuredAstValue,
    *,
    seen_container_ids: set[int],
    codegen: StructuredAstValue,
    debug_enabled: bool,
    project: StructuredAstValue,
    summary_map: StructuredAstValue,
) -> bool:
    """Prune one potential statement-list container; True if it changed."""
    if container is None:
        return False
    nested = getattr(container, "statements", None)
    if isinstance(nested, list):
        return _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_statement_list_8616(
            nested, seen_container_ids=seen_container_ids, codegen=codegen,
            debug_enabled=debug_enabled, project=project, summary_map=summary_map,
        )
    if container is node:
        return False
    return _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_nested_statement_lists_8616(
        container, seen_container_ids=seen_container_ids, codegen=codegen,
        debug_enabled=debug_enabled, project=project, summary_map=summary_map,
    )


def _prune_consumed_segmented_stack_byte_arg_stores_8616___iter_case_bodies_8616(node: StructuredAstValue) -> Iterator[StructuredAstValue]:
    """Yield each switch case body plus the default body."""
    for _case_value, case_body in _boundary_tuple_8616(
        cast(
            Iterable[tuple[StructuredAstValue, StructuredAstValue]],
            getattr(node, "cases", ()) or (),
        )
    ):
        yield case_body
    yield getattr(node, "default", None)


def _prune_consumed_segmented_stack_byte_arg_stores_8616___iter_condition_bodies_8616(node: StructuredAstValue) -> Iterator[StructuredAstValue]:
    """Yield each if/elif body plus the else body."""
    for _condition, child in _boundary_tuple_8616(
        cast(
            Iterable[tuple[StructuredAstValue, StructuredAstValue]],
            getattr(node, "condition_and_nodes", ()) or (),
        )
    ):
        yield child
    yield getattr(node, "else_node", None)


def _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_many_8616(
    containers: Iterable[StructuredAstValue],
    node: StructuredAstValue,
    *,
    seen_container_ids: set[int],
    codegen: StructuredAstValue,
    debug_enabled: bool,
    project: StructuredAstValue,
    summary_map: StructuredAstValue,
) -> bool:
    """Prune a sequence of statement-list containers."""
    changed = False
    for container in containers:
        changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_maybe_8616(
            container, node, seen_container_ids=seen_container_ids, codegen=codegen,
            debug_enabled=debug_enabled, project=project, summary_map=summary_map,
        ) or changed
    return changed


def _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_dict_value_8616(
    dict_value: StructuredAstValue,
    node: StructuredAstValue,
    *,
    seen_container_ids: set[int],
    codegen: StructuredAstValue,
    debug_enabled: bool,
    project: StructuredAstValue,
    summary_map: StructuredAstValue,
) -> bool:
    """Prune a value found inside a dict field."""
    if isinstance(dict_value, list):
        return _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_statement_list_8616(
            dict_value, seen_container_ids=seen_container_ids, codegen=codegen,
            debug_enabled=debug_enabled, project=project, summary_map=summary_map,
        )
    if dict_value is not None and dict_value is not node:
        return _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_maybe_8616(
            dict_value, node, seen_container_ids=seen_container_ids, codegen=codegen,
            debug_enabled=debug_enabled, project=project, summary_map=summary_map,
        )
    return False


def _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_fields_8616(
    node: StructuredAstValue,
    *,
    seen_container_ids: set[int],
    codegen: StructuredAstValue,
    debug_enabled: bool,
    project: StructuredAstValue,
    summary_map: StructuredAstValue,
) -> bool:
    """Walk every instance field and prune statement lists found inside."""
    changed = False
    raw_dict = getattr(node, "__dict__", None)
    values = tuple(raw_dict.values()) if isinstance(raw_dict, dict) else ()
    for value in values:
        if isinstance(value, list):
            changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_statement_list_8616(
                value, seen_container_ids=seen_container_ids, codegen=codegen,
                debug_enabled=debug_enabled, project=project, summary_map=summary_map,
            ) or changed
        elif isinstance(value, dict):
            for dict_value in tuple(value.values()):
                changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_dict_value_8616(
                    dict_value, node, seen_container_ids=seen_container_ids, codegen=codegen,
                    debug_enabled=debug_enabled, project=project, summary_map=summary_map,
                ) or changed
        elif isinstance(value, tuple):
            for tuple_value in value:
                if tuple_value is not None and tuple_value is not node:
                    changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_maybe_8616(
                        tuple_value, node, seen_container_ids=seen_container_ids, codegen=codegen,
                        debug_enabled=debug_enabled, project=project, summary_map=summary_map,
                    ) or changed
        elif value is not None and value is not node:
            changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_maybe_8616(
                value, node, seen_container_ids=seen_container_ids, codegen=codegen,
                debug_enabled=debug_enabled, project=project, summary_map=summary_map,
            ) or changed
    return changed


def _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_nested_statement_lists_8616(
    node: StructuredAstValue,
    *,
    seen_container_ids: set[int],
    codegen: StructuredAstValue,
    debug_enabled: bool,
    project: StructuredAstValue,
    summary_map: StructuredAstValue,
) -> bool:
    """Walk container nodes and prune consumed stores in every nested statement list."""
    if node is None:
        return False
    changed = False
    node_type = type(node).__name__
    if node_type == "CStatements":
        changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_maybe_8616(
            node, node, seen_container_ids=seen_container_ids, codegen=codegen,
            debug_enabled=debug_enabled, project=project, summary_map=summary_map,
        )
    elif node_type in {"CSwitchCase", "CIncompleteSwitchCase"}:
        changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_many_8616(
            _prune_consumed_segmented_stack_byte_arg_stores_8616___iter_case_bodies_8616(node),
            node, seen_container_ids=seen_container_ids, codegen=codegen,
            debug_enabled=debug_enabled, project=project, summary_map=summary_map,
        )
    elif node_type == "CIfElse":
        changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_many_8616(
            _prune_consumed_segmented_stack_byte_arg_stores_8616___iter_condition_bodies_8616(node),
            node, seen_container_ids=seen_container_ids, codegen=codegen,
            debug_enabled=debug_enabled, project=project, summary_map=summary_map,
        )
    elif node_type in {"CWhileLoop", "CDoWhileLoop", "CForLoop"}:
        changed = _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_maybe_8616(
            getattr(node, "body", None), node, seen_container_ids=seen_container_ids,
            codegen=codegen, debug_enabled=debug_enabled, project=project,
            summary_map=summary_map,
        )
    return _prune_consumed_segmented_stack_byte_arg_stores_8616___prune_fields_8616(
        node, seen_container_ids=seen_container_ids, codegen=codegen,
        debug_enabled=debug_enabled, project=project, summary_map=summary_map,
    ) or changed



def _prune_consumed_segmented_stack_byte_arg_stores_8616___consumed_store_stack_offset_8616(
    lhs: StructuredAstValue,
    *,
    idx: int,
    debug_enabled: bool,
    project: StructuredAstValue,
) -> StructuredAstValue | None:
    """Return the stack-offset lvalue arg when the store targets SS:off(stack)."""
    lhs_args = _segmented_stack_arg_store_lvalue_args_8616(lhs, project)
    if lhs_args is None:
        if debug_enabled and any(helper in str(lhs) for helper in ("SEG_U8", "SEG_U16", "SEG_U32")):
            _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("seg-u-lvalue-miss", idx=idx, lhs=str(lhs), debug_enabled=debug_enabled)
        return None
    seg_arg, offset_arg = lhs_args
    segment_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, project)
    seg_name = getattr(seg_arg, "name", None)
    if segment_name != "ss" and not (
        (isinstance(seg_arg, str) and seg_arg == "ss") or (isinstance(seg_name, str) and seg_name.lower() == "ss")
    ):
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("not-ss", idx=idx, segment_name=segment_name, seg_name=seg_name, lhs=str(lhs), debug_enabled=debug_enabled)
        return None
    if not (
        _prune_consumed_segmented_stack_byte_arg_stores_8616___node_contains_placeholder_stack_8616(offset_arg)
        or _generic_stack_carrier_keys_8616(offset_arg)
        or _prune_consumed_segmented_stack_byte_arg_stores_8616___expr_contains_dirty_expression_8616(offset_arg)
    ):
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("offset-not-stack-placeholder", idx=idx, offset=str(offset_arg), debug_enabled=debug_enabled)
        return None
    return offset_arg


def _prune_consumed_segmented_stack_byte_arg_stores_8616___consumed_store_next_call_matches_8616(
    statements: list[StructuredAstValue],
    idx: int,
    rhs: StructuredAstValue,
    *,
    codegen: StructuredAstValue,
    summary_map: StructuredAstValue,
    debug_enabled: bool,
) -> bool:
    """Check whether the following real call consumes the stored rhs."""
    next_call = _prune_consumed_segmented_stack_byte_arg_stores_8616___next_real_call_8616(statements, idx)
    if next_call is None:
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("next-not-real-call", idx=idx, next=str(statements[idx + 1]), debug_enabled=debug_enabled)
        return False
    summary = summary_map.get(id(next_call))
    if summary is not None and bool(summary.stack_probe_helper):
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("next-stack-probe-summary", idx=idx, call=str(next_call), debug_enabled=debug_enabled)
        return False
    call_args = _boundary_tuple_8616(getattr(next_call, "args", ()) or ())
    if not call_args:
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("next-call-no-args", idx=idx, call=str(next_call), debug_enabled=debug_enabled)
        return False
    if summary is None:
        codegen._inertia_consumed_segmented_stack_byte_arg_store_pruned_without_summary_8616 = (
            int(
                getattr(
                    codegen,
                    "_inertia_consumed_segmented_stack_byte_arg_store_pruned_without_summary_8616",
                    0,
                )
                or 0
            )
            + 1
        )
        return True
    push_sources = summary.push_arg_sources
    if isinstance(push_sources, tuple) and push_sources:
        return True
    matched_rhs = any(_same_c_expression_8616(arg, rhs) for arg in call_args)
    if not matched_rhs:
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug(
            "args-do-not-match-rhs",
            idx=idx,
            call=str(next_call),
            rhs=str(rhs),
            args=tuple(str(arg) for arg in call_args),
        debug_enabled=debug_enabled)
    return matched_rhs


def _prune_consumed_segmented_stack_byte_arg_stores_8616___statement_is_consumed_store_8616(statements: list[StructuredAstValue], idx: int, *, codegen: StructuredAstValue, debug_enabled: bool, project: StructuredAstValue, summary_map: StructuredAstValue) -> bool:
    """Decide whether statements[idx] is a stack byte-arg store consumed by the next call."""
    if idx + 1 >= len(statements):
        return False
    assignment = _prune_consumed_segmented_stack_byte_arg_stores_8616___top_level_assignment_node_8616(statements[idx])
    if assignment is None:
        return False
    lhs, rhs = _prune_consumed_segmented_stack_byte_arg_stores_8616___assignment_lhs_rhs_8616(assignment)
    if lhs is None or rhs is None:
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("missing-lhs-rhs", idx=idx, debug_enabled=debug_enabled)
        return False
    if _prune_consumed_segmented_stack_byte_arg_stores_8616___consumed_store_stack_offset_8616(lhs, idx=idx, debug_enabled=debug_enabled, project=project) is None:
        return False
    if not _prune_consumed_segmented_stack_byte_arg_stores_8616___rhs_is_side_effect_free_8616(rhs):
        _prune_consumed_segmented_stack_byte_arg_stores_8616___debug("rhs-not-side-effect-free", idx=idx, rhs=str(rhs), debug_enabled=debug_enabled)
        return False
    return _prune_consumed_segmented_stack_byte_arg_stores_8616___consumed_store_next_call_matches_8616(
        statements, idx, rhs, codegen=codegen, summary_map=summary_map, debug_enabled=debug_enabled
    )




def _prune_consumed_segmented_stack_byte_arg_stores_8616___debug(reason: str, debug_enabled: bool, **fields: StructuredAstValue) -> None:
    if debug_enabled:
        log.warning("[consumed-seg-stack-byte-prune] %s %r", reason, fields)



def _prune_consumed_segmented_stack_byte_arg_stores_8616___call_from_statement_8616(stmt: StructuredAstValue) -> StructuredAstValue | None:
    """Extract a direct call expression from a supported statement shell."""
    if isinstance(stmt, CFunctionCall):
        return stmt
    for attr in ("expr", "rhs", "src", "retval"):
        value = getattr(stmt, attr, None)
        if isinstance(value, CFunctionCall):
            return value
    nested = getattr(stmt, "statements", None)
    if isinstance(nested, (list, tuple)) and len(nested) == 1:
        return _prune_consumed_segmented_stack_byte_arg_stores_8616___call_from_statement_8616(nested[0])
    return None



def _prune_consumed_segmented_stack_byte_arg_stores_8616___assignment_lhs_rhs_8616(node: StructuredAstValue) -> StructuredAstValue:
    lhs = getattr(node, "lhs", None)
    rhs = getattr(node, "rhs", None)
    if lhs is None and hasattr(node, "dst"):
        lhs = getattr(node, "dst", None)
        rhs = getattr(node, "src", None)
    return lhs, rhs



def _prune_consumed_segmented_stack_byte_arg_stores_8616___is_assignment_node_8616(node: StructuredAstValue) -> bool:
    class_name = node.__class__.__name__
    return (
        class_name == "CAssignment"
        or class_name.endswith("Assignment")
        or (hasattr(node, "dst") and hasattr(node, "src"))
    )



def _prune_consumed_segmented_stack_byte_arg_stores_8616___top_level_assignment_node_8616(stmt: StructuredAstValue) -> StructuredAstValue:
    if _prune_consumed_segmented_stack_byte_arg_stores_8616___is_assignment_node_8616(stmt):
        return stmt
    expr = getattr(stmt, "expr", None)
    if expr is not None and _prune_consumed_segmented_stack_byte_arg_stores_8616___is_assignment_node_8616(expr):
        return expr
    return None



def _prune_consumed_segmented_stack_byte_arg_stores_8616___expr_contains_dirty_expression_8616(expr: StructuredAstValue) -> bool:
    for raw_node in (expr, *_iter_c_nodes_deep_8616(expr)):
        node = raw_node
        while isinstance(node, CTypeCast):
            node = node.expr
        if node.__class__.__name__ == "CDirtyExpression":
            return True
    return False



def _prune_consumed_segmented_stack_byte_arg_stores_8616___node_contains_placeholder_stack_8616(node: StructuredAstValue, *, max_nodes: int = 1024) -> bool:
    if isinstance(node, (tuple, list)):
        return any(_prune_consumed_segmented_stack_byte_arg_stores_8616___node_contains_placeholder_stack_8616(item, max_nodes=max_nodes) for item in node)
    for idx, candidate in enumerate((node, *_iter_c_nodes_deep_8616(node))):
        if idx > max_nodes:
            return False
        name = getattr(candidate, "name", None)
        if isinstance(name, str) and name.startswith(("stack_", "sp_", "bp_", "vvar_", "tmp_", "ir_")):
            return True
        variable = getattr(candidate, "variable", None)
        if isinstance(variable, SimStackVariable):
            return True
    return False



def _prune_consumed_segmented_stack_byte_arg_stores_8616___rhs_is_side_effect_free_8616(expr: StructuredAstValue) -> bool:
    for raw_node in (expr, *_iter_c_nodes_deep_8616(expr)):
        node = raw_node
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CFunctionCall):
            return False
        if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
            return False
    return True



def _prune_consumed_segmented_stack_byte_arg_stores_8616___is_safe_intervening_stack_carrier_8616(stmt: StructuredAstValue) -> bool:
    """Recognize a pure dirty SSA carrier between a consumed store and its call."""
    assignment = _prune_consumed_segmented_stack_byte_arg_stores_8616___top_level_assignment_node_8616(stmt)
    if assignment is None:
        return False
    lhs, rhs = _prune_consumed_segmented_stack_byte_arg_stores_8616___assignment_lhs_rhs_8616(assignment)
    if lhs is None or rhs is None or lhs.__class__.__name__ != "CDirtyExpression":
        return False
    return _prune_consumed_segmented_stack_byte_arg_stores_8616___rhs_is_side_effect_free_8616(rhs)



def _prune_consumed_segmented_stack_byte_arg_stores_8616___next_real_call_8616(
    statements: list[StructuredAstValue],
    store_idx: int,
    *,
    max_carriers: int = 8,
) -> StructuredAstValue:
    """Find the next call across only bounded, proven-pure dirty SP carriers."""
    for carrier_count, candidate in enumerate(statements[store_idx + 1 :]):
        call = _prune_consumed_segmented_stack_byte_arg_stores_8616___call_from_statement_8616(candidate)
        if call is not None:
            return None if _is_runtime_segment_helper_call_8616(call) else call
        if not _prune_consumed_segmented_stack_byte_arg_stores_8616___is_safe_intervening_stack_carrier_8616(candidate):
            return None
        if carrier_count >= max_carriers:
            return None
    return None



def _call_name_is_unknown_8616(name: str | None) -> bool:
    return name is None or name.startswith("sub_") or name == "CallReturn"


def _callee_names_match_8616(left: str | None, right: str | None) -> bool:
    left_norm = normalize_callee_name_8616(left)
    right_norm = normalize_callee_name_8616(right)
    if not isinstance(left_norm, str) or not isinstance(right_norm, str):
        return False
    if left_norm == right_norm:
        return True
    # MSC/OMF public C symbols commonly carry one leading underscore while the
    # generated C call expression does not. Treat that decoration as equivalent.
    return left_norm.lstrip("_") == right_norm.lstrip("_")


def _resolve_dirty_virtual_expr_8616(node: StructuredAstValue) -> StructuredAstValue:

    return __resolve_dirty_virtual_expr_8616___impl(node=node)


def __resolve_dirty_virtual_expr_8616___impl(*, node: StructuredAstValue) -> StructuredAstValue:
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
    for stmt in _iter_c_nodes_deep_8616(root):
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



def _stack_probe_candidate_addrs_8616(project: StructuredAstValue, target_addr: int) -> list[int]:
    """Build linear-address candidates under which stack-probe evidence may be registered."""
    candidate_addrs = [int(target_addr)]
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    if isinstance(linked_base, int):
        rebased_low = linked_base + (int(target_addr) & 0xFFFF)
        candidate_addrs.append(rebased_low)
    # Dynamic boundary: exact-slice projects may carry an original linear delta.
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        candidate_addrs.append(int(target_addr) + original_delta)
        rebased = int(target_addr) - original_delta
        if rebased >= 0:
            candidate_addrs.append(rebased)
    return candidate_addrs


def _summary_targets_stack_probe_helper_8616(project: StructuredAstValue, summary: CallsiteSummary8616 | None) -> bool:
    """Return whether binary helper evidence identifies this summary target as a stack probe."""
    if not isinstance(summary, CallsiteSummary8616):
        return False
    if bool(summary.stack_probe_helper):
        return True
    target_addr = summary.target_addr
    if not isinstance(target_addr, int):
        return False
    candidate_addrs = _stack_probe_candidate_addrs_8616(project, int(target_addr))
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        if candidate_project is None:
            continue
        for candidate_addr in dict.fromkeys(candidate_addrs):
            if is_x86_16_stack_probe_helper_at_8616(candidate_project, candidate_addr):
                return True
    return False


def _call_node_has_nonprobe_target_evidence_8616(project: StructuredAstValue, node: StructuredAstValue) -> bool:
    """Return whether a call node already points at a concrete non-stack-probe target."""
    for candidate_addr in _candidate_target_addrs_from_call_8616(node):
        if not is_x86_16_stack_probe_helper_at_8616(project, candidate_addr):
            return True
    return False


def _stack_probe_call_match_verdict_8616(
    project: StructuredAstValue, node: StructuredAstValue, call_name: StructuredAstValue, summary_targets_stack_probe: bool
) -> bool | None:
    """Decide a stack-probe summary match; None means the probe gate does not apply."""
    if not summary_targets_stack_probe:
        return None
    if is_x86_16_stack_probe_name_8616(call_name):
        return True
    if _call_node_has_nonprobe_target_evidence_8616(project, node):
        return False
    if not _call_name_is_unknown_8616(call_name):
        return False
    return None


def _call_name_matches_summary_target_8616(project: StructuredAstValue, target_addr: int, call_name: str) -> bool:
    """Match a call name against functions near the summary target address."""
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    for candidate_addr in _candidate_linear_target_addrs_8616(project, target_addr):
        try:
            target_function = lookup(addr=candidate_addr, create=False) if callable(lookup) else None
        except TypeError:
            target_function = None
        if _callee_names_match_8616(getattr(target_function, "name", None), call_name):
            return True
    lookup_names = [call_name]
    undecorated = call_name.lstrip("_")
    decorated = f"_{undecorated}" if undecorated else None
    if decorated is not None and decorated not in lookup_names:
        lookup_names.append(decorated)
    try:
        named_function = None
        if callable(lookup):
            for lookup_name in lookup_names:
                named_function = lookup(name=lookup_name, create=False)
                if named_function is not None:
                    break
    except TypeError:
        named_function = None
    named_addr = getattr(named_function, "addr", None)
    return isinstance(named_addr, int) and _target_addr_matches_near_or_linear_8616(named_addr, target_addr)


def _call_node_matches_summary_8616(
    project: StructuredAstValue, node: StructuredAstValue, summary: CallsiteSummary8616 | None
) -> bool:

    return __call_node_matches_summary_8616___impl(node=node, project=project, summary=summary)


def __call_node_matches_summary_8616___impl(*, node: StructuredAstValue, project: StructuredAstValue, summary: CallsiteSummary8616 | None) -> bool:
    if node is None or not isinstance(summary, CallsiteSummary8616):
        return False
    call_name = _call_node_name_8616(node)
    summary_targets_stack_probe = _summary_targets_stack_probe_helper_8616(project, summary)
    probe_verdict = _stack_probe_call_match_verdict_8616(project, node, call_name, summary_targets_stack_probe)
    if probe_verdict is not None:
        return probe_verdict

    target_addr = summary.target_addr
    if isinstance(target_addr, int):
        for candidate_addr in _candidate_target_addrs_from_call_8616(node):
            if _target_addr_matches_near_or_linear_8616(candidate_addr, target_addr):
                return True
        if isinstance(call_name, str) and _call_name_matches_summary_target_8616(project, target_addr, call_name):
            return True
        for candidate_name in (
            _sidecar_label_for_target_8616(project, target_addr),
            normalize_callee_name_8616(getattr(_lookup_callee_function_8616(project, target_addr), "name", None)),
        ):
            if _callee_names_match_8616(candidate_name, call_name):
                return True
    return False



def _call_node_can_take_summary_8616(
    project: StructuredAstValue, node: StructuredAstValue, summary: CallsiteSummary8616 | None
) -> bool:
    """Return whether a structured call node can safely consume a callsite summary."""
    if summary is None:
        return True
    if not isinstance(summary, CallsiteSummary8616):
        return False
    call_name = _call_node_name_8616(node)
    node_is_stack_probe = _is_stack_probe_call_name_8616(call_name)
    summary_is_stack_probe = _summary_targets_stack_probe_helper_8616(project, summary)
    summary_has_stack_probe_shape = int(summary.arg_count or 0) == 0 and summary.stack_cleanup is None
    if node_is_stack_probe:
        return summary_is_stack_probe or summary_has_stack_probe_shape
    if summary_is_stack_probe:
        if _call_node_has_nonprobe_target_evidence_8616(project, node):
            return False
        return _call_name_is_unknown_8616(call_name)
    if _call_name_is_unknown_8616(call_name):
        return True
    if _node_callsite_matches_summary_8616(node, summary):
        return True
    return _call_node_matches_summary_8616(project, node, summary)


def _node_callsite_matches_summary_8616(node: StructuredAstValue, summary: CallsiteSummary8616) -> bool:
    """Return true when node-local address metadata ties a summary to the callsite."""
    summary_callsite = summary.callsite_addr
    if not isinstance(summary_callsite, int):
        return False
    tags = getattr(node, "tags", None)
    if isinstance(tags, dict):
        for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
            value = tags.get(key)
            if isinstance(value, int) and value == summary_callsite:
                return True
    value = getattr(node, "addr", None)
    return isinstance(value, int) and value == summary_callsite


def _scan_call_names_for_target_8616(
    source_call_names: tuple[str, ...],
    source_call_idx: int,
    project: StructuredAstValue,
    target_addr: int,
    summary_has_stack_probe_shape: bool,
) -> tuple[str | None, int]:
    """Scan source call names for a probe match or a name matching the target address."""
    scan_idx = source_call_idx
    while scan_idx < len(source_call_names):
        candidate = source_call_names[scan_idx]
        if _is_stack_probe_call_name_8616(candidate):
            if summary_has_stack_probe_shape:
                return candidate, scan_idx + 1
            scan_idx += 1
            continue
        if _source_name_matches_target_8616(project, target_addr, candidate):
            return candidate, scan_idx + 1
        scan_idx += 1
    return None, source_call_idx


def _scan_call_names_for_arg_count_8616(
    source_call_names: tuple[str, ...], source_call_idx: int, summary_arg_count: int
) -> tuple[str | None, int]:
    """Scan source call names for one whose known callee arity matches the summary."""
    scan_idx = source_call_idx
    while scan_idx < len(source_call_names):
        candidate = source_call_names[scan_idx]
        if _is_stack_probe_call_name_8616(candidate):
            scan_idx += 1
            continue
        expected_arg_count = _expected_arg_count_for_known_callee_8616(candidate)
        if expected_arg_count is None or expected_arg_count == summary_arg_count:
            return candidate, scan_idx + 1
        scan_idx += 1
    return None, source_call_idx


def _scan_call_names_for_probe_8616(
    source_call_names: tuple[str, ...], source_call_idx: int
) -> tuple[str | None, int]:
    """Scan source call names for the next stack-probe helper name."""
    scan_idx = source_call_idx
    while scan_idx < len(source_call_names):
        candidate = source_call_names[scan_idx]
        if _is_stack_probe_call_name_8616(candidate):
            return candidate, scan_idx + 1
        scan_idx += 1
    return None, source_call_idx


def _next_source_call_name_for_summary_8616(
    source_call_names: tuple[str, ...],
    source_call_idx: int,
    summary: CallsiteSummary8616 | None,
    project: StructuredAstValue = None,
) -> tuple[str | None, int]:
    summary_is_stack_probe = bool(summary.stack_probe_helper) if summary is not None else False
    summary_has_stack_probe_shape = (
        summary is not None and int(summary.arg_count or 0) == 0 and summary.stack_cleanup is None
    )
    target_addr = summary.target_addr if summary is not None else None
    if (
        summary is not None
        and project is not None
        and isinstance(target_addr, int)
        and not summary_is_stack_probe
    ):
        found_name, found_idx = _scan_call_names_for_target_8616(
            source_call_names, source_call_idx, project, target_addr, summary_has_stack_probe_shape
        )
        if found_name is not None:
            return found_name, found_idx
        summary_arg_count = int(summary.arg_count or 0)
        return _scan_call_names_for_arg_count_8616(source_call_names, source_call_idx, summary_arg_count)
    if summary_is_stack_probe:
        return _scan_call_names_for_probe_8616(source_call_names, source_call_idx)
    while source_call_idx < len(source_call_names):
        candidate = source_call_names[source_call_idx]
        if not _is_stack_probe_call_name_8616(candidate) or summary_has_stack_probe_shape:
            return candidate, source_call_idx + 1
        source_call_idx += 1
    return None, source_call_idx

    while source_call_idx < len(source_call_names):
        candidate = source_call_names[source_call_idx]
        if not _is_stack_probe_call_name_8616(candidate) or summary_has_stack_probe_shape:
            return candidate, source_call_idx + 1
        source_call_idx += 1
    return None, source_call_idx


def _source_name_matches_target_8616(
    project: StructuredAstValue, target_addr: int | None, expected_source_name: str | None
) -> bool:
    if not isinstance(expected_source_name, str) or not expected_source_name:
        return False
    normalized_expected = normalize_callee_name_8616(expected_source_name)
    if not isinstance(normalized_expected, str):
        return False
    if not isinstance(target_addr, int):
        return False
    for candidate_name in (
        _sidecar_label_for_target_8616(project, target_addr),
        normalize_callee_name_8616(getattr(_lookup_callee_function_8616(project, target_addr), "name", None)),
    ):
        if _callee_names_match_8616(candidate_name, normalized_expected):
            return True
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    try:
        function = lookup(name=normalized_expected, create=False) if callable(lookup) else None
    except TypeError:
        function = None
    function_addr = getattr(function, "addr", None)
    return (
        isinstance(function_addr, int)
        and isinstance(target_addr, int)
        and _target_addr_matches_near_or_linear_8616(function_addr, target_addr)
    )


def _align_cod_call_names_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    return False


def _normalize_call_target_names_8616(codegen: StructuredAstValue) -> bool:

    return __normalize_call_target_names_8616___impl(codegen=codegen)


def _expected_source_name_for_call_node_8616(
    summary: CallsiteSummary8616 | None,
    node: StructuredAstValue,
    source_call_names: tuple[str, ...],
    source_call_idx: int,
    project: StructuredAstValue,
) -> tuple[str | None, int]:
    """Choose the source-level callee name expected for this call node."""
    is_stack_probe_helper = bool(summary.stack_probe_helper) if summary is not None else False
    if (
        summary is not None
        and is_stack_probe_helper
        and _summary_proves_stack_probe_call_8616(summary, node=node)
    ):
        return "aNchkstk", source_call_idx
    if summary is not None and not is_stack_probe_helper:
        return _next_source_call_name_for_summary_8616(
            source_call_names,
            source_call_idx,
            summary,
            project=project,
        )
    return None, source_call_idx


def __normalize_call_target_names_8616___impl(*, codegen: StructuredAstValue) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    project = getattr(codegen, "project", None)
    changed = False
    allow_call_target_rewrites = os.environ.get(
        "INERTIA_ENABLE_CALLSITE_TARGET_REWRITES",
        "1",
    ).strip().lower() not in {"0", "false", "no", "off"}
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    root = _structured_root_8616(cfunc)
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    else:
        _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    source_call_names: tuple[str, ...] = ()
    if _source_call_floor_enabled_8616():
        func_addr = getattr(cfunc, "addr", None)
        if isinstance(func_addr, int):
            source_call_names = _cod_source_call_names_8616(project, func_addr)
    source_call_idx = 0
    call_nodes = [
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
    ]
    for node in call_nodes:
        summary = summary_map.get(id(node))
        expected_source_name, source_call_idx = _expected_source_name_for_call_node_8616(
            summary, node, source_call_names, source_call_idx, project
        )
        target_addr = summary.target_addr if summary is not None else None
        summary_arg_count = int(summary.arg_count or 0) if summary is not None else 0
        summary_stack_cleanup = summary.stack_cleanup if summary is not None else None

        changed |= _normalize_single_call_target_node_8616(
            project=project,
            node=node,
            expected_source_name=expected_source_name,
            target_addr=target_addr,
            summary_arg_count=summary_arg_count,
            summary_stack_cleanup=summary_stack_cleanup,
            stats=stats,
            allow_call_target_rewrites=allow_call_target_rewrites,
        )

        if _rename_call_node_from_sidecar_8616(project, node):
            changed = True

    if _source_call_floor_enabled_8616() and _align_cod_call_names_8616(project, codegen):
        changed = True

    if _repair_callsite_args_before_final_stats_8616(project, codegen, root, summary_map):
        changed = True

    _finalize_callsite_materialization_stats_8616(codegen)
    return changed



def _repair_callsite_args_before_final_stats_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    root: StructuredAstValue,
    summary_map: dict[int, StructuredAstValue],
) -> bool:

    return __repair_callsite_args_before_final_stats_8616___impl(codegen=codegen, project=project, root=root, summary_map=summary_map)


def __repair_callsite_args_before_final_stats_8616___impl(*, codegen: StructuredAstValue, project: StructuredAstValue, root: StructuredAstValue, summary_map: dict[int, StructuredAstValue]) -> bool:
    debug_materialization = bool(os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"))
    if getattr(codegen, "_inertia_callsite_arg_pre_final_stats_active_8616", False):
        return False
    if not isinstance(summary_map, dict) or not summary_map:
        return False
    _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    if not _has_callsite_arg_materialization_gap_8616(root, summary_map, project=project):
        if debug_materialization:
            log.warning(
                "[call-pre-final-repair] function=%#x reason=no-gap",
                getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
            )
        return False
    codegen._inertia_callsite_arg_pre_final_stats_active_8616 = True
    try:
        changed = bool(_materialize_callsite_stack_arguments_8616(project, codegen))
    finally:
        codegen._inertia_callsite_arg_pre_final_stats_active_8616 = False
    if changed:
        _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    if debug_materialization:
        log.warning(
            "[call-pre-final-repair] function=%#x changed=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
            changed,
        )
    return changed



def _has_callsite_arg_materialization_gap_8616(
    root: StructuredAstValue, summary_map: dict[int, StructuredAstValue], project: StructuredAstValue = None
) -> bool:

    return __has_callsite_arg_materialization_gap_8616___impl(project=project, root=root, summary_map=summary_map)


def __has_callsite_arg_materialization_gap_8616___impl(*, project: StructuredAstValue, root: StructuredAstValue, summary_map: dict[int, StructuredAstValue]) -> bool:
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
            continue
        summary = summary_map.get(id(node))
        if summary is None or bool(summary.stack_probe_helper):
            continue
        push_sources = _boundary_tuple_8616(summary.push_arg_sources or ())
        if int(summary.arg_count or 0) <= 0 and not push_sources:
            continue
        expected_count = _logical_expected_arg_count_for_summary_8616(project, node, summary)
        if not (isinstance(expected_count, int) and expected_count > 0):
            continue
        current_count = len(_boundary_tuple_8616(getattr(node, "args", ()) or ()))
        if current_count != expected_count:
            return True
    return False



def _fixup_stack_probe_call_target_8616(
    *,
    node: StructuredAstValue,
    expected_source_name: str | None,
    summary_arg_count: int,
    summary_stack_cleanup: int | None,
) -> bool:
    """Clear callee_func and pin the stack-probe name when source proves a probe call."""
    if not _source_proves_stack_probe_call_8616(
        node=node,
        expected_source_name=expected_source_name,
        summary_arg_count=summary_arg_count,
        summary_stack_cleanup=summary_stack_cleanup,
    ):
        return False
    changed = False
    if getattr(node, "callee_func", None) is not None:
        node.callee_func = None
        changed = True
    normalized_probe_name = normalize_callee_name_8616(expected_source_name) or "aNchkstk"
    if getattr(node, "callee_target", None) != normalized_probe_name:
        node.callee_target = normalized_probe_name
        changed = True
    return changed


def _rename_call_node_to_sidecar_label_8616(
    project: StructuredAstValue, node: StructuredAstValue, target_addr: int
) -> bool:
    """Rename the call node to the sidecar label when it disagrees."""
    sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
    current_name = _call_node_name_8616(node)
    if not (
        isinstance(sidecar_label, str)
        and sidecar_label
        and isinstance(current_name, str)
        and current_name
        and not _callee_names_match_8616(current_name, sidecar_label)
    ):
        return False
    changed = False
    if getattr(node, "callee_func", None) is not None:
        node.callee_func = None
        changed = True
    if getattr(node, "callee_target", None) != sidecar_label:
        node.callee_target = sidecar_label
        changed = True
    return changed


def _bind_expected_callee_name_8616(node: StructuredAstValue, expected_source_name: str) -> bool:
    """Bind the expected source name onto the call node target and callee_func."""
    changed = False
    if getattr(node, "callee_target", None) != expected_source_name:
        node.callee_target = expected_source_name
        changed = True
    callee_func = getattr(node, "callee_func", None)
    if callee_func is not None and getattr(callee_func, "name", None) != expected_source_name:
        callee_func.name = expected_source_name
        changed = True
    return changed


def _normalize_single_call_target_node_8616(
    *,
    project: StructuredAstValue,
    node: StructuredAstValue,
    expected_source_name: str | None,
    target_addr: int | None,
    summary_arg_count: int,
    summary_stack_cleanup: int | None,
    stats: CallsiteMaterializationStats,
    allow_call_target_rewrites: bool,
) -> bool:

    return __normalize_single_call_target_node_8616___impl(allow_call_target_rewrites=allow_call_target_rewrites, expected_source_name=expected_source_name, node=node, project=project, stats=stats, summary_arg_count=summary_arg_count, summary_stack_cleanup=summary_stack_cleanup, target_addr=target_addr)


def __normalize_single_call_target_node_8616___impl(*, allow_call_target_rewrites: bool, expected_source_name: str | None, node: StructuredAstValue, project: StructuredAstValue, stats: CallsiteMaterializationStats, summary_arg_count: int, summary_stack_cleanup: int | None, target_addr: int | None) -> bool:
    if node is None:
        return False
    changed = False
    changed |= _drop_detached_callee_func_8616(node)
    callee_target = getattr(node, "callee_target", None)
    normalized_target = normalize_callee_name_8616(callee_target)
    if isinstance(normalized_target, str) and normalized_target != callee_target:
        node.callee_target = normalized_target
        changed = True

    callee_func = getattr(node, "callee_func", None)
    callee_name = getattr(callee_func, "name", None)
    normalized_name = normalize_callee_name_8616(callee_name)
    if callee_func is not None and isinstance(normalized_name, str) and normalized_name != callee_name:
        callee_func.name = normalized_name
        changed = True

    if isinstance(expected_source_name, str) and expected_source_name:
        changed |= _prefer_expected_source_name_8616(
            project=project,
            node=node,
            expected_source_name=expected_source_name,
            target_addr=target_addr,
            summary_arg_count=summary_arg_count,
        )

    changed |= _fixup_stack_probe_call_target_8616(
        node=node,
        expected_source_name=expected_source_name,
        summary_arg_count=summary_arg_count,
        summary_stack_cleanup=summary_stack_cleanup,
    )

    if isinstance(target_addr, int):
        changed |= _bind_stale_probe_or_unknown_target_8616(
            project=project,
            node=node,
            target_addr=target_addr,
            stats=stats,
        )

    if allow_call_target_rewrites and isinstance(target_addr, int):
        changed |= _bind_node_target_addr_8616(
            project=project,
            node=node,
            expected_source_name=expected_source_name,
            target_addr=target_addr,
            stats=stats,
        )
        changed |= _rename_call_node_to_sidecar_label_8616(project, node, target_addr)

    if (
        isinstance(expected_source_name, str)
        and expected_source_name
        and _call_name_is_unknown_8616(_call_node_name_8616(node))
        and _source_name_matches_target_8616(project, target_addr, expected_source_name)
    ):
        changed |= _bind_expected_callee_name_8616(node, expected_source_name)
    return changed



def _source_proves_stack_probe_call_8616(
    *,
    node: StructuredAstValue,
    expected_source_name: str | None,
    summary_arg_count: int,
    summary_stack_cleanup: int | None,
) -> bool:
    call_name = _call_node_name_8616(node)
    if not (_is_stack_probe_call_name_8616(expected_source_name) or _is_stack_probe_call_name_8616(call_name)):
        return False
    if not (_call_name_is_unknown_8616(call_name) or _is_stack_probe_call_name_8616(call_name)):
        return False
    # Microsoft C stack probes are compiler helpers called before normal stack
    # argument setup. COD/source evidence alone is not enough; require the
    # binary callsite summary to show no pushed args and no caller cleanup.
    return summary_arg_count == 0 and summary_stack_cleanup in {None, 0}


def _source_proven_stack_probe_summary_8616(
    summary: CallsiteSummary8616, *, node: StructuredAstValue, expected_source_name: str | None
) -> CallsiteSummary8616:
    """Upgrade a typed summary only when source and binary facts prove a stack probe."""
    summary_arg_count = int(summary.arg_count or 0)
    summary_stack_cleanup = summary.stack_cleanup
    if not _source_proves_stack_probe_call_8616(
        node=node,
        expected_source_name=expected_source_name,
        summary_arg_count=summary_arg_count,
        summary_stack_cleanup=summary_stack_cleanup,
    ):
        return summary
    if (
        bool(summary.stack_probe_helper)
        and summary.helper_return_state == "stack_address"
        and summary.helper_return_space == "ss"
        and summary.helper_return_width == 2
        and summary.helper_return_address_kind == "stack"
    ):
        return summary
    return replace(
        summary,
        stack_probe_helper=True,
        helper_return_state="stack_address",
        helper_return_space="ss",
        helper_return_width=2,
        helper_return_address_kind="stack",
    )


def _summary_proves_stack_probe_call_8616(summary: CallsiteSummary8616, *, node: StructuredAstValue) -> bool:
    """Return whether typed summary facts prove an unnamed stack-probe call."""
    if not bool(summary.stack_probe_helper):
        return False
    if not _call_name_is_unknown_8616(_call_node_name_8616(node)):
        return False
    return int(summary.arg_count or 0) == 0 and summary.stack_cleanup is None


def _bind_stale_probe_or_unknown_target_8616(
    *, project: StructuredAstValue, node: StructuredAstValue, target_addr: int, stats: StructuredAstValue
) -> bool:

    return __bind_stale_probe_or_unknown_target_8616___impl(node=node, project=project, stats=stats, target_addr=target_addr)


def __bind_stale_probe_or_unknown_target_8616___impl(*, node: StructuredAstValue, project: StructuredAstValue, stats: StructuredAstValue, target_addr: int) -> bool:
    call_name = _call_node_name_8616(node)
    if not (_is_stack_probe_call_name_8616(call_name) or _call_name_is_unknown_8616(call_name)):
        return False
    callee_func = getattr(node, "callee_func", None)
    if _function_matches_target_addr_8616(callee_func, target_addr):
        return False

    candidate = _lookup_callee_function_8616(project, target_addr, allow_containing=False)
    sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
    candidate_name = normalize_callee_name_8616(getattr(candidate, "name", None))
    target_name = (
        sidecar_label
        if isinstance(sidecar_label, str) and sidecar_label
        else candidate_name
        if isinstance(candidate_name, str) and candidate_name
        else None
    )
    if candidate is None and not isinstance(target_name, str):
        return False

    changed = False
    if candidate is not None and getattr(node, "callee_func", None) is not candidate:
        node.callee_func = candidate
        changed = True
    elif candidate is None and getattr(node, "callee_func", None) is not None:
        node.callee_func = None
        changed = True
    if isinstance(target_name, str) and getattr(node, "callee_target", None) != target_name:
        node.callee_target = target_name
        changed = True
    if changed:
        stats.stale_target_rejected_count += 1
    return changed



def _prefer_expected_source_name_8616(
    *,
    project: StructuredAstValue,
    node: StructuredAstValue,
    expected_source_name: str,
    target_addr: int | None,
    summary_arg_count: int,
) -> bool:

    return __prefer_expected_source_name_8616___impl(expected_source_name=expected_source_name, node=node, project=project, summary_arg_count=summary_arg_count, target_addr=target_addr)


def __prefer_expected_source_name_8616___impl(*, expected_source_name: str, node: StructuredAstValue, project: StructuredAstValue, summary_arg_count: int, target_addr: int | None) -> bool:
    expected_arity_contract = _known_callee_arity_contract_8616(expected_source_name)
    current_call_name = _call_node_name_8616(node)
    current_arity = len(_boundary_tuple_8616(getattr(node, "args", ()) or ()))
    current_expected_arity = (
        _expected_arg_count_for_known_callee_8616(current_call_name)
        if isinstance(current_call_name, str) and current_call_name
        else None
    )
    callsite_arity = summary_arg_count if summary_arg_count > 0 else current_arity
    source_name_proved = _source_name_matches_target_8616(project, target_addr, expected_source_name)
    if not (
        isinstance(expected_arity_contract.count, int)
        and expected_arity_contract.count >= 0
        and _call_arity_contract_allows_count_8616(expected_arity_contract, callsite_arity)
        and isinstance(current_call_name, str)
        and current_call_name
        and current_call_name != expected_source_name
        and source_name_proved
        and (
            current_expected_arity is None
            or current_expected_arity != expected_arity_contract.count
            or current_expected_arity == callsite_arity
        )
    ):
        return False
    changed = False
    if getattr(node, "callee_func", None) is not None:
        node.callee_func = None
        changed = True
    if getattr(node, "callee_target", None) != expected_source_name:
        node.callee_target = expected_source_name
        changed = True
    return changed



def _reject_stale_callee_target_8616(
    node: StructuredAstValue,
    matched_function: StructuredAstValue,
    current_addr: StructuredAstValue,
    expected_source_name: str | None,
    target_addr: int,
    stats: StructuredAstValue,
) -> bool:
    """Reject a callee_func whose address disagrees with the decoded target."""
    if (
        _function_matches_target_addr_8616(matched_function, target_addr)
        or not isinstance(expected_source_name, str)
        or not isinstance(current_addr, int)
    ):
        return False
    stats.stale_target_rejected_count += 1
    node.callee_func = None
    if getattr(node, "callee_target", None) != expected_source_name:
        node.callee_target = expected_source_name
    return True


def _rename_callee_to_expected_source_name_8616(
    project: StructuredAstValue,
    node: StructuredAstValue,
    callee_func: StructuredAstValue,
    target_addr: int,
    expected_source_name: str | None,
) -> bool:
    """Rename callee_func/callee_target to the expected source name when proven."""
    if not (
        isinstance(expected_source_name, str)
        and callee_func is not None
        and _source_name_matches_target_8616(project, target_addr, expected_source_name)
    ):
        return False
    changed = False
    current_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if current_name != expected_source_name:
        callee_func.name = expected_source_name
        changed = True
    if getattr(node, "callee_target", None) != expected_source_name:
        node.callee_target = expected_source_name
        changed = True
    return changed


def _bind_canonical_addr_target_8616(
    project: StructuredAstValue,
    node: StructuredAstValue,
    candidate: StructuredAstValue,
    target_addr: int,
    expected_source_name: str | None,
) -> bool:
    """Render the stable sub_<addr> target when no source or sidecar name is proven."""
    sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
    if not (
        _function_matches_target_addr_8616(candidate, target_addr)
        and not (isinstance(sidecar_label, str) and sidecar_label)
        and not (
            isinstance(expected_source_name, str)
            and expected_source_name
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
        )
    ):
        return False
    # A decoded direct-call address is stronger identity evidence than
    # an unproven third-party function name. Keep explicit source and
    # sidecar names above, otherwise render the stable address target.
    canonical_target = f"sub_{target_addr:x}"
    changed = False
    if getattr(node, "callee_func", None) is not None:
        node.callee_func = None
        changed = True
    if getattr(node, "callee_target", None) != canonical_target:
        node.callee_target = canonical_target
        changed = True
    return changed


def _bind_node_target_addr_8616(
    *,
    project: StructuredAstValue,
    node: StructuredAstValue,
    expected_source_name: str | None,
    target_addr: int,
    stats: StructuredAstValue,
) -> bool:

    return __bind_node_target_addr_8616___impl(expected_source_name=expected_source_name, node=node, project=project, stats=stats, target_addr=target_addr)


def __bind_node_target_addr_8616___impl(*, expected_source_name: str | None, node: StructuredAstValue, project: StructuredAstValue, stats: StructuredAstValue, target_addr: int) -> bool:
    changed = False
    candidate = _lookup_callee_function_8616(project, target_addr, allow_containing=False)
    if candidate is not None and getattr(node, "callee_func", None) is not candidate:
        candidate_name = normalize_callee_name_8616(getattr(candidate, "name", None))
        source_conflict = (
            isinstance(expected_source_name, str)
            and expected_source_name
            and _source_name_matches_target_8616(project, target_addr, expected_source_name)
            and isinstance(candidate_name, str)
            and candidate_name
            and expected_source_name != candidate_name
        )
        if not source_conflict:
            node.callee_func = candidate
            changed = True

    callee_func = getattr(node, "callee_func", None)
    current_addr = getattr(callee_func, "addr", None)
    matched_function = candidate if candidate is not None else callee_func
    if _reject_stale_callee_target_8616(
        node, matched_function, current_addr, expected_source_name, target_addr, stats
    ):
        return True
    changed |= _rename_callee_to_expected_source_name_8616(
        project, node, callee_func, target_addr, expected_source_name
    )
    changed |= _bind_canonical_addr_target_8616(project, node, candidate, target_addr, expected_source_name)
    return changed



def _accumulate_callsite_stats_from_call_nodes_8616(
    root: StructuredAstValue,
    summary_map: dict[int, StructuredAstValue],
    source_call_names: tuple[str, ...],
    project: StructuredAstValue,
    stats: CallsiteMaterializationStats,
) -> None:
    """Walk structured call nodes and accumulate materialization counters."""
    source_call_idx = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        summary = summary_map.get(id(node))
        if summary is None or bool(summary.stack_probe_helper):
            continue
        expected_source_name, source_call_idx = _next_source_call_name_for_summary_8616(
            source_call_names,
            source_call_idx,
            summary,
            project=project,
        )
        _accumulate_callsite_materialization_stats_8616(
            stats=stats,
            node=node,
            summary=summary,
            expected_source_name=expected_source_name,
            project=project,
        )


def _raise_on_prototype_arg_mismatch_8616(
    stats: CallsiteMaterializationStats, cfunc: StructuredAstValue, hard_gate_active: bool
) -> None:
    """Hard-fail (or defer) when known-prototype arg mismatches were observed."""
    if not stats.known_prototype_arg_mismatch_count:
        return
    mismatch_details = tuple(stats.known_prototype_arg_mismatches or ())
    if not hard_gate_active:
        log.debug("known prototype call argument mismatches deferred until final gate: %r", mismatch_details[:8])
        return
    log.error("known prototype call argument mismatches: %r", mismatch_details[:8])
    raise PipelineHardError(
        f"known prototype call argument mismatch count={stats.known_prototype_arg_mismatch_count}",
        layer="callsite_materialization",
        function_addr=int(getattr(cfunc, "addr", 0) or 0),
        details={
            "known_prototype_arg_mismatch_count": int(stats.known_prototype_arg_mismatch_count),
            "callsite_count": int(stats.callsite_count),
            "mismatches": mismatch_details[:8],
        },
    )


def _raise_on_unmaterialized_callsite_facts_8616(
    stats: CallsiteMaterializationStats, cfunc: StructuredAstValue, hard_gate_active: bool
) -> None:
    """Hard-fail when facts were classified but none materialized."""
    evidence_counters = stats.evidence_counters()
    if (
        evidence_counters["classified_fact_count"] <= 0
        or evidence_counters["materialized_count"] != 0
        or not hard_gate_active
    ):
        return
    log.error("callsite facts classified but none materialized: %r", evidence_counters)
    raise PipelineHardError(
        "callsite materialization classified facts but materialized none",
        layer="callsite_materialization",
        function_addr=int(getattr(cfunc, "addr", 0) or 0),
        details=evidence_counters,
    )


def _finalize_callsite_materialization_stats_8616(codegen: StructuredAstValue) -> CallsiteMaterializationStats:

    return __finalize_callsite_materialization_stats_8616___impl(codegen=codegen)


def __finalize_callsite_materialization_stats_8616___impl(*, codegen: StructuredAstValue) -> CallsiteMaterializationStats:
    previous = _ensure_callsite_materialization_stats_8616(codegen)
    stats = CallsiteMaterializationStats(
        bp_slot_arg_value_normalized_count=int(getattr(previous, "bp_slot_arg_value_normalized_count", 0) or 0),
        has_push_arg_evidence_count=int(getattr(previous, "has_push_arg_evidence_count", 0) or 0),
        no_push_arg_evidence_count=int(getattr(previous, "no_push_arg_evidence_count", 0) or 0),
        pointer_arg_materialized_count=int(getattr(previous, "pointer_arg_materialized_count", 0) or 0),
        push_order_reversed_count=int(getattr(previous, "push_order_reversed_count", 0) or 0),
        consumed_outgoing_stack_placeholder_count=int(
            getattr(previous, "consumed_outgoing_stack_placeholder_count", 0) or 0
        ),
        stale_target_rejected_count=int(getattr(previous, "stale_target_rejected_count", 0) or 0),
        byte_merge_raw_fact_count=int(getattr(previous, "byte_merge_raw_fact_count", 0) or 0),
        byte_merge_classified_fact_count=int(getattr(previous, "byte_merge_classified_fact_count", 0) or 0),
        byte_merge_materialized_count=int(getattr(previous, "byte_merge_materialized_count", 0) or 0),
        byte_merge_refused_count=int(getattr(previous, "byte_merge_refused_count", 0) or 0),
    )
    cfunc = getattr(codegen, "cfunc", None)
    root = _structured_root_8616(cfunc)
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        summary_map = {}
    else:
        _refresh_callsite_summary_node_ids_8616(codegen, summary_map)
    project = getattr(codegen, "project", None)
    source_call_names: tuple[str, ...] = ()
    if _source_call_floor_enabled_8616():
        func_addr = getattr(cfunc, "addr", None)
        if isinstance(func_addr, int):
            source_call_names = _cod_source_call_names_8616(project, func_addr)
    _accumulate_callsite_stats_from_call_nodes_8616(
        root, summary_map, source_call_names, project, stats
    )

    if stats.call_target_fact_count > stats.call_target_materialized_count:
        stats.failure_count += stats.call_target_fact_count - stats.call_target_materialized_count
    if stats.call_arg_fact_count > stats.call_arg_materialized_count:
        stats.failure_count += stats.call_arg_fact_count - stats.call_arg_materialized_count

    codegen._inertia_callsite_materialization_stats = stats
    _sync_callsite_materialization_stats_8616(codegen)
    codegen._inertia_callsite_materialization_report_8616 = stats.report_counters()

    hard_gate_active = bool(getattr(codegen, "_inertia_callsite_final_gate_active_8616", True))
    _raise_on_prototype_arg_mismatch_8616(stats, cfunc, hard_gate_active)
    _raise_on_unmaterialized_callsite_facts_8616(stats, cfunc, hard_gate_active)
    # Callsite summary evidence can be partial (especially for tiny helpers /
    # aggressively transformed CFG edges). Keep this as a diagnostic counter
    # instead of hard-aborting the whole function decompilation.
    if stats.call_target_fact_count > stats.call_target_materialized_count:
        log.debug(
            "callsite materialization incomplete: targets fact=%d materialized=%d",
            stats.call_target_fact_count,
            stats.call_target_materialized_count,
        )
    if stats.call_arg_fact_count > stats.call_arg_materialized_count:
        log.debug(
            "callsite materialization incomplete: args fact=%d materialized=%d",
            stats.call_arg_fact_count,
            stats.call_arg_materialized_count,
        )
    return stats



def _accumulate_callsite_materialization_stats_8616(
    *,
    stats: CallsiteMaterializationStats,
    node: StructuredAstValue,
    summary: CallsiteSummary8616,
    expected_source_name: str | None,
    project: StructuredAstValue = None,
) -> None:

    return __accumulate_callsite_materialization_stats_8616___impl(expected_source_name=expected_source_name, node=node, project=project, stats=stats, summary=summary)


def __accumulate_callsite_materialization_stats_8616___impl(*, expected_source_name: str | None, node: StructuredAstValue, project: StructuredAstValue, stats: CallsiteMaterializationStats, summary: CallsiteSummary8616) -> None:
    stats.callsite_count += 1
    target_addr = summary.target_addr
    if isinstance(target_addr, int):
        stats.call_target_fact_count += 1
        target_candidates = _candidate_linear_target_addrs_8616(project, target_addr)
        persisted_target_addr = structured_callsite_target_addr_8616(node)
        if (
            isinstance(persisted_target_addr, int)
            and any(
                _target_addr_matches_near_or_linear_8616(
                    persisted_target_addr,
                    expected_addr,
                )
                for expected_addr in target_candidates
            )
        ) or any(
            _function_matches_target_addr_8616(
                getattr(node, "callee_func", None),
                candidate,
            )
            for candidate in target_candidates
        ):
            stats.call_target_materialized_count += 1
        else:
            for candidate_addr in _candidate_target_addrs_from_call_8616(node):
                if any(
                    _target_addr_matches_near_or_linear_8616(candidate_addr, expected_addr)
                    for expected_addr in target_candidates
                ):
                    stats.call_target_materialized_count += 1
                    break
            else:
                call_name = _call_node_name_8616(node)
                if isinstance(expected_source_name, str) and call_name == expected_source_name:
                    stats.call_target_materialized_count += 1
    known_arity_contract = _known_callee_arity_contract_8616(_call_node_name_8616(node) or "")
    known_arg_count = known_arity_contract.count
    arg_fact_count = _logical_expected_arg_count_for_summary_8616(project, node, summary)
    if known_arg_count == 0:
        arg_fact_count = 0
    if arg_fact_count > 0:
        stats.call_arg_fact_count += arg_fact_count
        materialized_args = _boundary_tuple_8616(getattr(node, "args", ()) or ())
        stats.call_arg_materialized_count += min(arg_fact_count, len(materialized_args))
    actual_arg_count = len(_boundary_tuple_8616(getattr(node, "args", ()) or ()))
    if not _call_arity_contract_allows_count_8616(known_arity_contract, actual_arg_count):
        stats.known_prototype_arg_mismatch_count += 1
        stats.failure_count += 1
        stats.known_prototype_arg_mismatches.append(
            {
                "call": _call_node_name_8616(node),
                "callsite_addr": summary.callsite_addr,
                "target_addr": target_addr,
                "expected_arg_count": known_arg_count,
                "expected_arg_mode": known_arity_contract.mode.value,
                "actual_arg_count": actual_arg_count,
                "summary_arg_count": int(summary.arg_count or 0),
                "stack_probe_helper": bool(summary.stack_probe_helper),
            }
        )



def _cod_source_call_names_8616(project: StructuredAstValue, func_addr: int) -> tuple[str, ...]:
    return ()


def _cod_source_call_names_for_symbol_8616(project: StructuredAstValue, symbol_name: str | None) -> tuple[str, ...]:
    return ()


def _summary_type_8616(project: StructuredAstValue, width: int) -> StructuredAstValue:
    arch = getattr(project, "arch", None)
    ty = SimTypeLong(False) if width >= 4 else SimTypeShort(False)
    return ty.with_arch(arch) if arch is not None and hasattr(ty, "with_arch") else ty


def _word_type_8616(project: StructuredAstValue) -> StructuredAstValue:
    return _summary_type_8616(project, 2)


def _type_with_project_arch_8616(project: StructuredAstValue, type_: StructuredAstValue) -> StructuredAstValue:
    if type_ is None:
        return None
    try:
        _ = type_.size
        return type_
    except ValueError:
        pass
    except Exception:
        return type_
    arch = getattr(project, "arch", None)
    if arch is None or not hasattr(type_, "with_arch"):
        return type_
    with contextlib.suppress(Exception):
        return type_.with_arch(arch)
    return type_


def _ensure_c_expr_type_has_arch_8616(project: StructuredAstValue, expr: StructuredAstValue) -> StructuredAstValue:
    if expr is None:
        return None
    if isinstance(expr, structured_c.CVariable):
        variable_type = expr.variable_type
        fixed_type = _type_with_project_arch_8616(project, variable_type)
        if fixed_type is not None and fixed_type is not variable_type:
            with contextlib.suppress(Exception):
                expr.variable_type = fixed_type
    elif isinstance(expr, structured_c.CConstant):
        const_type = getattr(expr, "_type", None)
        fixed_type = _type_with_project_arch_8616(project, const_type)
        if fixed_type is not None and fixed_type is not const_type:
            with contextlib.suppress(Exception):
                expr._type = fixed_type
    return expr


def _safe_type_size_bits_8616(type_: StructuredAstValue, project: StructuredAstValue = None) -> int | None:
    if type_ is None:
        return None
    try:
        bits = getattr(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return bits
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(type_, "with_arch"):
        with contextlib.suppress(Exception):
            bound = type_.with_arch(arch)
            bits = getattr(bound, "size", None)
            if isinstance(bits, int) and bits > 0:
                return bits
    return None


def _prototype_arg_widths_8616(project: StructuredAstValue, prototype: StructuredAstValue) -> tuple[int, ...] | None:
    args = getattr(prototype, "args", None)
    if not isinstance(args, (list, tuple)):
        return None
    widths: list[int] = []
    for arg_type in args:
        bits = _safe_type_size_bits_8616(arg_type, project)
        if not isinstance(bits, int) or bits <= 0:
            return None
        widths.append(max(1, (bits + 7) // 8))
    return tuple(widths)


def _known_helper_prototype_arg_widths_8616(
    project: StructuredAstValue, symbol_name: str | None
) -> tuple[int, ...] | None:
    normalized = normalize_callee_name_8616(symbol_name)
    if not isinstance(normalized, str) or not normalized:
        return None
    override_widths = known_helper_abi_widths_8616(normalized)
    if override_widths is not None:
        return tuple(width for width in override_widths if isinstance(width, int)) if all(
            isinstance(width, int) for width in override_widths
        ) else None
    decl = preferred_known_helper_signature_decl(normalized)
    if not isinstance(decl, str) or not decl:
        return None
    with contextlib.suppress(Exception):
        _name, prototype, _arg_names = _parse_c_prototype_8616(decl)
        # Variadic declarations provide a minimum fixed prefix only. Their
        # parsed widths must not be used as an exact logical shape: doing so
        # can merge the format pointer and variadic values into one argument.
        if bool(getattr(prototype, "variadic", False)):
            return None
        return _prototype_arg_widths_8616(project, prototype)
    return None


def _near_function_pointer_type_8616(project: StructuredAstValue, arg_count: int | None) -> SimTypePointer:
    """Retain the pointer type class when binding the legacy callable view."""
    argc = arg_count if isinstance(arg_count, int) and arg_count >= 0 else 1
    prototype = SimTypeFunction(
        [_word_type_8616(project) for _ in range(argc)],
        _word_type_8616(project),
        variadic=False,
    )
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(prototype, "with_arch"):
        prototype = prototype.with_arch(arch)
    ptr_type = SimTypePointer(prototype)
    return cast(SimTypePointer, ptr_type.with_arch(arch)) if arch is not None else ptr_type


def _summary_return_type_8616(project: StructuredAstValue, summary: StructuredAstValue) -> StructuredAstValue:
    return_shape = summary.return_shape
    if return_shape == "dx_ax" and summary.return_used is True:
        return _summary_type_8616(project, 4)
    if return_shape in {None, "ax"} and summary.return_register == "ax" and summary.return_used is True:
        return _summary_type_8616(project, 2)
    ty = SimTypeBottom(label="void")
    arch = getattr(project, "arch", None)
    return ty.with_arch(arch) if arch is not None and hasattr(ty, "with_arch") else ty


def _prototype_needs_summary_8616(prototype: StructuredAstValue) -> bool:
    if prototype is None:
        return True
    args = _boundary_tuple_8616(getattr(prototype, "args", ()) or ())
    return_type = getattr(prototype, "returnty", None)
    if args:
        return False
    return type(return_type) is SimTypeBottom


def _resolved_summary_arg_widths_8616(
    summary: CallsiteSummary8616, callee_func: StructuredAstValue
) -> tuple[StructuredAstValue, ...] | None:
    """Resolve the summary arg width tuple, padding/truncating to the arg count."""
    logical_arg_widths = _logical_arg_widths_for_summary_8616(summary)
    arg_count = len(logical_arg_widths) if logical_arg_widths is not None else summary.arg_count
    if not isinstance(arg_count, int):
        return None
    arg_widths = logical_arg_widths or _boundary_tuple_8616(summary.arg_widths)
    try:
        callee_name = callee_func.name
    except AttributeError:
        callee_name = ""
    known_arg_count = _expected_arg_count_for_known_callee_8616(callee_name or "")
    if isinstance(known_arg_count, int) and known_arg_count > arg_count:
        arg_count = known_arg_count
    if len(arg_widths) < arg_count:
        arg_widths = arg_widths + tuple(2 for _ in range(arg_count - len(arg_widths)))
    elif len(arg_widths) > arg_count:
        arg_widths = arg_widths[:arg_count]
    return arg_widths


def _install_summary_prototype_8616(
    project: StructuredAstValue,
    callee_func: StructuredAstValue,
    summary: CallsiteSummary8616,
    arg_widths: tuple[StructuredAstValue, ...],
) -> None:
    """Build and install a guessed SimTypeFunction prototype on the callee."""
    arg_types = [_summary_type_8616(project, width) for width in arg_widths]
    arg_names = _normalize_arg_names_8616(None, len(arg_types))
    prototype = SimTypeFunction(
        arg_types,
        _summary_return_type_8616(project, summary),
        arg_names=arg_names,
        variadic=False,
    )
    try:
        arch = project.arch
    except AttributeError:
        arch = None
    if arch is not None and hasattr(prototype, "with_arch"):
        prototype = prototype.with_arch(arch)
    callee_func.prototype = prototype
    callee_func.is_prototype_guessed = True


def _apply_summary_prototype_8616(
    project: StructuredAstValue,
    callee_func: StructuredAstValue,
    summary: CallsiteSummary8616,
) -> bool:
    """Apply typed callsite evidence to a dynamic angr callee function."""


    return __apply_summary_prototype_8616___impl(callee_func=callee_func, project=project, summary=summary)


def __apply_summary_prototype_8616___impl(*, callee_func: StructuredAstValue, project: StructuredAstValue, summary: CallsiteSummary8616) -> bool:
    if callee_func is None:
        return False
    try:
        current_prototype = callee_func.prototype
    except AttributeError:
        return False
    if not _prototype_needs_summary_8616(current_prototype):
        return False
    arg_widths = _resolved_summary_arg_widths_8616(summary, callee_func)
    if arg_widths is None:
        return False
    _install_summary_prototype_8616(project, callee_func, summary, arg_widths)
    return True



def _collect_callsite_summary_inventory_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    function: StructuredAstValue,
    callsite_addrs: tuple[int, ...],
    names_changed: bool,
) -> dict[int, CallsiteSummary8616]:
    """Collect the authoritative per-callsite summary inventory."""
    retained_summaries = retained_program_callsite_summary_inventory_8616(
        project,
        function,
        callsite_addrs,
    )
    target_inventory: CallsiteTargetInventory8616 | None = None
    target_seeds = {seed.callsite_addr: seed for seed in collect_neighbor_call_targets(function)}
    previous_summary_inventory = _callsite_summary_inventory_8616(codegen)
    summary_inventory: dict[int, CallsiteSummary8616] = {}
    for callsite_addr in callsite_addrs:
        summary = retained_summaries.get(callsite_addr)
        if summary is None and not names_changed:
            summary = previous_summary_inventory.get(callsite_addr)
        if summary is None:
            if target_inventory is None:
                target_inventory = CallsiteTargetInventory8616.collect(function)
            summary = summarize_x86_16_callsite(
                function,
                callsite_addr,
                target_inventory=target_inventory,
            )
        if summary is None:
            summary = _tail_call_summary_from_seed_8616(target_seeds.get(callsite_addr))
        if summary is not None:
            previous_summary = previous_summary_inventory.get(callsite_addr)
            if previous_summary is not None:
                summary = carry_forward_logical_call_argument_shape_8616(
                    summary,
                    previous_summary,
                )
            summary_inventory[callsite_addr] = summary
    return summary_inventory


def _log_callsite_summary_debug_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    callsite_addrs: tuple[int, ...],
    source_call_names: tuple[str, ...],
    func_addr: int,
    measure_single_function_context: bool,
    kb_lookup_count: int,
) -> int:
    """Emit the callsite debug dump; returns the updated KB lookup count."""
    try:
        callsite_dbg = []
        for cs_addr in callsite_addrs:
            tgt = getattr(function, "get_call_target", lambda _addr: None)(cs_addr)
            if measure_single_function_context and isinstance(tgt, int):
                kb_lookup_count += 1
            callee = project.kb.functions.function(addr=tgt, create=False) if isinstance(tgt, int) else None
            callsite_dbg.append(
                (
                    hex(cs_addr),
                    hex(tgt) if isinstance(tgt, int) else None,
                    normalize_callee_name_8616(getattr(callee, "name", None)) if callee is not None else None,
                )
            )
        log.warning(
            "[callsite-summary] function=%#x callsites=%r source_calls=%r",
            int(func_addr),
            callsite_dbg,
            tuple(source_call_names),
        )
    except Exception:
        pass
    return kb_lookup_count


def _apply_summaries_to_ordered_callsite_pairs_8616(
    *,
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    ordered_pairs: list[tuple[CFunctionCall, int]],
    summary_inventory: dict[int, CallsiteSummary8616],
    summary_map: dict[int, StructuredAstValue],
    source_call_names: tuple[str, ...],
    source_call_idx: int,
    debug_callsites: bool,
    func_addr: int,
    allow_call_target_rewrites: bool,
    stats: CallsiteMaterializationStats,
) -> bool:
    """Apply each summary to its paired structured call node."""
    changed = False
    for node, callsite_addr in ordered_pairs:
        summary = summary_inventory.get(callsite_addr)
        if summary is None:
            continue
        if debug_callsites:
            log.warning(
                "[callsite-summary] map node_id=%#x callsite=%#x target=%r name_before=%r",
                id(node),
                callsite_addr,
                summary.target_addr,
                _call_node_name_8616(node),
            )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-attach] function=%#x node=%s callsite=%#x summary_args=%r summary_sources=%r",
                func_addr,
                _call_node_name_8616(node),
                callsite_addr,
                summary.arg_widths,
                summary.push_arg_sources,
            )
        expected_source_name = None
        if source_call_idx < len(source_call_names):
            expected_source_name, source_call_idx = _next_source_call_name_for_summary_8616(
                source_call_names,
                source_call_idx,
                summary,
                project=project,
            )
        changed |= _apply_callsite_summary_to_node_8616(
            project=project,
            codegen=codegen,
            node=node,
            summary=summary,
            summary_map=summary_map,
            expected_source_name=expected_source_name,
            allow_call_target_rewrites=allow_call_target_rewrites,
            stats=stats,
        )
    return changed


def _attach_callsite_summaries_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:

    return __attach_callsite_summaries_8616___impl(codegen=codegen, project=project)


def __attach_callsite_summaries_8616___impl(*, codegen: StructuredAstValue, project: StructuredAstValue) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return False
    measure_single_function_context = _single_function_context_measuring_enabled_8616()
    kb_lookup_count = 1
    lookup_start = time.perf_counter() if measure_single_function_context else 0.0
    function = _current_callsite_function_8616(project, func_addr)
    if function is None:
        return False
    patch_direct_call_sites(function)
    names_changed = _align_cod_call_names_8616(project, codegen) if _source_call_floor_enabled_8616() else False

    root = _structured_root_8616(cfunc)
    call_nodes = [
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
    ]
    callsite_addrs = _all_function_callsite_addrs_8616(project, function)
    if not callsite_addrs:
        return False
    summary_inventory = _collect_callsite_summary_inventory_8616(
        project, codegen, function, callsite_addrs, names_changed
    )
    codegen._inertia_callsite_summary_inventory_8616 = summary_inventory
    if not call_nodes:
        return False

    changed = bool(names_changed)
    allow_call_target_rewrites = os.environ.get(
        "INERTIA_ENABLE_CALLSITE_TARGET_REWRITES",
        "1",
    ).strip().lower() not in {"0", "false", "no", "off"}
    stats = _ensure_callsite_materialization_stats_8616(codegen)
    summary_map = dict(getattr(codegen, "_inertia_callsite_summaries", {}) or {})
    source_call_names: tuple[str, ...] = ()
    if _source_call_floor_enabled_8616():
        source_call_names = _cod_source_call_names_8616(project, func_addr)
    source_call_idx = 0
    debug_callsites = bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"))
    if debug_callsites:
        kb_lookup_count = _log_callsite_summary_debug_8616(
            project, function, callsite_addrs, source_call_names, func_addr,
            measure_single_function_context, kb_lookup_count,
        )
    ordered_pairs = _ordered_callsite_pairs_8616(
        project=project,
        function=function,
        root=root,
        call_nodes=call_nodes,
        callsite_addrs=callsite_addrs,
        node_callsite_addr_resolver=__attach_callsite_summaries_8616___node_callsite_addr,
        summary_inventory=summary_inventory,
    )

    if measure_single_function_context:
        print(
            f"[metric] fn={func_addr:#x} kind=kb-callsite-summary-lookups "
            f"kb_lookups={kb_lookup_count} elapsed_ms={int((time.perf_counter() - lookup_start) * 1000)}",
            file=sys.stderr,
            flush=True,
        )

    changed = _apply_summaries_to_ordered_callsite_pairs_8616(
        project=project,
        codegen=codegen,
        ordered_pairs=ordered_pairs,
        summary_inventory=summary_inventory,
        summary_map=summary_map,
        source_call_names=source_call_names,
        source_call_idx=source_call_idx,
        debug_callsites=debug_callsites,
        func_addr=func_addr,
        allow_call_target_rewrites=allow_call_target_rewrites,
        stats=stats,
    ) or changed
    if summary_map:
        codegen._inertia_callsite_summaries = summary_map
    return changed



def __attach_callsite_summaries_8616___node_callsite_addr(node: StructuredAstValue) -> int | None:
    if isinstance(node, CFunctionCall):
        exact_callsite_addr = structured_callsite_addr_8616(node)
        if exact_callsite_addr is not None:
            return exact_callsite_addr if isinstance(exact_callsite_addr, int) else None
    tags = getattr(node, "tags", None)
    if isinstance(tags, dict):
        for key in ("insn_addr", "stmt_addr", "addr"):
            value = tags.get(key)
            if isinstance(value, int):
                return value
    value = getattr(node, "addr", None)
    return value if isinstance(value, int) else None



def _all_function_callsite_addrs_8616(project: StructuredAstValue, function: StructuredAstValue) -> tuple[int, ...]:
    """Return exact decoded calls plus CFG-proven external tail-call sites."""
    recorded = {
        int(addr) for addr in (getattr(function, "get_call_sites", list)() or ()) if isinstance(addr, int)
    }
    discovered = set(recorded)
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return tuple(sorted(discovered))
    discovered.update(decoded_function_callsite_addresses_8616(function))
    discovered.update(target.callsite_addr for target in collect_neighbor_call_targets(function))
    return tuple(sorted(discovered))


def _match_unmatched_callsite_node_index_8616(
    *,
    project: StructuredAstValue,
    callsite_addr: int,
    summary: CallsiteSummary8616 | None,
    available_nodes: list[CFunctionCall],
    active_summary_inventory: Mapping[int, CallsiteSummary8616],
    call_return_store_offsets: dict[int, int],
    function: StructuredAstValue,
) -> int | None:
    """Resolve one unmatched callsite to an index into available_nodes."""
    matched_index = None
    if summary is not None:
        for idx, node in enumerate(available_nodes):
            if _call_node_matches_summary_8616(project, node, summary):
                matched_index = idx
                break
    if matched_index is None and summary is not None:
        matched_index = _match_node_index_by_return_store_8616(
            project, callsite_addr, summary, available_nodes,
            active_summary_inventory, call_return_store_offsets, function,
        )
    if matched_index is None:
        matched_index = _match_node_index_by_name_and_imm_8616(
            project, callsite_addr, summary, available_nodes,
            active_summary_inventory, function,
        )
    return matched_index


def _match_node_index_by_return_store_8616(
    project: StructuredAstValue,
    callsite_addr: int,
    summary: CallsiteSummary8616,
    available_nodes: list[CFunctionCall],
    active_summary_inventory: Mapping[int, CallsiteSummary8616],
    call_return_store_offsets: dict[int, int],
    function: StructuredAstValue,
) -> int | None:
    """Match a node via the stack offset that stores the call return value."""
    destination = summary.return_store_destination
    if not (
        isinstance(destination, tuple)
        and len(destination) == 2
        and destination[0] == "bp"
        and isinstance(destination[1], int)
    ):
        return None
    target_name = __ordered_callsite_pairs_8616___target_name_for_callsite(
        callsite_addr, active_summary_inventory=active_summary_inventory,
        function=function, project=project,
    )
    for idx, node in enumerate(available_nodes):
        if call_return_store_offsets.get(id(node)) != destination[1]:
            continue
        if isinstance(target_name, str) and not _callee_names_match_8616(
            _call_node_name_8616(node), target_name
        ):
            continue
        return idx
    return None


def _match_node_index_by_name_and_imm_8616(
    project: StructuredAstValue,
    callsite_addr: int,
    summary: CallsiteSummary8616 | None,
    available_nodes: list[CFunctionCall],
    active_summary_inventory: Mapping[int, CallsiteSummary8616],
    function: StructuredAstValue,
) -> int | None:
    """Match a node by callee name, refined by immediate argument equality."""
    target_name = __ordered_callsite_pairs_8616___target_name_for_callsite(
        callsite_addr, active_summary_inventory=active_summary_inventory,
        function=function, project=project,
    )
    if not (isinstance(target_name, str) and target_name):
        return None
    summary_imm_arg = __ordered_callsite_pairs_8616___single_summary_imm_arg(summary)
    if summary_imm_arg is not None:
        for idx, node in enumerate(available_nodes):
            existing_imm_arg = __ordered_callsite_pairs_8616___single_existing_imm_arg(node)
            if existing_imm_arg != summary_imm_arg:
                continue
            if _callee_names_match_8616(_call_node_name_8616(node), target_name):
                return idx
    matched_index = _match_node_index_by_imm_tuple_8616(
        summary, available_nodes, target_name
    )
    if matched_index is not None:
        return matched_index
    for idx, node in enumerate(available_nodes):
        existing_imm_arg = __ordered_callsite_pairs_8616___single_existing_imm_arg(node)
        if (
            summary_imm_arg is not None
            and existing_imm_arg is not None
            and existing_imm_arg != summary_imm_arg
        ):
            continue
        if _callee_names_match_8616(_call_node_name_8616(node), target_name):
            return idx
    return None


def _match_node_index_by_imm_tuple_8616(
    summary: CallsiteSummary8616 | None,
    available_nodes: list[CFunctionCall],
    target_name: str,
) -> int | None:
    """Match a node whose full immediate argument tuple equals the summary's."""
    summary_immediate_args = __ordered_callsite_pairs_8616___summary_immediate_args(summary)
    if summary_immediate_args is None:
        return None
    for idx, node in enumerate(available_nodes):
        if __ordered_callsite_pairs_8616___immediate_args(node) != summary_immediate_args:
            continue
        if _callee_names_match_8616(_call_node_name_8616(node), target_name):
            return idx
    return None


def _match_remaining_callsites_to_nodes_8616(
    *,
    project: StructuredAstValue,
    unmatched_callsites: list[int],
    remaining_nodes: list[CFunctionCall],
    active_summary_inventory: Mapping[int, CallsiteSummary8616],
    call_return_store_offsets: dict[int, int],
    ordered_pairs: list[tuple[CFunctionCall, int]],
    used_node_ids: set[int],
    function: StructuredAstValue,
) -> tuple[list[int], list[CFunctionCall]]:
    """Match leftover callsites against leftover nodes; returns (still_unmatched, available)."""
    still_unmatched_callsites: list[int] = []
    if remaining_nodes and unmatched_callsites:
        available_nodes = list(remaining_nodes)
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-summary] ordered unmatched callsites=%r remaining_names=%r",
                tuple(hex(addr) for addr in unmatched_callsites[:8]),
                tuple(_call_node_name_8616(node) for node in available_nodes[:16]),
            )
        for callsite_addr in unmatched_callsites:
            summary = active_summary_inventory.get(callsite_addr)
            matched_index = _match_unmatched_callsite_node_index_8616(
                project=project,
                callsite_addr=callsite_addr,
                summary=summary,
                available_nodes=available_nodes,
                active_summary_inventory=active_summary_inventory,
                call_return_store_offsets=call_return_store_offsets,
                function=function,
            )
            if matched_index is None:
                still_unmatched_callsites.append(callsite_addr)
                continue
            node = available_nodes.pop(matched_index)
            ordered_pairs.append((node, callsite_addr))
            used_node_ids.add(id(node))
        remaining_nodes = available_nodes
    return still_unmatched_callsites, remaining_nodes


def _local_callsite_summary_inventory_8616(
    function: StructuredAstValue, callsite_addrs: tuple[int, ...]
) -> dict[int, CallsiteSummary8616]:
    """Summarize each callsite locally when no shared inventory was provided."""
    local_inventory: dict[int, CallsiteSummary8616] = {}
    for callsite_addr in callsite_addrs:
        summary = summarize_x86_16_callsite(function, callsite_addr)
        if summary is not None:
            local_inventory[callsite_addr] = summary
    return local_inventory


def _call_return_store_stack_offsets_8616(
    root: StructuredAstValue, call_node_ids: set[int]
) -> dict[int, int]:
    """Map call node ids to the stack offset receiving their return value."""
    call_return_store_offsets: dict[int, int] = {}
    for assignment in _iter_c_nodes_deep_8616(root):
        if not isinstance(assignment, structured_c.CAssignment):
            continue
        lhs_offset = __ordered_callsite_pairs_8616___assignment_lhs_stack_offset(assignment)
        if not isinstance(lhs_offset, int):
            continue
        rhs = assignment.rhs
        matched_ids: set[int] = set()
        if id(rhs) in call_node_ids:
            matched_ids.add(id(rhs))
        for child in _iter_c_nodes_deep_8616(rhs):
            child_id = id(child)
            if child_id in call_node_ids:
                matched_ids.add(child_id)
        for node_id in matched_ids:
            call_return_store_offsets[node_id] = lhs_offset
    return call_return_store_offsets


def _partition_call_nodes_by_callsite_8616(
    call_nodes: list[CFunctionCall],
    node_callsite_addr_resolver: Callable[[StructuredAstValue], int | None],
) -> tuple[dict[int, list[CFunctionCall]], list[CFunctionCall]]:
    """Group call nodes by resolved callsite address; the rest stay unmatched."""
    nodes_by_callsite: dict[int, list[CFunctionCall]] = {}
    remaining_nodes: list[CFunctionCall] = []
    for node in call_nodes:
        node_callsite_addr = node_callsite_addr_resolver(node)
        if isinstance(node_callsite_addr, int):
            nodes_by_callsite.setdefault(node_callsite_addr, []).append(node)
        else:
            remaining_nodes.append(node)
    return nodes_by_callsite, remaining_nodes


def _match_call_nodes_by_callsite_addr_8616(
    project: StructuredAstValue,
    callsite_addrs: tuple[int, ...],
    nodes_by_callsite: dict[int, list[CFunctionCall]],
    active_summary_inventory: Mapping[int, CallsiteSummary8616],
    ordered_pairs: list[tuple[CFunctionCall, int]],
    used_node_ids: set[int],
) -> list[int]:
    """Pair callsites whose structured nodes carry a resolvable callsite address."""
    unmatched_callsites: list[int] = []
    for callsite_addr in callsite_addrs:
        matched_nodes = nodes_by_callsite.get(callsite_addr)
        if not matched_nodes:
            unmatched_callsites.append(callsite_addr)
            continue
        summary = active_summary_inventory.get(callsite_addr)
        chosen_index = _choose_summary_compatible_node_8616(project, matched_nodes, summary)
        if chosen_index is None:
            unmatched_callsites.append(callsite_addr)
            continue
        node = matched_nodes.pop(chosen_index)
        ordered_pairs.append((node, callsite_addr))
        used_node_ids.add(id(node))
        if len(callsite_addrs) == 1:
            for regenerated_node in tuple(matched_nodes):
                if not _call_node_can_take_summary_8616(project, regenerated_node, summary):
                    continue
                ordered_pairs.append((regenerated_node, callsite_addr))
                used_node_ids.add(id(regenerated_node))
    return unmatched_callsites


def _choose_summary_compatible_node_8616(
    project: StructuredAstValue,
    matched_nodes: list[CFunctionCall],
    summary: CallsiteSummary8616 | None,
) -> int | None:
    """Pick the index of the matched node compatible with the summary."""
    if len(matched_nodes) == 1:
        return 0 if _call_node_can_take_summary_8616(project, matched_nodes[0], summary) else None
    if summary is not None:
        for idx, node in enumerate(matched_nodes):
            if _call_node_matches_summary_8616(project, node, summary):
                return idx
    return None


def _ordered_callsite_pairs_8616(
    *,
    project: StructuredAstValue,
    function: StructuredAstValue,
    root: StructuredAstValue,
    call_nodes: list[CFunctionCall],
    callsite_addrs: tuple[int, ...],
    node_callsite_addr_resolver: Callable[[StructuredAstValue], int | None],
    summary_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> list[tuple[CFunctionCall, int]]:
    """Pair structured calls with the authoritative recovery inventory."""


    return __ordered_callsite_pairs_8616___impl(call_nodes=call_nodes, callsite_addrs=callsite_addrs, function=function, node_callsite_addr_resolver=node_callsite_addr_resolver, project=project, root=root, summary_inventory=summary_inventory)


def __ordered_callsite_pairs_8616___impl(*, call_nodes: list[CFunctionCall], callsite_addrs: tuple[int, ...], function: StructuredAstValue, node_callsite_addr_resolver: Callable[[StructuredAstValue], int | None], project: StructuredAstValue, root: StructuredAstValue, summary_inventory: Mapping[int, CallsiteSummary8616] | None) -> list[tuple[CFunctionCall, int]]:
    active_summary_inventory = summary_inventory
    if active_summary_inventory is None:
        active_summary_inventory = _local_callsite_summary_inventory_8616(function, callsite_addrs)































































    call_node_ids = {id(node) for node in call_nodes}
    call_return_store_offsets = _call_return_store_stack_offsets_8616(root, call_node_ids)

















    nodes_by_callsite, remaining_nodes = _partition_call_nodes_by_callsite_8616(
        call_nodes, node_callsite_addr_resolver
    )

    ordered_pairs: list[tuple[CFunctionCall, int]] = []
    used_node_ids: set[int] = set()
    unmatched_callsites = _match_call_nodes_by_callsite_addr_8616(
        project, callsite_addrs, nodes_by_callsite, active_summary_inventory,
        ordered_pairs, used_node_ids,
    )

    remaining_nodes.extend(
        node for node in call_nodes if id(node) not in used_node_ids and node not in remaining_nodes
    )
    still_unmatched_callsites: list[int] = []
    still_unmatched_callsites, remaining_nodes = _match_remaining_callsites_to_nodes_8616(
        project=project,
        unmatched_callsites=unmatched_callsites,
        remaining_nodes=remaining_nodes,
        active_summary_inventory=active_summary_inventory,
        call_return_store_offsets=call_return_store_offsets,
        ordered_pairs=ordered_pairs,
        used_node_ids=used_node_ids,
        function=function,
    )
    if len(remaining_nodes) == len(still_unmatched_callsites) and all(
        _call_node_name_8616(node) is None for node in remaining_nodes
    ):
        for node, callsite_addr in zip(remaining_nodes, still_unmatched_callsites, strict=False):
            ordered_pairs.append((node, callsite_addr))
    return ordered_pairs



def __ordered_callsite_pairs_8616___single_existing_imm_arg(node: StructuredAstValue) -> int | None:
    args = _boundary_tuple_8616(getattr(node, "args", ()) or ())
    if len(args) != 1:
        return None
    return __ordered_callsite_pairs_8616___constant_int_value(args[0])



def __ordered_callsite_pairs_8616___constant_int_value(node: StructuredAstValue) -> int | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    value = getattr(node, "value", None)
    if isinstance(value, int):
        return value & 0xFFFF
    return None



def __ordered_callsite_pairs_8616___assignment_lhs_stack_offset(node: StructuredAstValue) -> int | None:
    lhs = getattr(node, "lhs", None)
    while isinstance(lhs, CTypeCast):
        lhs = lhs.expr
    if isinstance(lhs, structured_c.CVariable):
        variable = lhs.variable
        if isinstance(variable, SimStackVariable):
            offset = variable.offset
            return offset if isinstance(offset, int) else None
    return None



def __ordered_callsite_pairs_8616___single_summary_imm_arg(summary: StructuredAstValue) -> int | None:
    sources = summary.push_arg_sources
    if not isinstance(sources, tuple) or len(sources) != 1:
        return None
    source = sources[0]
    if not isinstance(source, tuple) or len(source) < 2:
        return None
    if source[0] != "imm" or not isinstance(source[1], int):
        return None
    return int(source[1]) & 0xFFFF



def __ordered_callsite_pairs_8616___immediate_args(node: StructuredAstValue) -> tuple[int, ...] | None:
    args = _boundary_tuple_8616(getattr(node, "args", ()) or ())
    values = tuple(__ordered_callsite_pairs_8616___constant_int_value(arg) for arg in args)
    return tuple(value for value in values if isinstance(value, int)) if all(
        isinstance(value, int) for value in values
    ) else None



def __ordered_callsite_pairs_8616___summary_immediate_args(summary: StructuredAstValue) -> tuple[int, ...] | None:
    sources = summary.push_arg_sources
    if not isinstance(sources, tuple):
        return None
    values: list[int] = []
    for source in sources:
        if not isinstance(source, tuple) or len(source) < 2 or source[0] != "imm":
            return None
        value = source[1]
        if not isinstance(value, int):
            return None
        values.append(value & 0xFFFF)
    return tuple(values)



def __ordered_callsite_pairs_8616___target_name_for_callsite(callsite_addr: int, *, active_summary_inventory: dict[int, CallsiteSummary8616], function: StructuredAstValue, project: StructuredAstValue) -> str | None:
    try:
        target_addr = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
    except Exception:
        target_addr = None
    if not isinstance(target_addr, int):
        summary = active_summary_inventory.get(callsite_addr)
        target_addr = summary.target_addr if summary is not None else None
    if not isinstance(target_addr, int):
        return None
    candidate_func = _lookup_callee_function_8616(project, target_addr, allow_containing=False)
    candidate_name = normalize_callee_name_8616(getattr(candidate_func, "name", None))
    if isinstance(candidate_name, str) and candidate_name:
        return candidate_name
    return _sidecar_label_for_target_8616(project, target_addr)



def _upgrade_to_source_proven_probe_summary_8616(
    codegen: StructuredAstValue,
    node: StructuredAstValue,
    active_summary: CallsiteSummary8616,
    expected_source_name: str | None,
    stats: CallsiteMaterializationStats,
) -> tuple[CallsiteSummary8616, bool]:
    """Swap in the source-proven stack-probe summary and pin the probe name."""
    upgraded_summary = _source_proven_stack_probe_summary_8616(
        active_summary,
        node=node,
        expected_source_name=expected_source_name,
    )
    if upgraded_summary is active_summary:
        return active_summary, False
    changed = False
    stats.source_proven_stack_probe_count += 1
    _record_stack_probe_helper_target_fingerprints_8616(codegen, summary=upgraded_summary, call=node)
    normalized_probe_name = normalize_callee_name_8616(expected_source_name) or "aNchkstk"
    if getattr(node, "callee_func", None) is not None:
        node.callee_func = None
        changed = True
    if getattr(node, "callee_target", None) != normalized_probe_name:
        node.callee_target = normalized_probe_name
        changed = True
    return upgraded_summary, changed


def _resolve_summary_target_candidate_8616(
    project: StructuredAstValue,
    node: StructuredAstValue,
    callee_func: StructuredAstValue,
    target_addr: int,
    allow_call_target_rewrites: bool,
) -> tuple[StructuredAstValue, bool, StructuredAstValue, bool]:
    """Resolve the target-addr function candidate and rebind callee_func when allowed."""
    candidate = _lookup_callee_function_8616(project, target_addr, allow_containing=False)
    candidate_proves_target = False
    if candidate is not None and (
        _function_matches_target_addr_8616(candidate, target_addr)
        or _function_name_matches_target_addr_8616(candidate, target_addr)
    ):
        candidate_proves_target = True
    if candidate is None:
        containing_candidate = _lookup_callee_function_8616(project, target_addr, allow_containing=True)
        if containing_candidate is not None:
            candidate = containing_candidate
            candidate_proves_target = True
    changed = False
    if candidate is not None:
        current_addr = getattr(callee_func, "addr", None)
        candidate_addr = getattr(candidate, "addr", None)
        addr_mismatch = callee_func is None or (
            isinstance(current_addr, int)
            and isinstance(candidate_addr, int)
            and current_addr != candidate_addr
        )
        if candidate_proves_target and allow_call_target_rewrites and addr_mismatch:
            node.callee_func = candidate
            changed = True
            callee_func = candidate
    return candidate, candidate_proves_target, callee_func, changed


def _apply_sidecar_label_to_call_8616(
    project: StructuredAstValue,
    node: StructuredAstValue,
    candidate: StructuredAstValue,
    callee_func: StructuredAstValue,
    sidecar_label: str | None,
) -> tuple[StructuredAstValue, str | None, bool]:
    """Bind the sidecar label onto the call node and callee when it outranks."""
    changed = False
    if callee_func is None and node is not None and isinstance(sidecar_label, str):
        node.callee_func = candidate
        callee_func = candidate
    if (
        callee_func is None
        and isinstance(sidecar_label, str)
        and getattr(node, "callee_target", None) != sidecar_label
    ):
        cast(Any, node).callee_target = sidecar_label
        changed = True
    if _callee_name_should_yield_to_sidecar_8616(callee_func, sidecar_label):
        cast(Any, callee_func).name = sidecar_label
        changed = True
    callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if (
        isinstance(sidecar_label, str)
        and sidecar_label
        and isinstance(callee_name, str)
        and not _callee_names_match_8616(callee_name, sidecar_label)
    ):
        cast(Any, node).callee_func = None
        cast(Any, node).callee_target = sidecar_label
        callee_func = None
        callee_name = sidecar_label
        changed = True
    return callee_func, callee_name, changed


def _reject_unproven_matched_function_8616(
    project: StructuredAstValue,
    node: StructuredAstValue,
    candidate: StructuredAstValue,
    candidate_proves_target: bool,
    callee_func: StructuredAstValue,
    target_addr: int,
    expected_source_name: str | None,
    stats: CallsiteMaterializationStats,
) -> tuple[StructuredAstValue, str | None, bool]:
    """Drop callee_func/callee_name when the match does not prove the target."""
    current_addr = getattr(callee_func, "addr", None)
    matched_function = candidate if candidate is not None else callee_func
    if (
        candidate_proves_target
        or _function_matches_target_addr_8616(matched_function, target_addr)
        or not isinstance(current_addr, int)
    ):
        return callee_func, normalize_callee_name_8616(getattr(callee_func, "name", None)), False
    stats.stale_target_rejected_count += 1
    cast(Any, node).callee_func = None
    callee_func = None
    callee_name = None
    if (
        isinstance(expected_source_name, str)
        and expected_source_name
        and _source_name_matches_target_8616(project, target_addr, expected_source_name)
        and getattr(node, "callee_target", None) != expected_source_name
    ):
        cast(Any, node).callee_target = expected_source_name
    return callee_func, callee_name, True


def _bind_expected_name_to_proven_callee_8616(
    project: StructuredAstValue,
    callee_func: StructuredAstValue,
    callee_name: str | None,
    sidecar_label: str | None,
    target_addr: int,
    expected_source_name: str | None,
    candidate_proves_target: bool,
) -> tuple[StructuredAstValue, str | None, bool]:
    """Rename the callee to the expected source name when the target is proven."""
    changed = False
    expected_name_bindable = (
        isinstance(expected_source_name, str)
        and expected_source_name
        and sidecar_label is None
        and callee_func is not None
    )
    if expected_name_bindable and (
        candidate_proves_target or _function_matches_target_addr_8616(callee_func, target_addr)
    ) and not _callee_names_match_8616(callee_name, expected_source_name):
        callee_func.name = expected_source_name
        callee_name = normalize_callee_name_8616(expected_source_name)
        changed = True
    if (
        isinstance(expected_source_name, str)
        and callee_func is not None
        and (candidate_proves_target or _function_matches_target_addr_8616(callee_func, target_addr))
        and callee_name != expected_source_name
    ):
        callee_func.name = expected_source_name
        changed = True
    return callee_func, callee_name, changed


def _expected_name_fills_bare_target_8616(
    node: StructuredAstValue,
    callee_name: str | None,
    expected_source_name: str | None,
    sidecar_label: str | None,
    target_addr: int,
) -> bool:
    """Gate for filling an unlabeled callee_target from the expected source name."""
    if (
        callee_name is not None
        or not isinstance(expected_source_name, str)
        or not expected_source_name
    ):
        return False
    if sidecar_label is not None or isinstance(target_addr, int):
        return False
    return getattr(node, "callee_target", None) != expected_source_name


def _sync_call_node_callee_target_8616(
    project: StructuredAstValue,
    node: StructuredAstValue,
    callee_func: StructuredAstValue,
    callee_name: str | None,
    sidecar_label: str | None,
    target_addr: int,
    expected_source_name: str | None,
) -> bool:
    """Re-sync node.callee_target from the resolved callee name or sidecar."""
    callee_name = normalize_callee_name_8616(getattr(callee_func, "name", None))
    if callee_name is not None and getattr(node, "callee_target", None) != callee_name:
        cast(Any, node).callee_target = callee_name
        return True
    if (
        callee_name is None
        and isinstance(expected_source_name, str)
        and _source_name_matches_target_8616(project, target_addr, expected_source_name)
        and getattr(node, "callee_target", None) != expected_source_name
    ) or _expected_name_fills_bare_target_8616(
        node, callee_name, expected_source_name, sidecar_label, target_addr
    ):
        cast(Any, node).callee_target = expected_source_name
        return True
    return bool(_rename_call_node_from_sidecar_8616(project, node))


def _sync_prototype_widths_to_summary_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    node: StructuredAstValue,
    active_summary: CallsiteSummary8616,
    callee_func: StructuredAstValue,
    summary_map: dict[int, CallsiteSummary8616],
) -> tuple[CallsiteSummary8616, bool]:
    """Fold prototype arg widths back into the summary when they explain pushes."""
    if not (isinstance(active_summary, CallsiteSummary8616) and callee_func is not None):
        return active_summary, False
    try:
        prototype = callee_func.prototype
    except AttributeError:
        prototype = None
    logical_widths = _prototype_arg_widths_8616(project, prototype)
    push_sources = _boundary_tuple_8616(active_summary.push_arg_sources)
    if not (
        logical_widths
        and logical_widths != active_summary.logical_arg_widths
        and _prototype_widths_account_for_push_sources_top_8616(logical_widths, push_sources)
    ):
        return active_summary, False
    active_summary = replace(active_summary, logical_arg_widths=logical_widths)
    summary_map[id(node)] = active_summary
    record_callsite_summary_fact_8616(codegen, active_summary, node_id=id(node), attached=True)
    return active_summary, True


def _return_store_destination_applicable_8616(
    call: StructuredAstValue,
    summary: CallsiteSummary8616 | None,
    destination: StructuredAstValue,
) -> bool:
    """Gate for applying a summary return-store destination to a call."""
    return (
        call is not None
        and summary is not None
        and isinstance(destination, tuple)
        and len(destination) == 2
        and isinstance(destination[1], int)
        and summary.return_register in {None, "ax"}
    )


def _apply_callsite_summary_to_node_8616(
    *,
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    node: StructuredAstValue,
    summary: CallsiteSummary8616,
    summary_map: dict[int, CallsiteSummary8616],
    expected_source_name: str | None,
    allow_call_target_rewrites: bool,
    stats: CallsiteMaterializationStats,
) -> bool:
    """Attach one typed callsite summary to its C call node."""


    return __apply_callsite_summary_to_node_8616___impl(allow_call_target_rewrites=allow_call_target_rewrites, codegen=codegen, expected_source_name=expected_source_name, node=node, project=project, stats=stats, summary=summary, summary_map=summary_map)


def __apply_callsite_summary_to_node_8616___impl(*, allow_call_target_rewrites: bool, codegen: StructuredAstValue, expected_source_name: str | None, node: StructuredAstValue, project: StructuredAstValue, stats: CallsiteMaterializationStats, summary: CallsiteSummary8616, summary_map: dict[int, CallsiteSummary8616]) -> bool:
    if node is None:
        return False
    changed = False
    changed |= _drop_detached_callee_func_8616(node)
    active_summary, probe_changed = _upgrade_to_source_proven_probe_summary_8616(
        codegen, node, summary, expected_source_name, stats
    )
    changed |= probe_changed
    if summary_map.get(id(node)) != active_summary:
        summary_map[id(node)] = active_summary
        changed = True
        record_callsite_summary_fact_8616(codegen, active_summary, node_id=id(node), attached=True)
    target_addr = active_summary.target_addr
    if not isinstance(target_addr, int):
        return changed
    if active_summary.stack_probe_helper:
        return changed
    callee_func = getattr(node, "callee_func", None)
    candidate, candidate_proves_target, callee_func, candidate_changed = (
        _resolve_summary_target_candidate_8616(
            project, node, callee_func, target_addr, allow_call_target_rewrites
        )
    )
    changed |= candidate_changed
    sidecar_label = _sidecar_label_for_target_8616(project, target_addr)
    callee_func, callee_name, sidecar_changed = _apply_sidecar_label_to_call_8616(
        project, node, candidate, callee_func, sidecar_label
    )
    changed |= sidecar_changed
    callee_func, callee_name, stale_changed = _reject_unproven_matched_function_8616(
        project, node, candidate, candidate_proves_target, callee_func, target_addr,
        expected_source_name, stats,
    )
    changed |= stale_changed
    callee_func, callee_name, name_changed = _bind_expected_name_to_proven_callee_8616(
        project, callee_func, callee_name, sidecar_label, target_addr,
        expected_source_name, candidate_proves_target,
    )
    changed |= name_changed
    changed |= _sync_call_node_callee_target_8616(
        project, node, callee_func, callee_name, sidecar_label, target_addr, expected_source_name
    )
    active_summary, proto_changed = _sync_prototype_widths_to_summary_8616(
        codegen, project, node, active_summary, callee_func, summary_map
    )
    changed |= proto_changed
    return changed



def _census_call_nodes_by_callsite_8616(
    call_nodes: list[CFunctionCall],
) -> tuple[dict[int, list[CFunctionCall]], dict[int, CFunctionCall], dict[int, int]]:
    """Index call nodes by id and resolved callsite address."""
    nodes_by_callsite: dict[int, list[CFunctionCall]] = {}
    current_nodes_by_id: dict[int, CFunctionCall] = {}
    node_callsite_by_id: dict[int, int] = {}
    for node in call_nodes:
        node_id = id(node)
        current_nodes_by_id[node_id] = node
        callsite_addr = __refresh_callsite_summary_node_ids_8616___node_callsite_addr(node)
        if isinstance(callsite_addr, int):
            node_callsite_by_id[node_id] = callsite_addr
            nodes_by_callsite.setdefault(callsite_addr, []).append(node)
    return nodes_by_callsite, current_nodes_by_id, node_callsite_by_id


def _node_for_callsite_summary_8616(
    project: StructuredAstValue,
    callsite_addr: int,
    summary: StructuredAstValue,
    nodes_by_callsite: dict[int, list[CFunctionCall]],
) -> CFunctionCall | None:
    """Pick the unique structured node that can take this callsite summary."""
    candidates = nodes_by_callsite.get(callsite_addr, [])
    if not candidates:
        return None
    viable = [node for node in candidates if _call_node_can_take_summary_8616(project, node, summary)]
    if not viable:
        return None
    if len(viable) == 1:
        return viable[0]
    target_matches = [node for node in viable if _call_node_matches_summary_8616(project, node, summary)]
    if len(target_matches) == 1:
        return target_matches[0]
    named_viable = [node for node in viable if not _call_name_is_unknown_8616(_call_node_name_8616(node))]
    if len(named_viable) == 1:
        return named_viable[0]
    return None


def _refresh_one_summary_binding_8616(
    project: StructuredAstValue,
    node_id: int,
    node: CFunctionCall,
    summary: CallsiteSummary8616,
    node_callsite: int | None,
    refreshed: dict[int, CallsiteSummary8616],
    stale_items: list[tuple[int, CallsiteSummary8616]],
) -> bool:
    """Rebind one summary to its node or mark it stale; True when anything changed."""
    summary_callsite = summary.callsite_addr
    if (
        isinstance(summary_callsite, int)
        and isinstance(node_callsite, int)
        and summary_callsite != node_callsite
    ):
        stale_items.append((node_id, summary))
        return True
    if isinstance(summary_callsite, int) and node_callsite is None:
        if _summary_targets_stack_probe_helper_8616(project, summary) and (
            _call_node_has_nonprobe_target_evidence_8616(project, node)
        ):
            stale_items.append((node_id, summary))
            return True
        bind_structured_callsite_identity_8616(node, summary)
        refreshed[node_id] = summary
        return True
    if not _call_node_can_take_summary_8616(project, node, summary):
        stale_items.append((node_id, summary))
        return True
    previous_target_addr = structured_callsite_target_addr_8616(node)
    bind_structured_callsite_identity_8616(node, summary)
    refreshed[node_id] = summary
    return previous_target_addr != summary.target_addr


def _refresh_summary_map_bindings_8616(
    project: StructuredAstValue,
    summary_map: dict[int, CallsiteSummary8616],
    current_nodes_by_id: dict[int, CFunctionCall],
    node_callsite_by_id: dict[int, int],
) -> tuple[dict[int, CallsiteSummary8616], list[tuple[int, CallsiteSummary8616]], bool]:
    """Rebind each mapped summary to its current node; collect stale items."""
    changed = False
    refreshed: dict[int, CallsiteSummary8616] = {}
    stale_items: list[tuple[int, CallsiteSummary8616]] = []
    for node_id, summary in tuple(summary_map.items()):
        node = current_nodes_by_id.get(node_id)
        if node is None:
            stale_items.append((node_id, summary))
            continue
        changed = _refresh_one_summary_binding_8616(
            project, node_id, node, summary, node_callsite_by_id.get(node_id),
            refreshed, stale_items,
        ) or changed
    return refreshed, stale_items, changed


def _resolve_stale_summary_items_8616(
    project: StructuredAstValue,
    stale_items: list[tuple[int, CallsiteSummary8616]],
    refreshed: dict[int, CallsiteSummary8616],
    nodes_by_callsite: dict[int, list[CFunctionCall]],
) -> tuple[list[tuple[int, CallsiteSummary8616]], bool]:
    """Rebind stale summaries to the node matching their callsite when possible."""
    unresolved_stale_items: list[tuple[int, CallsiteSummary8616]] = []
    changed = False
    for node_id, summary in stale_items:
        callsite_addr = summary.callsite_addr
        if not isinstance(callsite_addr, int):
            unresolved_stale_items.append((node_id, summary))
            continue
        node = _node_for_callsite_summary_8616(project, callsite_addr, summary, nodes_by_callsite)
        if node is None:
            if __refresh_callsite_summary_node_ids_8616___summary_is_typed_stack_probe_fact_8616(summary):
                refreshed[node_id] = summary
                changed = True
            else:
                unresolved_stale_items.append((node_id, summary))
            continue
        target_node_id = id(node)
        if target_node_id in refreshed:
            changed = True
            continue
        bind_structured_callsite_identity_8616(node, summary)
        refreshed[target_node_id] = summary
        changed = True
    return unresolved_stale_items, changed


def _adopt_inventory_summaries_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    refreshed: dict[int, CallsiteSummary8616],
    nodes_by_callsite: dict[int, list[CFunctionCall]],
    unresolved_stale_items: list[tuple[int, CallsiteSummary8616]],
) -> bool:
    """Bind inventory summaries not yet represented by any refreshed node."""
    changed = False
    summary_inventory = _callsite_summary_inventory_8616(codegen)
    represented_callsites = {
        summary.callsite_addr
        for summary in refreshed.values()
        if isinstance(summary.callsite_addr, int)
    }
    for callsite_addr, summary in sorted(summary_inventory.items()):
        if callsite_addr in represented_callsites:
            continue
        node = _node_for_callsite_summary_8616(project, callsite_addr, summary, nodes_by_callsite)
        if node is not None and id(node) not in refreshed:
            bind_structured_callsite_identity_8616(node, summary)
            refreshed[id(node)] = summary
            represented_callsites.add(callsite_addr)
            changed = True
            continue
        unresolved_stale_items.append((-callsite_addr, summary))
    return changed


def _rebind_stale_summaries_by_evidence_8616(
    project: StructuredAstValue,
    unresolved_stale_items: list[tuple[int, CallsiteSummary8616]],
    call_nodes: list[CFunctionCall],
    refreshed: dict[int, CallsiteSummary8616],
) -> dict[int, CallsiteSummary8616]:
    """Fallback remap lane: rebind only where evidence still matches the summary."""
    # Fallback remap lane: when callsite tags are unavailable after AST
    # rewrites, rebind summaries only when the current call node still matches
    # the summary target/name evidence. Unknown means refuse; do not zip stale
    # summaries by order because that can manufacture wrong call semantics.
    if not all(isinstance(summary.callsite_addr, int) for _, summary in unresolved_stale_items):
        unresolved_stale_items = []
    available_nodes = [
        node for node in call_nodes if id(node) not in refreshed and __refresh_callsite_summary_node_ids_8616___node_callsite_addr(node) is None
    ]
    rebound = dict(refreshed)
    for old_node_id, summary in sorted(
        unresolved_stale_items,
        key=lambda item: item[1].callsite_addr,
    ):
        matched_idx = None
        for idx, node in enumerate(available_nodes):
            if _call_node_matches_summary_8616(project, node, summary):
                matched_idx = idx
                break
        if matched_idx is None:
            continue
        node = available_nodes.pop(matched_idx)
        rebound.pop(old_node_id, None)
        bind_structured_callsite_identity_8616(node, summary)
        rebound[id(node)] = summary
    return rebound


def _refresh_callsite_summary_node_ids_8616(
    codegen: StructuredAstValue, summary_map: dict[int, CallsiteSummary8616]
) -> bool:
    def _impl() -> bool:
        cfunc = getattr(codegen, "cfunc", None)
        root = _structured_root_8616(cfunc)
        if root is None:
            return False


        call_nodes = [
            node
            for node in _iter_c_nodes_deep_8616(root)
            if isinstance(node, CFunctionCall) and not _is_runtime_segment_helper_call_8616(node)
        ]
        nodes_by_callsite, current_nodes_by_id, node_callsite_by_id = (
            _census_call_nodes_by_callsite_8616(call_nodes)
        )
        project = getattr(codegen, "project", None)
        refreshed, stale_items, changed = _refresh_summary_map_bindings_8616(
            project, summary_map, current_nodes_by_id, node_callsite_by_id
        )
        unresolved_stale_items, stale_changed = _resolve_stale_summary_items_8616(
            project, stale_items, refreshed, nodes_by_callsite
        )
        changed |= stale_changed
        changed |= _adopt_inventory_summaries_8616(
            project, codegen, refreshed, nodes_by_callsite, unresolved_stale_items
        )
        rebound = _rebind_stale_summaries_by_evidence_8616(
            project, unresolved_stale_items, call_nodes, refreshed
        )

        if rebound == refreshed:
            if not changed and refreshed == summary_map:
                return False
            rebound = refreshed
        codegen._inertia_callsite_summaries = rebound
        summary_map.clear()
        summary_map.update(rebound)
        return True

    return _impl()


def __refresh_callsite_summary_node_ids_8616___summary_is_typed_stack_probe_fact_8616(summary: StructuredAstValue) -> bool:
    helper_return_space = summary.helper_return_space
    helper_return_space = helper_return_space.lower() if isinstance(helper_return_space, str) else None
    helper_return_width = summary.helper_return_width
    helper_return_address_kind = summary.helper_return_address_kind
    if isinstance(helper_return_address_kind, str):
        helper_return_address_kind = helper_return_address_kind.lower()
    return (
        bool(summary.stack_probe_helper)
        and summary.helper_return_state == "stack_address"
        and helper_return_space == "ss"
        and isinstance(helper_return_width, int)
        and helper_return_width > 0
        and helper_return_address_kind == "stack"
    )



def __refresh_callsite_summary_node_ids_8616___node_callsite_addr(node: StructuredAstValue) -> int | None:
    exact_callsite = structured_callsite_addr_8616(node)
    if isinstance(exact_callsite, int):
        return exact_callsite
    tags = getattr(node, "tags", None)
    try:
        normalized_tags = dict(cast(Mapping[object, object], tags).items())
    except (AttributeError, TypeError, ValueError):
        normalized_tags = {}
    if normalized_tags:
        for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
            value = normalized_tags.get(key)
            if isinstance(value, int):
                return value
    value = getattr(node, "addr", None)
    return value if isinstance(value, int) else None



def _prototype_candidate_summary_8616(
    node: StructuredAstValue, summary_map: dict[int, CallsiteSummary8616]
) -> tuple[CallsiteSummary8616 | None, str]:
    """Return the summary/call-name pair eligible for prototype materialization."""
    if not isinstance(node, CFunctionCall):
        return None, ""
    summary_obj = summary_map.get(id(node))
    if not isinstance(summary_obj, CallsiteSummary8616):
        return None, ""
    if not isinstance(summary_obj.target_addr, int):
        return None, ""
    if summary_obj.arg_count == 0 and _boundary_tuple_8616(node.args or ()):
        return None, ""
    call_name = _call_node_name_8616(node)
    if _is_runtime_segment_helper_call_8616(node):
        return None, ""
    if preferred_known_helper_signature_decl(call_name or "") is not None:
        return None, ""
    return summary_obj, call_name or ""


def _emit_summary_prototype_for_node_8616(
    project: StructuredAstValue,
    node: StructuredAstValue,
    summary_map: dict[int, CallsiteSummary8616],
    seen_decls: set[str],
    prototype_decls: list[str],
) -> bool:
    """Apply the summary prototype to the callee and record its decl."""
    summary, call_name = _prototype_candidate_summary_8616(node, summary_map)
    if summary is None:
        return False
    changed = _apply_summary_prototype_8616(project, node.callee_func, summary)
    if summary.stack_probe_helper or summary.arg_count == 0:
        return changed
    decl = __materialize_callsite_prototypes_8616___prototype_decl_from_summary(call_name, summary)
    if decl is not None and decl not in seen_decls:
        seen_decls.add(decl)
        prototype_decls.append(decl)
    return bool(changed)


def _materialize_callsite_prototypes_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:

    return __materialize_callsite_prototypes_8616___impl(codegen=codegen, project=project)


def __materialize_callsite_prototypes_8616___impl(*, codegen: StructuredAstValue, project: StructuredAstValue) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict) or not summary_map:
        return False


































    prototype_decls: list[str] = []
    seen_decls: set[str] = set(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
    changed = False
    root = _structured_root_8616(cfunc)
    for node in _iter_c_nodes_deep_8616(root):
        changed = _emit_summary_prototype_for_node_8616(
            project, node, summary_map, seen_decls, prototype_decls
        ) or changed
    if prototype_decls:
        existing = _boundary_tuple_8616(getattr(codegen, "_inertia_callsite_prototype_decls", ()) or ())
        set_codegen_sequence_attr(
            codegen,
            cfunc,
            "_inertia_callsite_prototype_decls",
            existing + tuple(prototype_decls),
        )
        codegen._inertia_codegen_decl_refresh_required_8616 = True
        changed = True
    return changed



def __materialize_callsite_prototypes_8616___prototype_decl_from_summary(name: str, summary: CallsiteSummary8616) -> str | None:
    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_]\w*", name) is None:
        return None
    logical_arg_widths = _logical_arg_widths_for_summary_8616(summary)
    arg_count = len(logical_arg_widths) if logical_arg_widths is not None else summary.arg_count
    if not isinstance(arg_count, int) or arg_count < 0:
        return None
    arg_widths = logical_arg_widths or _boundary_tuple_8616(summary.arg_widths)
    if len(arg_widths) != arg_count:
        arg_widths = tuple(2 for _ in range(arg_count))
    args = (
        "void"
        if arg_count == 0
        else ", ".join(f"{__materialize_callsite_prototypes_8616___ctype_for_width(width)} a{idx}" for idx, width in enumerate(arg_widths))
    )
    return_type = (
        __materialize_callsite_prototypes_8616___ctype_for_width(4)
        if summary.return_shape == "dx_ax" and summary.return_used is True
        else __materialize_callsite_prototypes_8616___ctype_for_width(2)
        if summary.return_shape in {None, "ax"}
        and summary.return_register == "ax"
        and summary.return_used is True
        else "int"
    )
    return f"{return_type} {name}({args});"



def __materialize_callsite_prototypes_8616___ctype_for_width(width: StructuredAstValue) -> str:
    if isinstance(width, int) and width >= 4:
        return "unsigned long"
    if isinstance(width, int) and width == 1:
        return "unsigned char"
    return "unsigned short"



def _stack_probe_summary_flags_8616(
    summary_map: dict[int, CallsiteSummary8616],
    typed_stack_probe_facts: dict[int, TypedStackProbeReturnFact8616],
) -> tuple[bool, bool]:
    """Classify typed stack-probe summaries for conservative argument lowering."""


    return __stack_probe_summary_flags_8616___impl(summary_map=summary_map, typed_stack_probe_facts=typed_stack_probe_facts)


def __stack_probe_summary_flags_8616___impl(*, summary_map: dict[int, CallsiteSummary8616], typed_stack_probe_facts: dict[int, TypedStackProbeReturnFact8616]) -> tuple[bool, bool]:
    has_recoverable_stack_probe = False
    for summary in tuple(summary_map.values()):
        if not summary.stack_probe_helper:
            continue
        if summary.helper_return_state != "stack_address":
            continue
        helper_return_space = summary.helper_return_space
        helper_return_space = helper_return_space.lower() if isinstance(helper_return_space, str) else None
        if helper_return_space not in {None, "ss"}:
            continue
        has_recoverable_stack_probe = True
        break
    has_unverified_non_ss_stack_probe = False
    for summary_node_id, summary in tuple(summary_map.items()):
        if not summary.stack_probe_helper:
            continue
        if typed_stack_probe_facts.get(summary_node_id) is not None:
            continue
        if summary.helper_return_state != "stack_address":
            continue
        helper_return_space = summary.helper_return_space
        helper_return_space = helper_return_space.lower() if isinstance(helper_return_space, str) else None
        if helper_return_space in {None, "ss"}:
            continue
        has_unverified_non_ss_stack_probe = True
        break
    return has_recoverable_stack_probe, has_unverified_non_ss_stack_probe



def _call_arg_materialization_mode_flags_8616(
    has_recoverable_stack_probe: bool,
) -> tuple[bool, bool]:
    conservative_materialization = (
        os.environ.get("INERTIA_CONSERVATIVE_CALLSITE_ARG_MATERIALIZE", "0").strip().lower()
        not in {
            "0",
            "false",
            "no",
            "off",
        }
        and not has_recoverable_stack_probe
    )
    prune_consumed_arg_stores = os.environ.get(
        "INERTIA_ENABLE_PRUNE_CONSUMED_CALL_ARG_STORES", "1"
    ).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return conservative_materialization, prune_consumed_arg_stores


def _default_args_override_expected_count_8616(
    expected_count: StructuredAstValue,
    known_count: int | None,
    default_args: tuple[StructuredAstValue, ...] | None,
    push_sources: tuple[StructuredAstValue, ...],
) -> bool:
    """Decide whether known-default args should override an absent expected count."""
    return (
        (not isinstance(expected_count, int) or expected_count <= 0)
        and isinstance(known_count, int)
        and known_count > 0
        and default_args is not None
        and len(default_args) == known_count
        and not push_sources
    )


def _direct_args_from_push_sources_8616(
    push_sources: tuple[StructuredAstValue, ...],
    expected_count: int,
    call_name: str,
    direct_expr_from_push_source_fn: Callable[..., StructuredAstValue | None],
) -> tuple[tuple[StructuredAstValue, ...], tuple[StructuredAstValue, ...]] | None:
    """Materialize direct args from push sources matching the expected count."""
    if not (isinstance(push_sources, tuple) and len(push_sources) == expected_count):
        return None
    ordered_sources = list(reversed(push_sources)) if len(push_sources) > 1 else list(push_sources)
    direct_args = [
        direct_expr_from_push_source_fn(source, call_name=call_name, arg_index=idx)
        for idx, source in enumerate(ordered_sources)
    ]
    if not all(arg is not None for arg in direct_args):
        return None
    return tuple(direct_args), tuple(ordered_sources)


def _commit_seeded_call_args_8616(
    node: StructuredAstValue,
    seeded_args: tuple[StructuredAstValue, ...],
    call_name: str,
    summary: CallsiteSummary8616 | None,
    set_materialized_call_args_fn: Callable[..., CallArgumentMutationResult8616],
    refresh_summary_arg_shape_fn: Callable[[StructuredAstValue, StructuredAstValue | None], None],
) -> bool:
    """Install seeded args on the call node and refresh the summary shape."""
    transaction = set_materialized_call_args_fn(
        node,
        seeded_args,
        call_name=call_name,
        force_replace=True,
    )
    if transaction.arguments_accepted:
        refresh_summary_arg_shape_fn(node, summary)
        return True
    return bool(transaction.changed)


def _conservative_seed_for_call_node_8616(
    node: StructuredAstValue,
    *,
    all_arg_exprs_are_non_segment_registers_fn: Callable[[StructuredAstValue], bool],
    call_args_need_rematerialization_fn: Callable[..., bool],
    call_name_fn: Callable[[StructuredAstValue], str | None],
    codegen: StructuredAstValue,
    direct_expr_from_push_source_fn: Callable[..., StructuredAstValue | None],
    expected_arg_count_fn: Callable[[str], int | None],
    has_unverified_non_ss_stack_probe: bool,
    known_default_args_fn: Callable[[str, StructuredAstValue], tuple[StructuredAstValue, ...] | None],
    normalize_materialized_call_args_fn: Callable[..., list[StructuredAstValue] | None],
    refresh_summary_arg_shape_fn: Callable[[StructuredAstValue, StructuredAstValue | None], None],
    set_materialized_call_args_fn: Callable[..., CallArgumentMutationResult8616],
    summary_map: dict[int, StructuredAstValue],
) -> bool:
    """Seed conservatively proven call args onto one call node."""
    if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
        return False
    call_name = call_name_fn(node) or ""
    summary_obj = summary_map.get(id(node))
    summary = summary_obj if isinstance(summary_obj, CallsiteSummary8616) else None
    if summary is not None and not _call_node_can_take_summary_8616(
        getattr(codegen, "project", None), node, summary
    ):
        summary = None
    push_sources = _boundary_tuple_8616(summary.push_arg_sources) if summary is not None else ()
    summary_arg_count = (
        _logical_expected_arg_count_for_summary_8616(codegen.project, node, summary)
        if summary is not None
        else None
    )
    known_count = expected_arg_count_fn(call_name)
    expected_count = _expected_arg_count_for_call_8616(
        summary_arg_count,
        known_arg_count=known_count,
        prototype_arg_count=None,
    )
    default_args = known_default_args_fn(call_name, codegen)
    if _default_args_override_expected_count_8616(expected_count, known_count, default_args, push_sources):
        expected_count = known_count
    if not (isinstance(expected_count, int) and expected_count > 0):
        return False
    current_args = _boundary_tuple_8616(getattr(node, "args", ()) or ())
    arity_mismatch = isinstance(known_count, int) and len(current_args) != known_count
    if (
        current_args
        and not arity_mismatch
        and not call_args_need_rematerialization_fn(node, push_arg_sources=push_sources)
    ):
        return False
    seeded_args = None
    direct_seed = _direct_args_from_push_sources_8616(
        push_sources, expected_count, call_name, direct_expr_from_push_source_fn
    )
    if direct_seed is not None:
        direct_args, ordered_sources = direct_seed
        normalized_args = normalize_materialized_call_args_fn(
            list(direct_args),
            [-1] * len(direct_args),
            [],
            call_name=call_name,
            push_sources=ordered_sources,
        )
        if normalized_args is not None and all_arg_exprs_are_non_segment_registers_fn(normalized_args):
            seeded_args = tuple(normalized_args)
    if seeded_args is None and (
        default_args is not None
        and len(default_args) == expected_count
        and not has_unverified_non_ss_stack_probe
    ):
        seeded_args = tuple(default_args)
    if seeded_args is None:
        return False
    return _commit_seeded_call_args_8616(
        node, seeded_args, call_name, summary,
        set_materialized_call_args_fn, refresh_summary_arg_shape_fn,
    )


def _seed_empty_known_helper_for_node_8616(
    node: StructuredAstValue,
    *,
    call_name_fn: Callable[[StructuredAstValue], str | None],
    codegen: StructuredAstValue,
    direct_expr_from_push_source_fn: Callable[..., StructuredAstValue | None],
    expected_arg_count_fn: Callable[[str], int | None],
    has_unverified_non_ss_stack_probe: bool,
    known_default_args_fn: Callable[[str, StructuredAstValue], tuple[StructuredAstValue, ...] | None],
    refresh_summary_arg_shape_fn: Callable[[StructuredAstValue, StructuredAstValue | None], None],
    set_materialized_call_args_fn: Callable[..., CallArgumentMutationResult8616],
    summary_map: dict[int, StructuredAstValue],
) -> bool:
    """Seed args onto one empty known-helper call node."""
    if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
        return False
    call_name = call_name_fn(node) or ""
    known_count = expected_arg_count_fn(call_name)
    summary_obj = summary_map.get(id(node))
    summary = summary_obj if isinstance(summary_obj, CallsiteSummary8616) else None
    if summary is not None and not _call_node_can_take_summary_8616(
        getattr(codegen, "project", None), node, summary
    ):
        summary = None
    push_sources = _boundary_tuple_8616(summary.push_arg_sources) if summary is not None else ()
    summary_arg_count = (
        _logical_expected_arg_count_for_summary_8616(codegen.project, node, summary)
        if summary is not None
        else None
    )
    expected_count = _expected_arg_count_for_call_8616(
        summary_arg_count,
        known_arg_count=known_count,
        prototype_arg_count=None,
    )
    default_args = known_default_args_fn(call_name, codegen)
    if _default_args_override_expected_count_8616(expected_count, known_count, default_args, push_sources):
        expected_count = known_count
    if not (isinstance(expected_count, int) and expected_count > 0):
        return False
    if _boundary_tuple_8616(getattr(node, "args", ()) or ()):
        return False
    seeded_args = None
    direct_seed = _direct_args_from_push_sources_8616(
        push_sources, expected_count, call_name, direct_expr_from_push_source_fn
    )
    if direct_seed is not None:
        seeded_args = direct_seed[0]
    if seeded_args is None and (
        default_args is not None
        and len(default_args) == expected_count
        and not has_unverified_non_ss_stack_probe
    ):
        seeded_args = tuple(default_args)
    if seeded_args is None:
        return False
    return _commit_seeded_call_args_8616(
        node, seeded_args, call_name, summary,
        set_materialized_call_args_fn, refresh_summary_arg_shape_fn,
    )


def _conservative_call_arg_seed_8616(
    *,
    root: StructuredAstValue,
    summary_map: dict[int, StructuredAstValue],
    codegen: StructuredAstValue,
    has_unverified_non_ss_stack_probe: bool,
    call_name_fn: Callable[[StructuredAstValue], str | None],
    expected_arg_count_fn: Callable[[str], int | None],
    known_default_args_fn: Callable[[str, StructuredAstValue], tuple[StructuredAstValue, ...] | None],
    direct_expr_from_push_source_fn: Callable[..., StructuredAstValue | None],
    normalize_materialized_call_args_fn: Callable[..., list[StructuredAstValue] | None],
    all_arg_exprs_are_non_segment_registers_fn: Callable[[StructuredAstValue], bool],
    set_materialized_call_args_fn: Callable[..., CallArgumentMutationResult8616],
    refresh_summary_arg_shape_fn: Callable[[StructuredAstValue, StructuredAstValue | None], None],
    call_args_need_rematerialization_fn: Callable[..., bool],
) -> bool:

    return __conservative_call_arg_seed_8616___impl(all_arg_exprs_are_non_segment_registers_fn=all_arg_exprs_are_non_segment_registers_fn, call_args_need_rematerialization_fn=call_args_need_rematerialization_fn, call_name_fn=call_name_fn, codegen=codegen, direct_expr_from_push_source_fn=direct_expr_from_push_source_fn, expected_arg_count_fn=expected_arg_count_fn, has_unverified_non_ss_stack_probe=has_unverified_non_ss_stack_probe, known_default_args_fn=known_default_args_fn, normalize_materialized_call_args_fn=normalize_materialized_call_args_fn, refresh_summary_arg_shape_fn=refresh_summary_arg_shape_fn, root=root, set_materialized_call_args_fn=set_materialized_call_args_fn, summary_map=summary_map)


def __conservative_call_arg_seed_8616___impl(*, all_arg_exprs_are_non_segment_registers_fn: Callable[[StructuredAstValue], bool], call_args_need_rematerialization_fn: Callable[..., bool], call_name_fn: Callable[[StructuredAstValue], str | None], codegen: StructuredAstValue, direct_expr_from_push_source_fn: Callable[..., StructuredAstValue | None], expected_arg_count_fn: Callable[[str], int | None], has_unverified_non_ss_stack_probe: bool, known_default_args_fn: Callable[[str, StructuredAstValue], tuple[StructuredAstValue, ...] | None], normalize_materialized_call_args_fn: Callable[..., list[StructuredAstValue] | None], refresh_summary_arg_shape_fn: Callable[[StructuredAstValue, StructuredAstValue | None], None], root: StructuredAstValue, set_materialized_call_args_fn: Callable[..., CallArgumentMutationResult8616], summary_map: dict[int, StructuredAstValue]) -> bool:
    changed = False
    for node in _iter_c_nodes_deep_8616(root):
        changed = _conservative_seed_for_call_node_8616(
            node,
            all_arg_exprs_are_non_segment_registers_fn=all_arg_exprs_are_non_segment_registers_fn,
            call_args_need_rematerialization_fn=call_args_need_rematerialization_fn,
            call_name_fn=call_name_fn,
            codegen=codegen,
            direct_expr_from_push_source_fn=direct_expr_from_push_source_fn,
            expected_arg_count_fn=expected_arg_count_fn,
            has_unverified_non_ss_stack_probe=has_unverified_non_ss_stack_probe,
            known_default_args_fn=known_default_args_fn,
            normalize_materialized_call_args_fn=normalize_materialized_call_args_fn,
            refresh_summary_arg_shape_fn=refresh_summary_arg_shape_fn,
            set_materialized_call_args_fn=set_materialized_call_args_fn,
            summary_map=summary_map,
        ) or changed
    return changed



def _seed_empty_known_helper_calls_8616(
    *,
    root: StructuredAstValue,
    summary_map: dict[int, StructuredAstValue],
    codegen: StructuredAstValue,
    has_unverified_non_ss_stack_probe: bool,
    call_name_fn: Callable[[StructuredAstValue], str | None],
    expected_arg_count_fn: Callable[[str], int | None],
    known_default_args_fn: Callable[[str, StructuredAstValue], tuple[StructuredAstValue, ...] | None],
    direct_expr_from_push_source_fn: Callable[..., StructuredAstValue | None],
    set_materialized_call_args_fn: Callable[..., CallArgumentMutationResult8616],
    refresh_summary_arg_shape_fn: Callable[[StructuredAstValue, StructuredAstValue | None], None],
) -> bool:

    return __seed_empty_known_helper_calls_8616___impl(call_name_fn=call_name_fn, codegen=codegen, direct_expr_from_push_source_fn=direct_expr_from_push_source_fn, expected_arg_count_fn=expected_arg_count_fn, has_unverified_non_ss_stack_probe=has_unverified_non_ss_stack_probe, known_default_args_fn=known_default_args_fn, refresh_summary_arg_shape_fn=refresh_summary_arg_shape_fn, root=root, set_materialized_call_args_fn=set_materialized_call_args_fn, summary_map=summary_map)


def __seed_empty_known_helper_calls_8616___impl(*, call_name_fn: Callable[[StructuredAstValue], str | None], codegen: StructuredAstValue, direct_expr_from_push_source_fn: Callable[..., StructuredAstValue | None], expected_arg_count_fn: Callable[[str], int | None], has_unverified_non_ss_stack_probe: bool, known_default_args_fn: Callable[[str, StructuredAstValue], tuple[StructuredAstValue, ...] | None], refresh_summary_arg_shape_fn: Callable[[StructuredAstValue, StructuredAstValue | None], None], root: StructuredAstValue, set_materialized_call_args_fn: Callable[..., CallArgumentMutationResult8616], summary_map: dict[int, StructuredAstValue]) -> bool:
    changed = False
    for node in _iter_c_nodes_deep_8616(root):
        changed = _seed_empty_known_helper_for_node_8616(
            node,
            call_name_fn=call_name_fn,
            codegen=codegen,
            direct_expr_from_push_source_fn=direct_expr_from_push_source_fn,
            expected_arg_count_fn=expected_arg_count_fn,
            has_unverified_non_ss_stack_probe=has_unverified_non_ss_stack_probe,
            known_default_args_fn=known_default_args_fn,
            refresh_summary_arg_shape_fn=refresh_summary_arg_shape_fn,
            set_materialized_call_args_fn=set_materialized_call_args_fn,
            summary_map=summary_map,
        ) or changed
    return changed



def _clear_zero_arg_known_helper_args_8616(
    *,
    root: StructuredAstValue,
    summary_map: dict[int, StructuredAstValue],
    call_name_fn: StructuredAstValue,
    expected_arg_count_fn: StructuredAstValue,
    set_materialized_call_args_fn: StructuredAstValue,
    refresh_summary_arg_shape_fn: StructuredAstValue,
) -> bool:

    return __clear_zero_arg_known_helper_args_8616___impl(call_name_fn=call_name_fn, expected_arg_count_fn=expected_arg_count_fn, root=root, set_materialized_call_args_fn=set_materialized_call_args_fn, summary_map=summary_map)


def __clear_zero_arg_known_helper_args_8616___impl(*, call_name_fn: StructuredAstValue, expected_arg_count_fn: StructuredAstValue, root: StructuredAstValue, set_materialized_call_args_fn: StructuredAstValue, summary_map: dict[int, StructuredAstValue]) -> bool:
    changed = False
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
            continue
        call_name = call_name_fn(node) or ""
        known_count = expected_arg_count_fn(call_name)
        if known_count != 0:
            continue
        current_args = _boundary_tuple_8616(getattr(node, "args", ()) or ())
        if not current_args:
            continue
        summary = summary_map.get(id(node))
        set_materialized_call_args_fn(node, (), call_name=call_name, force_replace=True)
        if summary is not None:
            updated = replace(summary, arg_count=0, arg_widths=())
            summary_map[id(node)] = updated
            changed = True
        changed = True
    return changed



def _record_unmaterialized_callsite_arg_gaps_8616(
    *,
    root: StructuredAstValue,
    summary_map: dict[int, StructuredAstValue],
    codegen: StructuredAstValue,
) -> None:
    gaps: list[dict[str, StructuredAstValue]] = []
    project = getattr(codegen, "project", None)
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall) or _is_runtime_segment_helper_call_8616(node):
            continue
        summary = summary_map.get(id(node))
        if summary is None:
            continue
        push_sources = _boundary_tuple_8616(summary.push_arg_sources or ())
        expected_count = _logical_expected_arg_count_for_summary_8616(project, node, summary)
        if expected_count <= 0:
            continue
        current_args = _boundary_tuple_8616(getattr(node, "args", ()) or ())
        if len(current_args) >= expected_count:
            continue
        gaps.append(
            {
                "kind": CallArgMaterializationGap8616.SUMMARY_ARG_PROOF_UNCONSUMED.value,
                "call": _call_node_name_8616(node),
                "callsite": summary.callsite_addr,
                "target": summary.target_addr,
                "expected": expected_count,
                "actual": len(current_args),
                "push_sources": push_sources,
            }
        )
    codegen._inertia_callsite_unmaterialized_arg_gaps_8616 = tuple(gaps)
    if gaps and os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
        log.warning(
            "[call-arg-gap] function=%#x gaps=%r",
            getattr(getattr(codegen, "cfunc", None), "addr", 0) or 0,
            gaps[:8],
        )


def _rhs_matches_call_return_addr_8616(rhs: StructuredAstValue, call_return_addr: int | None) -> bool:
    """Check whether an rhs stores the masked call return address."""
    if not isinstance(call_return_addr, int):
        return False
    node = rhs
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, structured_c.CConstant):
        return False
    value = node.value
    if not isinstance(value, int):
        return False
    return (value & 0xFFFF) == (int(call_return_addr) & 0xFFFF)


def _linear_add_offset_key_8616(
    lhs_key: StructuredAstValue, rhs_key: StructuredAstValue
) -> StructuredAstValue | None:
    lhs_const, lhs_scale, lhs_var = lhs_key
    rhs_const, rhs_scale, rhs_var = rhs_key
    if lhs_var is None:
        return ((lhs_const + rhs_const) & 0xFFFF, rhs_scale, rhs_var)
    if rhs_var is None:
        return ((lhs_const + rhs_const) & 0xFFFF, lhs_scale, lhs_var)
    if lhs_var == rhs_var:
        return ((lhs_const + rhs_const) & 0xFFFF, lhs_scale + rhs_scale, lhs_var)
    return None


@dataclass(frozen=True, slots=True)
class _CallEvidenceFlags8616:
    """Derived evidence flags for one call statement."""
    probe_seen_without_ss_address: StructuredAstValue
    has_exact_direct_push_sources: StructuredAstValue
    has_instruction_proven_direct_push_sources: StructuredAstValue
    has_safe_non_stack_fallback: StructuredAstValue
    has_recent_stack_arg_store_evidence: StructuredAstValue
    has_physical_far_pointer_push_sources: StructuredAstValue
    has_exact_arithmetic_push_sources: StructuredAstValue
    rematerialize_call_args: StructuredAstValue


@dataclass(frozen=True, slots=True)
class _CallStmtFacts8616:
    """Per-statement resolved call locals for the rewrite loop."""
    summary: StructuredAstValue
    arg_count: StructuredAstValue
    summary_arg_count: StructuredAstValue
    stack_cleanup: StructuredAstValue
    summary_return_addr: StructuredAstValue
    call_name: StructuredAstValue
    semantic_call_name: StructuredAstValue
    prototype_arg_widths: StructuredAstValue
    known_prototype_arg_widths: StructuredAstValue
    effective_prototype_arg_widths: StructuredAstValue
    summary_logical_arg_widths: StructuredAstValue
    prototype_arg_count: StructuredAstValue
    known_arg_count: StructuredAstValue
    is_stack_probe_helper: StructuredAstValue
    push_arg_sources: StructuredAstValue


@dataclass(frozen=True, slots=True)
class _CallArityEvidence8616:
    """Resolved argument-count/width evidence for one call statement."""
    typed_stack_probe_materialization: StructuredAstValue
    expected_arg_count: StructuredAstValue
    expected_arg_widths: StructuredAstValue
    logical_arg_widths_for_sources: StructuredAstValue
    fallback_arg_count: StructuredAstValue
    rematerialize_call_args: StructuredAstValue


class _CallsiteStackArgsMaterializer8616:
    """Materialize callsite stack arguments over the structured C body."""

    def __init__(self, project: StructuredAstValue, codegen: StructuredAstValue) -> None:
        self.project = project
        self.codegen = codegen

    def run(self) -> bool:
        self.cfunc = getattr(self.codegen, "cfunc", None)
        if self.cfunc is None:
            _set_callsite_materialization_decision_8616(
                self.codegen,
                CallsiteMaterializationDecision8616.NOT_APPLICABLE,
                changed=False,
                signature=None,
            )
            return False
        fixed_probe_changed = _replay_fixed_stack_probe_frame_lowerer_8616(self.codegen)
        signature = _callsite_materialization_signature_8616(self.codegen)
        previous_signature = getattr(self.codegen, "_inertia_callsite_materialization_signature_8616", None)
        previous_complete = bool(getattr(self.codegen, "_inertia_callsite_materialization_complete_8616", False))
        selector_materialized_before = int(
            getattr(self.codegen, "_inertia_call_return_switch_selector_materialized_8616", 0) or 0
        )
        self.codegen._inertia_callsite_unmaterialized_arg_gaps_8616 = ()
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-materialize-enter] function=%#x",
                getattr(self.cfunc, "addr", 0) or 0,
            )
        early = self._run_early_refusal_gates(
            fixed_probe_changed, signature, previous_signature, previous_complete
        )
        if early is not None:
            return early
        self._run_collect_evidence()
        early = self._run_summary_prep(fixed_probe_changed, signature)
        if early is not None:
            return early
        self.changed = fixed_probe_changed
        has_push_arg_evidence, conservative_materialization, disable_stack_probe_setup_prune = (
            self._run_evidence_and_controls()
        )
        root = _structured_root_8616(self.cfunc)
        if isinstance(getattr(root, "statements", None), (list, tuple)):
            self._run_rewrite_root(
                root,
                disable_stack_probe_setup_prune=disable_stack_probe_setup_prune,
                conservative_materialization=conservative_materialization,
                has_push_arg_evidence=has_push_arg_evidence,
            )
        return self._run_publish(root, selector_materialized_before)

    def _run_early_refusal_gates(
        self,
        fixed_probe_changed: bool,
        signature: StructuredAstValue,
        previous_signature: StructuredAstValue,
        previous_complete: bool,
    ) -> bool | None:
        """Handle pointer-memory and cache-hit early-refusal gates; None means continue."""
        if getattr(self.codegen, "_inertia_pointer_memory_materialized_8616", None):
            # Pointer-memory materialization replaces small leaf bodies from
            # instruction evidence. Running stale callsite recovery afterward can
            # rewrite non-call carrier statements, so call lowering must refuse.
            self.codegen._inertia_callsite_stack_args_refused_pointer_memory_8616 = (
                int(getattr(self.codegen, "_inertia_callsite_stack_args_refused_pointer_memory_8616", 0) or 0) + 1
            )
            _set_callsite_materialization_decision_8616(
                self.codegen,
                CallsiteMaterializationDecision8616.REFUSED_POINTER_MEMORY,
                changed=fixed_probe_changed,
                signature=signature,
            )
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-materialize-refuse] function=%#x reason=pointer-memory-materialized",
                    getattr(self.cfunc, "addr", 0) or 0,
                )
            return fixed_probe_changed
        if previous_complete and signature is not None and previous_signature == signature:
            _set_callsite_materialization_decision_8616(
                self.codegen,
                CallsiteMaterializationDecision8616.CACHE_HIT,
                changed=fixed_probe_changed,
                signature=signature,
            )
            return fixed_probe_changed
        return None

    def _run_collect_evidence(self) -> None:
        """Collect COD/function evidence for the current function."""
        self.func_addr = getattr(self.cfunc, "addr", None)
        with span(
            "x86_16.call_args.collect_evidence",
            function=self.func_addr if isinstance(self.func_addr, int) else None,
        ):
            cod_metadata = _cod_metadata_for_function_8616(self.project, self.func_addr) if isinstance(self.func_addr, int) else None
            self.cod_path_hint = getattr(cod_metadata, "cod_path", None) if cod_metadata is not None else None
            function = _current_callsite_function_8616(self.project, self.func_addr) if isinstance(self.func_addr, int) else None
            instruction_summaries = []
            if function is not None:
                with contextlib.suppress(Exception):
                    instruction_summaries = list(_function_instruction_summaries_8616(self.project, function))
            synthetic_globals = getattr(self.codegen, "_inertia_synthetic_globals", None)
            if not isinstance(synthetic_globals, dict):
                synthetic_globals = getattr(self.project, "_inertia_synthetic_globals", None)
            direct_global_arg_refs = _merge_direct_global_symbol_refs_8616(
                _collect_direct_global_symbol_refs_8616(cod_metadata, instruction_summaries),
                _collect_synthetic_direct_global_symbol_refs_8616(synthetic_globals, instruction_summaries),
            )
            self.direct_global_arg_refs_by_offset = {
                (ref.offset & 0xFFFF, int(ref.width or 0)): ref for ref in direct_global_arg_refs if int(ref.width or 0) > 0
            }

    def _run_summary_prep(self, fixed_probe_changed: bool, signature: StructuredAstValue) -> bool | None:
        """Build summary maps and refuse when no live summarized call remains."""
        summary_map_raw = getattr(self.codegen, "_inertia_callsite_summaries", None)
        self.summary_map: dict[int, CallsiteSummary8616] = (
            {
                key: value
                for key, value in summary_map_raw.items()
                if isinstance(key, int) and isinstance(value, CallsiteSummary8616)
            }
            if isinstance(summary_map_raw, dict)
            else {}
        )
        self.summary_by_callsite_addr: dict[int, CallsiteSummary8616] = {
            int(callsite_addr): _summary
            for _summary in tuple(self.summary_map.values())
            if isinstance((callsite_addr := _summary.callsite_addr), int)
        }
        _refresh_callsite_summary_node_ids_8616(self.codegen, self.summary_map)
        if self.summary_map and not _has_live_summarized_call_8616(_structured_root_8616(self.cfunc), self.summary_map):
            _set_callsite_materialization_decision_8616(
                self.codegen,
                CallsiteMaterializationDecision8616.REFUSED_NO_LIVE_SUMMARIZED_CALL,
                changed=fixed_probe_changed,
                signature=signature,
            )
            return fixed_probe_changed
        return None

    def _run_evidence_and_controls(self) -> tuple[bool, bool, bool]:
        """Census push-arg evidence, stack-probe flags, and materialization controls."""
        self.caller_stack_objects = tuple(
            CallerStackObject8616(variable.offset, variable.size)
            for cvar in _boundary_tuple_8616(getattr(self.cfunc, "arg_list", ()) or ())
            if isinstance(cvar, structured_c.CVariable)
            for variable in (cvar.variable,)
            if isinstance(variable, SimStackVariable)
            and isinstance(variable.offset, int)
            and isinstance(variable.size, int)
            and variable.offset >= 4
            and variable.size > 0
        )
        self.logical_shape_evidence_by_callsite: dict[int, LogicalArgumentShapeEvidence8616] = {}
        has_push_arg_evidence = False
        for _summary in self.summary_map.values():
            push_sources = _summary.push_arg_sources
            if isinstance(push_sources, tuple) and any(source is not None for source in push_sources):
                has_push_arg_evidence = True
                break
        self.stats = _ensure_callsite_materialization_stats_8616(self.codegen)
        if has_push_arg_evidence:
            self.stats.has_push_arg_evidence_count += 1
        else:
            self.stats.no_push_arg_evidence_count += 1
        with span(
            "x86_16.call_args.prepare_summaries",
            function=self.func_addr if isinstance(self.func_addr, int) else None,
            summaries=len(self.summary_map),
        ):
            self.typed_stack_probe_facts = build_typed_stack_probe_return_facts_8616(self.codegen)
            record_callsite_summary_map_facts_8616(self.codegen, cast(Mapping[object, object], self.summary_map))
        self.stats = _ensure_callsite_materialization_stats_8616(self.codegen)
        has_recoverable_stack_probe, self.has_unverified_non_ss_stack_probe = _stack_probe_summary_flags_8616(
            self.summary_map, self.typed_stack_probe_facts
        )
        self.function_scope_typed_stack_probe_fact = None
        if not self.has_unverified_non_ss_stack_probe:
            function_scope_stack_probe_facts = _boundary_tuple_8616(
                fact for fact in self.typed_stack_probe_facts.values() if fact.segment_space == "ss"
            )
            if len(function_scope_stack_probe_facts) == 1:
                self.function_scope_typed_stack_probe_fact = function_scope_stack_probe_facts[0]
        conservative_materialization, self.prune_consumed_arg_stores = _call_arg_materialization_mode_flags_8616(
            has_recoverable_stack_probe
        )
        materialization_controls = _ensure_callsite_materialization_controls_8616(self.codegen)
        if materialization_controls._inertia_callsite_disable_consumed_arg_store_prune_8616:
            self.prune_consumed_arg_stores = False
            materialization_controls._inertia_callsite_consumed_arg_store_prune_refused_by_context_8616 += 1
        disable_stack_probe_setup_prune = (
            materialization_controls._inertia_callsite_disable_stack_probe_setup_prune_8616
        )
        if disable_stack_probe_setup_prune:
            materialization_controls._inertia_callsite_stack_probe_setup_prune_refused_by_context_8616 += 1
        regen_replay_preserve_materialized_stack = (
            materialization_controls._inertia_callsite_arg_regen_replay_active_8616
            and materialization_controls._inertia_postprocess_changed
        )
        if regen_replay_preserve_materialized_stack:
            conservative_materialization = True
            self.prune_consumed_arg_stores = False
            materialization_controls._inertia_callsite_regen_replay_conservative_no_prune_8616 += 1
        if conservative_materialization and has_push_arg_evidence and not regen_replay_preserve_materialized_stack:
            conservative_materialization = False
        self.materialized_callsite_metadata_ids: dict[int, tuple[int, ...]] = {}
        self.synthetic_stack_cvars: dict[int, structured_c.CVariable] = {}
        self.return_call_exprs_by_callsite: dict[int, StructuredAstValue] = dict(
            materialization_controls._inertia_callsite_return_exprs_8616
        )
        self.rewritten_block_ids: set[int] = set()
        self.consumed_stale_return_alias_statement_ids: set[int] = set()
        self.fnptr_typed_stack_offsets_cache_8616: frozenset[int] | None = None
        self.fnptr_store_evidence_cache_8616: dict[int, list[tuple[int, StructuredAstValue]]] | None = None
        self.statement_contains_call_cache: dict[int, bool] = {}
        self.expr_dirty_carrier_cache: dict[int, bool] = {}
        self.rhs_safe_pre_call_setup_cache: dict[int, bool] = {}
        return has_push_arg_evidence, conservative_materialization, disable_stack_probe_setup_prune

    def _run_rewrite_root(
        self,
        root: StructuredAstValue,
        *,
        disable_stack_probe_setup_prune: bool,
        conservative_materialization: bool,
        has_push_arg_evidence: bool,
    ) -> None:
        """Rewrite the structured root blocks and run the post-rewrite prune passes."""
        if not conservative_materialization:
            with span(
                "x86_16.call_args.rewrite_blocks",
                function=self.func_addr if isinstance(self.func_addr, int) else None,
                statements=len(getattr(root, "statements", ()) or ()),
            ):
                self._rewrite_block(
                    root,
                    allow_setup_assignment_prune=not disable_stack_probe_setup_prune,
                )
        elif has_push_arg_evidence:
            with span(
                "x86_16.call_args.conservative_seed_initial",
                function=self.func_addr if isinstance(self.func_addr, int) else None,
            ):
                self.changed |= _conservative_call_arg_seed_8616(
                    root=root,
                    summary_map=self.summary_map,
                    codegen=self.codegen,
                    has_unverified_non_ss_stack_probe=self.has_unverified_non_ss_stack_probe,
                    call_name_fn=_call_node_name_8616,
                    expected_arg_count_fn=_expected_arg_count_for_known_callee_8616,
                    known_default_args_fn=_known_default_args_for_missing_8616,
                    direct_expr_from_push_source_fn=self._direct_expr_from_push_source_8616,
                    normalize_materialized_call_args_fn=self._normalize_materialized_call_args,
                    all_arg_exprs_are_non_segment_registers_fn=self._all_arg_exprs_are_non_segment_registers,
                    set_materialized_call_args_fn=self._set_materialized_call_args,
                    refresh_summary_arg_shape_fn=self._refresh_summary_arg_shape,
                    call_args_need_rematerialization_fn=self._call_args_need_rematerialization_8616,
                )
                self.changed |= _seed_empty_known_helper_calls_8616(
                    root=root,
                    summary_map=self.summary_map,
                    codegen=self.codegen,
                    has_unverified_non_ss_stack_probe=self.has_unverified_non_ss_stack_probe,
                    call_name_fn=_call_node_name_8616,
                    expected_arg_count_fn=_expected_arg_count_for_known_callee_8616,
                    known_default_args_fn=_known_default_args_for_missing_8616,
                    direct_expr_from_push_source_fn=self._direct_expr_from_push_source_8616,
                    set_materialized_call_args_fn=self._set_materialized_call_args,
                    refresh_summary_arg_shape_fn=self._refresh_summary_arg_shape,
                )
        with span("x86_16.call_args.clear_zero_arg_helpers"):
            zero_arg_helpers_changed = _clear_zero_arg_known_helper_args_8616(
                root=root,
                summary_map=self.summary_map,
                call_name_fn=_call_node_name_8616,
                expected_arg_count_fn=_expected_arg_count_for_known_callee_8616,
                set_materialized_call_args_fn=self._set_materialized_call_args,
                refresh_summary_arg_shape_fn=self._refresh_summary_arg_shape,
            )
            self.changed |= zero_arg_helpers_changed
        with span("x86_16.call_args.conservative_seed_final"):
            if zero_arg_helpers_changed or _has_callsite_arg_materialization_gap_8616(
                root, self.summary_map, project=self.project
            ) or has_call_argument_semantic_gap_8616(
                root, self.summary_map, self._call_args_need_rematerialization_8616,
            ):
                self.changed |= _conservative_call_arg_seed_8616(
                    root=root,
                    summary_map=self.summary_map,
                    codegen=self.codegen,
                    has_unverified_non_ss_stack_probe=self.has_unverified_non_ss_stack_probe,
                    call_name_fn=_call_node_name_8616,
                    expected_arg_count_fn=_expected_arg_count_for_known_callee_8616,
                    known_default_args_fn=_known_default_args_for_missing_8616,
                    direct_expr_from_push_source_fn=self._direct_expr_from_push_source_8616,
                    normalize_materialized_call_args_fn=self._normalize_materialized_call_args,
                    all_arg_exprs_are_non_segment_registers_fn=self._all_arg_exprs_are_non_segment_registers,
                    set_materialized_call_args_fn=self._set_materialized_call_args,
                    refresh_summary_arg_shape_fn=self._refresh_summary_arg_shape,
                    call_args_need_rematerialization_fn=self._call_args_need_rematerialization_8616,
                )
        with span("x86_16.call_args.restore_protected"):
            if self._restore_protected_call_args_8616(root):
                self.changed = True
        root_statements = getattr(root, "statements", None)
        if isinstance(root_statements, list) and self._fold_dx_ax_return_pair_assignments_8616(root_statements):
            self.changed = True
        summarized_calls = tuple(
            node
            for node in (root, *_iter_c_nodes_deep_8616(root))
            if isinstance(node, CFunctionCall)
            and id(node) in self.summary_map
        )
        # Types/Lowering must publish the final live argument shape even when
        # the AST already held the correct arguments before this pass. Branch-
        # local refreshes alone miss those stable calls and leave downstream
        # declaration lowering with only the physical PUSH count.
        for summarized_call in summarized_calls:
            self._refresh_summary_arg_shape(
                summarized_call,
                self.summary_map[id(summarized_call)],
            )
        # Regenerated third-party C nodes acquire their final exact projection
        # tags only after callsite summaries have been attached. Replay the
        # Lowering-owned consumer at that boundary; it owns all proof and
        # refuses non-frame or ambiguous producer ancestry.
        self.codegen._inertia_callsite_summaries = self.summary_map
        if _replay_call_return_frame_argument_lowerer_8616(self.project, self.codegen):
            self.changed = True
        if prune_materialized_call_push_stack_assignments_8616(
            self.project,
            self.codegen,
        ):
            self.changed = True
        summary_inventory = _callsite_summary_inventory_8616(self.codegen)
        return_frame_summaries = (
            tuple(summary_inventory.values())
            if summary_inventory
            else tuple(self.summary_map[id(call)] for call in summarized_calls)
        )
        return_addr_by_callsite = {
            summary.callsite_addr: summary.return_addr
            for summary in return_frame_summaries
            if summary.return_addr is not None
        }
        if prune_call_return_frame_stack_assignments_8616(
            self.project,
            self.codegen,
            return_addr_by_callsite,
        ):
            self.changed = True

    def _run_publish(self, root: StructuredAstValue, selector_materialized_before: int) -> bool:
        """Sync the structured root and publish materialization decision metadata."""
        if self.changed:
            with span("x86_16.call_args.sync_root"):
                _sync_cfunc_root_statements_8616(self.cfunc, root, getattr(root, "statements", None))
            with span("x86_16.call_args.record_gaps"):
                _record_unmaterialized_callsite_arg_gaps_8616(
                    root=root,
                    summary_map=self.summary_map,
                    codegen=self.codegen,
                )
        self.codegen._inertia_materialized_callsite_metadata_ids = self.materialized_callsite_metadata_ids
        self.codegen._inertia_callsite_summaries = self.summary_map
        if int(getattr(self.codegen, "_inertia_call_return_switch_selector_materialized_8616", 0) or 0) > selector_materialized_before:
            self.changed = True
        with span("x86_16.call_args.prune_segment_metadata"):
            if prune_materialized_callsite_segment_metadata_8616(self.project, self.codegen):
                self.changed = True
        _set_callsite_materialization_decision_8616(
            self.codegen,
            CallsiteMaterializationDecision8616.PROCESSED_CHANGED
            if self.changed
            else CallsiteMaterializationDecision8616.PROCESSED_NO_CHANGE,
            changed=self.changed,
            signature=_callsite_materialization_signature_8616(self.codegen),
        )
        return self.changed

    def _seg_helper_arg_width_8616(self, node: StructuredAstValue) -> int | None:
        """Return the byte width implied by a SEG_U8/U16/U32 helper call."""
        if not isinstance(node, CFunctionCall):
            return None
        helper_name = node.callee_target
        if not isinstance(helper_name, str):
            return None
        return {"SEG_U8": 1, "SEG_U16": 2, "SEG_U32": 4}.get(helper_name.upper())

    def _arg_width_from_type_bits_8616(self, type_: StructuredAstValue) -> int | None:
        """Derive a byte width from a type's bit size under the project arch."""
        bits = _safe_type_size_bits_8616(type_, getattr(self.codegen, "project", None))
        arch = getattr(getattr(self.codegen, "project", None), "arch", None)
        byte_width = getattr(arch, "byte_width", None)
        if isinstance(bits, int) and bits > 0 and isinstance(byte_width, int) and byte_width > 0:
            return max(bits // byte_width, 1)
        return None

    def _arg_width_from_expr(self, expr: StructuredAstValue) -> int:
        node = expr
        if isinstance(node, CTypeCast):
            cast_type = getattr(node, "type", None) or getattr(node, "dst_type", None)
            cast_width = self._arg_width_from_type_bits_8616(cast_type)
            if cast_width is not None:
                return cast_width
        while isinstance(node, CTypeCast):
            node = node.expr
        seg_helper_width = self._seg_helper_arg_width_8616(node)
        if seg_helper_width is not None:
            return seg_helper_width
        width = self._arg_width_from_type_bits_8616(getattr(node, "type", None))
        if width is not None:
            return width
        variable = getattr(node, "variable", None)
        size = getattr(variable, "size", None)
        if isinstance(size, int) and size > 0:
            return size
        return 2

    def _canonical_segment_register_name_8616(self, name: StructuredAstValue) -> str | None:
        if not isinstance(name, str):
            return None
        base = name.strip().lower().split("#", 1)[0]
        return base if base in {"cs", "ds", "es", "ss"} else None

    def _segment_register_name_from_expr_8616(self, expr: StructuredAstValue) -> str | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        canonical_name = self._canonical_segment_register_name_8616(name)
        if canonical_name is not None:
            return canonical_name
        if isinstance(variable, SimRegisterVariable):
            reg = variable.reg
            reg_name = getattr(getattr(self.project, "arch", None), "register_names", {}).get(reg)
            canonical_reg_name = self._canonical_segment_register_name_8616(reg_name)
            if canonical_reg_name is not None:
                return canonical_reg_name
        return None

    def _is_segment_register_value_expr(self, expr: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CBinaryOp) and node.op in {"Shr", "Shl", "And", "Or"}:
            return self._is_segment_register_value_expr(node.lhs)
        return self._segment_register_name_from_expr_8616(node) is not None

    def _is_call_arg_count_evidence_tuple(self, source: StructuredAstValue) -> bool:
        if not isinstance(source, tuple) or len(source) < 2:
            return False
        if source[0] not in {
            "bp",
            "bp_addr",
            "bp_index_addr",
            "global",
            "global_index",
            "seg_indirect",
            "imm",
            "expr",
            "ret_reg",
            "reg",
            "seg",
            "sp",
            "ss",
            "ds",
            "cs",
            "es",
            "dx",
            "ax",
            "bx",
            "cx",
            "di",
            "si",
        }:
            return False
        if source[0] == "reg":
            return isinstance(source[1], str) and source[1].lower() in {
                "ax",
                "bx",
                "cx",
                "dx",
                "si",
                "di",
            }
        if source[0] == "seg":
            return isinstance(source[1], str) and source[1].lower() in {"cs", "ds", "es", "ss"}
        if source[0] == "bp_index_addr":
            return (
                len(source) >= 4
                and isinstance(source[1], int)
                and isinstance(source[2], str)
                and isinstance(source[3], int)
                and (len(source) == 4 or (len(source) == 5 and self._is_call_arg_count_evidence_tuple(source[4])))
            )
        if source[0] == "expr":


            return (
                len(source) == 3
                and isinstance(source[1], tuple)
                and self._is_call_arg_count_evidence_tuple(source[1])
                and isinstance(source[2], tuple)
                and all(self._expr_op_is_valid(op) for op in source[2])
            )
        if source[0] == "global_index":
            return (
                len(source) == 5
                and isinstance(source[1], int)
                and isinstance(source[2], int)
                and source[2] in {1, 2, 4}
                and isinstance(source[3], tuple)
                and self._is_call_arg_count_evidence_tuple(source[3])
                and isinstance(source[4], tuple)
                and all(
                    isinstance(op, tuple)
                    and len(op) == 2
                    and op[0]
                    in {
                        CallsitePushExprOp8616.ADD.value,
                        CallsitePushExprOp8616.SUB.value,
                        CallsitePushExprOp8616.AND.value,
                        CallsitePushExprOp8616.OR.value,
                        CallsitePushExprOp8616.XOR.value,
                        CallsitePushExprOp8616.SHL.value,
                        CallsitePushExprOp8616.SHR.value,
                        CallsitePushExprOp8616.SAR.value,
                        CallsitePushExprOp8616.NEG.value,
                        CallsitePushExprOp8616.MUL.value,
                    }
                    and isinstance(op[1], int)
                    for op in source[4]
                )
            )
        if source[0] == "seg_indirect":
            return (
                len(source) == 4
                and isinstance(source[1], str)
                and source[1] in {"cs", "ds", "es", "ss"}
                and isinstance(source[2], int)
                and source[2] in {1, 2, 4}
                and isinstance(source[3], tuple)
                and self._is_call_arg_count_evidence_tuple(source[3])
            )
        return isinstance(source[1], int)

    def _fallback_call_arg_count_8616(self,
        *,
        expected_arg_count: int | None,
        push_arg_sources: tuple[StructuredAstValue, ...],
    ) -> int | None:
        if isinstance(expected_arg_count, int):
            return expected_arg_count
        if (
            isinstance(push_arg_sources, tuple)
            and push_arg_sources
            and all(self._is_call_arg_count_evidence_tuple(source) for source in push_arg_sources)
        ):
            return len(push_arg_sources)
        return 1

    def _all_arg_exprs_are_non_segment_registers(self, args: StructuredAstValue) -> bool:
        return bool(args) and all(not self._is_segment_register_value_expr(arg) for arg in args)

    def _is_plain_register_value_expr(self, expr: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = node.variable
        if not isinstance(variable, SimRegisterVariable):
            return False
        return not self._is_segment_register_value_expr(node)

    def _plain_register_expr_key(self, expr: StructuredAstValue) -> StructuredAstValue:
        if not self._is_plain_register_value_expr(expr):
            return None
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        if variable is None:
            return None
        return (
            getattr(variable, "reg", None),
            getattr(variable, "size", None),
        )

    def _outgoing_stack_value_expr_key(self, expr: StructuredAstValue) -> StructuredAstValue:
        """Return the machine-BP identity of an outgoing call-stack carrier."""
        if not self._is_outgoing_stack_value_carrier_expr(expr):
            return None
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        offset = outgoing_call_stack_carrier_offset_8616(self.codegen, node)
        if offset is None:
            return None
        cvar = cast(structured_c.CVariable, node)
        variable = cast(SimStackVariable, cvar.variable)
        return (
            offset,
            variable.size,
            variable.base,
            variable.name or cvar.name,
        )

    def _value_expr_key(self, expr: StructuredAstValue) -> StructuredAstValue:
        return self._plain_register_expr_key(expr) or self._outgoing_stack_value_expr_key(expr)

    def _same_value_carrier_identity_expr(self, expr_a: StructuredAstValue, expr_b: StructuredAstValue) -> bool:
        node_a = expr_a
        while isinstance(node_a, CTypeCast):
            node_a = node_a.expr
        node_b = expr_b
        while isinstance(node_b, CTypeCast):
            node_b = node_b.expr
        if not isinstance(node_a, structured_c.CVariable) or not isinstance(node_b, structured_c.CVariable):
            return False
        key_a = self._value_expr_key(node_a)
        key_b = self._value_expr_key(node_b)
        if key_a is None or key_b is None or key_a != key_b:
            return False
        var_a = getattr(node_a, "variable", None)
        var_b = getattr(node_b, "variable", None)
        name_a = getattr(var_a, "name", None) or getattr(node_a, "name", None)
        name_b = getattr(var_b, "name", None) or getattr(node_b, "name", None)
        return name_a == name_b

    def _is_outgoing_stack_value_carrier_expr(self, expr: StructuredAstValue) -> bool:
        """Use Lowering's machine-BP projection to identify outgoing carriers."""
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        return outgoing_call_stack_carrier_offset_8616(self.codegen, node) is not None

    def _is_c_ast_node(self, value: StructuredAstValue) -> bool:
        return type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen")

    def _clone_c_ast_tree(self,
        node: StructuredAstValue, memo: dict[int, StructuredAstValue] | None = None
    ) -> StructuredAstValue:
        if not self._is_c_ast_node(node):
            return node
        if memo is None:
            memo = {}
        marker = id(node)
        existing = memo.get(marker)
        if existing is not None:
            return existing
        cloned = copy(node)
        memo[marker] = cloned
        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "variable",
            "index",
        ):
            if not hasattr(cloned, attr):
                continue
            value = getattr(cloned, attr, None)
            if self._is_c_ast_node(value):
                setattr(cloned, attr, self._clone_c_ast_tree(value, memo))
        for attr in ("args", "operands"):
            if not hasattr(cloned, attr):
                continue
            items = getattr(cloned, attr, None)
            if not isinstance(items, (list, tuple)):
                continue
            rebuilt = [self._clone_c_ast_tree(item, memo) if self._is_c_ast_node(item) else item for item in items]
            setattr(cloned, attr, tuple(rebuilt) if isinstance(items, tuple) else rebuilt)
        return cloned

    def _c_ast_count_walk_8616(self, current: StructuredAstValue, seen: set[int], limit: int) -> int:
        """Count descendant AST nodes bounded by limit."""
        if not self._is_c_ast_node(current):
            return 0
        marker = id(current)
        if marker in seen:
            return 0
        seen.add(marker)
        total = 1
        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "index",
        ):
            if total > limit or not hasattr(current, attr):
                continue
            total += self._c_ast_count_walk_8616(getattr(current, attr, None), seen, limit)
        for attr in ("args", "operands"):
            if total > limit or not hasattr(current, attr):
                continue
            items = getattr(current, attr, None)
            if not isinstance(items, (list, tuple)):
                continue
            for item in items:
                total += self._c_ast_count_walk_8616(item, seen, limit)
                if total > limit:
                    break
        return total

    def _c_ast_node_count_limited(self, node: StructuredAstValue, *, limit: int = 128) -> int:
        seen: set[int] = set()
        return self._c_ast_count_walk_8616(node, seen, limit)

    def _c_ast_contains_identity_8616(self,
        node: StructuredAstValue, target: StructuredAstValue, *, max_nodes: int = 2048
    ) -> bool:
        target_id = id(target)
        stack = [node]
        seen: set[int] = set()
        visited = 0
        while stack:
            current = stack.pop()
            if current is None:
                continue
            while isinstance(current, CTypeCast):
                current = current.expr
            if not self._is_c_ast_node(current):
                continue
            marker = id(current)
            if marker == target_id:
                return True
            if marker in seen:
                continue
            seen.add(marker)
            visited += 1
            if visited > max_nodes:
                return True
            stack.extend(self._c_ast_child_nodes_8616(current))
        return False

    def _c_ast_child_nodes_8616(self, current: StructuredAstValue) -> Iterator[StructuredAstValue]:
        """Yield the direct structured-C child nodes of a node."""
        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "body",
            "retval",
            "variable",
            "index",
        ):
            child = getattr(current, attr, None)
            if child is not None:
                yield child
        for attr in ("args", "operands", "statements"):
            items = getattr(current, attr, None)
            if isinstance(items, (list, tuple)):
                yield from (item for item in items if item is not None)

    def _c_ast_has_cycle_or_too_complex_8616(self,
        node: StructuredAstValue, *, max_nodes: int = 4096, max_depth: int = 256
    ) -> bool:
        active: set[int] = set()
        complete: set[int] = set()
        visited = 0


        def _walk(current: StructuredAstValue, depth: int) -> bool:
            nonlocal visited
            while isinstance(current, CTypeCast):
                current = current.expr
            if not self._is_c_ast_node(current):
                return False
            marker = id(current)
            if marker in active:
                return True
            if marker in complete:
                return False
            if depth > max_depth:
                return True
            active.add(marker)
            visited += 1
            if visited > max_nodes:
                active.discard(marker)
                return True
            for child in self._children(current):
                if _walk(child, depth + 1):
                    return True
            active.discard(marker)
            complete.add(marker)
            return False

        return _walk(node, 0)

    def _resolve_recent_value_assignment(self,
        expr: StructuredAstValue, statements_prefix: list[StructuredAstValue]
    ) -> StructuredAstValue:
        if not (self._is_plain_register_value_expr(expr) or self._is_outgoing_stack_value_carrier_expr(expr)):
            return expr, len(statements_prefix)
        expr_value_key = self._value_expr_key(expr)
        for stmt_idx in range(len(statements_prefix) - 1, -1, -1):
            stmt = statements_prefix[stmt_idx]
            for assignment in reversed(self._iter_assignment_nodes(stmt)):
                lhs, rhs = self._assignment_lhs_rhs(assignment)
                if lhs is None or rhs is None:
                    continue
                lhs_value_key = self._value_expr_key(lhs)
                if not _same_c_expression_8616(lhs, expr) and not (
                    expr_value_key is not None and lhs_value_key is not None and lhs_value_key == expr_value_key
                ):
                    continue
                if self._assignment_lhs_writes_memory(lhs) or self._is_segment_register_value_expr(rhs):
                    return None, stmt_idx
                if self._same_value_carrier_identity_expr(rhs, expr):
                    return None, stmt_idx
                return rhs, stmt_idx
        return None, None

    def _expr_contains_plain_register_uses(self, expr: StructuredAstValue, *, max_nodes: int = 1024) -> bool:
        stack = [expr]
        seen: set[int] = set()
        visited = 0
        while stack:
            node = stack.pop()
            if node is None:
                continue
            while isinstance(node, CTypeCast):
                node = node.expr
            marker = id(node)
            if marker in seen:
                continue
            seen.add(marker)
            visited += 1
            if visited > max_nodes:
                return True
            if self._is_plain_register_value_expr(node) or self._is_outgoing_stack_value_carrier_expr(node):
                return True
            stack.extend(self._expr_plain_use_children_8616(node))
        return False

    def _expr_plain_use_children_8616(self, node: StructuredAstValue) -> Iterator[StructuredAstValue]:
        """Yield child nodes in the plain-register-use traversal order."""
        for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
            child = getattr(node, attr, None)
            if child is not None:
                yield child
        for attr in ("args", "operands"):
            items = getattr(node, attr, None)
            if isinstance(items, (list, tuple)):
                yield from (item for item in items if item is not None)

    def _register_carrier_transform_8616(self, node: StructuredAstValue, statements_prefix: list[StructuredAstValue], seen_keys: set[StructuredAstValue], failed: list[bool]) -> StructuredAstValue:
        if failed[0] or not (self._is_plain_register_value_expr(node) or self._is_outgoing_stack_value_carrier_expr(node)):
            return node
        key = self._value_expr_key(node)
        scoped_key = (key, len(statements_prefix)) if key is not None else None
        if scoped_key is not None and scoped_key in seen_keys:
            failed[0] = True
            return node
        resolved, resolved_stmt_idx = self._resolve_recent_value_assignment(node, statements_prefix)
        if resolved is None:
            failed[0] = True
            return node
        next_seen = set(seen_keys)
        current_prefix_len = len(statements_prefix)
        next_prefix = (
            statements_prefix[:resolved_stmt_idx]
            if isinstance(resolved_stmt_idx, int) and resolved_stmt_idx >= 0
            else statements_prefix
        )
        if key is not None:
            # Guard only against revisiting the same register identity at the
            # same search horizon. When the horizon shrinks, we still want to
            # walk earlier same-register carriers (ax_9 -> ax_7 -> iParent).
            next_seen.add((key, current_prefix_len))
        resolved = self._resolve_register_carriers_in_expr(resolved, next_prefix, next_seen)
        if resolved is None or self._expr_contains_plain_register_uses(resolved):
            failed[0] = True
            return node
        return self._clone_c_ast_tree(resolved)

    def _resolve_register_carriers_in_expr(self,
        expr: StructuredAstValue,
        statements_prefix: list[StructuredAstValue],
        seen_keys: set[StructuredAstValue] | None = None,
    ) -> StructuredAstValue:
        if self._c_ast_node_count_limited(expr, limit=512) > 512:
            self.codegen._inertia_call_arg_register_resolution_refused_complex_8616 = (
                int(getattr(self.codegen, "_inertia_call_arg_register_resolution_refused_complex_8616", 0) or 0) + 1
            )
            return None
        if not self._expr_contains_plain_register_uses(expr):
            return expr

        if seen_keys is None:
            seen_keys = set()
        rewritten = self._clone_c_ast_tree(expr)
        failed = [False]

        def transform(node: StructuredAstValue) -> StructuredAstValue:
            return self._register_carrier_transform_8616(node, statements_prefix, seen_keys, failed)

        new_root = transform(rewritten)
        if new_root is not rewritten:
            rewritten = new_root
        if failed[0]:
            return None
        _replace_c_children_8616(rewritten, transform)
        if failed[0] or self._expr_contains_plain_register_uses(rewritten):
            return None
        return rewritten

    def _stack_slot_fallback_name(self, offset: int) -> str:
        if offset >= 0:
            slot_index = max(offset // 2, 1)
            return f"arg_{slot_index}"
        slot_index = max(((-offset) + 1) // 2, 1)
        return f"local_{slot_index}"

    def _known_positive_bp_arg_offset_8616(self, offset: int) -> bool:
        if not isinstance(offset, int) or offset <= 0:
            return False
        cfunc_obj = getattr(self.codegen, "cfunc", None)
        for arg in _boundary_tuple_8616(getattr(cfunc_obj, "arg_list", ()) or ()):
            arg_variable = getattr(arg, "variable", None)
            if not isinstance(arg_variable, SimStackVariable):
                continue
            if arg_variable.base != "bp":
                continue
            arg_offset = arg_variable.offset
            if isinstance(arg_offset, int) and arg_offset == offset:
                return True
        return False

    def _materialize_fallback_stack_name_8616(self, offset: int, preferred_name: str | None = None) -> str:
        fallback_name = (
            preferred_name if isinstance(preferred_name, str) and preferred_name else self._stack_slot_fallback_name(offset)
        )
        if offset >= 0 and fallback_name.startswith("arg_") and not self._known_positive_bp_arg_offset_8616(offset):
            slot_index = max(offset // 2, 1)
            return f"local_{slot_index}"
        return fallback_name

    def _stack_name_preference(self, name: str | None) -> int:
        if not isinstance(name, str) or not name:
            return 0
        if name.startswith(("vvar_", "tmp_", "ir_", "s_", "stack_bp_", "stack_sp_")):
            return 1
        if name.startswith(("local_", "arg_")):
            return 3
        return 4

    def _iter_stack_cvar_candidates(self) -> StructuredAstValue:
        yield from iter_stack_cvariable_candidates_8616(self.codegen, self.synthetic_stack_cvars)

    def _existing_containing_stack_cvar_8616(self, offset: int, *, size_hint: int = 1) -> StructuredAstValue:
        cvar = containing_stack_cvariable_8616(
            self.codegen,
            self.synthetic_stack_cvars,
            offset=offset,
            size_hint=size_hint,
        )
        return self._clone_c_ast_tree(cvar) if cvar is not None else None

    def _stack_cvar_match_score_8616(
        self, cvar: StructuredAstValue, offset: int, size_hint: int
    ) -> tuple[int, int, int, int, int, int] | None:
        """Score a stack cvar candidate for containing/matching the offset."""
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        base_offset = variable.offset
        size = variable.size
        if not isinstance(base_offset, int) or not isinstance(size, int) or size <= 0:
            return None
        relation = 0
        if base_offset == offset:
            relation = 4
        elif base_offset <= offset < base_offset + size:
            relation = 3
        elif abs(base_offset - offset) == 1:
            relation = 2
        if relation == 0:
            return None
        name = variable.name or getattr(cvar, "name", None)
        name_pref = self._stack_name_preference(name)
        return (
            1 if name_pref >= 3 else 0,
            relation,
            name_pref,
            1 if isinstance(size_hint, int) and size >= size_hint else 0,
            size,
            -abs(base_offset - offset),
        )

    def _best_matching_stack_cvar_8616(
        self, offset: int, size_hint: int
    ) -> StructuredAstValue | None:
        """Pick the best-scoring stack cvar candidate for the offset."""
        best = None
        best_score: tuple[int, int, int, int, int, int] | None = None
        for cvar in self._iter_stack_cvar_candidates():
            candidate_score = self._stack_cvar_match_score_8616(cvar, offset, size_hint)
            if candidate_score is not None and (best_score is None or candidate_score > best_score):
                best = cvar
                best_score = candidate_score
        return best

    def _register_synthetic_stack_cvar_8616(
        self,
        name: str,
        variable_type: StructuredAstValue,
        *,
        offset: int,
        size_hint: int,
    ) -> StructuredAstValue | None:
        """Materialize and register a synthetic stack cvar for the offset."""
        cvar = materialize_call_argument_stack_cvariable_8616(
            self.codegen,
            self.synthetic_stack_cvars,
            machine_bp_offset=offset,
            size_hint=max(size_hint, 1),
            preferred_name=name,
        )
        if not isinstance(cvar, structured_c.CVariable):
            return None
        variable = cvar.variable
        bound_variable_type = variable_type or _word_type_8616(self.project)
        if variable.name != name:
            variable.name = name
        if cvar.variable_type is None:
            cvar.variable_type = bound_variable_type
        self.synthetic_stack_cvars[offset] = cvar
        variables_in_use = getattr(getattr(self.codegen, "cfunc", None), "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar
        unified_locals = getattr(getattr(self.codegen, "cfunc", None), "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            unified_locals[variable] = {(cvar, getattr(cvar, "variable_type", None))}
        return cvar

    def _stack_cvar_for_offset(self,
        offset: int, *, size_hint: int = 2, allow_best_match: bool = True
    ) -> StructuredAstValue | None:
        existing_synthetic = self.synthetic_stack_cvars.get(offset)
        if existing_synthetic is not None:
            return self._clone_c_ast_tree(existing_synthetic)

        proven_object = containing_stack_cvariable_8616(
            self.codegen,
            self.synthetic_stack_cvars,
            offset=offset,
            size_hint=max(size_hint, 1),
        )
        if proven_object is not None:
            return self._clone_c_ast_tree(proven_object)

        best = (
            self._best_matching_stack_cvar_8616(offset, size_hint) if allow_best_match else None
        )

        if best is not None:
            best_name = getattr(getattr(best, "variable", None), "name", None) or getattr(best, "name", None)
            if self._stack_name_preference(best_name) <= 1:
                return self._clone_c_ast_tree(
                    self._register_synthetic_stack_cvar_8616(
                        self._materialize_fallback_stack_name_8616(offset),
                        getattr(best, "variable_type", None) or _word_type_8616(self.project),
                        offset=offset,
                        size_hint=size_hint,
                    )
                )
            return self._clone_c_ast_tree(best)

        return self._clone_c_ast_tree(
            self._register_synthetic_stack_cvar_8616(
                self._materialize_fallback_stack_name_8616(offset),
                _word_type_8616(self.project),
                offset=offset,
                size_hint=size_hint,
            )
        )

    def _sanitize_exact_negative_bp_call_arg_cvar_8616(self, expr: StructuredAstValue, offset: int) -> StructuredAstValue:
        """Clear a stale display identity only for the already-proven BP slot."""
        if offset >= 0 or not isinstance(expr, structured_c.CVariable):
            return expr
        variable = expr.variable
        if not isinstance(variable, SimStackVariable):
            return expr
        if variable.base != "bp" or call_argument_stack_variable_offset_8616(self.codegen, expr) != offset:
            return expr
        unified = expr.unified_variable
        if unified is None:
            return expr
        # The callsite summary already proves the exact BP local offset.
        # Do not let a renderer-level unified name override that storage
        # identity; stale unifications have been observed to map BP-44 to
        # the BP+4 argument name.
        expr.unified_variable = None
        return expr

    def _set_variables_in_use_type_8616(
        self, variables: dict[StructuredAstValue, StructuredAstValue], offset: int, variable_type: StructuredAstValue
    ) -> bool:
        """Update cvar variable_type for stack variables at the offset."""
        changed_type = False
        for variable, cvar in variables.items():
            if not isinstance(variable, SimStackVariable):
                continue
            if variable.offset != offset:
                continue
            if getattr(cvar, "variable_type", None) != variable_type:
                cvar.variable_type = variable_type
                changed_type = True
        return changed_type

    def _set_unified_local_slot_type_8616(
        self, unified: dict[StructuredAstValue, StructuredAstValue], offset: int, variable_type: StructuredAstValue
    ) -> bool:
        """Update unified local entries for stack variables at the offset."""
        changed_type = False
        for variable, entries in list(unified.items()):
            if not isinstance(variable, SimStackVariable) or getattr(variable, "offset", None) != offset:
                continue
            new_entries = set()
            for cvar, _old_type in entries:
                if getattr(cvar, "variable_type", None) != variable_type:
                    cvar.variable_type = variable_type
                    changed_type = True
                new_entries.add((cvar, variable_type))
            unified[variable] = new_entries
        return changed_type

    def _set_ast_stack_slot_type_8616(self, cfunc_obj: StructuredAstValue, offset: int, variable_type: StructuredAstValue) -> bool:
        """Update in-AST CVariable node types for the stack slot."""
        changed_type = False
        for node in _iter_c_nodes_deep_8616(cfunc_obj):
            if not isinstance(node, structured_c.CVariable):
                continue
            variable = node.variable
            if not isinstance(variable, SimStackVariable) or getattr(variable, "offset", None) != offset:
                continue
            if node.variable_type != variable_type:
                node.variable_type = variable_type
                changed_type = True
        return changed_type

    def _set_stack_slot_type_8616(self, offset: int, variable_type: StructuredAstValue) -> bool:
        """Set the slot type across variable maps and AST nodes."""
        changed_type = False
        cfunc_obj = getattr(self.codegen, "cfunc", None)
        variables = getattr(cfunc_obj, "variables_in_use", None)
        if isinstance(variables, dict):
            changed_type = self._set_variables_in_use_type_8616(variables, offset, variable_type) or changed_type
        unified = getattr(cfunc_obj, "unified_local_vars", None)
        if isinstance(unified, dict):
            changed_type = self._set_unified_local_slot_type_8616(unified, offset, variable_type) or changed_type
        changed_type = self._set_ast_stack_slot_type_8616(cfunc_obj, offset, variable_type) or changed_type
        return bool(changed_type)

    def _stack_slot_offset_for_name_8616(self, name: str | None) -> int | None:
        if not isinstance(name, str) or not name:
            return None
        for cvar in self._iter_stack_cvar_candidates():
            variable = getattr(cvar, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            candidate_name = variable.name or getattr(cvar, "name", None)
            if candidate_name == name:
                offset = variable.offset
                return offset if isinstance(offset, int) else None
        return None

    def _indirect_call_target_stack_offset_8616(self,
        call: StructuredAstValue, summary: StructuredAstValue = None
    ) -> int | None:
        if call is None:
            return None
        target_source = summary.target_source if summary is not None else None
        if (
            isinstance(target_source, tuple)
            and len(target_source) >= 2
            and target_source[0] == "bp"
            and isinstance(target_source[1], int)
        ):
            return int(target_source[1])
        callee_target = getattr(call, "callee_target", None)
        offset = self._plain_bp_stack_load_offset(callee_target)
        if offset is None:
            offset = self._plain_stack_slot_address_offset(callee_target)
        return offset

    def _apply_indirect_callsite_type_8616(self,
        call: StructuredAstValue, summary: StructuredAstValue, _expected_arg_count: int | None
    ) -> bool:
        target_addr = summary.target_addr if summary is not None else None
        if call is None or isinstance(target_addr, int):
            return False
        target_offset = self._indirect_call_target_stack_offset_8616(call, summary)
        if not isinstance(target_offset, int):
            return False
        # Compatibility bridge only: the Types/Lowering owner persists this
        # type through angr's variable manager and function prototype.
        changed_type = materialize_function_pointer_parameters_8616(self.project, self.codegen)
        target_cvar = self._stack_cvar_for_offset(target_offset, size_hint=2, allow_best_match=False)
        if target_cvar is not None:
            if getattr(call, "callee_func", None) is not None:
                call.callee_func = None
                changed_type = True
            if not _same_c_expression_8616(getattr(call, "callee_target", None), target_cvar):
                call.callee_target = self._clone_c_ast_tree(target_cvar)
                changed_type = True
        return bool(changed_type)

    def _set_assignment_lhs_8616(self, assignment: StructuredAstValue, new_lhs: StructuredAstValue) -> bool:
        if assignment is None or new_lhs is None:
            return False
        if hasattr(assignment, "lhs"):
            if _same_c_expression_8616(getattr(assignment, "lhs", None), new_lhs):
                return False
            assignment.lhs = self._clone_c_ast_tree(new_lhs)
            return True
        if hasattr(assignment, "dst"):
            if _same_c_expression_8616(getattr(assignment, "dst", None), new_lhs):
                return False
            assignment.dst = self._clone_c_ast_tree(new_lhs)
            return True
        return False

    def _same_call_result_value_8616(self, lhs: StructuredAstValue, rhs: StructuredAstValue) -> bool:
        """Compare call-result values by SSA identity before storage identity."""
        while isinstance(lhs, CTypeCast):
            lhs = lhs.expr
        while isinstance(rhs, CTypeCast):
            rhs = rhs.expr
        if isinstance(lhs, CDirtyExpression) and isinstance(rhs, CDirtyExpression):
            lhs_dirty = lhs.dirty
            rhs_dirty = rhs.dirty
            if isinstance(lhs_dirty, str) or isinstance(rhs_dirty, str):
                return isinstance(lhs_dirty, str) and isinstance(rhs_dirty, str) and lhs_dirty == rhs_dirty
            for attribute in ("varid", "tmp_idx"):
                lhs_identity = getattr(lhs_dirty, attribute, None)
                rhs_identity = getattr(rhs_dirty, attribute, None)
                if isinstance(lhs_identity, int) or isinstance(rhs_identity, int):
                    return (
                        isinstance(lhs_identity, int) and isinstance(rhs_identity, int) and lhs_identity == rhs_identity
                    )
        return bool(_same_c_expression_8616(lhs, rhs))

    def _expression_reads_exact_call_result_8616(self,
        expression: StructuredAstValue,
        call_result: StructuredAstValue,
        *,
        seen: set[int] | None = None,
    ) -> bool:
        """Return whether a structured C expression reads the exact call result."""
        if expression is None:
            return False
        if self._same_call_result_value_8616(expression, call_result):
            return True
        if seen is None:
            seen = set()
        marker = id(expression)
        if marker in seen:
            return False
        seen.add(marker)
        return any(
            self._expression_reads_exact_call_result_8616(child, call_result, seen=seen)
            for child in self._call_result_read_children_8616(expression)
        )

    def _call_result_read_children_8616(self, expression: StructuredAstValue) -> tuple[StructuredAstValue, ...]:
        """Return the child expressions this node may read through."""
        if isinstance(expression, CTypeCast):
            return (expression.expr,)
        if isinstance(expression, CUnaryOp):
            return (expression.operand,)
        if isinstance(expression, CBinaryOp):
            return (expression.lhs, expression.rhs)
        if isinstance(expression, CITE):
            return (expression.cond, expression.iftrue, expression.iffalse)
        if isinstance(expression, CIndexedVariable):
            return (expression.variable, expression.index)
        if isinstance(expression, CFunctionCall):
            return tuple(expression.args or ())
        return ()

    def _is_exact_destination_view_8616(
        self,
        candidate_lhs: StructuredAstValue,
        destination_lhs: StructuredAstValue,
        expected_stack_destination: tuple[int, int] | None,
    ) -> bool:
        """Check whether candidate_lhs is the same proven destination."""
        if _same_c_expression_8616(candidate_lhs, destination_lhs):
            return True
        if expected_stack_destination is None:
            return False
        node = candidate_lhs
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = node.variable
        if not isinstance(variable, SimStackVariable):
            return False
        expected_offset, expected_width = expected_stack_destination
        if variable.base != "bp" or variable.offset != expected_offset or variable.size != expected_width:
            return False
        destination_variable = getattr(destination_lhs, "variable", None)
        destination_region = getattr(destination_variable, "region", None)
        return destination_region is None or variable.region is None or variable.region == destination_region

    def _classify_stale_alias_candidate_8616(
        self,
        candidate: StructuredAstValue,
        old_lhs: StructuredAstValue,
        destination_lhs: StructuredAstValue,
        expected_stack_destination: tuple[int, int] | None,
    ) -> tuple[StructuredAstValue, ...]:
        """Classify one following statement as refuse/match/skip for alias consumption."""
        if self._statement_contains_call(candidate):
            return ("refuse", "following-call")
        candidate_assignment = self._top_level_assignment_node_8616(candidate)
        if candidate_assignment is None:
            return ("refuse", "non-assignment")
        candidate_lhs, candidate_rhs = self._assignment_lhs_rhs(candidate_assignment)
        if candidate_lhs is None or candidate_rhs is None:
            return ("refuse", "incomplete-assignment")
        lhs_is_destination = self._is_exact_destination_view_8616(
            candidate_lhs, destination_lhs, expected_stack_destination
        )
        rhs_is_old_result = self._same_call_result_value_8616(candidate_rhs, old_lhs)
        if lhs_is_destination and rhs_is_old_result:
            return ("match", candidate_lhs)
        if lhs_is_destination or self._same_call_result_value_8616(candidate_lhs, old_lhs):
            return ("refuse", "lhs-clobber")
        if self._expression_reads_exact_call_result_8616(candidate_rhs, old_lhs):
            return ("refuse", "competing-read")
        return ("skip",)

    def _consume_exact_stale_return_alias_8616(self,
        call_node: StructuredAstValue,
        old_lhs: StructuredAstValue,
        destination_lhs: StructuredAstValue,
        following_stmts: tuple[StructuredAstValue, ...],
        *,
        expected_stack_destination: tuple[int, int] | None = None,
    ) -> StructuredAstValue | None:
        """Consume and return the exact destination view of a proven call result."""
        matched_alias: tuple[int, StructuredAstValue] | None = None

        for candidate in following_stmts:
            verdict = self._classify_stale_alias_candidate_8616(
                candidate, old_lhs, destination_lhs, expected_stack_destination
            )
            if verdict[0] == "refuse":
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-return-destination-refuse] target=%s reason=%s",
                        _call_node_name_8616(call_node),
                        verdict[1],
                    )
                return None
            if verdict[0] == "match":
                if matched_alias is not None:
                    return None
                matched_alias = (id(candidate), verdict[1])
        if matched_alias is None:
            return None
        candidate_id, candidate_lhs = matched_alias
        self.consumed_stale_return_alias_statement_ids.add(candidate_id)
        self.codegen._inertia_call_return_destination_stale_alias_pruned_8616 = (
            int(getattr(self.codegen, "_inertia_call_return_destination_stale_alias_pruned_8616", 0) or 0) + 1
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning("[call-return-destination-consume] target=%s", _call_node_name_8616(call_node))
        return candidate_lhs

    def _call_result_destination_cvar_8616(
        self, destination: tuple[StructuredAstValue, int], width_hint: int
    ) -> StructuredAstValue | None:
        """Resolve the destination lvalue cvar for the proven store."""
        if destination[0] == "bp":
            dest_cvar = self._stack_cvar_for_offset(destination[1], size_hint=width_hint, allow_best_match=False)
            if dest_cvar is None:
                dest_cvar = self._stack_cvar_for_offset(destination[1], size_hint=width_hint, allow_best_match=True)
            return dest_cvar
        if destination[0] == "global":
            direct_ref = self.direct_global_arg_refs_by_offset.get((destination[1] & 0xFFFF, width_hint))
            return (
                _make_direct_global_symbol_expr_8616(self.codegen, direct_ref, width_hint)
                if direct_ref is not None
                else None
            )
        return None

    def _apply_call_return_store_destination_8616(self,
        stmt: StructuredAstValue,
        call: StructuredAstValue,
        summary: CallsiteSummary8616 | None,
        following_stmts: tuple[StructuredAstValue, ...] = (),
    ) -> bool:
        """Apply a proven call-result destination and consume its exact stale alias."""
        destination = summary.return_store_destination if summary is not None else None
        if not _return_store_destination_applicable_8616(call, summary, destination):
            return False
        width_hint = summary.return_store_width
        if not isinstance(width_hint, int) or width_hint <= 0:
            width_hint = 4 if summary.return_shape == "dx_ax" else 2
        dest_cvar = self._call_result_destination_cvar_8616(destination, width_hint)
        if dest_cvar is None:
            return False
        updated = False
        for assignment in self._iter_assignment_nodes(stmt):
            if self._call_from_statement(assignment) is not call and not any(
                node is call for node in _iter_c_nodes_deep_8616(assignment)
            ):
                continue
            old_lhs, _old_rhs = self._assignment_lhs_rhs(assignment)
            selected_destination = dest_cvar
            if old_lhs is not None:
                if call_result_escapes_group_8616(self.codegen.cfunc.statements, assignment, following_stmts):
                    return False
                if _same_c_expression_8616(old_lhs, dest_cvar):
                    return False
                stale_destination = self._consume_exact_stale_return_alias_8616(
                    call,
                    old_lhs,
                    dest_cvar,
                    following_stmts,
                    expected_stack_destination=(destination[1], width_hint) if destination[0] == "bp" else None,
                )
                if stale_destination is None:
                    return False
                selected_destination = stale_destination
            updated |= self._set_assignment_lhs_8616(assignment, selected_destination)
            return updated
        return False

    def _promote_current_function_return_type_from_summary_8616(self, summary: StructuredAstValue) -> bool:
        if summary.return_register != "ax" or summary.return_used is not True:
            return False
        cfunc_obj = getattr(self.codegen, "cfunc", None)
        func_addr = getattr(cfunc_obj, "addr", None)
        functions = getattr(getattr(self.project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", None)
        func = cast(
            StructuredAstValue,
            lookup(addr=func_addr, create=False) if isinstance(func_addr, int) and callable(lookup) else None,
        )
        prototype = (
            getattr(cfunc_obj, "functy", None)
            or getattr(cfunc_obj, "prototype", None)
            or (getattr(func, "prototype", None) if func is not None else None)
        )
        return_type = _word_type_8616(self.project)
        args = list(getattr(prototype, "args", ()) or ()) if prototype is not None else []
        arg_names = list(getattr(prototype, "arg_names", None) or ()) if prototype is not None else []
        new_prototype = SimTypeFunction(
            args,
            return_type,
            arg_names=cast(list[str], arg_names),
            variadic=getattr(prototype, "variadic", False) if prototype is not None else False,
        )
        arch = getattr(self.project, "arch", None)
        if arch is not None and hasattr(new_prototype, "with_arch"):
            new_prototype = new_prototype.with_arch(arch)
        changed_return = False
        if cfunc_obj is not None:
            if getattr(cfunc_obj, "functy", None) != new_prototype:
                cfunc_obj.functy = new_prototype
                changed_return = True
            if getattr(cfunc_obj, "prototype", None) != new_prototype:
                with contextlib.suppress(Exception):
                    cfunc_obj.prototype = new_prototype
                    changed_return = True
        if func is not None and getattr(func, "prototype", None) != new_prototype:
            func.prototype = new_prototype
            func.is_prototype_guessed = False
            changed_return = True
        if changed_return:
            self.codegen._inertia_call_return_function_return_type_promoted_8616 = (
                int(getattr(self.codegen, "_inertia_call_return_function_return_type_promoted_8616", 0) or 0) + 1
            )
        return changed_return

    def _register_name_from_c_variable_8616(self, expr: StructuredAstValue) -> str | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return None
        variable = node.variable
        name = getattr(variable, "name", None) or node.name
        if isinstance(name, str) and name:
            return name.strip().lower().split("#", 1)[0]
        if isinstance(variable, SimRegisterVariable):
            reg = variable.reg
            reg_name = getattr(getattr(self.project, "arch", None), "register_names", {}).get(reg)
            if isinstance(reg_name, str) and reg_name:
                return reg_name.strip().lower().split("#", 1)[0]
        return None

    def _node_reads_register_name_8616(self, node: StructuredAstValue, register_name: str) -> bool:
        if node is None:
            return False
        if self._register_name_from_c_variable_8616(node) == register_name:
            return True
        return any(
            self._register_name_from_c_variable_8616(child) == register_name for child in _iter_c_nodes_deep_8616(node)
        )

    def _ret_selector_debug_refuse_8616(self,
        call: StructuredAstValue,
        stmt: StructuredAstValue,
        following_statements: tuple[StructuredAstValue, ...],
        summary: StructuredAstValue,
        reason: str,
    ) -> StructuredAstValue:
        """Log a selector-materialization refusal and keep ``stmt``."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-return-selector] refuse target=%r reason=%s stmt=%s following=%r return_register=%r return_used=%r",
                _call_node_name_8616(call) if call is not None else None,
                reason,
                type(stmt).__name__,
                tuple(type(candidate).__name__ for candidate in following_statements),
                summary.return_register if summary is not None else None,
                summary.return_used if summary is not None else None,
            )
        return stmt

    def _call_return_selector_assignment_statement_8616(self,
        stmt: StructuredAstValue,
        call: StructuredAstValue,
        summary: CallsiteSummary8616 | None,
        following_statements: StructuredAstValue,
    ) -> StructuredAstValue:
        """Materialize an AX selector only from a present typed callsite summary."""
        following_statements = tuple(following_statements or ())


        is_standalone_call = stmt is call or getattr(stmt, "expr", None) is call
        is_assignment_call = (
            stmt.__class__.__name__ == "CAssignment" or stmt.__class__.__name__.endswith("Assignment")
        ) and getattr(stmt, "rhs", None) is call
        if call is None:
            return self._ret_selector_debug_refuse_8616(call, stmt, following_statements, summary, "missing-call")
        if summary is None:
            return self._ret_selector_debug_refuse_8616(call, stmt, following_statements, summary, "missing-summary")
        if not is_scalar_ax_call_return_8616(summary):
            return self._ret_selector_debug_refuse_8616(call, stmt, following_statements, summary, "return-not-proven-scalar-ax")
        if not (is_standalone_call or is_assignment_call):
            return self._ret_selector_debug_refuse_8616(call, stmt, following_statements, summary, "call-not-standalone-or-assignment")
        has_following_ax_read = any(
            self._node_reads_register_name_8616(candidate, "ax") for candidate in following_statements
        )
        if not has_following_ax_read and summary.return_use_kind != "condition":
            return self._ret_selector_debug_refuse_8616(call, stmt, following_statements, summary, "no-ax-selector-evidence")
        ax_expr = self._register_expr_from_name_8616("ax")
        if ax_expr is None:
            return self._ret_selector_debug_refuse_8616(call, stmt, following_statements, summary, "missing-ax-expr")
        existing_lhs = getattr(stmt, "lhs", None) if is_assignment_call else None
        existing_variable = getattr(existing_lhs, "variable", None)
        if (
            isinstance(existing_variable, SimRegisterVariable)
            and isinstance(ax_expr.variable, SimRegisterVariable)
            and existing_variable.reg == ax_expr.variable.reg
            and existing_variable.size == ax_expr.variable.size
        ):
            return stmt
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-return-selector] materialize target=%r stmt=%s following=%r",
                _call_node_name_8616(call),
                type(stmt).__name__,
                tuple(type(candidate).__name__ for candidate in following_statements),
            )
        _drop_detached_callee_func_8616(call)
        self.codegen._inertia_call_return_switch_selector_materialized_8616 = (
            int(getattr(self.codegen, "_inertia_call_return_switch_selector_materialized_8616", 0) or 0) + 1
        )
        if is_assignment_call:
            self._set_assignment_lhs_8616(stmt, ax_expr)
            return stmt
        return structured_c.CAssignment(ax_expr, call, codegen=self.codegen)

    def _near_function_symbol_expr_8616(self, target_addr: int, arg_count: int | None = None) -> StructuredAstValue | None:
        name = None
        synthetic_globals = getattr(self.codegen, "_inertia_synthetic_globals", None)
        if not isinstance(synthetic_globals, dict):
            synthetic_globals = getattr(self.project, "_inertia_synthetic_globals", None)
        if isinstance(synthetic_globals, dict):
            synthetic = synthetic_globals.get(target_addr)
            if isinstance(synthetic, tuple) and len(synthetic) >= 1 and isinstance(synthetic[0], str) and synthetic[0]:
                name = normalize_callee_name_8616(synthetic[0].lstrip("_")) or synthetic[0].lstrip("_")
        if not isinstance(name, str) or not name:
            name = _sidecar_label_for_target_8616(self.project, target_addr)
        if not isinstance(name, str) or not name:
            callee = _lookup_callee_function_8616(self.project, target_addr, allow_containing=False)
            name = normalize_callee_name_8616(getattr(callee, "name", None))
        if not isinstance(name, str) or not name:
            return None
        variable = SimMemoryVariable(target_addr, 2, name=name, region=getattr(self.cfunc, "addr", None))
        return structured_c.CVariable(
            variable,
            variable_type=_near_function_pointer_type_8616(self.project, arg_count),
            codegen=self.codegen,
        )

    def _operand_reg_name_from_capstone_8616(self, insn: StructuredAstValue, operand: StructuredAstValue) -> str | None:
        reg = getattr(operand, "reg", None)
        if not isinstance(reg, int):
            return None
        reg_name = getattr(insn, "reg_name", None)
        if not callable(reg_name):
            return None
        with contextlib.suppress(Exception):
            name = reg_name(reg)
            if isinstance(name, str) and name:
                return name.lower()
        return None

    def _mov_bp_imm_store_8616(self, insn: StructuredAstValue) -> tuple[int, int] | None:
        if str(getattr(insn, "mnemonic", "") or "").lower() != "mov":
            return None
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if len(operands) != 2:
            return None
        dst, src = operands
        if getattr(dst, "type", None) != 3 or getattr(src, "type", None) != 2:
            return None
        mem = getattr(dst, "mem", None)
        base_reg = getattr(mem, "base", None) if mem is not None else None
        base_operand = SimpleNamespace(reg=base_reg) if isinstance(base_reg, int) else None
        base = self._operand_reg_name_from_capstone_8616(insn, base_operand) if base_operand is not None else None
        if base != "bp":
            return None
        disp = getattr(mem, "disp", None)
        imm = getattr(src, "imm", None)
        if not isinstance(disp, int) or not isinstance(imm, int):
            return None
        return disp, imm & 0xFFFF

    def _mov_bp_store_offset_8616(self, insn: StructuredAstValue) -> int | None:
        if str(getattr(insn, "mnemonic", "") or "").lower() != "mov":
            return None
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if len(operands) != 2:
            return None
        dst = operands[0]
        if getattr(dst, "type", None) != 3:
            return None
        mem = getattr(dst, "mem", None)
        base_reg = getattr(mem, "base", None) if mem is not None else None
        base_operand = SimpleNamespace(reg=base_reg) if isinstance(base_reg, int) else None
        base = self._operand_reg_name_from_capstone_8616(insn, base_operand) if base_operand is not None else None
        if base != "bp":
            return None
        disp = getattr(mem, "disp", None)
        return disp if isinstance(disp, int) else None

    def _function_for_current_cfunc_8616(self) -> StructuredAstValue:
        func_addr = getattr(self.cfunc, "addr", None)
        if not isinstance(func_addr, int):
            return None
        functions = getattr(getattr(self.project, "kb", None), "functions", None)
        lookup = getattr(functions, "function", None)
        if not callable(lookup):
            return None
        with contextlib.suppress(Exception):
            return lookup(addr=func_addr, create=False)
        return None

    def _function_pointer_stack_store_slot_has_type_evidence_8616(self, offset: int) -> bool:
        if self.fnptr_typed_stack_offsets_cache_8616 is None:
            self.fnptr_typed_stack_offsets_cache_8616 = _annotated_function_pointer_stack_offsets_8616(self.project, self.cfunc)
        return isinstance(offset, int) and offset in self.fnptr_typed_stack_offsets_cache_8616

    def _scan_fnptr_evidence_block_8616(self,
        block_addr: int,
        evidence: dict[int, list[tuple[int, StructuredAstValue]]],
        seen_stores: set[tuple[int, int, int]],
        debug_fnptr: bool,
    ) -> None:
        """Scan one lifted block for typed function-pointer stack stores."""
        with contextlib.suppress(Exception):
            block = self.project.factory.block(block_addr, opt_level=0)
            insns = _boundary_tuple_8616(getattr(getattr(block, "capstone", None), "insns", ()) or ())
            for insn in insns:
                self._scan_fnptr_evidence_insn_8616(insn, block_addr, evidence, seen_stores, debug_fnptr)

    def _scan_fnptr_evidence_insn_8616(self,
        insn: StructuredAstValue,
        block_addr: int,
        evidence: dict[int, list[tuple[int, StructuredAstValue]]],
        seen_stores: set[tuple[int, int, int]],
        debug_fnptr: bool,
    ) -> None:
        """Record one bp+imm function-pointer store when slot and target evidence hold."""
        capstone_insn = getattr(insn, "insn", insn)
        store = self._mov_bp_imm_store_8616(capstone_insn)
        if store is None:
            return
        offset, imm = store
        insn_addr = getattr(insn, "address", 0) or 0
        store_key = (int(insn_addr), int(offset), int(imm))
        if store_key in seen_stores:
            return
        seen_stores.add(store_key)
        has_slot_evidence = self._function_pointer_stack_store_slot_has_type_evidence_8616(offset)
        has_target_evidence = _target_addr_is_recovered_function_entry_8616(self.project, imm)
        if debug_fnptr:
            log.warning(
                (
                    "[fnptr-store-candidate] func=%#x block=%#x insn=%#x "
                    "offset=%r imm=%#x fnptr_slot=%r recovered_entry=%r"
                ),
                getattr(self.cfunc, "addr", 0) or 0,
                block_addr,
                insn_addr,
                offset,
                imm,
                has_slot_evidence,
                has_target_evidence,
            )
        if not has_slot_evidence:
            self.codegen._inertia_fnptr_stack_store_refused_untyped_slot_8616 = (
                int(getattr(self.codegen, "_inertia_fnptr_stack_store_refused_untyped_slot_8616", 0) or 0) + 1
            )
            if debug_fnptr:
                log.warning(
                    (
                        "[fnptr-store-refuse] func=%#x block=%#x insn=%#x "
                        "offset=%r imm=%#x reason=stack-slot-not-typed-function-pointer"
                    ),
                    getattr(self.cfunc, "addr", 0) or 0,
                    block_addr,
                    insn_addr,
                    offset,
                    imm,
                )
            return
        if not has_target_evidence:
            return
        symbol = self._near_function_symbol_expr_8616(imm)
        if debug_fnptr:
            log.warning(
                "[fnptr-store] func=%#x block=%#x insn=%#x offset=%r imm=%#x symbol=%r",
                getattr(self.cfunc, "addr", 0) or 0,
                block_addr,
                insn_addr,
                offset,
                imm,
                getattr(getattr(symbol, "variable", None), "name", None) if symbol is not None else None,
            )
        if symbol is None:
            return
        evidence.setdefault(offset, []).append((insn_addr, symbol))

    def _function_pointer_stack_store_evidence_8616(self) -> dict[int, list[tuple[int, StructuredAstValue]]]:
        function = self._function_for_current_cfunc_8616()
        block_addrs = _boundary_tuple_8616(sorted(getattr(function, "block_addrs_set", ()) or ()))
        debug_fnptr = bool(os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_STORES"))
        if debug_fnptr:
            log.warning(
                "[fnptr-scan] func=%#x blocks=%r",
                getattr(self.cfunc, "addr", 0) or 0,
                tuple(hex(addr) for addr in block_addrs),
            )
        evidence: dict[int, list[tuple[int, StructuredAstValue]]] = {}
        seen_stores: set[tuple[int, int, int]] = set()
        for block_addr in block_addrs:
            self._scan_fnptr_evidence_block_8616(block_addr, evidence, seen_stores, debug_fnptr)
        ordered: dict[int, list[tuple[int, StructuredAstValue]]] = {}
        for offset, items in evidence.items():
            ordered[offset] = [
                (int(getattr(getattr(symbol, "variable", None), "addr", imm) or imm), self._clone_c_ast_tree(symbol))
                for _addr, symbol in sorted(items, key=lambda item: item[0])
                for imm in [int(getattr(getattr(symbol, "variable", None), "addr", 0) or 0)]
            ]
        return ordered

    def _cached_function_pointer_stack_store_evidence_8616(self) -> dict[int, list[tuple[int, StructuredAstValue]]]:
        if self.fnptr_store_evidence_cache_8616 is None:
            self.fnptr_store_evidence_cache_8616 = self._function_pointer_stack_store_evidence_8616()
        return self.fnptr_store_evidence_cache_8616

    def _bp_stack_store_counts_8616(self) -> Counter[int]:
        function = self._function_for_current_cfunc_8616()
        block_addrs = _boundary_tuple_8616(sorted(getattr(function, "block_addrs_set", ()) or ()))
        counts: Counter[int] = Counter()
        seen_insns: set[int] = set()
        for block_addr in block_addrs:
            with contextlib.suppress(Exception):
                block = self.project.factory.block(block_addr, opt_level=0)
                insns = _boundary_tuple_8616(getattr(getattr(block, "capstone", None), "insns", ()) or ())
                for insn in insns:
                    insn_addr = int(getattr(insn, "address", 0) or 0)
                    if insn_addr in seen_insns:
                        continue
                    capstone_insn = getattr(insn, "insn", insn)
                    offset = self._mov_bp_store_offset_8616(capstone_insn)
                    if offset is None:
                        continue
                    seen_insns.add(insn_addr)
                    counts[offset] += 1
        return counts

    def _stack_offset_from_cvar_8616(self, expr: StructuredAstValue) -> int | None:
        """Return the authoritative machine-BP coordinate for a stack C variable."""
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        offset = call_argument_stack_variable_offset_8616(self.codegen, node)
        return offset if isinstance(offset, int) else None

    def _is_immediate_like_expr_8616(self, expr: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        return isinstance(node, structured_c.CConstant)

    def _constant_int_value_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        value = getattr(node, "value", None) if isinstance(node, structured_c.CConstant) else None
        return int(value) & 0xFFFF if isinstance(value, int) else None

    def _symbol_name_8616(self, expr: StructuredAstValue) -> str | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        return name if isinstance(name, str) and name else None

    def _assignment_to_stack_offset_8616(self,
        stmt: StructuredAstValue,
        offset: int,
    ) -> tuple[StructuredAstValue | None, StructuredAstValue | None]:
        for assignment in self._iter_assignment_nodes(stmt):
            lhs, rhs = self._assignment_lhs_rhs(assignment)
            if self._stack_offset_from_cvar_8616(lhs) == offset:
                return assignment, rhs
        return None, None

    def _debug_fnptr_ifelse_8616(
        self, stmt: StructuredAstValue, evidence: dict[int, list[tuple[int, StructuredAstValue]]]
    ) -> None:
        """Log branch assignment evidence for a function-pointer ifelse."""
        branch_debug = []
        for _cond, child in _boundary_tuple_8616(stmt.condition_and_nodes or ()):
            branch_debug.append(
                (
                    type(child).__name__ if child is not None else "None",
                    self._debug_assignments_in_stmt_8616(child),
                )
            )
        else_node = stmt.else_node
        log.warning(
            "[fnptr-ast] func=%#x ifelse branches=%r else=%r evidence_offsets=%r",
            getattr(self.cfunc, "addr", 0) or 0,
            branch_debug,
            (
                type(else_node).__name__ if else_node is not None else "None",
                self._debug_assignments_in_stmt_8616(else_node) if else_node is not None else (),
            ),
            tuple(sorted(evidence)),
        )

    def _branch_assignments_for_offset_8616(
        self, stmt: StructuredAstValue, else_node: StructuredAstValue, offset: int
    ) -> list[tuple[StructuredAstValue, StructuredAstValue | None]]:
        """Collect branch assignments whose LHS is the stack offset."""
        branch_assignments: list[tuple[StructuredAstValue, StructuredAstValue | None]] = []
        for _cond, child in _boundary_tuple_8616(stmt.condition_and_nodes or ()):
            for assignment in self._iter_assignment_nodes(child):
                lhs, rhs = self._assignment_lhs_rhs(assignment)
                if self._stack_offset_from_cvar_8616(lhs) == offset:
                    branch_assignments.append((assignment, rhs))
        if else_node is not None:
            for assignment in self._iter_assignment_nodes(else_node):
                lhs, rhs = self._assignment_lhs_rhs(assignment)
                if self._stack_offset_from_cvar_8616(lhs) == offset:
                    branch_assignments.append((assignment, rhs))
        return branch_assignments

    def _materialize_branch_unknown_fnptr_symbols_8616(
        self,
        stmt: StructuredAstValue,
        else_node: StructuredAstValue,
        evidence: dict[int, list[tuple[int, StructuredAstValue]]],
    ) -> bool:
        """Assign the single remaining known symbol to the single unknown branch."""
        changed = False
        for offset, symbols in evidence.items():
            symbol_by_name = {
                name: symbol
                for _addr, symbol in symbols
                for name in [self._symbol_name_8616(symbol)]
                if name is not None
            }
            if len(symbol_by_name) < 2:
                continue
            branch_assignments = self._branch_assignments_for_offset_8616(stmt, else_node, offset)
            known_names = {
                name
                for _assignment, rhs in branch_assignments
                for name in [self._symbol_name_8616(rhs)]
                if name in symbol_by_name
            }
            unknown_assignments = [
                assignment
                for assignment, rhs in branch_assignments
                if self._symbol_name_8616(rhs) not in symbol_by_name
            ]
            remaining = [symbol for name, symbol in symbol_by_name.items() if name not in known_names]
            if len(unknown_assignments) == 1 and len(remaining) == 1:
                assignment = unknown_assignments[0]
                symbol = self._clone_c_ast_tree(remaining[0])
                self._set_stack_slot_type_8616(offset, getattr(symbol, "variable_type", None))
                if hasattr(assignment, "rhs"):
                    assignment.rhs = symbol
                elif hasattr(assignment, "src"):
                    assignment.src = symbol
                self.codegen._inertia_fnptr_branch_symbols_materialized_8616 = (
                    int(getattr(self.codegen, "_inertia_fnptr_branch_symbols_materialized_8616", 0) or 0) + 1
                )
                changed = True
        return changed

    def _materialize_else_fnptr_symbols_8616(
        self,
        stmt: StructuredAstValue,
        else_node: StructuredAstValue,
        evidence: dict[int, list[tuple[int, StructuredAstValue]]],
    ) -> bool:
        """Materialize the missing branch symbol into an empty else block."""
        changed = False
        for offset in evidence:
            has_empty_else = else_node is None or not _boundary_tuple_8616(
                getattr(else_node, "statements", ()) or ()
            )
            if not has_empty_else:
                continue
            branch_names: set[str] = set()
            for _cond, child in _boundary_tuple_8616(stmt.condition_and_nodes or ()):
                for assignment in self._iter_assignment_nodes(child):
                    lhs, rhs = self._assignment_lhs_rhs(assignment)
                    if self._stack_offset_from_cvar_8616(lhs) == offset:
                        name = self._symbol_name_8616(rhs)
                        if name is not None:
                            branch_names.add(name)
            symbol = self.symbol_for_immediate(offset, None, exclude_names=branch_names, evidence=evidence)
            if symbol is None:
                continue
            assignment = self.make_assignment(offset, symbol)
            if assignment is None:
                continue
            stmt.else_node = structured_c.CStatements([assignment], codegen=self.codegen)
            changed = True
        return changed

    def _replace_stack_code_pointer_assignments_8616(self, root: StructuredAstValue) -> bool:
        evidence = self._cached_function_pointer_stack_store_evidence_8616()
        if not evidence:
            return False
        bp_stack_store_counts = self._bp_stack_store_counts_8616()
        changed_local = False
        debug_fnptr = bool(os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_STORES"))















        changed_local = self._walk_fnptr_statements_8616(
            root,
            evidence=evidence,
            bp_stack_store_counts=bp_stack_store_counts,
            debug_fnptr=debug_fnptr,
        )
        return changed_local

    def _walk_fnptr_ifelse_8616(
        self,
        stmt: StructuredAstValue,
        *,
        evidence: StructuredAstValue,
        bp_stack_store_counts: StructuredAstValue,
        debug_fnptr: bool,
    ) -> bool:
        """Apply function-pointer repairs inside a CIfElse statement."""
        changed_local = False
        if debug_fnptr:
            self._debug_fnptr_ifelse_8616(stmt, evidence)
        for _cond, child in _boundary_tuple_8616(stmt.condition_and_nodes or ()):
            if self._walk_fnptr_statements_8616(
                child, evidence=evidence, bp_stack_store_counts=bp_stack_store_counts, debug_fnptr=debug_fnptr
            ):
                changed_local = True
        else_node = stmt.else_node
        if self._materialize_empty_branch_function_pointer_stores_8616(stmt, evidence=evidence):
            changed_local = True
        if self._repair_branch_immediate_function_pointer_stores_8616(stmt, evidence=evidence):
            changed_local = True
        if self._materialize_branch_unknown_fnptr_symbols_8616(stmt, else_node, evidence):
            changed_local = True
        if self._materialize_else_fnptr_symbols_8616(stmt, else_node, evidence):
            changed_local = True
        if stmt.else_node is not None and self._walk_fnptr_statements_8616(
            stmt.else_node, evidence=evidence, bp_stack_store_counts=bp_stack_store_counts, debug_fnptr=debug_fnptr
        ):
            changed_local = True
        return changed_local

    def _walk_fnptr_children_8616(
        self,
        stmt: StructuredAstValue,
        *,
        evidence: StructuredAstValue,
        bp_stack_store_counts: StructuredAstValue,
        debug_fnptr: bool,
    ) -> bool:
        """Walk statement child containers for function-pointer repairs."""
        any_changed = False
        for attr in ("statements",):
            children = getattr(stmt, attr, None)
            if isinstance(children, (list, tuple)):
                for child in children:
                    if self._walk_fnptr_statements_8616(
                        child, evidence=evidence, bp_stack_store_counts=bp_stack_store_counts, debug_fnptr=debug_fnptr
                    ):
                        any_changed = True
                if self._prune_stale_post_branch_fnptr_overwrites_8616(stmt, bp_stack_store_counts=bp_stack_store_counts, evidence=evidence):
                    any_changed = True
        for attr in ("body", "else_node"):
            child = getattr(stmt, attr, None)
            if child is not None and self._walk_fnptr_statements_8616(
                child, evidence=evidence, bp_stack_store_counts=bp_stack_store_counts, debug_fnptr=debug_fnptr
            ):
                any_changed = True
        return any_changed

    def _walk_fnptr_statements_8616(
        self,
        stmt: StructuredAstValue,
        *,
        evidence: dict[int, list[tuple[int, StructuredAstValue]]],
        bp_stack_store_counts: StructuredAstValue,
        debug_fnptr: bool,
    ) -> bool:
        """Walk statements and apply function-pointer store repairs; return whether anything changed."""
        changed_local = False
        if stmt is None:
            return changed_local
        if isinstance(stmt, structured_c.CIfElse):
            if self._walk_fnptr_ifelse_8616(
                stmt, evidence=evidence, bp_stack_store_counts=bp_stack_store_counts, debug_fnptr=debug_fnptr
            ):
                changed_local = True
            return changed_local
        if self.materialize_assignment(stmt, evidence=evidence):
            changed_local = True
        if self._walk_fnptr_children_8616(
            stmt, evidence=evidence, bp_stack_store_counts=bp_stack_store_counts, debug_fnptr=debug_fnptr
        ):
            changed_local = True
        return changed_local
        return changed_local

    def _final_return_call_pair_8616(
        self, statements: list[StructuredAstValue]
    ) -> tuple[int, int] | None:
        """Locate the trailing ``call; return`` statement pair."""
        ret_idx = None
        for idx in range(len(statements) - 1, -1, -1):
            candidate = self.single_nested_statement(statements[idx])
            if isinstance(candidate, structured_c.CReturn):
                ret_idx = idx
                break
        if ret_idx is None or ret_idx <= 0:
            return None
        call_idx = ret_idx - 1
        while call_idx >= 0 and not self._statement_contains_call(statements[call_idx]):
            class_name = statements[call_idx].__class__.__name__
            if class_name not in {"CStatements"}:
                return None
            call_idx -= 1
        if call_idx < 0:
            return None
        return ret_idx, call_idx

    def _materialize_final_call_direct_args_8616(
        self,
        call: StructuredAstValue,
        summary: CallsiteSummary8616,
        statements: list[StructuredAstValue],
    ) -> None:
        """Materialize direct push-source args for the trailing call when proven."""
        push_arg_sources = summary.push_arg_sources
        summary_arg_count = summary.arg_count
        if not (
            isinstance(summary_arg_count, int)
            and summary_arg_count > 0
            and isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == summary_arg_count
            and len(_boundary_tuple_8616(getattr(call, "args", ()) or ())) != summary_arg_count
        ):
            return
        ordered_push_sources = (
            list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
        )
        direct_args: list[StructuredAstValue] = []
        direct_bindings = {}
        for idx, source in enumerate(ordered_push_sources):
            arg = self._direct_expr_from_push_source_8616(
                source,
                call_name=_call_node_name_8616(call),
                arg_index=idx,
            )
            if arg is None:
                direct_args.clear()
                break
            direct_args.append(arg)
            if isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int):
                direct_bindings[int(source[1])] = self._clone_c_ast_tree(arg)
        if len(direct_args) == summary_arg_count:
            normalized_args = self._normalize_materialized_call_args(
                direct_args,
                [-1] * len(direct_args),
                statements,
                call_name=_call_node_name_8616(call),
                stack_bindings=direct_bindings or None,
            )
            if normalized_args is not None and self._all_arg_exprs_are_non_segment_registers(normalized_args):
                transaction = self._set_materialized_call_args(
                    call,
                    normalized_args,
                    call_name=_call_node_name_8616(call),
                    force_replace=True,
                )
                if transaction.arguments_accepted:
                    record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
                    self._refresh_summary_arg_shape(call, summary)

    def _debug_final_return_call_8616(
        self,
        call: StructuredAstValue,
        summary: CallsiteSummary8616 | None,
        ret_stmt: StructuredAstValue,
    ) -> None:
        """Log trailing call/return diagnostics when debugging is enabled."""
        if os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_STORES"):
            log.warning(
                "[return-call] call=%r summary_return=%r used=%r ret=%r",
                _call_node_name_8616(call),
                summary.return_register if summary is not None else None,
                summary.return_used if summary is not None else None,
                getattr(ret_stmt.retval, "value", None),
            )

    def _apply_final_return_call_8616(
        self,
        statements: list[StructuredAstValue],
        call_idx: int,
        ret_stmt: StructuredAstValue,
        call: StructuredAstValue,
        summary: CallsiteSummary8616,
        nested_call_statements: StructuredAstValue,
        nested_call_idx: int | None,
    ) -> bool:
        """Replace the return value with the call and drop the call statement."""
        retval = ret_stmt.retval
        if retval is not None and not isinstance(retval, structured_c.CConstant):
            return False
        self._promote_current_function_return_type_from_summary_8616(summary)
        ret_stmt.retval = self._clone_c_ast_tree(call)
        if nested_call_statements is not None and nested_call_idx is not None:
            del nested_call_statements[nested_call_idx]
            if not nested_call_statements:
                del statements[call_idx]
        else:
            del statements[call_idx]
        return True

    def _materialize_final_return_call_8616(self, statements: list[StructuredAstValue]) -> bool:
        if os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_STORES"):
            log.warning(
                "[return-call-list] %r",
                [
                    (
                        idx,
                        stmt.__class__.__name__,
                        getattr(getattr(stmt, "expr", None), "__class__", type(None)).__name__,
                        getattr(getattr(stmt, "retval", None), "__class__", type(None)).__name__,
                    )
                    for idx, stmt in enumerate(statements[-8:])
                ],
            )
        if len(statements) < 2:
            return False




        pair = self._final_return_call_pair_8616(statements)
        if pair is None:
            return False
        ret_idx, call_idx = pair
        call_stmt = statements[call_idx]
        ret_stmt = self.single_nested_statement(statements[ret_idx])
        if not isinstance(ret_stmt, structured_c.CReturn):
            return False
        call, nested_call_statements, nested_call_idx = self.final_standalone_call_ref(call_stmt)
        if call is None:
            return False
        summary = self.summary_map.get(id(call))
        self._debug_final_return_call_8616(call, summary, ret_stmt)
        if summary is None:
            return False
        if summary.return_register != "ax":
            return False
        if summary.return_used is not True:
            return False
        function_addr = getattr(self.cfunc, "addr", None)
        caller_observation = (
            _bound_function_result_observation_8616(self.project, self.codegen, function_addr)
            if isinstance(function_addr, int)
            else None
        )
        self.codegen._inertia_final_return_call_caller_observation_8616 = caller_observation
        if caller_observation is CallerReturnUseVerdict8616.UNUSED:
            return False
        self._materialize_final_call_direct_args_8616(call, summary, statements)
        return self._apply_final_return_call_8616(
            statements, call_idx, ret_stmt, call, summary, nested_call_statements, nested_call_idx
        )

    def _register_expr_from_name_8616(self, reg_name: str) -> StructuredAstValue:
        register = getattr(getattr(self.project, "arch", None), "registers", {}).get(reg_name.lower())
        if not isinstance(register, tuple) or not register:
            return None
        return structured_c.CVariable(
            SimRegisterVariable(register[0], 2, name=reg_name.lower()),
            variable_type=_word_type_8616(self.project),
            codegen=self.codegen,
        )

    def _segment_register_expr(self, seg_name: str) -> StructuredAstValue:
        return self._register_expr_from_name_8616(seg_name)

    def _lower_proven_segment_push_source_8616(self,
        segment_name: str,
        push_sources: tuple[StructuredAstValue, ...],
    ) -> StructuredAstValue:
        """Delegate an exact segment PUSH source to the bound Types/Lowering service."""
        proven_segments = {
            source[1].lower()
            for source in push_sources
            if (
                isinstance(source, tuple)
                and len(source) == 2
                and source[0] == "seg"
                and isinstance(source[1], str)
            )
        }
        normalized_name = segment_name.lower()
        if normalized_name not in proven_segments:
            return None
        try:
            lowerer = cast(
                _CallsiteMaterializationControlCarrier8616,
                self.codegen,
            )._inertia_segment_push_source_lowerer_8616
        except AttributeError:
            return None
        cfunc = self.codegen.cfunc
        function_addr = cfunc.addr if cfunc is not None else None
        if not isinstance(function_addr, int):
            return None
        return lowerer(
            normalized_name,
            codegen=self.codegen,
            variable_type=_word_type_8616(self.project),
            function_addr=function_addr,
        )

    def _plain_stack_slot_address_offset(self, node: StructuredAstValue) -> int | None:
        term_root = node
        while isinstance(term_root, CTypeCast):
            term_root = term_root.expr



        const_total = 0
        stack_offsets: list[int] = []
        for term, sign in self.flatten(term_root):
            value = getattr(term, "value", None) if isinstance(term, structured_c.CConstant) else None
            if isinstance(value, int):
                const_total += sign * value
                continue
            if isinstance(term, CUnaryOp) and term.op == "Reference":
                inner = term.operand
                offset = self.resolve_stack_offset(inner)
                if isinstance(offset, int):
                    stack_offsets.append(sign * offset)
                    continue
            offset = self.resolve_stack_offset(term)
            if isinstance(offset, int):
                stack_offsets.append(sign * offset)
                continue
            return None
        if len(stack_offsets) != 1:
            return None
        return stack_offsets[0] + const_total

    def _plain_bp_stack_load_offset(self, node: StructuredAstValue) -> int | None:
        node = self._clone_c_ast_tree(node)
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CUnaryOp) or node.op != "Dereference":
            return None
        return self._plain_stack_slot_address_offset(node.operand)

    def _fold_stack_plus_const_term_8616(self,
        term: StructuredAstValue,
        stack_terms: list[StructuredAstValue],
    ) -> int | None:
        """Fold one add/sub term: returns its const contribution, 0 for stack terms, None to refuse."""
        unwrapped = self._unary_unwrap(term)
        if isinstance(unwrapped, structured_c.CVariable):
            variable = unwrapped.variable
            if isinstance(variable, SimStackVariable):
                stack_terms.append(self._clone_c_ast_tree(unwrapped))
                return 0
        term_const = (
            getattr(unwrapped, "value", None) if isinstance(unwrapped, structured_c.CConstant) else None
        )
        if isinstance(term_const, int):
            return int(term_const)
        term_offset = self._stack_offset_from_cvar_8616(unwrapped)
        if isinstance(term_offset, int):
            term_base = self._stack_cvar_for_offset(term_offset, allow_best_match=True)
            if term_base is not None:
                stack_terms.append(self._clone_c_ast_tree(term_base))
            return 0
        return None

    def _normalize_stack_plus_const_base_8616(
        self,
        node: StructuredAstValue,
        *,
        pointer_arg: bool,
        normalize_stack_slot_value_arithmetic: bool,
        node_has_stack_value_carrier: bool,
    ) -> StructuredAstValue | None:
        """Collapse a ``stack_var + const`` expression back to its stack base."""
        if not normalize_stack_slot_value_arithmetic or pointer_arg or not node_has_stack_value_carrier:
            return None
        if isinstance(node, CTypeCast):
            inner_width = self._arg_width_from_expr(node.expr)
            cast_width = self._arg_width_from_expr(node)
            if cast_width > inner_width:
                return None



        stack_terms = []
        constant_total = 0
        for term, sign in self._flatten_add_sub(node):
            const_delta = self._fold_stack_plus_const_term_8616(term, stack_terms)
            if const_delta is None:
                return None
            constant_total += sign * const_delta
        if len(stack_terms) != 1:
            return None
        return stack_terms[0]

    def _resolve_bp_slot_replacement_8616(self,
        displacement: int,
        stack_bindings: StructuredAstValue,
    ) -> StructuredAstValue | None:
        """Resolve the replacement expr for a BP slot displacement."""
        replacement = None
        if isinstance(stack_bindings, dict):
            replacement = stack_bindings.get(displacement)
            if replacement is not None and self._c_ast_node_count_limited(replacement, limit=128) > 128:
                self.codegen._inertia_call_arg_complex_stack_binding_inline_refused_8616 = (
                    int(getattr(self.codegen, "_inertia_call_arg_complex_stack_binding_inline_refused_8616", 0) or 0) + 1
                )
                replacement = None
        if replacement is None:
            replacement = self._stack_cvar_for_offset(displacement, allow_best_match=False)
        return replacement

    def _transform_bp_slot_node_8616(
        self,
        node: StructuredAstValue,
        *,
        stack_bindings: StructuredAstValue,
        pointer_arg: bool,
        normalize_stack_slot_value_arithmetic: bool,
        debug_materialization: bool,
        replacement_cache: dict[int, StructuredAstValue],
    ) -> tuple[StructuredAstValue, bool]:
        """Normalize one BP stack-slot load; return ``(node, replaced)``."""
        displacement = _match_bp_stack_load_8616(node, self.project)
        if displacement is None:
            displacement = self._plain_bp_stack_load_offset(node)
        if displacement is None and normalize_stack_slot_value_arithmetic:
            plain_slot_offset = self._plain_stack_slot_address_offset(node)
            if (
                isinstance(plain_slot_offset, int)
                and pointer_arg
                and (
                    self._node_contains_placeholder_stack_8616(node)
                    or self._node_contains_stable_named_stack_value_8616(node)
                )
            ):
                displacement = plain_slot_offset
        if displacement is None:
            return node, False
        replacement = self._resolve_bp_slot_replacement_8616(displacement, stack_bindings)
        if replacement is None:
            return node, False
        if debug_materialization:
            log.warning(
                "[call-bp-normalize] function=%#x displacement=%r pointer_arg=%s node=%r replacement=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                displacement,
                pointer_arg,
                node,
                replacement,
            )
        key = int(displacement)
        cached = replacement_cache.get(key)
        if cached is None:
            cached = self._clone_c_ast_tree(replacement)
            replacement_cache[key] = cached
        return cached, True

    def _normalize_bp_slot_value_arg_8616(self,
        expr: StructuredAstValue,
        *,
        stack_bindings: StructuredAstValue = None,
        pointer_arg: bool = False,
        normalize_stack_slot_value_arithmetic: bool = True,
    ) -> tuple[StructuredAstValue, int]:
        replacements = 0
        replacement_cache: dict[int, StructuredAstValue] = {}
        debug_materialization = bool(os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"))
        node_has_stack_value_carrier = self._node_contains_stable_named_stack_value_8616(
            expr
        ) or self._expr_contains_plain_register_uses(expr)

        def transform(node: StructuredAstValue) -> StructuredAstValue:
            """Normalize BP stack-slot loads into proven argument expressions."""
            nonlocal replacements
            new_node, replaced = self._transform_bp_slot_node_8616(
                node,
                stack_bindings=stack_bindings,
                pointer_arg=pointer_arg,
                normalize_stack_slot_value_arithmetic=normalize_stack_slot_value_arithmetic,
                debug_materialization=debug_materialization,
                replacement_cache=replacement_cache,
            )
            if replaced:
                replacements += 1
            return new_node

        rewritten = self._clone_c_ast_tree(expr)
        for _ in range(3):
            changed = False
            new_root = transform(rewritten)
            if new_root is not rewritten:
                rewritten = new_root
                changed = True
            if _replace_c_children_8616(rewritten, transform):
                changed = True
            if not changed:
                collapsed = self._normalize_stack_plus_const_base_8616(
                    rewritten,
                    pointer_arg=pointer_arg,
                    normalize_stack_slot_value_arithmetic=normalize_stack_slot_value_arithmetic,
                    node_has_stack_value_carrier=node_has_stack_value_carrier,
                )
                if collapsed is not None and collapsed is not rewritten:
                    rewritten = collapsed
                    changed = True
            if not changed:
                break
        return rewritten, replacements

    def _materialize_pointer_arg_8616(self,
        expr: StructuredAstValue, *, target_name: str, arg_index: int, force_pointer: bool = False
    ) -> tuple[StructuredAstValue | None, bool]:
        if call_argument_has_materialized_object_address_8616(expr):
            return expr, False
        if not force_pointer and not _callee_expects_pointer_arg_8616(
            target_name,
            arg_index,
            project=self.project,
            cod_path_hint=self.cod_path_hint,
        ):
            return expr, False
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CFunctionCall) and getattr(node, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
            return expr, False
        if isinstance(node, CUnaryOp) and getattr(node, "op", None) in {"Reference", "AddressOf"}:
            return expr, False
        if isinstance(node, structured_c.CVariable):
            variable_type = node.variable_type
            if isinstance(variable_type, SimTypePointer) and isinstance(
                getattr(variable_type, "pts_to", None), SimTypeFunction
            ):
                self.codegen._inertia_fnptr_call_arg_far_wrap_refused_typed_local_8616 = (
                    int(getattr(self.codegen, "_inertia_fnptr_call_arg_far_wrap_refused_typed_local_8616", 0) or 0) + 1
                )
                return expr, False
            offset = self._stack_offset_from_cvar_8616(node)
            if isinstance(offset, int) and self._function_pointer_stack_store_slot_has_type_evidence_8616(offset):
                self.codegen._inertia_fnptr_call_arg_far_wrap_refused_typed_slot_8616 = (
                    int(getattr(self.codegen, "_inertia_fnptr_call_arg_far_wrap_refused_typed_slot_8616", 0) or 0) + 1
                )
                return expr, False
        ds_expr = self._segment_register_expr("ds")
        if ds_expr is None:
            return None, False
        target = str(
            getattr(getattr(self.codegen, "project", None), "_inertia_c_target", "portable-flat") or "portable-flat"
        )
        return consume_near_pointer_argument_value_8616(
            expr, ds_expr, codegen=self.codegen, c_target=target,
        )

    def _global_index_source_shape_8616(self,
        source_kind: StructuredAstValue, source_value: StructuredAstValue, source: StructuredAstValue
    ) -> bool:
        return (
            source_kind == "global_index"
            and isinstance(source_value, int)
            and len(source) == 5
            and isinstance(source[2], int)
            and isinstance(source[3], tuple)
            and isinstance(source[4], tuple)
        )

    def _seg_indirect_source_shape_8616(self,
        source_kind: StructuredAstValue, source_value: StructuredAstValue, source: StructuredAstValue
    ) -> bool:
        return (
            source_kind == "seg_indirect"
            and isinstance(source_value, str)
            and source_value in {"cs", "ds", "es", "ss"}
            and len(source) == 4
            and isinstance(source[2], int)
            and isinstance(source[3], tuple)
        )

    def _direct_expr_ret_reg_8616(self, source: StructuredAstValue) -> StructuredAstValue | None:
        reg_name = source[2]
        if not isinstance(reg_name, str) or reg_name.lower() not in {"ax", "dx"}:
            return None
        return self._register_expr_from_name_8616(reg_name.lower())

    def _direct_expr_imm_8616(self,
        source_value: StructuredAstValue,
        *,
        call_name: str | None,
        arg_index: int,
        materialize_pointer: bool,
    ) -> StructuredAstValue | None:
        expr = structured_c.CConstant(source_value, _word_type_8616(self.project), codegen=self.codegen)
        if not materialize_pointer:
            return expr
        pointer_expr, _pointer_materialized = self._materialize_pointer_arg_8616(
            expr,
            target_name=call_name or "",
            arg_index=arg_index,
        )
        return pointer_expr

    def _direct_expr_extended_kinds_8616(self,
        source: tuple,
        source_kind: StructuredAstValue,
        source_value: StructuredAstValue,
        *,
        call_name: str | None,
        arg_index: int,
        materialize_pointer: bool,
    ) -> StructuredAstValue | None:
        """Build an expression for the composite push-source kinds, or None."""
        if self._global_index_source_shape_8616(source_kind, source_value, source):
            return self._direct_expr_global_index_8616(source, call_name=call_name, arg_index=arg_index)
        if self._seg_indirect_source_shape_8616(source_kind, source_value, source):
            return self._direct_expr_seg_indirect_8616(source, call_name=call_name, arg_index=arg_index)
        if source_kind == "ret_reg" and isinstance(source_value, int) and len(source) >= 3:
            return self._direct_expr_ret_reg_8616(source)
        if source_kind == "imm" and isinstance(source_value, int):
            return self._direct_expr_imm_8616(
                source_value, call_name=call_name, arg_index=arg_index,
                materialize_pointer=materialize_pointer,
            )
        if (
            source_kind == "expr"
            and len(source) == 3
            and isinstance(source_value, tuple)
            and isinstance(source[2], tuple)
        ):
            return self._direct_expr_expr_ops_8616(source, call_name=call_name, arg_index=arg_index, materialize_pointer=materialize_pointer)
        return None

    def _direct_expr_from_push_source_8616(self,
        source: StructuredAstValue,
        *,
        call_name: str | None,
        arg_index: int,
        materialize_pointer: bool = True,
        force_pointer_arg: bool = False,
    ) -> StructuredAstValue | None:
        """Build a C expression from structured push-source evidence."""
        if not isinstance(source, tuple) or len(source) < 2:
            return None
        source_kind, source_value = source[0], source[1]
        if source_kind == "bp" and isinstance(source_value, int):
            return self._direct_expr_bp_value_8616(source, call_name=call_name, arg_index=arg_index, materialize_pointer=materialize_pointer, force_pointer_arg=force_pointer_arg)
        if source_kind == "bp_addr" and isinstance(source_value, int):
            return self._direct_expr_bp_addr_8616(source)
        if source_kind == "bp_index_addr" and isinstance(source_value, int) and len(source) >= 4:
            return self._direct_expr_bp_index_addr_8616(source, call_name=call_name, arg_index=arg_index)
        if source_kind == "seg" and isinstance(source_value, str):
            seg_expr = self._segment_register_expr(source_value.lower())
            return seg_expr
        if source_kind == CallsitePushSourceKind8616.REGISTER_VALUE.value and isinstance(source_value, str):
            return self._register_expr_from_name_8616(source_value.lower())
        if source_kind == "global" and isinstance(source_value, int):
            return self._direct_expr_global_value_8616(source)
        return self._direct_expr_extended_kinds_8616(
            source,
            source_kind,
            source_value,
            call_name=call_name,
            arg_index=arg_index,
            materialize_pointer=materialize_pointer,
        )
        return None

    def _direct_expr_bp_value_8616(self,
        source: StructuredAstValue,
        *,
        call_name: str | None,
        arg_index: int,
        materialize_pointer: bool,
        force_pointer_arg: bool,
    ) -> StructuredAstValue | None:
        """Materialize a bp value push source."""
        source_value = source[1]
        source_width = source[2] if len(source) >= 3 and isinstance(source[2], int) else None
        if source_value > 0 and source_value % 2:
            base_expr = self._existing_containing_stack_cvar_8616(source_value - 1, size_hint=2)
            if base_expr is not None:
                base_expr = _ensure_c_expr_type_has_arch_8616(self.project, base_expr)
                return CBinaryOp(
                    "Shr",
                    base_expr,
                    structured_c.CConstant(8, _word_type_8616(self.project), codegen=self.codegen),
                    codegen=self.codegen,
                )
        expr = (
            stack_cvar_for_stable_ss_linear_access_8616(
                self.codegen, RealModeLinearStackAccess8616(source_value, source_width)
            )
            if source_width is not None
            else self._stack_cvar_for_offset(source_value, allow_best_match=False)
        )
        expr = _ensure_c_expr_type_has_arch_8616(self.project, expr)
        if expr is None or not materialize_pointer:
            return expr
        pointer_expr, _pointer_materialized = self._materialize_pointer_arg_8616(
            expr,
            target_name=call_name or "",
            arg_index=arg_index,
            force_pointer=force_pointer_arg,
        )
        return pointer_expr
    def _direct_expr_bp_addr_8616(self,
        source: StructuredAstValue,
    ) -> StructuredAstValue | None:
        """Materialize a bp addr push source."""
        source_value = source[1]
        expr = self._stack_cvar_for_offset(
            source_value,
            size_hint=1,
            allow_best_match=False,
        )
        if expr is None:
            return None
        expr = self._sanitize_exact_negative_bp_call_arg_cvar_8616(expr, source_value)
        expr = _ensure_c_expr_type_has_arch_8616(self.project, expr)
        return CUnaryOp("Reference", expr, codegen=self.codegen)
    def _direct_expr_bp_index_addr_8616(self,
        source: StructuredAstValue,
        *, call_name: str | None, arg_index: int
    ) -> StructuredAstValue | None:
        """Materialize a bp index addr push source."""
        source_value = source[1]
        index_reg = source[2]
        scale = source[3]
        if not isinstance(index_reg, str) or not isinstance(scale, int):
            return None
        expr = self._stack_cvar_for_offset(
            source_value,
            size_hint=1,
            allow_best_match=False,
        )
        index_source = source[4] if len(source) >= 5 and isinstance(source[4], tuple) else None
        index_expr = (
            self._direct_expr_from_push_source_8616(
                index_source,
                call_name=call_name,
                arg_index=arg_index,
                materialize_pointer=False,
            )
            if index_source is not None
            else self._register_expr_from_name_8616(index_reg)
        )
        if expr is None or index_expr is None:
            return None
        expr = self._sanitize_exact_negative_bp_call_arg_cvar_8616(expr, source_value)
        expr = _ensure_c_expr_type_has_arch_8616(self.project, expr)
        index_expr = _ensure_c_expr_type_has_arch_8616(self.project, index_expr)
        if scale != 1:
            index_expr = CBinaryOp(
                "Mul",
                index_expr,
                structured_c.CConstant(scale, _word_type_8616(self.project), codegen=self.codegen),
                codegen=self.codegen,
            )
        return CBinaryOp(
            "Add",
            CUnaryOp("Reference", expr, codegen=self.codegen),
            index_expr,
            codegen=self.codegen,
        )
    def _direct_expr_global_value_8616(self,
        source: StructuredAstValue,
    ) -> StructuredAstValue | None:
        """Materialize a global value push source."""
        source_value = source[1]
        width = source[2] if len(source) >= 3 else 2
        if isinstance(width, int):
            direct_ref = self.direct_global_arg_refs_by_offset.get((source_value & 0xFFFF, width))
            if direct_ref is not None:
                direct_expr = _make_direct_global_symbol_expr_8616(self.codegen, direct_ref, width)
                if direct_expr is not None:
                    return direct_expr
        ds_expr = self._segment_register_expr("ds")
        if ds_expr is None:
            return None
        helper = "SEG_U8" if width == 1 else "SEG_U16" if width == 2 else "SEG_U32" if width == 4 else None
        if helper is None:
            return None
        return structured_c.CFunctionCall(
            helper,
            None,
            [ds_expr, structured_c.CConstant(source_value, _word_type_8616(self.project), codegen=self.codegen)],
            codegen=self.codegen,
        )
    def _direct_expr_global_index_8616(self,
        source: StructuredAstValue,
        *, call_name: str | None, arg_index: int
    ) -> StructuredAstValue | None:
        """Materialize a global index push source."""
        source_value = source[1]
        ds_expr = self._segment_register_expr("ds")
        if ds_expr is None:
            return None
        width = int(source[2])
        helper = "SEG_U8" if width == 1 else "SEG_U16" if width == 2 else "SEG_U32" if width == 4 else None
        if helper is None:
            return None
        index_expr = self._direct_expr_from_push_source_8616(
            source[3],
            call_name=call_name,
            arg_index=arg_index,
            materialize_pointer=False,
        )
        if index_expr is None:
            return None
        index_expr = materialize_call_argument_operations_8616(
            index_expr,
            source[4],
            resolve_source=lambda nested_source: self._direct_expr_from_push_source_8616(
                nested_source,
                call_name=call_name,
                arg_index=arg_index,
                materialize_pointer=False,
            ),
            bind_type=lambda expression: _ensure_c_expr_type_has_arch_8616(self.project, expression),
            word_type=_word_type_8616(self.project),
            signed_word_type=_type_with_project_arch_8616(self.project, SimTypeShort(True)),
            codegen=self.codegen,
        )
        if index_expr is None:
            return None
        index_expr = _ensure_c_expr_type_has_arch_8616(self.project, index_expr)
        offset_expr = CBinaryOp(
            "Add",
            structured_c.CConstant(source_value, _word_type_8616(self.project), codegen=self.codegen),
            index_expr,
            codegen=self.codegen,
        )
        return structured_c.CFunctionCall(
            helper,
            None,
            [ds_expr, offset_expr],
            codegen=self.codegen,
        )
    def _direct_expr_seg_indirect_8616(self,
        source: StructuredAstValue,
        *, call_name: str | None, arg_index: int
    ) -> StructuredAstValue | None:
        """Materialize a seg indirect push source."""
        source_value = source[1]
        segment_expr = self._segment_register_expr(source_value)
        if segment_expr is None:
            return None
        width = int(source[2])
        helper = "SEG_U8" if width == 1 else "SEG_U16" if width == 2 else "SEG_U32" if width == 4 else None
        if helper is None:
            return None
        address_expr = self._direct_expr_from_push_source_8616(
            source[3],
            call_name=call_name,
            arg_index=arg_index,
            materialize_pointer=False,
        )
        if address_expr is None:
            return None
        address_expr = _ensure_c_expr_type_has_arch_8616(self.project, address_expr)
        return structured_c.CFunctionCall(
            helper,
            None,
            [segment_expr, address_expr],
            codegen=self.codegen,
        )
    def _direct_expr_expr_ops_8616(self,
        source: StructuredAstValue,
        *, call_name: str | None, arg_index: int, materialize_pointer: bool
    ) -> StructuredAstValue | None:
        """Materialize a expr ops push source."""
        source_value = source[1]
        expr = self._direct_expr_from_push_source_8616(
            source_value,
            call_name=call_name,
            arg_index=arg_index,
            materialize_pointer=False,
        )
        if expr is None:
            return None
        expr = materialize_call_argument_operations_8616(
            expr,
            source[2],
            resolve_source=lambda nested_source: self._direct_expr_from_push_source_8616(
                nested_source,
                call_name=call_name,
                arg_index=arg_index,
                materialize_pointer=False,
            ),
            bind_type=lambda expression: _ensure_c_expr_type_has_arch_8616(self.project, expression),
            word_type=_word_type_8616(self.project),
            signed_word_type=_type_with_project_arch_8616(self.project, SimTypeShort(True)),
            codegen=self.codegen,
        )
        if expr is None:
            return None
        if not materialize_pointer:
            return expr
        pointer_expr, _pointer_materialized = self._materialize_pointer_arg_8616(
            expr,
            target_name=call_name or "",
            arg_index=arg_index,
        )
        return pointer_expr

    def _push_source_width_8616(self, source: StructuredAstValue) -> int | None:
        if not isinstance(source, tuple) or len(source) < 2:
            return None
        if len(source) >= 3 and isinstance(source[2], int) and source[2] > 0:
            return int(source[2])
        if source[0] in {
            "bp",
            "bp_addr",
            "bp_index_addr",
            "global",
            "global_index",
            "seg_indirect",
            "imm",
            "expr",
            "ret_reg",
            "seg",
            "ax",
            "bx",
            "cx",
            "dx",
            "di",
            "si",
        }:
            return 2
        return None

    def _push_sources_total_width_8616(self, sources: tuple[StructuredAstValue, ...]) -> int | None:
        if not isinstance(sources, tuple) or not sources:
            return None
        total = 0
        for source in sources:
            width = self._push_source_width_8616(source)
            if not isinstance(width, int):
                return None
            total += width
        return total

    def _prototype_widths_account_for_push_sources_8616(self,
        widths: tuple[int, ...] | None, sources: tuple[StructuredAstValue, ...]
    ) -> bool:
        if not widths or not isinstance(sources, tuple) or not sources:
            return False
        source_total = self._push_sources_total_width_8616(sources)
        return isinstance(source_total, int) and source_total == sum(max(2, int(width)) for width in widths)

    def _logical_arg_count_from_width_evidence_8616(self,
        *,
        known_arg_count: int | None,
        prototype_arg_count: int | None,
        expected_arg_widths: tuple[int, ...] | None,
        push_arg_sources: tuple[StructuredAstValue, ...],
        arity_contract: CallArityContract8616,
    ) -> int | None:
        if not self._prototype_widths_account_for_push_sources_8616(expected_arg_widths, push_arg_sources):
            return None
        if arity_contract.mode is not CallArityMode8616.EXACT and not (
            isinstance(prototype_arg_count, int)
            and prototype_arg_count > 0
            and prototype_arg_count == len(expected_arg_widths or ())
        ):
            return None
        width_count = len(expected_arg_widths or ())
        if width_count <= 0:
            return None
        if isinstance(known_arg_count, int) and known_arg_count == width_count:
            return known_arg_count
        if (
            not isinstance(known_arg_count, int)
            and isinstance(prototype_arg_count, int)
            and prototype_arg_count == width_count
        ):
            return prototype_arg_count
        if (
            arity_contract.mode is not CallArityMode8616.EXACT
            and isinstance(prototype_arg_count, int)
            and prototype_arg_count == width_count
        ):
            return prototype_arg_count
        return None

    def _global_word_source_info_8616(self,
        source: StructuredAstValue,
    ) -> tuple[int, tuple[tuple[str, StructuredAstValue], ...]] | None:
        if not isinstance(source, tuple) or len(source) < 2:
            return None
        source_kind = source[0]
        if source_kind == "global" and isinstance(source[1], int):
            width = source[2] if len(source) >= 3 else 2
            if int(width) != 2:
                return None
            return int(source[1]), ()
        if source_kind == "expr" and len(source) == 3 and isinstance(source[1], tuple) and isinstance(source[2], tuple):
            base = self._global_word_source_info_8616(source[1])
            if base is None:
                return None
            if not all(
                isinstance(op, tuple)
                and len(op) == 2
                and isinstance(op[0], str)
                and (
                    isinstance(op[1], int)
                    or (
                        isinstance(op[1], tuple)
                        and op[0]
                        in {
                            CallsitePushExprOp8616.ADD_SOURCE.value,
                            CallsitePushExprOp8616.ADC_SOURCE.value,
                            CallsitePushExprOp8616.SUB_SOURCE.value,
                            CallsitePushExprOp8616.SBB_SOURCE.value,
                        }
                    )
                )
                for op in source[2]
            ):
                return None
            return base[0], tuple((op[0], op[1]) for op in source[2])
        return None

    def _global_u32_expr_8616(self, low_addr: int) -> StructuredAstValue:
        direct_ref = self.direct_global_arg_refs_by_offset.get((int(low_addr) & 0xFFFF, 4))
        if direct_ref is not None:
            direct_expr = _make_direct_global_symbol_expr_8616(self.codegen, direct_ref, 4)
            if direct_expr is not None:
                return direct_expr
        ds_expr = self._segment_register_expr("ds")
        if ds_expr is None:
            return None
        return structured_c.CFunctionCall(
            "SEG_U32",
            None,
            [ds_expr, structured_c.CConstant(int(low_addr), SimTypeShort(False), codegen=self.codegen)],
            codegen=self.codegen,
        )

    def _combine_word_pair_op_exprs_8616(
        self,
        low_op: StructuredAstValue,
        low_value: StructuredAstValue,
        high_op: StructuredAstValue,
        high_value: StructuredAstValue,
        base: StructuredAstValue,
    ) -> StructuredAstValue | None:
        """Combine the low/high op pair into a 32-bit expression over base."""
        low_rhs = self._global_word_source_info_8616(low_value)
        high_rhs = self._global_word_source_info_8616(high_value)
        if low_rhs is None or high_rhs is None:
            return None
        low_rhs_addr, low_rhs_ops = low_rhs
        high_rhs_addr, high_rhs_ops = high_rhs
        if low_rhs_ops or high_rhs_ops or high_rhs_addr != low_rhs_addr + 2:
            return None
        rhs = self._global_u32_expr_8616(low_rhs_addr)
        if rhs is None:
            return None
        return CBinaryOp(
            "Sub" if low_op == CallsitePushExprOp8616.SUB_SOURCE.value else "Add",
            base,
            rhs,
            codegen=self.codegen,
        )

    def _combine_word_pair_push_sources_8616(self,
        low_source: StructuredAstValue, high_source: StructuredAstValue
    ) -> StructuredAstValue | None:

        if (
            _push_source_is_sign_ext_word_pair_8616(low_source, high_source)
        ):
            low_expr = self._direct_expr_from_push_source_8616(
                low_source,
                call_name=None,
                arg_index=0,
                materialize_pointer=False,
            )
            if low_expr is not None:
                return CTypeCast(None, _summary_type_8616(self.project, 4), low_expr, codegen=self.codegen)

        caller_stack_object = exact_caller_stack_object_for_word_pair_8616(
            low_source,
            high_source,
            self.caller_stack_objects,
        )
        if caller_stack_object is not None:
            return self._stack_cvar_for_offset(
                caller_stack_object.offset,
                size_hint=caller_stack_object.width,
                allow_best_match=False,
            )

        sign_ext_high_source = self._sign_ext_source_8616(high_source)
        sign_ext_low_source = self._sign_ext_source_8616(low_source)
        if sign_ext_high_source is not None and isinstance(low_source, tuple) and low_source == sign_ext_high_source[1]:
            base_expr = self._direct_expr_from_push_source_8616(
                low_source,
                call_name=None,
                arg_index=0,
                materialize_pointer=False,
            )
            if base_expr is not None:
                return CTypeCast(None, _summary_type_8616(self.project, 4), base_expr, codegen=self.codegen)
        if sign_ext_low_source is not None and isinstance(high_source, tuple) and high_source == sign_ext_low_source[1]:
            base_expr = self._direct_expr_from_push_source_8616(
                high_source,
                call_name=None,
                arg_index=0,
                materialize_pointer=False,
            )
            if base_expr is not None:
                return CTypeCast(None, _summary_type_8616(self.project, 4), base_expr, codegen=self.codegen)

        if (
            _push_source_is_immediate_word_pair_8616(low_source, high_source)
        ):
            value = (int(low_source[1]) & 0xFFFF) | ((int(high_source[1]) & 0xFFFF) << 16)
            return structured_c.CConstant(value, _summary_type_8616(self.project, 4), codegen=self.codegen)

        return self._combine_global_word_pair_8616(low_source, high_source)


    def _combine_global_word_pair_8616(self,
        low_source: StructuredAstValue, high_source: StructuredAstValue
    ) -> StructuredAstValue | None:
        low_info = self._global_word_source_info_8616(low_source)
        high_info = self._global_word_source_info_8616(high_source)
        if low_info is None or high_info is None:
            return None
        low_addr, low_ops = low_info
        high_addr, high_ops = high_info
        if high_addr != low_addr + 2:
            return None
        base = self._global_u32_expr_8616(low_addr)
        if base is None:
            return None
        if not low_ops and not high_ops:
            return base
        if len(low_ops) != 1 or len(high_ops) != 1:
            return None
        low_op, low_value = low_ops[0]
        high_op, high_value = high_ops[0]
        if (
            low_op == CallsitePushExprOp8616.SUB_SOURCE.value and high_op == CallsitePushExprOp8616.SBB_SOURCE.value
        ) or (low_op == CallsitePushExprOp8616.ADD_SOURCE.value and high_op == CallsitePushExprOp8616.ADC_SOURCE.value):
            return self._combine_word_pair_op_exprs_8616(low_op, low_value, high_op, high_value, base)
        if high_value != 0:
            return None
        if low_op == CallsitePushExprOp8616.SUB.value and high_op == CallsitePushExprOp8616.SBB.value:
            return CBinaryOp(
                "Sub",
                base,
                structured_c.CConstant(low_value, _summary_type_8616(self.project, 4), codegen=self.codegen),
                codegen=self.codegen,
            )
        if low_op == CallsitePushExprOp8616.ADD.value and high_op == CallsitePushExprOp8616.ADC.value:
            return CBinaryOp(
                "Add",
                base,
                structured_c.CConstant(low_value, _summary_type_8616(self.project, 4), codegen=self.codegen),
                codegen=self.codegen,
            )
        return None

    def _combine_word_pair_scalar_arg_8616(self,
        low_expr: StructuredAstValue,
        high_expr: StructuredAstValue,
        low_source: StructuredAstValue = None,
        high_source: StructuredAstValue = None,
    ) -> StructuredAstValue:
        combined_from_sources = self._combine_word_pair_push_sources_8616(low_source, high_source)
        if combined_from_sources is not None:
            return combined_from_sources
        if (
            _push_source_is_global_word_pair_8616(low_source, high_source)
        ):
            ds_expr = self._segment_register_expr("ds")
            if ds_expr is not None:
                return structured_c.CFunctionCall(
                    "SEG_U32",
                    None,
                    [ds_expr, structured_c.CConstant(int(low_source[1]), SimTypeShort(False), codegen=self.codegen)],
                    codegen=self.codegen,
                )

        long_type = _summary_type_8616(self.project, 4)
        high_long = CTypeCast(None, long_type, self._clone_c_ast_tree(high_expr), codegen=self.codegen)
        low_long = CTypeCast(None, long_type, self._clone_c_ast_tree(low_expr), codegen=self.codegen)
        shifted_high = CBinaryOp(
            "Shl",
            high_long,
            structured_c.CConstant(16, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )
        return CBinaryOp("Or", low_long, shifted_high, codegen=self.codegen)

    def _logical_args_from_push_sources_by_expected_widths_8616(self,
        ordered_sources: list[StructuredAstValue],
        *,
        expected_arg_widths: tuple[int, ...] | None,
        call_name: str | None,
    ) -> list[StructuredAstValue] | None:
        if not expected_arg_widths or not ordered_sources:
            return None
        logical_args: list[StructuredAstValue] = []
        source_idx = 0
        for arg_idx, width in enumerate(expected_arg_widths):
            width = max(2, int(width))
            word_count = 2 if width == 4 else 1 if width <= 2 else 0
            if word_count <= 0 or source_idx + word_count > len(ordered_sources):
                return None
            if word_count == 1:
                expr = self._direct_expr_from_push_source_8616(
                    ordered_sources[source_idx],
                    call_name=call_name,
                    arg_index=arg_idx,
                )
                if expr is None:
                    return None
                logical_args.append(expr)
                source_idx += 1
                continue
            combined = self._combine_word_pair_push_sources_8616(
                ordered_sources[source_idx],
                ordered_sources[source_idx + 1],
            )
            if combined is None:
                return None
            logical_args.append(combined)
            source_idx += 2
        if source_idx != len(ordered_sources):
            return None
        return logical_args

    def _group_scalar_args_by_expected_widths_8616(self,
        values: list[StructuredAstValue],
        *,
        expected_arg_widths: tuple[int, ...] | None,
        push_sources: tuple[StructuredAstValue, ...] = (),
    ) -> list[StructuredAstValue] | None:
        if not expected_arg_widths or len(values) <= len(expected_arg_widths):
            return None
        grouped: list[StructuredAstValue] = []
        value_idx = 0
        for width in expected_arg_widths:
            width = max(2, int(width))
            word_count = 2 if width == 4 else 1 if width <= 2 else 0
            if word_count <= 0 or value_idx + word_count > len(values):
                return None
            if word_count == 1:
                grouped.append(self._clone_c_ast_tree(values[value_idx]))
                value_idx += 1
                continue
            low_expr = values[value_idx]
            high_expr = values[value_idx + 1]
            low_source = push_sources[value_idx] if value_idx < len(push_sources) else None
            high_source = push_sources[value_idx + 1] if value_idx + 1 < len(push_sources) else None
            grouped.append(self._combine_word_pair_scalar_arg_8616(low_expr, high_expr, low_source, high_source))
            value_idx += 2
        if value_idx != len(values):
            return None
        return grouped

    def _node_contains_stable_named_stack_value_8616(self, node: StructuredAstValue, *, max_nodes: int = 1024) -> bool:
        stack = [node]
        seen: set[int] = set()
        visited = 0
        while stack:
            current = stack.pop()
            while isinstance(current, CTypeCast):
                current = current.expr
            marker = id(current)
            if marker in seen:
                continue
            seen.add(marker)
            visited += 1
            if visited > max_nodes:
                return False
            if self._is_stable_named_stack_value_expr_8616(current):
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
                child = getattr(current, attr, None)
                if child is not None:
                    stack.append(child)
            for attr in ("args", "operands"):
                items = getattr(current, attr, None)
                if isinstance(items, (list, tuple)):
                    stack.extend(item for item in items if item is not None)
        return False

    def _placeholder_stack_node_hit_8616(self, current: StructuredAstValue) -> bool:
        if isinstance(current, structured_c.CFakeVariable) and getattr(current, "name", None) == "stack_base":
            return True
        if isinstance(current, structured_c.CVariable):
            variable = current.variable
            name = getattr(variable, "name", None) or current.name
            if name == "stack_base":
                return True
            if (
                isinstance(variable, SimStackVariable)
                and isinstance(name, str)
                and name.startswith(("arg_", "s_", "stack_", "vvar_", "tmp_", "ir_"))
            ):
                return True
        return self._is_virtual_dirty_expr_8616(current)

    def _placeholder_stack_expand_8616(self, current: StructuredAstValue, stack: list[StructuredAstValue]) -> None:
        """Push the child nodes of ``current`` onto the placeholder scan stack."""
        for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
            child = getattr(current, attr, None)
            if child is not None:
                stack.append(child)
        for attr in ("args", "operands"):
            items = getattr(current, attr, None)
            if isinstance(items, (list, tuple)):
                stack.extend(item for item in items if item is not None)

    def _node_contains_placeholder_stack_8616(self, node: StructuredAstValue, *, max_nodes: int = 1024) -> bool:
        if isinstance(node, (tuple, list)):
            return any(self._node_contains_placeholder_stack_8616(item, max_nodes=max_nodes) for item in node)
        stack = [node]
        seen: set[int] = set()
        visited = 0
        while stack:
            current = stack.pop()
            while isinstance(current, CTypeCast):
                current = current.expr
            marker = id(current)
            if marker in seen:
                continue
            seen.add(marker)
            visited += 1
            if visited > max_nodes:
                return True
            if self._placeholder_stack_node_hit_8616(current):
                return True
            self._placeholder_stack_expand_8616(current, stack)
        return False

    def _debug_expr_variable_8616(self, node: StructuredAstValue) -> str:
        variable = node.variable
        name = getattr(variable, "name", None) or node.name or "var"
        offset = getattr(variable, "offset", None)
        if isinstance(variable, SimStackVariable) and isinstance(offset, int):
            return f"{name}@{offset}:{variable.size}"
        reg = getattr(variable, "reg", None)
        if isinstance(variable, SimRegisterVariable) and reg is not None:
            return f"{name}#{reg}"
        return name

    def _debug_expr_8616(self, node: StructuredAstValue, seen: set[int] | None = None, depth: int = 0) -> StructuredAstValue:
        if seen is None:
            seen = set()
        if depth > 64:
            return "<depth-limit>"
        marker = id(node)
        if marker in seen:
            return "<cycle>"
        if self._is_c_ast_node(node):
            seen.add(marker)
        if isinstance(node, CTypeCast):
            return f"Cast({self._debug_expr_8616(node.expr, seen, depth + 1)})"
        if isinstance(node, structured_c.CVariable):
            return self._debug_expr_variable_8616(node)
        if isinstance(node, structured_c.CConstant):
            return repr(node.value)
        composite = self._debug_expr_composite_8616(node, seen, depth)
        if composite is not None:
            return composite
        return node.__class__.__name__

    def _debug_expr_composite_8616(self, node: StructuredAstValue, seen: set[int], depth: int) -> StructuredAstValue:
        """Render composite C AST nodes for debug output, or None when unmatched."""
        if isinstance(node, structured_c.CIndexedVariable):
            return (
                f"Index({self._debug_expr_8616(node.variable, seen, depth + 1)},"
                f"{self._debug_expr_8616(node.index, seen, depth + 1)})"
            )
        if isinstance(node, CUnaryOp):
            return f"{node.op}({self._debug_expr_8616(node.operand, seen, depth + 1)})"
        if isinstance(node, CBinaryOp):
            return f"{node.op}({self._debug_expr_8616(node.lhs, seen, depth + 1)},{self._debug_expr_8616(node.rhs, seen, depth + 1)})"
        if isinstance(node, CFunctionCall):
            name = node.callee_target or getattr(node.callee_func, "name", None) or "call"
            return f"{name}({','.join(self._debug_expr_8616(arg, seen, depth + 1) for arg in (node.args or ()))})"
        return None

    def _call_arg_is_pointer_shaped_8616(self, node: StructuredAstValue) -> bool:
        """Return whether an existing call argument is already pointer-shaped."""
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CFunctionCall):
            return node.callee_target in {"SEG_PTR", "MK_FP"}
        return isinstance(node, CUnaryOp) and getattr(node, "op", None) in {"Reference", "AddressOf"}

    def _linear_mul_offset_key_8616(self, node: StructuredAstValue) -> StructuredAstValue | None:
        lhs_mul_const = self._constant_int_value_8616(node.lhs)
        rhs_mul_const = self._constant_int_value_8616(node.rhs)
        if lhs_mul_const is not None:
            rhs_key = self._linear_offset_key_8616(node.rhs)
            if rhs_key is None:
                return None
            rhs_base, rhs_scale, rhs_var = rhs_key
            return ((rhs_base * lhs_mul_const) & 0xFFFF, rhs_scale * lhs_mul_const, rhs_var)
        if rhs_mul_const is not None:
            lhs_key = self._linear_offset_key_8616(node.lhs)
            if lhs_key is None:
                return None
            lhs_base, lhs_scale, lhs_var = lhs_key
            return ((lhs_base * rhs_mul_const) & 0xFFFF, lhs_scale * rhs_mul_const, lhs_var)
        return None

    def _linear_offset_key_binop_8616(self, node: StructuredAstValue) -> StructuredAstValue | None:
        """Affine-offset key for a binary-op node."""
        op = node.op
        lhs_key = self._linear_offset_key_8616(node.lhs)
        rhs_key = self._linear_offset_key_8616(node.rhs)
        if op == "Add" and lhs_key is not None and rhs_key is not None:
            return _linear_add_offset_key_8616(lhs_key, rhs_key)
        if op == "Sub" and lhs_key is not None and rhs_key is not None:
            lhs_const, lhs_scale, lhs_var = lhs_key
            rhs_const, rhs_scale, rhs_var = rhs_key
            if rhs_var is None:
                return ((lhs_const - rhs_const) & 0xFFFF, lhs_scale, lhs_var)
            if lhs_var == rhs_var:
                return ((lhs_const - rhs_const) & 0xFFFF, lhs_scale - rhs_scale, lhs_var)
            return None
        if op == "Shl":
            shift = self._constant_int_value_8616(node.rhs)
            lhs_key = self._linear_offset_key_8616(node.lhs)
            if shift is None or lhs_key is None or shift < 0 or shift > 4:
                return None
            lhs_const, lhs_scale, lhs_var = lhs_key
            multiplier = 1 << shift
            return ((lhs_const * multiplier) & 0xFFFF, lhs_scale * multiplier, lhs_var)
        if op == "Mul":
            return self._linear_mul_offset_key_8616(node)
        return None


    def _linear_offset_key_8616(self,
        node: StructuredAstValue,
    ) -> tuple[int, int, StructuredAstValue | None] | None:
        """Return a simple affine offset key `(constant, scale, variable_key)`."""
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, structured_c.CConstant):
            value = node.value
            return (int(value) & 0xFFFF, 0, None) if isinstance(value, int) else None
        if isinstance(node, structured_c.CVariable):
            variable = node.variable
            if isinstance(variable, SimStackVariable):
                offset = call_argument_stack_variable_offset_8616(self.codegen, node)
                if offset is None:
                    offset = variable.offset
                return (0, 1, ("stack", int(offset))) if isinstance(offset, int) else None
            return None
        if isinstance(node, CBinaryOp):
            return self._linear_offset_key_binop_8616(node)
        return None

    def _pointer_ref_offset_key_8616(self,
        node: StructuredAstValue,
    ) -> tuple[int, int, StructuredAstValue | None] | None:
        operand = node.operand
        while isinstance(operand, CTypeCast):
            operand = operand.expr
        if isinstance(operand, CIndexedVariable):
            base = operand.variable
            if not isinstance(base, structured_c.CVariable):
                return None
            variable = base.variable
            if not isinstance(variable, SimMemoryVariable):
                return None
            addr = variable.addr
            width = variable.size
            if not isinstance(addr, int) or not isinstance(width, int) or width <= 0:
                return None
            index_key = self._linear_offset_key_8616(operand.index)
            if index_key is None:
                return None
            index_const, index_scale, index_var = index_key
            return ((addr + index_const * width) & 0xFFFF, index_scale * width, index_var)
        if isinstance(operand, structured_c.CVariable):
            variable = operand.variable
            if isinstance(variable, SimMemoryVariable):
                addr = variable.addr
                return (int(addr) & 0xFFFF, 0, None) if isinstance(addr, int) else None
            if isinstance(variable, SimStackVariable):
                return self._linear_offset_key_8616(operand)
        return self._linear_offset_key_8616(node)

    def _pointer_offset_key_8616(self,
        node: StructuredAstValue,
    ) -> tuple[int, int, StructuredAstValue | None] | None:
        """Return the linear offset addressed by a pointer-shaped call argument."""
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CFunctionCall) and getattr(node, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
            args = _boundary_tuple_8616(node.args or ())
            if len(args) != 2:
                return None
            return self._linear_offset_key_8616(args[1])
        if isinstance(node, CUnaryOp) and getattr(node, "op", None) in {"Reference", "AddressOf"}:
            return self._pointer_ref_offset_key_8616(node)
        return self._linear_offset_key_8616(node)

    def _pointer_offset_keys_match_8616(self,
        actual_args: tuple[StructuredAstValue, ...],
        expected_args: tuple[StructuredAstValue, ...],
    ) -> bool:
        """Return whether actual pointer arguments address the expected offsets."""
        if len(actual_args) != len(expected_args) or not actual_args:
            return False
        actual_keys = tuple(self._pointer_offset_key_8616(arg) for arg in actual_args)
        expected_keys = tuple(self._pointer_offset_key_8616(arg) for arg in expected_args)
        return all(key is not None for key in actual_keys) and actual_keys == expected_keys

    def _stack_address_base_offset_8616(self, node: StructuredAstValue) -> int | None:
        """Return one pointer expression's proven machine-BP base coordinate."""
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, structured_c.CVariable):
            offset: object = call_argument_stack_variable_offset_8616(self.codegen, node)
            return offset if isinstance(offset, int) and not isinstance(offset, bool) else None
        if isinstance(node, CIndexedVariable):
            return self._stack_address_base_offset_8616(node.variable)
        if isinstance(node, CUnaryOp) and node.op in {"Reference", "AddressOf"}:
            return self._stack_address_base_offset_8616(node.operand)
        if isinstance(node, CBinaryOp) and node.op in {"Add", "Sub"}:
            lhs_offset = self._stack_address_base_offset_8616(node.lhs)
            if lhs_offset is not None:
                return lhs_offset
            if node.op == "Add":
                return self._stack_address_base_offset_8616(node.rhs)
        return None

    def _exact_stack_address_source_mismatch_8616(self,
        actual_args: tuple[StructuredAstValue, ...],
        ordered_sources: tuple[StructuredAstValue, ...] | list[StructuredAstValue],
    ) -> bool:
        """Return whether typed stack-address evidence rejects an existing argument."""
        for actual_arg, source in zip(actual_args, ordered_sources, strict=False):
            if not call_argument_source_requires_exact_address_identity_8616(source):
                continue
            if not isinstance(source, tuple) or len(source) < 2 or not isinstance(source[1], int):
                continue
            if self._stack_address_base_offset_8616(actual_arg) != int(source[1]):
                return True
        return False

    def _arg_contains_runtime_segment_access_8616(self, node: StructuredAstValue) -> bool:
        for raw in (node, *_iter_c_nodes_deep_8616(node)):
            current = raw
            while isinstance(current, CTypeCast):
                current = current.expr
            if not isinstance(current, CFunctionCall):
                continue
            call_name = _call_node_name_8616(current)
            if isinstance(call_name, str) and call_name.upper() in {"SEG_U8", "SEG_U16", "SEG_U32"}:
                return True
        return False

    def _pointer_arg_quality_8616(self, raw: StructuredAstValue) -> int:
        """Quality score for a pointer-kind argument node."""
        if self._node_contains_placeholder_stack_8616(raw) or self._expr_contains_plain_register_uses(raw):
            return 0
        if isinstance(raw, CFunctionCall) and getattr(raw, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
            return 8
        if isinstance(raw, CUnaryOp) and raw.op == "Reference":
            return 7
        return 2
    def _value_arg_quality_8616(self, raw: StructuredAstValue) -> int:
        """Quality score for a value-kind argument node."""
        if self._node_contains_placeholder_stack_8616(raw):
            return 0
        if self._node_contains_stable_named_stack_value_8616(raw):
            return 8
        if isinstance(raw, structured_c.CConstant):
            return 4
        if isinstance(raw, CFunctionCall) and getattr(raw, "callee_target", None) in {"SEG_PTR", "MK_FP"}:
            return 0
        return 3
    def _arg_semantic_quality_8616(self, arg_name: str | None, arg_index: int, node: StructuredAstValue) -> int:
        kind = _call_arg_semantic_kind_8616(
            arg_name or "",
            arg_index,
            project=self.project,
            cod_path_hint=self.cod_path_hint,
        )
        raw = node
        while isinstance(raw, CTypeCast):
            raw = raw.expr
        if self._arg_contains_runtime_segment_access_8616(raw):
            return 1
        if kind is CallArgSemanticKind8616.POINTER:
            return self._pointer_arg_quality_8616(raw)
        if kind is CallArgSemanticKind8616.VALUE:
            return self._value_arg_quality_8616(raw)
        if self._is_stable_named_stack_value_expr_8616(raw):
            return 6
        if isinstance(raw, structured_c.CConstant):
            return 4
        if isinstance(raw, CFunctionCall):
            return 4
        if self._node_contains_placeholder_stack_8616(raw):
            return 0
        return 2

    def _normalize_materialized_call_args(self,
        rhs_values: list[StructuredAstValue],
        source_indices: list[int],
        statements: list[StructuredAstValue],
        *,
        call_name: str | None = None,
        stack_bindings: dict[int, StructuredAstValue] | None = None,
        preserve_register_arg_indices: set[int] | None = None,
        expected_arg_widths: tuple[int, ...] | None = None,
        push_sources: tuple[StructuredAstValue, ...] = (),
    ) -> list[StructuredAstValue] | None:
        if not rhs_values:
            return None
        debug_materialization = bool(os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"))
        normalized: list[StructuredAstValue] = []
        preserved_register_indices = preserve_register_arg_indices or set()



































































































































































































        grouped_pointer_args = self._group_single_far_pointer_arg_8616(list(rhs_values), call_name=call_name)
        if grouped_pointer_args is not None:
            self.stats.pointer_arg_materialized_count += 1
            if debug_materialization:
                log.warning(
                    "[call-far-pointer] function=%#x target=%s args=%s grouped=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    tuple(self._debug_expr_8616(arg) for arg in rhs_values),
                    tuple(self._debug_expr_8616(arg) for arg in grouped_pointer_args),
                )
            return grouped_pointer_args

        grouped_scalar_args = self._group_scalar_args_by_expected_widths_8616(
            list(rhs_values),
            expected_arg_widths=expected_arg_widths,
            push_sources=push_sources,
        )
        if grouped_scalar_args is not None:
            rhs_values = grouped_scalar_args
            source_indices = [-1] * len(rhs_values)













        if len(source_indices) != len(rhs_values):
            source_indices = [-1] * len(rhs_values)
        resolved_stack_index_arg_indices: set[int] = set()
        for arg_idx, (rhs, source_idx) in enumerate(zip(rhs_values, source_indices, strict=False)):
            ok = self._normalize_rhs_register_arg_8616(
                rhs,
                arg_idx,
                source_idx,
                normalized,
                resolved_stack_index_arg_indices,
                statements,
                stack_bindings,
                preserved_register_indices,
                push_sources,
                rhs_values,
                call_name=call_name,
                debug_materialization=debug_materialization,
            )
            if not ok:
                return None
        for idx, expr in enumerate(tuple(normalized)):
            if not self._postprocess_normalized_arg_8616(
                normalized,
                idx,
                expr,
                source_indices,
                statements,
                push_sources,
                stack_bindings,
                resolved_stack_index_arg_indices,
                call_name=call_name,
                debug_materialization=debug_materialization,
            ):
                return None
        return normalized

    def _rewritten_pointer_arg_ok_8616(self,
        pointer_arg: StructuredAstValue, push_source_matches_stack_index: StructuredAstValue, idx: StructuredAstValue, resolved_stack_index_arg_indices: StructuredAstValue, rewritten: StructuredAstValue,
    ) -> bool:
        """Predicate extracted from a callsite gate."""
        return (
            (
        pointer_arg
        and idx in resolved_stack_index_arg_indices
        and not self._expr_contains_plain_register_uses(rewritten)
        and not self._node_contains_placeholder_stack_8616(rewritten)
    ) or (pointer_arg and push_source_matches_stack_index) or (pointer_arg and self._is_stack_address_index_arg_expr_8616(rewritten))
        )

    def _stale_return_pair_candidate_8616(self,
        lhs: StructuredAstValue, rhs: StructuredAstValue, low_expr: StructuredAstValue, high_expr: StructuredAstValue, seen_destinations: StructuredAstValue,
    ) -> bool:
        """Predicate extracted from a callsite gate."""
        return (
            lhs is not None
    and rhs is not None
    and not isinstance(rhs, CFunctionCall)
    and low_expr is not None
    and high_expr is not None
    and any(self._same_return_destination_8616(lhs, seen_lhs) for seen_lhs in seen_destinations)
    and (
        self._combined_low_high_target(rhs, low_expr, high_expr)
        or self._combined_unknown_low_high_target(rhs, high_expr)
    )
        )

    def _strict_push_source_shape_ok_8616(self,
        push_arg_sources: StructuredAstValue, has_physical_far_pointer_push_sources: StructuredAstValue, has_exact_arithmetic_push_sources: StructuredAstValue, has_instruction_proven_direct_push_sources: StructuredAstValue, expected_arg_count: StructuredAstValue, expected_arg_widths: StructuredAstValue, has_recent_stack_arg_store_evidence: StructuredAstValue,
    ) -> bool:
        """Predicate extracted from a callsite gate."""
        return (
            isinstance(push_arg_sources, tuple)
    and (
        len(push_arg_sources) == expected_arg_count
        or self._prototype_widths_account_for_push_sources_8616(expected_arg_widths, push_arg_sources)
    )
    and any(source is not None for source in push_arg_sources)
    and (
        not has_recent_stack_arg_store_evidence
        or has_physical_far_pointer_push_sources
        or has_exact_arithmetic_push_sources
        or has_instruction_proven_direct_push_sources
    )
        )

    def _normalized_args_probe_gate_8616(self,
        normalized_args: StructuredAstValue, stack_probe_address_seen: StructuredAstValue, stack_probe_seen: StructuredAstValue, typed_stack_probe_fact: StructuredAstValue, typed_stack_probe_materialization: StructuredAstValue,
    ) -> bool:
        """Predicate extracted from a callsite gate."""
        return (
            normalized_args is not None
    and self._all_arg_exprs_are_non_segment_registers(normalized_args)
    and (
        (typed_stack_probe_fact is not None and stack_probe_address_seen and stack_probe_seen)
        or (
            not typed_stack_probe_materialization
            and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
        )
    )
        )

    def _pointer_arg_from_default_shape_8616(self,
        call_name: str | None,
        idx: int,
        normalized: list[StructuredAstValue],
    ) -> bool:
        """Whether the known default arg at ``idx`` is pointer-shaped."""
        default_args = _known_default_args_for_missing_8616(call_name or "", self.codegen)
        default_arg = (
            default_args[idx]
            if default_args is not None and len(default_args) == len(normalized) and len(default_args) > idx
            else None
        )
        return isinstance(default_arg, CFunctionCall) and getattr(
            default_arg, "callee_target", None
        ) in {"SEG_PTR", "MK_FP"}

    def _postprocess_normalized_arg_8616(
        self,
        normalized: list[StructuredAstValue],
        idx: int,
        expr: StructuredAstValue,
        source_indices: list[int],
        statements: list[StructuredAstValue],
        push_sources: tuple[StructuredAstValue, ...],
        stack_bindings: dict[int, StructuredAstValue] | None,
        resolved_stack_index_arg_indices: set[int],
        *,
        call_name: str | None,
        debug_materialization: bool,
    ) -> bool:
        """Post-process one normalized arg: bp-slot values, carriers, pointer materialization."""
        source_idx = source_indices[idx] if idx < len(source_indices) else -1
        prefix = statements[: source_idx + 1] if isinstance(source_idx, int) and source_idx >= 0 else statements
        push_source = push_sources[idx] if isinstance(push_sources, tuple) and idx < len(push_sources) else None
        normalize_stack_slot_value_arithmetic = not self._push_source_has_arithmetic_expr_8616(push_source)
        pointer_arg = _callee_expects_pointer_arg_8616(
            call_name or "",
            idx,
            project=self.project,
            cod_path_hint=self.cod_path_hint,
        )
        if not pointer_arg:
            pointer_arg = self._pointer_arg_from_default_shape_8616(call_name, idx, normalized)
        if pointer_arg and (
            self._is_stack_address_arg_expr_8616(expr)
            or self._is_stack_address_index_arg_expr_8616(expr)
        ):
            normalized[idx] = self._clone_c_ast_tree(expr)
            return True
        rewritten, replacement_count = self._normalize_bp_slot_value_arg_8616(
            expr,
            stack_bindings=stack_bindings,
            pointer_arg=pointer_arg,
            normalize_stack_slot_value_arithmetic=normalize_stack_slot_value_arithmetic,
        )
        if replacement_count:
            self.stats.bp_slot_arg_value_normalized_count += replacement_count
        if self._expr_contains_plain_register_uses(rewritten):
            resolved_rewritten = self._resolve_register_carriers_in_expr(rewritten, prefix)
            if debug_materialization:
                log.warning(
                    "[call-post-bp-resolve] function=%#x target=%s rewritten=%s resolved=%s source_idx=%r",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    self._debug_expr_8616(rewritten),
                    self._debug_expr_8616(resolved_rewritten) if resolved_rewritten is not None else None,
                    source_idx,
                )
            if resolved_rewritten is not None:
                rewritten = self._clone_c_ast_tree(resolved_rewritten)
        push_source_offset = push_source[1] if isinstance(push_source, tuple) and len(push_source) > 1 else None
        push_source_matches_stack_index = (
            isinstance(push_source_offset, int)
            and isinstance(push_source, tuple)
            and self._resolved_stack_index_arg_base_from_evidence_8616(rewritten, push_source) == push_source_offset
        )
        if self._rewritten_pointer_arg_ok_8616(pointer_arg, push_source_matches_stack_index, idx, resolved_stack_index_arg_indices, rewritten):
            pointer_expr, pointer_materialized = rewritten, False
        else:
            pointer_expr, pointer_materialized = self._materialize_pointer_arg_8616(
                rewritten,
                target_name=call_name or "",
                arg_index=idx,
                force_pointer=pointer_arg,
            )
        if pointer_expr is None:
            self._debug_normalize_refuse_8616("pointer-materialization-failed", rewritten, call_name=call_name, debug_materialization=debug_materialization)
            return False
        if pointer_materialized:
            self.stats.pointer_arg_materialized_count += 1
        normalized[idx] = pointer_expr
        return True

    def _default_arg_expects_pointer_8616(self,
        call_name: str | None,
        normalized: list[StructuredAstValue],
        rhs_values: list[StructuredAstValue],
    ) -> bool:
        default_args = _known_default_args_for_missing_8616(call_name or "", self.codegen)
        default_arg = (
            default_args[len(normalized)]
            if (
                default_args is not None
                and len(default_args) == len(rhs_values)
                and len(default_args) > len(normalized)
            )
            else None
        )
        return isinstance(default_arg, CFunctionCall) and getattr(
            default_arg, "callee_target", None
        ) in {"SEG_PTR", "MK_FP"}

    def _source_expr_overrides_rhs_8616(self,
        rhs: StructuredAstValue,
        push_source: StructuredAstValue,
        source_expr: StructuredAstValue,
    ) -> bool:
        rhs_offset = self._stack_offset_from_cvar_8616(rhs)
        source_offset = self._stable_call_source_expr_stack_offset(push_source)
        if self._node_contains_stable_named_stack_value_8616(rhs):
            if source_offset is not None and rhs_offset is not None and rhs_offset != source_offset:
                return True
            return not _same_c_expression_8616(rhs, source_expr)
        if self._expr_contains_plain_register_uses(rhs):
            return False
        return source_offset is not None and rhs_offset is not None and rhs_offset != source_offset

    def _byte_merge_stack_index_ok_8616(self,
        expr: StructuredAstValue,
        byte_merge_resolved: bool,
    ) -> bool:
        byte_merge_stack_index_ok = (
            byte_merge_resolved
            and not self._is_segment_register_value_expr(expr)
            and not self._expr_contains_non_segment_register_uses(expr)
            and not self._node_contains_placeholder_stack_8616(expr)
        )
        byte_helper_stack_index_ok = (
            isinstance(expr, CFunctionCall)
            and getattr(expr, "callee_target", None) == "SEG_U8"
            and not self._expr_contains_non_segment_register_uses(expr)
            and not self._node_contains_placeholder_stack_8616(expr)
        )
        return bool(byte_merge_stack_index_ok or byte_helper_stack_index_ok)

    def _segment_register_rhs_arm_8616(self,
        rhs: StructuredAstValue,
        push_sources: StructuredAstValue,
        normalized: list[StructuredAstValue],
        call_name: str | None,
        debug_materialization: bool,
    ) -> bool | None:
        """Append a lowered segment-register arg; True applied, False refused, None not applicable."""
        if not self._is_segment_register_value_expr(rhs):
            return None
        segment_name = self._segment_register_name_from_expr_8616(rhs)
        lowered_segment = (
            self._lower_proven_segment_push_source_8616(segment_name, push_sources)
            if segment_name is not None
            else None
        )
        if lowered_segment is None:
            self._debug_normalize_refuse_8616("segment-register-rhs", rhs, call_name=call_name, debug_materialization=debug_materialization)
            return False
        normalized.append(lowered_segment)
        return True

    def _pointer_stack_index_rhs_arm_8616(self,
        rhs: StructuredAstValue,
        prefix: StructuredAstValue,
        normalized: list[StructuredAstValue],
        resolved_stack_index_arg_indices: set[int],
        *,
        call_name: str | None,
        debug_materialization: bool,
    ) -> bool:
        """Resolve a pointer stack-index arg; appends and returns True."""
        resolved_stack_index = self._resolve_stack_address_index_arg_expr_8616(rhs, prefix, call_name=call_name, debug_materialization=debug_materialization)
        if resolved_stack_index is not None:
            resolved_stack_index_arg_indices.add(len(normalized))
            normalized.append(resolved_stack_index)
            return True
        normalized.append(self._clone_c_ast_tree(rhs))
        return True

    def _normalize_rhs_register_arg_8616(
        self,
        rhs: StructuredAstValue,
        arg_idx: int,
        source_idx: int,
        normalized: list[StructuredAstValue],
        resolved_stack_index_arg_indices: set[int],
        statements: list[StructuredAstValue],
        stack_bindings: dict[int, StructuredAstValue] | None,
        preserved_register_indices: set[int],
        push_sources: tuple[StructuredAstValue, ...],
        rhs_values: list[StructuredAstValue],
        *,
        call_name: str | None,
        debug_materialization: bool,
    ) -> bool:
        """Normalize one register-carrier rhs into the output arg list."""
        byte_merge_resolved = False
        prefix = statements[: source_idx + 1] if isinstance(source_idx, int) and source_idx >= 0 else statements
        pointer_arg = _callee_expects_pointer_arg_8616(
            call_name or "",
            len(normalized),
            project=self.project,
            cod_path_hint=self.cod_path_hint,
        )
        if not pointer_arg:
            pointer_arg = self._default_arg_expects_pointer_8616(call_name, normalized, rhs_values)
        pointer_stack_index_arg = pointer_arg and self._is_stack_address_index_arg_expr_8616(rhs)
        push_source = (
            push_sources[arg_idx] if isinstance(push_sources, tuple) and arg_idx < len(push_sources) else None
        )
        source_expr = self._stack_call_source_expr_8616(push_source, arg_idx, call_name=call_name)
        if (
            source_expr is not None
            and isinstance(rhs, structured_c.CVariable)
            and self._source_expr_overrides_rhs_8616(rhs, push_source, source_expr)
        ):
            normalized.append(self._clone_c_ast_tree(source_expr))
            return True
        segment_verdict = self._segment_register_rhs_arm_8616(
            rhs, push_sources, normalized, call_name, debug_materialization
        )
        if segment_verdict is not None:
            return segment_verdict
        if arg_idx in preserved_register_indices and self._expr_contains_plain_register_uses(rhs):
            normalized.append(self._clone_c_ast_tree(rhs))
            return True
        if pointer_stack_index_arg:
            return self._pointer_stack_index_rhs_arm_8616(
                rhs, prefix, normalized, resolved_stack_index_arg_indices,
                call_name=call_name, debug_materialization=debug_materialization,
            )
        if not self._expr_contains_plain_register_uses(rhs):
            normalized.append(self._clone_c_ast_tree(rhs))
            return True
        resolved, byte_merge_resolved = self._resolve_register_rhs_chain_8616(
            rhs,
            prefix,
            call_name=call_name,
            debug_materialization=debug_materialization,
            source_idx=source_idx,
        )
        raw_expr = self._clone_c_ast_tree(rhs)
        raw_node = raw_expr
        while isinstance(raw_node, CTypeCast):
            raw_node = raw_node.expr
        if resolved is None and not (
            isinstance(raw_node, CFunctionCall) and getattr(raw_node, "callee_target", None) in {"SEG_PTR", "MK_FP"}
        ):
            self._debug_normalize_refuse_8616("unresolved-register-carrier", rhs, call_name=call_name, debug_materialization=debug_materialization)
            return False
        expr = self._clone_c_ast_tree(resolved) if resolved is not None else raw_expr
        expr = self._normalize_call_helper_offset_8616(
            expr,
            prefix,
            stack_bindings=stack_bindings,
            call_name=call_name,
            debug_materialization=debug_materialization,
            source_idx=source_idx,
        )
        if (
            self._is_segment_register_value_expr(expr) or self._expr_contains_plain_register_uses(expr)
        ) and not self._byte_merge_stack_index_ok_8616(expr, byte_merge_resolved):
            self._debug_normalize_refuse_8616("unresolved-normalized-register", expr, call_name=call_name, debug_materialization=debug_materialization)
            return False
        normalized.append(expr)
        return True

    def _resolve_shr_word_8616(
        self,
        rhs: StructuredAstValue,
        prefix: list[StructuredAstValue],
        *,
        call_name: str | None,
        debug_materialization: bool,
    ) -> StructuredAstValue | None:
        """Resolve `Shr(word, 8)` carriers to their underlying word value."""
        # Byte-split push carriers often materialize as `Shr(word_expr, 8)`.
        # For call-arg recovery we want the underlying 16-bit word value;
        # if that can be resolved, use it instead of failing the whole arg list.
        rhs_node = rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        if isinstance(rhs_node, CBinaryOp) and rhs_node.op == "Shr":
            shift_const = getattr(rhs_node.rhs, "value", None)
            if isinstance(shift_const, int) and shift_const == 8:
                lhs_resolved = self._resolve_register_carriers_in_expr(rhs_node.lhs, prefix)
                if lhs_resolved is None:
                    lhs_resolved = self._recent_dirty_value_rhs(rhs_node.lhs, prefix)
                if lhs_resolved is not None:
                    return lhs_resolved
        elif debug_materialization:
            window_start = max(0, len(prefix) - 6)
            for stmt_idx, stmt in enumerate(prefix[window_start:], start=window_start):
                for assignment in self._iter_assignment_nodes(stmt):
                    lhs, rhs_stmt = self._assignment_lhs_rhs(assignment)
                    if lhs is None or rhs_stmt is None:
                        continue
                    log.warning(
                        "[call-normalize-prefix] function=%#x target=%s stmt_idx=%d lhs=%s rhs=%s memory_lhs=%s",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        call_name,
                        stmt_idx,
                        self._debug_expr_8616(lhs),
                        self._debug_expr_8616(rhs_stmt),
                        self._assignment_lhs_writes_memory(lhs),
                    )
    def _resolve_dirty_rhs_fallback_8616(
        self,
        rhs: StructuredAstValue,
        prefix: list[StructuredAstValue],
        *,
        call_name: str | None,
        debug_materialization: bool,
        source_idx: int,
    ) -> StructuredAstValue | None:
        """Fall back to a recent dirty rhs value when carrier resolution fails."""
        dirty_rhs = self._recent_dirty_value_rhs(rhs, prefix)
        if dirty_rhs is not None:
            if debug_materialization:
                log.warning(
                    "[call-normalize-dirty-fallback] function=%#x target=%s rhs=%s fallback=%s source_idx=%r",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    self._debug_expr_8616(rhs),
                    self._debug_expr_8616(dirty_rhs),
                    source_idx,
                )
            return dirty_rhs
    def _resolve_register_rhs_chain_8616(
        self,
        rhs: StructuredAstValue,
        prefix: list[StructuredAstValue],
        *,
        call_name: str | None,
        debug_materialization: bool,
        source_idx: int,
    ) -> tuple[StructuredAstValue | None, bool]:
        """Resolve a register-carrier rhs via assignment, dirty-rhs, Shr, or byte-merge chains."""
        resolved = self._resolve_register_carriers_in_expr(rhs, prefix)
        if debug_materialization:
            log.warning(
                "[call-normalize] function=%#x target=%s rhs=%s resolved=%s source_idx=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                call_name,
                self._debug_expr_8616(rhs),
                self._debug_expr_8616(resolved) if resolved is not None else None,
                source_idx,
            )
        if resolved is None:
            resolved = self._resolve_dirty_rhs_fallback_8616(
                rhs, prefix, call_name=call_name,
                debug_materialization=debug_materialization,
                source_idx=source_idx,
            )
        if resolved is None:
            resolved = self._resolve_shr_word_8616(
                rhs, prefix, call_name=call_name,
                debug_materialization=debug_materialization,
            )
        if resolved is None:
            byte_resolved = self._resolve_byte_merge_low_source_8616(rhs, prefix, call_name=call_name, debug_materialization=debug_materialization)
            if byte_resolved is not None:
                return byte_resolved, True
        return resolved, False

    def _normalize_call_helper_offset_8616(
        self,
        expr: StructuredAstValue,
        prefix: list[StructuredAstValue],
        *,
        stack_bindings: dict[int, StructuredAstValue] | None,
        call_name: str | None,
        debug_materialization: bool,
        source_idx: int,
    ) -> StructuredAstValue:
        """Resolve register carriers inside a SEG_PTR/MK_FP helper offset argument."""
        if not (isinstance(expr, CFunctionCall) and getattr(expr, "callee_target", None) in {"SEG_PTR", "MK_FP"}):
            return expr
        helper_args = list(expr.args or ())
        if len(helper_args) >= 2:
            helper_offset = helper_args[1]
            if self._expr_contains_plain_register_uses(helper_offset):
                resolved_offset = self._resolve_register_carriers_in_expr(helper_offset, prefix)
                if debug_materialization:
                    log.warning(
                        "[call-helper-offset-normalize] function=%#x target=%s offset=%s resolved=%s source_idx=%r",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        call_name,
                        self._debug_expr_8616(helper_offset),
                        self._debug_expr_8616(resolved_offset) if resolved_offset is not None else None,
                        source_idx,
                    )
                if resolved_offset is None:
                    dirty_offset = self._recent_dirty_value_rhs(helper_offset, prefix)
                    if dirty_offset is not None:
                        resolved_offset = dirty_offset
                if resolved_offset is not None:
                    helper_offset = self._clone_c_ast_tree(resolved_offset)
            rewritten_offset, replacement_count = self._normalize_bp_slot_value_arg_8616(
                helper_offset,
                stack_bindings=stack_bindings,
                pointer_arg=True,
            )
            if replacement_count:
                self.stats.bp_slot_arg_value_normalized_count += replacement_count
            helper_args[1] = rewritten_offset
            expr.args = helper_args
        return expr

    def _debug_normalize_refuse_8616(
        self,reason: str, expr: StructuredAstValue = None, *, call_name: str | None, debug_materialization: bool
    ) -> None:
        if debug_materialization:
            log.warning(
                "[call-normalize-refuse] function=%#x target=%s reason=%s expr=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                call_name,
                reason,
                self._debug_expr_8616(expr) if expr is not None else None,
            )
        return None
    def _byte_merge_refuse_8616(self,
        reason_fmt: str,
        call_name: str | None,
        debug_materialization: bool,
        *fmt_args: StructuredAstValue,
    ) -> None:
        self.stats.byte_merge_refused_count += 1
        if debug_materialization:
            log.warning(
                "[call-byte-merge-refuse] function=%#x target=%s " + reason_fmt,
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                call_name,
                *fmt_args,
            )

    def _resolve_byte_merge_low_source_8616(
        self,
        expr: StructuredAstValue, prefix: list[StructuredAstValue],
    *, call_name: str | None, debug_materialization: bool
    ) -> StructuredAstValue:
        low_source = self._byte_merge_low_source(expr)
        if low_source is None:
            return None
        if self._expr_contains_non_segment_register_uses(low_source):
            resolved_low = self._resolve_register_carriers_in_expr(low_source, prefix)
            if resolved_low is None:
                resolved_low = self._recent_dirty_value_rhs(low_source, prefix)
        else:
            resolved_low = low_source
        if resolved_low is None:
            return self._byte_merge_refuse_8616("reason=low-source-unresolved low=%s", call_name, debug_materialization, self._debug_expr_8616(low_source),)
        if self._expr_contains_non_segment_register_uses(resolved_low):
            return self._byte_merge_refuse_8616("reason=low-source-registers low=%s", call_name, debug_materialization, self._debug_expr_8616(resolved_low),)
        if self._node_contains_placeholder_stack_8616(resolved_low):
            return self._byte_merge_refuse_8616("reason=low-source-placeholder-stack low=%s", call_name, debug_materialization, self._debug_expr_8616(resolved_low),)
        if not self._is_proven_byte_value_source(resolved_low):
            return self._byte_merge_refuse_8616("reason=low-source-not-byte low=%s width=%r", call_name, debug_materialization, self._debug_expr_8616(resolved_low), self._arg_width_from_expr(resolved_low),)
        self.stats.byte_merge_classified_fact_count += 1
        self.stats.byte_merge_materialized_count += 1
        if debug_materialization:
            log.warning(
                "[call-byte-merge] function=%#x target=%s low=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                call_name,
                self._debug_expr_8616(resolved_low),
            )
        return resolved_low
    def _resolve_value_carrier_or_byte_source_8616(
        self,
        expr: StructuredAstValue,
        prefix: list[StructuredAstValue],
        seen: set[tuple[StructuredAstValue, int]] | None = None,
    *, call_name: str | None, debug_materialization: bool
    ) -> StructuredAstValue:
        if seen is None:
            seen = set()
        key = (self._value_expr_key(expr), len(prefix))
        if key in seen:
            return None
        next_seen = set(seen)
        next_seen.add(key)

        resolved = self._resolve_register_carriers_in_expr(expr, prefix)
        if resolved is not None and not self._expr_contains_non_segment_register_uses(resolved):
            return resolved

        assigned_rhs, assigned_idx = self._resolve_recent_value_assignment(expr, prefix)
        if assigned_rhs is None:
            return None
        next_prefix = prefix[:assigned_idx] if isinstance(assigned_idx, int) and assigned_idx >= 0 else prefix
        byte_resolved = self._resolve_byte_merge_low_source_8616(assigned_rhs, next_prefix, call_name=call_name, debug_materialization=debug_materialization)
        if byte_resolved is not None and not self._expr_contains_non_segment_register_uses(byte_resolved):
            return byte_resolved
        return self._resolve_value_carrier_or_byte_source_8616(assigned_rhs, next_prefix, next_seen, call_name=call_name, debug_materialization=debug_materialization)
    def _resolve_stack_address_index_arg_expr_8616(
        self,
        expr: StructuredAstValue, prefix: list[StructuredAstValue],
    *, call_name: str | None, debug_materialization: bool
    ) -> StructuredAstValue:
        node = self._strip_arg_casts(expr)
        if not isinstance(node, CBinaryOp) or getattr(node, "op", None) not in {"Add", "Sub"}:
            return None
        lhs = self._strip_arg_casts(getattr(node, "lhs", None))
        rhs = self._strip_arg_casts(getattr(node, "rhs", None))
        if self._is_stack_address_arg_expr_8616(lhs) and self._is_index_register_expr_8616(rhs):
            stack_expr = lhs
            index_expr = rhs
            stack_on_lhs = True
        elif (
            getattr(node, "op", None) == "Add"
            and self._is_index_register_expr_8616(lhs)
            and self._is_stack_address_arg_expr_8616(rhs)
        ):
            stack_expr = rhs
            index_expr = lhs
            stack_on_lhs = False
        else:
            return None
        if not self._expr_contains_plain_register_uses(index_expr):
            return self._clone_c_ast_tree(expr)
        resolved_index = self._resolve_value_carrier_or_byte_source_8616(index_expr, prefix, call_name=call_name, debug_materialization=debug_materialization)
        if resolved_index is None or self._expr_contains_non_segment_register_uses(resolved_index):
            return None
        cloned_stack = self._clone_c_ast_tree(stack_expr)
        cloned_index = self._clone_c_ast_tree(resolved_index)
        if stack_on_lhs:
            return CBinaryOp(getattr(node, "op", "Add"), cloned_stack, cloned_index, codegen=self.codegen)
        return CBinaryOp("Add", cloned_index, cloned_stack, codegen=self.codegen)
    def _group_single_far_pointer_arg_8616(
        self,values: list[StructuredAstValue], *, call_name: str | None
    ) -> list[StructuredAstValue] | None:
        logical_arg_count = _expected_arg_count_for_known_callee_8616(call_name or "")
        if logical_arg_count != 1 or len(values) != 2:
            return None
        if not _callee_expects_pointer_arg_8616(
            call_name or "",
            0,
            project=self.project,
            cod_path_hint=self.cod_path_hint,
        ):
            return None

        segment_idx = None
        segment_name = None
        for idx, value in enumerate(values):
            name = self._segment_register_name_from_expr_8616(value)
            if name is None:
                continue
            if segment_idx is not None:
                return None
            segment_idx = idx
            segment_name = name
        if segment_idx is None or segment_name is None:
            return None
        offset_idx = 1 - segment_idx
        offset_expr = self._clone_c_ast_tree(values[offset_idx])

        if segment_name == "ss" and self._is_stack_address_arg_expr_8616(offset_expr):
            return [offset_expr]

        segment_expr = self._segment_register_expr(segment_name)
        if segment_expr is None:
            return None
        target = str(
            getattr(getattr(self.codegen, "project", None), "_inertia_c_target", "portable-flat") or "portable-flat"
        )
        helper = "SEG_PTR" if target == "portable-flat" else "MK_FP"
        return [
            structured_c.CFunctionCall(
                helper,
                None,
                [segment_expr, offset_expr],
                codegen=self.codegen,
            )
        ]
    def _stack_call_source_expr_8616(
        self,source: StructuredAstValue, arg_index: int, *, call_name: str | None
    ) -> StructuredAstValue | None:
        if not isinstance(source, tuple) or not source:
            return None
        if source[0] == CallsitePushSourceKind8616.RETURN_REGISTER.value:
            return None
        return self._direct_expr_from_push_source_8616(
            source,
            call_name=call_name,
            arg_index=arg_index,
        )

    def _normalize_ret_reg_source_args_8616(
        self,
        call: StructuredAstValue,
        args: StructuredAstValue,
        push_arg_sources: tuple[StructuredAstValue, ...],
        statements: list[StructuredAstValue],
        call_name: str | None,
    ) -> bool | None:
        """Normalize args when push sources carry return-register evidence; None = not applicable."""
        ordered_sources = list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
        direct_args, consumed_return_call_indices = (
            self._direct_args_from_ordered_push_sources_consuming_return_calls_8616(
                ordered_sources,
                call_name=call_name,
                statements=statements,
            )
        )
        if consumed_return_call_indices and self._call_args_embed_return_source_callsites_8616(
            call,
            ordered_sources,
        ):
            return self._delete_consumed_return_call_refs_8616(consumed_return_call_indices)
        if direct_args is not None and all(arg is not None for arg in direct_args):
            has_unresolved_arg = any(
                self._node_contains_placeholder_stack_8616(arg) or self._expr_contains_plain_register_uses(arg)
                for arg in args
            )
            if has_unresolved_arg or len(direct_args) != len(args):
                normalized_direct_args = self._normalize_materialized_call_args(
                    list(direct_args),
                    [-1] * len(direct_args),
                    statements,
                    call_name=call_name,
                )
                if (
                    normalized_direct_args is not None
                    and self._all_arg_exprs_are_non_segment_registers(normalized_direct_args)
                    and tuple(normalized_direct_args) != args
                ):
                    transaction = self._set_materialized_call_args(
                        call,
                        normalized_direct_args,
                        call_name=call_name,
                        force_replace=True,
                    )
                    if transaction.arguments_accepted:
                        deleted = self._delete_consumed_return_call_refs_8616(consumed_return_call_indices)
                        return transaction.changed or deleted
                    return bool(transaction.changed)
        return None
    def _existing_args_have_unresolved_8616(self, args: StructuredAstValue) -> bool:
        """Whether any existing arg still has placeholder/register evidence."""
        for arg in args:
            node = arg
            while isinstance(node, CTypeCast):
                node = node.expr
            if (
                self._node_contains_placeholder_stack_8616(node)
                or self._expr_contains_plain_register_uses(node)
                or self._plain_bp_stack_load_offset(node) is not None
                or self._plain_stack_slot_address_offset(node) is not None
            ):
                return True
        return False

    def _normalize_existing_call_args_8616(self,
        call: StructuredAstValue,
        statements: list[StructuredAstValue],
        *,
        call_name: str | None,
        push_arg_sources: tuple[StructuredAstValue, ...] = (),
    ) -> bool:
        args = _boundary_tuple_8616(getattr(call, "args", ()) or ())
        if not args:
            return False
        if (
            isinstance(push_arg_sources, tuple)
            and push_arg_sources
            and any(
                isinstance(source, tuple)
                and len(source) >= 3
                and source[0] == CallsitePushSourceKind8616.RETURN_REGISTER.value
                for source in push_arg_sources
            )
        ):
            ret_reg_result = self._normalize_ret_reg_source_args_8616(
                call, args, push_arg_sources, statements, call_name
            )
            if ret_reg_result is not None:
                return ret_reg_result
        preserve_return_register_indices: set[int] = set()
        ordered_push_sources_for_args: tuple[StructuredAstValue, ...] = ()
        if isinstance(push_arg_sources, tuple) and len(push_arg_sources) == len(args):
            ordered_sources = list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
            ordered_push_sources_for_args = tuple(ordered_sources)
            preserve_return_register_indices = {
                idx
                for idx, source in enumerate(ordered_sources)
                if isinstance(source, tuple)
                and len(source) >= 3
                and source[0] == "ret_reg"
                and isinstance(source[2], str)
                and source[2].lower() in {"ax", "dx"}
            }
        normalized_args = self._normalize_materialized_call_args(
            list(args),
            [-1] * len(args),
            statements,
            call_name=call_name,
            preserve_register_arg_indices=preserve_return_register_indices,
            push_sources=ordered_push_sources_for_args,
        )
        if normalized_args is None:
            return False


        force_replace_args = any(
            self._push_source_is_expr_arithmetic_8616(source)
            for source in (tuple(push_arg_sources) if isinstance(push_arg_sources, tuple) else ())
        )
        if len(tuple(normalized_args)) != len(args) and not self._existing_args_have_unresolved_8616(args):
            return False
        if tuple(normalized_args) == args:
            return False
        return bool(
            self._set_materialized_call_args(
                call,
                normalized_args,
                call_name=call_name,
                force_replace=force_replace_args,
            ).changed
        )

    def _normalize_near_function_pointer_call_arg_8616(self, arg: StructuredAstValue) -> StructuredAstValue:
        node = arg
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CFunctionCall) or getattr(node, "callee_target", None) not in {"SEG_PTR", "MK_FP"}:
            return arg, False
        call_args = _boundary_tuple_8616(getattr(node, "args", ()) or ())
        if len(call_args) != 2:
            return arg, False
        offset_expr = call_args[1]
        offset = self._stack_offset_from_cvar_8616(offset_expr)
        if not isinstance(offset, int):
            return arg, False
        if offset not in self._cached_function_pointer_stack_store_evidence_8616():
            return arg, False
        self.codegen._inertia_fnptr_call_arg_segptr_unwrapped_8616 = (
            int(getattr(self.codegen, "_inertia_fnptr_call_arg_segptr_unwrapped_8616", 0) or 0) + 1
        )
        return self._clone_c_ast_tree(offset_expr), True

    def _call_node_tagged_callsite_addr_8616(self, call: StructuredAstValue) -> int | None:
        if isinstance(call, CFunctionCall):
            exact_callsite_addr = structured_callsite_addr_8616(call)
            if exact_callsite_addr is not None:
                    return exact_callsite_addr if isinstance(exact_callsite_addr, int) else None
        tags = getattr(call, "tags", None)
        if isinstance(tags, dict):
            for key in ("insn_addr", "stmt_addr", "addr"):
                value = tags.get(key)
                if isinstance(value, int):
                    return value
        value = getattr(call, "addr", None)
        return value if isinstance(value, int) else None

    def _known_name_callsite_mismatch_8616(self,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        current_name: StructuredAstValue,
        semantic_name: str,
    ) -> bool:
        """Refuse target rewrite when a known name disagrees with the summary callsite."""
        if not (isinstance(current_name, str) and current_name and not _call_name_is_unknown_8616(current_name)):
            return False
        summary_callsite = summary.callsite_addr
        node_callsite = self._call_node_tagged_callsite_addr_8616(call)
        if isinstance(summary_callsite, int) and node_callsite == summary_callsite:
            return False
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-target-refuse] function=%#x before=%r after=%r reason=known-name-callsite-mismatch node_callsite=%r summary_callsite=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                current_name,
                semantic_name,
                node_callsite,
                summary_callsite,
            )
        return True

    def _install_summary_target_8616(self,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        semantic_name: str,
        current_name: StructuredAstValue,
        target_addr: int,
    ) -> None:
        """Install the proven summary target name and callee on ``call``."""
        candidate = _lookup_callee_function_8616(self.project, target_addr, allow_containing=False)
        if candidate is not None and _callee_names_match_8616(getattr(candidate, "name", None), semantic_name):
            call.callee_func = candidate
        elif getattr(call, "callee_func", None) is not None:
            call.callee_func = None
        call.callee_target = semantic_name
        self.codegen._inertia_callsite_target_materialized_from_summary_8616 = (
            int(getattr(self.codegen, "_inertia_callsite_target_materialized_from_summary_8616", 0) or 0) + 1
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-target-materialized] function=%#x call_id=%#x before=%r after=%r target=%#x summary_callsite=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                id(call),
                current_name,
                semantic_name,
                target_addr,
                summary.callsite_addr if summary is not None else None,
            )

    def _apply_summary_call_target_8616(self,
        call: StructuredAstValue, summary: StructuredAstValue, fallback_name: str | None
    ) -> tuple[bool, bool]:
        if call is None or summary is None or bool(summary.stack_probe_helper):
            return False, False
        changed = _drop_detached_callee_func_8616(call)
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            return changed, False
        semantic_name = _semantic_call_name_from_summary_8616(self.project, summary, fallback_name)
        if not isinstance(semantic_name, str) or not semantic_name or _call_name_is_unknown_8616(semantic_name):
            return changed, False
        current_name = _call_node_name_8616(call)
        if _callee_names_match_8616(current_name, semantic_name):
            return changed, False
        if self._known_name_callsite_mismatch_8616(call, summary, current_name, semantic_name):
            return changed, True
        self._install_summary_target_8616(call, summary, semantic_name, current_name, target_addr)
        return True, False

    def _call_args_match_materialized_args_8616(self,
        call: StructuredAstValue,
        args: StructuredAstValue,
    ) -> bool:
        """Return whether a call already carries the evidence-derived arguments."""
        current_args = _boundary_tuple_8616(getattr(call, "args", ()) or ())
        materialized_args = _boundary_tuple_8616(args or ())
        return len(current_args) == len(materialized_args) and all(
            _same_c_expression_8616(before, after)
            or (
                _call_arg_semantic_key_8616(before) is not None
                and _call_arg_semantic_key_8616(before) == _call_arg_semantic_key_8616(after)
            )
            for before, after in zip(current_args, materialized_args, strict=False)
        )

    def _merge_proven_partial_direct_args_8616(self,
        call: StructuredAstValue,
        direct_args: list[StructuredAstValue],
    ) -> tuple[StructuredAstValue, ...] | None:
        """Replace only unresolved arguments backed by an exact direct source."""
        current_args = _boundary_tuple_8616(getattr(call, "args", ()) or ())
        if len(current_args) != len(direct_args):
            return None
        merged: list[StructuredAstValue] = []
        replacement_count = 0
        for current_arg, direct_arg in zip(current_args, direct_args, strict=False):
            if direct_arg is not None and _bound_call_argument_requires_rematerialization_8616(
                self.codegen,
                current_arg,
            ):
                merged.append(direct_arg)
                replacement_count += 1
            else:
                merged.append(current_arg)
        return tuple(merged) if replacement_count > 0 else None

    def _argument_matches_register_push_source_8616(self,
        argument: StructuredAstValue,
        source: StructuredAstValue,
    ) -> bool:
        """Return whether an argument is the exact register named by PUSH evidence."""
        if (
            not isinstance(source, tuple)
            or len(source) != 2
            or source[0] != CallsitePushSourceKind8616.REGISTER_VALUE.value
            or not isinstance(source[1], str)
        ):
            return False
        node = argument
        while isinstance(node, CTypeCast):
            node = node.expr
        return bool(
            isinstance(node, structured_c.CVariable)
            and isinstance(node.variable, SimRegisterVariable)
            and isinstance(node.variable.name, str)
            and node.variable.name.lower() == source[1].lower()
        )

    def _regroup_args_from_summary_widths_8616(
        self, args_after: StructuredAstValue, summary: StructuredAstValue, callee_name: str | None
    ) -> StructuredAstValue:
        """Regroup scalar args to match summary-declared logical widths."""
        if summary is None or len(args_after) <= 1:
            return args_after
        push_sources = _boundary_tuple_8616(summary.push_arg_sources or ())
        if not push_sources:
            return args_after
        ordered_sources = tuple(reversed(push_sources)) if len(push_sources) > 1 else push_sources
        expected_widths = self._summary_logical_arg_widths(summary, callee_name)
        grouped_args = self._group_scalar_args_by_expected_widths_8616(
            list(args_after),
            expected_arg_widths=expected_widths,
            push_sources=ordered_sources,
        )
        if grouped_args is None or len(grouped_args) >= len(args_after):
            return args_after
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-summary-width-regroup] function=%#x target=%s args_before=%s args_after=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                callee_name,
                tuple(self._debug_expr_8616(arg) for arg in args_after),
                tuple(self._debug_expr_8616(arg) for arg in grouped_args),
            )
        return tuple(grouped_args)

    def _apply_zero_arity_ownership_8616(
        self,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        args_before: StructuredAstValue,
        args_after: StructuredAstValue,
        target_changed: bool,
    ) -> CallArgumentMutationResult8616 | None:
        """Apply the zero-argument ownership contract when it enforces arity."""
        if not isinstance(summary, CallsiteSummary8616):
            return None
        zero_arity_ownership = classify_callsite_zero_argument_ownership_8616(
            summary,
            len(args_after),
        )
        self.codegen._inertia_callsite_zero_argument_ownership_8616 = zero_arity_ownership
        if not zero_arity_ownership.enforces_zero_arguments:
            if zero_arity_ownership.blocks_candidate:
                self.codegen._inertia_callsite_nonzero_arg_candidate_refused_8616 = (
                    int(
                        getattr(
                            self.codegen,
                            "_inertia_callsite_nonzero_arg_candidate_refused_8616",
                            0,
                        )
                        or 0
                    )
                    + 1
                )
                return refused_call_argument_mutation_8616(target_changed=target_changed)
            return None
        protected = self._protected_call_arg_state()
        protected.discard_call(call)
        if args_before:
            call.args = []
            self.codegen._inertia_callsite_args_ast_materialized_8616 = True
            self.codegen._inertia_codegen_decl_refresh_required_8616 = True
            self.codegen._inertia_codegen_call_args_render_refresh_required_8616 = True
        if zero_arity_ownership.blocks_candidate:
            self.codegen._inertia_callsite_nonzero_arg_candidate_refused_8616 = (
                int(
                    getattr(
                        self.codegen,
                        "_inertia_callsite_nonzero_arg_candidate_refused_8616",
                        0,
                    )
                    or 0
                )
                + 1
            )
            return refused_call_argument_mutation_8616(
                arguments_changed=bool(args_before),
                target_changed=target_changed,
            )
        return accepted_call_argument_mutation_8616(
            arguments_changed=bool(args_before),
            target_changed=target_changed,
        )

    def _materialization_quality_refused_8616(
        self,
        call_name: str | None,
        args_before: StructuredAstValue,
        args_after: StructuredAstValue,
        exact_register_args: bool,
        exact_stack_address_mismatch: bool,
    ) -> bool:
        """Refuse replacement when materialized args score worse without exact evidence."""
        before_score = sum(self._arg_semantic_quality_8616(call_name, idx, arg) for idx, arg in enumerate(args_before))
        after_score = sum(self._arg_semantic_quality_8616(call_name, idx, arg) for idx, arg in enumerate(args_after))
        if (
            after_score < before_score
            and not exact_register_args
            and not exact_stack_address_mismatch
        ):
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-materialized-skip] function=%#x target=%s before_score=%d after_score=%d args_before=%s args_after=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    before_score,
                    after_score,
                    tuple(self._debug_expr_8616(arg) for arg in args_before),
                    tuple(self._debug_expr_8616(arg) for arg in args_after),
                )
            return True
        return False
    def _refresh_summary_arg_widths_8616(self,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        effective_call_name: str | None,
    ) -> StructuredAstValue:
        logical_widths = self._summary_logical_arg_widths(summary, effective_call_name)
        if (
            logical_widths
            and logical_widths != summary.logical_arg_widths
            and _prototype_widths_account_for_push_sources_top_8616(
                logical_widths,
                _boundary_tuple_8616(summary.push_arg_sources or ()),
            )
        ):
            summary = replace(summary, logical_arg_widths=logical_widths)
            self.summary_map[id(call)] = summary
            record_callsite_summary_fact_8616(self.codegen, summary, node_id=id(call), attached=True)
        return summary

    def _attach_arg_provenance_8616(self,
        args_after: tuple[StructuredAstValue, ...],
        summary: StructuredAstValue,
    ) -> None:
        carrier = cast(_CallsiteMaterializationControlCarrier8616, self.codegen)
        try:
            provenance_attacher = carrier._inertia_segment_address_provenance_attacher_8616
        except AttributeError:
            provenance_attacher = None
        if provenance_attacher is not None:
            provenance_attacher(args_after, tuple(summary.push_arg_instruction_addrs))

    def _set_materialized_call_args(self,
        call: StructuredAstValue, args: StructuredAstValue, *, call_name: str | None, force_replace: bool = False
    ) -> CallArgumentMutationResult8616:


        summary = self.summary_map.get(id(call))
        target_changed, target_refused = self._apply_summary_call_target_8616(call, summary, call_name)
        if target_refused:
            self.codegen._inertia_callsite_known_target_arg_materialization_refused_8616 = (
                int(getattr(self.codegen, "_inertia_callsite_known_target_arg_materialization_refused_8616", 0) or 0) + 1
            )
            return refused_call_argument_mutation_8616(target_changed=target_changed)
        args_before = _boundary_tuple_8616(getattr(call, "args", ()) or ())
        normalized_args_after = []
        for arg in tuple(args):
            normalized_arg, _changed_arg = self._normalize_near_function_pointer_call_arg_8616(arg)
            normalized_args_after.append(normalized_arg)
        args_after = tuple(normalized_args_after)
        zero_result = self._apply_zero_arity_ownership_8616(call, summary, args_before, args_after, target_changed)
        if zero_result is not None:
            return zero_result
        effective_call_name = _call_node_name_8616(call) or call_name
        if summary is not None:
            summary = self._refresh_summary_arg_widths_8616(call, summary, effective_call_name)
        args_after = tuple(self._regroup_args_from_summary_widths_8616(args_after, summary, effective_call_name))
        if summary is not None:
            self._attach_arg_provenance_8616(args_after, summary)
        summaryless_result = self._summaryless_conflict_gate_8616(
            call,
            summary,
            args_before,
            args_after,
            call_name=call_name,
            target_changed=target_changed,
            force_replace=force_replace,
        )
        if summaryless_result is not None:
            return summaryless_result
        safety_result = self._materialization_safety_refusal_8616(
            call, args_before, args_after, target_changed=target_changed
        )
        if safety_result is not None:
            return safety_result
        args_equal = self._call_args_match_materialized_args_8616(call, args_after)
        summary_push_sources = (
            _boundary_tuple_8616(summary.push_arg_sources or ())
            if isinstance(summary, CallsiteSummary8616)
            else ()
        )
        ordered_summary_sources = (
            tuple(reversed(summary_push_sources))
            if len(summary_push_sources) > 1
            else summary_push_sources
        )
        exact_register_args = bool(args_after) and len(args_after) == len(ordered_summary_sources) and all(
            self._argument_matches_register_push_source_8616(argument, source)
            for argument, source in zip(args_after, ordered_summary_sources, strict=True)
        )
        exact_stack_address_mismatch = self._exact_stack_address_source_mismatch_8616(
            args_before,
            ordered_summary_sources,
        )
        if args_before and (not force_replace) and self._materialization_quality_refused_8616(
            call_name, args_before, args_after,
            exact_register_args, exact_stack_address_mismatch,
        ):
            return refused_call_argument_mutation_8616(target_changed=target_changed)
        if not args_before and len(args_after) > 1:
            self.stats.push_order_reversed_count += 1
        protected = self._protected_call_arg_state()
        self._remember_materialized_args_8616(
            call,
            args_after,
            ordered_summary_sources,
            force_replace=force_replace,
            call_name=call_name,
            args_before_len=len(args_before),
            protected=protected,
        )
        return self._commit_materialized_call_args_8616(
            call,
            args_before,
            args_after,
            summary,
            args_equal=args_equal,
            target_changed=target_changed,
            call_name=call_name,
        )

    def _summaryless_conflict_gate_8616(
        self,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        args_before: StructuredAstValue,
        args_after: StructuredAstValue,
        *,
        call_name: str | None,
        target_changed: bool,
        force_replace: bool,
    ) -> CallArgumentMutationResult8616 | None:
        """Refuse summaryless replacement when resolved args would conflict."""
        if summary is None and force_replace and args_before and len(args_before) == len(args_after):
            existing_args_are_resolved = not any(
                self._node_contains_placeholder_stack_8616(arg) or self._expr_contains_plain_register_uses(arg)
                for arg in args_before
            )
            before_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in args_before)
            after_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in args_after)
            before_pointer_keys = tuple(self._pointer_offset_key_8616(arg) for arg in args_before)
            after_pointer_keys = tuple(self._pointer_offset_key_8616(arg) for arg in args_after)
            semantic_replacement_has_conflict = (
                existing_args_are_resolved
                and all(key is not None for key in before_keys)
                and all(key is not None for key in after_keys)
                and before_keys != after_keys
            )
            pointer_replacement_has_conflict = (
                existing_args_are_resolved
                and all(key is not None for key in before_pointer_keys)
                and all(key is not None for key in after_pointer_keys)
                and before_pointer_keys != after_pointer_keys
            )
            if semantic_replacement_has_conflict or pointer_replacement_has_conflict:
                self.codegen._inertia_summaryless_call_arg_replacement_refused_8616 = (
                    int(getattr(self.codegen, "_inertia_summaryless_call_arg_replacement_refused_8616", 0) or 0) + 1
                )
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-materialized-refuse] function=%#x target=%s reason=summaryless-conflicting-replacement args_before=%s args_after=%s",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        call_name,
                        tuple(self._debug_expr_8616(arg) for arg in args_before),
                        tuple(self._debug_expr_8616(arg) for arg in args_after),
                    )
                return refused_call_argument_mutation_8616(target_changed=target_changed)
        return None

    def _materialization_safety_refusal_8616(
        self,
        call: StructuredAstValue,
        args_before: StructuredAstValue,
        args_after: StructuredAstValue,
        *,
        target_changed: bool,
    ) -> CallArgumentMutationResult8616 | None:
        """Refuse cyclic, self-referencing, or call-dropping materializations."""
        if any(self._c_ast_has_cycle_or_too_complex_8616(arg) for arg in args_after):
            self.codegen._inertia_call_arg_cyclic_or_complex_refused_8616 = (
                int(getattr(self.codegen, "_inertia_call_arg_cyclic_or_complex_refused_8616", 0) or 0) + 1
            )
            return refused_call_argument_mutation_8616(target_changed=target_changed)
        if any(self._c_ast_contains_identity_8616(arg, call) for arg in args_after):
            self.codegen._inertia_call_arg_self_reference_refused_8616 = (
                int(getattr(self.codegen, "_inertia_call_arg_self_reference_refused_8616", 0) or 0) + 1
            )
            return refused_call_argument_mutation_8616(target_changed=target_changed)
        preservation = classify_call_argument_call_preservation_8616(args_before, args_after)
        if not preservation.preserves_calls:
            return refused_call_argument_mutation_8616(target_changed=target_changed)
        return None

    def _remember_materialized_args_8616(
        self,
        call: StructuredAstValue,
        args_after: StructuredAstValue,
        ordered_summary_sources: StructuredAstValue,
        *,
        force_replace: bool,
        call_name: str | None,
        args_before_len: int,
        protected: StructuredAstValue,
    ) -> None:
        """Remember accepted args into the protected-arg store with quality scores."""
        if force_replace or len(args_after) != args_before_len:
            protected.discard_call(call)
        for idx, arg in enumerate(args_after):
            score = self._arg_semantic_quality_8616(call_name, idx, arg)
            if idx < len(ordered_summary_sources) and self._argument_matches_register_push_source_8616(
                arg,
                ordered_summary_sources[idx],
            ):
                score += 8
            return_arg_sources = getattr(self.codegen, "_inertia_return_register_arg_sources_8616", None)
            if (
                isinstance(arg, CFunctionCall)
                and isinstance(return_arg_sources, dict)
                and id(arg) in return_arg_sources
            ):
                score += 8
            protected.remember(call, idx, self._clone_c_ast_tree(arg), score)

    def _commit_materialized_call_args_8616(
        self,
        call: StructuredAstValue,
        args_before: StructuredAstValue,
        args_after: StructuredAstValue,
        summary: StructuredAstValue,
        *,
        args_equal: bool,
        target_changed: bool,
        call_name: str | None,
    ) -> CallArgumentMutationResult8616:
        """Commit accepted args onto the call node and record the mutation."""
        if args_equal:
            if summary is not None:
                self._record_materialized_return_call_expr_8616(call, summary)
            if target_changed:
                self.codegen._inertia_codegen_decl_refresh_required_8616 = True
                self.codegen._inertia_codegen_call_args_render_refresh_required_8616 = True
            return accepted_call_argument_mutation_8616(
                arguments_changed=False,
                target_changed=target_changed,
            )
        call.args = list(args_after)
        self.stats.call_arg_materialized_count += len(args_after)
        self.codegen._inertia_callsite_args_ast_materialized_8616 = True
        self.codegen._inertia_codegen_decl_refresh_required_8616 = True
        self.codegen._inertia_codegen_call_args_render_refresh_required_8616 = True
        if summary is not None:
            self._record_materialized_return_call_expr_8616(call, summary)
        log.debug(
            "callarg-normalized function=%#x target=%s args_before=%s args_after=%s",
            getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
            call_name,
            tuple(self._debug_expr_8616(arg) for arg in args_before),
            tuple(self._debug_expr_8616(arg) for arg in args_after),
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-materialized] function=%#x call_id=%#x target=%s summary_callsite=%r args_before=%s args_after=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                id(call),
                call_name,
                summary.callsite_addr if summary is not None else None,
                tuple(self._debug_expr_8616(arg) for arg in args_before),
                tuple(self._debug_expr_8616(arg) for arg in args_after),
            )
        return accepted_call_argument_mutation_8616(
            arguments_changed=True,
            target_changed=target_changed,
        )

    def _prototype_arg_count(self, call: StructuredAstValue) -> int | None:
        callee_func = getattr(call, "callee_func", None)
        prototype = getattr(callee_func, "prototype", None)
        args = getattr(prototype, "args", None)
        if isinstance(args, (list, tuple)):
            return len(args)
        return None

    def _prototype_arg_widths_for_call_8616(self,
        call: StructuredAstValue,
    ) -> tuple[int, ...] | None:
        callee_func = getattr(call, "callee_func", None)
        return _prototype_arg_widths_8616(self.project, getattr(callee_func, "prototype", None))

    def _is_stable_named_stack_value_expr_8616(self, expr: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return False
        variable = node.variable
        if not isinstance(variable, SimStackVariable):
            return False
        offset = variable.offset
        name = variable.name or node.name
        if not isinstance(offset, int) or not isinstance(name, str) or not name:
            return False
        return not name.startswith(("arg_", "s_", "stack_", "vvar_", "tmp_", "ir_"))

    def _remat_exact_width_mismatch_8616(
        self, call: StructuredAstValue, args: StructuredAstValue, ordered_push_sources: list[StructuredAstValue]
    ) -> bool:
        """Return whether an exact stack-source arg has a storage-width mismatch."""
        for actual_arg, push_source in zip(args, ordered_push_sources, strict=False):
            source_evidence = call_argument_stack_value_source_8616(push_source)
            if source_evidence is None:
                continue
            actual_node = actual_arg
            while isinstance(actual_node, CTypeCast):
                actual_node = actual_node.expr
            actual_variable = (
                actual_node.variable
                if isinstance(actual_node, structured_c.CVariable)
                else None
            )
            actual_storage_width = (
                actual_variable.size
                if isinstance(actual_variable, SimStackVariable)
                else None
            )
            if (
                call_argument_stack_variable_offset_8616(self.codegen, actual_node)
                == source_evidence.offset
                and isinstance(actual_storage_width, int)
                and actual_storage_width != source_evidence.width
            ):
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=exact-stack-source-width "
                        "offset=%d actual=%d expected=%d",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                        source_evidence.offset,
                        actual_storage_width,
                        source_evidence.width,
                    )
                return True
        return False

    def _remat_arith_push_source_alignment_8616(
        self,
        call: StructuredAstValue,
        args: StructuredAstValue,
        ordered_push_sources: list[StructuredAstValue],
        semantic_call_name: str | None,
    ) -> bool | None:
        """Verdict for arithmetic push-source args; ``None`` means undecided."""
        if not (
            len(ordered_push_sources) == len(args)
            and any(
                self._push_source_is_arithmetic_expr_8616(source) for source in ordered_push_sources
            )
        ):
            return None
        direct_source_args = [
            self._direct_expr_from_push_source_8616(
                source,
                call_name=semantic_call_name or getattr(call, "callee_target", None),
                arg_index=idx,
                force_pointer_arg=idx < len(args) and self._call_arg_is_pointer_shaped_8616(args[idx]),
            )
            for idx, source in enumerate(ordered_push_sources)
        ]
        if not all(arg is not None for arg in direct_source_args):
            return None
        if self._pointer_offset_keys_match_8616(args, tuple(direct_source_args)):
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-remat] function=%#x target=%s reason=keep-pointer-push-offset-alignment args=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    getattr(call, "callee_target", None),
                    tuple(self._debug_expr_8616(arg) for arg in args),
                )
            return False
        current_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in args)
        direct_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in direct_source_args)
        if (
            all(key is not None for key in current_keys)
            and all(key is not None for key in direct_keys)
            and current_keys != direct_keys
        ):
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=arithmetic-push-source-mismatch actual=%s expected=%s",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                        current_keys,
                        direct_keys,
                    )
                return True
        return None

    def _remat_bp_offset_mismatch_8616(
        self, call: StructuredAstValue, args: StructuredAstValue, push_arg_sources: StructuredAstValue
    ) -> bool:
        """Return whether bp push-source offsets disagree with the actual args."""
        if not (
            isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == len(args)
            and all(
                isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int)
                for source in push_arg_sources
            )
        ):
            return False
        expected_offsets = [
            int(source[1])
            for source in (reversed(push_arg_sources) if len(push_arg_sources) > 1 else push_arg_sources)
        ]
        actual_offsets: list[int | None] = []
        for arg in args:
            node = arg
            while isinstance(node, CTypeCast):
                node = node.expr
            projected_offset = call_argument_stack_variable_offset_8616(
                self.codegen,
                node,
            )
            actual_offsets.append(
                projected_offset
                if projected_offset is not None
                else self._plain_stack_slot_address_offset(node)
            )
        if all(isinstance(offset, int) for offset in actual_offsets):
            normalized_actual = [cast(int, offset) for offset in actual_offsets]
            if normalized_actual != expected_offsets:
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=push-source-mismatch actual=%s expected=%s",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                        tuple(normalized_actual),
                        tuple(expected_offsets),
                    )
                return True
        return False

    def _remat_derived_push_args_body_8616(
        self,
        call: StructuredAstValue,
        args: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        semantic_name: str,
        arity_contract: StructuredAstValue,
        expected_arg_widths: StructuredAstValue,
    ) -> tuple[StructuredAstValue, bool, bool, bool, StructuredAstValue, list[StructuredAstValue]]:
        """Compute rematerialization verdicts from aligned push sources."""
        expr_verified = False
        push_align = False
        remat_expr = False
        expected_args: StructuredAstValue = None
        ordered_sources: list[StructuredAstValue] = []
        ordered_sources = list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
        logical_widths_for_existing_args = (
            expected_arg_widths if arity_contract.mode is CallArityMode8616.EXACT else None
        )
        expected_args = self._logical_args_from_push_sources_by_expected_widths_8616(
            ordered_sources,
            expected_arg_widths=logical_widths_for_existing_args,
            call_name=semantic_call_name or getattr(call, "callee_target", None),
        ) or [
            self._direct_expr_from_push_source_8616(
                source,
                call_name=semantic_call_name or getattr(call, "callee_target", None),
                arg_index=idx,
                force_pointer_arg=idx < len(args) and self._call_arg_is_pointer_shaped_8616(args[idx]),
            )
            for idx, source in enumerate(ordered_sources)
        ]
        remat_verdict, expr_verified, push_align, remat_expr, expected_args = (
            self._remat_expected_args_verdict_8616(
                expected_args, ordered_sources, args, semantic_call_name, semantic_name, call,
                logical_widths_for_existing_args, expr_verified, push_align, remat_expr,
            )
        )
        if remat_verdict is not None:
            return remat_verdict, expr_verified, push_align, remat_expr, expected_args, ordered_sources
        return None, expr_verified, push_align, remat_expr, expected_args, ordered_sources

    def _remat_expected_args_verdict_8616(self,
        expected_args: StructuredAstValue,
        ordered_sources: list[StructuredAstValue],
        args: StructuredAstValue,
        semantic_call_name: str | None,
        semantic_name: str,
        call: StructuredAstValue,
        logical_widths_for_existing_args: StructuredAstValue,
        expr_verified: bool,
        push_align: bool,
        remat_expr: bool,
    ) -> tuple[bool | None, bool, bool, bool, StructuredAstValue]:
        if all(expected is not None for expected in expected_args):
            preserve_return_register_indices = {
                idx
                for idx, source in enumerate(ordered_sources)
                if isinstance(source, tuple)
                and len(source) >= 3
                and source[0] == "ret_reg"
                and isinstance(source[2], str)
                and source[2].lower() in {"ax", "dx"}
            }
            normalized_expected_args = self._normalize_materialized_call_args(
                expected_args,
                [-1] * len(expected_args),
                [],
                call_name=semantic_call_name or getattr(call, "callee_target", None),
                preserve_register_arg_indices=preserve_return_register_indices,
                expected_arg_widths=logical_widths_for_existing_args,
                push_sources=tuple(ordered_sources),
            )
            if normalized_expected_args is not None:
                expected_args = normalized_expected_args
            exact_stack_address_mismatch = self._exact_stack_address_source_mismatch_8616(
                args,
                ordered_sources,
            )
            if exact_stack_address_mismatch:
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=exact-stack-address-source-mismatch",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                    )
                return True, expr_verified, push_align, remat_expr, expected_args
            if self._pointer_offset_keys_match_8616(args, tuple(expected_args)):
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-remat] function=%#x target=%s reason=keep-derived-pointer-push-offset-alignment args=%s",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        getattr(call, "callee_target", None),
                        tuple(self._debug_expr_8616(arg) for arg in args),
                    )
                return False, expr_verified, push_align, remat_expr, expected_args
            expected_keys = tuple(_call_arg_semantic_key_8616(expected) for expected in expected_args)
            actual_keys = tuple(_call_arg_semantic_key_8616(arg) for arg in args)
            if all(key is not None for key in expected_keys) and all(key is not None for key in actual_keys):
                mismatch_verdict = self._remat_key_mismatch_verdict_8616(
                    args, expected_args, ordered_sources, exact_stack_address_mismatch,
                    semantic_name, call, expr_verified, push_align, remat_expr, actual_keys, expected_keys,
                )
                if mismatch_verdict is not None:
                    return mismatch_verdict
                expr_verified = True
                push_align = any(
                    self._push_source_is_arithmetic_expr_8616(source) for source in ordered_sources
                )
        return None, expr_verified, push_align, remat_expr, expected_args

    def _remat_key_mismatch_verdict_8616(self,
        args: StructuredAstValue,
        expected_args: StructuredAstValue,
        ordered_sources: list[StructuredAstValue],
        exact_stack_address_mismatch: bool,
        semantic_name: str,
        call: StructuredAstValue,
        expr_verified: bool,
        push_align: bool,
        remat_expr: bool,
        actual_keys: tuple[StructuredAstValue, ...],
        expected_keys: tuple[StructuredAstValue, ...],
    ) -> tuple[bool, bool, bool, bool, StructuredAstValue] | None:
        if actual_keys != expected_keys:
            actual_score = sum(
                self._arg_semantic_quality_8616(semantic_name, idx, arg) for idx, arg in enumerate(args)
            )
            expected_score = sum(
                self._arg_semantic_quality_8616(semantic_name, idx, arg) for idx, arg in enumerate(expected_args)
            )
            if (
                actual_score > expected_score
                and not exact_stack_address_mismatch
                and not any(self._node_contains_placeholder_stack_8616(arg) for arg in args)
                and not any(self._expr_contains_plain_register_uses(arg) for arg in args)
            ):
                return False, expr_verified, push_align, remat_expr, expected_args
            resolved_stack_index_args_match = True
            remat_expr = False
            for actual_arg, expected_arg, source in zip(args, expected_args, ordered_sources, strict=False):
                actual_key = _call_arg_semantic_key_8616(actual_arg)
                expected_key = _call_arg_semantic_key_8616(expected_arg)
                if actual_key == expected_key:
                    continue
                if not (
                    isinstance(source, tuple)
                    and len(source) >= 4
                    and source[0] == "bp_index_addr"
                    and isinstance(source[1], int)
                    and self._guard_stack_address_offset_arg_base_8616(actual_arg) == int(source[1])
                    and not self._expr_contains_plain_register_uses(actual_arg)
                    and not self._node_contains_placeholder_stack_8616(actual_arg)
                ):
                    resolved_stack_index_args_match = False
                    break
            if resolved_stack_index_args_match:
                return False, expr_verified, push_align, remat_expr, expected_args
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-remat] function=%#x target=%s reason=derived-push-source-mismatch actual=%s expected=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    getattr(call, "callee_target", None),
                    actual_keys,
                    expected_keys,
                )
            return True, expr_verified, push_align, remat_expr, expected_args
        return None, expr_verified, push_align, remat_expr, expected_args
    def _remat_derived_push_args_8616(
        self,
        call: StructuredAstValue,
        args: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        arity_contract: StructuredAstValue,
        expected_arg_widths: tuple[int, ...] | None,
    ) -> tuple[bool | None, bool, bool, bool, StructuredAstValue, list[StructuredAstValue]]:
        """Compare push-source-derived expected args against the current call args."""
        semantic_name = semantic_call_name or getattr(call, "callee_target", None) or ""
        expr_verified = False
        push_align = False
        remat_expr = False
        expected_args: StructuredAstValue = None
        ordered_sources: list[StructuredAstValue] = []
        if (
            isinstance(push_arg_sources, tuple)
            and (
                len(push_arg_sources) == len(args)
                or self._prototype_widths_account_for_push_sources_8616(expected_arg_widths, push_arg_sources)
            )
            and any(source is not None for source in push_arg_sources)
        ):
            return self._remat_derived_push_args_body_8616(
                call, args, push_arg_sources, semantic_call_name,
                semantic_name, arity_contract, expected_arg_widths,
            )
        return None, expr_verified, push_align, remat_expr, expected_args, ordered_sources

    def _remat_debug_8616(self, call: StructuredAstValue, fmt_tail: str, *args: StructuredAstValue) -> None:
        """Emit the standard call-rematerialization debug line when enabled."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-remat] function=%#x target=%s " + fmt_tail,
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                getattr(call, "callee_target", None),
                *args,
            )

    def _remat_stack_variable_verdict_8616(self, node: StructuredAstValue, call: StructuredAstValue) -> bool:
        """Return whether a stack-variable arg node still needs rematerialization."""
        variable = node.variable
        name = getattr(variable, "name", None) or node.name
        if isinstance(variable, SimStackVariable):
            if isinstance(name, str) and (
                name.startswith(("arg_", "stack_", "s_"))
            ):
                self._remat_debug_8616(call, 'reason=stack-placeholder name=%s offset=%r',name, variable.offset)
                return True
            offset = variable.offset
            if isinstance(offset, int) and offset <= 2:
                self._remat_debug_8616(call, 'reason=small-stack-offset offset=%r',offset)
                return True
    def _remat_arith_source_verdict_8616(self,
        arg: StructuredAstValue,
        arg_index: int,
        call: StructuredAstValue,
        expected_args: StructuredAstValue,
        *,
        expr_source_alignment_verified: bool,
        rematerialize_for_expr_sources: bool,
    ) -> bool:
        """Verdict for an arithmetic-expression push source arg."""
        if (
            expr_source_alignment_verified
            and not rematerialize_for_expr_sources
            and _call_arg_semantic_key_8616(arg) == _call_arg_semantic_key_8616(expected_args[arg_index])
        ):
            return False
        self._remat_debug_8616(call, 'reason=push-expr-ops arg=%d', arg_index)
        return True

    def _remat_arg_verdict_8616(
        self,
        arg: StructuredAstValue,
        arg_index: int,
        ordered_push_sources: StructuredAstValue,
        call: StructuredAstValue,
        *,
        semantic_call_name: str | None,
        semantic_name: str | None,
        expr_source_alignment_verified: bool,
        rematerialize_for_expr_sources: bool,
        expected_args: StructuredAstValue,
        arity_satisfied: bool,
        callee_prototype: StructuredAstValue,
    ) -> bool:
        """Return whether this arg needs rematerialization."""
        node = arg
        while isinstance(node, CTypeCast):
            node = node.expr
        source = ordered_push_sources[arg_index] if arg_index < len(ordered_push_sources) else None
        if (
            _bound_call_argument_requires_rematerialization_8616(self.codegen, arg)
            and isinstance(source, tuple)
            and self._direct_expr_from_push_source_8616(
                source,
                call_name=semantic_call_name or getattr(call, "callee_target", None),
                arg_index=arg_index,
                force_pointer_arg=self._call_arg_is_pointer_shaped_8616(arg),
            )
            is not None
        ):
            self._remat_debug_8616(call, 'reason=unresolved-virtual-carrier arg=%d',arg_index)
            return True
        if self._push_source_is_arithmetic_expr_8616(source):
            return self._remat_arith_source_verdict_8616(
                arg, arg_index, call, expected_args,
                expr_source_alignment_verified=expr_source_alignment_verified,
                rematerialize_for_expr_sources=rematerialize_for_expr_sources,
            )
        if self._node_contains_placeholder_stack_8616(node):
            self._remat_debug_8616(call, 'reason=stack-placeholder-expression')
            return True
        if self._is_stable_named_stack_value_expr_8616(node):
            return False
        if self._plain_bp_stack_load_offset(node) is not None:
            self._remat_debug_8616(call, 'reason=bp-load')
            return True
        if self._plain_stack_slot_address_offset(node) is not None:
            if self._arg_is_stable_materialized_for_contract_8616(arg_index, node, arity_satisfied=arity_satisfied, callee_prototype=callee_prototype, semantic_name=semantic_name):
                return False
            self._remat_debug_8616(call, 'reason=stack-slot-address')
            return True
        if isinstance(node, structured_c.CVariable):
            return self._remat_stack_variable_verdict_8616(node, call)
    def _remat_per_arg_scan_8616(
        self,
        call: StructuredAstValue,
        args: StructuredAstValue,
        ordered_push_sources: StructuredAstValue,
        semantic_name: str | None,
        semantic_call_name: str | None,
        arity_satisfied: StructuredAstValue,
        callee_prototype: StructuredAstValue,
        expr_source_alignment_verified: bool,
        rematerialize_for_expr_sources: bool,
        expected_args: StructuredAstValue,
    ) -> bool:
        """Per-argument rematerialization verdicts for placeholder/stack args."""
        for arg_index, arg in enumerate(args):
            if self._remat_arg_verdict_8616(
                arg,
                arg_index,
                ordered_push_sources,
                call,
                semantic_call_name=semantic_call_name,
                semantic_name=semantic_name,
                expr_source_alignment_verified=expr_source_alignment_verified,
                rematerialize_for_expr_sources=rematerialize_for_expr_sources,
                expected_args=expected_args,
                arity_satisfied=arity_satisfied,
                callee_prototype=callee_prototype,
            ):
                return True
        return False

    def _remat_debug_reason_8616(self,
        call: StructuredAstValue,
        reason: str,
        *,
        args: StructuredAstValue = (),
    ) -> None:
        """Log a rematerialization decision reason for ``call``."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-remat] function=%#x target=%s reason=%s args=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                getattr(call, "callee_target", None),
                reason,
                tuple(self._debug_expr_8616(arg) for arg in args),
            )

    def _remat_debug_keep_existing_8616(self, call: StructuredAstValue, args: StructuredAstValue) -> None:
        """Log the keep-existing-args rematerialization verdict."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-remat] function=%#x target=%s reason=keep-existing args=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                getattr(call, "callee_target", None),
                _boundary_tuple_8616(
                    getattr(getattr(arg, "variable", None), "name", None)
                    or getattr(arg, "name", None)
                    or arg.__class__.__name__
                    for arg in args
                ),
            )

    def _call_args_need_rematerialization_8616(self,
        call: StructuredAstValue,
        push_arg_sources: StructuredAstValue = (),
        *,
        semantic_call_name: str | None = None,
        expected_arg_widths: tuple[int, ...] | None = None,
    ) -> bool:
        rematerialize_for_expr_sources = False
        expr_source_alignment_verified = False
        push_source_arg_alignment_verified = False



        args = _boundary_tuple_8616(getattr(call, "args", ()) or ())
        if not args:
            self._remat_debug_reason_8616(call, "no-args")
            return True
        semantic_name = semantic_call_name or getattr(call, "callee_target", None) or ""
        arity_contract = _known_callee_arity_contract_8616(semantic_name)
        arity_satisfied = _call_arity_contract_allows_count_8616(arity_contract, len(args))
        callee_func = getattr(call, "callee_func", None)
        callee_prototype = getattr(callee_func, "prototype", None)


        push_sources_tuple = push_arg_sources if isinstance(push_arg_sources, tuple) else ()
        if has_literal_push_stack_carrier_8616(call, push_sources_tuple):
            return True
        ordered_push_sources = (
            list(reversed(push_sources_tuple)) if len(push_sources_tuple) > 1 else list(push_sources_tuple)
        )
        if self._remat_exact_width_mismatch_8616(call, args, ordered_push_sources):
            return True
        arith_verdict = self._remat_arith_push_source_alignment_8616(
            call, args, ordered_push_sources, semantic_call_name
        )
        if arith_verdict is not None:
            return arith_verdict


        if self._remat_bp_offset_mismatch_8616(call, args, push_arg_sources):
            return True
        (
            derived_verdict,
            expr_source_alignment_verified,
            push_source_arg_alignment_verified,
            rematerialize_for_expr_sources,
            expected_args,
            _ordered_sources_for_args,
        ) = self._remat_derived_push_args_8616(
            call, args, push_arg_sources, semantic_call_name, arity_contract, expected_arg_widths
        )
        if derived_verdict is not None:
            return derived_verdict
        if push_source_arg_alignment_verified:
            self._remat_debug_reason_8616(
                call, "keep-structured-push-source-alignment", args=args
            )
            return False
        if self._remat_per_arg_scan_8616(
            call,
            args,
            ordered_push_sources,
            semantic_name,
            semantic_call_name,
            arity_satisfied,
            callee_prototype,
            expr_source_alignment_verified,
            rematerialize_for_expr_sources,
            expected_args,
        ):
            return True
        self._remat_debug_keep_existing_8616(call, args)
        return False

    def _prototype_logical_evidence_8616(self,
        call: StructuredAstValue,
        current_summary: StructuredAstValue,
        arg_widths_live: tuple[int, ...],
    ) -> StructuredAstValue:
        callee = call.callee_func
        try:
            prototype = callee.prototype if callee is not None else None
        except AttributeError:
            prototype = None
        prototype_widths = _prototype_arg_widths_8616(self.project, prototype)
        if isinstance(prototype, SimTypeFunction) and prototype.variadic:
            return accounted_variadic_target_shape_evidence_8616(
                current_summary,
                arg_widths_live,
                prototype_widths or (),
            )
        return accounted_target_prototype_shape_evidence_8616(
            current_summary,
            arg_widths_live,
            prototype_widths,
        )

    def _publish_inventory_summary_8616(self,
        updated: StructuredAstValue,
        reconciliation: StructuredAstValue,
    ) -> None:
        summary_inventory = _callsite_summary_inventory_8616(self.codegen)
        inventory_summary = summary_inventory.get(updated.callsite_addr)
        if inventory_summary is None:
            summary_inventory[updated.callsite_addr] = updated
            self.codegen._inertia_callsite_summary_inventory_8616 = summary_inventory
            return
        projected_inventory_summary = carry_forward_logical_call_argument_shape_8616(
            inventory_summary,
            updated,
        )
        projected_inventory_summary = publish_reconciled_call_argument_shape_8616(
            projected_inventory_summary, updated, reconciliation,
        )
        if projected_inventory_summary is not inventory_summary:
            summary_inventory[updated.callsite_addr] = projected_inventory_summary

    def _refresh_summary_arg_shape(self,
        call: CFunctionCall,
        summary: CallsiteSummary8616 | None,
    ) -> None:
        """Publish a Lowering-reconciled call shape to typed callsite metadata."""
        if summary is None:
            return
        args = _boundary_tuple_8616(call.args or ())
        arg_widths_live = tuple(self._arg_width_from_expr(arg) for arg in args)
        if any(not isinstance(width, int) or width <= 0 for width in arg_widths_live):
            return
        current_summary = self.summary_map.get(id(call), summary)
        logical_evidence = self.logical_shape_evidence_by_callsite.get(current_summary.callsite_addr)
        if logical_evidence is not None and logical_evidence.widths != arg_widths_live:
            logical_evidence = None
        return_pair_evidence = exact_call_return_pair_shape_evidence_8616(current_summary)
        if (
            return_pair_evidence is not None
            and len(return_pair_evidence.widths) == len(args)
            and all(
                isinstance(args[index], CFunctionCall)
                or any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(args[index]))
                for index in return_pair_evidence.return_argument_indices
            )
        ):
            logical_evidence = return_pair_evidence
        known_widths = _known_helper_prototype_arg_widths_8616(self.project, _call_node_name_8616(call))
        if (
            known_widths is not None
            and _prototype_widths_account_for_push_sources_top_8616(
                known_widths,
                _boundary_tuple_8616(current_summary.push_arg_sources),
            )
        ):
            logical_evidence = LogicalArgumentShapeEvidence8616(
                widths=known_widths,
                source=LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_TARGET_PROTOTYPE,
            )
        if logical_evidence is None:
            logical_evidence = self._prototype_logical_evidence_8616(call, current_summary, arg_widths_live)
        reconciliation = reconcile_materialized_call_argument_shape_8616(
            current_summary,
            arg_widths_live,
            logical_evidence=logical_evidence,
        )
        updated = reconciliation.summary
        semantic_name = _semantic_call_name_from_summary_8616(
            self.project,
            current_summary,
            _call_node_name_8616(call),
        )
        helper_widths = known_helper_abi_widths_8616(semantic_name)
        if (
            helper_widths is not None
            and sum(helper_widths)
            == sum(width for width in current_summary.arg_widths if isinstance(width, int) and width > 0)
            and updated.logical_arg_widths != helper_widths
        ):
            updated = replace(updated, logical_arg_widths=helper_widths)
        # ``logical_arg_widths`` is non-comparing metadata on the frozen
        # summary. Reconciliation returns the original object when unchanged
        # and ``replace(...)`` when it publishes facts, so identity is the
        # authoritative update signal here.
        if self.summary_map.get(id(call)) is not updated:
            self.summary_map[id(call)] = updated
            self.changed = True
        self._publish_inventory_summary_8616(updated, reconciliation)

    def _record_prunable_segment_metadata_ids(self,
        call: StructuredAstValue, statements: list[StructuredAstValue], consumed_indices: list[int]
    ) -> None:
        if call is None or not consumed_indices:
            return
        tail_ids: list[int] = []
        scan = max(consumed_indices) + 1
        while scan < len(statements):
            stmt = statements[scan]
            if self._is_segment_register_metadata_store(stmt):
                tail_ids.append(id(stmt))
                scan += 1
                continue
            if self._is_stack_carrier_temp_assignment(stmt):
                scan += 1
                continue
            break
        if tail_ids:
            self.materialized_callsite_metadata_ids[id(call)] = tuple(tail_ids)

    def _consumed_index_step_8616(self,
        statement: StructuredAstValue,
        is_candidate: bool,
        setup_is_proven_dead: StructuredAstValue,
        live_identity_keys: set[StructuredAstValue],
    ) -> bool:
        """Update live-key state for one statement; return True when removable."""
        assignment = self._top_level_assignment_node_8616(statement)
        lhs = rhs = None
        lhs_key = None
        if assignment is not None:
            lhs, rhs = self._assignment_lhs_rhs(assignment)
            lhs_key = self._c_variable_identity_key_8616(lhs)
        if is_candidate:
            if lhs_key is None:
                if lhs is not None and self._assignment_lhs_writes_memory(lhs):
                    return True
                live_identity_keys.update(self._statement_variable_identity_keys_8616(statement))
                self.stats.live_setup_definition_preserved_count += 1
                return False
            if setup_is_proven_dead(lhs_key, frozenset(live_identity_keys)):
                return True
            if rhs is not None:
                live_identity_keys.update(self._statement_variable_identity_keys_8616(rhs))
            self.stats.live_setup_definition_preserved_count += 1
            return False
        if lhs_key is not None:
            live_identity_keys.discard(lhs_key)
            if rhs is not None:
                live_identity_keys.update(self._statement_variable_identity_keys_8616(rhs))
            return False
        live_identity_keys.update(self._statement_variable_identity_keys_8616(statement))
        return False

    def _delete_consumed_indices_8616(self,
        statements: list[StructuredAstValue],
        indices: list[int],
        *,
        live_consumers: tuple[StructuredAstValue, ...] = (),
    ) -> None:
        """Delete consumed setup only after proving its value has no retained read."""
        if not isinstance(statements, list) or not indices:
            return
        clean_indices = sorted(
            {int(idx) for idx in indices if isinstance(idx, int) and 0 <= int(idx) < len(statements)},
            reverse=True,
        )
        if not clean_indices:
            return
        try:
            setup_is_proven_dead = cast(
                _CallsiteMaterializationControlCarrier8616,
                self.codegen,
            )._inertia_call_argument_setup_liveness_classifier_8616
        except AttributeError as ex:
            raise PipelineHardError("Types/Lowering call-setup liveness classifier is not bound") from ex

        candidate_indices = set(clean_indices)
        live_identity_keys: set[tuple[StructuredAstValue, ...]] = set()
        for consumer in live_consumers:
            live_identity_keys.update(self._statement_variable_identity_keys_8616(consumer))
        removable_indices: list[int] = []
        for statement_idx in range(len(statements) - 1, -1, -1):
            if self._consumed_index_step_8616(
                statements[statement_idx],
                statement_idx in candidate_indices,
                setup_is_proven_dead,
                live_identity_keys,
            ):
                removable_indices.append(statement_idx)

        for idx in sorted(removable_indices, reverse=True):
            del statements[idx]

    def _call_from_statement(self, stmt: StructuredAstValue) -> StructuredAstValue | None:
        """Extract a direct call expression from a supported statement shell."""
        if isinstance(stmt, CFunctionCall):
            return stmt
        for attr in ("expr", "rhs", "src", "retval"):
            value = getattr(stmt, attr, None)
            if isinstance(value, CFunctionCall):
                return value
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)) and len(nested_statements) == 1:
            return self._call_from_statement(nested_statements[0])
        return None

    def _statement_contains_call(self, stmt: StructuredAstValue) -> bool:
        """Return whether a statement subtree contains any call node."""
        marker = id(stmt)
        cached = self.statement_contains_call_cache.get(marker)
        if cached is not None:
            return cached
        result = False
        if isinstance(stmt, CFunctionCall):
            result = True
        else:
            expr = getattr(stmt, "expr", None)
            if isinstance(expr, CFunctionCall):
                result = True
            else:
                for node in _iter_c_nodes_deep_8616(stmt):
                    if isinstance(node, CFunctionCall):
                        result = True
                        break
        self.statement_contains_call_cache[marker] = result
        return result

    def _fold_dx_ax_return_pair_assignments_8616(self, statements: list[StructuredAstValue]) -> bool:














        if not isinstance(statements, list):
            return False
        changed = self._fold_list(statements)
        changed = self._fold_later_stale_return_pair_by_preorder_8616(statements, []) or changed
        return changed

    def _is_standalone_call_statement_8616(self, stmt: StructuredAstValue, call: StructuredAstValue) -> bool:
        if call is None:
            return False
        if stmt is call:
            return True
        return getattr(stmt, "expr", None) is call

    def _is_consumable_return_call_statement_8616(self, stmt: StructuredAstValue, call: StructuredAstValue) -> bool:
        if self._is_standalone_call_statement_8616(stmt, call):
            return True
        return isinstance(stmt, structured_c.CAssignment) and getattr(stmt, "rhs", None) is call

    def _ret_reg_source_info_8616(self, source: StructuredAstValue) -> tuple[int, str] | None:
        if not (
            isinstance(source, tuple)
            and len(source) >= 3
            and source[0] == CallsitePushSourceKind8616.RETURN_REGISTER.value
            and isinstance(source[1], int)
            and isinstance(source[2], str)
        ):
            return None
        reg_name = source[2].lower()
        if reg_name not in {"ax", "dx"}:
            return None
        return int(source[1]), reg_name

    def _call_args_embed_return_source_callsites_8616(self,
        call: StructuredAstValue,
        ordered_sources: list[StructuredAstValue],
    ) -> bool:
        """Prove that return-register producer calls already occur in call arguments."""
        expected_callsites = {
            info[0]
            for source in ordered_sources
            if (info := self._ret_reg_source_info_8616(source)) is not None
        }
        embedded_callsites = {
            callsite_addr
            for arg in _boundary_tuple_8616(getattr(call, "args", ()) or ())
            for node in (arg, *_iter_c_nodes_deep_8616(arg))
            if isinstance(node, CFunctionCall)
            if isinstance((callsite_addr := structured_callsite_addr_8616(node)), int)
        }
        return bool(expected_callsites) and expected_callsites <= embedded_callsites

    def _summary_for_call_node_8616(self,
        call: StructuredAstValue, callsite_addr: int
    ) -> CallsiteSummary8616 | None:
        """Resolve a cloned call through its stable machine callsite identity."""
        summary = self.summary_map.get(id(call))
        if summary is not None:
            return summary
        tagged_callsite = structured_callsite_addr_8616(call)
        return self.summary_by_callsite_addr.get(callsite_addr) if tagged_callsite == callsite_addr else None

    def _walk_return_call_matches_8616(self,
        node: StructuredAstValue,
        callsite_addr: int,
        matches: list[StructuredAstValue],
    ) -> None:
        if node is None:
            return
        container = getattr(node, "statements", None)
        if isinstance(container, list):
            self._scan_return_call_container_8616(container, callsite_addr, matches)
        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if child is not None:
                self._walk_return_call_matches_8616(child, callsite_addr, matches)
        self._walk_return_call_condition_nodes_8616(getattr(node, "condition_and_nodes", None), callsite_addr, matches)

    def _scan_return_call_container_8616(self,
        container: list[StructuredAstValue],
        callsite_addr: int,
        matches: list[StructuredAstValue],
    ) -> None:
        """Append matching return-call carriers in ``container`` and recurse."""
        for idx, stmt in enumerate(list(container)):
            call = self._call_from_statement(stmt)
            summary = self._summary_for_call_node_8616(call, callsite_addr) if call is not None else None
            if (
                call is not None
                and summary is not None
                and summary.callsite_addr == callsite_addr
                and self._is_consumable_return_call_statement_8616(stmt, call)
            ):
                matches.append((container, idx, call, summary))
            self._walk_return_call_matches_8616(stmt, callsite_addr, matches)

    def _walk_return_call_condition_nodes_8616(self,
        condition_nodes: StructuredAstValue,
        callsite_addr: int,
        matches: list[StructuredAstValue],
    ) -> None:
        """Recurse into ``condition_and_nodes`` items."""
        if not isinstance(condition_nodes, (list, tuple)):
            return
        for item in condition_nodes:
            if isinstance(item, (list, tuple)):
                for child in item:
                    self._walk_return_call_matches_8616(child, callsite_addr, matches)
            else:
                self._walk_return_call_matches_8616(item, callsite_addr, matches)

    def _find_unique_standalone_return_call_ref_8616(self, callsite_addr: int) -> StructuredAstValue:
        root = _structured_root_8616(getattr(self.codegen, "cfunc", None))
        matches: list[tuple[list[StructuredAstValue], int, StructuredAstValue, StructuredAstValue]] = []

        self._walk_return_call_matches_8616(root, callsite_addr, matches)
        return matches[0] if len(matches) == 1 else None

    def _nearest_standalone_return_call_8616(self,
        statements: list[StructuredAstValue], callsite_addr: int
    ) -> StructuredAstValue:
        for idx in range(len(statements) - 1, -1, -1):
            stmt = statements[idx]
            call = self._call_from_statement(stmt)
            if call is None:
                continue
            summary = self.summary_map.get(id(call))
            if summary is None and structured_callsite_addr_8616(call) == callsite_addr:
                summary = self.summary_by_callsite_addr.get(callsite_addr)
            if (
                summary is not None
                and summary.callsite_addr == callsite_addr
                and self._is_consumable_return_call_statement_8616(stmt, call)
            ):
                return statements, idx, call, summary
            return None
        return self._find_unique_standalone_return_call_ref_8616(callsite_addr)

    def _delete_consumed_return_call_refs_8616(self, refs: StructuredAstValue) -> bool:
        """Delete exact standalone return-call carriers consumed as call arguments."""
        if not refs:
            return False
        grouped: dict[int, tuple[list[StructuredAstValue], set[int]]] = {}
        for ref in refs:
            if not isinstance(ref, tuple) or len(ref) != 2:
                continue
            container, idx = ref
            if not isinstance(container, list) or not isinstance(idx, int):
                continue
            if idx < 0 or idx >= len(container):
                continue
            key = id(container)
            if key not in grouped:
                grouped[key] = (container, set())
            grouped[key][1].add(idx)
        deleted = False
        for container, indices in grouped.values():
            for idx in sorted(indices, reverse=True):
                del container[idx]
                deleted = True
        return deleted

    def _record_materialized_return_call_expr_8616(self, call: StructuredAstValue, summary: StructuredAstValue) -> None:
        if call is None or summary is None:
            return
        callsite_addr = summary.callsite_addr
        if not isinstance(callsite_addr, int):
            return
        if not _boundary_tuple_8616(getattr(call, "args", ()) or ()):
            return
        if not isinstance(call, CFunctionCall) or not isinstance(summary, CallsiteSummary8616):
            raise TypeError("materialized return-call state requires typed call and summary contracts")
        bind_structured_callsite_identity_8616(call, summary)
        cloned_call = self._clone_c_ast_tree(call)
        if not isinstance(cloned_call, CFunctionCall):
            raise TypeError("materialized return-call clone must remain a CFunctionCall")
        bind_structured_callsite_identity_8616(cloned_call, summary)
        self.return_call_exprs_by_callsite[callsite_addr] = cloned_call
        self.codegen._inertia_callsite_return_exprs_8616 = dict(self.return_call_exprs_by_callsite)

    def _stored_return_call_expr_for_callsite_8616(self, callsite_addr: int) -> StructuredAstValue | None:
        stored_return_call = self.return_call_exprs_by_callsite.get(callsite_addr)
        if stored_return_call is not None:
            return stored_return_call
        persistent_return_calls = getattr(self.codegen, "_inertia_callsite_return_exprs_8616", None)
        if isinstance(persistent_return_calls, dict):
            stored_return_call = persistent_return_calls.get(callsite_addr)
            if stored_return_call is not None:
                self.return_call_exprs_by_callsite[callsite_addr] = stored_return_call
                return stored_return_call
        return None

    def _summary_for_callsite_addr_8616(self, callsite_addr: int) -> StructuredAstValue | None:
        summary = self.summary_by_callsite_addr.get(callsite_addr)
        if summary is not None:
            return summary
        for summary in tuple(self.summary_map.values()):
            if summary.callsite_addr == callsite_addr:
                return summary
        return None

    def _callee_name_for_summary_8616(self, summary: StructuredAstValue) -> str | None:
        target_addr = summary.target_addr
        candidates: list[str | None] = []
        if isinstance(target_addr, int):
            synthetic_globals = getattr(self.codegen, "_inertia_synthetic_globals", None)
            if not isinstance(synthetic_globals, dict):
                synthetic_globals = getattr(self.project, "_inertia_synthetic_globals", None)
            if isinstance(synthetic_globals, dict):
                synthetic = synthetic_globals.get(target_addr)
                if isinstance(synthetic, tuple) and synthetic and isinstance(synthetic[0], str):
                    candidates.append(synthetic[0])
            candidates.append(_sidecar_label_for_target_8616(self.project, target_addr))
            callee = _lookup_callee_function_8616(self.project, target_addr, allow_containing=False)
            candidates.append(getattr(callee, "name", None))
        for raw in candidates:
            normalized = normalize_callee_name_8616(raw)
            if isinstance(normalized, str) and normalized:
                return normalized
        return None

    def _synthesized_return_call_expr_from_summary_8616(self, callsite_addr: int) -> StructuredAstValue | None:
        summary = self._summary_for_callsite_addr_8616(callsite_addr)
        if summary is None:
            return None
        callee_name = self._callee_name_for_summary_8616(summary)
        if not isinstance(callee_name, str) or not callee_name:
            return None
        push_sources = _boundary_tuple_8616(summary.push_arg_sources or ())
        if not push_sources:
            return None
        ordered_sources = list(reversed(push_sources)) if len(push_sources) > 1 else list(push_sources)
        expected_widths = _known_helper_prototype_arg_widths_8616(self.project, callee_name)
        if expected_widths is None or not _prototype_widths_account_for_push_sources_top_8616(
            expected_widths, push_sources
        ):
            arity_contract = _known_callee_arity_contract_8616(callee_name)
            source_width = _push_sources_total_width_for_arg_accounting_8616(push_sources)
            logical_arg_count = (
                arity_contract.count
                if isinstance(arity_contract.count, int) and arity_contract.count > 0
                else len(expected_widths)
                if expected_widths
                else None
            )
            if (
                isinstance(logical_arg_count, int)
                and logical_arg_count > 0
                and isinstance(source_width, int)
                and source_width >= logical_arg_count * 2
                and source_width % logical_arg_count == 0
            ):
                expected_widths = (source_width // logical_arg_count,) * logical_arg_count
        args = self._logical_args_from_push_sources_by_expected_widths_8616(
            ordered_sources,
            expected_arg_widths=expected_widths,
            call_name=callee_name,
        )
        if args is None:
            args = [
                self._direct_expr_from_push_source_8616(source, call_name=callee_name, arg_index=idx)
                for idx, source in enumerate(ordered_sources)
            ]
        if not args or any(arg is None for arg in args):
            return None
        target_addr = summary.target_addr
        callee_func = (
            _lookup_callee_function_8616(self.project, target_addr, allow_containing=False)
            if isinstance(target_addr, int)
            else None
        )
        ret_call_expr = CFunctionCall(
            callee_name,
            callee_func,
            [self._clone_c_ast_tree(arg) for arg in args],
            codegen=self.codegen,
        )
        bind_structured_callsite_identity_8616(ret_call_expr, summary)
        with contextlib.suppress(Exception):
            cast(Any, ret_call_expr).type = _summary_return_type_8616(self.project, summary)
        self.return_call_exprs_by_callsite[callsite_addr] = self._clone_c_ast_tree(ret_call_expr)
        self.codegen._inertia_callsite_return_exprs_8616 = dict(self.return_call_exprs_by_callsite)
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-ret-reg-producer-synth] function=%#x return_call=%s ret_callsite=%#x args=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                callee_name,
                callsite_addr,
                tuple(self._debug_expr_8616(arg) for arg in args),
            )
        return ret_call_expr

    def _regroup_return_call_args_from_summary_8616(self, call: StructuredAstValue, summary: StructuredAstValue) -> None:
        if call is None or summary is None:
            return
        args = _boundary_tuple_8616(getattr(call, "args", ()) or ())
        push_sources = _boundary_tuple_8616(summary.push_arg_sources or ())
        if len(args) <= 1 or not push_sources:
            return
        callee_name = _call_node_name_8616(call) or self._callee_name_for_summary_8616(summary)
        if not isinstance(callee_name, str) or not callee_name:
            return
        expected_widths = _known_helper_prototype_arg_widths_8616(self.project, callee_name)
        if expected_widths is None or not _prototype_widths_account_for_push_sources_top_8616(
            expected_widths, push_sources
        ):
            arity_contract = _known_callee_arity_contract_8616(callee_name)
            source_width = _push_sources_total_width_for_arg_accounting_8616(push_sources)
            logical_arg_count = (
                arity_contract.count
                if isinstance(arity_contract.count, int) and arity_contract.count > 0
                else len(expected_widths)
                if expected_widths
                else None
            )
            if (
                isinstance(logical_arg_count, int)
                and logical_arg_count > 0
                and isinstance(source_width, int)
                and source_width >= logical_arg_count * 2
                and source_width % logical_arg_count == 0
            ):
                expected_widths = (source_width // logical_arg_count,) * logical_arg_count
        ordered_sources = list(reversed(push_sources)) if len(push_sources) > 1 else list(push_sources)
        grouped_args = self._group_scalar_args_by_expected_widths_8616(
            list(args),
            expected_arg_widths=expected_widths,
            push_sources=tuple(ordered_sources),
        )
        if grouped_args is not None and len(grouped_args) < len(args):
            call.args = grouped_args
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-ret-reg-producer-regroup] function=%#x return_call=%s args_before=%r args_after=%r",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    callee_name,
                    tuple(self._debug_expr_8616(arg) for arg in args),
                    tuple(self._debug_expr_8616(arg) for arg in grouped_args),
                )

    def _ret_arg_without_nearby_call_8616(
        self,
        statements: list[StructuredAstValue],
        ordered_sources: StructuredAstValue,
        source_idx: int,
        first_callsite: StructuredAstValue,
        first_reg: str,
        result_read: StructuredAstValue,
        call_name: str,
    ) -> StructuredAstValue | None:
        """Handle the return-source arm when no standalone return call exists."""
        if result_read.verdict is RuntimeCallResultVerdict8616.UNKNOWN_REFUSE:
            return None
        stored_return_call = self._stored_return_call_expr_for_callsite_8616(first_callsite)
        if stored_return_call is None:
            stored_return_call = self._synthesized_return_call_expr_from_summary_8616(first_callsite)
        if stored_return_call is not None and source_idx + 1 < len(ordered_sources):
            second_info = self._ret_reg_source_info_8616(ordered_sources[source_idx + 1])
            if (
                second_info is not None
                and second_info[0] == first_callsite
                and {first_reg, second_info[1]} == {"ax", "dx"}
            ):
                ret_call_expr = self._clone_c_ast_tree(stored_return_call)
                producer_summary = self._summary_for_callsite_addr_8616(first_callsite)
                self._regroup_return_call_args_from_summary_8616(ret_call_expr, producer_summary)
                ret_call_expr = self._mark_return_register_arg_8616(
                    ret_call_expr,
                    first_callsite,
                    (first_reg, second_info[1]),
                )
                with contextlib.suppress(Exception):
                    cast(Any, ret_call_expr).type = _summary_type_8616(self.project, 4)
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-ret-reg-consume] function=%#x target=%s return_call=%s ret_callsite=%#x regs=%s source=recorded",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        call_name,
                        _call_node_name_8616(stored_return_call),
                        first_callsite,
                        tuple(sorted({first_reg, second_info[1]})),
                    )
                return ret_call_expr, 2, None
        if (
            first_reg == "ax"
            and (stored_return_call := self._stored_return_call_expr_for_callsite_8616(first_callsite)) is not None
        ):
            ret_call_expr = self._clone_c_ast_tree(stored_return_call)
            producer_summary = self._summary_for_callsite_addr_8616(first_callsite)
            self._regroup_return_call_args_from_summary_8616(ret_call_expr, producer_summary)
            ret_call_expr = self._mark_return_register_arg_8616(ret_call_expr, first_callsite, (first_reg,))
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-ret-reg-consume] function=%#x target=%s return_call=%s ret_callsite=%#x regs=%s source=recorded",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    _call_node_name_8616(stored_return_call),
                    first_callsite,
                    (first_reg,),
                )
            return ret_call_expr, 1, None
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            self._ret_consume_debug_refuse_8616(statements, call_name, first_callsite, first_reg)
        return None

    def _ret_consume_debug_refuse_8616(self,
        statements: list[StructuredAstValue],
        call_name: str | None,
        first_callsite: int,
        first_reg: str,
    ) -> None:
        """Log a missing-return-call refusal with the prefix call census."""
        prefix_calls = []
        for stmt in statements[-8:]:
            call = self._call_from_statement(stmt)
            if call is None:
                continue
            summary = self.summary_map.get(id(call))
            prefix_calls.append(
                (
                    _call_node_name_8616(call),
                    summary.callsite_addr if summary is not None else None,
                    stmt.__class__.__name__,
                )
            )
        log.warning(
            "[call-ret-reg-consume-refuse] function=%#x target=%s reason=missing-return-call ret_callsite=%#x reg=%s prefix_calls=%r",
            getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
            call_name,
            first_callsite,
            first_reg,
            tuple(prefix_calls),
        )
    def _return_call_arg_from_ret_sources_8616(self,
        ordered_sources: list[StructuredAstValue],
        source_idx: int,
        statements: list[StructuredAstValue],
        *,
        call_name: str | None,
    ) -> tuple[StructuredAstValue, int, StructuredAstValue | None] | None:
        """Consume only the register sources proven to belong to one return value."""

        first_info = (
            self._ret_reg_source_info_8616(ordered_sources[source_idx]) if 0 <= source_idx < len(ordered_sources) else None
        )
        if first_info is None:
            return None
        first_callsite, first_reg = first_info
        result_read = materialize_runtime_call_result_read_8616(
            _structured_root_8616(self.codegen.cfunc), statements, first_callsite, first_reg,
            codegen=self.codegen, function_addr=self.codegen.cfunc.addr,
        )
        self.codegen._inertia_runtime_call_result_read_8616 = result_read
        if result_read.verdict is RuntimeCallResultVerdict8616.PROVEN:
            return result_read.expression, 1, None
        nearest = self._nearest_standalone_return_call_8616(statements, first_callsite)
        if nearest is None:
            return self._ret_arg_without_nearby_call_8616(
                statements, ordered_sources, source_idx, first_callsite,
                first_reg, result_read, call_name,
            )
        call_container, call_stmt_idx, return_call, return_summary = nearest


        if source_idx + 1 < len(ordered_sources):
            second_info = self._ret_reg_source_info_8616(ordered_sources[source_idx + 1])
            if (
                second_info is not None
                and second_info[0] == first_callsite
                and {first_reg, second_info[1]} == {"ax", "dx"}
            ):
                ret_call_expr = self._return_call_expr_with_materialized_args_8616(first_callsite=first_callsite, return_call=return_call, return_summary=return_summary)
                ret_call_expr = self._mark_return_register_arg_8616(
                    ret_call_expr,
                    first_callsite,
                    (first_reg, second_info[1]),
                )
                with contextlib.suppress(Exception):
                    cast(Any, ret_call_expr).type = (
                        _summary_return_type_8616(self.project, return_summary)
                        if getattr(return_summary, "return_shape", None) == "dx_ax"
                        else _summary_type_8616(self.project, 4)
                    )
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-ret-reg-consume] function=%#x target=%s return_call=%s ret_callsite=%#x regs=%s",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        call_name,
                        _call_node_name_8616(return_call),
                        first_callsite,
                        tuple(sorted({first_reg, second_info[1]})),
                    )
                return ret_call_expr, 2, (call_container, call_stmt_idx)

        if (
            first_reg == "ax"
            and getattr(return_summary, "return_register", None) == "ax"
            and getattr(return_summary, "return_used", None) is True
            and getattr(return_summary, "return_shape", None) in {None, "ax"}
        ):
            ret_call_expr = self._return_call_expr_with_materialized_args_8616(first_callsite=first_callsite, return_call=return_call, return_summary=return_summary)
            ret_call_expr = self._mark_return_register_arg_8616(ret_call_expr, first_callsite, (first_reg,))
            with contextlib.suppress(Exception):
                cast(Any, ret_call_expr).type = _summary_return_type_8616(self.project, return_summary)
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-ret-reg-consume] function=%#x target=%s return_call=%s ret_callsite=%#x regs=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    call_name,
                    _call_node_name_8616(return_call),
                    first_callsite,
                    (first_reg,),
                )
            return ret_call_expr, 1, (call_container, call_stmt_idx)
        return None

    def _direct_args_from_ordered_push_sources_consuming_return_calls_8616(self,
        ordered_sources: list[StructuredAstValue],
        *,
        call_name: str | None,
        statements: list[StructuredAstValue],
    ) -> tuple[
        list[StructuredAstValue] | None,
        tuple[tuple[list[StructuredAstValue], int], ...],
    ]:
        direct_args: list[StructuredAstValue] = []
        consumed_return_call_indices: list[tuple[list[StructuredAstValue], int]] = []
        return_args_materialized_count = 0
        source_idx = 0
        while source_idx < len(ordered_sources):
            ret_arg = self._return_call_arg_from_ret_sources_8616(
                ordered_sources,
                source_idx,
                statements,
                call_name=call_name,
            )
            if ret_arg is not None:
                expr, consumed_sources, call_stmt_ref = ret_arg
                direct_args.append(expr)
                return_args_materialized_count += 1
                if call_stmt_ref is not None:
                    consumed_return_call_indices.append(call_stmt_ref)
                source_idx += consumed_sources
                continue
            expr = self._direct_expr_from_push_source_8616(
                ordered_sources[source_idx],
                call_name=call_name,
                arg_index=len(direct_args),
            )
            if expr is None:
                return None, ()
            direct_args.append(expr)
            source_idx += 1
        if return_args_materialized_count:
            self.codegen._inertia_return_register_call_args_materialized_8616 = (
                int(getattr(self.codegen, "_inertia_return_register_call_args_materialized_8616", 0) or 0)
                + return_args_materialized_count
            )
        return direct_args, tuple(consumed_return_call_indices)

    def _probe_assignment_is_stable_store_8616(self, assignment: StructuredAstValue) -> bool:
        lhs, _rhs = self._assignment_lhs_rhs(assignment)
        dereference = lhs
        while isinstance(dereference, CTypeCast):
            dereference = dereference.expr
        if not (isinstance(dereference, CUnaryOp) and dereference.op == "Dereference"):
            return False
        operand = dereference.operand
        if isinstance(_stack_offset_from_expr_8616(operand, self.project, self.codegen), int):
            return True
        segment_name, _terms = _match_real_mode_segmented_store_shape_8616(lhs, self.project)
        has_named_stack_reference = any(
            isinstance(node, CUnaryOp)
            and node.op == "Reference"
            and isinstance(node.operand, structured_c.CVariable)
            and isinstance(node.operand.variable, SimStackVariable)
            for node in (operand, *_iter_c_nodes_deep_8616(operand))
        )
        return bool(segment_name == "ss" and has_named_stack_reference)

    def _stack_probe_helper_statement_is_consumable_8616(self,
        stmt: StructuredAstValue,
        call: CFunctionCall,
        summary: CallsiteSummary8616 | None,
        statements: list[StructuredAstValue],
        probe_index: int,
        typed_fact: TypedStackProbeReturnFact8616 | None,
    ) -> bool:
        """Return whether an evidence-backed compiler stack probe is fully represented by C locals."""
        if not self._is_standalone_call_statement_8616(stmt, call):
            return False
        if _boundary_tuple_8616(call.args or ()):
            return False
        call_name = _call_node_name_8616(call)
        if summary is None or not bool(summary.stack_probe_helper):
            return bool(summary is None and not self.summary_map and _is_stack_probe_call_name_8616(call_name))
        if int(summary.arg_count or 0) != 0 or summary.stack_cleanup not in {None, 0}:
            return False
        if typed_fact is None or typed_fact.segment_space != "ss":
            return False

        stable_store_count = 0
        following_arg_count: int | None = None
        for candidate in statements[probe_index + 1 :]:
            candidate_call = self._call_from_statement(candidate)
            candidate_summary = self.summary_map.get(id(candidate_call)) if candidate_call is not None else None
            if candidate_call is not None and not bool(candidate_summary and candidate_summary.stack_probe_helper):
                following_arg_count = candidate_summary.arg_count if candidate_summary is not None else None
                break
            for assignment in self._iter_assignment_nodes(candidate):
                if self._probe_assignment_is_stable_store_8616(assignment):
                    stable_store_count += 1
        return stable_store_count > 0 and (
            not isinstance(following_arg_count, int)
            or following_arg_count <= 0
            or stable_store_count >= following_arg_count
        )

    def _has_nonvirtual_dirty_probe_consumer_8616(self,
        statements: list[StructuredAstValue],
        probe_index: int,
    ) -> bool:
        """Refuse probe pruning while an unclassified dirty consumer remains."""
        for candidate in statements[probe_index + 1 :]:
            candidate_call = self._call_from_statement(candidate)
            candidate_summary = self.summary_map.get(id(candidate_call)) if candidate_call is not None else None
            if candidate_call is not None and not bool(
                candidate_summary is not None and candidate_summary.stack_probe_helper
            ):
                break
            for node in (candidate, *_iter_c_nodes_deep_8616(candidate)):
                if node.__class__.__name__ == "CDirtyExpression" and not self._is_virtual_dirty_expr_8616(node):
                    return True
        return False

    def _assignment_lhs_rhs(self,
        node: StructuredAstValue,
    ) -> tuple[StructuredAstValue | None, StructuredAstValue | None]:
        """Return assignment lhs/rhs across angr C and AIL assignment shapes."""
        lhs = getattr(node, "lhs", None)
        rhs = getattr(node, "rhs", None)
        if lhs is None and hasattr(node, "dst"):
            lhs = getattr(node, "dst", None)
            rhs = getattr(node, "src", None)
        return lhs, rhs

    def _is_assignment_node(self, node: StructuredAstValue) -> bool:
        """Return whether a node has assignment semantics."""
        class_name = node.__class__.__name__
        if class_name == "CAssignment" or class_name.endswith("Assignment"):
            return True
        return hasattr(node, "dst") and hasattr(node, "src")

    def _iter_assignment_nodes(self, stmt: StructuredAstValue) -> list[StructuredAstValue]:
        """Return assignment nodes contained in a statement tree."""
        candidates: list[StructuredAstValue] = []
        seen_ids: set[int] = set()
        for node in (stmt, *_iter_c_nodes_deep_8616(stmt)):
            if self._is_assignment_node(node) and id(node) not in seen_ids:
                candidates.append(node)
                seen_ids.add(id(node))
        return candidates

    def _statement_sequence_identity_changed_8616(self,
        original: list[StructuredAstValue], rewritten: list[StructuredAstValue]
    ) -> bool:
        """Return true when block statement membership changed without deep AST equality."""
        if len(original) != len(rewritten):
            return True
        return any(before is not after for before, after in zip(original, rewritten, strict=False))

    def _contains_ss_evidence_for_callstack_8616(self, term: StructuredAstValue) -> bool:
        if term is None:
            return False
        nodes = (term, *_iter_c_nodes_deep_8616(term))
        for raw_node in nodes:
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            variable = getattr(node, "variable", None)
            register_name = getattr(variable, "name", None)
            if isinstance(register_name, str) and register_name.lower() == "ss":
                return True
            seg_name, _linear = _match_real_mode_linear_expr_8616(node, self.project)
            if seg_name == "ss":
                return True
            segment_selector = getattr(node, "segment_selector", None)
            if isinstance(segment_selector, str) and segment_selector.lower() == "ss":
                return True
        return False

    def _contains_ss_dereference_for_callstack_8616(self, term: StructuredAstValue) -> bool:
        if term is None:
            return False
        nodes = (term, *_iter_c_nodes_deep_8616(term))
        for raw_node in nodes:
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            if (
                isinstance(node, CUnaryOp)
                and node.op == "Dereference"
                and self._contains_ss_evidence_for_callstack_8616(getattr(node, "operand", None))
            ):
                return True
        return False

    def _contains_unresolved_dirty_expr_8616(self, term: StructuredAstValue) -> bool:
        nodes = (term, *_iter_c_nodes_deep_8616(term))
        for raw_node in nodes:
            if raw_node.__class__.__name__ != "CDirtyExpression":
                continue
            if self._is_virtual_dirty_expr_8616(raw_node):
                continue
            return True
        return False

    def _contains_dirty_expr_8616(self, term: StructuredAstValue) -> bool:
        nodes = (term, *_iter_c_nodes_deep_8616(term))
        return any(raw_node.__class__.__name__ == "CDirtyExpression" for raw_node in nodes)

    def _deref_stack_store_rhs_verdict_8616(self, lhs: StructuredAstValue, rhs: StructuredAstValue) -> StructuredAstValue | None:
        """Final verdict for dereference-shaped stack-store lhs."""
        deref = lhs
        while isinstance(deref, CTypeCast):
            deref = deref.expr
        if not isinstance(deref, CUnaryOp) or deref.op != "Dereference":
            if self._contains_ss_dereference_for_callstack_8616(lhs):
                return rhs
            return None
        if isinstance(_stack_offset_from_expr_8616(getattr(deref, "operand", None), self.project, self.codegen), int):
            return rhs
        if self._contains_ss_evidence_for_callstack_8616(getattr(deref, "operand", None)):
            return rhs
        return None

    def _stack_store_rhs_verdict_8616(self, lhs: StructuredAstValue, rhs: StructuredAstValue) -> StructuredAstValue | None:
        """Return rhs when the assignment lhs is a proven stack store target."""
        if classify_push_store_width_8616(lhs) is not PushStoreWidthVerdict8616.COMPLETE_WIDTH:
            return None
        if self._contains_unresolved_dirty_expr_8616(lhs):
            return None
        if _is_consumed_push_ss_store_lhs_8616(self.project, self.codegen, lhs):
            return rhs
        seg_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, self.project)
        if seg_name == "ss":
            return rhs
        if _match_bp_stack_dereference_8616(lhs, self.project, self.codegen) is not None:
            return rhs
        seg_name, _linear = _match_segmented_dereference_8616(lhs, self.project)
        if seg_name == "ss":
            return rhs
        return self._deref_stack_store_rhs_verdict_8616(lhs, rhs)
    def _stack_store_rhs_from_statement(self, stmt: StructuredAstValue) -> StructuredAstValue | None:
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            for nested in reversed(tuple(nested_statements)):
                rhs = self._stack_store_rhs_from_statement(nested)
                if rhs is not None:
                    return rhs
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if self._is_stack_carrier_temp_assignment(nested) or self._is_non_memory_assignment(nested):
                    continue
            return None

        self.project = getattr(self.codegen, "project", None)

        for assignment in reversed(self._iter_assignment_nodes(stmt)):
            lhs, rhs = self._assignment_lhs_rhs(assignment)
            if lhs is None:
                continue
            verdict = self._stack_store_rhs_verdict_8616(lhs, rhs)
            if verdict is not None:
                return verdict
        return None

    def _store_matches_typed_stack_probe_fact(self,
        lhs: StructuredAstValue, fact: TypedStackProbeReturnFact8616 | None
    ) -> bool:
        if lhs is None or fact is None:
            return False


        seg_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, self.project)
        if any(self._contains_unsafe_dirty_term(term) for _sign, term in _offset_terms):
            return False
        if seg_name == fact.segment_space:
            return True

        deref = lhs
        while isinstance(deref, CTypeCast):
            deref = deref.expr
        if not isinstance(deref, CUnaryOp) or deref.op != "Dereference":
            return False
        stack_offset = _stack_offset_from_expr_8616(getattr(deref, "operand", None), self.project, self.codegen)
        return isinstance(stack_offset, int)

    def _typed_stack_store_rhs_from_statement(self,
        stmt: StructuredAstValue, fact: TypedStackProbeReturnFact8616 | None
    ) -> StructuredAstValue:
        if fact is None:
            return None
        for assignment in reversed(self._iter_assignment_nodes(stmt)):
            lhs, rhs = self._assignment_lhs_rhs(assignment)
            if not self._assignment_lhs_writes_memory(lhs):
                continue
            if self._is_segment_register_value_expr(rhs):
                continue
            if self._store_matches_typed_stack_probe_fact(lhs, fact):
                return rhs
        return None

    def _stack_store_rhss_from_statement(self, stmt: StructuredAstValue, *, max_collect: int = 4) -> list[StructuredAstValue]:
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            rhss: list[StructuredAstValue] = []
            for nested in reversed(tuple(nested_statements)):
                nested_rhss = self._stack_store_rhss_from_statement(nested, max_collect=max_collect)
                if nested_rhss:
                    rhss.extend(reversed(nested_rhss))
                    if len(rhss) >= max_collect:
                        break
                    continue
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if self._is_stack_carrier_temp_assignment(nested) or self._is_non_memory_assignment(nested):
                    continue
            rhss.reverse()
            return rhss[:max_collect]
        rhs = self._stack_store_rhs_from_statement(stmt)
        return [rhs] if rhs is not None else []

    def _typed_stack_store_rhss_from_statement(self,
        stmt: StructuredAstValue,
        fact: TypedStackProbeReturnFact8616 | None,
        *,
        max_collect: int = 4,
    ) -> list[StructuredAstValue]:
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            rhss: list[StructuredAstValue] = []
            for nested in reversed(tuple(nested_statements)):
                nested_rhss = self._typed_stack_store_rhss_from_statement(nested, fact, max_collect=max_collect)
                if nested_rhss:
                    rhss.extend(reversed(nested_rhss))
                    if len(rhss) >= max_collect:
                        break
                    continue
                nested_children = getattr(nested, "statements", None)
                if isinstance(nested_children, (list, tuple)):
                    continue
                if self._is_stack_carrier_temp_assignment(nested) or self._is_non_memory_assignment(nested):
                    continue
            rhss.reverse()
            return rhss[:max_collect]
        rhs = self._typed_stack_store_rhs_from_statement(stmt, fact)
        return [rhs] if rhs is not None else []

    def _typed_stack_store_rhs_from_nested_8616(self,
        nested_statements: StructuredAstValue,
        fact: TypedStackProbeReturnFact8616,
        max_collect: int,
    ) -> tuple[list[StructuredAstValue], list[set[tuple[str, str | int]]]]:
        rhss: list[StructuredAstValue] = []
        sources: list[set[tuple[str, str | int]]] = []
        for nested in reversed(tuple(nested_statements)):
            nested_rhss, nested_sources = self._typed_stack_store_rhs_sources_from_statement(
                nested,
                fact,
                max_collect=max_collect,
            )
            if nested_rhss:
                rhss.extend(reversed(nested_rhss))
                sources.extend(reversed(nested_sources))
                if len(rhss) >= max_collect:
                    break
                continue
            nested_children = getattr(nested, "statements", None)
            if isinstance(nested_children, (list, tuple)):
                continue
            if self._is_stack_carrier_temp_assignment(nested) or self._is_non_memory_assignment(nested):
                continue
        rhss.reverse()
        sources.reverse()
        if len(rhss) > max_collect:
            rhss = rhss[:max_collect]
            sources = sources[:max_collect]
        return rhss, sources

    def _typed_stack_store_rhs_sources_from_statement(self,
        stmt: StructuredAstValue,
        fact: TypedStackProbeReturnFact8616 | None,
        *,
        max_collect: int = 4,
    ) -> tuple[
        list[StructuredAstValue],
        list[set[tuple[str, str | int]]],
    ]:
        if fact is None:
            return [], []
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)):
            return self._typed_stack_store_rhs_from_nested_8616(nested_statements, fact, max_collect)

        rhs = None
        carrier_sources: set[tuple[str, str | int]] = set()
        for assignment in reversed(self._iter_assignment_nodes(stmt)):
            lhs, assignment_rhs = self._assignment_lhs_rhs(assignment)
            if not self._assignment_lhs_writes_memory(lhs):
                continue
            if self._is_segment_register_value_expr(assignment_rhs):
                continue
            if self._store_matches_typed_stack_probe_fact(lhs, fact):
                rhs = assignment_rhs
                carrier_sources = set(_generic_stack_carrier_keys_8616(lhs))
                if isinstance(assignment_rhs, object):
                    carrier_sources.update(_generic_stack_carrier_keys_8616(assignment_rhs))
                break
        return ([rhs], [carrier_sources]) if rhs is not None else ([], [])

    def _collect_typed_stack_carrier_defs(self,
        statements: list[StructuredAstValue],
        start_index: int,
        *,
        wanted_indices: list[int],
        wanted_keys: set[tuple[str, str | int]],
    ) -> list[int]:
        if not wanted_indices or not wanted_keys:
            return wanted_indices
        consumed = list(wanted_indices)
        pending_keys = set(wanted_keys)
        idx = start_index
        while idx >= 0 and pending_keys:
            stmt = statements[idx]
            if self._statement_contains_call(stmt):
                break
            for assignment in reversed(self._iter_assignment_nodes(stmt)):
                lhs, rhs = self._assignment_lhs_rhs(assignment)
                if lhs is None:
                    continue
                lhs_keys = _generic_stack_carrier_keys_8616(lhs)
                if not lhs_keys & pending_keys:
                    continue
                consumed.append(idx)
                pending_keys -= lhs_keys
                pending_keys.update(_generic_stack_carrier_keys_8616(rhs))
                break
            idx -= 1
        return sorted(consumed)

    def _is_stack_carrier_temp_assignment(self, stmt: StructuredAstValue) -> bool:
        candidates = self._iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = self._assignment_lhs_rhs(candidates[-1])
        if lhs is None:
            return False
        if _stack_carrier_key_8616(lhs) is None:
            return False
        rhs_node = rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        # Carrier temps are arithmetic/address shuttles only.
        if isinstance(rhs_node, CUnaryOp) and rhs_node.op in {"Reference", "Dereference"}:
            return True
        if isinstance(rhs_node, CBinaryOp):
            return rhs_node.op in {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}
        return False

    def _is_non_memory_assignment(self, stmt: StructuredAstValue) -> bool:
        candidates = self._iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, _rhs = self._assignment_lhs_rhs(candidates[-1])
        return isinstance(lhs, structured_c.CVariable)

    def _value_carrier_assignment_rhs_from_statement(self, stmt: StructuredAstValue) -> StructuredAstValue:
        candidates = self._iter_assignment_nodes(stmt)
        if not candidates:
            return None
        lhs, rhs = self._assignment_lhs_rhs(candidates[-1])
        if lhs is None or rhs is None or self._assignment_lhs_writes_memory(lhs):
            return None
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return None
        if _stack_carrier_key_8616(lhs_node) is None:
            return None
        if self._is_segment_register_value_expr(rhs):
            return None
        return rhs

    def _outgoing_placeholder_lhs_ok_8616(self, lhs: StructuredAstValue) -> bool:
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return False
        # A placeholder fallback cannot turn a byte rejected by the stack-store
        # selector into a complete PUSH merely because its name looks local.
        if classify_push_store_width_8616(lhs_node) is not PushStoreWidthVerdict8616.COMPLETE_WIDTH:
            return False
        variable = lhs_node.variable
        name = getattr(variable, "name", None) or lhs_node.name
        if not isinstance(name, str):
            return False
        if isinstance(variable, SimStackVariable):
            offset = variable.offset
            if not isinstance(offset, int) or offset >= 0:
                return False
        elif not (
            name.startswith(("local_", "arg_", "s_", "stack_bp_", "stack_sp_"))
        ):
            return False
        # Accept both canonical stack-placeholder names and materialized local/arg
        # names as potential outgoing stack-argument carriers. This is still gated
        # by immediate callsite backtracking and stack-slot offset constraints.
        return bool(name.startswith(("s_", "stack_bp_", "stack_sp_", "local_", "arg_")))

    def _outgoing_arg_placeholder_rhs_from_statement(self, stmt: StructuredAstValue) -> StructuredAstValue:
        """Refuse partial stores before considering legacy outgoing carriers."""
        candidates = self._iter_assignment_nodes(stmt)
        if not candidates:
            return None
        lhs, rhs = self._assignment_lhs_rhs(candidates[-1])
        if lhs is None or rhs is None:
            return None
        if not self._outgoing_placeholder_lhs_ok_8616(lhs):
            return None
        rhs_node = rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        if rhs_node.__class__.__name__ == "CDirtyExpression":
            resolved = _resolve_dirty_virtual_expr_8616(rhs_node)
            if resolved is not None:
                rhs = resolved
        if self._is_segment_register_value_expr(rhs):
            return None
        return rhs

    def _is_outgoing_segment_return_store_statement(self,
        stmt: StructuredAstValue, *, stack_probe_seen: bool = False
    ) -> bool:
        if not stack_probe_seen:
            return False
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return False
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            return False
        segment_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, self.project)
        if segment_name != "ss":
            return False
        rhs_segments = set()
        for raw_node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            variable = getattr(node, "variable", None)
            name = getattr(variable, "name", None) or getattr(node, "name", None)
            if isinstance(name, str) and name.lower() in {"cs", "ds", "es", "ss"}:
                rhs_segments.add(name.lower())
            segment_selector = getattr(node, "segment_selector", None)
            if isinstance(segment_selector, str) and segment_selector.lower() in {"cs", "ds", "es", "ss"}:
                rhs_segments.add(segment_selector.lower())
            linear_segment_name, _linear_offset_terms = _match_real_mode_linear_expr_8616(node, self.project)
            if linear_segment_name in {"cs", "ds", "es", "ss"}:
                rhs_segments.add(linear_segment_name)
        return rhs_segments == {"ss"}

    def _offset_terms_include_stack_base_placeholder(self, offset_terms: StructuredAstValue) -> bool:
        for _sign, term in _boundary_tuple_8616(offset_terms or ()):
            if self._node_contains_placeholder_stack_8616(term):
                return True
        return False

    def _is_stack_probe_frame_artifact_store_statement(self, stmt: StructuredAstValue) -> bool:
        if self._statement_contains_call(stmt):
            return False
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return False
        lhs, _rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None:
            return False
        segment_name, offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, self.project)
        if segment_name != "ss":
            return False
        return self._offset_terms_include_stack_base_placeholder(offset_terms)

    def _top_level_assignment_node_8616(self, stmt: StructuredAstValue) -> StructuredAstValue:
        if self._is_assignment_node(stmt):
            return stmt
        nested_statements = getattr(stmt, "statements", None)
        if isinstance(nested_statements, (list, tuple)) and len(nested_statements) == 1:
            nested = nested_statements[0]
            if self._is_assignment_node(nested):
                return nested
        return None

    def _c_variable_identity_key_8616(self, node: StructuredAstValue) -> StructuredAstValue:
        current = node
        while isinstance(current, CTypeCast):
            current = current.expr
        if not isinstance(current, structured_c.CVariable):
            return None
        variable = current.variable
        name = getattr(variable, "name", None) or current.name
        if isinstance(variable, SimStackVariable):
            return ("stack", variable.offset, variable.size, name)
        if isinstance(variable, SimRegisterVariable):
            return ("reg", variable.reg, variable.size, name)
        if variable is not None:
            return (
                type(variable).__name__,
                getattr(variable, "ident", None),
                getattr(variable, "offset", None),
                getattr(variable, "size", None),
                name,
            )
        if isinstance(name, str) and name:
            return ("name", name)
        return None

    def _statement_variable_identity_keys_8616(self,
        stmt: StructuredAstValue,
    ) -> set[tuple[StructuredAstValue, ...]]:
        """Return variable identity keys referenced anywhere in a statement."""
        keys: set[tuple[StructuredAstValue, ...]] = set()
        for raw_node in (stmt, *_iter_c_nodes_deep_8616(stmt)):
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            key = self._c_variable_identity_key_8616(node)
            if isinstance(key, tuple):
                keys.add(key)
        return keys

    def _statement_references_variable_identity_8616(self,
        stmt: StructuredAstValue, key: tuple[StructuredAstValue, ...] | None
    ) -> bool:
        """Return whether a statement references a specific variable identity."""
        if key is None:
            return True
        return key in self._statement_variable_identity_keys_8616(stmt)

    def _variable_identity_referenced_later_8616(self,
        key: tuple[StructuredAstValue, ...] | None, later_statements: tuple[StructuredAstValue, ...]
    ) -> bool:
        """Return whether later statements reference a variable identity."""
        return any(self._statement_references_variable_identity_8616(stmt, key) for stmt in later_statements)

    def _debug_node_shape_8616(self, node: StructuredAstValue) -> str:
        if node is None:
            return "None"
        parts = [type(node).__name__]
        for attr in ("statements", "lhs", "rhs", "dst", "src", "expr", "operand", "args"):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if isinstance(value, (list, tuple)):
                parts.append(f"{attr}[{len(value)}]")
            elif value is None:
                parts.append(f"{attr}=None")
            else:
                parts.append(f"{attr}={type(value).__name__}")
        return " ".join(parts)

    def _probe_artifact_refuse_8616(self, fmt: str, *args: StructuredAstValue) -> bool:
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
            log.warning("[stack-probe-artifacts] refuse-assignment reason=" + fmt, *args)
        return False

    def _is_stack_probe_frame_artifact_assignment_statement(self,
        stmt: StructuredAstValue,
        *,
        later_statements: tuple[StructuredAstValue, ...] = (),
        later_identity_keys: frozenset[tuple[StructuredAstValue, ...]] | None = None,
    ) -> bool:
        """Recognize legacy scalar artifacts, never infer dead stack storage."""
        if self._statement_contains_call(stmt):
            return False
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return self._probe_artifact_refuse_8616(
                "no-top-assignment count=%d stmt=%s",
                len(self._iter_assignment_nodes(stmt)),
                self._debug_expr_8616(stmt),
            )
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            return self._probe_artifact_refuse_8616(
                "lhs-rhs lhs=%s rhs=%s stmt=%s",
                self._debug_expr_8616(lhs),
                self._debug_expr_8616(rhs),
                self._debug_expr_8616(stmt),
            )
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return self._probe_artifact_refuse_8616(
                "lhs-not-variable lhs_type=%s lhs=%s stmt=%s",
                type(lhs_node).__name__,
                self._debug_expr_8616(lhs),
                self._debug_expr_8616(stmt),
            )
        variable = lhs_node.variable
        name = getattr(variable, "name", None) or lhs_node.name
        lhs_is_stack_variable = isinstance(variable, SimStackVariable)
        if not lhs_is_stack_variable and self._assignment_lhs_writes_memory(lhs):
            return self._probe_artifact_refuse_8616(
                "memory-lhs lhs=%s rhs=%s stmt=%s",
                self._debug_expr_8616(lhs),
                self._debug_expr_8616(rhs),
                self._debug_expr_8616(stmt),
            )
        lhs_key = self._c_variable_identity_key_8616(lhs_node)
        live_later = (
            True
            if lhs_key is None
            else lhs_key in later_identity_keys
            if later_identity_keys is not None
            else self._variable_identity_referenced_later_8616(lhs_key, later_statements)
        )
        if live_later:
            return self._probe_artifact_refuse_8616(
                "live-later key=%r lhs=%s stmt=%s",
                lhs_key,
                self._debug_expr_8616(lhs),
                self._debug_expr_8616(stmt),
            )
        return self._probe_artifact_lhs_accepted_8616(variable, name, lhs_node, lhs, stmt)

    def _probe_artifact_lhs_accepted_8616(self,
        variable: StructuredAstValue,
        name: StructuredAstValue,
        lhs_node: StructuredAstValue,
        lhs: StructuredAstValue,
        stmt: StructuredAstValue,
    ) -> bool:
        if isinstance(variable, SimStackVariable):
            # A nested sequence's suffix omits outer reads and alias uses.
            # Only the storage owner can prove this memory definition dead.
            return False
        if isinstance(variable, SimRegisterVariable) and _generic_stack_carrier_keys_8616(lhs_node):
            return True
        accepted = isinstance(name, str) and (
            name.startswith(("local_", "vvar_", "tmp_", "ir_")) or re.fullmatch(r"v\d+", name) is not None
        )
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS") and not accepted:
            log.warning(
                "[stack-probe-artifacts] refuse-assignment reason=lhs-name name=%r var_type=%s lhs=%s stmt=%s",
                name,
                type(variable).__name__,
                self._debug_expr_8616(lhs),
                self._debug_expr_8616(stmt),
            )
        return accepted

    def _is_outgoing_stack_arg_segment_placeholder_store_statement(self,
        stmt: StructuredAstValue, *, stack_probe_seen: bool
    ) -> bool:
        if not stack_probe_seen or self._statement_contains_call(stmt):
            return False
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-placeholder reason=no-top-assignment count=%d shape=%s stmt=%s",
                    len(self._iter_assignment_nodes(stmt)),
                    self._debug_node_shape_8616(stmt),
                    self._debug_expr_8616(stmt),
                )
            return False
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-placeholder reason=lhs-rhs lhs=%s rhs=%s stmt=%s",
                    self._debug_expr_8616(lhs),
                    self._debug_expr_8616(rhs),
                    self._debug_expr_8616(stmt),
                )
            return False
        segment_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, self.project)
        if segment_name != "ss":
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
                log.warning(
                    "[stack-probe-artifacts] refuse-placeholder reason=segment segment=%r lhs=%s rhs=%s stmt=%s",
                    segment_name,
                    self._debug_expr_8616(lhs),
                    self._debug_expr_8616(rhs),
                    self._debug_expr_8616(stmt),
                )
            return False
        return not self._statement_contains_call(rhs)

    def _is_outgoing_stack_slot_placeholder_store_statement(self,
        stmt: StructuredAstValue, *, stack_probe_seen: bool
    ) -> bool:
        if not stack_probe_seen or self._statement_contains_call(stmt):
            return False
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return False
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None or self._statement_contains_call(rhs):
            return False
        lhs_node = lhs
        while isinstance(lhs_node, CTypeCast):
            lhs_node = lhs_node.expr
        if not isinstance(lhs_node, structured_c.CVariable):
            return False
        variable = lhs_node.variable
        offset = getattr(variable, "offset", None)
        return isinstance(variable, SimStackVariable) and isinstance(offset, int) and offset < 0

    def _next_statement_is_materialized_direct_push_call_8616(self, statements: list[StructuredAstValue], idx: int) -> bool:
        if idx + 1 >= len(statements):
            return False
        next_stmt = statements[idx + 1]
        call = self._call_from_statement(next_stmt)
        if call is None:
            return False
        summary = self.summary_map.get(id(call))
        if summary is None or bool(summary.stack_probe_helper):
            return False
        push_sources = summary.push_arg_sources
        if not isinstance(push_sources, tuple) or not push_sources:
            return False
        if not all(
            isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int)
            for source in push_sources
        ):
            return False
        return bool(_boundary_tuple_8616(getattr(call, "args", ()) or ()))

    def _stack_variable_offset_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, structured_c.CVariable):
            return None
        variable = node.variable
        if not isinstance(variable, SimStackVariable):
            return None
        offset = variable.offset
        return offset if isinstance(offset, int) else None

    def _assignment_ins_addr_8616(self, stmt: StructuredAstValue) -> int | None:
        tags = getattr(stmt, "tags", None)
        if not isinstance(tags, dict):
            return None
        ins_addr = tags.get("ins_addr")
        return ins_addr if isinstance(ins_addr, int) else None

    def _push_source_op_step_8616(
        self, current: StructuredAstValue, op_name: str, op_value: StructuredAstValue
    ) -> StructuredAstValue | None:
        """Resolve one nested-source push op against the binary node."""
        if not isinstance(op_value, tuple):
            return None
        c_op = current.op
        lhs = current.lhs
        rhs = current.rhs
        lhs_matches = self._expr_matches_push_source_value_8616(lhs, op_value)
        rhs_matches = self._expr_matches_push_source_value_8616(rhs, op_value)
        if (
            op_name
            in {
                CallsitePushExprOp8616.ADD_SOURCE.value,
                CallsitePushExprOp8616.ADC_SOURCE.value,
            }
            and c_op == "Add"
        ):
            if rhs_matches:
                return lhs
            if lhs_matches:
                return rhs
        if (
            op_name
            in {
                CallsitePushExprOp8616.SUB_SOURCE.value,
                CallsitePushExprOp8616.SBB_SOURCE.value,
            }
            and c_op == "Sub"
            and rhs_matches
        ):
            return lhs
        return None

    def _push_op_sign_ext_hi_step_8616(
        self, current: StructuredAstValue, op_value: int
    ) -> StructuredAstValue | None:
        """Consume a sign-extend-high pattern ``0 - ((x >> (w-1)) & 1)``."""
        width_bits = max(int(op_value), 1)
        if current.op != "Sub" or self._constant_int_value_8616(current.lhs) != 0:
            return None
        rhs_node = current.rhs
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        if not isinstance(rhs_node, CBinaryOp) or getattr(rhs_node, "op", None) != "And":
            return None
        and_lhs = getattr(rhs_node, "lhs", None)
        and_rhs = getattr(rhs_node, "rhs", None)
        if self._constant_int_value_8616(and_rhs) != 1:
            return None
        while isinstance(and_lhs, CTypeCast):
            and_lhs = and_lhs.expr
        if not isinstance(and_lhs, CBinaryOp) or getattr(and_lhs, "op", None) != "Shr":
            return None
        if self._constant_int_value_8616(getattr(and_lhs, "rhs", None)) != width_bits - 1:
            return None
        return getattr(and_lhs, "lhs", None)

    def _push_op_commutative_8616(self, c_op: str, commutative_c_op: str, lhs: StructuredAstValue, rhs: StructuredAstValue, lhs_value: StructuredAstValue, rhs_value: StructuredAstValue, wanted: int) -> StructuredAstValue | None:
        """Verdict for one named push-op step."""
        if c_op != commutative_c_op:
            return None
        if rhs_value == wanted:
            return lhs
        if lhs_value == wanted:
            return rhs
        return None
    def _push_op_sub_8616(self, c_op: str, lhs: StructuredAstValue, rhs: StructuredAstValue, lhs_value: StructuredAstValue, rhs_value: StructuredAstValue, wanted: int) -> StructuredAstValue | None:
        """Verdict for one named push-op step."""
        if c_op != "Sub" or rhs_value != wanted:
            return None
        return lhs
    def _push_op_shl_8616(self, c_op: str, lhs: StructuredAstValue, rhs: StructuredAstValue, lhs_value: StructuredAstValue, rhs_value: StructuredAstValue, wanted: int) -> StructuredAstValue | None:
        """Verdict for one named push-op step."""
        if (c_op == "Shl" and rhs_value == wanted) or (c_op == "Mul" and rhs_value == ((1 << wanted) & 0xFFFF)):
            return lhs
        if c_op == "Mul" and lhs_value == ((1 << wanted) & 0xFFFF):
            return rhs
        return None
    def _push_op_shr_8616(self, c_op: str, lhs: StructuredAstValue, rhs: StructuredAstValue, lhs_value: StructuredAstValue, rhs_value: StructuredAstValue, wanted: int) -> StructuredAstValue | None:
        """Verdict for one named push-op step."""
        if c_op != "Shr" or rhs_value != wanted:
            return None
        return lhs
    def _push_op_sar_8616(self, c_op: str, lhs: StructuredAstValue, rhs: StructuredAstValue, lhs_value: StructuredAstValue, rhs_value: StructuredAstValue, wanted: int) -> StructuredAstValue | None:
        """Verdict for one named push-op step."""
        if c_op != "Shr" or rhs_value != wanted or not isinstance(lhs, CTypeCast):
            return None
        if not isinstance(lhs.dst_type, SimTypeShort) or lhs.dst_type.signed is not True:
            return None
        return lhs.expr
    def _push_op_neg_8616(self, c_op: str, lhs: StructuredAstValue, rhs: StructuredAstValue, lhs_value: StructuredAstValue, rhs_value: StructuredAstValue, wanted: int) -> StructuredAstValue | None:
        """Verdict for one named push-op step."""
        if c_op != "Sub" or lhs_value != 0:
            return None
        return rhs
    def _push_op_scalar_step_8616(
        self, current: StructuredAstValue, op_name: str, op_value: int
    ) -> StructuredAstValue | None:
        """Consume one constant-int push op against the binary node."""
        c_op = current.op
        lhs = current.lhs
        rhs = current.rhs
        rhs_value = self._constant_int_value_8616(rhs)
        lhs_value = self._constant_int_value_8616(lhs)
        wanted = int(op_value) & 0xFFFF
        commutative_c_op = _PUSH_COMMUTATIVE_OPS_8616.get(op_name)
        if commutative_c_op is not None:
            return self._push_op_commutative_8616(c_op, commutative_c_op, lhs, rhs, lhs_value, rhs_value, wanted)
        handler = {
            CallsitePushExprOp8616.SUB.value: self._push_op_sub_8616,
            CallsitePushExprOp8616.SHL.value: self._push_op_shl_8616,
            CallsitePushExprOp8616.SHR.value: self._push_op_shr_8616,
            CallsitePushExprOp8616.SAR.value: self._push_op_sar_8616,
            CallsitePushExprOp8616.NEG.value: self._push_op_neg_8616,
        }.get(op_name)
        if handler is None:
            return None
        return handler(c_op, lhs, rhs, lhs_value, rhs_value, wanted)

    def _scalar_push_source_verdict_8616(
        self, node: StructuredAstValue, source: StructuredAstValue
    ) -> bool | None:
        """Verdict for scalar ``bp``/``imm`` push sources; ``None`` for ``expr``."""
        if not isinstance(source, tuple) or len(source) < 2:
            return False
        source_kind, source_value = source[0], source[1]
        if source_kind == "bp" and isinstance(source_value, int):
            return self._stack_variable_offset_8616(node) == int(source_value)
        if source_kind == "imm" and isinstance(source_value, int):
            return self._constant_int_value_8616(node) == (int(source_value) & 0xFFFF)
        return None

    def _expr_matches_push_source_value_8616(self, expr: StructuredAstValue, source: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        scalar = self._scalar_push_source_verdict_8616(node, source)
        if scalar is not None:
            return scalar
        source_kind, source_value = source[0], source[1]
        if not (source_kind == "expr" and len(source) == 3 and isinstance(source_value, tuple)):
            return False
        ops = source[2]
        if not isinstance(ops, tuple):
            return False
        current = node
        for op_name, op_value in reversed(ops):
            current = self._push_source_expr_op_step_8616(current, op_name, op_value)
            if current is None:
                return False
        return self._expr_matches_push_source_value_8616(current, source_value)
    def _push_source_expr_op_step_8616(self,
        current: StructuredAstValue,
        op_name: StructuredAstValue,
        op_value: StructuredAstValue,
    ) -> StructuredAstValue | None:
        while isinstance(current, CTypeCast):
            current = current.expr
        if not isinstance(op_name, str):
            return None
        if not isinstance(current, CBinaryOp):
            return None
        if op_name in _PUSH_SOURCE_OPS_8616:
            current = self._push_source_op_step_8616(current, op_name, op_value)
            if current is None:
                return None
            return current
        if not isinstance(op_value, int):
            return None
        if op_name == CallsitePushExprOp8616.SIGN_EXT_HI.value:
            current = self._push_op_sign_ext_hi_step_8616(current, op_value)
        else:
            current = self._push_op_scalar_step_8616(current, op_name, op_value)
        if current is None:
            return None
        return current

    def _setup_rhs_matches_push_sources_8616(
        self,
        rhs: StructuredAstValue,
        push_sources: StructuredAstValue,
        setup_ins_addr: int,
        idx: int,
        lhs: StructuredAstValue,
    ) -> bool:
        """Return whether the setup RHS matches an imm/expr push source."""
        rhs_value = self._constant_int_value_8616(rhs)
        imm_source_matches = (
            tuple(
                source
                for source in push_sources
                if isinstance(source, tuple)
                and len(source) >= 2
                and source[0] == "imm"
                and isinstance(source[1], int)
                and isinstance(rhs_value, int)
                and (int(source[1]) & 0xFFFF) == (rhs_value & 0xFFFF)
                and _mov_reg_imm_setup_matches_push_source_8616(self.project, setup_ins_addr, source)
            )
            if isinstance(rhs_value, int)
            else ()
        )
        if isinstance(rhs_value, int) and imm_source_matches:
            return True
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS_VERBOSE") and isinstance(rhs_value, int):
            log.warning(
                "[call-arg-setup-prune] imm-setup-check idx=%d rhs=%#x lhs_memory=%s setup=%r "
                "matches=%r push_sources=%r",
                idx,
                rhs_value,
                self._assignment_lhs_writes_memory(lhs),
                setup_ins_addr,
                imm_source_matches,
                push_sources,
            )

        expr_source_matches = tuple(
            source
            for source in push_sources
            if self._expr_matches_push_source_value_8616(rhs, source)
            and _reg_expr_setup_matches_push_source_8616(self.project, setup_ins_addr, source)
        )
        if expr_source_matches:
            return True
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS_VERBOSE"):
            expr_diagnostics = tuple(
                (
                    source,
                    self._expr_matches_push_source_value_8616(rhs, source),
                    _reg_expr_setup_matches_push_source_8616(self.project, setup_ins_addr, source),
                )
                for source in push_sources
                if isinstance(source, tuple) and source and source[0] == "expr"
            )
            if expr_diagnostics:
                log.warning(
                    "[call-arg-setup-prune] expr-setup-check idx=%d rhs=%s setup=%r diagnostics=%r",
                    idx,
                    self._debug_expr_8616(rhs),
                    setup_ins_addr,
                    expr_diagnostics,
                )
        return False

    def _setup_lhs_reference_matches_8616(
        self,
        next_call: StructuredAstValue,
        lhs: StructuredAstValue,
        rhs: StructuredAstValue,
        lhs_offset: int | None,
        lhs_key: StructuredAstValue,
        push_sources: StructuredAstValue,
        setup_ins_addr: int,
    ) -> bool:
        """Return whether the setup LHS is a proven call-arg source reference."""
        if lhs_offset is not None and lhs_key is not None and self._call_args_reference_identity(next_call, lhs_key):
            lhs_source_setup_matches = tuple(
                source
                for source in push_sources
                if lhs_offset in _bp_offsets_from_push_source_8616(source)
                and _reg_expr_setup_matches_push_source_8616(self.project, setup_ins_addr, source)
            )
            if lhs_source_setup_matches:
                return True
        if lhs_offset is None or lhs_key is None:
            return False
        call_args = _boundary_tuple_8616(getattr(next_call, "args", ()) or ())
        imm_setup_matches = tuple(
            source
            for source in push_sources
            if isinstance(source, tuple)
            and len(source) >= 2
            and source[0] == "imm"
            and any(self._expr_matches_push_source_value_8616(arg, source) for arg in call_args)
            and _mov_reg_imm_setup_matches_push_source_8616(self.project, setup_ins_addr, source)
        )
        if imm_setup_matches:
            return True
        return bool(
            self._expr_contains_dirty_carrier_for_setup_8616(rhs)
            and self._rhs_is_safe_pre_call_setup_artifact_8616(rhs)
            and self._push_sources_have_return_register_setup_window_evidence_8616(next_call, push_sources)
        )

    def _consumed_seg_byte_arg_store_8616(
        self,
        lhs: StructuredAstValue,
        rhs: StructuredAstValue,
        statements: list[StructuredAstValue],
        idx: int,
    ) -> bool:
        """Return whether the assignment is a consumed segmented stack byte store."""
        lhs_args = _segmented_stack_arg_store_lvalue_args_8616(lhs, self.project, allow_raw_dereference=False)
        if lhs_args is None:
            return False
        segment_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(lhs, self.project)
        seg_arg, _offset_arg = lhs_args
        seg_name = getattr(seg_arg, "name", None)
        if segment_name != "ss" and not (
            (isinstance(seg_arg, str) and seg_arg == "ss")
            or (isinstance(seg_name, str) and seg_name.lower() == "ss")
        ):
            return False
        _seg_arg, offset_arg = lhs_args
        if not (
            self._node_contains_placeholder_stack_8616(offset_arg)
            or _generic_stack_carrier_keys_8616(offset_arg)
            or self._local_expr_contains_dirty_expression_8616(offset_arg)
        ):
            return False
        if not self._rhs_is_safe_pre_call_setup_artifact_8616(rhs):
            return False
        next_call = self._call_from_statement(statements[idx + 1])
        if next_call is None:
            return False
        summary = self.summary_map.get(id(next_call))
        if summary is None or bool(summary.stack_probe_helper):
            return False
        push_sources = summary.push_arg_sources
        if not isinstance(push_sources, tuple) or not push_sources:
            return False
        call_args = _boundary_tuple_8616(getattr(next_call, "args", ()) or ())
        return bool(call_args) and (
            any(_same_c_expression_8616(arg, rhs) for arg in call_args)
            or any(isinstance(source, tuple) and source for source in push_sources)
        )

    def _pre_call_setup_window_artifact_8616(
        self,
        assignment: StructuredAstValue,
        lhs: StructuredAstValue,
        rhs: StructuredAstValue,
        statements: list[StructuredAstValue],
        idx: int,
    ) -> bool:
        """Return whether the setup window before a call is prunable."""
        candidates: list[tuple[StructuredAstValue, StructuredAstValue, int]] = []
        current_ins_addr = self._assignment_ins_addr_8616(assignment)
        if not isinstance(current_ins_addr, int):
            return False
        candidates.append((lhs, rhs, current_ins_addr))
        scan_idx = idx + 1
        stop_idx = min(len(statements), idx + 24)
        call_node = None
        call_summary = None
        scan_result = self._setup_window_scan_8616(statements, scan_idx, stop_idx, candidates)
        if scan_result is None or scan_result[1].stack_probe_helper:
            return False
        call_node, call_summary = scan_result
        window_callsite_addr = call_summary.callsite_addr
        if not isinstance(window_callsite_addr, int):
            return False
        window_push_sources = call_summary.push_arg_sources
        if not isinstance(window_push_sources, tuple) or not window_push_sources:
            return False
        if not _boundary_tuple_8616(getattr(call_node, "args", ()) or ()):
            return False
        has_binary_push_setup_evidence = self._push_sources_have_binary_setup_window_evidence_8616(
            window_callsite_addr, window_push_sources
        )
        has_return_register_setup_evidence = self._push_sources_have_return_register_setup_window_evidence_8616(
            call_node, window_push_sources
        )
        if not (has_binary_push_setup_evidence or has_return_register_setup_evidence):
            return False
        for _candidate_lhs, _candidate_rhs, candidate_ins_addr in candidates:
            setup_gap = window_callsite_addr - candidate_ins_addr
            if not (0 <= setup_gap <= 16):
                return False
            if not self._setup_window_assignment_shape_is_prunable_8616(
                _candidate_lhs,
                _candidate_rhs,
                call_node,
                allow_unreferenced_stack_dirty=has_return_register_setup_evidence,
            ):
                return False
        return True

    def _setup_window_scan_8616(self,
        statements: list[StructuredAstValue],
        scan_idx: int,
        stop_idx: int,
        candidates: list[StructuredAstValue],
    ) -> tuple[StructuredAstValue, StructuredAstValue] | None:
        call_node = None
        call_summary = None
        while scan_idx < stop_idx:
            call_node = self._call_from_statement(statements[scan_idx])
            if call_node is not None:
                call_summary = self.summary_map.get(id(call_node))
                break
            candidate_assignment = self._top_level_assignment_node_8616(statements[scan_idx])
            if candidate_assignment is None or self._statement_contains_call(candidate_assignment):
                return None
            candidate_lhs, candidate_rhs = self._assignment_lhs_rhs(candidate_assignment)
            if candidate_lhs is None or candidate_rhs is None or self._statement_contains_call(candidate_rhs):
                return None
            candidate_ins_addr = self._assignment_ins_addr_8616(candidate_assignment)
            if not isinstance(candidate_ins_addr, int):
                return None
            candidates.append((candidate_lhs, candidate_rhs, candidate_ins_addr))
            scan_idx += 1
        if call_node is None or call_summary is None:
                return None
        return (call_node, call_summary)

    def _consumed_setup_lhs_tail_verdict_8616(
        self,
        next_call: StructuredAstValue,
        lhs: StructuredAstValue,
        rhs: StructuredAstValue,
        lhs_offset: StructuredAstValue,
        lhs_key: StructuredAstValue,
        push_sources: StructuredAstValue,
        setup_ins_addr: int,
        setup_gap: int,
    ) -> bool | str:
        """True when the setup lhs is a proven consumed call arg; else a refusal reason."""
        if self._setup_lhs_reference_matches_8616(
            next_call, lhs, rhs, lhs_offset, lhs_key, push_sources, setup_ins_addr
        ):
            return True
        if lhs_offset is None or lhs_offset <= 0:
            return (
                "lhs-not-positive-stack-slot "
                f"push_sources={push_sources!r} setup={setup_ins_addr!r} "
                f"delta={getattr(self.project, '_inertia_original_linear_delta', None)!r} "
                f"has_original={getattr(self.project, '_inertia_original_project', None) is not None}"
            )
        if setup_gap > 4:
            return (f"stack-slot-ins-gap:{setup_gap}")
        source_offsets = {
            int(source[1])
            for source in push_sources
            if isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int)
        }
        if lhs_offset not in source_offsets:
            return ("lhs-offset-not-source")
        if lhs_key is None:
            return ("missing-lhs-key")
        args = _boundary_tuple_8616(getattr(next_call, "args", ()) or ())
        if not any(self._c_variable_identity_key_8616(arg) == lhs_key for arg in args):
            return ("lhs-not-call-arg")
        return True
    def _setup_prune_refuse_8616(self, idx: int, reason: str) -> bool:
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS_VERBOSE"):
            log.warning("[call-arg-setup-prune] refuse idx=%d reason=%s", idx, reason)
        return False

    def _setup_next_call_gate_8616(self,
        next_call: StructuredAstValue,
        assignment: StructuredAstValue,
        lhs: StructuredAstValue,
        rhs: StructuredAstValue,
        statements: list[StructuredAstValue],
        idx: int,
    ) -> tuple[bool | None, StructuredAstValue]:
        """(True,) consume; (False, reason) refuse; (None, (gap, ins, sources)) continue."""
        if next_call is None:
            if self._pre_call_setup_window_artifact_8616(assignment, lhs, rhs, statements, idx):
                return (True, None)
            return (False, "next-not-call")
        summary = self.summary_map.get(id(next_call))
        if summary is None or bool(summary.stack_probe_helper):
            return (False, "missing-summary-or-stack-probe")
        callsite_addr = summary.callsite_addr
        setup_ins_addr = self._assignment_ins_addr_8616(assignment)
        if not isinstance(callsite_addr, int) or not isinstance(setup_ins_addr, int):
            return (False, "missing-callsite-or-ins-addr")
        setup_gap = callsite_addr - setup_ins_addr
        # Byte-proven register setup can appear before later argument pushes in
        # a multi-argument call. Keep a small outgoing-argument window here; the
        # actual deletion still requires matching push-source and instruction bytes.
        if not (0 < setup_gap <= 16):
            return (False, f"ins-gap:{setup_gap}")
        push_sources = summary.push_arg_sources
        if not isinstance(push_sources, tuple) or not push_sources:
            return (False, "missing-push-sources")
        return (None, (setup_ins_addr, setup_gap, push_sources))

    def _is_consumed_materialized_call_arg_setup_assignment_8616(self,
        statements: list[StructuredAstValue],
        idx: int,
    ) -> bool:
        if idx + 1 >= len(statements):
            return self._setup_prune_refuse_8616(idx, "no-next-statement")
        assignment = self._top_level_assignment_node_8616(statements[idx])
        if assignment is None:
            return self._setup_prune_refuse_8616(idx, "not-pure-assignment")
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None or self._statement_contains_call(rhs):
            return self._setup_prune_refuse_8616(idx, "missing-lhs-rhs-or-rhs-call")



        if self._consumed_seg_byte_arg_store_8616(lhs, rhs, statements, idx):
            return True






        next_call = self._call_from_statement(statements[idx + 1])
        gate_ok, gate_payload = self._setup_next_call_gate_8616(
            next_call, assignment, lhs, rhs, statements, idx
        )
        if gate_ok is True:
            return True
        if gate_ok is False:
            return self._setup_prune_refuse_8616(idx, gate_payload)
        setup_ins_addr, setup_gap, push_sources = gate_payload

        if self._setup_rhs_matches_push_sources_8616(rhs, push_sources, setup_ins_addr, idx, lhs):
            return True

        lhs_offset = self._stack_variable_offset_8616(lhs)
        lhs_key = self._c_variable_identity_key_8616(lhs)
        verdict = self._consumed_setup_lhs_tail_verdict_8616(
            next_call, lhs, rhs, lhs_offset, lhs_key, push_sources,
            setup_ins_addr, setup_gap,
        )
        if verdict is True:
            return True
        return self._setup_prune_refuse_8616(idx, verdict)

    def _seg_u8_lvalue_args_8616(self, lhs: StructuredAstValue) -> tuple[StructuredAstValue, ...] | None:
        node = lhs
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CFunctionCall):
            return None
        call_name = _call_node_name_8616(node)
        if not isinstance(call_name, str) or call_name.upper() != "SEG_U8":
            return None
        args = _boundary_tuple_8616(node.args or ())
        return args if len(args) == 2 else None

    def _dirty_expr_identity_key_8616(self,
        expr: StructuredAstValue,
    ) -> tuple[str, int | str] | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if node.__class__.__name__ != "CDirtyExpression":
            return None
        dirty = getattr(node, "dirty", None)
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return ("varid", varid)
        name = getattr(dirty, "name", None) or getattr(node, "name", None)
        if isinstance(name, str) and name:
            return ("name", name)
        return None

    def _same_probe_carrier_expr_8616(self, left: StructuredAstValue, right: StructuredAstValue) -> bool:
        if _same_c_expression_8616(left, right):
            return True
        left_key = self._dirty_expr_identity_key_8616(left)
        if left_key is not None and left_key == self._dirty_expr_identity_key_8616(right):
            return True
        left_carriers = _generic_stack_carrier_keys_8616(left)
        return bool(left_carriers and left_carriers == _generic_stack_carrier_keys_8616(right))

    def _expr_contains_dirty_expression_8616(self, expr: StructuredAstValue) -> bool:
        for node in (expr, *_iter_c_nodes_deep_8616(expr)):
            while isinstance(node, CTypeCast):
                node = node.expr
            if node.__class__.__name__ == "CDirtyExpression":
                return True
        return False

    def _expr_is_add_one_of_8616(self, expr: StructuredAstValue, base: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CBinaryOp):
            return False
        lhs = node.lhs
        rhs = node.rhs
        if node.op == "Add":
            return (
                (self._constant_int_value_8616(rhs) == 1
                and self._same_probe_carrier_expr_8616(lhs, base))
                or (self._constant_int_value_8616(lhs) == 1
                and self._same_probe_carrier_expr_8616(rhs, base))
            )
        if node.op == "Sub":
            return self._constant_int_value_8616(rhs) == 0xFFFF and self._same_probe_carrier_expr_8616(lhs, base)
        return False

    def _expr_is_add_one_shape_8616(self, expr: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CBinaryOp):
            return False
        lhs = node.lhs
        rhs = node.rhs
        if node.op == "Add":
            return self._constant_int_value_8616(rhs) == 1 or self._constant_int_value_8616(lhs) == 1
        if node.op == "Sub":
            return self._constant_int_value_8616(rhs) == 0xFFFF
        return False

    def _expr_is_shr8_of_8616(self, expr: StructuredAstValue, base: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        return (
            isinstance(node, CBinaryOp)
            and getattr(node, "op", None) == "Shr"
            and self._constant_int_value_8616(getattr(node, "rhs", None)) == 8
            and self._same_probe_carrier_expr_8616(getattr(node, "lhs", None), base)
        )

    def _expr_is_shr8_shape_8616(self, expr: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        return (
            isinstance(node, CBinaryOp)
            and getattr(node, "op", None) == "Shr"
            and self._constant_int_value_8616(getattr(node, "rhs", None)) == 8
        )

    def _expr_is_side_effect_free_byte_value_8616(self, expr: StructuredAstValue) -> bool:
        for raw_node in (expr, *_iter_c_nodes_deep_8616(expr)):
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                return False
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                return False
        return True

    def _stack_probe_seg_u8_probe_store_parts_8616(self,
        stmt: StructuredAstValue,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
    ) -> tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue] | None:
        if typed_probe_fact is None:
            return None
        if typed_probe_fact.segment_space != "ss" or typed_probe_fact.width != 2:
            return None
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return None
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            return None
        args = self._seg_u8_lvalue_args_8616(lhs)
        if args is None:
            return None
        seg_arg, offset_arg = args
        if not (
            self._is_segment_register_value_expr(seg_arg)
            or self._node_contains_placeholder_stack_8616(seg_arg)
            or _generic_stack_carrier_keys_8616(seg_arg)
            or self._expr_contains_dirty_expression_8616(seg_arg)
        ):
            return None
        if not (
            self._node_contains_placeholder_stack_8616(offset_arg)
            or _generic_stack_carrier_keys_8616(offset_arg)
            or self._expr_contains_dirty_expression_8616(offset_arg)
        ):
            return None
        if not self._expr_is_side_effect_free_byte_value_8616(rhs):
            return None
        return seg_arg, offset_arg, rhs

    def _stmt_tag_int_8616(self, stmt: StructuredAstValue, key: str) -> int | None:
        tags = getattr(stmt, "tags", None)
        if not isinstance(tags, dict):
            return None
        value = tags.get(key)
        return value if isinstance(value, int) else None

    def _same_instruction_byte_pair_tags_8616(self, low_stmt: StructuredAstValue, high_stmt: StructuredAstValue) -> bool:
        low_ins = self._stmt_tag_int_8616(low_stmt, "ins_addr")
        high_ins = self._stmt_tag_int_8616(high_stmt, "ins_addr")
        low_block = self._stmt_tag_int_8616(low_stmt, "vex_block_addr")
        high_block = self._stmt_tag_int_8616(high_stmt, "vex_block_addr")
        low_idx = self._stmt_tag_int_8616(low_stmt, "vex_stmt_idx")
        high_idx = self._stmt_tag_int_8616(high_stmt, "vex_stmt_idx")
        return (
            low_ins is not None
            and low_ins == high_ins
            and low_block is not None
            and low_block == high_block
            and low_idx is not None
            and high_idx == low_idx + 1
        )

    def _is_typed_stack_probe_seg_u8_byte_pair_8616(self,
        low_stmt: StructuredAstValue,
        high_stmt: StructuredAstValue,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
    ) -> bool:
        low_parts = self._stack_probe_seg_u8_probe_store_parts_8616(low_stmt, typed_probe_fact)
        high_parts = self._stack_probe_seg_u8_probe_store_parts_8616(high_stmt, typed_probe_fact)
        if low_parts is None or high_parts is None:
            return False
        low_seg, low_offset, low_rhs = low_parts
        high_seg, high_offset, high_rhs = high_parts
        if (
            self._same_probe_carrier_expr_8616(low_seg, high_seg)
            and self._expr_is_add_one_of_8616(high_offset, low_offset)
            and self._expr_is_shr8_of_8616(high_rhs, low_rhs)
        ):
            return True
        return (
            self._same_instruction_byte_pair_tags_8616(low_stmt, high_stmt)
            and self._expr_is_add_one_shape_8616(high_offset)
            and self._expr_is_shr8_shape_8616(high_rhs)
            and self._expr_contains_dirty_expression_8616(low_offset)
            and self._expr_contains_dirty_expression_8616(low_rhs)
        )

    def _later_non_probe_call_has_materialized_args_8616(self, statements: list[StructuredAstValue], idx: int) -> bool:
        for candidate in statements[idx + 1 :]:
            call = self._call_from_statement(candidate)
            if call is None:
                continue
            summary = self.summary_map.get(id(call))
            if summary is not None and bool(summary.stack_probe_helper):
                continue
            return bool(_boundary_tuple_8616(getattr(call, "args", ()) or ()))
        return False

    def _record_probe_artifacts_pruned_8616(self, removed_artifacts: int, before: int, after: int) -> None:
        """Publish the pruned stack-probe artifact count and debug line."""
        ensure_stack_probe_fact_stats_8616(self.codegen)["stack_probe_frame_artifacts_pruned"] = (
            int(ensure_stack_probe_fact_stats_8616(self.codegen).get("stack_probe_frame_artifacts_pruned", 0) or 0)
            + removed_artifacts
        )
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
            log.warning(
                "[stack-probe-artifacts] pruned=%d before=%d after=%d",
                removed_artifacts,
                before,
                after,
            )

    def _probe_frame_debug_stmt_8616(self,
        stmt: StructuredAstValue,
        idx: int,
        helper_or_helper_zone_active: bool,
        stack_probe_seen: bool,
    ) -> None:
        """Emit the verbose per-statement stack-probe artifact debug line."""
        assignment = self._top_level_assignment_node_8616(stmt)
        lhs = rhs = None
        if assignment is not None:
            lhs, rhs = self._assignment_lhs_rhs(assignment)
        log.warning(
            "[stack-probe-artifacts] stmt idx=%d helper_zone=%s stack_probe_seen=%s shape=%s lhs=%s rhs=%s tags=%r",
            idx,
            helper_or_helper_zone_active,
            stack_probe_seen,
            self._debug_node_shape_8616(stmt),
            self._debug_expr_8616(lhs),
            self._debug_expr_8616(rhs),
            getattr(assignment, "tags", None) if assignment is not None else getattr(stmt, "tags", None),
        )

    def _prune_stack_probe_frame_artifacts(self,
        statements: list[StructuredAstValue],
        *,
        stack_probe_seen: bool,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
        allow_setup_assignment_prune: bool,
    ) -> tuple[list[StructuredAstValue], bool]:
        if not stack_probe_seen and not self.prune_consumed_arg_stores:
            return statements, False
        helper_or_helper_zone_active = bool(stack_probe_seen)
        pruned = []
        removed_artifacts = 0
        skip_next = False


        later_identity_keys_by_index = (
            self._later_identity_keys_by_index_8616(statements)
            if allow_setup_assignment_prune
            else ()
        )



        for idx, stmt in enumerate(statements):
            if skip_next:
                skip_next = False
                continue
            if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS_VERBOSE"):
                self._probe_frame_debug_stmt_8616(stmt, idx, helper_or_helper_zone_active, stack_probe_seen)
            action, helper_or_helper_zone_active = self._prune_probe_frame_step_8616(
                stmt,
                idx,
                statements,
                helper_or_helper_zone_active=helper_or_helper_zone_active,
                stack_probe_seen=stack_probe_seen,
                typed_probe_fact=typed_probe_fact,
                later_identity_keys_by_index=later_identity_keys_by_index,
                allow_setup_assignment_prune=allow_setup_assignment_prune,
            )
            if action == "keep":
                pruned.append(stmt)
                continue
            if action == "drop_pair":
                removed_artifacts += 2
                skip_next = True
                continue
            if action in ("drop_artifact", "drop_setup"):
                removed_artifacts += 1
        if removed_artifacts:
            self._record_probe_artifacts_pruned_8616(removed_artifacts, len(statements), len(pruned))
        return pruned, bool(removed_artifacts)

    def _probe_next_call_debug_8616(
        self,
        statements: list[StructuredAstValue],
        idx: int,
        tag: str,
        stmt: StructuredAstValue = None,
    ) -> None:
        """Emit the stack-probe placeholder refuse debug line when enabled."""
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
            next_stmt = statements[idx + 1] if idx + 1 < len(statements) else None
            next_call = self._call_from_statement(next_stmt) if next_stmt is not None else None
            next_summary = self.summary_map.get(id(next_call)) if next_call is not None else None
            stmt_part = f" stmt={self._debug_expr_8616(stmt)}" if stmt is not None else ""
            log.warning(
                f"[stack-probe-artifacts] {tag} reason=next-call{stmt_part} "
                "idx=%d next_shape=%s next_call=%s summary=%s push_sources=%r args=%r",
                idx,
                self._debug_node_shape_8616(next_stmt),
                self._debug_expr_8616(next_call),
                type(next_summary).__name__ if next_summary is not None else None,
                getattr(next_summary, "push_arg_sources", None) if next_summary is not None else None,
                _boundary_tuple_8616(self._debug_expr_8616(arg) for arg in (getattr(next_call, "args", ()) or ()))
                if next_call is not None
                else (),
            )

    def _probe_placeholder_store_action_8616(self,
        stmt: StructuredAstValue,
        idx: int,
        statements: list[StructuredAstValue],
        stack_probe_seen: bool,
    ) -> str | None:
        if self._is_outgoing_stack_arg_segment_placeholder_store_statement(
            stmt,
            stack_probe_seen=stack_probe_seen,
        ):
            if self._next_statement_is_materialized_direct_push_call_8616(statements, idx):
                return "drop_placeholder"
            self._probe_next_call_debug_8616(statements, idx, 'refuse-placeholder-consume')
        if self._is_outgoing_stack_slot_placeholder_store_statement(
            stmt, stack_probe_seen=stack_probe_seen
        ):
            if self._next_statement_is_materialized_direct_push_call_8616(statements, idx):
                return "drop_placeholder"
            self._probe_next_call_debug_8616(statements, idx, 'refuse-slot-placeholder-consume', stmt)
        return None

    def _probe_drop_artifact_8616(self, stmt: StructuredAstValue) -> str:
        """Record and report the drop-artifact probe-frame verdict."""
        self.stats.consumed_outgoing_stack_placeholder_count += 1
        self._record_pruned_stack_write_token_8616(stmt)
        return "drop_artifact"

    def _probe_drop_setup_8616(self, stmt: StructuredAstValue) -> str:
        """Record and report the drop-setup probe-frame verdict."""
        self.stats.consumed_outgoing_stack_placeholder_count += 1
        self._record_pruned_stack_write_token_8616(stmt)
        self.codegen._inertia_call_arg_setup_assignments_pruned_8616 = (
            int(getattr(self.codegen, "_inertia_call_arg_setup_assignments_pruned_8616", 0) or 0) + 1
        )
        return "drop_setup"

    def _probe_zone_active_update_8616(self, stmt: StructuredAstValue, helper_or_helper_zone_active: bool) -> bool:
        """Update the helper-zone flag when ``stmt`` carries a callsite summary."""
        call = self._call_from_statement(stmt)
        summary = self.summary_map.get(id(call)) if call is not None else None
        if call is None or summary is None:
            return helper_or_helper_zone_active
        return bool(summary.stack_probe_helper)

    def _prune_probe_frame_step_8616(
        self,
        stmt: StructuredAstValue,
        idx: int,
        statements: list[StructuredAstValue],
        *,
        helper_or_helper_zone_active: bool,
        stack_probe_seen: bool,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
        later_identity_keys_by_index: list[StructuredAstValue],
        allow_setup_assignment_prune: bool,
    ) -> tuple[str, bool]:
        """Classify one statement's artifact verdict; returns (action, helper_zone_active)."""
        helper_or_helper_zone_active = self._probe_zone_active_update_8616(stmt, helper_or_helper_zone_active)
        if (
            helper_or_helper_zone_active
            and idx + 1 < len(statements)
            and self._is_typed_stack_probe_seg_u8_byte_pair_8616(stmt, statements[idx + 1], typed_probe_fact)
        ):
            self.stats.consumed_outgoing_stack_placeholder_count += 2
            return "drop_pair", helper_or_helper_zone_active
        if self._is_stack_probe_frame_artifact_store_statement(stmt):
            if not helper_or_helper_zone_active and not stack_probe_seen:
                return "keep", helper_or_helper_zone_active
            if typed_probe_fact is None:
                return "keep", helper_or_helper_zone_active
            if not self._later_non_probe_call_has_materialized_args_8616(statements, idx):
                return "keep", helper_or_helper_zone_active
            self.stats.consumed_outgoing_stack_placeholder_count += 1
            return "drop_placeholder", helper_or_helper_zone_active
        if helper_or_helper_zone_active:
            placeholder_action = self._probe_placeholder_store_action_8616(stmt, idx, statements, stack_probe_seen)
            if placeholder_action is not None:
                return placeholder_action, helper_or_helper_zone_active
        if (
            allow_setup_assignment_prune
            and helper_or_helper_zone_active
            and self._is_stack_probe_frame_artifact_assignment_statement(
                stmt,
                later_identity_keys=later_identity_keys_by_index[idx]
                if idx < len(later_identity_keys_by_index)
                else None,
            )
        ):
            return self._probe_drop_artifact_8616(stmt), helper_or_helper_zone_active
        if self.prune_consumed_arg_stores and self._is_consumed_materialized_call_arg_setup_assignment_8616(
            statements,
            idx,
        ):
            return self._probe_drop_setup_8616(stmt), helper_or_helper_zone_active
        return "keep", helper_or_helper_zone_active

    def _is_virtual_dirty_expr_8616(self, term: StructuredAstValue) -> bool:
        dirty = getattr(term, "dirty", None)
        if isinstance(dirty, str):
            return dirty.startswith(("vvar_", "tmp_", "ir_"))
        if dirty is None:
            return False
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return True
        name = getattr(dirty, "name", None)
        return isinstance(name, str) and (name.startswith(("vvar_", "tmp_", "ir_")))

    def _assignment_lhs_writes_memory(self, lhs: StructuredAstValue) -> bool:
        if lhs is None:
            return False
        nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
        for raw_node in nodes:
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            if isinstance(node, CFunctionCall):
                call_name = _call_node_name_8616(node)
                if isinstance(call_name, str) and call_name.upper() in {"SEG_U8", "SEG_U16", "SEG_U32"}:
                    return True
            if isinstance(node, CUnaryOp) and node.op == "Dereference":
                return True
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable):
                return True
        return False

    def _is_value_only_assignment(self, stmt: StructuredAstValue) -> bool:
        candidates = self._iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, _rhs = self._assignment_lhs_rhs(candidates[-1])
        return not self._assignment_lhs_writes_memory(lhs)

    def _is_segment_register_metadata_store(self, stmt: StructuredAstValue) -> bool:
        candidates = self._iter_assignment_nodes(stmt)
        if not candidates:
            return False
        lhs, rhs = self._assignment_lhs_rhs(candidates[-1])
        return self._assignment_lhs_writes_memory(lhs) and self._is_segment_register_value_expr(rhs)

    def _expand_typed_carrier_defs_8616(
        self,
        statements: list[StructuredAstValue],
        stmt_index: int,
        wanted_indices: list[int],
        wanted_keys: set[tuple[str, str | int]],
    ) -> list[int]:
        """Expand typed carrier defs covering the wanted statement indices."""
        if not wanted_indices or not wanted_keys:
            return wanted_indices
        if stmt_index < 0:
            return wanted_indices
        return self._collect_typed_stack_carrier_defs(
            statements,
            start_index=stmt_index,
            wanted_indices=wanted_indices,
            wanted_keys=wanted_keys,
        )

    def _filter_call_return_frame_rhss_8616(
        self,
        rhss: list[StructuredAstValue],
        source_index: int,
        *,
        call_return_addr: int | None,
    ) -> tuple[list[StructuredAstValue], list[int]]:
        """Drop rhs stores that merely re-store the call return address."""
        if not rhss:
            return [], []
        kept: list[StructuredAstValue] = []
        skipped_indices: list[int] = []
        for rhs in rhss:
            if _rhs_matches_call_return_addr_8616(rhs, call_return_addr):
                skipped_indices.append(source_index)
                continue
            kept.append(rhs)
        return kept, skipped_indices

    def _trailing_typed_probe_collect_8616(
        self,
        node: StructuredAstValue,
        seq_idx: int,
        statements: list[StructuredAstValue],
        parent_stmt_index: int,
        typed_probe_fact: StructuredAstValue,
        max_collect: int,
        rhss: list[StructuredAstValue],
        consumed_nested_indices: list[int],
        skipped_carriers: int,
        skipped_value_assignments: int,
    ) -> tuple[int, int, str]:
        """Collect typed-probe store rhss from one nested node; returns skips and action."""
        nested_rhss, nested_sources = self._typed_stack_store_rhs_sources_from_statement(
            node,
            typed_probe_fact,
            max_collect=max_collect,
        )
        if not nested_rhss:
            skipped_carriers, skipped_value_assignments, action = self._skip_after_empty_typed_collect_8616(
                node, skipped_carriers, skipped_value_assignments
            )
            return skipped_carriers, skipped_value_assignments, ("advance" if action == "advance" else "stop")
        rhss.extend(nested_rhss)
        consumed_nested_indices.append(seq_idx)
        if nested_sources:
            keys = set()
            for entry in nested_sources:
                keys.update(entry)
            # Typed nested store materialization currently remains scoped to the
            # parent call statement; nested statement indices are not directly
            # removable from the outer sequence.
            self._expand_typed_carrier_defs_8616(
                statements,
                seq_idx - 1,
                wanted_indices=[parent_stmt_index - 1],
                wanted_keys=keys,
            )
        if len(rhss) >= max_collect:
            return skipped_carriers, skipped_value_assignments, "stop"
        return skipped_carriers, skipped_value_assignments, "advance"

    def _trailing_non_probe_collect_8616(
        self,
        node: StructuredAstValue,
        seq_idx: int,
        call_return_addr: StructuredAstValue,
        max_collect: int,
        rhss: list[StructuredAstValue],
        consumed_nested_indices: list[int],
        skipped_carriers: int,
        skipped_value_assignments: int,
        value_skip_limit: int,
    ) -> tuple[int, int, str]:
        """Collect non-probe trailing store rhss from one node; returns skips and action."""
        nested_rhss = self._stack_store_rhss_from_statement(node, max_collect=max_collect)
        if nested_rhss:
            rhss.extend(nested_rhss)
            consumed_nested_indices.append(seq_idx)
            if len(rhss) >= max_collect:
                return skipped_carriers, skipped_value_assignments, "stop"
            return skipped_carriers, skipped_value_assignments, "advance"
        kind, placeholder_rhs = self._classify_non_store_backtrack_8616(node)
        if kind == "placeholder":
            if _rhs_matches_call_return_addr_8616(placeholder_rhs, call_return_addr):
                consumed_nested_indices.append(seq_idx)
                return skipped_carriers, skipped_value_assignments, "advance"
            rhss.append(placeholder_rhs)
            if len(rhss) >= max_collect:
                return skipped_carriers, skipped_value_assignments, "stop"
            return skipped_carriers, skipped_value_assignments, "advance"
        if kind == "carrier":
            skipped_carriers += 1
            if skipped_carriers > 4:
                return skipped_carriers, skipped_value_assignments, "stop"
            return skipped_carriers, skipped_value_assignments, "advance"
        if kind == "value":
            skipped_value_assignments += 1
            if skipped_value_assignments > value_skip_limit:
                return skipped_carriers, skipped_value_assignments, "stop"
            return skipped_carriers, skipped_value_assignments, "advance"
        return skipped_carriers, skipped_value_assignments, "stop"

    def _apply_consumed_nested_deletions_8616(self,
        stmt: StructuredAstValue,
        sequence: list[StructuredAstValue],
        nested_statements: StructuredAstValue,
        consumed_nested_indices: list[int],
    ) -> None:
        for del_idx in reversed(self._dedupe_indices(consumed_nested_indices)):
            if 0 <= del_idx < len(sequence):
                del sequence[del_idx]
        if isinstance(nested_statements, list):
            stmt.statements = sequence
        else:
            stmt.statements = tuple(sequence)

    def _trailing_stack_store_rhss_after_last_call_8616(
        self,
        stmt: StructuredAstValue,
        *,
        max_collect: int,
        parent_stmt_index: int,
        statements: list[StructuredAstValue],
        wanted_count: int | None,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
        call_return_addr: int | None,
    ) -> tuple[list[StructuredAstValue], list[int]]:
        """Collect stack-store rhss nested after the last call in a container statement."""
        nested_statements = getattr(stmt, "statements", None)
        if not isinstance(nested_statements, (list, tuple)):
            return [], []
        sequence = list(nested_statements)
        last_call_idx = None
        for seq_idx, node in enumerate(sequence):
            if self._statement_contains_call(node):
                last_call_idx = seq_idx
        if last_call_idx is None:
            return [], []

        rhss: list[StructuredAstValue] = []
        consumed_nested_indices: list[int] = []
        skipped_carriers = 0
        skipped_value_assignments = 0
        value_skip_limit = 160 if isinstance(wanted_count, int) and wanted_count > 0 else 8
        for seq_idx, node in enumerate(sequence[last_call_idx + 1 :], start=last_call_idx + 1):
            if self._statement_contains_call(node):
                break
            if typed_probe_fact is not None:
                skipped_carriers, skipped_value_assignments, action = self._trailing_typed_probe_collect_8616(
                    node, seq_idx, statements, parent_stmt_index, typed_probe_fact,
                    max_collect, rhss, consumed_nested_indices,
                    skipped_carriers, skipped_value_assignments,
                )
            else:
                skipped_carriers, skipped_value_assignments, action = self._trailing_non_probe_collect_8616(
                    node, seq_idx, call_return_addr, max_collect, rhss,
                    consumed_nested_indices, skipped_carriers,
                    skipped_value_assignments, value_skip_limit,
                )
            if action == "stop":
                break
        if consumed_nested_indices:
            self._apply_consumed_nested_deletions_8616(stmt, sequence, nested_statements, consumed_nested_indices)

        return rhss[:max_collect], []

    def _skip_after_empty_typed_collect_8616(
        self, stmt: StructuredAstValue, skipped_carriers: int, skipped_value_assignments: int
    ) -> tuple[int, int, str]:
        """Classify a statement that produced no typed probe stores."""
        if not self._is_skip_after_typed_collect(stmt):
            return skipped_carriers, skipped_value_assignments, "stop"
        if self._is_segment_register_metadata_store(stmt) or self._is_stack_carrier_temp_assignment(stmt):
            skipped_carriers += 1
        else:
            skipped_value_assignments += 1
        if skipped_carriers > 4 or skipped_value_assignments > 8:
            return skipped_carriers, skipped_value_assignments, "stop"
        return skipped_carriers, skipped_value_assignments, "advance"

    def _consume_backtracked_store_rhss_8616(
        self,
        rhss: list[StructuredAstValue],
        idx: int,
        rhs_sources: list[set[tuple[str, str | int]]],
        statements: list[StructuredAstValue],
        rhs_values: list[StructuredAstValue],
        consumed_indices: list[int],
        consumed_return_frame_indices: list[int],
        skipped_carriers: int,
        *,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
        call_return_addr: int | None,
    ) -> tuple[str, list[StructuredAstValue], int]:
        """Consume collected store rhss; returns (action, rhss, skipped_carriers)."""
        rhss, return_frame_indices = self._filter_call_return_frame_rhss_8616(
            rhss, idx, call_return_addr=call_return_addr
        )
        if return_frame_indices:
            consumed_return_frame_indices.extend(return_frame_indices)
            if not rhss:
                return "advance", rhss, skipped_carriers
        if all(self._is_segment_register_value_expr(rhs) for rhs in rhss):
            skipped_carriers += 1
            if skipped_carriers > 4:
                return "stop", rhss, skipped_carriers
            return "advance", rhss, skipped_carriers
        if len(rhss) > 1:
            self.stats.push_order_reversed_count += 1
        rhs_values.extend(rhss)
        expanded_indices = [idx]
        if typed_probe_fact is not None and rhs_sources:
            keys = set()
            for entry in rhs_sources:
                keys.update(entry)
            expanded_indices = self._expand_typed_carrier_defs_8616(
                statements,
                idx - 1,
                wanted_indices=expanded_indices,
                wanted_keys=keys,
            )
        consumed_indices.extend(expanded_indices)
        return "advance", rhss, skipped_carriers

    def _classify_non_store_backtrack_8616(
        self, stmt: StructuredAstValue
    ) -> tuple[str, StructuredAstValue | None]:
        """Classify a backtracked node that produced no stack-store rhss."""
        placeholder_rhs = self._outgoing_arg_placeholder_rhs_from_statement(stmt)
        if placeholder_rhs is not None:
            return "placeholder", placeholder_rhs
        if self._is_segment_register_metadata_store(stmt):
            return "carrier", None
        if self._is_stack_carrier_temp_assignment(stmt):
            return "carrier", None
        if self._is_non_memory_assignment(stmt) or self._is_value_only_assignment(stmt):
            return "value", None
        return "stop", None

    def _backtrack_non_store_action_8616(
        self,
        stmt: StructuredAstValue,
        idx: int,
        call_return_addr: StructuredAstValue,
        rhs_values: list[StructuredAstValue],
        consumed_indices: list[int],
        consumed_return_frame_indices: list[int],
        skipped_carriers: int,
        skipped_value_assignments: int,
        value_skip_limit: int,
    ) -> tuple[str, int, int]:
        """Classify a non-store backtrack node; return (action, skips)."""
        kind, placeholder_rhs = self._classify_non_store_backtrack_8616(stmt)
        if kind == "placeholder":
            self.stats.consumed_outgoing_stack_placeholder_count += 1
            if _rhs_matches_call_return_addr_8616(placeholder_rhs, call_return_addr):
                consumed_return_frame_indices.append(idx)
            else:
                rhs_values.append(placeholder_rhs)
                consumed_indices.append(idx)
            return "advance", skipped_carriers, skipped_value_assignments
        if kind == "carrier":
            skipped_carriers += 1
            if skipped_carriers > 4:
                return "stop", skipped_carriers, skipped_value_assignments
            return "advance", skipped_carriers, skipped_value_assignments
        if kind == "value":
            skipped_value_assignments += 1
            if skipped_value_assignments > value_skip_limit:
                return "stop", skipped_carriers, skipped_value_assignments
            return "advance", skipped_carriers, skipped_value_assignments
        return "stop", skipped_carriers, skipped_value_assignments
    def _collect_call_trailing_rhss_8616(self,
        stmt: StructuredAstValue,
        idx: int,
        statements: list[StructuredAstValue],
        rhs_values: list[StructuredAstValue],
        consumed_indices: list[int],
        limit: int,
        wanted_count: StructuredAstValue,
        typed_probe_fact: StructuredAstValue,
        call_return_addr: StructuredAstValue,
    ) -> None:
        trailing_rhss = self._trailing_stack_store_rhss_after_last_call_8616(
            stmt,
            max_collect=max(0, limit - len(rhs_values)),
            parent_stmt_index=idx,
            statements=statements,
            wanted_count=wanted_count,
            typed_probe_fact=typed_probe_fact,
            call_return_addr=call_return_addr,
        )
        if not trailing_rhss:
            return
        trailing_args, trailing_indices = trailing_rhss
        if len(trailing_args) > 1:
            self.stats.push_order_reversed_count += 1
        rhs_values.extend(trailing_args)
        consumed_indices.extend(trailing_indices)

    def _collect_backtracked_stack_args(self,
        statements: list[StructuredAstValue],
        *,
        wanted_count: int | None = None,
        max_count: int = 4,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None = None,
        allow_partial: bool = False,
        call_return_addr: int | None = None,
    ) -> tuple[list[StructuredAstValue], list[StructuredAstValue]]:

        rhs_values: list[StructuredAstValue] = []
        consumed_indices: list[int] = []
        consumed_return_frame_indices: list[int] = []
        skipped_carriers = 0
        skipped_value_assignments = 0
        value_skip_limit = 160 if isinstance(wanted_count, int) and wanted_count > 0 else 8
        limit = max_count if wanted_count is None else max(wanted_count, 1)
        idx = len(statements) - 1
        while idx >= 0 and len(rhs_values) < limit:
            stmt = statements[idx]
            if self._statement_contains_call(stmt):
                self._collect_call_trailing_rhss_8616(
                    stmt, idx, statements, rhs_values, consumed_indices,
                    limit, wanted_count, typed_probe_fact, call_return_addr,
                )
                break
            stop, skipped_carriers, skipped_value_assignments = self._collect_backtrack_step_8616(
                stmt, idx, statements, rhs_values, consumed_indices,
                consumed_return_frame_indices, skipped_carriers,
                skipped_value_assignments, value_skip_limit, max_count, limit,
                wanted_count, typed_probe_fact, call_return_addr,
            )
            if stop:
                break
            idx -= 1
        if wanted_count is not None and len(rhs_values) != wanted_count:
            if allow_partial and rhs_values:
                return rhs_values, consumed_indices + consumed_return_frame_indices
            return [], []
        if len(rhs_values) > 1:
            self.stats.push_order_reversed_count += 1
        return rhs_values, consumed_indices + consumed_return_frame_indices
    def _collect_backtrack_step_8616(self,
        stmt: StructuredAstValue,
        idx: int,
        statements: list[StructuredAstValue],
        rhs_values: list[StructuredAstValue],
        consumed_indices: list[int],
        consumed_return_frame_indices: list[int],
        skipped_carriers: int,
        skipped_value_assignments: int,
        value_skip_limit: int,
        max_count: int,
        limit: int,
        wanted_count: StructuredAstValue,
        typed_probe_fact: StructuredAstValue,
        call_return_addr: StructuredAstValue,
    ) -> tuple[bool, int, int]:
        rhss: list[StructuredAstValue] = []
        rhs_sources: list[set[tuple[str, str | int]]] = []
        if typed_probe_fact is not None:
            rhss, rhs_sources = self._typed_stack_store_rhs_sources_from_statement(
                stmt,
                typed_probe_fact,
                max_collect=max_count,
            )
            if not rhss:
                skipped_carriers, skipped_value_assignments, action = self._skip_after_empty_typed_collect_8616(
                    stmt, skipped_carriers, skipped_value_assignments
                )
                if action == "stop":
                    return (True, skipped_carriers, skipped_value_assignments)
                if action == "advance":
                    return (False, skipped_carriers, skipped_value_assignments)

                return (True, skipped_carriers, skipped_value_assignments)
        if not rhss and typed_probe_fact is None:
            rhss = self._stack_store_rhss_from_statement(stmt, max_collect=max_count)
        if rhss:
            action, rhss, skipped_carriers = self._consume_backtracked_store_rhss_8616(
                rhss,
                idx,
                rhs_sources,
                statements,
                rhs_values,
                consumed_indices,
                consumed_return_frame_indices,
                skipped_carriers,
                typed_probe_fact=typed_probe_fact,
                call_return_addr=call_return_addr,
            )
            if action == "stop":
                return (True, skipped_carriers, skipped_value_assignments)
            return (False, skipped_carriers, skipped_value_assignments)

        action, skipped_carriers, skipped_value_assignments = self._backtrack_non_store_action_8616(
            stmt, idx, call_return_addr, rhs_values, consumed_indices,
            consumed_return_frame_indices, skipped_carriers,
            skipped_value_assignments, value_skip_limit,
        )
        if action == "stop":
            return (True, skipped_carriers, skipped_value_assignments)
        return (False, skipped_carriers, skipped_value_assignments)

        return (False, skipped_carriers, skipped_value_assignments)


    def _collect_backtracked_value_carrier_args(self,
        statements: list[StructuredAstValue],
        *,
        wanted_count: int,
    ) -> tuple[list[StructuredAstValue], list[StructuredAstValue]]:
        if not isinstance(wanted_count, int) or wanted_count <= 0:
            return [], []
        rhs_values: list[StructuredAstValue] = []
        consumed_indices: list[int] = []
        idx = len(statements) - 1
        while idx >= 0 and len(rhs_values) < wanted_count:
            stmt = statements[idx]
            if self._statement_contains_call(stmt):
                break
            rhs = self._value_carrier_assignment_rhs_from_statement(stmt)
            if rhs is not None:
                rhs_values.append(rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            placeholder_rhs = self._outgoing_arg_placeholder_rhs_from_statement(stmt)
            if placeholder_rhs is not None:
                self.stats.consumed_outgoing_stack_placeholder_count += 1
                rhs_values.append(placeholder_rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            if self._is_stack_carrier_temp_assignment(stmt):
                idx -= 1
                continue
            break
        if len(rhs_values) != wanted_count:
            return [], []
        return rhs_values, consumed_indices

    def _node_is_or_contains_call_8616(self, node: StructuredAstValue, call: StructuredAstValue) -> bool:
        """Whether node is or contains the given call expression."""
        if node is call:
            return True
        expr = getattr(node, "expr", None)
        if expr is call:
            return True
        return any(sub is call for sub in _iter_c_nodes_deep_8616(node))
    def _inline_arg_backtrack_step_8616(self, node: StructuredAstValue) -> tuple[StructuredAstValue | None, str]:
        """One backward inline-arg scan step: (rhs, consume|skip|stop)."""
        rhs = self._stack_store_rhs_from_statement(node)
        if rhs is None:
            rhs = self._outgoing_arg_placeholder_rhs_from_statement(node)
            if rhs is not None:
                self.stats.consumed_outgoing_stack_placeholder_count += 1
        if rhs is None:
            if self._is_stack_carrier_temp_assignment(node):
                return None, "skip"
            return None, "stop"
        return rhs, "consume"
    def _inline_call_index_8616(self, sequence: list[StructuredAstValue], call: StructuredAstValue) -> int | None:
        """Index of the statement that is or contains ``call``, or None."""
        for idx, node in enumerate(sequence):
            if self._node_is_or_contains_call_8616(node, call):
                return idx
        return None

    def _backtrack_inline_arg_values_8616(self,
        sequence: list[StructuredAstValue],
        call_idx: int,
        arg_count: int,
    ) -> tuple[list[StructuredAstValue], list[int]]:
        """Walk backward from ``call_idx`` collecting consumed stack-store arg rhss."""
        rhs_values: list[StructuredAstValue] = []
        consumed_indices: list[int] = []
        scan = call_idx - 1
        skipped_carriers = 0
        while scan >= 0 and len(rhs_values) < arg_count:
            rhs, action = self._inline_arg_backtrack_step_8616(sequence[scan])
            if action == "stop":
                break
            if action == "skip":
                skipped_carriers += 1
                if skipped_carriers > 4:
                    break
                scan -= 1
                continue
            rhs_values.append(rhs)
            consumed_indices.append(scan)
            scan -= 1
        return rhs_values, consumed_indices

    def _extract_inline_stack_store_args(self,
        stmt: StructuredAstValue, call: StructuredAstValue, arg_count: int
    ) -> tuple[StructuredAstValue, ...] | None:
        if not isinstance(arg_count, int) or arg_count <= 0:
            return None
        nested_statements = getattr(stmt, "statements", None)
        if not isinstance(nested_statements, (list, tuple)):
            return None
        if not nested_statements:
            return None

        sequence = list(nested_statements)

        call_idx = self._inline_call_index_8616(sequence, call)
        if call_idx is None:
            return None

        rhs_values, consumed_indices = self._backtrack_inline_arg_values_8616(sequence, call_idx, arg_count)
        if len(rhs_values) != arg_count:
            return None

        self._delete_consumed_indices_8616(
            sequence,
            consumed_indices,
            live_consumers=tuple(sequence[call_idx:]),
        )
        stmt.statements = sequence if isinstance(nested_statements, list) else tuple(sequence)
        if len(rhs_values) > 1:
            self.stats.push_order_reversed_count += 1
        return tuple(rhs_values)

    def _restore_protected_call_args_8616(self, block: StructuredAstValue) -> bool:
        protected = getattr(self.codegen, "_inertia_protected_call_args_8616", None)
        if not isinstance(protected, ProtectedCallArgumentStore8616):
            return False
        restored = False
        for node in _iter_c_nodes_deep_8616(block):
            if not isinstance(node, CFunctionCall):
                continue
            call_name = _call_node_name_8616(node) or ""
            summary = self.summary_map.get(id(node)) if isinstance(self.summary_map, dict) else None
            semantic_call_name = _semantic_call_name_from_summary_8616(self.project, summary, call_name) or call_name
            current_args = list(node.args or ())
            if not current_args:
                push_sources = summary.push_arg_sources if summary is not None else ()
                ordered_sources = (
                    tuple(reversed(push_sources))
                    if isinstance(push_sources, tuple) and len(push_sources) > 1
                    else push_sources
                )
                direct_args = tuple(
                    self._direct_expr_from_push_source_8616(
                        source,
                        call_name=semantic_call_name,
                        arg_index=idx,
                    )
                    for idx, source in enumerate(ordered_sources)
                )
                if direct_args and all(argument is not None for argument in direct_args):
                    transaction = self._set_materialized_call_args(
                        node,
                        direct_args,
                        call_name=semantic_call_name,
                        force_replace=True,
                    )
                    restored = transaction.changed or restored
                continue
            updated = False
            updated = self._restore_protected_current_args_8616(
                node, summary, semantic_call_name, current_args, protected)
            if updated:
                node.args = current_args
                restored = True
        return restored

    def _restore_protected_current_args_8616(self,
        node: StructuredAstValue,
        summary: StructuredAstValue,
        semantic_call_name: str,
        current_args: list[StructuredAstValue],
        protected: StructuredAstValue,
    ) -> bool:
        updated = False
        for idx, current_arg in enumerate(tuple(current_args)):
            protected_entry = protected.get(node, idx)
            if protected_entry is None:
                continue
            protected_arg = protected_entry.expression
            protected_score = protected_entry.score
            current_score = self._arg_semantic_quality_8616(semantic_call_name, idx, current_arg)
            if current_score < int(protected_score) and not _same_c_expression_8616(current_arg, protected_arg):
                push_sources = summary.push_arg_sources if summary is not None else ()
                source_idx = idx
                if isinstance(push_sources, tuple) and len(push_sources) > 1:
                    source_idx = len(push_sources) - 1 - idx
                push_source = (
                    push_sources[source_idx]
                    if isinstance(push_sources, tuple) and 0 <= source_idx < len(push_sources)
                    else None
                )
                if (
                    _protected_arg_is_source_immediate_8616(push_sources, push_source, current_arg)
                ):
                    # Keep source-evidenced immediates (e.g. first arg 0)
                    # instead of restoring higher-scored stack carriers.
                    continue
                if (
                    isinstance(push_sources, tuple)
                    and 0 <= source_idx < len(push_sources)
                    and self._protected_expected_arg_matches_8616(
                        current_arg, push_sources, source_idx, idx, semantic_call_name
                    )
                ):
                    continue
                current_args[idx] = self._clone_c_ast_tree(protected_arg)
                updated = True
        return updated

    def _protected_expected_arg_matches_8616(self,
        current_arg: StructuredAstValue,
        push_sources: StructuredAstValue,
        source_idx: int,
        idx: int,
        semantic_call_name: str,
    ) -> bool:
        expected_arg = None
        expected_widths = _known_helper_prototype_arg_widths_8616(self.project, semantic_call_name)
        arity_contract = _known_callee_arity_contract_8616(semantic_call_name)
        if (
            arity_contract.mode is CallArityMode8616.EXACT
            and self._prototype_widths_account_for_push_sources_8616(expected_widths, push_sources)
        ):
            grouped_sources = list(reversed(push_sources)) if len(push_sources) > 1 else list(push_sources)
            grouped_args = self._logical_args_from_push_sources_by_expected_widths_8616(
                grouped_sources,
                expected_arg_widths=expected_widths,
                call_name=semantic_call_name,
            )
            if grouped_args is not None and idx < len(grouped_args):
                expected_arg = grouped_args[idx]
        if expected_arg is None:
            expected_arg = self._direct_expr_from_push_source_8616(
                push_sources[source_idx],
                call_name=semantic_call_name,
                arg_index=idx,
            )
        # Exact push-source evidence is stronger than the
        # readability score used for protected arg restore.
        return expected_arg is not None and _call_arg_semantic_key_8616(
            current_arg
        ) == _call_arg_semantic_key_8616(expected_arg)

    def _rewrite_block(self,
        block: StructuredAstValue,
        *,
        inherited_stack_probe_seen: bool = False,
        inherited_stack_probe_address_seen: bool = False,
        inherited_typed_stack_probe_fact: TypedStackProbeReturnFact8616 | None = None,
        allow_setup_assignment_prune: bool,
        depth: int = 0,
    ) -> tuple[bool, bool, TypedStackProbeReturnFact8616 | None]:
        block_id = id(block)
        if block_id in self.rewritten_block_ids:
            self.codegen._inertia_callsite_duplicate_block_rewrite_refused_8616 = (
                int(getattr(self.codegen, "_inertia_callsite_duplicate_block_rewrite_refused_8616", 0) or 0) + 1
            )
            return inherited_stack_probe_seen, inherited_stack_probe_address_seen, inherited_typed_stack_probe_fact
        self.rewritten_block_ids.add(block_id)
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return inherited_stack_probe_seen, inherited_stack_probe_address_seen, inherited_typed_stack_probe_fact
        if self._replace_stack_code_pointer_assignments_8616(block):
            self.changed = True
            statements = getattr(block, "statements", None)
            if not isinstance(statements, (list, tuple)):
                return inherited_stack_probe_seen, inherited_stack_probe_address_seen, inherited_typed_stack_probe_fact
        statements = list(statements)
        with span(
            "x86_16.call_args.rewrite_block",
            function=self.func_addr if isinstance(self.func_addr, int) else None,
            block_type=type(block).__name__,
            depth=depth,
            statements=len(statements),
        ):
            return self._rewrite_block_body(
                block,
                statements,
                inherited_stack_probe_seen=inherited_stack_probe_seen,
                inherited_stack_probe_address_seen=inherited_stack_probe_address_seen,
                inherited_typed_stack_probe_fact=inherited_typed_stack_probe_fact,
                allow_setup_assignment_prune=allow_setup_assignment_prune,
                depth=depth,
            )

    def _strict_apply_direct_args_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        consumed_return_call_indices: StructuredAstValue,
        direct_args: StructuredAstValue,
        direct_bindings: StructuredAstValue,
        logical_arg_widths_for_sources: StructuredAstValue,
        new_statements: list[StructuredAstValue],
        ordered_push_sources: StructuredAstValue,
        partial_direct_args: StructuredAstValue,
        semantic_call_name: str | None,
        summary: StructuredAstValue,
    ) -> bool:
        """Install strict direct args when all or partially proven."""
        if partial_direct_args is not None:
            direct_args = list(partial_direct_args)
        preserve_return_register_indices = {
            idx
            for idx, source in enumerate(ordered_push_sources)
            if isinstance(source, tuple)
            and len(source) >= 3
            and source[0] == "ret_reg"
            and isinstance(source[2], str)
            and source[2].lower() in {"ax", "dx"}
        }
        normalized_args = self._normalize_materialized_call_args(
            direct_args,
            [-1] * len(direct_args),
            new_statements,
            call_name=semantic_call_name or call_name,
            stack_bindings=direct_bindings or None,
            preserve_register_arg_indices=preserve_return_register_indices,
            expected_arg_widths=logical_arg_widths_for_sources,
            push_sources=tuple(ordered_push_sources),
        )
        if normalized_args is not None and self._all_arg_exprs_are_non_segment_registers(normalized_args):
            args_already_materialized = self._call_args_match_materialized_args_8616(
                call,
                normalized_args,
            )
            transaction = self._set_materialized_call_args(
                call,
                normalized_args,
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_changed:
                record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
            return_calls_already_embedded = self._call_args_embed_return_source_callsites_8616(
                call,
                ordered_push_sources,
            )
            if (
                transaction.arguments_accepted
                and (transaction.arguments_changed or args_already_materialized or return_calls_already_embedded)
            ) and self._delete_consumed_return_call_refs_8616(consumed_return_call_indices):
                self.changed = True
            if transaction.arguments_accepted:
                self._refresh_summary_arg_shape(call, summary)
            if transaction.changed:
                self.changed = True
            return transaction.arguments_accepted
        return False


    def _strict_direct_args_from_unproven_sources_8616(self,
        *,
        call_name: str | None,
        logical_arg_widths_for_sources: StructuredAstValue,
        new_statements: list[StructuredAstValue],
        ordered_push_sources: list[StructuredAstValue],
        semantic_call_name: str | None,
    ) -> tuple[StructuredAstValue, StructuredAstValue]:
        """Collect direct args when push sources are not all proven."""
        consumed_direct_args, consumed_return_call_indices = (
            self._direct_args_from_ordered_push_sources_consuming_return_calls_8616(
                ordered_push_sources,
                call_name=semantic_call_name or call_name,
                statements=new_statements,
            )
        )
        direct_args = consumed_direct_args or (
            self._logical_args_from_push_sources_by_expected_widths_8616(
                ordered_push_sources,
                expected_arg_widths=logical_arg_widths_for_sources,
                call_name=semantic_call_name or call_name,
            )
            or [
                self._direct_expr_from_push_source_8616(
                    source,
                    call_name=semantic_call_name or call_name,
                    arg_index=idx,
                )
                for idx, source in enumerate(ordered_push_sources)
            ]
        )
        return direct_args, consumed_return_call_indices

    def _strict_remat_arm_0_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        has_instruction_proven_direct_push_sources: bool,
        has_recent_stack_arg_store_evidence: bool,
        logical_arg_widths_for_sources: StructuredAstValue,
        new_statements: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        summary: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 0."""
        applied = False
        if has_recent_stack_arg_store_evidence and has_instruction_proven_direct_push_sources:
            self.stats.direct_push_override_recent_store_count += 1
        ordered_push_sources = (
            list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
        )
        direct_args: list[StructuredAstValue] = []
        direct_bindings = {}
        strict_push_sources = all(
            isinstance(source, tuple)
            and len(source) >= 2
            and source[0] == "bp"
            and isinstance(source[1], int)
            for source in ordered_push_sources
        )
        if strict_push_sources:
            for arg_index, source in enumerate(ordered_push_sources):
                source_value = source[1]
                cvar = self._direct_expr_from_push_source_8616(
                    source,
                    call_name=semantic_call_name or call_name,
                    arg_index=arg_index,
                    materialize_pointer=False,
                )
                if cvar is None:
                    break
                direct_args.append(self._clone_c_ast_tree(cvar))
                direct_bindings[source_value] = self._clone_c_ast_tree(cvar)
        else:
            direct_args, consumed_return_call_indices = (
                self._strict_direct_args_from_unproven_sources_8616(
                    ordered_push_sources=ordered_push_sources,
                    call_name=call_name,
                    logical_arg_widths_for_sources=logical_arg_widths_for_sources,
                    new_statements=new_statements,
                    semantic_call_name=semantic_call_name,
                )
            )
        if strict_push_sources:
            consumed_return_call_indices = ()
        partial_direct_args = self._merge_proven_partial_direct_args_8616(
            call,
            direct_args,
        )
        if all(arg is not None for arg in direct_args) or partial_direct_args is not None:
            applied = self._strict_apply_direct_args_8616(
                call=call,
                call_name=call_name,
                consumed_return_call_indices=consumed_return_call_indices,
                direct_args=direct_args,
                direct_bindings=direct_bindings,
                logical_arg_widths_for_sources=logical_arg_widths_for_sources,
                new_statements=new_statements,
                ordered_push_sources=ordered_push_sources,
                partial_direct_args=partial_direct_args,
                semantic_call_name=semantic_call_name,
                summary=summary,
            ) or applied
        return applied

    def _strict_remat_arm_1_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        fallback_arg_count: StructuredAstValue,
        i: int,
        new_statements: StructuredAstValue,
        semantic_call_name: str | None,
        statements: StructuredAstValue,
        summary: StructuredAstValue,
        summary_return_addr: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 1."""
        applied = False
        expanded_rhs, consumed_indices = self._collect_backtracked_stack_args(
            new_statements,
            wanted_count=fallback_arg_count
            if isinstance(fallback_arg_count, int) and fallback_arg_count > 0
            else None,
            max_count=4,
            typed_probe_fact=typed_stack_probe_fact,
            call_return_addr=summary_return_addr,
        )
        normalized_args = self._normalize_materialized_call_args(
            expanded_rhs,
            consumed_indices,
            new_statements,
            call_name=semantic_call_name or call_name,
        )
        if (
            normalized_args is not None
            and isinstance(expected_arg_count, int)
            and len(normalized_args) >= expected_arg_count
            and self._all_arg_exprs_are_non_segment_registers(normalized_args)
        ):
            transaction = self._set_materialized_call_args(
                call,
                normalized_args,
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_accepted:
                record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
                self._record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                if self.prune_consumed_arg_stores and summary is not None:
                    self._delete_consumed_indices_8616(
                        new_statements,
                        consumed_indices,
                        live_consumers=(call, *statements[i + 1 :]),
                    )
                self._refresh_summary_arg_shape(call, summary)
                applied = True
            if transaction.changed:
                self.changed = True
        return applied

    def _strict_remat_arm_2_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        i: int,
        new_statements: StructuredAstValue,
        semantic_call_name: str | None,
        statements: StructuredAstValue,
        summary: StructuredAstValue,
        summary_return_addr: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 2."""
        applied = False
        typed_rhs, consumed_indices = self._collect_backtracked_stack_args(
            new_statements,
            wanted_count=expected_arg_count,
            max_count=max(expected_arg_count, 1),
            typed_probe_fact=typed_stack_probe_fact,
            call_return_addr=summary_return_addr,
        )
        normalized_args = self._normalize_materialized_call_args(
            typed_rhs,
            consumed_indices,
            new_statements,
            call_name=semantic_call_name or call_name,
        )
        if normalized_args is not None and self._all_arg_exprs_are_non_segment_registers(normalized_args):
            transaction = self._set_materialized_call_args(
                call,
                normalized_args,
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_accepted:
                record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
                self._record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                if self.prune_consumed_arg_stores and (
                    summary is not None or typed_stack_probe_fact is not None
                ):
                    self._delete_consumed_indices_8616(
                        new_statements,
                        consumed_indices,
                        live_consumers=(call, *statements[i + 1 :]),
                    )
                self._refresh_summary_arg_shape(call, summary)
                applied = True
            if transaction.changed:
                self.changed = True
        return applied

    def _strict_remat_arm_3_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        logical_arg_widths_for_sources: StructuredAstValue,
        new_statements: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        summary: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 3."""
        applied = False
        ordered_sources = (
            list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
        )
        direct_args = [
            self._direct_expr_from_push_source_8616(
                source,
                call_name=semantic_call_name or call_name,
                arg_index=arg_index,
            )
            for arg_index, source in enumerate(ordered_sources)
        ]
        if all(arg is not None for arg in direct_args):
            normalized_args = self._normalize_materialized_call_args(
                direct_args,
                [-1] * len(direct_args),
                new_statements,
                call_name=semantic_call_name or call_name,
                expected_arg_widths=logical_arg_widths_for_sources,
                push_sources=tuple(ordered_sources),
            )
            if normalized_args is not None and self._all_arg_exprs_are_non_segment_registers(normalized_args):
                transaction = self._set_materialized_call_args(
                    call,
                    normalized_args,
                    call_name=semantic_call_name or call_name,
                    force_replace=True,
                )
                if transaction.arguments_accepted:
                    record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
                    self._refresh_summary_arg_shape(call, summary)
                    applied = True
                if transaction.changed:
                    self.changed = True
        return applied

    def _strict_remat_arm_4_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        expected_arg_widths: StructuredAstValue,
        i: int,
        logical_arg_widths_for_sources: StructuredAstValue,
        new_statements: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        statements: StructuredAstValue,
        summary: StructuredAstValue,
        summary_return_addr: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 4."""
        applied = False
        backtrack_wanted_count = expected_arg_count
        backtrack_push_sources = ()
        if isinstance(push_arg_sources, tuple) and self._prototype_widths_account_for_push_sources_8616(
            expected_arg_widths, push_arg_sources
        ):
            backtrack_wanted_count = len(push_arg_sources)
            backtrack_push_sources = (
                tuple(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else push_arg_sources
            )
        backtracked_rhs, consumed_indices = self._collect_backtracked_stack_args(
            new_statements,
            wanted_count=backtrack_wanted_count,
            call_return_addr=summary_return_addr,
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-backtrack] function=%#x target=%s wanted=%r rhs=%s consumed=%r statements=%d",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                call_name,
                expected_arg_count,
                tuple(self._debug_expr_8616(rhs) for rhs in backtracked_rhs),
                tuple(consumed_indices),
                len(new_statements),
            )
        normalized_args = self._normalize_materialized_call_args(
            backtracked_rhs,
            consumed_indices,
            new_statements,
            call_name=semantic_call_name or call_name,
            expected_arg_widths=logical_arg_widths_for_sources,
            push_sources=backtrack_push_sources,
        )
        if normalized_args is not None and self._all_arg_exprs_are_non_segment_registers(normalized_args):
            transaction = self._set_materialized_call_args(
                call,
                normalized_args,
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_accepted:
                record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
                self._record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                if self.prune_consumed_arg_stores and summary is not None:
                    self._delete_consumed_indices_8616(
                        new_statements,
                        consumed_indices,
                        live_consumers=(call, *statements[i + 1 :]),
                    )
                self._refresh_summary_arg_shape(call, summary)
                applied = True
            if transaction.changed:
                self.changed = True
        return applied

    def _strict_remat_arm_5_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        i: int,
        new_statements: StructuredAstValue,
        semantic_call_name: str | None,
        stmt: StructuredAstValue,
        summary: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 5."""
        applied = False
        inline_rhs = self._extract_inline_stack_store_args(stmt, call, expected_arg_count)
        normalized_args = (
            self._normalize_materialized_call_args(
                list(inline_rhs),
                list(range(max(0, i - len(inline_rhs)), i)),
                new_statements,
                call_name=semantic_call_name or call_name,
            )
            if inline_rhs is not None
            else None
        )
        if normalized_args is not None and self._all_arg_exprs_are_non_segment_registers(normalized_args):
            transaction = self._set_materialized_call_args(
                call,
                normalized_args,
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_accepted:
                record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
                self._refresh_summary_arg_shape(call, summary)
                applied = True
            if transaction.changed:
                self.changed = True
        return applied

    def _strict_remat_arm_6_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        i: int,
        new_statements: StructuredAstValue,
        semantic_call_name: str | None,
        statements: StructuredAstValue,
        summary: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 6."""
        applied = False
        carrier_rhs, consumed_indices = self._collect_backtracked_value_carrier_args(
            new_statements,
            wanted_count=expected_arg_count,
        )
        normalized_args = self._normalize_materialized_call_args(
            carrier_rhs,
            consumed_indices,
            new_statements,
            call_name=semantic_call_name or call_name,
        )
        if normalized_args is not None and self._all_arg_exprs_are_non_segment_registers(normalized_args):
            transaction = self._set_materialized_call_args(
                call,
                normalized_args,
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_accepted:
                record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
                if self.prune_consumed_arg_stores and summary is not None:
                    self._delete_consumed_indices_8616(
                        new_statements,
                        consumed_indices,
                        live_consumers=(call, *statements[i + 1 :]),
                    )
                self._refresh_summary_arg_shape(call, summary)
                applied = True
            if transaction.changed:
                self.changed = True
        return applied

    def _strict_remat_arm_7_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        i: int,
        new_statements: StructuredAstValue,
        semantic_call_name: str | None,
        statements: StructuredAstValue,
        summary: StructuredAstValue,
        summary_return_addr: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 7."""
        applied = False
        candidate_rhs, consumed_indices = self._collect_backtracked_stack_args(
            new_statements,
            wanted_count=1,
            max_count=1,
            typed_probe_fact=typed_stack_probe_fact,
            call_return_addr=summary_return_addr,
        )
        normalized_args = self._normalize_materialized_call_args(
            candidate_rhs,
            consumed_indices,
            new_statements,
            call_name=semantic_call_name or call_name,
        )
        if normalized_args is not None and not self._is_segment_register_value_expr(normalized_args[0]):
            transaction = self._set_materialized_call_args(
                call,
                [normalized_args[0]],
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_accepted:
                record_stack_arg_materialization_8616(self.codegen, 1)
                self._record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                if self.prune_consumed_arg_stores and (
                    summary is not None or typed_stack_probe_fact is not None
                ):
                    self._delete_consumed_indices_8616(
                        new_statements,
                        consumed_indices,
                        live_consumers=(call, *statements[i + 1 :]),
                    )
                self._refresh_summary_arg_shape(call, summary)
                applied = True
            if transaction.changed:
                self.changed = True
        return applied

    def _strict_remat_arm_8_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        semantic_call_name: str | None,
        summary: StructuredAstValue,
    ) -> bool:
        """Strict-rematerialization attempt arm 8."""
        applied = False
        resolved_call_name = semantic_call_name or call_name
        default_args = (
            _known_default_args_for_missing_8616(resolved_call_name, self.codegen)
            if isinstance(resolved_call_name, str)
            else None
        )
        if default_args is not None and len(default_args) == expected_arg_count:
            transaction = self._set_materialized_call_args(
                call,
                list(default_args),
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_changed:
                record_stack_arg_materialization_8616(self.codegen, len(default_args))
            if transaction.arguments_accepted:
                self._refresh_summary_arg_shape(call, summary)
                applied = True
            if transaction.changed:
                self.changed = True
        return applied

    def _strict_shape_remat_stmt_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        expected_arg_widths: StructuredAstValue,
        fallback_arg_count: StructuredAstValue,
        has_exact_arithmetic_push_sources: bool,
        has_instruction_proven_direct_push_sources: bool,
        has_physical_far_pointer_push_sources: bool,
        has_recent_stack_arg_store_evidence: bool,
        i: int,
        is_stack_probe_helper: bool,
        logical_arg_widths_for_sources: StructuredAstValue,
        new_statements: list[StructuredAstValue],
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        stack_probe_address_seen: bool,
        stack_probe_seen: bool,
        statements: list[StructuredAstValue],
        stmt: StructuredAstValue,
        summary: StructuredAstValue,
        summary_return_addr: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
        typed_stack_probe_materialization: bool,
    ) -> None:
        """Apply strict push-source rematerialization for one call statement."""
        strict_arg_shape_applied = False
        if (
            self._strict_push_source_shape_ok_8616(push_arg_sources, has_physical_far_pointer_push_sources, has_exact_arithmetic_push_sources, has_instruction_proven_direct_push_sources, expected_arg_count, expected_arg_widths, has_recent_stack_arg_store_evidence)
        ):
            applied = self._strict_remat_arm_0_8616(
                call=call,
                call_name=call_name,
                has_instruction_proven_direct_push_sources=has_instruction_proven_direct_push_sources,
                has_recent_stack_arg_store_evidence=has_recent_stack_arg_store_evidence,
                logical_arg_widths_for_sources=logical_arg_widths_for_sources,
                new_statements=new_statements,
                push_arg_sources=push_arg_sources,
                semantic_call_name=semantic_call_name,
                summary=summary,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied
        if (
            not strict_arg_shape_applied
            and typed_stack_probe_fact is not None
            and stack_probe_seen
            and not is_stack_probe_helper
        ):
            applied = self._strict_remat_arm_1_8616(
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                fallback_arg_count=fallback_arg_count,
                i=i,
                new_statements=new_statements,
                semantic_call_name=semantic_call_name,
                statements=statements,
                summary=summary,
                summary_return_addr=summary_return_addr,
                typed_stack_probe_fact=typed_stack_probe_fact,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied
        if (
            not strict_arg_shape_applied
            and typed_stack_probe_fact is not None
            and stack_probe_seen
            and not is_stack_probe_helper
        ):
            applied = self._strict_remat_arm_2_8616(
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                i=i,
                new_statements=new_statements,
                semantic_call_name=semantic_call_name,
                statements=statements,
                summary=summary,
                summary_return_addr=summary_return_addr,
                typed_stack_probe_fact=typed_stack_probe_fact,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied
        if (
            _push_source_count_matches_8616(strict_arg_shape_applied, expected_arg_count, push_arg_sources)
        ):
            applied = self._strict_remat_arm_3_8616(
                call=call,
                call_name=call_name,
                logical_arg_widths_for_sources=logical_arg_widths_for_sources,
                new_statements=new_statements,
                push_arg_sources=push_arg_sources,
                semantic_call_name=semantic_call_name,
                summary=summary,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied
        if not strict_arg_shape_applied and (
            not typed_stack_probe_materialization
            and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
        ):
            applied = self._strict_remat_arm_4_8616(
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                expected_arg_widths=expected_arg_widths,
                i=i,
                logical_arg_widths_for_sources=logical_arg_widths_for_sources,
                new_statements=new_statements,
                push_arg_sources=push_arg_sources,
                semantic_call_name=semantic_call_name,
                statements=statements,
                summary=summary,
                summary_return_addr=summary_return_addr,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied
        if not strict_arg_shape_applied and (
            not typed_stack_probe_materialization
            and (not stack_probe_seen or stack_probe_address_seen or typed_stack_probe_fact is None)
        ):
            applied = self._strict_remat_arm_5_8616(
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                i=i,
                new_statements=new_statements,
                semantic_call_name=semantic_call_name,
                stmt=stmt,
                summary=summary,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied
        if (
            _probe_fact_gate_ok_8616(strict_arg_shape_applied, typed_stack_probe_materialization, stack_probe_address_seen, expected_arg_count, stack_probe_seen, typed_stack_probe_fact)
        ):
            applied = self._strict_remat_arm_6_8616(
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                i=i,
                new_statements=new_statements,
                semantic_call_name=semantic_call_name,
                statements=statements,
                summary=summary,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied
        if (
            _single_probe_fact_arg_gate_8616(stack_probe_seen, strict_arg_shape_applied, expected_arg_count, typed_stack_probe_fact, is_stack_probe_helper, new_statements)
        ):
            applied = self._strict_remat_arm_7_8616(
                call=call,
                call_name=call_name,
                i=i,
                new_statements=new_statements,
                semantic_call_name=semantic_call_name,
                statements=statements,
                summary=summary,
                summary_return_addr=summary_return_addr,
                typed_stack_probe_fact=typed_stack_probe_fact,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied
        if (
            _named_probe_fact_gate_8616(strict_arg_shape_applied, expected_arg_count, stack_probe_address_seen, semantic_call_name, call_name, stack_probe_seen, typed_stack_probe_fact)
        ):
            applied = self._strict_remat_arm_8_8616(
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                semantic_call_name=semantic_call_name,
                summary=summary,
            )
            strict_arg_shape_applied = strict_arg_shape_applied or applied

    def _remat_fallback_args_8616(self,
        *,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        has_recent_stack_arg_store_evidence: bool,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
    ) -> tuple[StructuredAstValue, ...] | None:
        """Resolve exact-shape direct push sources or known default args."""
        if not (isinstance(expected_arg_count, int) and expected_arg_count > 0):
            return None
        fallback_args = None
        if (
            isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == expected_arg_count
            and not has_recent_stack_arg_store_evidence
        ):
            ordered_push_sources = (
                list(reversed(push_arg_sources)) if len(push_arg_sources) > 1 else list(push_arg_sources)
            )
            direct_args = [
                self._direct_expr_from_push_source_8616(
                    source,
                    call_name=semantic_call_name or call_name,
                    arg_index=idx,
                )
                for idx, source in enumerate(ordered_push_sources)
            ]
            if all(arg is not None for arg in direct_args):
                fallback_args = tuple(direct_args)
        if fallback_args is None:
            fallback_args = _known_default_args_for_missing_8616(
                semantic_call_name or call_name or "", self.codegen
            )
        return fallback_args

    def _remat_apply_fallback_args_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        fallback_args: StructuredAstValue,
        i: int,
        is_stack_probe_helper: bool,
        new_statements: list[StructuredAstValue],
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        stack_probe_seen: bool,
        statements: list[StructuredAstValue],
        stmt: StructuredAstValue,
        summary: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> int | None:
        """Install exact-count fallback args and consume the statement."""
        if not (
            fallback_args is not None
            and isinstance(expected_arg_count, int)
            and len(fallback_args) == expected_arg_count
        ):
            return None
        transaction = self._set_materialized_call_args(
            call,
            list(fallback_args),
            call_name=semantic_call_name or call_name,
            force_replace=True,
        )
        if transaction.arguments_accepted:
            record_stack_arg_materialization_8616(self.codegen, len(fallback_args))
            self._refresh_summary_arg_shape(call, summary)
        if transaction.changed:
            self.changed = True
        if self._apply_call_return_store_destination_8616(
            stmt,
            call,
            summary,
            tuple(statements[i + 1 : i + 9]),
        ):
            self.changed = True
        self._append_call_statement_with_relocated_writes_8616(call=call, i=i, is_stack_probe_helper=is_stack_probe_helper, new_statements=new_statements, push_arg_sources=push_arg_sources, stack_probe_seen=stack_probe_seen, statements=statements, stmt=stmt, summary=summary, typed_stack_probe_fact=typed_stack_probe_fact)
        return i + 1

    def _remat_apply_backtracked_args_8616(self,
        *,
        call: StructuredAstValue,
        call_name: str | None,
        consumed_indices: list[int],
        i: int,
        is_stack_probe_helper: bool,
        new_statements: list[StructuredAstValue],
        normalized_args: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        stack_probe_address_seen: bool,
        stack_probe_seen: bool,
        statements: list[StructuredAstValue],
        stmt: StructuredAstValue,
        summary: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
        typed_stack_probe_materialization: bool,
        want_arg_count: int,
    ) -> int | None:
        """Install backtracked stack args, or retry with inline store args."""
        if (
            self._normalized_args_probe_gate_8616(normalized_args, stack_probe_address_seen, stack_probe_seen, typed_stack_probe_fact, typed_stack_probe_materialization)
        ):
            transaction = self._set_materialized_call_args(
                call,
                normalized_args,
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_accepted:
                record_stack_arg_materialization_8616(self.codegen, len(normalized_args))
                self._record_prunable_segment_metadata_ids(call, new_statements, consumed_indices)
                if self.prune_consumed_arg_stores and (
                    summary is not None or (typed_stack_probe_fact is not None and stack_probe_seen)
                ):
                    self._delete_consumed_indices_8616(
                        new_statements,
                        consumed_indices,
                        live_consumers=(call, *statements[i + 1 :]),
                    )
                self._refresh_summary_arg_shape(call, summary)
            if transaction.changed:
                self.changed = True
            return None
        if want_arg_count <= 0:
            self._append_call_statement_with_relocated_writes_8616(call=call, i=i + 1, is_stack_probe_helper=is_stack_probe_helper, new_statements=new_statements, push_arg_sources=push_arg_sources, stack_probe_seen=stack_probe_seen, statements=statements, stmt=stmt, summary=summary, typed_stack_probe_fact=typed_stack_probe_fact)
            return i + 1
        inline_rhs = self._extract_inline_stack_store_args(stmt, call, 1)
        normalized_args = (
            self._normalize_materialized_call_args(
                list(inline_rhs),
                [max(i - 1, 0)],
                new_statements,
                call_name=semantic_call_name or call_name,
            )
            if inline_rhs
            else None
        )
        if (
            self._normalized_args_probe_gate_8616(normalized_args, stack_probe_address_seen, stack_probe_seen, typed_stack_probe_fact, typed_stack_probe_materialization)
        ):
            transaction = self._set_materialized_call_args(
                call,
                [normalized_args[0]],
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.arguments_accepted:
                record_stack_arg_materialization_8616(self.codegen, 1)
                self._refresh_summary_arg_shape(call, summary)
            if transaction.changed:
                self.changed = True
        return None

    def _remat_no_count_stmt_8616(self,
        *,
        arg_count: StructuredAstValue,
        call: StructuredAstValue,
        call_name: str | None,
        expected_arg_count: StructuredAstValue,
        fallback_arg_count: StructuredAstValue,
        has_recent_stack_arg_store_evidence: bool,
        i: int,
        is_stack_probe_helper: bool,
        known_arg_count: StructuredAstValue,
        new_statements: list[StructuredAstValue],
        prototype_arg_count: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: str | None,
        stack_probe_address_seen: bool,
        stack_probe_seen: bool,
        statements: list[StructuredAstValue],
        stmt: StructuredAstValue,
        summary: StructuredAstValue,
        summary_return_addr: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
        typed_stack_probe_materialization: bool,
    ) -> int | None:
        """Fallback rematerialization when no arg-count contract applies.

        Returns the advanced statement index when the statement was fully
        consumed (appended to ``new_statements``); ``None`` lets the caller run
        its normal post-call tail.
        """
        fallback_args = self._remat_fallback_args_8616(
            call_name=call_name,
            expected_arg_count=expected_arg_count,
            has_recent_stack_arg_store_evidence=has_recent_stack_arg_store_evidence,
            push_arg_sources=push_arg_sources,
            semantic_call_name=semantic_call_name,
        )
        consumed_i = self._remat_apply_fallback_args_8616(
            call=call,
            call_name=call_name,
            expected_arg_count=expected_arg_count,
            fallback_args=fallback_args,
            i=i,
            is_stack_probe_helper=is_stack_probe_helper,
            new_statements=new_statements,
            push_arg_sources=push_arg_sources,
            semantic_call_name=semantic_call_name,
            stack_probe_seen=stack_probe_seen,
            statements=statements,
            stmt=stmt,
            summary=summary,
            typed_stack_probe_fact=typed_stack_probe_fact,
        )
        if consumed_i is not None:
            return consumed_i
        want_arg_count = 0
        if isinstance(fallback_arg_count, int) and fallback_arg_count > 0:
            want_arg_count = max(fallback_arg_count, 1)
        allow_unbounded_collect = (
            (isinstance(fallback_arg_count, int) and fallback_arg_count > 1)
            or (isinstance(known_arg_count, int) and known_arg_count > 1)
            or (isinstance(prototype_arg_count, int) and prototype_arg_count > 1)
        )
        candidate_rhs, consumed_indices = self._collect_backtracked_stack_args(
            new_statements,
            wanted_count=None if allow_unbounded_collect else want_arg_count,
            max_count=max(want_arg_count, 4),
            typed_probe_fact=typed_stack_probe_fact if stack_probe_seen else None,
            allow_partial=not (isinstance(arg_count, int) and arg_count > 0),
            call_return_addr=summary_return_addr,
        )
        normalized_args = self._normalize_materialized_call_args(
            candidate_rhs,
            consumed_indices,
            new_statements,
            call_name=semantic_call_name or call_name,
        )
        return self._remat_apply_backtracked_args_8616(
            call=call,
            call_name=call_name,
            consumed_indices=consumed_indices,
            i=i,
            is_stack_probe_helper=is_stack_probe_helper,
            new_statements=new_statements,
            normalized_args=normalized_args,
            push_arg_sources=push_arg_sources,
            semantic_call_name=semantic_call_name,
            stack_probe_address_seen=stack_probe_address_seen,
            stack_probe_seen=stack_probe_seen,
            statements=statements,
            stmt=stmt,
            summary=summary,
            typed_stack_probe_fact=typed_stack_probe_fact,
            typed_stack_probe_materialization=typed_stack_probe_materialization,
            want_arg_count=want_arg_count,
        )

    def _rewrite_probe_helper_stmt_8616(self,
        *,
        stmt: StructuredAstValue,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        statements: list[StructuredAstValue],
        i: int,
        is_stack_probe_helper: bool,
        stack_probe_seen: bool,
        stack_probe_address_seen: bool,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> tuple[bool, bool, StructuredAstValue, bool]:
        """Process one stack-probe helper statement.

        Returns ``(stack_probe_seen, stack_probe_address_seen, typed_fact,
        consumed)`` where ``consumed`` marks a pruned helper call.
        """
        if not is_stack_probe_helper:
            return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact, False
        stack_probe_seen = True
        _record_stack_probe_helper_target_fingerprints_8616(self.codegen, summary=summary, call=call)
        typed_stack_probe_fact = self.typed_stack_probe_facts.get(id(call)) if call is not None else None
        helper_return_space = summary.helper_return_space if summary is not None else None
        helper_return_space = helper_return_space.lower() if isinstance(helper_return_space, str) else None
        helper_return_state = summary.helper_return_state if summary is not None else "none"
        if (
            typed_stack_probe_fact is None
            and helper_return_state == "stack_address"
            and isinstance(helper_return_space, str)
            and helper_return_space != "ss"
        ):
            helper_return_width = summary.helper_return_width if summary is not None else None
            if isinstance(helper_return_width, int) and helper_return_width > 0:
                typed_stack_probe_fact = TypedStackProbeReturnFact8616(
                    call_node_id=id(call) if call is not None else -1,
                    segment_space=helper_return_space,
                    width=helper_return_width,
                    carrier_keys=(),
                )
        stack_probe_address_seen = (
            typed_stack_probe_fact is not None and typed_stack_probe_fact.segment_space == "ss"
        ) or (bool(helper_return_state == "stack_address") and helper_return_space in {None, "ss"})
        if isinstance(call, CFunctionCall) and self._stack_probe_helper_statement_is_consumable_8616(
            stmt,
            call,
            summary,
            statements,
            i,
            typed_stack_probe_fact,
        ) and not self._has_nonvirtual_dirty_probe_consumer_8616(statements, i):
            ensure_stack_probe_fact_stats_8616(self.codegen)["stack_probe_calls_pruned"] += 1
            self.changed = True
            return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact, True
        ensure_stack_probe_fact_stats_8616(self.codegen)["stack_probe_calls_refused"] += 1
        return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact, False

    def _resolve_call_arity_evidence_8616(self,
        *,
        arg_count: StructuredAstValue,
        call: StructuredAstValue,
        call_name: StructuredAstValue,
        effective_prototype_arg_widths: StructuredAstValue,
        is_stack_probe_helper: StructuredAstValue,
        known_arg_count: StructuredAstValue,
        prototype_arg_count: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: StructuredAstValue,
        stack_cleanup: StructuredAstValue,
        stack_probe_seen: StructuredAstValue,
        summary: StructuredAstValue,
        summary_arg_count: StructuredAstValue,
        summary_logical_arg_widths: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> _CallArityEvidence8616:
        """Resolve expected arg count/widths and rematerialization verdict."""
        typed_stack_probe_materialization = (
            typed_stack_probe_fact is not None and stack_probe_seen and not is_stack_probe_helper
        )
        expected_arg_count = (
            len(summary_logical_arg_widths)
            if summary_logical_arg_widths is not None
            else _expected_arg_count_for_call_8616(
                arg_count if isinstance(arg_count, int) else None,
                known_arg_count=known_arg_count,
                prototype_arg_count=prototype_arg_count,
            )
        )
        expected_arg_widths = summary_logical_arg_widths or effective_prototype_arg_widths
        arity_contract = _known_callee_arity_contract_8616(semantic_call_name or call_name or "")
        exact_callee_abi = arity_contract.mode is CallArityMode8616.EXACT
        caller_stack_shape_evidence = (
            exact_caller_stack_object_shape_evidence_8616(summary, self.caller_stack_objects)
            if summary is not None and not exact_callee_abi
            else None
        )
        if caller_stack_shape_evidence is not None:
            expected_arg_widths = caller_stack_shape_evidence.widths
            expected_arg_count = len(caller_stack_shape_evidence.widths)
        if (
            arity_contract.mode is CallArityMode8616.EXACT
            and isinstance(arity_contract.count, int)
            and arity_contract.count > 0
            and isinstance(push_arg_sources, tuple)
            and push_arg_sources
        ):
            source_width = self._push_sources_total_width_8616(push_arg_sources)
            if (
                isinstance(source_width, int)
                and source_width >= arity_contract.count * 2
                and source_width % arity_contract.count == 0
                and (
                    expected_arg_widths is None
                    or source_width != sum(max(2, int(width)) for width in expected_arg_widths)
                )
            ):
                expected_arg_widths = (source_width // arity_contract.count,) * arity_contract.count
        if (
            _arity_contract_extends_count_8616(arity_contract, expected_arg_count, push_arg_sources, stack_cleanup)
        ):
            expected_arg_count = arity_contract.count
        logical_count_from_widths = self._logical_arg_count_from_width_evidence_8616(
            known_arg_count=known_arg_count,
            prototype_arg_count=prototype_arg_count,
            expected_arg_widths=expected_arg_widths,
            push_arg_sources=push_arg_sources,
            arity_contract=arity_contract,
        )
        if (
            isinstance(logical_count_from_widths, int)
            and isinstance(summary_arg_count, int)
            and summary_arg_count > logical_count_from_widths
        ):
            expected_arg_count = logical_count_from_widths
        accounted_target_prototype = (
            expected_arg_widths is not None
            and isinstance(prototype_arg_count, int)
            and prototype_arg_count == len(expected_arg_widths)
            and self._prototype_widths_account_for_push_sources_8616(expected_arg_widths, push_arg_sources)
        )
        logical_arg_widths_for_sources = (
            caller_stack_shape_evidence.widths
            if caller_stack_shape_evidence is not None
            else expected_arg_widths
            if exact_callee_abi or accounted_target_prototype
            else None
        )
        if call is not None and summary is not None and logical_arg_widths_for_sources:
            self.logical_shape_evidence_by_callsite[summary.callsite_addr] = (
                caller_stack_shape_evidence
                if caller_stack_shape_evidence is not None
                else LogicalArgumentShapeEvidence8616(
                    widths=logical_arg_widths_for_sources,
                    source=(
                        LogicalArgumentShapeEvidenceSource8616.EXACT_CALLEE_ABI
                        if exact_callee_abi
                        else LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_TARGET_PROTOTYPE
                    ),
                )
            )
        if (
            expected_arg_widths is not None
            and isinstance(prototype_arg_count, int)
            and isinstance(summary_arg_count, int)
            and prototype_arg_count < summary_arg_count
            and self._prototype_widths_account_for_push_sources_8616(expected_arg_widths, push_arg_sources)
        ):
            expected_arg_count = prototype_arg_count
        if self._apply_indirect_callsite_type_8616(call, summary, expected_arg_count):
            self.changed = True
        has_strong_direct_push_sources = (
            isinstance(expected_arg_count, int)
            and expected_arg_count > 0
            and isinstance(push_arg_sources, tuple)
            and len(push_arg_sources) == expected_arg_count
            and all(
                isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int)
                for source in push_arg_sources
            )
        )
        if (
            _known_arg_count_override_ok_8616(expected_arg_count, known_arg_count, summary_arg_count, has_strong_direct_push_sources, stack_probe_seen)
        ):
            expected_arg_count = known_arg_count
        fallback_arg_count = self._fallback_call_arg_count_8616(
            expected_arg_count=expected_arg_count,
            push_arg_sources=push_arg_sources,
        )
        rematerialize_call_args = (
            self._call_args_need_rematerialization_8616(
                call,
                push_arg_sources=push_arg_sources,
                semantic_call_name=semantic_call_name,
                expected_arg_widths=logical_arg_widths_for_sources,
            )
            if call is not None
            else False
        )
        return _CallArityEvidence8616(
            typed_stack_probe_materialization=typed_stack_probe_materialization,
            expected_arg_count=expected_arg_count,
            expected_arg_widths=expected_arg_widths,
            logical_arg_widths_for_sources=logical_arg_widths_for_sources,
            fallback_arg_count=fallback_arg_count,
            rematerialize_call_args=rematerialize_call_args,
        )

    def _single_bp_direct_arg_stmt_8616(self,
        *,
        call: StructuredAstValue,
        call_name: StructuredAstValue,
        expected_arg_count: StructuredAstValue,
        i: StructuredAstValue,
        is_stack_probe_helper: StructuredAstValue,
        new_statements: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: StructuredAstValue,
        stack_probe_seen: StructuredAstValue,
        statements: StructuredAstValue,
        stmt: StructuredAstValue,
        summary: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> int | None:
        """Materialize a single proven BP push source as the sole call arg.

        Returns the advanced statement index when consumed, else ``None``.
        """
        direct_stack_arg = self._direct_expr_from_push_source_8616(
            push_arg_sources[0],
            call_name=semantic_call_name or call_name,
            arg_index=0,
            materialize_pointer=False,
        )
        if direct_stack_arg is not None:
            transaction = self._set_materialized_call_args(
                call,
                [self._clone_c_ast_tree(direct_stack_arg)],
                call_name=semantic_call_name or call_name,
                force_replace=True,
            )
            if transaction.changed:
                self.changed = True
            if transaction.arguments_accepted:
                while new_statements and self._is_outgoing_stack_arg_segment_placeholder_store_statement(
                    new_statements[-1],
                    stack_probe_seen=stack_probe_seen,
                ):
                    new_statements.pop()
                    self.stats.consumed_outgoing_stack_placeholder_count += 1
                    self.changed = True
                if transaction.arguments_changed:
                    record_stack_arg_materialization_8616(self.codegen, 1)
                self._refresh_summary_arg_shape(call, summary)
            if self._apply_call_return_store_destination_8616(
                stmt,
                call,
                summary,
                tuple(statements[i + 1 : i + 9]),
            ):
                self.changed = True
            self._append_call_statement_with_relocated_writes_8616(call=call, i=i, is_stack_probe_helper=is_stack_probe_helper, new_statements=new_statements, push_arg_sources=push_arg_sources, stack_probe_seen=stack_probe_seen, statements=statements, stmt=stmt, summary=summary, typed_stack_probe_fact=typed_stack_probe_fact)
            return i + 1
        return None


    def _rematerialize_call_stmt_8616(self,
        *,
        arg_count: StructuredAstValue,
        call: StructuredAstValue,
        call_name: StructuredAstValue,
        effective_prototype_arg_widths: StructuredAstValue,
        i: StructuredAstValue,
        is_stack_probe_helper: StructuredAstValue,
        known_arg_count: StructuredAstValue,
        known_prototype_arg_widths: StructuredAstValue,
        new_statements: StructuredAstValue,
        prototype_arg_count: StructuredAstValue,
        prototype_arg_widths: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        semantic_call_name: StructuredAstValue,
        stack_cleanup: StructuredAstValue,
        stack_probe_address_seen: StructuredAstValue,
        stack_probe_seen: StructuredAstValue,
        statements: StructuredAstValue,
        stmt: StructuredAstValue,
        summary: StructuredAstValue,
        summary_arg_count: StructuredAstValue,
        summary_logical_arg_widths: StructuredAstValue,
        summary_return_addr: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> int:
        """Run evidence resolution and rematerialization for one call stmt.

        Returns the advanced statement index.
        """
        ev = self._resolve_call_arity_evidence_8616(
            arg_count=arg_count,
            call=call,
            call_name=call_name,
            effective_prototype_arg_widths=effective_prototype_arg_widths,
            is_stack_probe_helper=is_stack_probe_helper,
            known_arg_count=known_arg_count,
            prototype_arg_count=prototype_arg_count,
            push_arg_sources=push_arg_sources,
            semantic_call_name=semantic_call_name,
            stack_cleanup=stack_cleanup,
            stack_probe_seen=stack_probe_seen,
            summary=summary,
            summary_arg_count=summary_arg_count,
            summary_logical_arg_widths=summary_logical_arg_widths,
            typed_stack_probe_fact=typed_stack_probe_fact,
        )
        typed_stack_probe_materialization = ev.typed_stack_probe_materialization
        expected_arg_count = ev.expected_arg_count
        expected_arg_widths = ev.expected_arg_widths
        logical_arg_widths_for_sources = ev.logical_arg_widths_for_sources
        fallback_arg_count = ev.fallback_arg_count
        rematerialize_call_args = ev.rematerialize_call_args
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION") and call is not None:
            log.warning(
                "[call-summary] function=%#x target=%s semantic=%s callsite=%r summary_target=%r expected_arg_count=%r "
                "prototype_widths=%r known_widths=%r effective_widths=%r push_arg_sources=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                call_name,
                semantic_call_name,
                summary.callsite_addr if summary is not None else None,
                summary.target_addr if summary is not None else None,
                expected_arg_count,
                prototype_arg_widths,
                known_prototype_arg_widths,
                effective_prototype_arg_widths,
                push_arg_sources,
            )
        if os.environ.get("INERTIA_DEBUG_PERCOLATEUP_CALLSITE") and call is not None and call_name == "PercolateUp":
            log.warning(
                "[percolateup-callsite] function=%#x expected_arg_count=%r prototype_arg_count=%r known_arg_count=%r remat=%r push_arg_sources=%r args=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                expected_arg_count,
                prototype_arg_count,
                known_arg_count,
                rematerialize_call_args,
                push_arg_sources,
                _boundary_tuple_8616(
                    self._debug_expr_8616(arg) for arg in _boundary_tuple_8616(getattr(call, "args", ()) or ())
                ),
            )
        # When a stack-probe helper was seen but its segment space is not SS
        # (e.g. "ds"), the probe return address is not a stack address.
        # Reject backward-scan materialization for calls after the probe.
        # Guard only when we have typed stack-probe address evidence in-flight.
        # Plain stack-probe helpers like aNchkstk are not address-producing
        # evidence and must not globally suppress call-argument rematerialization.
        fl = self._collect_call_evidence_flags_8616(
            call=call,
            call_name=call_name,
            expected_arg_count=expected_arg_count,
            expected_arg_widths=expected_arg_widths,
            is_stack_probe_helper=is_stack_probe_helper,
            logical_arg_widths_for_sources=logical_arg_widths_for_sources,
            new_statements=new_statements,
            push_arg_sources=push_arg_sources,
            rematerialize_call_args=rematerialize_call_args,
            semantic_call_name=semantic_call_name,
            stack_probe_address_seen=stack_probe_address_seen,
            stack_probe_seen=stack_probe_seen,
            summary=summary,
            typed_stack_probe_fact=typed_stack_probe_fact,
            typed_stack_probe_materialization=typed_stack_probe_materialization,
        )
        probe_seen_without_ss_address = fl.probe_seen_without_ss_address
        has_exact_direct_push_sources = fl.has_exact_direct_push_sources
        has_instruction_proven_direct_push_sources = fl.has_instruction_proven_direct_push_sources
        has_safe_non_stack_fallback = fl.has_safe_non_stack_fallback
        has_recent_stack_arg_store_evidence = fl.has_recent_stack_arg_store_evidence
        has_physical_far_pointer_push_sources = fl.has_physical_far_pointer_push_sources
        has_exact_arithmetic_push_sources = fl.has_exact_arithmetic_push_sources
        rematerialize_call_args = fl.rematerialize_call_args
        if (
            _single_bp_push_source_8616(call, is_stack_probe_helper, expected_arg_count, push_arg_sources)
        ):
            single_i = self._single_bp_direct_arg_stmt_8616(
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                i=i,
                is_stack_probe_helper=is_stack_probe_helper,
                new_statements=new_statements,
                push_arg_sources=push_arg_sources,
                semantic_call_name=semantic_call_name,
                stack_probe_seen=stack_probe_seen,
                statements=statements,
                stmt=stmt,
                summary=summary,
                typed_stack_probe_fact=typed_stack_probe_fact,
            )
            if single_i is not None:
                return single_i
        if (
            _strict_shape_remat_ok_8616(rematerialize_call_args, call, expected_arg_count, has_exact_direct_push_sources, has_safe_non_stack_fallback, probe_seen_without_ss_address)
        ):
            remat_i = self._strict_shape_remat_stmt_8616(
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                expected_arg_widths=expected_arg_widths,
                fallback_arg_count=fallback_arg_count,
                has_exact_arithmetic_push_sources=has_exact_arithmetic_push_sources,
                has_instruction_proven_direct_push_sources=has_instruction_proven_direct_push_sources,
                has_physical_far_pointer_push_sources=has_physical_far_pointer_push_sources,
                has_recent_stack_arg_store_evidence=has_recent_stack_arg_store_evidence,
                i=i,
                is_stack_probe_helper=is_stack_probe_helper,
                logical_arg_widths_for_sources=logical_arg_widths_for_sources,
                new_statements=new_statements,
                push_arg_sources=push_arg_sources,
                semantic_call_name=semantic_call_name,
                stack_probe_address_seen=stack_probe_address_seen,
                stack_probe_seen=stack_probe_seen,
                statements=statements,
                stmt=stmt,
                summary=summary,
                summary_return_addr=summary_return_addr,
                typed_stack_probe_fact=typed_stack_probe_fact,
                typed_stack_probe_materialization=typed_stack_probe_materialization,
            )
        elif (
            _remat_no_count_gate_8616(rematerialize_call_args, call, is_stack_probe_helper, arg_count, new_statements)
        ):
            remat_i = self._remat_no_count_stmt_8616(
                arg_count=arg_count,
                call=call,
                call_name=call_name,
                expected_arg_count=expected_arg_count,
                fallback_arg_count=fallback_arg_count,
                has_recent_stack_arg_store_evidence=has_recent_stack_arg_store_evidence,
                i=i,
                is_stack_probe_helper=is_stack_probe_helper,
                known_arg_count=known_arg_count,
                new_statements=new_statements,
                prototype_arg_count=prototype_arg_count,
                push_arg_sources=push_arg_sources,
                semantic_call_name=semantic_call_name,
                stack_probe_address_seen=stack_probe_address_seen,
                stack_probe_seen=stack_probe_seen,
                statements=statements,
                stmt=stmt,
                summary=summary,
                summary_return_addr=summary_return_addr,
                typed_stack_probe_fact=typed_stack_probe_fact,
                typed_stack_probe_materialization=typed_stack_probe_materialization,
            )
        else:
            remat_i = None
        if remat_i is not None:
            return remat_i
        if self._apply_call_return_store_destination_8616(
            stmt,
            call,
            summary,
            tuple(statements[i + 1 : i + 9]),
        ):
            self.changed = True
        if call is not None:
            self._append_call_statement_with_relocated_writes_8616(call=call, i=i, is_stack_probe_helper=is_stack_probe_helper, new_statements=new_statements, push_arg_sources=push_arg_sources, stack_probe_seen=stack_probe_seen, statements=statements, stmt=stmt, summary=summary, typed_stack_probe_fact=typed_stack_probe_fact)
        else:
            new_statements.append(stmt)
        return i + 1


    def _collect_call_evidence_flags_8616(self,
        *,
        call: StructuredAstValue,
        call_name: StructuredAstValue,
        expected_arg_count: StructuredAstValue,
        expected_arg_widths: StructuredAstValue,
        is_stack_probe_helper: StructuredAstValue,
        logical_arg_widths_for_sources: StructuredAstValue,
        new_statements: StructuredAstValue,
        push_arg_sources: StructuredAstValue,
        rematerialize_call_args: StructuredAstValue,
        semantic_call_name: StructuredAstValue,
        stack_probe_address_seen: StructuredAstValue,
        stack_probe_seen: StructuredAstValue,
        summary: StructuredAstValue,
        typed_stack_probe_fact: StructuredAstValue,
        typed_stack_probe_materialization: StructuredAstValue,
    ) -> _CallEvidenceFlags8616:
        """Collect derived push-source/store evidence flags for one call."""
        probe_seen_without_ss_address = (
            stack_probe_seen and not stack_probe_address_seen and typed_stack_probe_fact is not None
        )
        if (
            call is not None
            and isinstance(expected_arg_count, int)
            and expected_arg_count >= 0
            and len(_boundary_tuple_8616(getattr(call, "args", ()) or ())) != expected_arg_count
        ):
            rematerialize_call_args = True
        if typed_stack_probe_materialization:
            rematerialize_call_args = True
        has_exact_direct_push_sources = (
            isinstance(expected_arg_count, int)
            and expected_arg_count > 0
            and isinstance(push_arg_sources, tuple)
            and (
                len(push_arg_sources) == expected_arg_count
                or self._prototype_widths_account_for_push_sources_8616(expected_arg_widths, push_arg_sources)
            )
            and any(source is not None for source in push_arg_sources)
        )
        has_complete_exact_direct_push_sources = has_exact_direct_push_sources and all(
            source is not None for source in push_arg_sources
        )
        push_arg_instruction_addrs = (
            _boundary_tuple_8616(summary.push_arg_instruction_addrs) if summary is not None else ()
        )
        has_instruction_proven_direct_push_sources = (
            has_complete_exact_direct_push_sources
            and len(push_arg_instruction_addrs) == len(push_arg_sources)
            and all(isinstance(addr, int) for addr in push_arg_instruction_addrs)
        )
        has_safe_non_stack_fallback = (
            isinstance(expected_arg_count, int)
            and expected_arg_count > 0
            and _known_default_args_for_missing_8616(semantic_call_name or call_name or "", self.codegen) is not None
        )
        # Do not destructively clear existing call args when inferred arg-count
        # drops to zero. Zero can be an unproven placeholder; preserving current
        # args keeps call semantics stable until stronger evidence rematerializes.
        if (
            call is not None
            and not is_stack_probe_helper
            and expected_arg_count == 0
            and _boundary_tuple_8616(getattr(call, "args", ()) or ())
            and not probe_seen_without_ss_address
        ):
            rematerialize_call_args = False
        if os.environ.get("INERTIA_DEBUG_PERCOLATEUP_CALLSITE") and call is not None and call_name == "PercolateUp":
            log.warning(
                "[percolateup-callsite-post-zero] function=%#x expected_arg_count=%r remat=%r args=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                expected_arg_count,
                rematerialize_call_args,
                _boundary_tuple_8616(
                    self._debug_expr_8616(arg) for arg in _boundary_tuple_8616(getattr(call, "args", ()) or ())
                ),
            )



        if (
            call is not None
            and _boundary_tuple_8616(getattr(call, "args", ()) or ())
            and self._normalize_existing_call_args_8616(
                call,
                new_statements,
                call_name=semantic_call_name or call_name,
                push_arg_sources=push_arg_sources,
            )
        ):
            self._refresh_summary_arg_shape(call, summary)
            self.changed = True
            rematerialize_call_args = (
                self._call_args_need_rematerialization_8616(
                    call,
                    push_arg_sources=push_arg_sources,
                    semantic_call_name=semantic_call_name,
                    expected_arg_widths=logical_arg_widths_for_sources,
                )
                if (
                    isinstance(push_arg_sources, tuple)
                    and any(self._has_arithmetic_push_source(source) for source in push_arg_sources)
                )
                else rematerialize_call_args
            )
        has_recent_stack_arg_store_evidence = (
            self._has_recent_stack_arg_store_evidence(
                new_statements,
                expected_arg_count,
                typed_stack_probe_fact if stack_probe_seen else None,
            )
            if isinstance(expected_arg_count, int)
            else False
        )
        has_physical_far_pointer_push_sources = (
            isinstance(push_arg_sources, tuple)
            and self._prototype_widths_account_for_push_sources_8616(expected_arg_widths, push_arg_sources)
            and any(
                isinstance(source, tuple)
                and len(source) >= 1
                and source[0] == CallsitePushSourceKind8616.SEGMENT.value
                for source in push_arg_sources
            )
        )
        has_exact_arithmetic_push_sources = (
            has_exact_direct_push_sources
            and isinstance(push_arg_sources, tuple)
            and any(self._has_simple_bp_arithmetic_push_source(source) for source in push_arg_sources)
        )
        return _CallEvidenceFlags8616(
            probe_seen_without_ss_address=probe_seen_without_ss_address,
            has_exact_direct_push_sources=has_exact_direct_push_sources,
            has_instruction_proven_direct_push_sources=has_instruction_proven_direct_push_sources,
            has_safe_non_stack_fallback=has_safe_non_stack_fallback,
            has_recent_stack_arg_store_evidence=has_recent_stack_arg_store_evidence,
            has_physical_far_pointer_push_sources=has_physical_far_pointer_push_sources,
            has_exact_arithmetic_push_sources=has_exact_arithmetic_push_sources,
            rematerialize_call_args=rematerialize_call_args,
        )

    def _resolve_call_stmt_facts_8616(self, call: StructuredAstValue) -> _CallStmtFacts8616:
        """Resolve summary, names, prototype widths, and probe-helper verdict."""
        summary = self.summary_map.get(id(call)) if call is not None else None
        arg_count = summary.arg_count if summary is not None else None
        summary_arg_count = arg_count if isinstance(arg_count, int) else None
        stack_cleanup = summary.stack_cleanup if summary is not None else None
        summary_return_addr = summary.return_addr if summary is not None else None
        call_name = _call_node_name_8616(call) if call is not None else None
        semantic_call_name = _semantic_call_name_from_summary_8616(self.project, summary, call_name)
        prototype_arg_widths = self._prototype_arg_widths_for_call_8616(call) if call is not None else None
        known_prototype_arg_widths = (
            _known_helper_prototype_arg_widths_8616(self.project, semantic_call_name or call_name)
            if call is not None
            else None
        )
        effective_prototype_arg_widths = known_prototype_arg_widths or prototype_arg_widths
        if (
            summary is not None
            and known_prototype_arg_widths is not None
            and _prototype_widths_account_for_push_sources_top_8616(
                known_prototype_arg_widths,
                _boundary_tuple_8616(summary.push_arg_sources or ()),
            )
            and summary.logical_arg_widths != known_prototype_arg_widths
        ):
            summary = replace(summary, logical_arg_widths=known_prototype_arg_widths)
            self.summary_map[id(call)] = summary
            record_callsite_summary_fact_8616(self.codegen, summary, node_id=id(call), attached=True)
            self.changed = True
        summary_logical_arg_widths = _logical_arg_widths_for_summary_8616(summary)
        if summary_logical_arg_widths is not None:
            effective_prototype_arg_widths = summary_logical_arg_widths
        prototype_arg_count = (
            len(effective_prototype_arg_widths)
            if effective_prototype_arg_widths is not None
            else self._prototype_arg_count(call)
            if call is not None
            else None
        )
        normalized_call_name = (
            normalize_callee_name_8616(semantic_call_name or call_name)
            if isinstance(semantic_call_name or call_name, str)
            else None
        )
        known_arg_count = (
            _expected_arg_count_for_known_callee_8616(semantic_call_name or call_name or "")
            if call is not None
            else None
        )
        if known_arg_count is None and isinstance(normalized_call_name, str) and normalized_call_name:
            known_arg_count = _expected_arg_count_for_known_callee_8616(normalized_call_name)
        is_stack_probe_helper = summary.stack_probe_helper if summary is not None else False
        push_arg_sources = _boundary_tuple_8616(summary.push_arg_sources) if summary is not None else ()
        physical_logical_widths = logical_argument_widths_from_callsite_8616(
            summary,
            expected_arg_count=known_arg_count if isinstance(known_arg_count, int) else prototype_arg_count,
        )
        if physical_logical_widths is not None and not self._prototype_widths_account_for_push_sources_8616(
            effective_prototype_arg_widths,
            push_arg_sources,
        ):
            effective_prototype_arg_widths = physical_logical_widths
            prototype_arg_count = len(physical_logical_widths)
            self.stats.physical_arg_width_override_count += 1
        if call is not None and not is_stack_probe_helper and _is_stack_probe_call_name_8616(call_name):
            is_stack_probe_helper = True
        return _CallStmtFacts8616(
            summary=summary,
            arg_count=arg_count,
            summary_arg_count=summary_arg_count,
            stack_cleanup=stack_cleanup,
            summary_return_addr=summary_return_addr,
            call_name=call_name,
            semantic_call_name=semantic_call_name,
            prototype_arg_widths=prototype_arg_widths,
            known_prototype_arg_widths=known_prototype_arg_widths,
            effective_prototype_arg_widths=effective_prototype_arg_widths,
            summary_logical_arg_widths=summary_logical_arg_widths,
            prototype_arg_count=prototype_arg_count,
            known_arg_count=known_arg_count,
            is_stack_probe_helper=is_stack_probe_helper,
            push_arg_sources=push_arg_sources,
        )

    def _rewrite_child_blocks_8616(self,
        block: StructuredAstValue,
        stack_probe_seen: bool,
        stack_probe_address_seen: bool,
        typed_stack_probe_fact: StructuredAstValue,
        allow_setup_assignment_prune: bool,
        depth: int,
    ) -> tuple[bool, bool, StructuredAstValue]:
        """Recurse into nested blocks, propagating stack-probe facts."""
        for stmt in getattr(block, "statements", ()) or ():
            nested_statements = getattr(stmt, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                (stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact) = (
                    self._rewrite_child_merge_8616(
                        stmt,
                        allow_setup_assignment_prune,
                        depth,
                        stack_probe_seen,
                        stack_probe_address_seen,
                        typed_stack_probe_fact,
                    )
                )
            if type(stmt).__name__ == "CSwitchCase":
                (stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact) = (
                    self._rewrite_switch_children_8616(
                        stmt,
                        stack_probe_seen,
                        stack_probe_address_seen,
                        typed_stack_probe_fact,
                        depth,
                    )
                )
            self._rewrite_deep_children_8616(
                stmt,
                stack_probe_seen,
                stack_probe_address_seen,
                typed_stack_probe_fact,
                depth,
            )
        return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact

    def _rewrite_child_merge_8616(self,
        child: StructuredAstValue,
        allow_setup_assignment_prune: bool,
        depth: int,
        stack_probe_seen: bool,
        stack_probe_address_seen: bool,
        typed_stack_probe_fact: StructuredAstValue,
    ) -> tuple[bool, bool, StructuredAstValue]:
        """Rewrite one child block and merge its probe facts."""
        (child_seen, child_addr_seen, child_fact) = self._rewrite_block(
            child,
            inherited_stack_probe_seen=stack_probe_seen,
            inherited_stack_probe_address_seen=stack_probe_address_seen,
            inherited_typed_stack_probe_fact=typed_stack_probe_fact,
            allow_setup_assignment_prune=allow_setup_assignment_prune,
            depth=depth + 1,
        )
        stack_probe_seen = stack_probe_seen or child_seen
        stack_probe_address_seen = stack_probe_address_seen or child_addr_seen
        if child_fact is not None:
            typed_stack_probe_fact = child_fact
        return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact

    def _rewrite_switch_children_8616(self,
        stmt: StructuredAstValue,
        stack_probe_seen: bool,
        stack_probe_address_seen: bool,
        typed_stack_probe_fact: StructuredAstValue,
        depth: int,
    ) -> tuple[bool, bool, StructuredAstValue]:
        """Rewrite CSwitchCase case/default bodies, merging probe facts."""
        for _case_value, case_body in getattr(stmt, "cases", ()) or ():
            if isinstance(getattr(case_body, "statements", None), (list, tuple)):
                (stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact) = (
                    self._rewrite_child_merge_8616(
                        case_body, False, depth, stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact
                    )
                )
        default_body = getattr(stmt, "default", None)
        if isinstance(getattr(default_body, "statements", None), (list, tuple)):
            (stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact) = (
                self._rewrite_child_merge_8616(
                    default_body, False, depth, stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact
                )
            )
        return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact

    def _rewrite_deep_children_8616(self,
        stmt: StructuredAstValue,
        stack_probe_seen: bool,
        stack_probe_address_seen: bool,
        typed_stack_probe_fact: StructuredAstValue,
        depth: int,
    ) -> None:
        """Rewrite nested body/else/branch children without merging facts."""
        nested = getattr(stmt, "body", None)
        if isinstance(getattr(nested, "statements", None), (list, tuple)):
            self._rewrite_block(
                nested,
                inherited_stack_probe_seen=stack_probe_seen,
                inherited_stack_probe_address_seen=stack_probe_address_seen,
                inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                allow_setup_assignment_prune=False,
                depth=depth + 1,
            )
        else_node = getattr(stmt, "else_node", None)
        if isinstance(getattr(else_node, "statements", None), (list, tuple)):
            self._rewrite_block(
                else_node,
                inherited_stack_probe_seen=stack_probe_seen,
                inherited_stack_probe_address_seen=stack_probe_address_seen,
                inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                allow_setup_assignment_prune=False,
                depth=depth + 1,
            )
        for pair in getattr(stmt, "condition_and_nodes", ()) or ():
            if isinstance(pair, tuple) and len(pair) == 2:
                branch = pair[1]
                if isinstance(getattr(branch, "statements", None), (list, tuple)):
                    self._rewrite_block(
                        branch,
                        inherited_stack_probe_seen=stack_probe_seen,
                        inherited_stack_probe_address_seen=stack_probe_address_seen,
                        inherited_typed_stack_probe_fact=typed_stack_probe_fact,
                        allow_setup_assignment_prune=False,
                        depth=depth + 1,
                    )



    def _rewrite_stmt_pre_gate_8616(self,
        stmt: StructuredAstValue,
        stack_probe_seen: bool,
        new_statements: list[StructuredAstValue],
    ) -> tuple[StructuredAstValue, bool]:
        """Early per-statement dispatch.

        Returns ``(call, True)`` when the statement is a call that should
        continue through materialization; ``(call, False)`` when it was
        already consumed or appended verbatim.
        """
        if id(stmt) in self.consumed_stale_return_alias_statement_ids:
            self.changed = True
            return None, False
        if self._is_outgoing_segment_return_store_statement(stmt, stack_probe_seen=stack_probe_seen):
            self.stats.consumed_outgoing_stack_placeholder_count += 1
            self.changed = True
            return None, False
        call = self._call_from_statement(stmt)
        if call is not None and _is_runtime_segment_helper_call_8616(call):
            new_statements.append(stmt)
            return call, False
        if (
            call is not None
            and structured_call_kind_8616(call) is StructuredCallKind8616.CODEGEN_INSERT_INTRINSIC
        ):
            self.codegen._inertia_callsite_structured_intrinsic_refusal_count_8616 = (
                int(getattr(self.codegen, "_inertia_callsite_structured_intrinsic_refusal_count_8616", 0) or 0) + 1
            )
            new_statements.append(stmt)
            return call, False
        if call is None:
            new_statements.append(stmt)
            return None, False
        return call, True

    def _rewrite_block_body(self,
        block: StructuredAstValue,
        statements: list[StructuredAstValue],
        *,
        inherited_stack_probe_seen: bool,
        inherited_stack_probe_address_seen: bool,
        inherited_typed_stack_probe_fact: TypedStackProbeReturnFact8616 | None,
        allow_setup_assignment_prune: bool,
        depth: int,
    ) -> tuple[bool, bool, TypedStackProbeReturnFact8616 | None]:
        new_statements: list[StructuredAstValue] = []
        i = 0
        typed_stack_probe_fact = inherited_typed_stack_probe_fact or self.function_scope_typed_stack_probe_fact
        stack_probe_seen = inherited_stack_probe_seen or any(
            summary.stack_probe_helper for summary in self.summary_map.values()
        )
        stack_probe_address_seen = inherited_stack_probe_address_seen or (
            typed_stack_probe_fact is not None and typed_stack_probe_fact.segment_space == "ss"
        )
























































































        while i < len(statements):
            stmt = statements[i]
            call, proceed = self._rewrite_stmt_pre_gate_8616(
                stmt, stack_probe_seen=stack_probe_seen, new_statements=new_statements
            )
            if not proceed:
                i += 1
                continue
            facts = self._resolve_call_stmt_facts_8616(call)
            summary = facts.summary
            arg_count = facts.arg_count
            summary_arg_count = facts.summary_arg_count
            stack_cleanup = facts.stack_cleanup
            summary_return_addr = facts.summary_return_addr
            call_name = facts.call_name
            semantic_call_name = facts.semantic_call_name
            prototype_arg_widths = facts.prototype_arg_widths
            known_prototype_arg_widths = facts.known_prototype_arg_widths
            effective_prototype_arg_widths = facts.effective_prototype_arg_widths
            summary_logical_arg_widths = facts.summary_logical_arg_widths
            prototype_arg_count = facts.prototype_arg_count
            known_arg_count = facts.known_arg_count
            is_stack_probe_helper = facts.is_stack_probe_helper
            push_arg_sources = facts.push_arg_sources
            (stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact, probe_consumed) = (
                self._rewrite_probe_helper_stmt_8616(
                    stmt=stmt,
                    call=call,
                    summary=summary,
                    statements=statements,
                    i=i,
                    is_stack_probe_helper=is_stack_probe_helper,
                    stack_probe_seen=stack_probe_seen,
                    stack_probe_address_seen=stack_probe_address_seen,
                    typed_stack_probe_fact=typed_stack_probe_fact,
                )
            )
            if probe_consumed:
                i += 1
                continue











































































































































































































































































































































































































































































































































































































































































































































































































































































            # A typed stack-probe fact is strong evidence for a helper-returned SS
            # address. If no typed fact exists, direct segmented SS stores before the
            # call remain valid evidence and the generic stack-arg backtracker must
            # stay enabled.
            i = self._rematerialize_call_stmt_8616(
                arg_count=arg_count,
                call=call,
                call_name=call_name,
                effective_prototype_arg_widths=effective_prototype_arg_widths,
                i=i,
                is_stack_probe_helper=is_stack_probe_helper,
                known_arg_count=known_arg_count,
                known_prototype_arg_widths=known_prototype_arg_widths,
                new_statements=new_statements,
                prototype_arg_count=prototype_arg_count,
                prototype_arg_widths=prototype_arg_widths,
                push_arg_sources=push_arg_sources,
                semantic_call_name=semantic_call_name,
                stack_cleanup=stack_cleanup,
                stack_probe_address_seen=stack_probe_address_seen,
                stack_probe_seen=stack_probe_seen,
                statements=statements,
                stmt=stmt,
                summary=summary,
                summary_arg_count=summary_arg_count,
                summary_logical_arg_widths=summary_logical_arg_widths,
                summary_return_addr=summary_return_addr,
                typed_stack_probe_fact=typed_stack_probe_fact,
            )
        if self._fold_dx_ax_return_pair_assignments_8616(new_statements):
            self.changed = True
        if os.environ.get("INERTIA_DEBUG_STACK_PROBE_ARTIFACTS"):
            log.warning(
                "[stack-probe-artifacts] final-prune stack_probe_seen=%s stack_probe_address_seen=%s "
                "typed_probe_fact=%r function_scope_fact=%r typed_fact_count=%d unverified_non_ss=%s statements=%d",
                stack_probe_seen,
                stack_probe_address_seen,
                typed_stack_probe_fact,
                self.function_scope_typed_stack_probe_fact,
                len(self.typed_stack_probe_facts),
                self.has_unverified_non_ss_stack_probe,
                len(new_statements),
            )
        for _ in range(4):
            pruned_statements, prune_changed = self._prune_stack_probe_frame_artifacts(
                new_statements,
                stack_probe_seen=stack_probe_seen,
                typed_probe_fact=typed_stack_probe_fact if stack_probe_seen else None,
                allow_setup_assignment_prune=allow_setup_assignment_prune,
            )
            if not prune_changed:
                break
            new_statements = pruned_statements
            self.changed = True
        if self._materialize_final_return_call_8616(new_statements):
            self.changed = True

        if self._statement_sequence_identity_changed_8616(statements, new_statements):
            block.statements = new_statements

        stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact = (
            self._rewrite_child_blocks_8616(
                block,
                stack_probe_seen,
                stack_probe_address_seen,
                typed_stack_probe_fact,
                allow_setup_assignment_prune,
                depth,
            )
        )
        return stack_probe_seen, stack_probe_address_seen, typed_stack_probe_fact

    def _debug_dirty_refuse_8616(self, call: StructuredAstValue, reason: str) -> int:
        """Log and return the refusal count for dirty-setup consumption."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-dirty-setup-consume] refuse function=%#x target=%s reason=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                reason,
            )
        return 0
    def _debug_dirty_stop_8616(
        self,
        call: StructuredAstValue,
        callsite_addr: StructuredAstValue,
        reason: str,
        candidate: StructuredAstValue,
        lhs: StructuredAstValue = None,
        rhs: StructuredAstValue = None,
        ins_addr: StructuredAstValue = None,
    ) -> None:
        """Log a dirty-setup stop decision when debug is enabled."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-dirty-setup-consume] stop function=%#x target=%s reason=%s "
                "ins=%r callsite=%r shape=%s lhs=%s rhs=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                reason,
                ins_addr,
                callsite_addr if isinstance(callsite_addr, int) else None,
                self._debug_node_shape_8616(candidate),
                self._debug_expr_8616(lhs),
                self._debug_expr_8616(rhs),
            )
    def _dirty_setup_candidate_reason_8616(
        self,
        candidate: StructuredAstValue,
        callsite_addr: int,
    ) -> tuple[str, StructuredAstValue, StructuredAstValue, StructuredAstValue, StructuredAstValue] | None:
        """Return (reason, candidate, lhs, rhs, ins_addr) when the candidate cannot be consumed."""
        assignment = self._top_level_assignment_node_8616(candidate)
        if assignment is None:
            return ("not-pure-assignment", candidate, None, None, None)
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            return ("missing-lhs-rhs", candidate, lhs, rhs, None)
        if (self._statement_contains_call(candidate) or self._statement_contains_call(assignment)) and not (
            self._is_runtime_segment_store_lvalue_8616(lhs) and not self._statement_contains_call(rhs)
        ):
            return ("suffix-is-call", candidate, lhs, rhs, None)
        if not self._expr_contains_dirty_carrier_8616(lhs):
            return ("lhs-not-dirty", candidate, lhs, rhs, None)
        ins_addr = self._assignment_ins_addr_8616(assignment)
        if not isinstance(ins_addr, int):
            ins_addr = self._assignment_ins_addr_8616(candidate)
        if not isinstance(ins_addr, int):
            return ("missing-ins-addr", candidate, lhs, rhs, ins_addr)
        setup_gap = callsite_addr - ins_addr
        if not (ins_addr == callsite_addr or 0 < setup_gap <= 16):
            return (f"outside-window:{setup_gap}", candidate, lhs, rhs, ins_addr)
        if not self._rhs_is_safe_to_relocate_after_call_8616(rhs):
            return ("impure-rhs", candidate, lhs, rhs, ins_addr)
        return None
    def _pop_consumed_callsite_dirty_setup_assignments_8616(self,
        call: StructuredAstValue, summary: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...]
   , *, new_statements: StructuredAstValue) -> int:































        if call is None or summary is None or bool(summary.stack_probe_helper):
            return self._debug_dirty_refuse_8616(call, "missing-call-summary-or-stack-probe")
        callsite_addr = summary.callsite_addr
        if not isinstance(callsite_addr, int):
            return self._debug_dirty_refuse_8616(call, "missing-callsite")
        if not isinstance(push_sources, tuple) or not push_sources:
            return self._debug_dirty_refuse_8616(call, "missing-push-sources")
        if not _boundary_tuple_8616(getattr(call, "args", ()) or ()):
            return self._debug_dirty_refuse_8616(call, "missing-materialized-args")

        consumed = 0
        while new_statements and consumed < 8:
            candidate = new_statements[-1]
            refusal = self._dirty_setup_candidate_reason_8616(candidate, callsite_addr)
            if refusal is not None:
                reason, cand, lhs, rhs, ins_addr = refusal
                self._debug_dirty_stop_8616(call, callsite_addr, reason, cand, lhs, rhs, ins_addr)
                break
            new_statements.pop()
            consumed += 1

        if consumed <= 0:
            return self._debug_dirty_refuse_8616(call, "no-consumable-suffix")
        self.codegen._inertia_callsite_dirty_setup_assignments_consumed_8616 = (
            int(getattr(self.codegen, "_inertia_callsite_dirty_setup_assignments_consumed_8616", 0) or 0) + consumed
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-dirty-setup-consume] function=%#x target=%s callsite=%#x count=%d",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                callsite_addr,
                consumed,
            )
        return consumed

    def _push_sources_include_far_pointer_parts_8616(self, push_sources: tuple[StructuredAstValue, ...]) -> bool:

        if not isinstance(push_sources, tuple) or len(push_sources) < 2:
            return False
        has_segment = any(
            isinstance(source, tuple)
            and len(source) >= 2
            and source[0] == CallsitePushSourceKind8616.SEGMENT.value
            for source in push_sources
        )
        return has_segment and any(self._is_far_pointer_offset_source_8616(source) for source in push_sources)

    def _is_scalar_global_high_byte_store_remnant_8616(self,
        stmt: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...], call_node: StructuredAstValue
    ) -> bool:
        def _debug_scalar_refuse(reason: str, *, source_offset: int | None = None) -> bool:
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                assignment = self._top_level_assignment_node_8616(stmt)
                lhs, rhs = self._assignment_lhs_rhs(assignment) if assignment is not None else (None, None)
                log.warning(
                    "[call-scalar-high-byte-remnant] refuse function=%#x target=%s reason=%s "
                    "source=%r push_offsets=%r args=%r shape=%s lhs=%s rhs=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    _call_node_name_8616(call_node),
                    reason,
                    source_offset,
                    tuple(sorted(self._global_word_push_source_offsets_8616(push_sources))),
                    _boundary_tuple_8616(
                        self._debug_expr_8616(arg)
                        for arg in _boundary_tuple_8616(getattr(call_node, "args", ()) or ())
                    ),
                    self._debug_node_shape_8616(stmt),
                    self._debug_expr_8616(lhs),
                    self._debug_expr_8616(rhs),
                )
            return False

        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return _debug_scalar_refuse("not-top-level-assignment")
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        lhs_is_dirty_memory_candidate = lhs is not None and lhs.__class__.__name__ == "CDirtyExpression"
        if (
            lhs is None
            or rhs is None
            or not (self._assignment_lhs_writes_memory(lhs) or lhs_is_dirty_memory_candidate)
        ):
            return _debug_scalar_refuse("lhs-not-memory")
        source_offset = self._global_word_high_byte_source_offset_8616(rhs)
        if source_offset is None:
            return _debug_scalar_refuse("rhs-not-global-high-byte")
        if source_offset not in self._global_word_push_source_offsets_8616(push_sources):
            return _debug_scalar_refuse("source-not-in-push-sources", source_offset=source_offset)
        if not self._call_args_reference_global_word_8616(call_node, source_offset):
            return _debug_scalar_refuse("call-args-missing-source", source_offset=source_offset)
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-scalar-high-byte-remnant] matched function=%#x target=%s source=%#x shape=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call_node),
                source_offset,
                self._debug_node_shape_8616(stmt),
            )
        return True

    def _scalar_global_remnant_step_8616(self,
        candidate: StructuredAstValue,
        scan: int,
        push_sources: tuple[StructuredAstValue, ...],
        call: StructuredAstValue,
        high_byte_store_count: int,
        removable_indices: list[int],
        pending_carrier_indices: list[int],
    ) -> int | None:
        """Record ``scan`` for removal and return the high-byte count delta, or ``None`` to stop."""
        if self._is_scalar_global_high_byte_store_remnant_8616(candidate, push_sources, call):
            removable_indices.append(scan)
            removable_indices.extend(pending_carrier_indices)
            pending_carrier_indices.clear()
            return 1
        if high_byte_store_count > 0 and self._is_scalar_global_low_byte_store_remnant_8616(
            candidate, push_sources, call
        ):
            removable_indices.append(scan)
            removable_indices.extend(pending_carrier_indices)
            pending_carrier_indices.clear()
            return 0
        if self._is_scalar_global_high_byte_carrier_remnant_8616(candidate):
            if high_byte_store_count > 0:
                removable_indices.append(scan)
            else:
                pending_carrier_indices.append(scan)
            return 0
        return None

    def _pop_pre_call_scalar_global_high_byte_remnants_8616(self,
        call: StructuredAstValue, summary: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...]
   , *, new_statements: StructuredAstValue) -> int:
        if call is None or summary is None or bool(summary.stack_probe_helper):
            return 0
        if not _boundary_tuple_8616(getattr(call, "args", ()) or ()):
            return 0
        if not self._global_word_push_source_offsets_8616(push_sources):
            return 0
        if not new_statements:
            return 0

        scan = len(new_statements) - 1
        removable_indices: list[int] = []
        pending_carrier_indices: list[int] = []
        high_byte_store_count = 0
        while scan >= 0 and len(removable_indices) + len(pending_carrier_indices) < 6:
            step = self._scalar_global_remnant_step_8616(
                new_statements[scan], scan, push_sources, call, high_byte_store_count,
                removable_indices, pending_carrier_indices,
            )
            if step is None:
                break
            high_byte_store_count += step
            scan -= 1
        if high_byte_store_count <= 0:
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-scalar-high-byte-remnant] refuse function=%#x target=%s reason=no-match "
                    "push_offsets=%r suffix=%r",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    _call_node_name_8616(call),
                    tuple(sorted(self._global_word_push_source_offsets_8616(push_sources))),
                    tuple(self._debug_node_shape_8616(stmt) for stmt in new_statements[-4:]),
                )
            return 0
        for idx in sorted(removable_indices, reverse=True):
            del new_statements[idx]
        self.codegen._inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616 = int(
            getattr(
                self.codegen,
                "_inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616",
                0,
            )
            or 0
        ) + len(removable_indices)
        return len(removable_indices)

    def _farptr_store_debug_refuse_8616(self,
        call: StructuredAstValue,
        stmt: StructuredAstValue,
        reason: str,
    ) -> str | None:
        """Log a far-pointer byte-store remnant refusal."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            assignment = self._top_level_assignment_node_8616(stmt)
            lhs, rhs = self._assignment_lhs_rhs(assignment) if assignment is not None else (None, None)
            log.warning(
                "[call-farptr-high-byte-remnant] store-refuse function=%#x target=%s reason=%s shape=%s lhs=%s rhs=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                reason,
                self._debug_node_shape_8616(stmt),
                self._debug_expr_8616(lhs),
                self._debug_expr_8616(rhs),
            )
        return None

    def _far_pointer_byte_store_remnant_kind_8616(self,
        stmt: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...]
   , *, call: StructuredAstValue) -> str | None:
        if not self._push_sources_include_far_pointer_parts_8616(push_sources):
            return self._farptr_store_debug_refuse_8616(call, stmt, "missing-far-pointer-sources-or-call")
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return self._farptr_store_debug_refuse_8616(call, stmt, "missing-assignment")
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        lhs_is_dirty_memory_candidate = lhs is not None and lhs.__class__.__name__ == "CDirtyExpression"
        if (
            lhs is None
            or rhs is None
            or not (self._assignment_lhs_writes_memory(lhs) or lhs_is_dirty_memory_candidate)
        ):
            return self._farptr_store_debug_refuse_8616(call, stmt, "lhs-rhs-or-memory")
        if not (lhs_is_dirty_memory_candidate or self._lhs_is_far_pointer_outgoing_byte_store_8616(lhs)):
            return self._farptr_store_debug_refuse_8616(call, stmt, "lhs-not-outgoing-byte-store")
        node = rhs
        while isinstance(node, CTypeCast):
            node = node.expr
        shift_value = getattr(getattr(node, "rhs", None), "value", None)
        if isinstance(node, CBinaryOp) and node.op == "Shr" and shift_value == 8:
            source = node.lhs
            byte_kind = "high"
        else:
            source = node
            byte_kind = "low"
        while isinstance(source, CTypeCast):
            source = source.expr
        if not self._is_far_pointer_byte_store_source_8616(source):
            return self._farptr_store_debug_refuse_8616(call, stmt, "unsafe-source")
        return byte_kind

    def _is_far_pointer_high_byte_store_remnant_8616(self,
        stmt: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...]
   , *, call: StructuredAstValue) -> bool:
        return self._far_pointer_byte_store_remnant_kind_8616(stmt, push_sources, call=call) == "high"

    def _is_far_pointer_low_byte_store_remnant_8616(self,
        stmt: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...]
   , *, call: StructuredAstValue) -> bool:
        return self._far_pointer_byte_store_remnant_kind_8616(stmt, push_sources, call=call) == "low"

    def _is_far_pointer_passthrough_suffix_assignment_8616(self, stmt: StructuredAstValue, *, call: StructuredAstValue) -> bool:
        def _debug_passthrough_refuse(reason: str) -> bool:
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                assignment = self._top_level_assignment_node_8616(stmt)
                lhs, rhs = self._assignment_lhs_rhs(assignment) if assignment is not None else (None, None)
                log.warning(
                    "[call-farptr-high-byte-remnant] passthrough-refuse function=%#x target=%s reason=%s shape=%s lhs=%s rhs=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    _call_node_name_8616(call),
                    reason,
                    self._debug_node_shape_8616(stmt),
                    self._debug_expr_8616(lhs),
                    self._debug_expr_8616(rhs),
                )
            return False

        if self._statement_contains_call(stmt):
            return _debug_passthrough_refuse("contains-call")
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return _debug_passthrough_refuse("missing-assignment")
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            return _debug_passthrough_refuse("missing-lhs-rhs")
        lhs_is_stack_slot = self._stack_variable_offset_8616(lhs) is not None
        if lhs.__class__.__name__ == "CDirtyExpression":
            return _debug_passthrough_refuse("dirty-lhs")
        if self._assignment_lhs_writes_memory(lhs) and not lhs_is_stack_slot:
            return _debug_passthrough_refuse("non-stack-memory-lhs")
        if not self._rhs_is_safe_push_alias_artifact_8616(rhs):
            return _debug_passthrough_refuse("unsafe-rhs")
        return True

    def _pop_pre_call_far_pointer_high_byte_remnants_8616(self,
        call: StructuredAstValue, summary: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...]
   , *, new_statements: StructuredAstValue) -> int:
        def _debug_farptr_refuse(reason: str) -> int:
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-farptr-high-byte-remnant] refuse function=%#x target=%s reason=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    _call_node_name_8616(call),
                    reason,
                )
            return 0

        if call is None or summary is None or bool(summary.stack_probe_helper):
            return _debug_farptr_refuse("missing-call-summary-or-stack-probe")
        if not _boundary_tuple_8616(getattr(call, "args", ()) or ()):
            return _debug_farptr_refuse("missing-materialized-args")
        if not self._push_sources_include_far_pointer_parts_8616(push_sources):
            return _debug_farptr_refuse("missing-far-pointer-push-sources")
        if not new_statements:
            return _debug_farptr_refuse("missing-predecessor")

        removable_indices, high_byte_store_count, passthrough_count = (
            self._scan_farptr_high_byte_remnants_8616(new_statements, push_sources, call)
        )
        if high_byte_store_count < 2:
            return _debug_farptr_refuse(
                f"missing-high-byte-pair:stores={high_byte_store_count}:passthrough={passthrough_count}"
            )
        for idx in sorted(removable_indices, reverse=True):
            del new_statements[idx]
        self.codegen._inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616 = int(
            getattr(self.codegen, "_inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616", 0) or 0
        ) + len(removable_indices)
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-farptr-high-byte-remnant] pruned function=%#x target=%s statements=%d stores=%d",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                len(removable_indices),
                high_byte_store_count,
            )
        return len(removable_indices)

    def _non_exact_push_candidate_ok_8616(self,
        lhs: StructuredAstValue,
        lhs_offset: int,
        source_offsets: set[int],
        call: StructuredAstValue,
    ) -> bool:
        """Gate a non-exact-push candidate: lhs must be a push-source call arg."""
        if lhs_offset not in source_offsets:
            return False
        lhs_key = self._c_variable_identity_key_8616(lhs)
        return self._call_args_reference_identity_8616(call, lhs_key)

    def _pre_call_alias_artifact_candidate_ok_8616(
        self,
        candidate: StructuredAstValue,
        call: StructuredAstValue,
        push_sources: StructuredAstValue,
        source_offsets: StructuredAstValue,
        expr_sources: StructuredAstValue,
        push_instruction_addrs: frozenset,
    ) -> bool:
        """Whether a trailing statement is a consumable pre-call push-alias artifact."""
        if self._statement_contains_call(candidate):
            return False
        assignment = self._top_level_assignment_node_8616(candidate)
        if assignment is None or self._statement_contains_call(assignment):
            return False
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            return False
        lhs_offset = self._stack_variable_offset_8616(lhs)
        if not isinstance(lhs_offset, int):
            return False
        ins_addr = self._assignment_ins_addr_8616(assignment)
        if not isinstance(ins_addr, int):
            ins_addr = self._assignment_ins_addr_8616(candidate)
        if not isinstance(ins_addr, int):
            return False
        exact_push_instruction = ins_addr in push_instruction_addrs and any(
            _direct_bp_push_instruction_matches_source_8616(self.project, ins_addr, source)
            for source in push_sources
        )
        matching_sources = _expr_push_sources_for_bp_offset_8616(push_sources, lhs_offset)
        matching_sources = tuple(dict.fromkeys((*matching_sources, *expr_sources)))
        if not exact_push_instruction and not self._non_exact_push_candidate_ok_8616(
            lhs, lhs_offset, source_offsets, call
        ):
            return False
        expression_setup_instruction = any(
            _reg_expr_setup_matches_push_source_8616(self.project, ins_addr, source)
            for source in matching_sources
        )
        if not exact_push_instruction and not expression_setup_instruction:
            return False
        return (
            self._rhs_is_safe_push_alias_artifact_8616(rhs)
            or self._rhs_is_byte_proven_dirty_push_alias_artifact_8616(rhs)
            or (exact_push_instruction and self._rhs_is_exact_push_register_alias_artifact_8616(rhs))
        )

    def _scan_farptr_high_byte_remnants_8616(self,
        new_statements: list[StructuredAstValue],
        push_sources: StructuredAstValue,
        call: StructuredAstValue,
    ) -> tuple[list[int], int, int]:
        removable_indices: list[int] = []
        high_byte_store_count = 0
        passthrough_count = 0
        scan = len(new_statements) - 1
        while scan >= 0 and len(removable_indices) < 24 and passthrough_count <= 6:
            candidate = new_statements[scan]
            if self._is_far_pointer_high_byte_store_remnant_8616(candidate, push_sources, call=call):
                removable_indices.append(scan)
                high_byte_store_count += 1
                scan -= 1
                continue
            if high_byte_store_count > 0 and self._is_far_pointer_low_byte_store_remnant_8616(
                candidate, push_sources, call=call
            ):
                removable_indices.append(scan)
                scan -= 1
                continue
            if high_byte_store_count > 0 and self._is_far_pointer_carrier_remnant_8616(candidate):
                removable_indices.append(scan)
                scan -= 1
                continue
            if self._is_far_pointer_passthrough_suffix_assignment_8616(candidate, call=call):
                passthrough_count += 1
                scan -= 1
                continue
            break
        return (removable_indices, high_byte_store_count, passthrough_count)

    def _alias_artifact_debug_8616(self,
        call: StructuredAstValue,
        decision: CallsiteAliasArtifactDecision8616,
        reason: str,
    ) -> int:
        """Log an alias-artifact decision and count refusals; returns zero artifacts."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-source-alias-artifact] function=%#x target=%s decision=%s reason=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                decision.value,
                reason,
            )
        if decision is CallsiteAliasArtifactDecision8616.KEEP_NO_BINARY_PUSH_EXPR_EVIDENCE:
            self.codegen._inertia_callsite_pre_call_source_alias_artifacts_refused_8616 = (
                int(getattr(self.codegen, "_inertia_callsite_pre_call_source_alias_artifacts_refused_8616", 0) or 0) + 1
            )
        return 0

    def _pop_pre_call_source_alias_artifacts_8616(self,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        push_sources: tuple[StructuredAstValue, ...],
        *,
        new_statements: list[StructuredAstValue],
    ) -> int:
        """Pop proven pre-call push-alias artifact statements; returns count removed."""
        if call is None or summary is None or bool(summary.stack_probe_helper):
            return self._alias_artifact_debug_8616(call, CallsiteAliasArtifactDecision8616.KEEP_NO_BINARY_PUSH_EXPR_EVIDENCE, "missing-call-summary-or-stack-probe")
        if not isinstance(push_sources, tuple) or not push_sources:
            return self._alias_artifact_debug_8616(call, CallsiteAliasArtifactDecision8616.KEEP_NO_BINARY_PUSH_EXPR_EVIDENCE, "missing-push-sources")
        if not _boundary_tuple_8616(getattr(call, "args", ()) or ()):
            return self._alias_artifact_debug_8616(call, CallsiteAliasArtifactDecision8616.KEEP_NO_BINARY_PUSH_EXPR_EVIDENCE, "missing-materialized-args")

        source_offsets = set().union(*(_bp_offsets_from_push_source_8616(source) for source in push_sources))
        expr_sources = _expr_push_sources_8616(push_sources)
        push_instruction_addrs = frozenset(
            address
            for address in _boundary_tuple_8616(summary.push_arg_instruction_addrs or ())
            if isinstance(address, int)
        )
        if not push_instruction_addrs and (not source_offsets or not expr_sources):
            return self._alias_artifact_debug_8616(call, CallsiteAliasArtifactDecision8616.KEEP_NO_BINARY_PUSH_EXPR_EVIDENCE, "missing-source-offsets-or-push-instruction-evidence")

        consumed = 0
        while new_statements and consumed < 4:
            candidate = new_statements[-1]
            if not self._pre_call_alias_artifact_candidate_ok_8616(
                candidate,
                call,
                push_sources,
                source_offsets,
                expr_sources,
                push_instruction_addrs,
            ):
                break
            new_statements.pop()
            consumed += 1

        if consumed <= 0:
            return self._alias_artifact_debug_8616(call, CallsiteAliasArtifactDecision8616.KEEP_NO_BINARY_PUSH_EXPR_EVIDENCE, "no-proven-suffix")
        self.codegen._inertia_callsite_pre_call_source_alias_artifacts_pruned_8616 = (
            int(getattr(self.codegen, "_inertia_callsite_pre_call_source_alias_artifacts_pruned_8616", 0) or 0)
            + consumed
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-source-alias-artifact] function=%#x target=%s decision=%s count=%d",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                CallsiteAliasArtifactDecision8616.PRUNE_BINARY_PUSH_EXPR_ALIAS.value,
                consumed,
            )
        return consumed

    def _debug_clobber_refuse_8616(self, call: StructuredAstValue, reason: str) -> bool:
        """Log a clobber-gate refusal for ``call`` and return the keep verdict."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-pre-source-clobber] refuse function=%#x target=%s reason=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                reason,
            )
        return False

    def _clobber_rhs_keys_match_8616(self,
        pre_rhs_key: StructuredAstValue,
        post_rhs_key: StructuredAstValue,
        pre_rhs: StructuredAstValue,
        post_rhs: StructuredAstValue,
    ) -> bool:
        if pre_rhs_key is not None and post_rhs_key is not None:
            return pre_rhs_key == post_rhs_key
        return _same_c_expression_8616(pre_rhs, post_rhs)

    def _clobber_copy_key_verdict_8616(self,
        pre_stmt: StructuredAstValue,
        post_stmt: StructuredAstValue,
        source_offsets: set[int],
        call: StructuredAstValue,
    ) -> tuple[str | None, StructuredAstValue]:
        """Compare the pre-call and post-call copy keys for a clobber candidate."""
        pre_key = self._assignment_semantic_copy_key_8616(pre_stmt)
        post_key = self._assignment_semantic_copy_key_8616(post_stmt)
        if pre_key is None or post_key is None:
            return ("missing-copy-key", None)
        pre_lhs_key, pre_rhs_key, pre_lhs, pre_rhs = pre_key
        post_lhs_key, post_rhs_key, _post_lhs, post_rhs = post_key
        lhs_offset = self._stack_variable_offset_8616(pre_lhs)
        if lhs_offset not in source_offsets:
            return (f"lhs-not-push-source:{lhs_offset!r}", lhs_offset)
        if pre_lhs_key != post_lhs_key:
            return ("lhs-copy-mismatch", lhs_offset)
        if not self._clobber_rhs_keys_match_8616(pre_rhs_key, post_rhs_key, pre_rhs, post_rhs):
            return ("rhs-copy-mismatch", lhs_offset)
        if not self._call_args_reference_identity_8616(call, pre_lhs_key):
            return ("lhs-not-call-arg", lhs_offset)
        return (None, lhs_offset)

    def _clobber_candidate_gate_8616(self,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        push_sources: tuple[StructuredAstValue, ...],
        new_statements: list[StructuredAstValue],
        statements: list[StructuredAstValue],
        i: int,
    ) -> tuple[str | None, StructuredAstValue]:
        if call is None or summary is None or bool(summary.stack_probe_helper):
            return ("missing-call-summary-or-stack-probe", None)
        if not isinstance(push_sources, tuple) or not push_sources:
            return ("missing-push-sources", None)
        source_offsets = set().union(*(_bp_offsets_from_push_source_8616(source) for source in push_sources))
        if not source_offsets:
            return ("missing-bp-source-offsets", None)
        if not new_statements:
            return ("missing-predecessor", None)
        if i + 1 >= len(statements):
            return ("missing-post-call-copy", None)

        return self._clobber_copy_key_verdict_8616(
            new_statements[-1], statements[i + 1], source_offsets, call
        )

    def _pop_duplicate_pre_call_stack_source_clobber_8616(self,
        call: StructuredAstValue, summary: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...],
        *,
        i: int,
        new_statements: list[StructuredAstValue],
        statements: list[StructuredAstValue],
    ) -> bool:
        """Pop a duplicate pre-call stack-source clobber when the gate accepts it."""

        gate_reason, lhs_offset = self._clobber_candidate_gate_8616(
            call, summary, push_sources, new_statements, statements, i
        )
        if gate_reason is not None:
            return self._debug_clobber_refuse_8616(call, gate_reason)

        new_statements.pop()
        self.codegen._inertia_callsite_pre_call_source_clobbers_pruned_8616 = (
            int(getattr(self.codegen, "_inertia_callsite_pre_call_source_clobbers_pruned_8616", 0) or 0) + 1
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-pre-source-clobber] pruned function=%#x target=%s lhs_offset=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                lhs_offset,
            )
        return True

    def _resync_consumed_push_stores_8616(
        self,
        new_statements: list[StructuredAstValue],
        non_segment_push_count: int,
        physical_push_count: int,
        *,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
    ) -> tuple[list[StructuredAstValue], list[int]]:
        """Recollect consumed stores when segment pushes skew the count."""
        consumed_rhs, consumed_indices = self._collect_backtracked_stack_args(
            new_statements,
            wanted_count=non_segment_push_count,
            typed_probe_fact=typed_probe_fact,
        )
        if len(consumed_rhs) != non_segment_push_count:
            consumed_rhs, consumed_indices = self._collect_backtracked_runtime_stack_store_args_8616(
                wanted_count=non_segment_push_count
           , new_statements=new_statements)
        if len(consumed_rhs) != non_segment_push_count:
            consumed_rhs, consumed_indices = self._scan_consumable_push_store_tail_8616(
                new_statements,
                non_segment_push_count,
                physical_push_count,
                consumed_rhs,
                consumed_indices,
            )
        return consumed_rhs, consumed_indices

    def _scan_consumable_push_store_tail_8616(
        self,
        new_statements: list[StructuredAstValue],
        non_segment_push_count: int,
        physical_push_count: int,
        consumed_rhs: list[StructuredAstValue],
        consumed_indices: list[int],
    ) -> tuple[list[StructuredAstValue], list[int]]:
        """Back-scan consumable non-segment store indices as a last resort."""
        cleanup_indices: list[int] = []
        non_segment_seen = 0
        scan_idx = len(new_statements) - 1
        while scan_idx >= 0 and len(cleanup_indices) < physical_push_count:
            candidate = new_statements[scan_idx]
            if self._statement_contains_call(candidate):
                break
            rhs = self._stack_store_rhs_from_statement(candidate)
            if rhs is not None and not self._is_segment_register_value_expr(rhs):
                cleanup_indices.append(scan_idx)
                non_segment_seen += 1
                scan_idx -= 1
                continue
            assignment = self._top_level_assignment_node_8616(candidate)
            if assignment is not None:
                lhs, segment_rhs = self._assignment_lhs_rhs(assignment)
                segment_name, _offset_terms = _match_real_mode_segmented_store_shape_8616(
                    lhs,
                    self.project,
                )
                if segment_name == "ss" and self._segment_register_name_from_expr_8616(segment_rhs):
                    cleanup_indices.append(scan_idx)
                    scan_idx -= 1
                    continue
            if self._is_stack_carrier_temp_assignment(candidate) or self._is_segment_register_metadata_store(
                candidate
            ):
                cleanup_indices.append(scan_idx)
                scan_idx -= 1
                continue
            break
        if non_segment_seen == non_segment_push_count and cleanup_indices:
            return [object()] * non_segment_push_count, sorted(set(cleanup_indices))
        return consumed_rhs, consumed_indices

    def _resync_partial_push_stores_8616(
        self,
        new_statements: list[StructuredAstValue],
        push_sources: tuple[StructuredAstValue, ...],
        physical_push_count: int,
        typed_probe_fact: StructuredAstValue,
        consumed_rhs: list[StructuredAstValue],
        consumed_indices: list[int],
    ) -> tuple[list[StructuredAstValue], list[int]]:
        """Resync consumed stores when a segment source is folded into the count."""
        non_segment_push_count = sum(
            1
            for source in push_sources
            if not (
                isinstance(source, tuple)
                and len(source) >= 1
                and source[0] == CallsitePushSourceKind8616.SEGMENT.value
            )
        )
        if 0 < non_segment_push_count < physical_push_count:
            consumed_rhs, consumed_indices = self._resync_consumed_push_stores_8616(
                new_statements,
                non_segment_push_count,
                physical_push_count,
                typed_probe_fact=typed_probe_fact,
            )
            if len(consumed_rhs) != non_segment_push_count:
                consumed_rhs, consumed_indices = self._scan_consumable_push_store_tail_8616(
                    new_statements,
                    non_segment_push_count,
                    physical_push_count,
                    consumed_rhs,
                    consumed_indices,
                )
            cleanup_index_set = set(consumed_indices)
            scan_idx = min(consumed_indices, default=len(new_statements)) + 1
            while scan_idx < len(new_statements):
                candidate = new_statements[scan_idx]
                if self._is_segment_register_metadata_store(candidate) or self._is_stack_carrier_temp_assignment(
                    candidate
                ):
                    cleanup_index_set.add(scan_idx)
                    scan_idx += 1
                    continue
                break
            consumed_indices = sorted(cleanup_index_set)
        return consumed_rhs, consumed_indices
    def _direct_push_store_evidence_map_8616(
        self,
        call: StructuredAstValue,
        consumed_rhs: list[StructuredAstValue],
        consumed_indices: list[int],
        physical_push_count: int,
        push_sources: tuple[StructuredAstValue, ...],
        new_statements: list[StructuredAstValue],
    ) -> dict | None:
        """Verify every consumed store matches a recorded PUSH; return source map or None."""
        if (
            len(consumed_rhs) > physical_push_count
            or len(consumed_indices) < physical_push_count
            or not consumed_indices
        ):
            return None
        # A matching store count is not consumption evidence. Require
        # every removed store to belong to an exact recorded PUSH and
        # carry its recorded value; unknown/conflicting stores survive.
        call_summary = self.summary_map.get(id(call))
        push_addresses = call_summary.push_arg_instruction_addrs if call_summary is not None else ()
        if len(push_addresses) != physical_push_count or len(set(push_addresses)) != physical_push_count:
            return None
        sources_by_instruction = dict(zip(push_addresses, push_sources, strict=True))
        for consumed_index in consumed_indices:
            candidate = self._top_level_assignment_node_8616(new_statements[consumed_index])
            if candidate is None:
                return None
            instruction = self._assignment_ins_addr_8616(candidate)
            if instruction is None:
                return None
            source = sources_by_instruction.get(instruction)
            if not self._expr_matches_push_source_value_8616(candidate.rhs, source):
                return None
            return sources_by_instruction
    def _prune_consumed_direct_push_source_stores_8616(self,
        call: StructuredAstValue,
        push_sources: tuple[StructuredAstValue, ...],
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
    *, i: StructuredAstValue,new_statements: StructuredAstValue,statements: StructuredAstValue) -> int:
        """Consume only stores matching recorded PUSH identities and values."""
        if not self.prune_consumed_arg_stores:
            return 0
        if call is None or not _boundary_tuple_8616(getattr(call, "args", ()) or ()):
            return 0
        physical_push_count = len(push_sources) if isinstance(push_sources, tuple) else 0
        if physical_push_count <= 0:
            return 0
        consumed_rhs, consumed_indices = self._collect_backtracked_stack_args(
            new_statements,
            wanted_count=physical_push_count,
            typed_probe_fact=typed_probe_fact,
        )
        if len(consumed_rhs) != physical_push_count:
            consumed_rhs, consumed_indices = self._collect_backtracked_runtime_stack_store_args_8616(
                wanted_count=physical_push_count
           , new_statements=new_statements)
        if len(consumed_rhs) != physical_push_count and isinstance(push_sources, tuple):
            consumed_rhs, consumed_indices = self._resync_partial_push_stores_8616(
                new_statements, push_sources, physical_push_count,
                typed_probe_fact, consumed_rhs, consumed_indices,
            )
        sources_by_instruction = self._direct_push_store_evidence_map_8616(
            call, consumed_rhs, consumed_indices, physical_push_count,
            push_sources, new_statements,
        )
        if sources_by_instruction is None:
            return 0
        cleanup_indices = sorted(
            set(consumed_indices) | set(self._consumed_stack_store_carrier_indices_8616(consumed_indices, new_statements=new_statements))
        )
        self._record_prunable_segment_metadata_ids(
            call,
            new_statements,
            cleanup_indices,
        )
        self._delete_consumed_indices_8616(
            new_statements,
            cleanup_indices,
            live_consumers=(call, *statements[i + 1 :]),
        )
        self.codegen._inertia_callsite_direct_push_source_stores_pruned_8616 = int(
            getattr(self.codegen, "_inertia_callsite_direct_push_source_stores_pruned_8616", 0) or 0
        ) + len(cleanup_indices)
        return len(cleanup_indices)

    def _dedup_summaryless_call_stmt_8616(self,
        materialized_stmt: StructuredAstValue,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        new_statements: list[StructuredAstValue],
        is_stack_probe_helper: bool,
    ) -> bool:
        """Drop one of two identical standalone calls, keeping the summarized one."""
        if call is None or is_stack_probe_helper:
            return False
        materialized_call = self._call_from_statement(materialized_stmt)
        if materialized_call is not call or not self._is_standalone_call_statement_8616(materialized_stmt, call):
            return False
        current_has_summary = summary is not None
        for existing_idx in range(len(new_statements) - 1, -1, -1):
            existing_stmt = new_statements[existing_idx]
            existing_call = self._call_from_statement(existing_stmt)
            if existing_call is None or not self._is_standalone_call_statement_8616(
                existing_stmt,
                existing_call,
            ):
                continue
            if not self._calls_match_8616(existing_call, call):
                continue
            existing_has_summary = self.summary_map.get(id(existing_call)) is not None
            if current_has_summary and not existing_has_summary:
                del new_statements[existing_idx]
                self.codegen._inertia_summaryless_duplicate_call_pruned_8616 = (
                    int(getattr(self.codegen, "_inertia_summaryless_duplicate_call_pruned_8616", 0) or 0) + 1
                )
                self.changed = True
                continue
            if existing_has_summary and not current_has_summary:
                self.codegen._inertia_summaryless_duplicate_call_pruned_8616 = (
                    int(getattr(self.codegen, "_inertia_summaryless_duplicate_call_pruned_8616", 0) or 0) + 1
                )
                self.changed = True
                return True
        return False

    def _append_call_statement_with_relocated_writes_8616(self, *, call: StructuredAstValue,i: StructuredAstValue,is_stack_probe_helper: StructuredAstValue,new_statements: StructuredAstValue,push_arg_sources: StructuredAstValue,stack_probe_seen: StructuredAstValue,statements: StructuredAstValue,stmt: StructuredAstValue,summary: StructuredAstValue,typed_stack_probe_fact: StructuredAstValue) -> None:
        consumed_dirty_setup = (
            self._pop_consumed_callsite_dirty_setup_assignments_8616(call, summary, push_arg_sources, new_statements=new_statements)
            if call is not None and not is_stack_probe_helper
            else 0
        )
        source_alias_artifacts = (
            self._pop_pre_call_source_alias_artifacts_8616(call, summary, push_arg_sources, new_statements=new_statements)
            if call is not None and not is_stack_probe_helper
            else 0
        )
        scalar_high_byte_remnants = (
            self._pop_pre_call_scalar_global_high_byte_remnants_8616(call, summary, push_arg_sources, new_statements=new_statements)
            if call is not None and not is_stack_probe_helper and not source_alias_artifacts
            else 0
        )
        farptr_high_byte_remnants = (
            self._pop_pre_call_far_pointer_high_byte_remnants_8616(call, summary, push_arg_sources, new_statements=new_statements)
            if (
                call is not None
                and not is_stack_probe_helper
                and not source_alias_artifacts
                and not scalar_high_byte_remnants
            )
            else 0
        )
        pre_clobber_removed = (
            self._pop_duplicate_pre_call_stack_source_clobber_8616(call, summary, push_arg_sources, i=i, new_statements=new_statements, statements=statements)
            if (
                call is not None
                and not is_stack_probe_helper
                and not source_alias_artifacts
                and not scalar_high_byte_remnants
                and not farptr_high_byte_remnants
            )
            else False
        )
        direct_push_source_stores_pruned = (
            self._prune_consumed_direct_push_source_stores_8616(
                call,
                push_arg_sources,
                typed_stack_probe_fact if stack_probe_seen else None, i=i, new_statements=new_statements, statements=statements,
            )
            if (
                call is not None
                and not is_stack_probe_helper
                and not source_alias_artifacts
                and not scalar_high_byte_remnants
                and not farptr_high_byte_remnants
                and not pre_clobber_removed
            )
            else 0
        )
        relocated_after_call = (
            []
            if (
                pre_clobber_removed
                or source_alias_artifacts
                or scalar_high_byte_remnants
                or farptr_high_byte_remnants
                or direct_push_source_stores_pruned
            )
            else self._pop_post_call_stack_source_writes_8616(call, summary, push_arg_sources, new_statements=new_statements)
            if call is not None and not is_stack_probe_helper
            else []
        )
        self._record_materialized_return_call_expr_8616(call, summary)
        following_statements = statements[i + 1 : i + 6]
        materialized_stmt = self._call_return_selector_assignment_statement_8616(
            stmt,
            call,
            summary,
            following_statements,
        )
        if self._dedup_summaryless_call_stmt_8616(
            materialized_stmt, call, summary, new_statements, is_stack_probe_helper
        ):
            return
        new_statements.append(materialized_stmt)
        if (
            _setup_cleanup_changed_8616(consumed_dirty_setup, source_alias_artifacts, scalar_high_byte_remnants, farptr_high_byte_remnants, pre_clobber_removed, direct_push_source_stores_pruned, materialized_stmt, stmt)
        ):
            self.changed = True
        if relocated_after_call:
            new_statements.extend(relocated_after_call)
            self.changed = True

    def _post_call_relocate_gate_8616(
        self,
        candidate: StructuredAstValue,
        callsite_addr: int,
        source_offsets: StructuredAstValue,
    ) -> tuple[str | None, str]:
        """Return (refusal_reason, debug_shape) for one trailing post-call statement."""
        last_debug_shape = ""
        last_debug_shape = (
            f"shape={self._debug_node_shape_8616(candidate)} tags={getattr(candidate, 'tags', None)!r}"
        )
        if self._statement_contains_call(candidate):
            return "suffix-is-call", last_debug_shape
        assignment = self._top_level_assignment_node_8616(candidate)
        if assignment is None or self._statement_contains_call(assignment):
            return "suffix-not-pure-assignment", last_debug_shape
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        last_debug_shape = (
            f"shape={self._debug_node_shape_8616(candidate)} "
            f"assign_shape={self._debug_node_shape_8616(assignment)} "
            f"lhs={self._debug_expr_8616(lhs)} rhs={self._debug_expr_8616(rhs)} "
            f"tags={getattr(assignment, 'tags', None)!r}/{getattr(candidate, 'tags', None)!r}"
        )
        if lhs is None or rhs is None:
            return "suffix-missing-lhs-rhs", last_debug_shape
        lhs_offset = self._stack_variable_offset_8616(lhs)
        if lhs_offset is None and self._assignment_lhs_writes_memory(lhs):
            return "suffix-memory-lhs", last_debug_shape
        if lhs_offset not in source_offsets:
            return f"suffix-lhs-offset:{lhs_offset!r}", last_debug_shape
        ins_addr = self._assignment_ins_addr_8616(assignment)
        if not isinstance(ins_addr, int):
            ins_addr = self._assignment_ins_addr_8616(candidate)
        if not isinstance(ins_addr, int) or ins_addr <= callsite_addr:
            return f"suffix-ins-order:{ins_addr!r}<={callsite_addr!r}", last_debug_shape
        if not self._rhs_is_safe_to_relocate_after_call_8616(rhs):
            return "suffix-impure-rhs", last_debug_shape
        return None, last_debug_shape
    def _post_write_relocate_refuse_8616(self, call: StructuredAstValue, reason: str) -> list[StructuredAstValue]:
        """Log a post-call write-relocation refusal and return the empty relocation."""
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-post-write-relocate] refuse function=%#x target=%s reason=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                reason,
            )
        return []

    def _pop_post_call_stack_source_writes_8616(self,
        call: StructuredAstValue, summary: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...]
   , *, new_statements: StructuredAstValue) -> list[StructuredAstValue]:
        if call is None or summary is None or bool(summary.stack_probe_helper):
            return self._post_write_relocate_refuse_8616(call, "missing-call-summary-or-stack-probe")
        callsite_addr = summary.callsite_addr
        if not isinstance(callsite_addr, int):
            return self._post_write_relocate_refuse_8616(call, "missing-callsite")
        source_offsets = set().union(*(_bp_offsets_from_push_source_8616(source) for source in push_sources))
        if not source_offsets:
            return self._post_write_relocate_refuse_8616(call, "missing-bp-source-offsets")

        relocated_reversed: list[StructuredAstValue] = []
        last_refusal = "no-suffix"
        last_debug_shape = ""
        while new_statements:
            candidate = new_statements[-1]
            last_refusal, last_debug_shape = self._post_call_relocate_gate_8616(
                candidate, callsite_addr, source_offsets
            )
            if last_refusal is not None:
                break
            relocated_reversed.append(new_statements.pop())

        if not relocated_reversed:
            detail = f"no-relocatable-suffix:{last_refusal}"
            if last_debug_shape:
                detail = f"{detail} {last_debug_shape}"
            return self._post_write_relocate_refuse_8616(call, detail)
        relocated = list(reversed(relocated_reversed))
        self.codegen._inertia_callsite_post_call_stack_source_writes_relocated_8616 = int(
            getattr(self.codegen, "_inertia_callsite_post_call_stack_source_writes_relocated_8616", 0) or 0
        ) + len(relocated)
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-post-write-relocate] function=%#x target=%s callsite=%#x count=%d offsets=%r",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                callsite_addr,
                len(relocated),
                tuple(sorted(source_offsets)),
            )
        return relocated





    def _is_far_pointer_carrier_remnant_8616(self, stmt: StructuredAstValue) -> bool:

        if self._statement_contains_call(stmt):
            return False
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return False
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None or self._assignment_lhs_writes_memory(lhs):
            return False
        if lhs.__class__.__name__ != "CDirtyExpression" and _stack_carrier_key_8616(lhs) is None:
            return False
        return self._rhs_is_safe_far_pointer_carrier_artifact_8616(rhs)



    def _global_byte_expr_offset_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, structured_c.CVariable):
            variable = node.variable
            addr = getattr(variable, "addr", None)
            if isinstance(variable, SimMemoryVariable) and isinstance(addr, int):
                return addr & 0xFFFF
        return None



    def make_assignment(self, offset: int, symbol: StructuredAstValue) -> StructuredAstValue:
        lhs = self._stack_cvar_for_offset(offset, allow_best_match=False)
        if lhs is None:
            lhs = self._stack_cvar_for_offset(offset, allow_best_match=True)
        if lhs is None:
            return None
        self._set_stack_slot_type_8616(offset, getattr(symbol, "variable_type", None))
        return structured_c.CAssignment(self._clone_c_ast_tree(lhs), self._clone_c_ast_tree(symbol), codegen=self.codegen)



    def _is_stack_address_index_arg_expr_8616(self, expr: StructuredAstValue) -> bool:
        node = self._strip_arg_casts(expr)
        if not isinstance(node, CBinaryOp) or getattr(node, "op", None) not in {"Add", "Sub"}:
            return False
        lhs = self._strip_arg_casts(getattr(node, "lhs", None))
        rhs = self._strip_arg_casts(getattr(node, "rhs", None))
        return (self._is_stack_address_arg_expr_8616(lhs) and self._is_index_register_expr_8616(rhs)) or (
            getattr(node, "op", None) == "Add"
            and self._is_index_register_expr_8616(lhs)
            and self._is_stack_address_arg_expr_8616(rhs)
        )



    def _is_proven_byte_value_source(self, node: StructuredAstValue) -> bool:
        node = self._strip_arg_casts(node)
        if isinstance(node, CFunctionCall) and getattr(node, "callee_target", None) == "SEG_U8":
            return True
        if self._arg_width_from_expr(node) == 1:
            return True
        access = match_stable_ds_es_linear_global_access_8616(node, self.project, self.codegen)
        if access is None:
            return False
        width = getattr(access, "width", None)
        if width == 1:
            return True
        # The exact `Or(And(stale_word, 0xff00), deref)` shape is produced
        # when a byte load into the low half of a word carrier lost its
        # width annotation. Structured C defaults untyped dereferences to a
        # word, so the stable real-mode dereference proof is the evidence;
        # this helper is only called after the stale-high-byte shape matched.
        return isinstance(node, CUnaryOp) and node.op == "Dereference"



    def _resolved_stack_index_arg_base_from_evidence_8616(self,
        expr: StructuredAstValue, source: StructuredAstValue
    ) -> int | None:
        if not (
            isinstance(source, tuple)
            and len(source) >= 5
            and source[0] == "bp_index_addr"
            and isinstance(source[1], int)
            and isinstance(source[4], tuple)
        ):
            return None
        if self._expr_contains_plain_register_uses(expr) or self._node_contains_placeholder_stack_8616(expr):
            return None
        node = self._strip_arg_casts(expr)
        if not isinstance(node, CBinaryOp) or getattr(node, "op", None) not in {"Add", "Sub"}:
            return None
        lhs = self._strip_arg_casts(getattr(node, "lhs", None))
        rhs = self._strip_arg_casts(getattr(node, "rhs", None))
        lhs_offset = self._stack_address_arg_offset_8616(lhs)
        if lhs_offset is not None:
            return lhs_offset
        lhs_offset = self._stack_offset_from_cvar_8616(lhs)
        if lhs_offset is not None:
            return lhs_offset
        if getattr(node, "op", None) == "Add":
            rhs_offset = self._stack_address_arg_offset_8616(rhs)
            if rhs_offset is not None:
                return rhs_offset
            return self._stack_offset_from_cvar_8616(rhs)
        return None



    def _same_return_destination_8616(self, lhs: StructuredAstValue, rhs: StructuredAstValue) -> bool:
        if _same_c_expression_8616(lhs, rhs):
            return True
        lhs_key = _call_arg_semantic_key_8616(lhs)
        rhs_key = _call_arg_semantic_key_8616(rhs)
        return lhs_key is not None and lhs_key == rhs_key



    def _single_statement_shell(self, node: StructuredAstValue) -> StructuredAstValue:
        nested = getattr(node, "statements", None)
        if isinstance(nested, (list, tuple)) and len(nested) == 1:
            return nested[0]
        return node



    def _recent_dirty_assignment_match_8616(self,
        assignment: StructuredAstValue,
        expr_op: StructuredAstValue,
        expr_consts: StructuredAstValue,
        stmt_idx: int,
    ) -> tuple[tuple[int, int, int], StructuredAstValue] | None:
        lhs, rhs_stmt = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs_stmt is None or self._assignment_lhs_writes_memory(lhs):
            return None
        if lhs.__class__.__name__ != "CDirtyExpression":
            return None
        if self._is_segment_register_value_expr(rhs_stmt) or self._expr_contains_plain_register_uses(rhs_stmt):
            return None
        rhs_node = rhs_stmt
        while isinstance(rhs_node, CTypeCast):
            rhs_node = rhs_node.expr
        rhs_op = getattr(rhs_node, "op", None) if isinstance(rhs_node, CBinaryOp) else None
        if expr_op is not None and rhs_op != expr_op:
            return None
        rhs_consts = self._expr_int_constants(rhs_node)
        if expr_consts and rhs_consts and expr_consts.isdisjoint(rhs_consts):
            return None
        score = (
            1 if self._node_contains_stable_named_stack_value_8616(rhs_node) else 0,
            0 if self._node_contains_placeholder_stack_8616(rhs_node) else 1,
            stmt_idx,
        )
        return (score, rhs_stmt)

    def _recent_dirty_value_rhs(self, expr: StructuredAstValue, prefix: list[StructuredAstValue]) -> StructuredAstValue:
        expr_node = expr
        while isinstance(expr_node, CTypeCast):
            expr_node = expr_node.expr
        expr_op = getattr(expr_node, "op", None) if isinstance(expr_node, CBinaryOp) else None
        expr_consts = self._expr_int_constants(expr_node)
        matches: list[tuple[tuple[int, int, int], StructuredAstValue]] = []
        seen_assignments: set[int] = set()
        for stmt_idx in range(len(prefix) - 1, -1, -1):
            stmt = prefix[stmt_idx]
            for assignment in reversed(self._iter_assignment_nodes(stmt)):
                assignment_id = id(assignment)
                if assignment_id in seen_assignments:
                    continue
                seen_assignments.add(assignment_id)
                match = self._recent_dirty_assignment_match_8616(assignment, expr_op, expr_consts, stmt_idx)
                if match is not None:
                    matches.append(match)
        if not matches:
            return None
        matches.sort(key=lambda item: item[0], reverse=True)
        if len(matches) > 1 and matches[0][0] == matches[1][0]:
            return None
        return matches[0][1]



    def _sign_ext_source_8616(self, source: StructuredAstValue) -> tuple[StructuredAstValue, ...] | None:
        if not (
            isinstance(source, tuple)
            and len(source) == 3
            and source[0] == CallsitePushSourceKind8616.EXPR.value
            and isinstance(source[1], tuple)
            and isinstance(source[2], tuple)
            and len(source[2]) == 1
        ):
            return None
        op = source[2][0]
        if not (isinstance(op, tuple) and op[0] == CallsitePushExprOp8616.SIGN_EXT_HI.value):
            return None
        return source



    def _guard_stack_address_arg_offset_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CUnaryOp) or node.op not in {"Reference", "AddressOf"}:
            return None
        operand = node.operand
        while isinstance(operand, CTypeCast):
            operand = operand.expr
        offset: object = call_argument_stack_variable_offset_8616(self.codegen, operand)
        return offset if isinstance(offset, int) and not isinstance(offset, bool) else None



    def _rhs_is_safe_to_relocate_after_call_8616(self, rhs: StructuredAstValue) -> bool:
        if self._statement_contains_call(rhs):
            return False
        for node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                return False
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimMemoryVariable) and not isinstance(variable, SimStackVariable):
                return False
        return True



    def _global_word_expr_offset_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, structured_c.CVariable):
            variable = node.variable
            if isinstance(variable, SimMemoryVariable):
                addr = variable.addr
                width = variable.size
                if isinstance(addr, int) and int(width or 0) in {0, 1, 2}:
                    return addr & 0xFFFF
        pair_offset = self._global_word_byte_pair_offset_8616(node)
        if pair_offset is not None:
            return pair_offset
        call_name = _call_node_name_8616(node) if isinstance(node, CFunctionCall) else None
        if isinstance(call_name, str) and call_name.upper() == "SEG_U16":
            args = _boundary_tuple_8616(getattr(node, "args", ()) or ())
            if len(args) == 2 and self._is_segment_register_value_expr(args[0]):
                offset = getattr(args[1], "value", None)
                if isinstance(offset, int):
                    return offset & 0xFFFF
        return None



    def _calls_match_8616(self, lhs_call: StructuredAstValue, rhs_call: StructuredAstValue) -> bool:
        lhs_name = _call_node_name_8616(lhs_call)
        rhs_name = _call_node_name_8616(rhs_call)
        return _callee_names_match_8616(lhs_name, rhs_name) and self._call_args_match_8616(
            lhs_call,
            rhs_call,
        )



    def _expr_contains_dirty_carrier_for_setup_8616(self, expr: StructuredAstValue) -> bool:
        expr_id = id(expr)
        cached = self.expr_dirty_carrier_cache.get(expr_id)
        if cached is not None:
            return cached
        if _generic_stack_carrier_keys_8616(expr):
            self.expr_dirty_carrier_cache[expr_id] = True
            return True
        for node in (expr, *_iter_c_nodes_deep_8616(expr)):
            if node.__class__.__name__ == "CDirtyExpression":
                self.expr_dirty_carrier_cache[expr_id] = True
                return True
        self.expr_dirty_carrier_cache[expr_id] = False
        return False



    def _call_args_include_recorded_return_call_8616(self, call_node: StructuredAstValue, ret_callsite: int) -> bool:
        stored_return_call = self._stored_return_call_expr_for_callsite_8616(ret_callsite)
        if stored_return_call is None:
            return False
        stored_name = _call_node_name_8616(stored_return_call)
        if not stored_name:
            return False
        for arg in _boundary_tuple_8616(getattr(call_node, "args", ()) or ()):
            for node in (arg, *_iter_c_nodes_deep_8616(arg)):
                if isinstance(node, CFunctionCall) and _call_node_name_8616(node) == stored_name:
                    return True
        return False



    def _is_runtime_segment_store_lvalue_8616(self, expr: StructuredAstValue) -> bool:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CFunctionCall):
            return False
        call_name = _call_node_name_8616(node)
        return isinstance(call_name, str) and call_name.upper() in {"SEG_U8", "SEG_U16", "SEG_U32"}



    def _global_word_low_byte_source_offset_8616(self, expr: StructuredAstValue) -> int | None:
        return self._global_word_expr_offset_8616(expr)



    def _call_args_match_8616(self, lhs_call: StructuredAstValue, rhs_call: StructuredAstValue) -> bool:
        lhs_args = _boundary_tuple_8616(getattr(lhs_call, "args", ()) or ())
        rhs_args = _boundary_tuple_8616(getattr(rhs_call, "args", ()) or ())
        if len(lhs_args) != len(rhs_args):
            return False
        for lhs_arg, rhs_arg in zip(lhs_args, rhs_args, strict=True):
            if _same_c_expression_8616(lhs_arg, rhs_arg):
                continue
            lhs_key = _call_arg_semantic_key_8616(lhs_arg)
            rhs_key = _call_arg_semantic_key_8616(rhs_arg)
            if lhs_key is not None and lhs_key == rhs_key:
                continue
            lhs_pointer_key = self._pointer_offset_key_8616(lhs_arg)
            rhs_pointer_key = self._pointer_offset_key_8616(rhs_arg)
            if lhs_pointer_key is not None and lhs_pointer_key == rhs_pointer_key:
                continue
            return False
        return True



    def _byte_merge_low_source(self, expr: StructuredAstValue) -> StructuredAstValue:
        node = self._strip_arg_casts(expr)
        if not isinstance(node, CBinaryOp) or node.op != "Or":
            return None
        for maybe_high, maybe_low in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            if self._is_stale_high_byte_mask(maybe_high):
                self.stats.byte_merge_raw_fact_count += 1
                return maybe_low
        return None



    def _fold_list(self, container: list[StructuredAstValue]) -> bool:
        changed_local = False
        idx = 0
        while idx < len(container):
            stmt = container[idx]
            nested = getattr(stmt, "statements", None)
            if isinstance(nested, list) and self._fold_list(nested):
                changed_local = True
            if self._fold_list_step_8616(container, stmt, idx):
                changed_local = True
            idx += 1
        return self._fold_adjacent_stale_return_pair_after_destination_call_8616(container) or changed_local
    def _fold_list_kept_dest_apply_8616(self,
        container: list[StructuredAstValue],
        idx: int,
        combine_idx: int,
        combine_rhs: StructuredAstValue,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        low_expr: StructuredAstValue,
        high_expr: StructuredAstValue,
        target_lhs: StructuredAstValue,
    ) -> bool:
        """Fold a stale DX:AX pair when the combine target matches the call destination."""
        if not (
            self._combined_low_high_target(combine_rhs, low_expr, high_expr)
            or self._combined_unknown_low_high_target(combine_rhs, high_expr)
        ):
            return False
        del container[idx + 1 : combine_idx + 1]
        with contextlib.suppress(Exception):
            cast(Any, call).type = _summary_return_type_8616(self.project, summary)
        self.codegen._inertia_dx_ax_return_pair_assignments_folded_8616 = (
            int(getattr(self.codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) or 0) + 1
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-dx-ax-return-pair-fold] function=%#x kept_destination=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                self._debug_expr_8616(target_lhs),
            )
        return True

    def _fold_list_rewrite_apply_8616(self,
        container: list[StructuredAstValue],
        idx: int,
        combine_idx: int,
        combine_rhs: StructuredAstValue,
        call: StructuredAstValue,
        summary: StructuredAstValue,
        lhs: StructuredAstValue,
        high_expr: StructuredAstValue,
        target_lhs: StructuredAstValue,
    ) -> bool:
        """Rewrite the call store to the combined DX:AX destination and drop the stale pair."""
        if not self._combined_low_high_target(combine_rhs, lhs, high_expr):
            return False
        container[idx] = structured_c.CAssignment(self._clone_c_ast_tree(target_lhs), call, codegen=self.codegen)
        del container[idx + 1 : combine_idx + 1]
        with contextlib.suppress(Exception):
            cast(Any, call).type = _summary_return_type_8616(self.project, summary)
        self.codegen._inertia_dx_ax_return_pair_assignments_folded_8616 = (
            int(getattr(self.codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) or 0) + 1
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-dx-ax-return-pair-fold] function=%#x target=%s destination=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call),
                self._debug_expr_8616(target_lhs),
            )
        return True

    def _fold_list_step_8616(self,
        container: list[StructuredAstValue],
        stmt: StructuredAstValue,
        idx: int,
    ) -> bool:
        lhs, rhs = self._assignment_lhs_rhs_local(stmt)
        call = rhs if isinstance(rhs, CFunctionCall) else None
        summary = self.summary_map.get(id(call)) if call is not None else None
        if (
            lhs is None
            or call is None
            or summary is None
            or summary.return_used is not True
            or summary.return_register not in {None, "ax"}
        ):
            return False
        has_dx_ax_return_proof = summary.return_shape == "dx_ax" or isinstance(
            summary.return_store_destination,
            tuple,
        )
        if not has_dx_ax_return_proof:
            return False
        low_expr = self._register_expr_from_name_8616("ax")
        high_expr = self._register_expr_from_name_8616("dx")
        combine_idx = self._next_nonempty_index(container, idx + 1)
        if combine_idx < len(container):
            high_lhs, high_rhs = self._assignment_lhs_rhs_local(container[combine_idx])
            if high_lhs is not None and self._register_name_from_c_variable_8616(high_rhs) == "dx":
                high_expr = high_lhs
                combine_idx = self._next_nonempty_index(container, combine_idx + 1)
        if high_expr is None or combine_idx >= len(container):
            return False
        target_lhs, combine_rhs = self._assignment_lhs_rhs_local(container[combine_idx])
        if target_lhs is None or combine_rhs is None:
            return False
        if low_expr is not None and self._same_return_destination_8616(lhs, target_lhs):
            return self._fold_list_kept_dest_apply_8616(
                container, idx, combine_idx, combine_rhs, call, summary, low_expr, high_expr, target_lhs
            )
        return self._fold_list_rewrite_apply_8616(
            container, idx, combine_idx, combine_rhs, call, summary, lhs, high_expr, target_lhs
        )



    def _protected_call_arg_state(self) -> ProtectedCallArgumentStore8616:
        protected = getattr(self.codegen, "_inertia_protected_call_args_8616", None)
        if not isinstance(protected, ProtectedCallArgumentStore8616):
            protected = ProtectedCallArgumentStore8616()
            self.codegen._inertia_protected_call_args_8616 = protected
        return protected



    def _next_nonempty_index(self, container: list[StructuredAstValue], start: int) -> int:
        idx = int(start)
        while idx < len(container) and self._is_empty_statement_shell(container[idx]):
            idx += 1
        return idx



    def _strip_casts(self, node: StructuredAstValue) -> StructuredAstValue:
        while isinstance(node, CTypeCast):
            node = node.expr
        return node



    def materialize_assignment(self, stmt: StructuredAstValue, *, evidence: dict[int, list[tuple[int, StructuredAstValue]]] | None) -> bool:
        local_changed = False
        for offset in tuple(evidence):
            assignment, rhs = self._assignment_to_stack_offset_8616(stmt, offset)
            if assignment is None or not self._is_immediate_like_expr_8616(rhs):
                continue
            symbol = self.symbol_for_immediate(offset, self._constant_int_value_8616(rhs), evidence=evidence)
            if symbol is None:
                continue
            lhs, _old_rhs = self._assignment_lhs_rhs(assignment)
            self._set_stack_slot_type_8616(offset, getattr(symbol, "variable_type", None))
            if hasattr(assignment, "rhs"):
                assignment.rhs = symbol
            elif hasattr(assignment, "src"):
                assignment.src = symbol
            if lhs is not None:
                self._set_assignment_lhs_8616(assignment, lhs)
            local_changed = True
        return local_changed



    def _repair_branch_immediate_function_pointer_stores_8616(self, stmt: structured_c.CIfElse, *, evidence: dict[int, list[tuple[int, StructuredAstValue]]] | None) -> bool:
        local_changed = False
        branch_nodes = [
            child
            for _cond, child in _boundary_tuple_8616(getattr(stmt, "condition_and_nodes", ()) or ())
            if child is not None
        ]
        else_node = getattr(stmt, "else_node", None)
        if else_node is not None:
            branch_nodes.append(else_node)
        if len(branch_nodes) < 2:
            return False
        branch_assignments = [
            assignment
            for node in branch_nodes
            for assignment in self._iter_assignment_nodes(node)
            if self._assignment_lhs_rhs(assignment)[0] is not None and self._assignment_lhs_rhs(assignment)[1] is not None
        ]
        if len(branch_assignments) < 2:
            return False
        for offset, symbols in evidence.items():
            if self._repair_branch_offset_group_8616(offset, symbols, branch_assignments):
                local_changed = True
        return local_changed


    def _repair_branch_offset_group_8616(self,
        offset: StructuredAstValue,
        symbols: StructuredAstValue,
        branch_assignments: list[StructuredAstValue],
    ) -> bool:
        repaired = False
        symbol_by_imm = {int(imm) & 0xFFFF: symbol for imm, symbol in symbols}
        if len(symbol_by_imm) < 2:
            return False
        matched: list[tuple[StructuredAstValue, int, StructuredAstValue]] = []
        for assignment in branch_assignments:
            lhs, rhs = self._assignment_lhs_rhs(assignment)
            imm = self._constant_int_value_8616(rhs)
            if imm is None or (imm & 0xFFFF) not in symbol_by_imm:
                continue
            lhs_offset = self._stack_offset_from_cvar_8616(lhs)
            if lhs_offset == offset and self._symbol_name_8616(rhs) in {
                self._symbol_name_8616(symbol) for symbol in symbol_by_imm.values()
            }:
                continue
            matched.append((assignment, imm & 0xFFFF, lhs))
        if len({imm for _assignment, imm, _lhs in matched}) != len(matched):
            return False
        if not matched:
            return False
        # This is a branch-local storage repair, not a naming guess: every
        # rewritten RHS immediate must match an instruction-level near
        # function-pointer store to the same BP-relative slot.
        for assignment, imm, _lhs in matched:
            symbol = symbol_by_imm.get(imm)
            if symbol is None:
                continue
            if self._materialize_symbol_store_assignment_8616(assignment, offset, symbol):
                repaired = True
                self.codegen._inertia_fnptr_branch_store_identity_repaired_8616 = (
                    int(getattr(self.codegen, "_inertia_fnptr_branch_store_identity_repaired_8616", 0) or 0) + 1
                )
        return repaired

    def _replace_branch_node_with_assignment_8616(self, node: StructuredAstValue, assignment: StructuredAstValue) -> bool:
        if node is None:
            return False
        statements = getattr(node, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return False
        node.statements = [assignment] if isinstance(statements, list) else (assignment,)
        return True



    def resolve_stack_offset(self, expr: StructuredAstValue) -> int | None:
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        if isinstance(expr, structured_c.CVariable):
            offset = call_argument_stack_variable_offset_8616(self.codegen, expr)
            return offset if isinstance(offset, int) else None
        if isinstance(expr, structured_c.CIndexedVariable):
            base_expr = expr.variable
            index_expr = expr.index
            while isinstance(base_expr, CTypeCast):
                base_expr = base_expr.expr
            if isinstance(base_expr, CUnaryOp) and base_expr.op == "Reference":
                base_expr = base_expr.operand
            base_offset = self.resolve_stack_offset(base_expr)
            index_value = getattr(index_expr, "value", None)
            if isinstance(base_offset, int) and isinstance(index_value, int):
                if index_value % 2 == 0 and abs(index_value) >= 2:
                    return base_offset + index_value // 2
                return base_offset + index_value
        return None



    def _seg_u8_store_args_8616(self, lhs: StructuredAstValue) -> tuple[StructuredAstValue, ...] | None:
        node = lhs
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CFunctionCall):
            return None
        call_name = _call_node_name_8616(node)
        if not isinstance(call_name, str) or call_name.upper() != "SEG_U8":
            return None
        args = _boundary_tuple_8616(node.args or ())
        return args if len(args) == 2 else None



    def _call_args_reference_global_word_8616(self, call_node: StructuredAstValue, offset: int) -> bool:
        if call_node is None:
            return False
        for arg in _boundary_tuple_8616(getattr(call_node, "args", ()) or ()):
            for node in (arg, *_iter_c_nodes_deep_8616(arg)):
                if self._global_word_expr_offset_8616(node) == (offset & 0xFFFF):
                    return True
        return False



    def _push_source_has_arithmetic_expr_8616(self, source: StructuredAstValue) -> bool:
        if not isinstance(source, tuple) or len(source) < 3:
            return False
        if source[0] != "expr":
            return False
        source_ops = source[2]
        return isinstance(source_ops, tuple) and len(source_ops) > 0



    def _materialize_empty_branch_function_pointer_stores_8616(self, stmt: structured_c.CIfElse, *, evidence: dict[int, list[tuple[int, StructuredAstValue]]] | None) -> bool:
        condition_nodes = _boundary_tuple_8616(getattr(stmt, "condition_and_nodes", ()) or ())
        if len(condition_nodes) != 1:
            return False
        true_node = condition_nodes[0][1]
        else_node = getattr(stmt, "else_node", None)
        if not (self._branch_node_is_empty_8616(true_node) and self._branch_node_is_empty_8616(else_node)):
            return False
        for offset, symbols in evidence.items():
            ordered_symbols = tuple(symbol for _imm, symbol in symbols)
            if len(ordered_symbols) != 2:
                continue
            true_assignment = self.make_assignment(offset, ordered_symbols[0])
            false_assignment = self.make_assignment(offset, ordered_symbols[1])
            if true_assignment is None or false_assignment is None:
                continue
            if not self._replace_branch_node_with_assignment_8616(true_node, true_assignment):
                continue
            if not self._replace_branch_node_with_assignment_8616(else_node, false_assignment):
                continue
            self.codegen._inertia_fnptr_empty_branch_stores_materialized_8616 = (
                int(getattr(self.codegen, "_inertia_fnptr_empty_branch_stores_materialized_8616", 0) or 0) + 2
            )
            return True
        return False



    def _mark_return_register_arg_8616(self,
        expr: StructuredAstValue, callsite: int, regs: tuple[str, ...]
    ) -> StructuredAstValue:
        if isinstance(expr, CFunctionCall):
            return_arg_sources = getattr(self.codegen, "_inertia_return_register_arg_sources_8616", None)
            if not isinstance(return_arg_sources, dict):
                return_arg_sources = {}
                self.codegen._inertia_return_register_arg_sources_8616 = return_arg_sources
            return_arg_sources[id(expr)] = (int(callsite), tuple(sorted(regs)))
        return expr



    def _push_source_is_expr_arithmetic_8616(self, source: StructuredAstValue) -> bool:
        return bool(
            isinstance(source, tuple)
            and len(source) >= 3
            and source[0] == "expr"
            and isinstance(source[2], tuple)
            and source[2]
        )



    def _record_pruned_stack_write_token_8616(self, stmt: StructuredAstValue) -> None:
        token = self._stack_slot_write_token_for_stmt_8616(stmt)
        if token is None:
            return
        existing = getattr(self.codegen, "_inertia_callsite_pruned_stack_write_tokens_8616", ())
        if not isinstance(existing, tuple):
            existing = ()
        self.codegen._inertia_callsite_pruned_stack_write_tokens_8616 = (*existing, token)



    def _dedupe_indices(self, indices: list[int]) -> list[int]:
        return sorted(set(indices))



    def _local_expr_contains_dirty_expression_8616(self, expr: StructuredAstValue) -> bool:
        for raw_node in (expr, *_iter_c_nodes_deep_8616(expr)):
            node = raw_node
            while isinstance(node, CTypeCast):
                node = node.expr
            if node.__class__.__name__ == "CDirtyExpression":
                return True
        return False



    def _call_args_reference_identity_8616(self,
        call_node: StructuredAstValue, identity_key: StructuredAstValue
    ) -> bool:
        if call_node is None or identity_key is None:
            return False
        for arg in _boundary_tuple_8616(getattr(call_node, "args", ()) or ()):
            if self._c_variable_identity_key_8616(arg) == identity_key:
                return True
            if self._statement_references_variable_identity_8616(arg, identity_key):
                return True
        return False



    def _global_scaled_byte_expr_offset_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CBinaryOp):
            return None
        if node.op == "Mul":
            if self._constant_int_value_8616(node.lhs) == 256:
                return self._global_byte_expr_offset_8616(node.rhs)
            if self._constant_int_value_8616(node.rhs) == 256:
                return self._global_byte_expr_offset_8616(node.lhs)
        if node.op == "Shl" and self._constant_int_value_8616(node.rhs) == 8:
            return self._global_byte_expr_offset_8616(node.lhs)
        return None



    def _lhs_is_far_pointer_outgoing_byte_store_8616(self, lhs: StructuredAstValue) -> bool:
        args = self._seg_u8_store_args_8616(lhs)
        if args is None:
            return False
        seg_arg, offset_arg = args
        if not (self._is_segment_register_value_expr(seg_arg) or self._expr_contains_dirty_carrier_8616(seg_arg)):
            return False
        return bool(
            _generic_stack_carrier_keys_8616(offset_arg)
            or self._expr_contains_dirty_carrier_8616(offset_arg)
            or self._rhs_is_dirty_stack_pointer_arithmetic_8616(offset_arg)
        )



    def _carrier_rhs_keys_to_chase_for_consumed_store_8616(self,
        rhs: StructuredAstValue,
    ) -> set[tuple[str, str | int]]:
        node = rhs
        while isinstance(node, CTypeCast):
            node = node.expr
        if node is None or isinstance(node, structured_c.CConstant):
            return set()
        if isinstance(node, structured_c.CVariable):
            return set()
        if self._is_segment_register_value_expr(node):
            return set()
        if isinstance(node, CUnaryOp) and getattr(node, "op", None) in {"Reference", "Dereference"}:
            return {
                (str(key[0]), key[1])
                for key in _generic_stack_carrier_keys_8616(node)
                if isinstance(key, tuple)
                and len(key) == 2
                and isinstance(key[0], str)
                and isinstance(key[1], (str, int))
            }
        if isinstance(node, CBinaryOp):
            return {
                (str(key[0]), key[1])
                for key in _generic_stack_carrier_keys_8616(node)
                if isinstance(key, tuple)
                and len(key) == 2
                and isinstance(key[0], str)
                and isinstance(key[1], (str, int))
            }
        if node.__class__.__name__ == "CDirtyExpression":
            return {
                (str(key[0]), key[1])
                for key in _generic_stack_carrier_keys_8616(node)
                if isinstance(key, tuple)
                and len(key) == 2
                and isinstance(key[0], str)
                and isinstance(key[1], (str, int))
            }
        return set()



    def _is_far_pointer_offset_source_8616(self, source: StructuredAstValue) -> bool:
        if not isinstance(source, tuple) or len(source) < 2:
            return False
        source_kind = source[0]
        if source_kind in {
            CallsitePushSourceKind8616.BP_ADDRESS.value,
            CallsitePushSourceKind8616.BP_INDEX_ADDRESS.value,
        }:
            return True
        if source_kind == CallsitePushSourceKind8616.GLOBAL_VALUE.value:
            return len(source) >= 3 and isinstance(source[2], int) and int(source[2]) == 2
        if source_kind == CallsitePushSourceKind8616.GLOBAL_INDEX_VALUE.value:
            return len(source) >= 3 and isinstance(source[2], int) and int(source[2]) == 2
        if source_kind == CallsitePushSourceKind8616.SEGMENTED_INDIRECT_VALUE.value:
            return len(source) == 4 and isinstance(source[2], int) and int(source[2]) == 2
        if (
            source_kind == CallsitePushSourceKind8616.EXPR.value
            and len(source) >= 2
            and isinstance(source[1], tuple)
        ):
            return self._is_far_pointer_offset_source_8616(source[1])
        return False



    def _recent_stack_evidence_step_8616(self,
        candidate: StructuredAstValue,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
        skipped_carriers: int,
        skipped_values: int,
    ) -> tuple[str, int, int]:
        """Classify one trailing statement; returns (hit|carrier|value|stop, carriers, values)."""
        if self._statement_contains_call(candidate):
            return "stop", skipped_carriers, skipped_values
        if typed_probe_fact is not None:
            rhs = self._typed_stack_store_rhs_from_statement(candidate, typed_probe_fact)
        else:
            rhs = self._stack_store_rhs_from_statement(candidate)
        if rhs is not None and not self._is_segment_register_value_expr(rhs):
            return "hit", skipped_carriers, skipped_values
        if self._outgoing_arg_placeholder_rhs_from_statement(candidate) is not None:
            return "hit", skipped_carriers, skipped_values
        if self._is_stack_carrier_temp_assignment(candidate) or self._is_segment_register_metadata_store(candidate):
            skipped_carriers += 1
            return (
                "stop" if skipped_carriers > 4 else "carrier",
                skipped_carriers,
                skipped_values,
            )
        if self._is_non_memory_assignment(candidate) or self._is_value_only_assignment(candidate):
            skipped_values += 1
            return (
                "stop" if skipped_values > 8 else "value",
                skipped_carriers,
                skipped_values,
            )
        return "stop", skipped_carriers, skipped_values

    def _has_recent_stack_arg_store_evidence(self,
        statement_list: list[StructuredAstValue],
        wanted_count: int,
        typed_probe_fact: TypedStackProbeReturnFact8616 | None,
    ) -> bool:
        if not isinstance(wanted_count, int) or wanted_count <= 0:
            return False
        needed = wanted_count
        skipped_carriers = 0
        skipped_values = 0
        idx = len(statement_list) - 1
        while idx >= 0 and needed > 0:
            action, skipped_carriers, skipped_values = self._recent_stack_evidence_step_8616(
                statement_list[idx], typed_probe_fact, skipped_carriers, skipped_values
            )
            if action == "stop":
                break
            if action == "hit":
                needed -= 1
            idx -= 1
        return needed <= 0



    def _stable_call_source_expr_stack_offset(self, source: StructuredAstValue) -> int | None:
        if not isinstance(source, tuple) or len(source) < 2:
            return None
        if source[0] != "expr" and source[0] != "bp":
            return None
        if source[0] == "expr":
            source_inner = source[1]
            if not isinstance(source_inner, tuple) or len(source_inner) < 2:
                return None
            source_offset = source_inner[1]
        else:
            source_offset = source[1]
        return int(source_offset) if isinstance(source_offset, int) else None



    def final_standalone_call_ref(self, stmt: StructuredAstValue) -> StructuredAstValue:
        call = self.standalone_call_from_statement(stmt)
        if call is not None:
            return call, None, None
        nested = getattr(stmt, "statements", None)
        if not isinstance(nested, list) or not nested:
            return None, None, None
        call = self.standalone_call_from_statement(nested[-1])
        if call is None:
            return None, None, None
        return call, nested, len(nested) - 1



    def _prune_stale_fnptr_overwrite_at_8616(self,
        new_statements: list[StructuredAstValue],
        idx: int,
        stmt: StructuredAstValue,
        next_stmt: StructuredAstValue,
        evidence: dict[int, list[tuple[int, StructuredAstValue]]],
        bp_stack_store_counts: dict[int, int],
    ) -> bool:
        """Remove ``next_stmt`` when it stale-overwrites a proven fnptr branch slot."""
        for offset, symbols in evidence.items():
            symbol_names = {
                name for _imm, symbol in symbols for name in [self._symbol_name_8616(symbol)] if name is not None
            }
            if len(symbol_names) < 2:
                continue
            branch_names = self._ifelse_branch_symbol_names_for_offset_8616(stmt, offset)
            if branch_names != symbol_names:
                continue
            if int(bp_stack_store_counts.get(offset, 0)) != len(symbols):
                continue
            if not self._assignment_is_stale_post_branch_fnptr_overwrite_8616(next_stmt, offset, symbol_names):
                continue
            del new_statements[idx + 1]
            self.codegen._inertia_fnptr_stale_post_branch_overwrites_pruned_8616 = (
                int(getattr(self.codegen, "_inertia_fnptr_stale_post_branch_overwrites_pruned_8616", 0) or 0) + 1
            )
            return True
        return False

    def _prune_stale_post_branch_fnptr_overwrites_8616(self, block: StructuredAstValue, *, bp_stack_store_counts: dict[int, int], evidence: dict[int, list[tuple[int, StructuredAstValue]]] | None) -> bool:
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)) or len(statements) < 2:
            return False
        new_statements = list(statements)
        changed_block = False
        idx = 0
        while idx + 1 < len(new_statements):
            stmt = new_statements[idx]
            next_stmt = new_statements[idx + 1]
            if not isinstance(stmt, structured_c.CIfElse):
                idx += 1
                continue
            removed = self._prune_stale_fnptr_overwrite_at_8616(
                new_statements, idx, stmt, next_stmt, evidence, bp_stack_store_counts
            )
            changed_block = changed_block or removed
            if not removed:
                idx += 1
        if not changed_block:
            return False
        block.statements = new_statements if isinstance(statements, list) else tuple(new_statements)
        return True



    def _is_empty_statement_shell(self, node: StructuredAstValue) -> bool:
        nested = getattr(node, "statements", None)
        return isinstance(nested, (list, tuple)) and len(nested) == 0



    def _children(self, current: StructuredAstValue) -> StructuredAstValue:
        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "iftrue",
            "iffalse",
            "body",
            "retval",
            "variable",
            "index",
        ):
            if hasattr(current, attr):
                child = getattr(current, attr, None)
                if child is not None:
                    yield child
        for attr in ("args", "operands", "statements"):
            if not hasattr(current, attr):
                continue
            items = getattr(current, attr, None)
            if isinstance(items, (list, tuple)):
                yield from (item for item in items if item is not None)



    def _assignment_lhs_rhs_local(self,
        node: StructuredAstValue,
    ) -> tuple[StructuredAstValue | None, StructuredAstValue | None]:
        node = self._single_statement_shell(node)
        if node is None:
            return None, None
        expr = getattr(node, "expr", None)
        if expr is not None and (
            expr.__class__.__name__ == "CAssignment" or expr.__class__.__name__.endswith("Assignment")
        ):
            node = expr
        if node.__class__.__name__ == "CAssignment" or node.__class__.__name__.endswith("Assignment"):
            lhs = getattr(node, "lhs", None)
            rhs = getattr(node, "rhs", None)
            if lhs is None and hasattr(node, "dst"):
                lhs = getattr(node, "dst", None)
                rhs = getattr(node, "src", None)
            return lhs, rhs
        return None, None



    def _return_call_expr_with_materialized_args_8616(self, *, first_callsite: int, return_call: StructuredAstValue, return_summary: StructuredAstValue) -> StructuredAstValue:
        if _boundary_tuple_8616(getattr(return_call, "args", ()) or ()):
            ret_expr = self._clone_c_ast_tree(return_call)
            self._regroup_return_call_args_from_summary_8616(ret_expr, return_summary)
            return ret_expr
        synthesized = self._synthesized_return_call_expr_from_summary_8616(first_callsite)
        if synthesized is not None:
            return self._clone_c_ast_tree(synthesized)
        ret_expr = self._clone_c_ast_tree(return_call)
        self._regroup_return_call_args_from_summary_8616(ret_expr, return_summary)
        return ret_expr



    def _push_sources_have_return_register_setup_window_evidence_8616(self,
        call_node: StructuredAstValue, window_push_sources: tuple[StructuredAstValue, ...]
    ) -> bool:
        ret_reg_infos = tuple(
            info for source in window_push_sources if (info := self._ret_reg_source_info_8616(source)) is not None
        )
        if not ret_reg_infos:
            return False
        ret_callsites = {callsite for callsite, _reg in ret_reg_infos}
        return bool(ret_callsites) and all(
            self._call_args_include_recorded_return_call_8616(call_node, ret_callsite) for ret_callsite in ret_callsites
        )



    def _later_identity_keys_by_index_8616(self,
        statement_list: list[StructuredAstValue],
    ) -> tuple[frozenset[tuple[StructuredAstValue, ...]], ...]:
        """Build suffix identity sets so live-later checks stay linear."""
        suffix_keys: set[tuple[StructuredAstValue, ...]] = set()
        reversed_suffixes: list[frozenset[tuple[StructuredAstValue, ...]]] = []
        for statement in reversed(statement_list):
            reversed_suffixes.append(frozenset(suffix_keys))
            suffix_keys.update(self._statement_variable_identity_keys_8616(statement))
        return tuple(reversed(reversed_suffixes))



    def _constant_int_value(self, node: StructuredAstValue) -> int | None:
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, structured_c.CConstant):
            value = node.value
            return int(value) if isinstance(value, int) else None
        return None



    def _rhs_is_exact_push_register_alias_artifact_8616(self, rhs: StructuredAstValue) -> bool:
        """Accept a pure register carrier only at an exact physical push."""
        if not isinstance(rhs, structured_c.CVariable):
            return False
        return isinstance(rhs.variable, SimRegisterVariable)



    def _rhs_is_safe_push_alias_artifact_8616(self, rhs: StructuredAstValue) -> bool:
        if self._statement_contains_call(rhs):
            return False
        for node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                return False
            if self._expr_contains_dirty_carrier_8616(node):
                return False
        return True



    def _global_word_byte_pair_offset_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CBinaryOp) or node.op != "Or":
            return None
        low_offset = self._global_byte_expr_offset_8616(getattr(node, "lhs", None))
        high_offset = self._global_scaled_byte_expr_offset_8616(getattr(node, "rhs", None))
        if low_offset is None or high_offset is None:
            low_offset = self._global_byte_expr_offset_8616(getattr(node, "rhs", None))
            high_offset = self._global_scaled_byte_expr_offset_8616(getattr(node, "lhs", None))
        if low_offset is None or high_offset is None or high_offset != low_offset + 1:
            return None
        return low_offset & 0xFFFF



    def _rhs_is_safe_far_pointer_carrier_artifact_8616(self, rhs: StructuredAstValue) -> bool:
        if self._statement_contains_call(rhs):
            return False
        for node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                return False
        return True



    def _call_args_reference_identity(self, call_node: StructuredAstValue, identity_key: StructuredAstValue) -> bool:
        if call_node is None or identity_key is None:
            return False
        for arg in _boundary_tuple_8616(getattr(call_node, "args", ()) or ()):
            if self._c_variable_identity_key_8616(arg) == identity_key:
                return True
            if self._statement_references_variable_identity_8616(arg, identity_key):
                return True
        return False



    def _is_skip_after_typed_collect(self, stmt: StructuredAstValue) -> bool:
        return (
            self._is_stack_carrier_temp_assignment(stmt)
            or self._is_non_memory_assignment(stmt)
            or self._is_value_only_assignment(stmt)
            or self._is_segment_register_metadata_store(stmt)
        )



    def _call_has_dx_ax_destination_proof_8616(self, call: StructuredAstValue) -> bool:
        summary = self.summary_map.get(id(call)) if call is not None else None
        if summary is None or summary.return_used is not True or summary.return_register not in {None, "ax"}:
            return False
        return summary.return_shape == "dx_ax" or isinstance(
            summary.return_store_destination,
            tuple,
        )



    def _expr_op_is_valid(self, op: StructuredAstValue) -> bool:
        if not isinstance(op, tuple) or len(op) != 2:
            return False
        op_name, op_value = op
        if op_name in CALL_ARGUMENT_INTEGER_OPERATION_NAMES_8616:
            return isinstance(op_value, int)
        if op_name in CALL_ARGUMENT_SOURCE_OPERATION_NAMES_8616:
            return isinstance(op_value, tuple) and self._is_call_arg_count_evidence_tuple(op_value)
        return False



    def _is_stack_address_arg_expr_8616(self, expr: StructuredAstValue) -> bool:
        node = self._strip_arg_casts(expr)
        if not isinstance(node, CUnaryOp) or getattr(node, "op", None) not in {"Reference", "AddressOf"}:
            return False
        operand = self._strip_arg_casts(getattr(node, "operand", None))
        variable = getattr(operand, "variable", None)
        return isinstance(variable, SimStackVariable)



    def _summary_logical_arg_widths(self, summary: StructuredAstValue, callee_name: str | None) -> tuple[int, ...] | None:
        if summary is None or not isinstance(callee_name, str) or not callee_name:
            return None
        push_sources = _boundary_tuple_8616(summary.push_arg_sources or ())
        if not push_sources:
            return None
        expected_widths = _known_helper_prototype_arg_widths_8616(self.project, callee_name)
        if expected_widths is not None and _prototype_widths_account_for_push_sources_top_8616(
            expected_widths,
            push_sources,
        ):
            return expected_widths
        arity_contract = _known_callee_arity_contract_8616(callee_name)
        logical_arg_count = (
            arity_contract.count
            if arity_contract.mode is CallArityMode8616.EXACT
            and isinstance(arity_contract.count, int)
            and arity_contract.count > 0
            else len(expected_widths)
            if expected_widths
            else None
        )
        source_width = _push_sources_total_width_for_arg_accounting_8616(push_sources)
        if (
            isinstance(logical_arg_count, int)
            and logical_arg_count > 0
            and isinstance(source_width, int)
            and source_width >= logical_arg_count * 2
            and source_width % logical_arg_count == 0
        ):
            return (source_width // logical_arg_count,) * logical_arg_count
        return expected_widths



    def _arg_is_stable_materialized_for_contract_8616(self, arg_index: int, node: StructuredAstValue, *, arity_satisfied: bool, callee_prototype: object, semantic_name: str | None) -> bool:
        if not arity_satisfied:
            return False
        if self._node_contains_placeholder_stack_8616(node) or self._expr_contains_plain_register_uses(node):
            return False
        kind = _call_arg_semantic_kind_8616(
            semantic_name,
            arg_index,
            project=self.project,
            prototype=callee_prototype,
            cod_path_hint=self.cod_path_hint,
        )
        if kind is CallArgSemanticKind8616.UNKNOWN:
            return _call_arg_semantic_key_8616(node) is not None
        return self._arg_semantic_quality_8616(semantic_name, arg_index, node) > 0



    def _materialize_symbol_store_assignment_8616(self,
        assignment: StructuredAstValue, offset: int, symbol: StructuredAstValue
    ) -> bool:
        lhs = self._stack_cvar_for_offset(offset, allow_best_match=False)
        if lhs is None:
            lhs = self._stack_cvar_for_offset(offset, allow_best_match=True)
        if lhs is None:
            return False
        symbol = self._clone_c_ast_tree(symbol)
        self._set_stack_slot_type_8616(offset, getattr(symbol, "variable_type", None))
        if hasattr(assignment, "lhs"):
            assignment.lhs = self._clone_c_ast_tree(lhs)
        elif hasattr(assignment, "dst"):
            assignment.dst = self._clone_c_ast_tree(lhs)
        else:
            return False
        if hasattr(assignment, "rhs"):
            assignment.rhs = symbol
        elif hasattr(assignment, "src"):
            assignment.src = symbol
        else:
            return False
        return True



    def _debug_assignments_in_stmt_8616(self,
        stmt: StructuredAstValue,
    ) -> tuple[
        tuple[
            tuple[str, str | None, int | None, int | None],
            tuple[str, str | None, int | None, int | None],
        ],
        ...,
    ]:
        return tuple(self._debug_assignment_tuple_8616(assignment) for assignment in self._iter_assignment_nodes(stmt))



    def _combined_low_high_target(self,
        node: StructuredAstValue, low_expr: StructuredAstValue, high_expr: StructuredAstValue
    ) -> bool:
        node = self._strip_casts(node)
        if not isinstance(node, CBinaryOp) or getattr(node, "op", None) != "Or":
            return False
        lhs = self._strip_casts(getattr(node, "lhs", None))
        rhs = self._strip_casts(getattr(node, "rhs", None))
        rhs_shift_source = self._shift16_source(rhs)
        lhs_is_low = _same_c_expression_8616(lhs, low_expr) or self._is_register_expr_by_offset(lhs, "ax")
        rhs_is_low = _same_c_expression_8616(rhs, low_expr) or self._is_register_expr_by_offset(rhs, "ax")
        if lhs_is_low and rhs_shift_source is not None:
            return _same_c_expression_8616(rhs_shift_source, high_expr) or self._is_register_expr_by_offset(
                rhs_shift_source, "dx"
            )
        lhs_shift_source = self._shift16_source(lhs)
        if rhs_is_low and lhs_shift_source is not None:
            return _same_c_expression_8616(lhs_shift_source, high_expr) or self._is_register_expr_by_offset(
                lhs_shift_source, "dx"
            )
        return False



    def _expr_contains_non_segment_register_uses(self, node: StructuredAstValue) -> bool:
        stack = [node]
        while stack:
            current = stack.pop()
            if current is None:
                continue
            current = self._strip_arg_casts(current)
            if self._is_plain_register_value_expr(current):
                return True
            for attr in ("lhs", "rhs", "operand", "expr", "condition", "iftrue", "iffalse", "variable", "index"):
                child = getattr(current, attr, None)
                if child is not None:
                    stack.append(child)
            for attr in ("args", "operands"):
                items = getattr(current, attr, None)
                if isinstance(items, (list, tuple)):
                    stack.extend(item for item in items if item is not None)
        return False



    def symbol_for_immediate(self,
        offset: int, imm: int | None, *, exclude_names: set[str] | None = None, evidence: dict[int, list[tuple[int, StructuredAstValue]]] | None
    ) -> StructuredAstValue:
        symbols = evidence.get(offset)
        if not symbols:
            return None
        excluded = exclude_names or set()
        if isinstance(imm, int):
            for candidate_imm, symbol in symbols:
                if (candidate_imm & 0xFFFF) == (imm & 0xFFFF):
                    return self._clone_c_ast_tree(symbol)
        for _candidate_imm, symbol in symbols:
            name = self._symbol_name_8616(symbol)
            if name is not None and name in excluded:
                continue
            return self._clone_c_ast_tree(symbol)
        return None



    def _rhs_is_dirty_stack_pointer_arithmetic_8616(self, rhs: StructuredAstValue) -> bool:
        node = rhs
        while isinstance(node, CTypeCast):
            node = node.expr
        if node is None:
            return False
        if node.__class__.__name__ == "CDirtyExpression":
            return True
        if isinstance(node, structured_c.CConstant):
            return True
        if isinstance(node, CBinaryOp):
            return self._rhs_is_dirty_stack_pointer_arithmetic_8616(
                node.lhs
            ) and self._rhs_is_dirty_stack_pointer_arithmetic_8616(node.rhs)
        return False



    def _rhs_is_dirty_far_pointer_value_artifact_8616(self, rhs: StructuredAstValue) -> bool:
        if not self._expr_contains_dirty_carrier_8616(rhs):
            return False
        for node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                return False
        return True



    def _consumed_carrier_scan_step_8616(self,
        candidate: StructuredAstValue,
        pending_keys: set[tuple[str, str | int]],
    ) -> str:
        """Classify one candidate while chasing consumed-store carriers (take|skip|stop)."""
        if self._statement_contains_call(candidate):
            return "stop"
        assignment = self._top_level_assignment_node_8616(candidate)
        if assignment is None:
            return "stop"
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        lhs_keys = _generic_stack_carrier_keys_8616(lhs)
        if not lhs_keys & pending_keys:
            return "skip"
        if self._assignment_lhs_writes_memory(lhs):
            return "stop"
        if not (
            self._rhs_is_safe_push_alias_artifact_8616(rhs)
            or self._rhs_is_dirty_stack_pointer_arithmetic_8616(rhs)
        ):
            return "stop"
        pending_keys.difference_update(lhs_keys)
        pending_keys.update(self._carrier_rhs_keys_to_chase_for_consumed_store_8616(rhs))
        return "take"

    def _consumed_stack_store_carrier_indices_8616(self,
        consumed_indices: list[int], *, new_statements: list[StructuredAstValue],
    ) -> list[int]:
        if not consumed_indices:
            return []
        pending_keys: set[tuple[str, str | int]] = set()
        for consumed_idx in consumed_indices:
            if consumed_idx < 0 or consumed_idx >= len(new_statements):
                continue
            assignment = self._top_level_assignment_node_8616(new_statements[consumed_idx])
            if assignment is None:
                continue
            lhs, rhs = self._assignment_lhs_rhs(assignment)
            pending_keys.update(_generic_stack_carrier_keys_8616(lhs))
            pending_keys.update(_generic_stack_carrier_keys_8616(rhs))
        if not pending_keys:
            return []
        carrier_indices: list[int] = []
        scan_idx = min(consumed_indices) - 1
        while scan_idx >= 0 and pending_keys:
            action = self._consumed_carrier_scan_step_8616(new_statements[scan_idx], pending_keys)
            if action == "stop":
                break
            if action == "take":
                carrier_indices.append(scan_idx)
            scan_idx -= 1
        return carrier_indices



    def _collect_backtracked_runtime_stack_store_args_8616(self,
        *, wanted_count: int, new_statements: list[StructuredAstValue]
    ) -> tuple[list[StructuredAstValue], list[int]]:
        if wanted_count <= 0:
            return [], []
        rhs_values: list[StructuredAstValue] = []
        consumed_indices: list[int] = []
        skipped_carriers = 0
        skipped_values = 0
        idx = len(new_statements) - 1
        while idx >= 0 and len(rhs_values) < wanted_count:
            stmt = new_statements[idx]
            rhs = self._stack_store_rhs_from_statement(stmt)
            if rhs is not None and not self._is_segment_register_value_expr(rhs):
                rhs_values.append(rhs)
                consumed_indices.append(idx)
                idx -= 1
                continue
            if self._is_segment_register_metadata_store(stmt) or self._is_stack_carrier_temp_assignment(stmt):
                skipped_carriers += 1
                if skipped_carriers > 8:
                    break
                idx -= 1
                continue
            if self._is_non_memory_assignment(stmt) or self._is_value_only_assignment(stmt):
                skipped_values += 1
                if skipped_values > 16:
                    break
                idx -= 1
                continue
            break
        if len(rhs_values) != wanted_count:
            return [], []
        return rhs_values, consumed_indices



    def _unary_unwrap(self, value_node: StructuredAstValue) -> StructuredAstValue:
        while isinstance(value_node, CTypeCast):
            value_node = value_node.expr
        return value_node



    def _has_arithmetic_push_source(self, source: StructuredAstValue) -> bool:
        return (
            isinstance(source, tuple)
            and len(source) >= 3
            and source[0] == "expr"
            and isinstance(source[2], tuple)
            and bool(source[2])
        )



    def _is_scalar_global_high_byte_carrier_remnant_8616(self, stmt: StructuredAstValue) -> bool:
        if self._statement_contains_call(stmt):
            return False
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return False
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None or self._assignment_lhs_writes_memory(lhs):
            return False
        if lhs.__class__.__name__ != "CDirtyExpression" and _stack_carrier_key_8616(lhs) is None:
            return False
        return self._rhs_is_safe_push_alias_artifact_8616(rhs) or self._rhs_is_dirty_stack_pointer_arithmetic_8616(rhs)



    def _setup_window_assignment_shape_is_prunable_8616(self,
        candidate_lhs: StructuredAstValue,
        candidate_rhs: StructuredAstValue,
        call_node: StructuredAstValue,
        *,
        allow_unreferenced_stack_dirty: bool,
    ) -> bool:
        if candidate_lhs is None or candidate_rhs is None:
            return False
        if candidate_lhs.__class__.__name__ == "CDirtyExpression":
            return self._rhs_is_safe_pre_call_setup_artifact_8616(candidate_rhs)
        lhs_offset = self._stack_variable_offset_8616(candidate_lhs)
        lhs_key = self._c_variable_identity_key_8616(candidate_lhs)
        return (
            isinstance(lhs_offset, int)
            and lhs_key is not None
            and (allow_unreferenced_stack_dirty or self._call_args_reference_identity(call_node, lhs_key))
            and self._expr_contains_dirty_carrier_for_setup_8616(candidate_rhs)
            and self._rhs_is_safe_pre_call_setup_artifact_8616(candidate_rhs)
        )



    def flatten(self, term: StructuredAstValue, sign: int = 1) -> StructuredAstValue:
        while isinstance(term, CTypeCast):
            term = term.expr
        if isinstance(term, CBinaryOp) and term.op == "Add":
            return self.flatten(term.lhs, sign) + self.flatten(term.rhs, sign)
        if isinstance(term, CBinaryOp) and term.op == "Sub":
            return self.flatten(term.lhs, sign) + self.flatten(term.rhs, -sign)
        return [(term, sign)]



    def _is_register_expr_by_offset(self, node: StructuredAstValue, reg_name: str) -> bool:
        node = self._strip_casts(node)
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            return False
        reg = variable.reg
        arch_reg_name = getattr(getattr(self.project, "arch", None), "register_names", {}).get(reg)
        return isinstance(arch_reg_name, str) and arch_reg_name.lower() == reg_name.lower()



    def _expr_int_constants(self, node: StructuredAstValue) -> set[int]:
        values: set[int] = set()
        for current in (node, *_iter_c_nodes_deep_8616(node)):
            if isinstance(current, structured_c.CConstant):
                value = current.value
                if isinstance(value, int):
                    values.add(value)
        return values



    def _is_index_register_expr_8616(self, expr: StructuredAstValue) -> bool:
        node = self._strip_arg_casts(expr)
        if self._is_plain_register_value_expr(node):
            return True
        if isinstance(node, CBinaryOp) and getattr(node, "op", None) == "Mul":
            return (self._is_plain_register_value_expr(node.lhs) and self._constant_int_value(node.rhs) is not None) or (
                self._is_plain_register_value_expr(node.rhs) and self._constant_int_value(node.lhs) is not None
            )
        return False



    def _combined_unknown_low_high_target(self, node: StructuredAstValue, high_expr: StructuredAstValue) -> bool:
        node = self._strip_casts(node)
        if not isinstance(node, CBinaryOp) or getattr(node, "op", None) != "Or":
            return False
        lhs = self._strip_casts(getattr(node, "lhs", None))
        rhs = self._strip_casts(getattr(node, "rhs", None))
        rhs_shift_source = self._shift16_source(rhs)
        if rhs_shift_source is not None:
            return _same_c_expression_8616(rhs_shift_source, high_expr) or self._is_register_expr_by_offset(
                rhs_shift_source, "dx"
            )
        lhs_shift_source = self._shift16_source(lhs)
        if lhs_shift_source is not None:
            return _same_c_expression_8616(lhs_shift_source, high_expr) or self._is_register_expr_by_offset(
                lhs_shift_source, "dx"
            )
        return False



    def _stack_address_arg_offset_8616(self, expr: StructuredAstValue) -> int | None:
        node = self._strip_arg_casts(expr)
        if not isinstance(node, CUnaryOp) or getattr(node, "op", None) not in {"Reference", "AddressOf"}:
            return None
        operand = self._strip_arg_casts(getattr(node, "operand", None))
        variable = getattr(operand, "variable", None)
        offset = getattr(variable, "offset", None)
        return int(offset) if isinstance(variable, SimStackVariable) and isinstance(offset, int) else None



    def _rhs_is_byte_proven_dirty_push_alias_artifact_8616(self, rhs: StructuredAstValue) -> bool:
        if self._statement_contains_call(rhs):
            return False
        has_dirty = False
        for node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                return False
            if node.__class__.__name__ == "CDirtyExpression":
                has_dirty = True
        return has_dirty



    def _has_simple_bp_arithmetic_push_source(self, source: StructuredAstValue) -> bool:
        """Return true only for exact stack-slot arithmetic push facts."""
        if not (
            isinstance(source, tuple)
            and len(source) >= 3
            and source[0] == "expr"
            and isinstance(source[1], tuple)
            and len(source[1]) >= 2
            and source[1][0] == "bp"
            and isinstance(source[1][1], int)
            and isinstance(source[2], tuple)
            and source[2]
        ):
            return False
        return all(
            isinstance(op, tuple)
            and len(op) == 2
            and op[0] in {CallsitePushExprOp8616.ADD.value, CallsitePushExprOp8616.SUB.value}
            and isinstance(op[1], int)
            for op in source[2]
        )



    def standalone_call_from_statement(self, stmt: StructuredAstValue) -> StructuredAstValue:
        if isinstance(stmt, CFunctionCall):
            return stmt
        expr = getattr(stmt, "expr", None)
        if isinstance(expr, CFunctionCall):
            return expr
        nested = getattr(stmt, "statements", None)
        if isinstance(nested, (list, tuple)) and len(nested) == 1:
            return self.standalone_call_from_statement(nested[0])
        return None



    def _global_word_high_byte_source_offset_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        shift_value = getattr(getattr(node, "rhs", None), "value", None)
        if not isinstance(node, CBinaryOp) or node.op != "Shr" or shift_value != 8:
            return None
        lhs = getattr(node, "lhs", None)
        offset = self._global_word_expr_offset_8616(lhs)
        if offset is not None:
            return offset
        while isinstance(lhs, CTypeCast):
            lhs = lhs.expr
        if isinstance(lhs, structured_c.CVariable):
            variable = lhs.variable
            addr = getattr(variable, "addr", None)
            if isinstance(variable, SimMemoryVariable) and isinstance(addr, int):
                return addr & 0xFFFF
        return None



    def _is_far_pointer_byte_store_source_8616(self, source: StructuredAstValue) -> bool:
        if self._is_segment_register_value_expr(source):
            return True
        if self._rhs_is_safe_push_alias_artifact_8616(source):
            return True
        return self._rhs_is_dirty_far_pointer_value_artifact_8616(source)



    def _ifelse_branch_symbol_names_for_offset_8616(self, stmt: structured_c.CIfElse, offset: int) -> set[str]:
        names: set[str] = set()
        for _cond, child in _boundary_tuple_8616(getattr(stmt, "condition_and_nodes", ()) or ()):
            for assignment in self._iter_assignment_nodes(child):
                lhs, rhs = self._assignment_lhs_rhs(assignment)
                if self._stack_offset_from_cvar_8616(lhs) == offset:
                    name = self._symbol_name_8616(rhs)
                    if name is not None:
                        names.add(name)
        else_node = getattr(stmt, "else_node", None)
        if else_node is not None:
            for assignment in self._iter_assignment_nodes(else_node):
                lhs, rhs = self._assignment_lhs_rhs(assignment)
                if self._stack_offset_from_cvar_8616(lhs) == offset:
                    name = self._symbol_name_8616(rhs)
                    if name is not None:
                        names.add(name)
        return names



    def _debug_assignment_tuple_8616(self,
        assignment: StructuredAstValue,
    ) -> tuple[
        tuple[str, str | None, int | None, int | None],
        tuple[str, str | None, int | None, int | None],
    ]:
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        return (self._debug_expr_name_offset_value_8616(lhs), self._debug_expr_name_offset_value_8616(rhs))



    def _assignment_is_stale_post_branch_fnptr_overwrite_8616(self,
        stmt: StructuredAstValue, offset: int, symbol_names: set[str]
    ) -> bool:
        assignments = tuple(self._iter_assignment_nodes(stmt))
        if len(assignments) != 1:
            return False
        assignment = assignments[0]
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if self._stack_offset_from_cvar_8616(lhs) != offset:
            return False
        rhs_symbol = self._symbol_name_8616(rhs)
        if rhs_symbol in symbol_names:
            return False
        return all(not isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(stmt))



    def _shift16_source(self, node: StructuredAstValue) -> StructuredAstValue | None:
        node = self._strip_casts(node)
        if not isinstance(node, CBinaryOp) or getattr(node, "op", None) not in {"Shl", "LShift"}:
            return None
        if self._constant_value(getattr(node, "rhs", None)) != 16:
            return None
        return self._strip_casts(getattr(node, "lhs", None))



    def _fold_later_stale_return_pair_by_preorder_8616(self,
        container: list[StructuredAstValue], seen_destinations: list[StructuredAstValue]
    ) -> bool:

        changed_local = False
        idx = 0
        while idx < len(container):
            stmt = container[idx]
            lhs, rhs = self._assignment_lhs_rhs_local(stmt)
            low_expr = self._register_expr_from_name_8616("ax")
            high_expr = self._register_expr_from_name_8616("dx")
            if (
                self._stale_return_pair_candidate_8616(lhs, rhs, low_expr, high_expr, seen_destinations)
            ):
                del container[idx]
                self.codegen._inertia_dx_ax_return_pair_assignments_folded_8616 = (
                    int(getattr(self.codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) or 0) + 1
                )
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    log.warning(
                        "[call-dx-ax-return-pair-fold] function=%#x preorder_stale_destination=%s",
                        getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                        self._debug_expr_8616(lhs),
                    )
                changed_local = True
                continue
            if lhs is not None and isinstance(rhs, CFunctionCall) and self._call_has_dx_ax_destination_proof_8616(rhs):
                seen_destinations.append(lhs)
            nested = getattr(stmt, "statements", None)
            if isinstance(nested, list) and self._fold_later_stale_return_pair_by_preorder_8616(
                nested,
                seen_destinations,
            ):
                changed_local = True
            idx += 1
        return changed_local



    def _constant_value(self, node: StructuredAstValue) -> int | None:
        node = self._strip_casts(node)
        if isinstance(node, structured_c.CConstant):
            value = node.value
            return int(value) if isinstance(value, int) else None
        return None



    def _rhs_is_safe_pre_call_setup_artifact_8616(self, expr: StructuredAstValue) -> bool:
        expr_id = id(expr)
        cached = self.rhs_safe_pre_call_setup_cache.get(expr_id)
        if cached is not None:
            return cached
        if self._statement_contains_call(expr):
            self.rhs_safe_pre_call_setup_cache[expr_id] = False
            return False
        for node in (expr, *_iter_c_nodes_deep_8616(expr)):
            if isinstance(node, CFunctionCall):
                self.rhs_safe_pre_call_setup_cache[expr_id] = False
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                self.rhs_safe_pre_call_setup_cache[expr_id] = False
                return False
        self.rhs_safe_pre_call_setup_cache[expr_id] = True
        return True



    def _push_source_has_binary_evidence_in_call_window_8616(self,
        source: StructuredAstValue, callsite_addr: int
    ) -> bool:
        for evidence_ins_addr in range(callsite_addr - 1, callsite_addr - 17, -1):
            if (
                isinstance(source, tuple)
                and len(source) >= 2
                and source[0] == "imm"
                and _mov_reg_imm_setup_matches_push_source_8616(self.project, evidence_ins_addr, source)
            ):
                return True
            if (
                isinstance(source, tuple)
                and len(source) >= 1
                and source[0] == "expr"
                and _reg_expr_setup_matches_push_source_8616(self.project, evidence_ins_addr, source)
            ):
                return True
        return False



    def _global_word_push_source_offsets_8616(self,
        push_sources: tuple[StructuredAstValue, ...],
    ) -> set[int]:
        offsets: set[int] = set()
        if not isinstance(push_sources, tuple):
            return offsets
        for source in push_sources:
            info = self._global_word_source_info_8616(source)
            if info is None:
                continue
            offset, ops = info
            if not ops:
                offsets.add(offset & 0xFFFF)
        return offsets



    def _stack_slot_write_token_for_stmt_8616(self, stmt: StructuredAstValue) -> str | None:
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return None
        lhs, _rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None:
            return None
        offset = self._stack_variable_offset_8616(lhs)
        if not isinstance(offset, int):
            return None
        variable = getattr(lhs, "variable", None)
        size = getattr(variable, "size", None)
        if not isinstance(size, int) or size <= 0:
            size = 2
        sign = "+" if offset >= 0 else "-"
        return f"stack_slot:SS:BP{sign}0x{abs(offset):x}:size{int(size)}"



    def _expr_contains_dirty_carrier_8616(self, expr: StructuredAstValue) -> bool:
        for node in (expr, *_iter_c_nodes_deep_8616(expr)):
            if node.__class__.__name__ == "CDirtyExpression":
                return True
        return False



    def _fold_stale_return_pair_8616(self,
        container: list[StructuredAstValue],
        idx: int,
        lhs: StructuredAstValue,
        rhs: StructuredAstValue,
        seen_call_destinations: list[StructuredAstValue],
    ) -> bool:
        """Fold a stale post-call DX:AX pair re-assignment at ``idx``; return True when removed."""
        low_expr = self._register_expr_from_name_8616("ax")
        high_expr = self._register_expr_from_name_8616("dx")
        if not (
            low_expr is not None
            and high_expr is not None
            and any(self._same_return_destination_8616(lhs, seen_lhs) for seen_lhs in seen_call_destinations)
            and (
                self._combined_low_high_target(rhs, low_expr, high_expr)
                or self._combined_unknown_low_high_target(rhs, high_expr)
            )
        ):
            return False
        del container[idx]
        self.codegen._inertia_dx_ax_return_pair_assignments_folded_8616 = (
            int(getattr(self.codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) or 0) + 1
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-dx-ax-return-pair-fold] function=%#x later_stale_destination=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                self._debug_expr_8616(lhs),
            )
        return True

    def _fold_adjacent_return_pair_8616(self,
        container: list[StructuredAstValue],
        idx: int,
        lhs: StructuredAstValue,
        seen_call_destinations: list[StructuredAstValue],
    ) -> bool:
        """Fold an adjacent stale DX:AX pair after the call store at ``idx``; return True when folded."""
        low_expr = self._register_expr_from_name_8616("ax")
        high_expr = self._register_expr_from_name_8616("dx")
        combine_idx = self._next_nonempty_index(container, idx + 1)
        if low_expr is None or high_expr is None or combine_idx >= len(container):
            return False
        target_lhs, combine_rhs = self._assignment_lhs_rhs_local(container[combine_idx])
        if not self._same_return_destination_8616(lhs, target_lhs):
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-dx-ax-return-pair-refuse] function=%#x reason=destination-mismatch call_lhs=%s call_key=%r combine_lhs=%s combine_key=%r combine_rhs=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    self._debug_expr_8616(lhs),
                    _call_arg_semantic_key_8616(lhs),
                    self._debug_expr_8616(target_lhs),
                    _call_arg_semantic_key_8616(target_lhs),
                    self._debug_expr_8616(combine_rhs),
                )
            return False
        if not self._combined_low_high_target(combine_rhs, low_expr, high_expr):
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                log.warning(
                    "[call-dx-ax-return-pair-refuse] function=%#x reason=combine-mismatch destination=%s combine_rhs=%s low=%s high=%s",
                    getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                    self._debug_expr_8616(lhs),
                    self._debug_expr_8616(combine_rhs),
                    self._debug_expr_8616(low_expr),
                    self._debug_expr_8616(high_expr),
                )
            return False
        del container[idx + 1 : combine_idx + 1]
        self.codegen._inertia_dx_ax_return_pair_assignments_folded_8616 = (
            int(getattr(self.codegen, "_inertia_dx_ax_return_pair_assignments_folded_8616", 0) or 0) + 1
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-dx-ax-return-pair-fold] function=%#x adjacent_stale_destination=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                self._debug_expr_8616(lhs),
            )
        return True

    def _fold_adjacent_stale_return_pair_after_destination_call_8616(self, container: list[StructuredAstValue]) -> bool:
        changed_local = False
        seen_call_destinations: list[StructuredAstValue] = []
        idx = 0
        while idx < len(container):
            lhs, rhs = self._assignment_lhs_rhs_local(container[idx])
            if lhs is None:
                idx += 1
                continue
            if not isinstance(rhs, CFunctionCall):
                if self._fold_stale_return_pair_8616(container, idx, lhs, rhs, seen_call_destinations):
                    changed_local = True
                    continue
                idx += 1
                continue
            changed_local = self._fold_adjacent_return_pair_8616(
                container, idx, lhs, seen_call_destinations
            ) or changed_local
            seen_call_destinations.append(lhs)
            idx += 1
        return changed_local



    def _debug_expr_name_offset_value_8616(self,
        expr: StructuredAstValue,
    ) -> tuple[str, str | None, int | None, int | None]:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        offset = getattr(variable, "offset", None) if isinstance(variable, SimStackVariable) else None
        value = getattr(node, "value", None) if isinstance(node, structured_c.CConstant) else None
        return (
            type(node).__name__ if node is not None else "None",
            name if isinstance(name, str) else None,
            offset if isinstance(offset, int) else None,
            value if isinstance(value, int) else None,
        )



    def _branch_node_is_empty_8616(self, node: StructuredAstValue) -> bool:
        return node is not None and not _boundary_tuple_8616(getattr(node, "statements", ()) or ())



    def _strip_arg_casts(self, node: StructuredAstValue) -> StructuredAstValue:
        while isinstance(node, CTypeCast):
            node = node.expr
        return node



    def _push_source_is_arithmetic_expr_8616(self, source: StructuredAstValue) -> bool:
        return (
            isinstance(source, tuple)
            and len(source) == 3
            and source[0] == "expr"
            and isinstance(source[1], tuple)
            and isinstance(source[2], tuple)
            and source[2] != ()
        )



    def _guard_stack_address_offset_arg_base_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CBinaryOp) or node.op not in {"Add", "Sub"}:
            return None
        lhs = node.lhs
        rhs = node.rhs
        lhs_offset = self._guard_stack_address_arg_offset_8616(lhs)
        if lhs_offset is not None:
            return lhs_offset
        lhs_offset = self._stack_offset_from_cvar_8616(lhs)
        if lhs_offset is not None:
            return lhs_offset
        if getattr(node, "op", None) == "Add":
            rhs_offset = self._guard_stack_address_arg_offset_8616(rhs)
            if rhs_offset is not None:
                return rhs_offset
            return self._stack_offset_from_cvar_8616(rhs)
        return None



    def _contains_unsafe_dirty_term(self, term: StructuredAstValue) -> bool:
        nodes = (term, *_iter_c_nodes_deep_8616(term))
        for raw_node in nodes:
            if raw_node.__class__.__name__ == "CDirtyExpression":
                if self._is_virtual_dirty_expr_8616(raw_node):
                    continue
                return True
        return False



    def _flatten_add_sub(self, value_node: StructuredAstValue, sign: int = 1) -> list[tuple[StructuredAstValue, int]]:
        value_node = self._unary_unwrap(value_node)
        if isinstance(value_node, CBinaryOp) and value_node.op == "Add":
            return self._flatten_add_sub(value_node.lhs, sign) + self._flatten_add_sub(value_node.rhs, sign)
        if isinstance(value_node, CBinaryOp) and value_node.op == "Sub":
            return self._flatten_add_sub(value_node.lhs, sign) + self._flatten_add_sub(value_node.rhs, -sign)
        return [(value_node, sign)]



    def single_nested_statement(self, stmt: StructuredAstValue) -> StructuredAstValue:
        nested = getattr(stmt, "statements", None)
        if isinstance(nested, (list, tuple)) and len(nested) == 1:
            return nested[0]
        return stmt



    def _assignment_semantic_copy_key_8616(self, candidate: StructuredAstValue) -> StructuredAstValue:
        assignment = self._top_level_assignment_node_8616(candidate)
        if assignment is None or self._statement_contains_call(assignment):
            return None
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        if lhs is None or rhs is None:
            return None
        if self._assignment_lhs_writes_memory(lhs) and self._stack_variable_offset_8616(lhs) is None:
            return None
        if not self._rhs_is_safe_to_relocate_after_call_8616(rhs):
            return None
        lhs_key = self._c_variable_identity_key_8616(lhs)
        rhs_key = self._c_variable_identity_key_8616(rhs)
        if lhs_key is None:
            return None
        return lhs_key, rhs_key, lhs, rhs



    def _is_scalar_global_low_byte_store_remnant_8616(self,
        stmt: StructuredAstValue, push_sources: tuple[StructuredAstValue, ...], call_node: StructuredAstValue
    ) -> bool:
        assignment = self._top_level_assignment_node_8616(stmt)
        if assignment is None:
            return False
        lhs, rhs = self._assignment_lhs_rhs(assignment)
        lhs_is_dirty_memory_candidate = lhs is not None and lhs.__class__.__name__ == "CDirtyExpression"
        if (
            lhs is None
            or rhs is None
            or not (self._assignment_lhs_writes_memory(lhs) or lhs_is_dirty_memory_candidate)
        ):
            return False
        source_offset = self._global_word_low_byte_source_offset_8616(rhs)
        if source_offset is None:
            return False
        if source_offset not in self._global_word_push_source_offsets_8616(push_sources):
            return False
        if not self._call_args_reference_global_word_8616(call_node, source_offset):
            return False
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            log.warning(
                "[call-scalar-low-byte-remnant] matched function=%#x target=%s source=%#x shape=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", 0) or 0,
                _call_node_name_8616(call_node),
                source_offset,
                self._debug_node_shape_8616(stmt),
            )
        return True



    def _is_stale_high_byte_mask(self, node: StructuredAstValue) -> bool:
        node = self._strip_arg_casts(node)
        if not isinstance(node, CBinaryOp) or node.op != "And":
            return False
        return self._constant_int_value(node.lhs) == 0xFF00 or self._constant_int_value(node.rhs) == 0xFF00



    def _constant_int_value_8616(self, expr: StructuredAstValue) -> int | None:
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        value = getattr(node, "value", None) if node is not None else None
        return int(value) if isinstance(value, int) else None



    def _push_sources_have_binary_setup_window_evidence_8616(self,
        window_callsite_addr: int, window_push_sources: tuple[StructuredAstValue, ...]
    ) -> bool:
        bp_expr_sources = tuple(
            source
            for source in window_push_sources
            if isinstance(source, tuple)
            and len(source) >= 1
            and source[0] == "expr"
            and _bp_offsets_from_push_source_8616(source)
        )
        if not bp_expr_sources:
            return False
        evidence_sources = tuple(
            source
            for source in window_push_sources
            if (
                isinstance(source, tuple) and len(source) >= 1 and (source[0] == "imm" or source in bp_expr_sources)
            )
        )
        return bool(evidence_sources) and all(
            self._push_source_has_binary_evidence_in_call_window_8616(source, window_callsite_addr)
            for source in evidence_sources
        )



    def _rhs_is_safe_far_pointer_carrier_artifact_8616(self, rhs: StructuredAstValue) -> bool:
        if self._statement_contains_call(rhs):
            return False
        for node in (rhs, *_iter_c_nodes_deep_8616(rhs)):
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
                return False
        return True



    def _call_has_dx_ax_destination_proof_8616(self, call: StructuredAstValue) -> bool:
        summary = self.summary_map.get(id(call)) if call is not None else None
        if summary is None or summary.return_used is not True or summary.return_register not in {None, "ax"}:
            return False
        return summary.return_shape == "dx_ax" or isinstance(
            summary.return_store_destination,
            tuple,
        )


def _materialize_callsite_stack_arguments_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    return _CallsiteStackArgsMaterializer8616(project, codegen).run()


def replay_callsite_stack_arguments_after_regeneration_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Replay source/summary-backed call argument materialization after text regeneration.

    angr's ``regenerate_text()`` may rebuild the structured C tree from older
    codegen state. Callsite materialization is evidence-backed by persisted
    callsite summaries, so replaying it immediately after regeneration keeps the
    emitted tree aligned with the validated semantic tree without using rendered
    C text as input.
    """
    if getattr(codegen, "_inertia_callsite_arg_regen_replay_active_8616", False):
        return False
    project = project or getattr(codegen, "project", None)
    arch_name = getattr(getattr(project, "arch", None), "name", None)
    if arch_name != "86_16":
        return False
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict) or not summary_map:
        return False
    if getattr(codegen, "cfunc", None) is None:
        return False

    codegen._inertia_callsite_arg_regen_replay_active_8616 = True
    try:
        changed = bool(_attach_callsite_summaries_8616(project, codegen))
        changed = bool(_replay_call_target_identity_consumer_8616(project, codegen)) or changed
        # Dynamic angr/codegen compatibility boundary. Regeneration and later
        # simplification may mutate arguments without changing summary identity,
        # so an explicit replay must recheck the live tree instead of accepting
        # the summary-only materialization cache key.
        codegen._inertia_callsite_materialization_complete_8616 = False
        changed = bool(_materialize_callsite_stack_arguments_8616(project, codegen)) or changed
    finally:
        codegen._inertia_callsite_arg_regen_replay_active_8616 = False

    count_attr = "_inertia_callsite_arg_regen_replay_count_8616"
    changed_attr = "_inertia_callsite_arg_regen_replay_changed_count_8616"
    setattr(codegen, count_attr, int(getattr(codegen, count_attr, 0) or 0) + 1)
    if changed:
        setattr(codegen, changed_attr, int(getattr(codegen, changed_attr, 0) or 0) + 1)
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


def _rhs_is_dirty_stack_pointer_arithmetic_8616(rhs: StructuredAstValue) -> bool:
    """Return whether the RHS is dirty-expression stack-pointer arithmetic."""
    node = rhs
    while isinstance(node, CTypeCast):
        node = node.expr
    if node is None:
        return False
    if node.__class__.__name__ == "CDirtyExpression":
        return True
    if isinstance(node, structured_c.CConstant):
        return True
    if isinstance(node, CBinaryOp):
        return _rhs_is_dirty_stack_pointer_arithmetic_8616(
            node.lhs
        ) and _rhs_is_dirty_stack_pointer_arithmetic_8616(node.rhs)
    return False


def _rhs_is_safe_value_artifact_8616(rhs: StructuredAstValue) -> bool:
    """Return whether the RHS contains only value-safe artifacts."""
    for child in (rhs, *_iter_c_nodes_deep_8616(rhs)):
        if isinstance(child, CFunctionCall):
            return False
        if isinstance(child, CUnaryOp) and getattr(child, "op", None) == "Dereference":
            return False
    return True


def _safe_carrier_lhs_children_ok_8616(lhs: StructuredAstValue) -> bool:
    """Whether the carrier lhs subtree is free of calls, dereferences, and memory vars."""
    for lhs_child in (lhs, *_iter_c_nodes_deep_8616(lhs)):
        if isinstance(lhs_child, CFunctionCall):
            return False
        if isinstance(lhs_child, CUnaryOp) and getattr(lhs_child, "op", None) == "Dereference":
            return False
        variable = getattr(lhs_child, "variable", None)
        if isinstance(variable, SimMemoryVariable):
            return False
    return True


def _is_safe_carrier_stmt_8616(stmt: StructuredAstValue) -> bool:
    """Return whether the statement is a removable scalar carrier assignment."""
    if _hb_statement_contains_call(stmt):
        return False
    assignment = _hb_top_level_assignment(stmt)
    if assignment is None:
        return False
    lhs, rhs = _hb_assignment_lhs_rhs(assignment)
    if lhs is None or rhs is None:
        return False
    node = lhs
    while isinstance(node, CTypeCast):
        node = node.expr
    lhs_is_dirty_carrier = node.__class__.__name__ == "CDirtyExpression"
    if not lhs_is_dirty_carrier and _stack_carrier_key_8616(node) is None:
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        if not (isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_"))):
            return False
    if not lhs_is_dirty_carrier and not _safe_carrier_lhs_children_ok_8616(lhs):
        return False
    return _rhs_is_safe_value_artifact_8616(rhs) or _rhs_is_dirty_stack_pointer_arithmetic_8616(rhs)


def _hb_call_name(call: StructuredAstValue) -> str | None:
    name = getattr(call, "callee_target", None)
    if isinstance(name, str) and name:
        return name
    name = getattr(getattr(call, "callee_func", None), "name", None)
    return name if isinstance(name, str) and name else None


def _hb_call_from_statement(stmt: StructuredAstValue) -> StructuredAstValue:
    if isinstance(stmt, CFunctionCall):
        return stmt
    for attr in ("expr", "rhs", "src"):
        value = getattr(stmt, attr, None)
        if isinstance(value, CFunctionCall):
            return value
    nested = getattr(stmt, "statements", None)
    if isinstance(nested, (list, tuple)) and len(nested) == 1:
        return _hb_call_from_statement(nested[0])
    return None


def _hb_statement_contains_call(stmt: StructuredAstValue) -> bool:
    if isinstance(stmt, CFunctionCall):
        return True
    return any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(stmt))


def _hb_is_assignment(node: StructuredAstValue) -> bool:
    if node is None:
        return False
    class_name = node.__class__.__name__
    return (
        class_name == "CAssignment"
        or class_name.endswith("Assignment")
        or (hasattr(node, "dst") and hasattr(node, "src"))
    )


def _hb_assignment_lhs_rhs(node: StructuredAstValue) -> StructuredAstValue:
    lhs = getattr(node, "lhs", None)
    rhs = getattr(node, "rhs", None)
    if lhs is None and hasattr(node, "dst"):
        lhs = getattr(node, "dst", None)
        rhs = getattr(node, "src", None)
    return lhs, rhs


def _hb_top_level_assignment(stmt: StructuredAstValue) -> StructuredAstValue:
    if _hb_is_assignment(stmt):
        return stmt
    nested = getattr(stmt, "statements", None)
    if isinstance(nested, (list, tuple)) and len(nested) == 1 and _hb_is_assignment(nested[0]):
        return nested[0]
    return None


def _hb_function_call_name_is(node: StructuredAstValue, wanted: str) -> bool:
    return isinstance(node, CFunctionCall) and (_hb_call_name(node) or "").upper() == wanted


def _hb_constant_int(expr: StructuredAstValue) -> int | None:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    value = getattr(node, "value", None) if node is not None else None
    return int(value) if isinstance(value, int) else None


def _hb_global_word_expr_offset(expr: StructuredAstValue) -> int | None:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, structured_c.CVariable):
        variable = node.variable
        addr = getattr(variable, "addr", None)
        width = getattr(variable, "size", None)
        if isinstance(variable, SimMemoryVariable) and isinstance(addr, int) and int(width or 0) in {0, 1, 2}:
            return addr & 0xFFFF
    pair_offset = _hb_global_word_byte_pair_offset(node)
    if pair_offset is not None:
        return pair_offset
    if isinstance(node, CFunctionCall) and _hb_function_call_name_is(node, "SEG_U16"):
        args = _boundary_tuple_8616(node.args or ())
        if len(args) == 2:
            offset = _hb_constant_int(args[1])
            if offset is not None:
                return offset & 0xFFFF
    return None


def _hb_global_byte_expr_offset(expr: StructuredAstValue) -> int | None:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, structured_c.CVariable):
        variable = node.variable
        addr = getattr(variable, "addr", None)
        if isinstance(variable, SimMemoryVariable) and isinstance(addr, int):
            return addr & 0xFFFF
    return None


def _hb_global_scaled_byte_expr_offset(expr: StructuredAstValue) -> int | None:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Mul":
        if _hb_constant_int(node.lhs) == 256:
            return _hb_global_byte_expr_offset(node.rhs)
        if _hb_constant_int(node.rhs) == 256:
            return _hb_global_byte_expr_offset(node.lhs)
    if node.op == "Shl" and _hb_constant_int(node.rhs) == 8:
        return _hb_global_byte_expr_offset(node.lhs)
    return None


def _hb_global_word_byte_pair_offset(expr: StructuredAstValue) -> int | None:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp) or getattr(node, "op", None) != "Or":
        return None
    low_offset = _hb_global_byte_expr_offset(getattr(node, "lhs", None))
    high_offset = _hb_global_scaled_byte_expr_offset(getattr(node, "rhs", None))
    if low_offset is None or high_offset is None:
        low_offset = _hb_global_byte_expr_offset(getattr(node, "rhs", None))
        high_offset = _hb_global_scaled_byte_expr_offset(getattr(node, "lhs", None))
    if low_offset is None or high_offset is None or high_offset != low_offset + 1:
        return None
    return low_offset & 0xFFFF


def _hb_global_high_byte_source_offset(expr: StructuredAstValue) -> int | None:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp) or getattr(node, "op", None) != "Shr":
        return None
    if _hb_constant_int(getattr(node, "rhs", None)) != 8:
        return None
    lhs = getattr(node, "lhs", None)
    offset = _hb_global_word_expr_offset(lhs)
    if offset is not None:
        return offset
    while isinstance(lhs, CTypeCast):
        lhs = lhs.expr
    if isinstance(lhs, structured_c.CVariable):
        variable = lhs.variable
        addr = getattr(variable, "addr", None)
        if isinstance(variable, SimMemoryVariable) and isinstance(addr, int):
            return addr & 0xFFFF
    return None


def _hb_call_args_reference_global_word(call: StructuredAstValue, offset: int) -> bool:
    for arg in _boundary_tuple_8616(getattr(call, "args", ()) or ()):
        for node in (arg, *_iter_c_nodes_deep_8616(arg)):
            if _hb_global_word_expr_offset(node) == (offset & 0xFFFF):
                return True
    return False


def _hb_summary_direct_global_word_offsets(summary: StructuredAstValue) -> set[int]:
    offsets: set[int] = set()
    for source in _boundary_tuple_8616(summary.push_arg_sources or ()):
        if (
            isinstance(source, tuple)
            and len(source) >= 3
            and source[0] == CallsitePushSourceKind8616.GLOBAL_VALUE.value
            and isinstance(source[1], int)
            and int(source[2] or 0) == 2
        ):
            offsets.add(int(source[1]) & 0xFFFF)
    return offsets


def _hb_lhs_is_segmented_byte_store(lhs: StructuredAstValue) -> bool:
    if isinstance(lhs, CFunctionCall) and _hb_function_call_name_is(lhs, "SEG_U8"):
        return True
    return any(
        isinstance(node, CFunctionCall) and _hb_function_call_name_is(node, "SEG_U8")
        for node in _iter_c_nodes_deep_8616(lhs)
    )


def _hb_scalar_high_byte_store_source(
    stmt: StructuredAstValue, call: StructuredAstValue, push_offsets: set[int]
) -> int | None:
    assignment = _hb_top_level_assignment(stmt)
    if assignment is None:
        return None
    lhs, rhs = _hb_assignment_lhs_rhs(assignment)
    if lhs is None or rhs is None or not _hb_lhs_is_segmented_byte_store(lhs):
        return None
    source_offset = _hb_global_high_byte_source_offset(rhs)
    if source_offset is None or source_offset not in push_offsets:
        return None
    return source_offset if _hb_call_args_reference_global_word(call, source_offset) else None


def _hb_debug_stmt_shape(stmt: StructuredAstValue) -> str:
    assignment = _hb_top_level_assignment(stmt)
    lhs, rhs = _hb_assignment_lhs_rhs(assignment) if assignment is not None else (None, None)
    lhs_calls = tuple(
        _hb_call_name(node) for node in (lhs, *_iter_c_nodes_deep_8616(lhs)) if isinstance(node, CFunctionCall)
    )
    rhs_source = _hb_global_high_byte_source_offset(rhs)
    return (
        f"{type(stmt).__name__}:assign={type(assignment).__name__ if assignment is not None else None}:"
        f"lhs={type(lhs).__name__ if lhs is not None else None}:rhs={type(rhs).__name__ if rhs is not None else None}:"
        f"lhs_calls={lhs_calls}:rhs_source={rhs_source}"
    )


def _hb_is_safe_carrier(stmt: StructuredAstValue) -> bool:
    return _is_safe_carrier_stmt_8616(stmt)


def _hb_is_sequence_wrapper(stmt: StructuredAstValue) -> bool:
    return stmt.__class__.__name__ == "CStatements" and isinstance(getattr(stmt, "statements", None), (list, tuple))


def _hb_sequence_leaf_entries(
    owner: StructuredAstValue,
) -> list[tuple[StructuredAstValue, int, StructuredAstValue]]:
    entries: list[tuple[StructuredAstValue, int, StructuredAstValue]] = []

    def collect(parent: StructuredAstValue) -> None:
        children = getattr(parent, "statements", None)
        if not isinstance(children, (list, tuple)):
            return
        for index, child in enumerate(children):
            if _hb_is_sequence_wrapper(child):
                collect(child)
            else:
                entries.append((parent, index, child))

    collect(owner)
    return entries


def _hb_delete_indexed_statements(
    removals: dict[int, tuple[StructuredAstValue, set[int]]],
) -> int:
    removed_count = 0
    for parent, indexes in removals.values():
        statements = getattr(parent, "statements", None)
        if not isinstance(statements, (list, tuple)):
            continue
        items = list(statements)
        for index in sorted(indexes, reverse=True):
            if 0 <= index < len(items):
                del items[index]
                removed_count += 1
        parent.statements = items if isinstance(statements, list) else tuple(items)
    return removed_count


def _hb_removable_flat_scan(
    flat: StructuredAstValue,
    index: int,
    call: StructuredAstValue,
    push_offsets: StructuredAstValue,
) -> list[int]:
    scan = index - 1
    pending_carriers: list[int] = []
    removable_flat_indexes: list[int] = []
    while scan >= 0 and index - scan <= 8:
        candidate = flat[scan][2]
        store_source = _hb_scalar_high_byte_store_source(candidate, call, push_offsets)
        if store_source is not None:
            removable_flat_indexes.append(scan)
            removable_flat_indexes.extend(pending_carriers)
            scan -= 1
            while scan >= 0 and index - scan <= 8 and _hb_is_safe_carrier(flat[scan][2]):
                removable_flat_indexes.append(scan)
                scan -= 1
            break
        if _hb_statement_contains_call(candidate):
            break
        if _hb_is_safe_carrier(candidate):
            pending_carriers.append(scan)
            scan -= 1
            continue
        break
    return removable_flat_indexes


def _hb_prune_flat_sequence_remnants(owner: StructuredAstValue, *, codegen: StructuredAstValue, summary_map: StructuredAstValue) -> bool:
    flat = _hb_sequence_leaf_entries(owner)
    if len(flat) < 2:
        return False
    removals: dict[int, tuple[StructuredAstValue, set[int]]] = {}

    for index, (_parent, _child_index, stmt) in enumerate(flat):
        call = _hb_call_from_statement(stmt)
        summary = summary_map.get(id(call)) if call is not None else None
        push_offsets = _hb_summary_direct_global_word_offsets(summary) if summary is not None else set()
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION") and call is not None:
            log.warning(
                "[call-scalar-final-prune-flat] call=%s summary=%s push_offsets=%r idx=%d prev=%r",
                _hb_call_name(call),
                summary is not None,
                tuple(sorted(push_offsets)),
                index,
                tuple(_hb_debug_stmt_shape(entry[2]) for entry in flat[max(0, index - 6) : index]),
            )
        if call is None or not push_offsets:
            continue
        removable_flat_indexes = _hb_removable_flat_scan(flat, index, call, push_offsets)
        for removable_index in removable_flat_indexes:
            parent, child_index, _child = flat[removable_index]
            marker = id(parent)
            if marker not in removals:
                removals[marker] = (parent, set())
            removals[marker][1].add(child_index)

    removed_count = _hb_delete_indexed_statements(removals)
    if removed_count <= 0:
        return False
    codegen._inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616 = (
        int(getattr(codegen, "_inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616", 0) or 0)
        + removed_count
    )
    return True


def _hb_removable_scalar_remnants(
    items: list[StructuredAstValue], i: int, push_offsets: StructuredAstValue, call: StructuredAstValue
) -> list[int]:
    """Scan backward from a call for removable scalar high-byte remnants."""
    scan = i - 1
    pending_carriers: list[int] = []
    removable: list[int] = []
    while scan >= 0 and i - scan <= 6:
        candidate = items[scan]
        store_source = _hb_scalar_high_byte_store_source(candidate, call, push_offsets)
        if store_source is not None:
            removable.append(scan)
            removable.extend(pending_carriers)
            scan -= 1
            while scan >= 0 and i - scan <= 6 and _hb_is_safe_carrier(items[scan]):
                removable.append(scan)
                scan -= 1
            break
        if _hb_statement_contains_call(candidate):
            break
        if _hb_is_safe_carrier(candidate):
            pending_carriers.append(scan)
            scan -= 1
            continue
        break
    return removable


def _hb_delete_scalar_remnants_8616(
    items: list[StructuredAstValue],
    i: int,
    removable: list[int],
    codegen: StructuredAstValue,
) -> int:
    """Delete the proven scalar remnant indexes from ``items``; return adjusted ``i``."""
    removed = sorted(set(removable), reverse=True)
    for idx in removed:
        del items[idx]
        if idx < i:
            i -= 1
    codegen._inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616 = int(
        getattr(codegen, "_inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616", 0) or 0
    ) + len(removed)
    return i


def _hb_prune_statement_owner(owner: StructuredAstValue, *, codegen: StructuredAstValue, seen: StructuredAstValue, summary_map: StructuredAstValue) -> bool:
    marker = id(owner)
    if marker in seen:
        return False
    seen.add(marker)
    statements = getattr(owner, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return False
    local_changed = False
    items = list(statements)

    for stmt in tuple(items):
        local_changed = _hb_walk_statement(stmt, codegen=codegen, seen=seen, summary_map=summary_map) or local_changed

    i = 0
    while i < len(items):
        call = _hb_call_from_statement(items[i])
        summary = summary_map.get(id(call)) if call is not None else None
        push_offsets = _hb_summary_direct_global_word_offsets(summary) if summary is not None else set()
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION") and call is not None:
            log.warning(
                "[call-scalar-final-prune] call=%s summary=%s push_offsets=%r idx=%d prev=%r",
                _hb_call_name(call),
                summary is not None,
                tuple(sorted(push_offsets)),
                i,
                tuple(_hb_debug_stmt_shape(stmt) for stmt in items[max(0, i - 4) : i]),
            )
        if call is None or not push_offsets:
            i += 1
            continue
        removable = _hb_removable_scalar_remnants(items, i, push_offsets, call)
        if removable:
            i = _hb_delete_scalar_remnants_8616(items, i, removable, codegen)
            local_changed = True
        i += 1

    if local_changed:
        owner.statements = items if isinstance(statements, list) else tuple(items)
    local_changed = _hb_prune_flat_sequence_remnants(owner, codegen=codegen, summary_map=summary_map) or local_changed
    return local_changed


def _hb_walk_statement(
    stmt: StructuredAstValue,
    *,
    codegen: StructuredAstValue,
    seen: StructuredAstValue,
    summary_map: StructuredAstValue,
) -> bool:
    local_changed = _hb_prune_statement_owner(stmt, codegen=codegen, seen=seen, summary_map=summary_map)
    for attr in ("body", "else_node"):
        child = getattr(stmt, attr, None)
        if child is not None:
            local_changed = _hb_walk_statement(child, codegen=codegen, seen=seen, summary_map=summary_map) or local_changed
    for pair in _boundary_tuple_8616(getattr(stmt, "condition_and_nodes", ()) or ()):
        if isinstance(pair, tuple) and len(pair) == 2 and pair[1] is not None:
            local_changed = _hb_walk_statement(pair[1]) or local_changed
    return local_changed



def _prune_scalar_global_high_byte_call_arg_remnants_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Prune final lowered scalar high-byte stores already consumed by a call."""
    _ = project
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "body", None) or getattr(cfunc, "statements", None)
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if root is None or not isinstance(summary_map, dict) or not summary_map:
        return False
    _refresh_callsite_summary_node_ids_8616(codegen, summary_map)









































































































































































































































































































    seen: set[int] = set()

















































































    changed = _hb_prune_statement_owner(root, codegen=codegen, seen=seen, summary_map=summary_map)
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed
