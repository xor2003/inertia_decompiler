"""Finalize exact structured occurrences of machine callsites.

Layer: Structuring.
Responsibility: sequence Structuring-owned call occurrence normalization after
typed call arguments or regenerated C AST nodes become available.

This module owns no call semantics. It consumes existing callsite summaries,
CFG topology, and structured ancestry, then marks codegen regeneration when a
proven occurrence change is materialized. Rewrite and CLI may invoke this
owner as orchestration boundaries, but must not reproduce its proof.

Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import logging
import os
from typing import Protocol, cast

from inertia.lowering.call_return_frame_arguments import prune_exact_call_return_frame_arguments_8616
from inertia.structuring import structuring_codegen as _codegen

from .shared_call_result_aliases import materialize_shared_call_result_aliases_8616
from .shared_tail_call_ownership import materialize_shared_tail_call_ownership_8616
from .stored_call_result_assignments import materialize_stored_call_result_assignments_8616
from .stored_call_result_occurrences import materialize_stored_call_result_occurrences_8616
from .unused_call_result_self_xor import materialize_unused_call_result_self_xor_8616

__all__ = ["finalize_shared_call_occurrences_8616"]

logger: logging.Logger = logging.getLogger(__name__)


class _CodegenOccurrenceSurface8616(Protocol):
    """Codegen state updated after a proven structured occurrence change."""

    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_force_codegen_regeneration_8616: bool


def finalize_shared_call_occurrences_8616(project: object, codegen: object) -> bool:
    """Normalize and own exact call occurrences after an AST rebuild boundary."""
    changed = bool(_codegen.split_distinct_condition_call_occurrences_8616(codegen))
    stored_assignments = materialize_stored_call_result_assignments_8616(codegen)
    changed = stored_assignments.changed or changed
    if os.environ.get("INERTIA_DEBUG_STORED_CALL_RESULT_OCCURRENCES") == "1":
        logger.warning("[stored-call-result-assignments] result=%r", stored_assignments)
    result_aliases = materialize_shared_call_result_aliases_8616(codegen)
    changed = result_aliases.changed or changed
    frame_arguments = prune_exact_call_return_frame_arguments_8616(project, codegen)
    changed = frame_arguments.changed or changed
    if os.environ.get("INERTIA_DEBUG_STORED_CALL_RESULT_OCCURRENCES") == "1":
        logger.warning("[call-return-frame-arguments] result=%r", frame_arguments)
    stored_result = materialize_stored_call_result_occurrences_8616(codegen)
    changed = stored_result.changed or changed
    if os.environ.get("INERTIA_DEBUG_STORED_CALL_RESULT_OCCURRENCES") == "1":
        logger.warning("[stored-call-result-occurrences] result=%r", stored_result)
    self_xor = materialize_unused_call_result_self_xor_8616(codegen)
    changed = self_xor.changed or changed
    changed = bool(_codegen.coalesce_shared_call_side_effect_statements_8616(codegen)) or changed
    shared_tail = materialize_shared_tail_call_ownership_8616(project, codegen)
    changed = shared_tail.changed or changed
    if os.environ.get("INERTIA_DEBUG_STORED_CALL_RESULT_OCCURRENCES") == "1":
        logger.warning("[shared-tail-call-ownership] result=%r", shared_tail)
    if changed:
        boundary = cast(_CodegenOccurrenceSurface8616, codegen)
        boundary._inertia_codegen_decl_refresh_required_8616 = True
        boundary._inertia_force_codegen_regeneration_8616 = True
    return changed
