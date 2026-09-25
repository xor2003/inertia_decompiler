"""Coordinate stack/global lowering passes before rewrite.

Layer: Types/Lowering.
Responsibility: coordinate proven stack/global lowering consumers before rewrite cleanup.
Consumes alias, widening, and typed facts to materialize stable stack slots,
segmented accesses, and stack-probe returns.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Protocol

from ..stack_probe_fact_trace import (
    record_stable_ss_lowering_refusal_8616,
    record_stable_ss_lowering_replacement_8616,
)
from .real_mode_linear import (
    lower_stable_ds_es_linear_global_addresses_8616,
    lower_stable_ds_es_linear_global_dereferences_8616,
    lower_stable_ss_linear_stack_dereferences_8616,
)
from .segmented_memory_lowering import apply_runtime_segment_lowering_8616
from .software_interrupt_calls import materialize_software_interrupt_calls_8616
from .stack_lowering_impl import (
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _materialize_stack_cvar_at_offset,
    _resolve_stack_cvar_at_offset,
    _resolve_stack_cvar_from_addr_expr,
)
from .stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)

log: logging.Logger = logging.getLogger(__name__)


class _StackLoweringCodegen8616(Protocol):
    """Codegen-side fields owned by stack-lowering coordination."""

    _inertia_typed_stack_probe_return_facts: dict[int, TypedStackProbeReturnFact8616]
    _inertia_ss_lowering_refusal_log: list[object]
    _inertia_stack_lowering_debug: dict[str, object]
    _inertia_ss_lowering_refusal_summary: list[object]
    _inertia_global_deref_after_address_materialized_count: int
    cfunc: object


def _dynamic_codegen_attr_8616(obj: object | None, name: str, default: object | None = None) -> object | None:
    """Dynamic codegen boundary: read optional decompiler/codegen state fields."""
    if obj is None:
        return default
    return getattr(obj, name, default)


def _record_lowering_change_8616(codegen: _StackLoweringCodegen8616 | None) -> None:
    """Record that stack lowering changed the current codegen tree."""
    if codegen is not None:
        record_stable_ss_lowering_replacement_8616(codegen)


def _initialize_stack_lowering_debug_state_8616(
    codegen: _StackLoweringCodegen8616 | None,
    typed_stack_probe_return_facts: dict[int, TypedStackProbeReturnFact8616] | None,
) -> int:
    """Initialize stack-lowering counters and return the typed fact count."""
    if codegen is None:
        return 0
    codegen._inertia_typed_stack_probe_return_facts = (
        build_typed_stack_probe_return_facts_8616(codegen)
        if typed_stack_probe_return_facts is None
        else typed_stack_probe_return_facts
    )
    codegen._inertia_ss_lowering_refusal_log = []
    debug_stats = _dynamic_codegen_attr_8616(codegen, "_inertia_stack_lowering_debug")
    if not isinstance(debug_stats, dict):
        debug_stats = {}
        codegen._inertia_stack_lowering_debug = debug_stats
    debug_stats.setdefault("candidate_text_match_count", 0)
    debug_stats.setdefault("candidate_ast_match_count", 0)
    debug_stats.setdefault("lowering_replacements", 0)
    debug_stats.setdefault("lowering_refusals", 0)
    debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
    typed_facts = _dynamic_codegen_attr_8616(codegen, "_inertia_typed_stack_probe_return_facts", {})
    return len(typed_facts) if isinstance(typed_facts, dict) else 0


def _record_stack_lowering_refusal_8616(codegen: _StackLoweringCodegen8616 | None) -> None:
    """Record that a proven stack fact could not be lowered this round."""
    debug_stats = _dynamic_codegen_attr_8616(codegen, "_inertia_stack_lowering_debug")
    if isinstance(debug_stats, dict):
        debug_stats["lowering_refusals"] = int(debug_stats.get("lowering_refusals", 0) or 0) + 1
        reasons = debug_stats.setdefault("stable_ss_lowering_refusal_reasons", {})
        reasons["no_codegen_match"] = int(reasons.get("no_codegen_match", 0) or 0) + 1
    record_stable_ss_lowering_refusal_8616(codegen)


def _lower_global_segment_accesses_8616(
    codegen: _StackLoweringCodegen8616,
    project: object | None,
) -> bool:
    """Lower stable DS/ES globals and recount post-address dereferences."""
    round_changed = False
    if lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project):
        _record_lowering_change_8616(codegen)
        round_changed = True
    if lower_stable_ds_es_linear_global_addresses_8616(codegen, project=project):
        _record_lowering_change_8616(codegen)
        round_changed = True
        if lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project):
            current_global_deref_count = _dynamic_codegen_attr_8616(
                codegen,
                "_inertia_global_deref_after_address_materialized_count",
                0,
            )
            codegen._inertia_global_deref_after_address_materialized_count = (
                current_global_deref_count if isinstance(current_global_deref_count, int) else 0
            ) + 1
            _record_lowering_change_8616(codegen)
            round_changed = True
    return round_changed


def _round_impl_8616(
    *,
    rewrite_ss_stack_byte_offsets: Callable[[], bool],
    canonicalize_stack_cvars: Callable[[], bool],
    lower_stable_ss_stack_accesses: Callable[[], bool] | None,
    codegen: _StackLoweringCodegen8616 | None,
    project: object | None,
    typed_fact_count: int,
    lower_global_segment_accesses: bool,
    lower_runtime_segment_accesses: bool,
) -> bool:
    """Run the ordered lowering steps for one round."""
    round_changed = False
    if codegen is not None and lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project):
        _record_lowering_change_8616(codegen)
        round_changed = True
    # Preserve DS/ES provenance before anonymous global projection can
    # collapse a segmented address into a plain SimMemoryVariable.
    if (
        lower_runtime_segment_accesses
        and codegen is not None
        and apply_runtime_segment_lowering_8616(
            codegen,
            target=str(_dynamic_codegen_attr_8616(project, "_inertia_c_target", "portable-flat") or "portable-flat"),
        )
    ):
        _record_lowering_change_8616(codegen)
        round_changed = True
    if (
        lower_global_segment_accesses
        and codegen is not None
        and _lower_global_segment_accesses_8616(codegen, project)
    ):
        round_changed = True
    if lower_stable_ss_stack_accesses is not None:
        lowered = lower_stable_ss_stack_accesses()
        if lowered:
            _record_lowering_change_8616(codegen)
            round_changed = True
        elif codegen is not None and typed_fact_count > 0:
            _record_stack_lowering_refusal_8616(codegen)
    if rewrite_ss_stack_byte_offsets():
        _record_lowering_change_8616(codegen)
        round_changed = True
    if canonicalize_stack_cvars():
        _record_lowering_change_8616(codegen)
        round_changed = True
    return round_changed


def _run_single_stack_lowering_round_8616(
    *,
    rewrite_ss_stack_byte_offsets: Callable[[], bool],
    canonicalize_stack_cvars: Callable[[], bool],
    lower_stable_ss_stack_accesses: Callable[[], bool] | None,
    codegen: _StackLoweringCodegen8616 | None,
    project: object | None,
    typed_fact_count: int,
    lower_global_segment_accesses: bool,
    lower_runtime_segment_accesses: bool,
) -> bool:
    """Run one ordered stack/global lowering round."""
    return _round_impl_8616(
        rewrite_ss_stack_byte_offsets=rewrite_ss_stack_byte_offsets,
        canonicalize_stack_cvars=canonicalize_stack_cvars,
        lower_stable_ss_stack_accesses=lower_stable_ss_stack_accesses,
        codegen=codegen,
        project=project,
        typed_fact_count=typed_fact_count,
        lower_global_segment_accesses=lower_global_segment_accesses,
        lower_runtime_segment_accesses=lower_runtime_segment_accesses,
    )


def _emit_stack_lowering_debug_summary_8616(codegen: _StackLoweringCodegen8616 | None) -> None:
    """Emit optional stack-lowering debug statistics for noisy local runs."""

    def _impl() -> None:
        if codegen is None:
            return
        refusal_log = _dynamic_codegen_attr_8616(codegen, "_inertia_ss_lowering_refusal_log")
        if isinstance(refusal_log, list) and refusal_log:
            if not hasattr(codegen, "_inertia_ss_lowering_refusal_summary"):
                codegen._inertia_ss_lowering_refusal_summary = []
            codegen._inertia_ss_lowering_refusal_summary.extend(refusal_log)
        if not os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            return
        debug_stats = _dynamic_codegen_attr_8616(codegen, "_inertia_stack_lowering_debug")
        if isinstance(debug_stats, dict):
            cfunc = _dynamic_codegen_attr_8616(codegen, "cfunc")
            func_addr = _dynamic_codegen_attr_8616(cfunc, "addr", -1)
            if not isinstance(func_addr, int):
                func_addr = -1
            log.warning(
                "[stack-lowering] function=%#x stable_stack_fact_count=%d stable_bp_fact_count=%d stack_binding_count=%d candidate_text_match_count=%d candidate_ast_match_count=%d lowering_replacements=%d lowering_refusals=%d reasons=%r",
                func_addr,
                int(debug_stats.get("stable_stack_fact_count", 0) or 0),
                int(debug_stats.get("stable_bp_fact_count", 0) or 0),
                int(debug_stats.get("stack_binding_count", 0) or 0),
                int(debug_stats.get("candidate_text_match_count", 0) or 0),
                int(debug_stats.get("candidate_ast_match_count", 0) or 0),
                int(debug_stats.get("lowering_replacements", 0) or 0),
                int(debug_stats.get("lowering_refusals", 0) or 0),
                debug_stats.get("stable_ss_lowering_refusal_reasons", {}),
            )

    return _impl()


def run_stack_lowering_pass_8616(
    *,
    rewrite_ss_stack_byte_offsets: Callable[[], bool],
    canonicalize_stack_cvars: Callable[[], bool],
    lower_stable_ss_stack_accesses: Callable[[], bool] | None = None,
    codegen: _StackLoweringCodegen8616 | None = None,
    project: object | None = None,
    typed_stack_probe_return_facts: dict[int, TypedStackProbeReturnFact8616] | None = None,
    max_rounds: int = 2,
    lower_global_segment_accesses: bool = True,
    lower_runtime_segment_accesses: bool = True,
) -> bool:
    """Run the ordered stack lowering pass until a fixed point or round limit."""
    typed_fact_count = _initialize_stack_lowering_debug_state_8616(codegen, typed_stack_probe_return_facts)
    changed = False
    for _ in range(max(max_rounds, 1)):
        round_changed = _run_single_stack_lowering_round_8616(
            rewrite_ss_stack_byte_offsets=rewrite_ss_stack_byte_offsets,
            canonicalize_stack_cvars=canonicalize_stack_cvars,
            lower_stable_ss_stack_accesses=lower_stable_ss_stack_accesses,
            codegen=codegen,
            project=project,
            typed_fact_count=typed_fact_count,
            lower_global_segment_accesses=lower_global_segment_accesses,
            lower_runtime_segment_accesses=lower_runtime_segment_accesses,
        )
        if not round_changed:
            break
        changed = True
    if codegen is not None and materialize_software_interrupt_calls_8616(codegen):
        changed = True
    _emit_stack_lowering_debug_summary_8616(codegen)
    return changed


__all__ = (
    "TypedStackProbeReturnFact8616",
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_materialize_stack_cvar_at_offset",
    "_resolve_stack_cvar_at_offset",
    "_resolve_stack_cvar_from_addr_expr",
    "build_typed_stack_probe_return_facts_8616",
    "run_stack_lowering_pass_8616",
)
