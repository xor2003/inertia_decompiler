"""Configure one guarded postprocess run from typed runtime policy.

Layer: Rewrite/Postprocess cleanup.
Responsibility: project dynamic angr runtime state into the immutable pass
configuration consumed by the guarded Rewrite transaction.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
Function complexity and validation-summary callbacks are already owned inputs.
Dynamic boundary: project, codegen, and CFunction are third-party angr objects.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from inertia.validation.tail_validation import X86_16TailValidationSummary

from .pass_runtime import (
    DecompilerPostprocessPassSpec,
    PostprocessRuntimeConfig8616,
    build_postprocess_runtime_config_8616,
    postprocess_optional_reject_budget_8616,
)
from .pass_validation_policy import POSTPROCESS_EXPENSIVE_VALIDATION_BASELINE_MS_8616
from .validation_contracts import PostprocessFunctionComplexity8616

__all__ = ["configure_postprocess_runtime_8616"]

type ComplexityResolver8616 = Callable[
    [object, object, int | None],
    PostprocessFunctionComplexity8616,
]
type BaselineSummaryCollector8616 = Callable[[object, object], X86_16TailValidationSummary]


class _CodegenRuntimeBoundary8616(Protocol):
    """Third-party codegen metadata configured for guarded postprocess."""

    cfunc: object
    _inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616: bool
    _inertia_postprocess_pre_validation_cost_ms_8616: int
    _inertia_postprocess_pre_validation_summary: X86_16TailValidationSummary | None
    _inertia_skip_per_pass_validation_large_function: bool
    _inertia_postprocess_function_complexity_8616: dict[str, object]
    _inertia_postprocess_passes: tuple[str, ...]
    _inertia_postprocess_optional_reject_budget_8616: int


def _nonnegative_int_8616(value: object) -> int:
    """Return a bounded policy integer without accepting booleans."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _function_addr_8616(codegen: object) -> int | None:
    """Return the active address at the explicit third-party CFunction boundary."""
    try:
        cfunc = cast(_CodegenRuntimeBoundary8616, codegen).cfunc
    except AttributeError:
        return None
    # Dynamic boundary: angr CFunction variants do not share an owned protocol.
    addr = getattr(cfunc, "addr", None)
    return addr if isinstance(addr, int) else None


def configure_postprocess_runtime_8616(
    project: object,
    codegen: object,
    pass_specs: Sequence[DecompilerPostprocessPassSpec],
    *,
    complexity_resolver: ComplexityResolver8616,
    baseline_summary_collector: BaselineSummaryCollector8616,
    fact_backed_stack_normalize_enabled: bool,
) -> PostprocessRuntimeConfig8616:
    """Publish dynamic runtime metadata and return immutable pass policy."""
    surface = cast(_CodegenRuntimeBoundary8616, codegen)
    func_addr = _function_addr_8616(codegen)
    # Dynamic boundary: these are optional project plugin fields.
    delta = getattr(project, "_inertia_original_linear_delta", None)
    func_addr_candidates: set[int] = set()
    if func_addr is not None:
        func_addr_candidates.add(func_addr)
        if isinstance(delta, int):
            func_addr_candidates.update((func_addr + delta, func_addr - delta))

    replacement_records = getattr(
        project,
        "_inertia_typed_switch_seqnode_replacement_8616",
        None,
    )
    if func_addr is not None and isinstance(replacement_records, list):
        surface._inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616 = any(
            isinstance(record, Mapping)
            and record.get("function_addr") in func_addr_candidates
            and record.get("changed") is True
            and _nonnegative_int_8616(record.get("replaced_count")) > 0
            for record in replacement_records
        )

    validation_enabled = bool(
        getattr(project, "_inertia_tail_validation_enabled", True)
    )
    per_pass_validation_requested = bool(
        getattr(project, "_inertia_postprocess_per_pass_validation_enabled", True)
    )
    complexity = complexity_resolver(project, codegen, func_addr)
    try:
        baseline_validation_cost_ms = int(
            surface._inertia_postprocess_pre_validation_cost_ms_8616 or 0
        )
    except AttributeError:
        baseline_validation_cost_ms = 0
    expensive_validation_baseline = (
        baseline_validation_cost_ms
        >= POSTPROCESS_EXPENSIVE_VALIDATION_BASELINE_MS_8616
    )
    large_function = (
        complexity.is_expensive_for_local_validation
        or expensive_validation_baseline
    )
    surface._inertia_skip_per_pass_validation_large_function = large_function
    surface._inertia_postprocess_function_complexity_8616 = {
        "blocks": complexity.block_count,
        "bytes": complexity.byte_count,
        "source": complexity.source,
        "expensive": large_function,
        "baseline_validation_cost_ms": baseline_validation_cost_ms,
        "expensive_validation_baseline": expensive_validation_baseline,
    }

    baseline_summary: X86_16TailValidationSummary | None = None
    if validation_enabled:
        try:
            baseline_summary = surface._inertia_postprocess_pre_validation_summary
        except AttributeError:
            baseline_summary = None
        if baseline_summary is None:
            baseline_summary = baseline_summary_collector(project, codegen)

    surface._inertia_postprocess_passes = tuple(spec.name for spec in pass_specs)
    surface._inertia_postprocess_optional_reject_budget_8616 = (
        postprocess_optional_reject_budget_8616()
    )
    return build_postprocess_runtime_config_8616(
        validation_enabled=validation_enabled,
        per_pass_validation_requested=per_pass_validation_requested,
        large_function_for_per_pass_validation=large_function,
        fact_backed_stack_normalize_enabled=fact_backed_stack_normalize_enabled,
        baseline_summary=baseline_summary,
    )
