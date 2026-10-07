"""Define typed postprocess pass and runtime policy contracts.

Layer: Rewrite/Postprocess cleanup.
Responsibility: own immutable pass descriptors and parse bounded runtime policy
without inspecting or mutating semantic evidence or the structured C AST.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from inertia.validation.tail_validation import X86_16TailValidationSummary

from .pass_validation_policy import PASS_REJECT_BUDGET_DEFAULT_8616

__all__ = [
    "CallArgumentAstEffect8616",
    "DecompilerPostprocessPassSpec",
    "PostprocessRuntimeConfig8616",
    "build_postprocess_runtime_config_8616",
    "postprocess_optional_reject_budget_8616",
]


class CallArgumentAstEffect8616(Enum):
    """Declare whether a postprocess pass rebuilds call arguments."""

    PRESERVES = "preserves"
    REBUILDS = "rebuilds"


@dataclass(frozen=True, slots=True)
class DecompilerPostprocessPassSpec:
    """Describe one ordered postprocess command and its AST effect."""

    name: str
    func: Callable[..., bool]
    needs_project: bool
    callsite_final_gate: bool = False
    call_argument_effect: CallArgumentAstEffect8616 = (
        CallArgumentAstEffect8616.PRESERVES
    )


class PostprocessRuntimeConfig8616(NamedTuple):
    """Compatibility-shaped runtime configuration for one postprocess run."""

    pass_timeout_seconds: int | None
    validation_enabled: bool
    per_pass_validation_enabled: bool
    skip_names: set[str]
    baseline_summary: X86_16TailValidationSummary | None


def _environment(env: Mapping[str, str] | None) -> Mapping[str, str]:
    """Return an explicit environment mapping for deterministic policy tests."""
    return os.environ if env is None else env


def postprocess_optional_reject_budget_8616(
    env: Mapping[str, str] | None = None,
) -> int:
    """Parse the bounded optional-pass rejection budget."""
    environment = _environment(env)
    raw = environment.get("INERTIA_POSTPROCESS_OPTIONAL_REJECT_BUDGET", "").strip()
    if not raw:
        return PASS_REJECT_BUDGET_DEFAULT_8616
    try:
        return max(0, int(raw))
    except ValueError:
        return PASS_REJECT_BUDGET_DEFAULT_8616


def build_postprocess_runtime_config_8616(
    *,
    validation_enabled: bool,
    per_pass_validation_requested: bool,
    large_function_for_per_pass_validation: bool,
    fact_backed_stack_normalize_enabled: bool,
    baseline_summary: X86_16TailValidationSummary | None,
    env: Mapping[str, str] | None = None,
) -> PostprocessRuntimeConfig8616:
    """Build deterministic validation, skip, and timeout policy."""
    environment = _environment(env)
    force_per_pass = bool(environment.get("INERTIA_FORCE_PER_PASS_TV"))
    debug_per_pass = bool(
        environment.get("INERTIA_DEBUG_CONDITION_TRACE")
        or environment.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION")
    )
    per_pass_validation_enabled = bool(
        per_pass_validation_requested or force_per_pass or debug_per_pass
    )
    if large_function_for_per_pass_validation and not force_per_pass:
        per_pass_validation_enabled = False

    skip_names = {
        name.strip()
        for name in environment.get("INERTIA_SKIP_POSTPROCESS_PASSES", "").split(",")
        if name.strip()
    }
    if not fact_backed_stack_normalize_enabled:
        skip_names.add("_normalize_fact_backed_stack_accesses_8616")

    default_timeout = "2" if large_function_for_per_pass_validation else "6"
    timeout_raw = (
        environment.get("INERTIA_POSTPROCESS_PASS_TIMEOUT_SEC", "").strip()
        or default_timeout
    )
    pass_timeout_seconds: int | None = None
    try:
        parsed_timeout = float(timeout_raw)
    except ValueError:
        pass
    else:
        if parsed_timeout > 0.0:
            pass_timeout_seconds = max(1, round(parsed_timeout))

    return PostprocessRuntimeConfig8616(
        pass_timeout_seconds=pass_timeout_seconds,
        validation_enabled=validation_enabled,
        per_pass_validation_enabled=per_pass_validation_enabled,
        skip_names=skip_names,
        baseline_summary=baseline_summary,
    )
