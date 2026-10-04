"""Bind callee-entry DS to an owned structured-C runtime selector.

Layer: Types/Lowering.
Responsibility: join a complete ``NearReturnSegmentUse8616`` receipt with the
exact callee structured-codegen surface, the project-owned raw-IR registry and
the callee's proven architectural DS entry live-in, then materialize the
runtime segment-state selector through the segment-register-state owner.
Nonpublishing: it mutates no body, prototype, callsite or registry and grants
no native-pointer representation. Detached construction consumes a codegen
node identifier; completeness replay is observational and allocates nothing. A later
near-return publication stage consumes the retained replayable binding.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeShort
from angr.sim_variable import SimMemoryVariable

from ..ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)
from .near_return_segment_use import (
    NearReturnSegmentUse8616,
    NearReturnSegmentUseFailure8616,
)
from .near_return_selector import (
    NearReturnSelectorEvidence8616,
    _unsigned_int_bits_8616,
    classify_near_return_selector_8616,
)
from .segment_register_state import (
    _entry_live_in_segments_8616,
    runtime_segment_name_for_variable_8616,
    runtime_segment_state_cvar_8616,
    runtime_segment_state_variable_matches_8616,
)

__all__ = [
    "NearReturnEntrySelector8616",
    "NearReturnEntrySelectorFailure8616",
    "bind_near_return_entry_selector_8616",
]


class NearReturnEntrySelectorFailure8616(StrEnum):
    """Stable reasons callee-entry DS cannot bind an owned runtime selector."""

    SEGMENT_USE_INCOMPLETE = "segment_use_incomplete"
    CODEGEN_SURFACE_UNPROVEN = "codegen_surface_unproven"
    CALLEE_MISMATCH = "callee_mismatch"
    PROJECT_MISMATCH = "project_mismatch"
    REGISTERED_IR_STALE = "registered_ir_stale"
    ENTRY_LIVE_IN_UNPROVEN = "entry_live_in_unproven"
    SELECTOR_CONSTRUCTION_REFUSED = "selector_construction_refused"
    SELECTOR_TYPE_UNPROVEN = "selector_type_unproven"
    SELECTOR_DOMAIN_UNPROVEN = "selector_domain_unproven"
    SELECTOR_IDENTITY_MISMATCH = "selector_identity_mismatch"


_F8616 = NearReturnEntrySelectorFailure8616

# Refusals raised before the codegen surface normalizes never claim a
# normalized fact; every later refusal keeps normalized=1 with zero
# classified and materialized counts.
_UNNORMALIZED_FAILURES_8616: frozenset[NearReturnEntrySelectorFailure8616] = frozenset(
    {
        _F8616.SEGMENT_USE_INCOMPLETE,
        _F8616.CODEGEN_SURFACE_UNPROVEN,
    }
)


@dataclass(frozen=True, slots=True)
class NearReturnEntrySelector8616:
    """Replayable callee-entry-DS runtime-selector binding or typed refusal.

    ``selector`` is the detached runtime segment-state carrier for the
    callee's proven DS architectural live-in; it is never attached to a body
    and grants no native-pointer representation. ``complete`` replays the
    segment-use receipt, the callee codegen/function/project identity, the
    registered raw IR, the DS entry live-in and the selector subtree, so a
    mutated type, foreign or forged variable, stale registry or other callee
    cannot keep a bound verdict.
    """

    segment_use: NearReturnSegmentUse8616
    callee_addr: int
    codegen: object | None
    selector: structured_c.CVariable | None
    selector_type: SimType | None
    failure: NearReturnEntrySelectorFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    upstream_failure: NearReturnSegmentUseFailure8616 | None = None

    @property
    def complete(self) -> bool:
        """Re-prove the bound receipt, codegen surface and selector subtree."""
        if self.failure is not None or self.upstream_failure is not None or not _counts_bound_8616(self):
            return False
        codegen = self.codegen
        selector = self.selector
        if codegen is None or selector is None:
            return False
        if _binding_failure_8616(codegen, self.segment_use, self.callee_addr) is not None:
            return False
        return (
            _selector_failure_8616(selector, codegen, self.callee_addr, self.selector_type)
            is None
        )


def _counts_bound_8616(result: NearReturnEntrySelector8616) -> bool:
    """Return whether the result retains the exact-int bound accounting."""
    counts = (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
    )
    return all(type(count) is int for count in counts) and counts == (1, 1, 1, 1, 0)


def _binding_failure_8616(
    codegen: object,
    segment_use: NearReturnSegmentUse8616,
    callee_addr: int,
) -> NearReturnEntrySelectorFailure8616 | None:
    """Replay the receipt, callee codegen identity, registry and live-in.

    The callee address and project are taken only from the retained typed
    evidence, never from a rendered name or a caller-supplied claim. The raw
    IR registry must still hold the identical artifact object the callee
    closure consumed, and the callee entry state must prove DS as an
    architectural live-in through the owning segment-state contract.
    Dynamic angr codegen boundary: optional cfunc, addr and project attributes
    may be absent on incomplete third-party surfaces, requiring refusal reads.
    """
    if not segment_use.complete:
        return _F8616.SEGMENT_USE_INCOMPLETE
    preservation = segment_use.call_preservation
    callee = preservation.callee
    artifact = callee.coverage.artifact
    if type(callee_addr) is not int or callee_addr != artifact.function_addr:
        return _F8616.CALLEE_MISMATCH
    # Dynamic third-party codegen boundary: incomplete surfaces may carry no
    # cfunc or project, so the reads use getattr defaults rather than the dot
    # access reserved for owned contracts.
    cfunc = getattr(codegen, "cfunc", None)
    function_addr = getattr(cfunc, "addr", None)
    project = getattr(codegen, "project", None)
    if type(function_addr) is not int or function_addr < 0 or project is None:
        return _F8616.CODEGEN_SURFACE_UNPROVEN
    if function_addr != callee_addr:
        return _F8616.CALLEE_MISMATCH
    if (
        project is not preservation.caller.boundary.project
        or project is not callee.coverage.boundary.project
    ):
        return _F8616.PROJECT_MISMATCH
    resolution = registered_function_ir_artifact_8616(project, callee_addr)
    if (
        resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN
        or resolution.artifact is not artifact
    ):
        return _F8616.REGISTERED_IR_STALE
    if "ds" not in _entry_live_in_segments_8616(callee.state, callee_addr):
        return _F8616.ENTRY_LIVE_IN_UNPROVEN
    return None


def _selector_failure_8616(
    selector: object,
    codegen: object,
    callee_addr: int,
    selector_type: SimType | None,
) -> NearReturnEntrySelectorFailure8616 | None:
    """Replay the retained selector's owned identity, type and DS carrier.

    The variable must carry the owned runtime category and reserved symbol,
    and every identity field must match the segment-register-state owner's
    observational contract. Name equality alone cannot substitute. Replay
    neither duplicates the private tables nor consumes codegen identifiers.
    """
    if type(selector) is not structured_c.CVariable:
        return _F8616.SELECTOR_IDENTITY_MISMATCH
    # Preserve exact-class admission at the foreign codegen boundary; MyPy
    # does not narrow an object from a type(...) identity comparison.
    checked_selector = cast(structured_c.CVariable, selector)
    if (
        checked_selector.codegen is not codegen
        or checked_selector.unified_variable is not None
        or checked_selector.vvar_id is not None
    ):
        return _F8616.SELECTOR_IDENTITY_MISMATCH
    if (
        selector_type is None
        or checked_selector.variable_type is not selector_type
        or not _unsigned_int_bits_8616(selector_type, 16)
    ):
        return _F8616.SELECTOR_TYPE_UNPROVEN
    if classify_near_return_selector_8616(checked_selector) is not NearReturnSelectorEvidence8616.WORD:
        return _F8616.SELECTOR_DOMAIN_UNPROVEN
    variable = checked_selector.variable
    if (
        type(variable) is not SimMemoryVariable
        or runtime_segment_name_for_variable_8616(variable) != "ds"
    ):
        return _F8616.SELECTOR_IDENTITY_MISMATCH
    if not runtime_segment_state_variable_matches_8616(variable, "ds", callee_addr):
        return _F8616.SELECTOR_IDENTITY_MISMATCH
    return None


def _refuse_8616(
    segment_use: NearReturnSegmentUse8616,
    callee_addr: int,
    codegen: object | None,
    selector: structured_c.CVariable | None,
    selector_type: SimType | None,
    failure: NearReturnEntrySelectorFailure8616,
    *,
    normalized: bool,
    upstream: NearReturnSegmentUseFailure8616 | None = None,
) -> NearReturnEntrySelector8616:
    """Retain one refused binding with closed zero-classification accounting.

    A refusal never claims a classified or materialized fact; the normalized
    count only records that the submitted evidence was well-formed enough to
    classify before it failed.
    """
    return NearReturnEntrySelector8616(
        segment_use=segment_use,
        callee_addr=callee_addr,
        codegen=codegen,
        selector=selector,
        selector_type=selector_type,
        failure=failure,
        raw_fact_count=1,
        normalized_fact_count=int(normalized),
        classified_fact_count=0,
        materialized_count=0,
        failure_count=1,
        upstream_failure=upstream,
    )


def bind_near_return_entry_selector_8616(
    codegen: object,
    segment_use: NearReturnSegmentUse8616,
) -> NearReturnEntrySelector8616:
    """Materialize the callee-entry DS runtime selector, or retain a refusal.

    ``codegen`` is the callee's structured-codegen surface; it must name the
    proven callee on the same project that still registers the exact raw IR
    artifact. Construction allocates one detached AST node; registry, bodies,
    prototypes and callsites remain unchanged. Consumers
    must publish through ``complete`` so every obligation is replayed.
    """
    preservation = segment_use.call_preservation
    callee_addr = preservation.callee.coverage.artifact.function_addr
    failure = _binding_failure_8616(codegen, segment_use, callee_addr)
    if failure is not None:
        upstream = (
            segment_use.failure if failure is _F8616.SEGMENT_USE_INCOMPLETE else None
        )
        return _refuse_8616(
            segment_use,
            callee_addr,
            codegen,
            None,
            None,
            failure,
            normalized=failure not in _UNNORMALIZED_FAILURES_8616,
            upstream=upstream,
        )
    selector = runtime_segment_state_cvar_8616(
        "ds",
        codegen=codegen,
        variable_type=SimTypeShort(False),
        function_addr=callee_addr,
    )
    if selector is None:
        return _refuse_8616(
            segment_use,
            callee_addr,
            codegen,
            None,
            None,
            _F8616.SELECTOR_CONSTRUCTION_REFUSED,
            normalized=True,
        )
    selector_type = selector.variable_type
    failure = _selector_failure_8616(selector, codegen, callee_addr, selector_type)
    if failure is not None:
        return _refuse_8616(
            segment_use,
            callee_addr,
            codegen,
            selector,
            selector_type,
            failure,
            normalized=True,
        )
    result = NearReturnEntrySelector8616(
        segment_use=segment_use,
        callee_addr=callee_addr,
        codegen=codegen,
        selector=selector,
        selector_type=selector_type,
        failure=None,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
    if not result.complete:
        raise RuntimeError("near-return entry selector lost owned evidence")
    return result
