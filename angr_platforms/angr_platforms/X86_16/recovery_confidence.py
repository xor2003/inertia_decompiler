"""Layer: Recovery/reporting.

Responsibility: classify recovery confidence from already-collected structured diagnostics.
Forbidden: creating proof, hiding assumptions, or changing recovered semantics.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from .function_effect_summary import FunctionEffectSource, FunctionEffectSummary, summarize_x86_16_function_effects
from .function_state_summary import FunctionStateSummary, summarize_x86_16_function_state
from .helper_effect_summary import HelperEligibilitySummary, summarize_x86_16_helper_eligibility
from .helper_family_routing import summarize_x86_16_helper_family_routes
from .ir_readiness import IRReadinessSummary, summarize_x86_16_ir_readiness

__all__ = [
    "RECOVERY_CONFIDENCE_AXES",
    "FunctionEffectSummary",
    "FunctionStateSummary",
    "HelperEligibilitySummary",
    "RecoveryAssumption",
    "RecoveryConfidenceSummary",
    "RecoveryEvidence",
    "classify_x86_16_recovery_confidence",
    "describe_x86_16_recovery_confidence_axes",
    "summarize_recovery_confidence",
]

type RecoveryConfidenceSource = FunctionEffectSource


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    """Evidence item supporting a recovery confidence classification."""

    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class RecoveryAssumption:
    """Open assumption that weakens a recovery confidence classification."""

    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class RecoveryConfidenceSummary:
    """Deterministic confidence verdict derived from existing recovery diagnostics."""

    status: str
    evidence: tuple[RecoveryEvidence, ...] = ()
    assumptions: tuple[RecoveryAssumption, ...] = ()
    diagnostics: tuple[str, ...] = ()
    scan_safe_classification: str = "unknown"
    helper_summary: HelperEligibilitySummary | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible recovery confidence payload."""
        return {
            "status": self.status,
            "evidence": [{"kind": item.kind, "detail": item.detail} for item in self.evidence],
            "assumptions": [{"kind": item.kind, "detail": item.detail} for item in self.assumptions],
            "diagnostics": list(self.diagnostics),
            "scan_safe_classification": self.scan_safe_classification,
            "helper_summary": None if self.helper_summary is None else self.helper_summary.to_dict(),
        }


def _value(source: RecoveryConfidenceSource, name: str, default: object = None) -> object:
    return source.get(name, default)


def _count(source: RecoveryConfidenceSource, name: str) -> int:
    value = _value(source, name, 0)
    return value if isinstance(value, int) else 0


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _append_recovery_evidence_8616(
    source: RecoveryConfidenceSource,
    *,
    ok: bool,
    decompiled_count: int,
    fallback_kind: str | None,
    interrupt_dos_helper_count: int,
    interrupt_bios_helper_count: int,
    last_structuring_pass: str | None,
    last_postprocess_pass: str | None,
    effect_summary: FunctionEffectSummary,
    state_summary: FunctionStateSummary,
    helper_summary: HelperEligibilitySummary,
    ir_readiness: IRReadinessSummary,
) -> list[RecoveryEvidence]:
    def _impl() -> list[RecoveryEvidence]:
        evidence = _output_stage_evidence_8616(
            ok=ok,
            decompiled_count=decompiled_count,
            interrupt_dos_helper_count=interrupt_dos_helper_count,
            interrupt_bios_helper_count=interrupt_bios_helper_count,
            last_structuring_pass=last_structuring_pass,
            last_postprocess_pass=last_postprocess_pass,
        )
        evidence += _summary_evidence_8616(
            effect_summary, state_summary, helper_summary, ir_readiness
        )
        if (
            ok
            and fallback_kind == "cfg_only"
            and _value(source, "semantic_family", None) == "stack_control"
            and _value(source, "stage_reached", None) == "cleanup"
        ):
            evidence.append(
                RecoveryEvidence(
                    "bounded_recovery", "scan-safe helper lane completed at cleanup without requiring decompilation"
                )
            )
        return evidence

    return _impl()



def _output_stage_evidence_8616(
    *,
    ok: bool,
    decompiled_count: int,
    interrupt_dos_helper_count: int,
    interrupt_bios_helper_count: int,
    last_structuring_pass: str | None,
    last_postprocess_pass: str | None,
) -> list[RecoveryEvidence]:
    """Collect evidence about decompilation output, helpers, and pass stages."""
    evidence: list[RecoveryEvidence] = []
    if ok and decompiled_count > 0:
        evidence.append(RecoveryEvidence("decompiled_output", "decompiler produced structured C output"))
    if interrupt_dos_helper_count or interrupt_bios_helper_count:
        evidence.append(
            RecoveryEvidence(
                "helper_lowering",
                f"{interrupt_dos_helper_count} DOS helper(s), {interrupt_bios_helper_count} BIOS helper(s)",
            )
        )
    if last_structuring_pass:
        evidence.append(RecoveryEvidence("structuring_pass", f"last structuring pass: {last_structuring_pass}"))
    if last_postprocess_pass:
        evidence.append(RecoveryEvidence("postprocess_pass", f"last postprocess pass: {last_postprocess_pass}"))
    return evidence


def _summary_evidence_8616(
    effect_summary: FunctionEffectSummary,
    state_summary: FunctionStateSummary,
    helper_summary: HelperEligibilitySummary,
    ir_readiness: IRReadinessSummary,
) -> list[RecoveryEvidence]:
    """Collect evidence contributed by the effect/state/helper/IR summaries."""
    evidence: list[RecoveryEvidence] = []
    if _effect_summary_has_signal_8616(effect_summary):
        evidence.append(RecoveryEvidence("function_effect_summary", effect_summary.brief()))
    if _state_summary_has_signal_8616(state_summary):
        evidence.append(RecoveryEvidence("function_state_summary", state_summary.brief()))
    if helper_summary.status == "eligible":
        evidence.append(RecoveryEvidence("helper_eligibility", helper_summary.brief()))
    if ir_readiness.level != "missing":
        evidence.append(
            RecoveryEvidence(
                "typed_ir_readiness",
                (
                    f"level={ir_readiness.level} "
                    f"cond={ir_readiness.condition_count} "
                    f"phi={ir_readiness.phi_node_count} "
                    f"defaulted={ir_readiness.defaulted_segment_count} "
                    f"proven={ir_readiness.proven_segment_count}"
                ),
            )
        )
    return evidence


def _effect_summary_has_signal_8616(effect_summary: FunctionEffectSummary) -> bool:
    """True when the effect summary carries any observable signal."""
    return bool(
        effect_summary.register_inputs
        or effect_summary.register_outputs
        or effect_summary.direct_call_count
        or effect_summary.indirect_call_count
        or effect_summary.direct_branch_count
        or effect_summary.indirect_branch_count
        or effect_summary.frame_stack_reads
        or effect_summary.frame_stack_writes
        or effect_summary.memory_reads
        or effect_summary.memory_writes
    )


def _state_summary_has_signal_8616(state_summary: FunctionStateSummary) -> bool:
    """True when the state summary carries any observable signal."""
    return bool(
        state_summary.gp_register_inputs
        or state_summary.gp_register_outputs
        or state_summary.segment_register_inputs
        or state_summary.segment_register_outputs
        or state_summary.flag_inputs
        or state_summary.flag_outputs
    )

def _append_recovery_assumptions_8616(
    *,
    ok: bool,
    fallback_kind: str | None,
    has_far_call_reloc: bool,
    rewrite_failed: bool,
    regeneration_failed: bool,
    structuring_failed: bool,
    interrupt_unresolved_wrapper_count: int,
    interrupt_wrapper_call_count: int,
    interrupt_dos_helper_count: int,
    interrupt_bios_helper_count: int,
    effect_summary: FunctionEffectSummary,
    state_summary: FunctionStateSummary,
    helper_summary: HelperEligibilitySummary,
    ir_readiness: IRReadinessSummary,
) -> list[RecoveryAssumption]:
    def _impl() -> list[RecoveryAssumption]:
        assumptions = _helper_assumptions_8616(
            interrupt_unresolved_wrapper_count=interrupt_unresolved_wrapper_count,
            interrupt_wrapper_call_count=interrupt_wrapper_call_count,
            interrupt_dos_helper_count=interrupt_dos_helper_count,
            interrupt_bios_helper_count=interrupt_bios_helper_count,
            helper_summary=helper_summary,
        )
        assumptions += _failure_assumptions_8616(
            ok=ok,
            fallback_kind=fallback_kind,
            has_far_call_reloc=has_far_call_reloc,
            rewrite_failed=rewrite_failed,
            regeneration_failed=regeneration_failed,
            structuring_failed=structuring_failed,
        )
        assumptions += _summary_assumptions_8616(
            effect_summary=effect_summary,
            state_summary=state_summary,
            helper_summary=helper_summary,
            ir_readiness=ir_readiness,
            interrupt_unresolved_wrapper_count=interrupt_unresolved_wrapper_count,
        )
        return assumptions

    return _impl()



def _helper_assumptions_8616(
    *,
    interrupt_unresolved_wrapper_count: int,
    interrupt_wrapper_call_count: int,
    interrupt_dos_helper_count: int,
    interrupt_bios_helper_count: int,
    helper_summary: HelperEligibilitySummary,
) -> list[RecoveryAssumption]:
    """Collect assumptions about unresolved/unmapped helper calls."""
    assumptions: list[RecoveryAssumption] = []
    if interrupt_unresolved_wrapper_count > 0:
        assumptions.append(
            RecoveryAssumption(
                "helper_guessed_from_weak_evidence",
                f"{interrupt_unresolved_wrapper_count} unresolved wrapper call(s) still need helper signatures",
            )
        )
    elif interrupt_wrapper_call_count > 0 and interrupt_dos_helper_count == 0 and interrupt_bios_helper_count == 0:
        assumptions.append(
            RecoveryAssumption(
                "helper_guessed_from_weak_evidence",
                f"{interrupt_wrapper_call_count} wrapper call(s) were observed without a settled helper mapping",
            )
        )
        if helper_summary.status != "eligible":
            assumptions.append(RecoveryAssumption("helper_shape_refused", helper_summary.brief()))
    return assumptions


def _failure_assumptions_8616(
    *,
    ok: bool,
    fallback_kind: str | None,
    has_far_call_reloc: bool,
    rewrite_failed: bool,
    regeneration_failed: bool,
    structuring_failed: bool,
) -> list[RecoveryAssumption]:
    """Collect assumptions tied to unresolved relocations and failed stages."""
    assumptions: list[RecoveryAssumption] = []
    if has_far_call_reloc and (not ok or fallback_kind not in (None, "none")):
        assumptions.append(
            RecoveryAssumption(
                "far_pointer_unresolved", "far pointer / far call evidence still needs a stable target association"
            )
        )
    if rewrite_failed or regeneration_failed:
        assumptions.append(
            RecoveryAssumption(
                "return_shape_uncertain",
                "postprocess rewrite/regeneration still needs a stable return-shape boundary",
            )
        )
    if structuring_failed:
        assumptions.append(
            RecoveryAssumption(
                "structuring_failure", "control-flow structuring still needs a stable downstream boundary"
            )
        )
    return assumptions


def _summary_assumptions_8616(
    *,
    effect_summary: FunctionEffectSummary,
    state_summary: FunctionStateSummary,
    helper_summary: HelperEligibilitySummary,
    ir_readiness: IRReadinessSummary,
    interrupt_unresolved_wrapper_count: int,
) -> list[RecoveryAssumption]:
    """Collect assumptions derived from the effect/state/helper/IR summaries."""
    assumptions: list[RecoveryAssumption] = []
    if effect_summary.has_indirect_control():
        assumptions.append(
            RecoveryAssumption(
                "indirect_control_flow",
                "indirect call/branch behavior still needs an explicit effect-summary consumer",
            )
        )
    if helper_summary.status == "refused" and interrupt_unresolved_wrapper_count > 0:
        assumptions.append(RecoveryAssumption("helper_shape_refused", helper_summary.brief()))
    if state_summary.touches_segments():
        assumptions.append(
            RecoveryAssumption(
                "segment_state_needs_tracking",
                "segment-register dataflow should stay explicit across CFG and call boundaries",
            )
        )
    if state_summary.touches_flags() and ir_readiness.condition_count == 0:
        assumptions.append(
            RecoveryAssumption(
                "live_flags_need_typed_conditions",
                "live flag dependencies still need typed condition recovery at branch and loop boundaries",
            )
        )
    if ir_readiness.unknown_segment_count > 0:
        assumptions.append(
            RecoveryAssumption(
                "typed_ir_segment_unknown",
                f"{ir_readiness.unknown_segment_count} typed address(es) still have unknown segment identity",
            )
        )
    elif ir_readiness.defaulted_segment_count > 0 and ir_readiness.proven_segment_count == 0:
        assumptions.append(
            RecoveryAssumption(
                "typed_ir_segment_defaulted",
                f"{ir_readiness.defaulted_segment_count} typed address(es) still rely on default segment identity",
            )
        )
    if ir_readiness.block_count > 1 and ir_readiness.phi_node_count == 0:
        assumptions.append(
            RecoveryAssumption("typed_ir_cross_block_ssa_missing", "typed IR is still block-local across CFG joins")
        )
    if ir_readiness.condition_count == 0 and ir_readiness.block_count > 0:
        assumptions.append(
            RecoveryAssumption("typed_ir_conditions_missing", "typed IR still lacks lifted branch/loop conditions")
        )
    return assumptions

def _recovery_diagnostics_8616(
    *,
    reason: str | None,
    failure_class: str | None,
    stage_reached: str | None,
    effect_summary: FunctionEffectSummary,
    state_summary: FunctionStateSummary,
    helper_summary: HelperEligibilitySummary,
    ir_readiness: IRReadinessSummary,
) -> list[str]:
    diagnostics: list[str] = []
    if reason:
        diagnostics.append(str(reason))
    if failure_class:
        diagnostics.append(f"failure_class={failure_class}")
    if stage_reached:
        diagnostics.append(f"stage_reached={stage_reached}")
    if effect_summary != summarize_x86_16_function_effects({}):
        diagnostics.append(f"function_effects={effect_summary.brief()}")
    if state_summary != summarize_x86_16_function_state({}):
        diagnostics.append(f"function_state={state_summary.brief()}")
    if helper_summary.status != "no_signal":
        diagnostics.append(f"helper_summary={helper_summary.brief()}")
    if ir_readiness.level != "missing":
        diagnostics.append(
            "ir_readiness="
            f"{ir_readiness.level}"
            f":cond={ir_readiness.condition_count}"
            f":phi={ir_readiness.phi_node_count}"
            f":defaulted={ir_readiness.defaulted_segment_count}"
            f":unknown={ir_readiness.unknown_segment_count}"
        )
    return diagnostics


def _recovery_status_8616(
    *,
    source: RecoveryConfidenceSource,
    ok: bool,
    decompiled_count: int,
    fallback_kind: str | None,
    has_far_call_reloc: bool,
    rewrite_failed: bool,
    regeneration_failed: bool,
    structuring_failed: bool,
    interrupt_unresolved_wrapper_count: int,
    interrupt_wrapper_call_count: int,
    interrupt_dos_helper_count: int,
    interrupt_bios_helper_count: int,
    assumptions: list[RecoveryAssumption],
) -> str:
    def _impl() -> str:
        if (
            ok
            and fallback_kind == "cfg_only"
            and _value(source, "semantic_family", None) == "stack_control"
            and _value(source, "stage_reached", None) == "cleanup"
            and not assumptions
        ):
            return "bounded_recovery"
        if rewrite_failed or regeneration_failed:
            return "return_shape_uncertain"
        if structuring_failed and ok:
            return "partial_recovery"
        if has_far_call_reloc and (assumptions or not ok):
            return "far_pointer_unresolved"
        if interrupt_unresolved_wrapper_count > 0 or (
            interrupt_wrapper_call_count > 0 and interrupt_dos_helper_count == 0 and interrupt_bios_helper_count == 0
        ):
            return "helper_guessed_weak"
        if ok and fallback_kind not in (None, "none"):
            return "partial_recovery"
        if ok and decompiled_count > 0 and not fallback_kind:
            return "target_recovered_strong"
        if ok and decompiled_count > 0:
            return "partial_recovery"
        return "target_unrecovered"

    return _impl()


def _scan_safe_classification_for_status_8616(status: str) -> str:
    if status in {"target_recovered_strong", "bounded_recovery"}:
        return "strong"
    if status in {"partial_recovery", "helper_guessed_weak"}:
        return "partial"
    return "unresolved"


def classify_x86_16_recovery_confidence(source: RecoveryConfidenceSource) -> RecoveryConfidenceSummary:
    """Classify confidence from already-collected structured recovery diagnostics."""
    ok = bool(_value(source, "ok", False))
    decompiled_count = _count(source, "decompiled_count")
    fallback_kind = _optional_text(_value(source, "fallback_kind", None))
    has_far_call_reloc = bool(_value(source, "has_far_call_reloc", False))
    rewrite_failed = bool(_value(source, "rewrite_failed", False))
    regeneration_failed = bool(_value(source, "regeneration_failed", False))
    structuring_failed = bool(_value(source, "structuring_failed", False))
    interrupt_unresolved_wrapper_count = _count(source, "interrupt_unresolved_wrapper_count")
    interrupt_wrapper_call_count = _count(source, "interrupt_wrapper_call_count")
    interrupt_dos_helper_count = _count(source, "interrupt_dos_helper_count")
    interrupt_bios_helper_count = _count(source, "interrupt_bios_helper_count")
    last_structuring_pass = _optional_text(_value(source, "last_structuring_pass", None))
    last_postprocess_pass = _optional_text(_value(source, "last_postprocess_pass", None))
    reason = _optional_text(_value(source, "reason", None))
    failure_class = _optional_text(_value(source, "failure_class", None))
    stage_reached = _optional_text(_value(source, "stage_reached", None))
    effect_summary = summarize_x86_16_function_effects(source)
    state_summary = summarize_x86_16_function_state(source)
    helper_summary = summarize_x86_16_helper_eligibility(source)
    ir_readiness = summarize_x86_16_ir_readiness(source)

    evidence = _append_recovery_evidence_8616(
        source,
        ok=ok,
        decompiled_count=decompiled_count,
        fallback_kind=fallback_kind,
        interrupt_dos_helper_count=interrupt_dos_helper_count,
        interrupt_bios_helper_count=interrupt_bios_helper_count,
        last_structuring_pass=last_structuring_pass,
        last_postprocess_pass=last_postprocess_pass,
        effect_summary=effect_summary,
        state_summary=state_summary,
        helper_summary=helper_summary,
        ir_readiness=ir_readiness,
    )
    assumptions = _append_recovery_assumptions_8616(
        ok=ok,
        fallback_kind=fallback_kind,
        has_far_call_reloc=has_far_call_reloc,
        rewrite_failed=rewrite_failed,
        regeneration_failed=regeneration_failed,
        structuring_failed=structuring_failed,
        interrupt_unresolved_wrapper_count=interrupt_unresolved_wrapper_count,
        interrupt_wrapper_call_count=interrupt_wrapper_call_count,
        interrupt_dos_helper_count=interrupt_dos_helper_count,
        interrupt_bios_helper_count=interrupt_bios_helper_count,
        effect_summary=effect_summary,
        state_summary=state_summary,
        helper_summary=helper_summary,
        ir_readiness=ir_readiness,
    )
    diagnostics = _recovery_diagnostics_8616(
        reason=reason,
        failure_class=failure_class,
        stage_reached=stage_reached,
        effect_summary=effect_summary,
        state_summary=state_summary,
        helper_summary=helper_summary,
        ir_readiness=ir_readiness,
    )
    status = _recovery_status_8616(
        source=source,
        ok=ok,
        decompiled_count=decompiled_count,
        fallback_kind=fallback_kind,
        has_far_call_reloc=has_far_call_reloc,
        rewrite_failed=rewrite_failed,
        regeneration_failed=regeneration_failed,
        structuring_failed=structuring_failed,
        interrupt_unresolved_wrapper_count=interrupt_unresolved_wrapper_count,
        interrupt_wrapper_call_count=interrupt_wrapper_call_count,
        interrupt_dos_helper_count=interrupt_dos_helper_count,
        interrupt_bios_helper_count=interrupt_bios_helper_count,
        assumptions=assumptions,
    )
    scan_safe_classification = _scan_safe_classification_for_status_8616(status)

    return RecoveryConfidenceSummary(
        status=status,
        evidence=tuple(evidence),
        assumptions=tuple(assumptions),
        diagnostics=tuple(diagnostics),
        scan_safe_classification=scan_safe_classification,
        helper_summary=helper_summary,
    )


def summarize_recovery_confidence(results: Sequence[RecoveryConfidenceSource]) -> dict[str, object]:
    """Summarize confidence classifications across existing recovery mapping rows."""

    def _impl() -> dict[str, object]:
        summaries = [classify_x86_16_recovery_confidence(result) for result in results]
        status_counter = Counter(summary.status for summary in summaries)
        scan_safe_counter = Counter(summary.scan_safe_classification for summary in summaries)
        assumption_counter = Counter(item.kind for summary in summaries for item in summary.assumptions)
        evidence_counter = Counter(item.kind for summary in summaries for item in summary.evidence)
        helper_status_counter = Counter(
            summary.helper_summary.status for summary in summaries if summary.helper_summary is not None
        )
        helper_candidate_counter = Counter(
            summary.helper_summary.candidate_kind
            for summary in summaries
            if summary.helper_summary is not None and summary.helper_summary.candidate_kind != "none"
        )
        helper_refusal_counter = Counter(
            refusal.kind
            for summary in summaries
            if summary.helper_summary is not None
            for refusal in summary.helper_summary.refusals
        )
        helper_family_rows = tuple(
            item.to_dict()
            for item in summarize_x86_16_helper_family_routes(
                summary.helper_summary for summary in summaries if summary.helper_summary is not None
            )
        )

        return {
            "status_counts": dict(sorted(status_counter.items())),
            "scan_safe_counts": dict(sorted(scan_safe_counter.items())),
            "assumption_counts": dict(sorted(assumption_counter.items())),
            "evidence_counts": dict(sorted(evidence_counter.items())),
            "helper_status_counts": dict(sorted(helper_status_counter.items())),
            "helper_candidate_counts": dict(sorted(helper_candidate_counter.items())),
            "helper_refusal_counts": dict(sorted(helper_refusal_counter.items())),
            "helper_family_rows": list(helper_family_rows),
        }

    return _impl()


RECOVERY_CONFIDENCE_AXES: tuple[tuple[str, str], ...] = (
    ("target_recovered_strong", "Recovered output with stable evidence and no active assumptions."),
    ("bounded_recovery", "Bounded scan-safe recovery completed without requiring decompilation."),
    ("helper_guessed_weak", "Helper signatures still need stronger evidence."),
    ("far_pointer_unresolved", "Far-pointer or far-call association is not yet stable."),
    ("return_shape_uncertain", "Postprocess still depends on an unstable return-shape boundary."),
    ("target_unrecovered", "The target could not be recovered with the current evidence."),
)


def describe_x86_16_recovery_confidence_axes() -> tuple[tuple[str, str], ...]:
    """Return the stable recovery confidence axis descriptions."""
    return RECOVERY_CONFIDENCE_AXES
