"""Layer: Recovery metadata.

Responsibility: summarize helper/wrapper eligibility from recovered function effects.
Forbidden: synthesizing helper signatures from names, source, COD, or rendered C.
"""

from __future__ import annotations

from dataclasses import dataclass

from .function_effect_summary import FunctionEffectSource, FunctionEffectSummary, summarize_x86_16_function_effects

__all__ = [
    "HelperEligibilityRefusal",
    "HelperEligibilitySummary",
    "summarize_x86_16_helper_eligibility",
]


@dataclass(frozen=True, slots=True)
class HelperEligibilityRefusal:
    """Reason that a function is not eligible for helper-wrapper treatment."""

    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class HelperEligibilitySummary:
    """Decision summary for helper/wrapper eligibility from recovered effects."""

    status: str
    candidate_kind: str = "none"
    effect_summary: FunctionEffectSummary = FunctionEffectSummary()  # noqa: RUF009
    refusals: tuple[HelperEligibilityRefusal, ...] = ()

    def brief(self) -> str:
        """Return a compact stable helper eligibility diagnostic string."""
        refusal_kinds = ",".join(item.kind for item in self.refusals) or "none"
        return f"status={self.status} candidate={self.candidate_kind} refusals={refusal_kinds}"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation of helper eligibility."""
        return {
            "status": self.status,
            "candidate_kind": self.candidate_kind,
            "effect_summary": self.effect_summary.to_dict(),
            "refusals": [{"kind": item.kind, "detail": item.detail} for item in self.refusals],
        }


def _eligibility_refusals_8616(
    effect_summary: FunctionEffectSummary,
    stack_probe_helper: bool,
) -> list[HelperEligibilityRefusal]:
    """Collect every proven refusal against single-wrapper helper eligibility."""
    refusals: list[HelperEligibilityRefusal] = []
    if effect_summary.indirect_call_count > 0 or effect_summary.indirect_branch_count > 0:
        refusals.append(
            HelperEligibilityRefusal(
                "indirect_control",
                "indirect call or branch effects block stable helper-wrapper eligibility",
            )
        )
    if effect_summary.direct_branch_count > 0:
        refusals.append(
            HelperEligibilityRefusal(
                "direct_branching",
                "direct branch effects block single-wrapper helper eligibility",
            )
        )
    if effect_summary.direct_call_count != 1:
        refusals.append(
            HelperEligibilityRefusal(
                "call_count_not_single",
                "helper-wrapper eligibility currently requires exactly one direct call",
            )
        )
    if effect_summary.memory_reads or effect_summary.memory_writes:
        refusals.append(
            HelperEligibilityRefusal(
                "nonlocal_memory_effects",
                "non-frame memory effects block single-wrapper helper eligibility",
            )
        )
    clobbers = set(effect_summary.register_clobbers)
    if clobbers.intersection({"ss", "ds", "es", "cs", "flags", "cf", "zf", "sf", "of"}):
        refusals.append(
            HelperEligibilityRefusal(
                "register_clobber_side_effects",
                "segment or flag clobbers block single-wrapper helper eligibility",
            )
        )
    if effect_summary.return_kind == "unknown":
        refusals.append(
            HelperEligibilityRefusal(
                "return_kind_unknown",
                "helper-wrapper eligibility requires a settled return kind",
            )
        )
    if stack_probe_helper and effect_summary.helper_return_state == "unknown":
        refusals.append(
            HelperEligibilityRefusal(
                "helper_return_state_unknown",
                "stack-probe helper return state is unresolved; keep explicit refusal instead of guessed stack-address semantics",
            )
        )
    if (
        stack_probe_helper
        and effect_summary.helper_return_state == "stack_address"
        and effect_summary.helper_return_address_kind == "stack"
        and effect_summary.helper_return_width is None
    ):
        refusals.append(
            HelperEligibilityRefusal(
                "helper_return_width_unknown",
                "stack-probe helper stack-address returns need known width before helper-wrapper use",
            )
        )
    return refusals


def summarize_x86_16_helper_eligibility(source: FunctionEffectSource) -> HelperEligibilitySummary:
    """Classify helper-wrapper eligibility from existing function-effect facts."""
    effect_summary = summarize_x86_16_function_effects(source)
    empty_summary = summarize_x86_16_function_effects({})
    if effect_summary == empty_summary:
        return HelperEligibilitySummary(
            status="no_signal",
            effect_summary=effect_summary,
            refusals=(
                HelperEligibilityRefusal(
                    "no_effect_signal",
                    "no function-effect evidence was available for helper or wrapper inference",
                ),
            ),
        )

    stack_probe_helper = bool(source.get("stack_probe_helper", False))
    refusals = _eligibility_refusals_8616(effect_summary, stack_probe_helper)
    if refusals:
        return HelperEligibilitySummary(
            status="refused",
            effect_summary=effect_summary,
            refusals=tuple(refusals),
        )

    return HelperEligibilitySummary(
        status="eligible",
        candidate_kind="single_direct_call_wrapper",
        effect_summary=effect_summary,
    )
