"""Explicit comparison choices independent of architecture installation.

Layer: dosunit proof contracts.
Responsibility: name layout inference and identity-shortcut admission policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class LayoutNormalization(StrEnum):
    """Whether comparison may infer layout constants from real16 evidence."""

    INFERRED = "inferred"
    EXPLICIT_ONLY = "explicit_only"


class ComparisonRefusal(StrEnum):
    """Evidence boundaries introduced by explicit comparison policy."""

    REGION_NORMALIZATION_REQUIRES_BLOCK_PROOF = "region_normalization_requires_block_proof"


@dataclass(frozen=True, slots=True)
class ComparisonPolicy:
    """Immutable policy carried through pair, region, callee and edge proofs.

    Explicit-only layout leaves each function's declared constant map intact
    and does not derive additional maps from instruction or image heuristics.
    Literal identity prevents raw SSA or byte equality from bypassing solving
    when either side has a nonempty constant-normalization map.
    """

    layout_normalization: LayoutNormalization = LayoutNormalization.INFERRED
    require_literal_identity: bool = False

    def document(self) -> dict[str, str | bool]:
        """Serialize the active choices alongside the comparison options."""
        return {
            "layout_normalization": self.layout_normalization.value,
            "require_literal_identity": self.require_literal_identity,
        }


DEFAULT_COMPARISON_POLICY: ComparisonPolicy = ComparisonPolicy()
EXPLICIT_COMPARISON_POLICY: ComparisonPolicy = ComparisonPolicy(
    layout_normalization=LayoutNormalization.EXPLICIT_ONLY,
    require_literal_identity=True,
)
