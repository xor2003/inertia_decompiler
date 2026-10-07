"""Explicit successor discovery admission at the loader boundary.

Layer: dosunit lowering contracts.
Responsibility: describe range admission without importing a backend or scanner.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol


class FunctionLoweringPolicy(Enum):
    """Select a function lowering owner independently of mutable legacy facades."""

    SCAN = "scan"
    FLAT32_LEAF = "flat32_leaf"


class SuccessorRangeAdmission(Protocol):
    """Admit a discovered successor using caller-owned loaded-image evidence."""

    def __call__(self, *, project: Any, function_base: int, successor: int) -> bool:  # noqa: ANN401
        """Decide extension eligibility at the opaque third-party loader boundary.

        This callback never authorizes extension of declared-only ranges; the
        scanner's authoritative range policy remains the first admission gate.
        """
        ...
