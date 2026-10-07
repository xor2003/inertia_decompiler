"""Layer: validation orchestration contracts.

Responsibility: resolve qualified native proof owners without artifact import state.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType


@dataclass(frozen=True)
class NativeProofOwners:
    """Explicit module boundaries for the native model and shared proof policies."""

    model: ModuleType
    cfg: ModuleType
    catalog: ModuleType
    verdict: ModuleType


def proof_owners() -> NativeProofOwners:
    """Load backend owners only when native proof execution requests them."""
    from tools.comparator import catalog, cfg, native, verdict

    return NativeProofOwners(native, cfg, catalog, verdict)
