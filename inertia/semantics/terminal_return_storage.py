"""Project complete terminal paths onto one exact return-storage class.

Layer: Semantics.
Responsibility: distinguish AL, AH, AX, and DX:AX return carriers only after
the binary terminal-path census closes with one identical storage class.
Forbidden: C type selection, prototype mutation, source/COD/name evidence,
rendered-text recovery, or any fallback from a successful path subset.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from enum import StrEnum

from .terminal_register_returns import (
    TerminalAxReturnEvidence8616,
    TerminalAxReturnLane8616,
    TerminalReturnStorageState8616,
    collect_terminal_ax_return_evidence_8616,
)

__all__ = [
    "TerminalReturnStorage8616",
    "consistent_terminal_return_storage_8616",
    "terminal_return_storage_8616",
]


class TerminalReturnStorage8616(StrEnum):
    """Exact register carrier shared by every reachable terminal path."""

    NONE = "none"
    CALL_OUTPUT = "call_output"
    AL = "al"
    AH = "ah"
    AX = "ax"
    DX_AX = "dx_ax"


def _path_storage_8616(
    state: TerminalReturnStorageState8616,
) -> TerminalReturnStorage8616 | None:
    """Classify one terminal path without discarding split-pair provenance."""
    if state.call_output_only:
        return TerminalReturnStorage8616.CALL_OUTPUT
    explicit_lanes = state.explicit_ax_lanes
    if state.dx_ax_pair_proven:
        return (
            TerminalReturnStorage8616.DX_AX
            if explicit_lanes is TerminalAxReturnLane8616.WORD
            else None
        )
    return {
        TerminalAxReturnLane8616.NONE: TerminalReturnStorage8616.NONE,
        TerminalAxReturnLane8616.LOW: TerminalReturnStorage8616.AL,
        TerminalAxReturnLane8616.HIGH: TerminalReturnStorage8616.AH,
        TerminalAxReturnLane8616.WORD: TerminalReturnStorage8616.AX,
    }.get(explicit_lanes)


def consistent_terminal_return_storage_8616(
    evidence: TerminalAxReturnEvidence8616,
) -> TerminalReturnStorage8616 | None:
    """Return one exact carrier only when the complete path census agrees."""
    if not evidence.complete or not evidence.storage_states:
        return None
    storages = frozenset(_path_storage_8616(state) for state in evidence.storage_states)
    if None in storages or len(storages) != 1:
        return None
    storage = next(iter(storages))
    return storage if isinstance(storage, TerminalReturnStorage8616) else None


def terminal_return_storage_8616(
    project: object,
    function: object,
) -> TerminalReturnStorage8616 | None:
    """Collect and classify the exact return carrier for one function."""
    evidence = collect_terminal_ax_return_evidence_8616(project, function)
    return consistent_terminal_return_storage_8616(evidence)
