"""Layer: IR.
Responsibility: retain raw boot census identity without claiming proven CFG edges.
"""
from __future__ import annotations

from dataclasses import dataclass

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRFunctionArtifact


@dataclass(frozen=True, slots=True)
class RawBootEntrySurface8616:
    """Exact raw startup facts; only an authenticated path census can prove them.

    This record grants neither complete coverage nor registry publication. Its
    boundary and artifact are retained by identity for replay and consumption.
    """

    artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616


def raw_boot_entry_surface_pending_8616(surface: RawBootEntrySurface8616) -> bool:
    """Return whether a raw surface's only refusals are pending window gates.

    Raw census geometry is not edge proof: the sole refusal a raw boot
    surface may carry is the importer's retained
    ``SELECTOR_WINDOW_UNPROVED`` obligation, which the consuming census
    discharges by re-evaluating each pending transfer's destination under
    the live register/tmp state, and at least one such pending obligation
    must exist — an empty refusal pool means the surface needs no raw
    bootstrap and belongs to the ordinary coverage route. Any other
    refusal kind — decode, fetch, or effect — means the surface was never
    a census this prover can close, so the surface is ineligible.
    """
    from .vex_terminal_jump import TerminalJumpRefusalReason8616

    allowed = TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED
    refusals = (
        *surface.artifact.refusals,
        *(
            row
            for block in surface.artifact.blocks
            for row in block.refusals
        ),
    )
    return bool(refusals) and all(
        refusal.kind == allowed for refusal in refusals
    )
