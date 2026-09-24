"""Derive the proven first stack-argument machine-BP offset for one function.

Layer: Types/Lowering.
Responsibility: expose the argument-frame base proven by the terminal return
frame. A near function's two-byte return leaves the first argument at machine
``BP+4``; a far function's ``retf`` frame restores caller CS at ``BP+4..+5``, so
its first argument starts at ``BP+6``. Without far-frame proof the near base is
kept rather than guessed. Consumes alias, widening, and typed facts. Do not
recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Any, Protocol, cast

from ..alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreVerdict8616,
)
from ..ir.vex_control_flow import terminal_ret_instruction_addrs_8616
from ..semantics.terminal_return_contract import TerminalReturnFrameKind8616
from ..semantics.terminal_stack_cleanup import terminal_stack_cleanup_at_address_8616

__all__ = [
    "FAR_FIRST_ARGUMENT_BP_OFFSET_8616",
    "NEAR_FIRST_ARGUMENT_BP_OFFSET_8616",
    "proven_far_return_frame_8616",
    "proven_far_return_frame_at_8616",
    "proven_first_argument_machine_bp_offset_8616",
    "proven_first_argument_machine_bp_offset_at_8616",
]

NEAR_FIRST_ARGUMENT_BP_OFFSET_8616: int = 4
FAR_FIRST_ARGUMENT_BP_OFFSET_8616: int = 6
_FAR_RETURN_REGISTER_8616 = "cs"


class _ArgumentFrameCodegen8616(Protocol):
    """Codegen fields carrying the frame and segment-restore proofs."""

    _inertia_vex_ir_artifact: object
    _inertia_segment_stack_restore_artifact: object


def proven_far_return_frame_8616(codegen: object) -> bool:
    """Return whether the terminal frame is a proven far return.

    A ``cs`` stack restore at a block-terminal RET with no in-function save is
    the caller-pushed far return frame pop. The alias layer records that restore
    as ``UNKNOWN_REFUSE`` precisely because the save belongs to the caller's far
    call; such a fact proves the far frame and therefore the ``BP+4`` CS slot.
    """
    boundary = cast(_ArgumentFrameCodegen8616, codegen)
    try:
        artifact = boundary._inertia_segment_stack_restore_artifact
        ir_artifact = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return False
    if not isinstance(artifact, SegmentStackRestoreArtifact8616):
        return False
    terminal_rets = terminal_ret_instruction_addrs_8616(ir_artifact)
    if not terminal_rets:
        return False
    return any(
        fact.restore_register == _FAR_RETURN_REGISTER_8616
        and fact.saved_instruction_addr is None
        and fact.verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
        and fact.restore_instruction_addr in terminal_rets
        for fact in artifact.facts
    )


def proven_far_return_frame_at_8616(project: object, function_addr: int) -> bool:
    """Return whether the function at ``function_addr`` ends in a far return.

    This is the codegen-free variant used when reasoning about a callee whose
    own terminal ``retf``/``lret`` is the authority; decoded terminal evidence
    must agree on a single far frame kind.
    """
    evidence = terminal_stack_cleanup_at_address_8616(project, function_addr)
    return (
        evidence.complete
        and evidence.consistent_return_frame_kind is TerminalReturnFrameKind8616.FAR
    )


def proven_first_argument_machine_bp_offset_8616(codegen: object) -> int:
    """Return the machine-BP offset of the first stack argument.

    A far frame reserves ``BP+4..+5`` for the caller CS word, so arguments begin
    at ``BP+6``. A near frame begins them at ``BP+4``. The near base is the
    default whenever far-frame proof is absent.
    """
    if proven_far_return_frame_8616(codegen):
        return FAR_FIRST_ARGUMENT_BP_OFFSET_8616
    return NEAR_FIRST_ARGUMENT_BP_OFFSET_8616


def proven_first_argument_machine_bp_offset_at_8616(
    project: object,
    function_addr: int,
) -> int:
    """Return the machine-BP first-argument base for the function at an address."""
    if proven_far_return_frame_at_8616(project, function_addr):
        return FAR_FIRST_ARGUMENT_BP_OFFSET_8616
    return NEAR_FIRST_ARGUMENT_BP_OFFSET_8616


def msc_calling_convention_for_function_8616(project: object, function: object) -> object:
    """Return the proven Microsoft C calling convention for one function.

    A function whose terminal return is ``retf``/``lret`` owns a four-byte
    return frame and needs ``SimCC8616MSClarge`` so its stack arguments resolve
    at ``BP+6``; every other function keeps the near ``SimCC8616MSCsmall``
    convention rather than guessing a far frame.
    """
    from ..simos_86_16 import SimCC8616MSClarge, SimCC8616MSCsmall

    arch = cast(Any, project).arch
    # Dynamic angr boundary: recovered Function objects may lack .addr.
    addr = getattr(function, "addr", None)
    far = isinstance(addr, int) and proven_far_return_frame_at_8616(project, addr)
    if far:
        return SimCC8616MSClarge(arch)
    return SimCC8616MSCsmall(arch)
