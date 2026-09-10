"""Derive native string direction from the architectural DF bit.

Layer: Frontend.
Responsibility: synchronize derived direction state without introducing false
dependencies on status bits. FLAGS stays authoritative, including when native
direction state is stale. This never skips a FLAGS or direction-state write.
"""

from __future__ import annotations

from typing import Protocol, cast

from pyvex.expr import Const, RdTmp
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import IRSBCustomizer, Type

from .ir.vex_bit_source import BitSourceProjection8616, project_bit_source_8616
from .vex_value_contract import require_vex_value_8616


class _DirectionProof8616(Protocol):
    """Per-instruction evidence for every consumed DF source projection."""

    _inertia_direction_projection_reports_8616: tuple[BitSourceProjection8616, ...]
    irsb_c: IRSBCustomizer


def lifted_direction_step_8616(instruction: object, flags_value: object) -> VexValue:
    """Project DF through the lifter facade's native customizer-compatible API."""
    # The facade deliberately emulates IRSBCustomizer while retaining its own
    # VexValue identity; switching to its wrapped builder breaks operand checks.
    builder = cast(IRSBCustomizer, instruction)
    boundary = cast(_DirectionProof8616, instruction)
    flags = (
        VexValue(builder, builder.mkconst(flags_value & 0xffff, Type.int_16))
        if isinstance(flags_value, int)
        else require_vex_value_8616(require_vex_value_8616(flags_value).cast_to(Type.int_16))
    )
    block = boundary.irsb_c.irsb
    proof = project_bit_source_8616(flags.rdt, block.statements, block.tyenv, bit=10)
    try:
        reports = boundary._inertia_direction_projection_reports_8616
    except AttributeError:
        reports = ()
    boundary._inertia_direction_projection_reports_8616 = (*reports, proof)
    if not isinstance(proof.source, (RdTmp, Const)):
        raise TypeError("Direction projection must retain a captured VEX atom")
    flags = VexValue(builder, proof.source)
    direction = require_vex_value_8616(((flags >> 10) & 1).cast_to(Type.int_1))
    negative = builder.mkconst(0xFFFFFFFF, Type.int_32)
    positive = builder.mkconst(1, Type.int_32)
    return VexValue(builder, boundary.irsb_c.ite(direction.rdt, negative, positive))
