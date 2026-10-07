"""Layer: validation control lowering.

Responsibility: finish flat32 leaf or closed mapped-CFG blocks with explicit targets.
"""

from __future__ import annotations

from typing import Any

import pyvex

from tools.dosunit.architectures.flat32 import _flat32_lower_expr
from tools.dosunit.compare import straightline_ssa as S


def finish_flat32_control(
    state: S._IrsbLowerState, *, irsb: pyvex.IRSB, output_regs: tuple[str, ...], max_assignments_per_function: int,
    control_targets: dict[int, int] | None,
) -> dict[str, Any] | S.LowerFailure:
    """Expose all 32 bits of the return address; never accept a branch prefix."""
    if control_targets is None and (irsb.jumpkind != "Ijk_Ret" or state.exits):
        return S.LowerFailure(
            "flat32_control_flow",
            "requires a complete single-block near return; calls/CFG/loops need a 32-bit region owner",
        )
    address = _flat32_lower_expr(
        irsb.next,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=irsb.tyenv,
        memory=state.mem_version,
    )
    if isinstance(address, S.LowerFailure):
        return address
    if control_targets is not None:
        if irsb.jumpkind == "Ijk_Boring":
            if address.op != "const" or address.value not in control_targets:
                return S.LowerFailure("flat32_indirect_control", "unmapped direct successor")
            address = S.SsaExpr("const", 32, value=control_targets[address.value])
        elif irsb.jumpkind != "Ijk_Ret":
            return S.LowerFailure("call_boundary", "only direct CFG edges and near returns are admitted")
        for guard, destination, jumpkind in reversed(state.exits):
            if jumpkind != "Ijk_Boring":
                return S.LowerFailure("flat32_exception_edge", "only ordinary conditional edges are admitted")
            if destination.op != "const" or destination.value not in control_targets:
                return S.LowerFailure("flat32_indirect_control", "unmapped conditional successor")
            address = S.SsaExpr(
                "ite", 32, (guard, S.SsaExpr("const", 32, value=control_targets[destination.value]), address)
            )
        state.memory_touched = True
    state.reg_versions["eip"] = address
    return S._finish_irsb_with_context(
        state, irsb=irsb, output_regs=output_regs, max_assignments_per_function=max_assignments_per_function,
        control_expression=address,
    )
