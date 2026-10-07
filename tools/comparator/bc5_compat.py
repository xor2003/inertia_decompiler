"""Layer: validation adapter.

Responsibility: scope flat i386 VEX patches to one dosunit comparison process.
The accepted proof surfaces are complete leaves and closed matched integer CFGs.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import angr
import archinfo
import pyvex

from tools.comparator.abi import DEFAULT_OUTPUT_REGS
from tools.comparator.profiles import declared_bounds_only as declared_bounds_only
from tools.comparator.profiles import executable_section_bounds as executable_section_bounds
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.architectures.flat32 import (
    _FLAT32_GPRS as GPRS,
)
from tools.dosunit.architectures.flat32 import (
    _FLAT32_REG_NAMES as REG_NAMES,
)
from tools.dosunit.architectures.flat32 import (
    _FLAT32_REGS as REG32,
)
from tools.dosunit.architectures.flat32 import (
    _flat32_lower_expr as lower_expr,
)
from tools.dosunit.architectures.flat32 import (
    _flat32_read_register as read_register,
)
from tools.dosunit.architectures.flat32 import (
    _flat32_register_access,
)
from tools.dosunit.architectures.flat32 import (
    _flat32_write_register as write_register,
)
from tools.dosunit.architectures.flat32 import (
    _flat32_write_target as write_target,
)
from tools.dosunit.architectures.flat32_control import finish_flat32_control
from tools.dosunit.architectures.flat32_leaf import lower_flat32_leaf_function as lower_function
from tools.dosunit.architectures.flat32_loader import load_flat32_project

ARCH: archinfo.ArchX86 = archinfo.ArchX86()
OUTPUT_REGS: tuple[str, ...] = DEFAULT_OUTPUT_REGS

register_access: Callable[[int, int | None], tuple[str, int, int] | None] = _flat32_register_access

# GCC may freely clobber ecx/edx; callers observe the explicitly chosen contract.
_ORIGINAL_FINISH = S._finish_irsb_lowering
CONTROL_TARGETS: dict[int, int] | None = None


def load32(exe_path: Path, *, perform_relocations: bool = True) -> angr.Project:
    """Load through the shared i386 image owner with the existing driver policy."""
    return load_flat32_project(exe_path, perform_relocations=perform_relocations)

def finish_lowering(
    state: S._IrsbLowerState, *, irsb: pyvex.IRSB, output_regs: tuple[str, ...], max_assignments_per_function: int
) -> dict[str, Any] | S.LowerFailure:
    """Delegate legacy target state to the canonical explicit control owner."""
    return finish_flat32_control(
        state, irsb=irsb, output_regs=output_regs,
        max_assignments_per_function=max_assignments_per_function, control_targets=CONTROL_TARGETS,
    )


def all_statements(irsb: pyvex.IRSB, output_regs: tuple[str, ...]) -> set[int]:
    """Retain statements until partial-register liveness has a 32-bit proof owner."""
    return set(range(len(irsb.statements)))


@contextmanager
def installed(
    control_targets: dict[int, int] | None = None, *, region: bool = False
) -> Iterator[None]:
    """Install and restore every seam, including maps, even on exceptions."""
    global CONTROL_TARGETS
    prior_targets = CONTROL_TARGETS
    CONTROL_TARGETS = control_targets
    previous = (
        S._load_lifter_project,
        S._vex_live_statement_indices,
        S.REG_BY_OFFSET,
        S.SSA_REGISTER_WIDTHS,
        S.INTERNAL_STATE_REGS,
        S.HIGH_HALF_REGS,
        S.RAW_OUTPUT_REGS,
        S.BYTE_REGISTER_ACCESS,
        S._lower_expr,
        S._read_register,
        S._write_register,
        S._register_write_target,
        S._finish_irsb_lowering,
        S._lower_function,
    )
    try:
        S._load_lifter_project = load32
        S._vex_live_statement_indices = all_statements
        S.REG_BY_OFFSET = REG32
        S.SSA_REGISTER_WIDTHS = dict(REG32.values())
        S.INTERNAL_STATE_REGS = REG_NAMES
        S.HIGH_HALF_REGS = ()
        S.RAW_OUTPUT_REGS = GPRS
        S.BYTE_REGISTER_ACCESS = {}
        S._lower_expr = lower_expr
        S._read_register = read_register
        S._write_register = write_register
        S._register_write_target = write_target
        S._finish_irsb_lowering = _ORIGINAL_FINISH if region else finish_lowering
        if not region:
            S._lower_function = lower_function
        yield
    finally:
        CONTROL_TARGETS = prior_targets
        (
            S._load_lifter_project,
            S._vex_live_statement_indices,
            S.REG_BY_OFFSET,
            S.SSA_REGISTER_WIDTHS,
            S.INTERNAL_STATE_REGS,
            S.HIGH_HALF_REGS,
            S.RAW_OUTPUT_REGS,
            S.BYTE_REGISTER_ACCESS,
            S._lower_expr,
            S._read_register,
            S._write_register,
            S._register_write_target,
            S._finish_irsb_lowering,
            S._lower_function,
        ) = previous
