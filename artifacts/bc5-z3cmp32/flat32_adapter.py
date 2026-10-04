"""Layer: validation adapter.

Responsibility: scope flat i386 VEX patches to one dosunit comparison process.
The accepted proof surfaces are complete leaves and closed matched integer CFGs.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

# Resolve shared proof owners from this checkout, including frozen snapshots.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import angr
import archinfo
import pyvex

from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_lifting import (
    _FLAT32_GPRS as GPRS,
)
from tools.dosunit.flat32_lifting import (
    _FLAT32_REG_NAMES as REG_NAMES,
)
from tools.dosunit.flat32_lifting import (
    _FLAT32_REGS as REG32,
)
from tools.dosunit.flat32_lifting import (
    _flat32_lower_expr as lower_expr,
)
from tools.dosunit.flat32_lifting import (
    _flat32_read_register as read_register,
)
from tools.dosunit.flat32_lifting import (
    _flat32_register_access,
)
from tools.dosunit.flat32_lifting import (
    _flat32_write_register as write_register,
)
from tools.dosunit.flat32_lifting import (
    _flat32_write_target as write_target,
)
from tools.dosunit.flat32_pe_loader import InclusivePE
from tools.dosunit.model import stable_id

ARCH: archinfo.ArchX86 = archinfo.ArchX86()

register_access: Callable[[int, int | None], tuple[str, int, int] | None] = _flat32_register_access

# GCC may freely clobber ecx/edx; callers observe the explicitly chosen contract.
OUTPUT_REGS: tuple[str, ...] = (
    "eax",
    "edx",
    "esp",
    "ebx",
    "ebp",
    "esi",
    "edi",
    "eip",
    "d",
    "cs",
    "ds",
    "es",
    "fs",
    "gs",
    "ss",
)
_ORIGINAL_FINISH = S._finish_irsb_lowering
_ORIGINAL_QUICK = S._quick_compare_functions
CONTROL_TARGETS: dict[int, int] | None = None


def load32(exe_path: Path, *, perform_relocations: bool = True) -> angr.Project:
    """Retain the inclusive PE end before applying optional loader relocations."""
    with Path(exe_path).open("rb") as stream:
        magic = stream.read(4)
    backend = "pe" if magic[:2] == b"MZ" else "elf"
    if backend == "pe":
        project = angr.Project(
            str(exe_path), auto_load_libs=False,
            main_opts={"backend": InclusivePE, "max_mapped_bytes": 64 * 1024 * 1024},
            load_options={"perform_relocations": perform_relocations},
        )
    else:
        project = angr.Project(str(exe_path), auto_load_libs=False, main_opts={"backend": backend})
    if project.arch.name != "X86":
        raise ValueError(f"expected i386, found {project.arch.name}: {exe_path}")
    return project


def declared_bounds_only(*, project: angr.Project, function_base: int, successor: int) -> bool:
    """Keep region scans within complete function bounds supplied by the listing."""
    return False


def executable_section_bounds(*, project: angr.Project, function_base: int, successor: int) -> bool:
    """Admit successors inside executable image bytes — .lst proc extents understate
    real reachability through shared tails and tail-called neighbors."""
    section = project.loader.find_section_containing(successor)
    if section is not None:
        return bool(section.is_executable)
    return S._loader_bytes(project, successor, 1) is not None


def finish_lowering(
    state: S._IrsbLowerState, *, irsb: pyvex.IRSB, output_regs: tuple[str, ...], max_assignments_per_function: int
) -> dict[str, Any] | S.LowerFailure:
    """Expose all 32 bits of the return address; never accept a branch prefix."""
    if CONTROL_TARGETS is None and (irsb.jumpkind != "Ijk_Ret" or state.exits):
        return S.LowerFailure(
            "flat32_control_flow",
            "requires a complete single-block near return; calls/CFG/loops need a 32-bit region owner",
        )
    address = lower_expr(
        irsb.next,
        temp_defs=state.temp_defs,
        temp_failures=state.temp_failures,
        reg_versions=state.reg_versions,
        tyenv=irsb.tyenv,
        memory=state.mem_version,
    )
    if isinstance(address, S.LowerFailure):
        return address
    if CONTROL_TARGETS is not None:
        if irsb.jumpkind == "Ijk_Boring":
            if address.op != "const" or address.value not in CONTROL_TARGETS:
                return S.LowerFailure("flat32_indirect_control", "unmapped direct successor")
            address = S.SsaExpr("const", 32, value=CONTROL_TARGETS[address.value])
        elif irsb.jumpkind != "Ijk_Ret":
            return S.LowerFailure("call_boundary", "only direct CFG edges and near returns are admitted")
        for guard, destination, jumpkind in reversed(state.exits):
            if jumpkind != "Ijk_Boring":
                return S.LowerFailure("flat32_exception_edge", "only ordinary conditional edges are admitted")
            if destination.op != "const" or destination.value not in CONTROL_TARGETS:
                return S.LowerFailure("flat32_indirect_control", "unmapped conditional successor")
            address = S.SsaExpr(
                "ite", 32, (guard, S.SsaExpr("const", 32, value=CONTROL_TARGETS[destination.value]), address)
            )
        state.memory_touched = True
    state.reg_versions["eip"] = address
    return _ORIGINAL_FINISH(
        state, irsb=irsb, output_regs=output_regs, max_assignments_per_function=max_assignments_per_function
    )


def strict_layout(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    global_map: dict[int, int] | None = None,
    image_context: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], None]:
    """Keep explicit normalization; disable inferred 16-bit layout heuristics."""
    return oracle, candidate, None


def all_statements(irsb: pyvex.IRSB, output_regs: tuple[str, ...]) -> set[int]:
    """Retain statements until partial-register liveness has a 32-bit proof owner."""
    return set(range(len(irsb.statements)))


def lower_function(
    *,
    project: angr.Project,
    linked_base: int,
    function: dict[str, Any],
    output_regs: tuple[str, ...],
    scan_limit: int,
    max_assignments_per_function: int,
    **_limits: object,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Own flat addresses and complete-body metadata instead of truncating DOS IPs."""
    start = linked_base + int(function["entry"]["offset"], 0)
    size = min(function["size"], scan_limit)
    block = project.factory.block(start, size=size, opt_level=0)
    lowered = S._lower_irsb(
        block.vex, output_regs=output_regs, max_assignments_per_function=max_assignments_per_function
    )
    if isinstance(lowered, S.LowerFailure):
        return [], [S._refusal(function, lowered.reason, lowered.message)], 1
    entry = {"linear": hex(start)}
    body = {
        "function": {"id": function["id"], "name": function["names"][0]},
        "part": {"kind": "block", "index": 0, "entry_delta": "0x0"},
        "function_entry": entry,
        "entry": entry,
        "source": {"ir": "vex", "jumpkind": block.vex.jumpkind, "machine_code_size": block.size},
        **lowered,
    }
    body["id"] = stable_id("ssa-function", body)
    return [body], [], 1



def quick_compare(oracle: dict[str, Any], candidate: dict[str, Any], *, skip_binary_equal: bool) -> dict[str, Any] | None:
    """Raw SSA identity is sufficient only when neither side rewrites constants."""
    if oracle.get('_constant_normalization') or candidate.get('_constant_normalization'):
        return None
    result: dict[str, Any] | None = _ORIGINAL_QUICK(oracle, candidate, skip_binary_equal=skip_binary_equal)
    return result


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
        S._prepare_layout_normalized_functions,
        S._quick_compare_functions,
        S._lower_function,
        S._can_add_dynamic_successor_range,
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
        S._prepare_layout_normalized_functions = strict_layout
        S._quick_compare_functions = quick_compare
        if region:
            # Listing ranges can omit shared tails; retain the driver's existing
            # executable-section policy without changing the execution lifter.
            S._can_add_dynamic_successor_range = executable_section_bounds
        else:
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
            S._prepare_layout_normalized_functions,
            S._quick_compare_functions,
            S._lower_function,
            S._can_add_dynamic_successor_range,
        ) = previous
