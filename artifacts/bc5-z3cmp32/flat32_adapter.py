"""Layer: validation adapter.

Responsibility: scope flat i386 VEX patches to one dosunit comparison process.
The accepted proof surfaces are complete leaves and closed matched integer CFGs.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path("/home/xor/vextest")))
import angr
import archinfo
import pyvex

from tools.dosunit import straightline_ssa as S

GPRS: tuple[str, ...] = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
REG_NAMES: tuple[str, ...] = (
    *GPRS,
    "cc_op",
    "cc_dep1",
    "cc_dep2",
    "cc_ndep",
    "d",
    "eip",
    "cs",
    "ds",
    "es",
    "fs",
    "gs",
    "ss",
)
ARCH = archinfo.ArchX86()
REG32: dict[int, tuple[str, int]] = {ARCH.registers[name][0]: (name, ARCH.registers[name][1] * 8) for name in REG_NAMES}
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
_ORIGINAL_LOWER = S._lower_expr
_ORIGINAL_FINISH = S._finish_irsb_lowering
_ORIGINAL_QUICK = S._quick_compare_functions
CONTROL_TARGETS: dict[int, int] | None = None


def load32(exe_path: Path) -> angr.Project:
    """Force PE for MZ images, retaining CLE's actual linked and mapped bases."""
    with Path(exe_path).open("rb") as stream:
        magic = stream.read(4)
    backend = "pe" if magic[:2] == b"MZ" else "elf"
    project = angr.Project(str(exe_path), auto_load_libs=False, main_opts={"backend": backend})
    if project.arch.name != "X86":
        raise ValueError(f"expected i386, found {project.arch.name}: {exe_path}")
    return project


def register_access(offset: int, width: int | None) -> tuple[str, int, int] | None:
    """Resolve full, low-word, low-byte and legacy high-byte guest registers."""
    for base, (name, bits) in REG32.items():
        if offset == base and (width is None or width == bits):
            return name, bits, 0
        if name in GPRS and offset == base and width in (8, 16):
            return name, bits, 0
        if name in GPRS[:4] and offset == base + 1 and width in (None, 8):
            return name, bits, 8
    return None


def read_register(
    versions: dict[str, S.SsaExpr], offset: int, width: int, *, source: str
) -> S.SsaExpr | S.LowerFailure:
    """Read a partial register without dropping the enclosing register's width."""
    access = register_access(offset, width)
    if access is None:
        return S.LowerFailure("unsupported_ir", f"{source}: unsupported register {offset}:{width}")
    name, bits, shift = access
    value = versions.get(name, S.SsaExpr("input", bits, name=name))
    if shift:
        value = S.SsaExpr("lshr", bits, (value, S.SsaExpr("const", bits, value=shift)))
    return S._coerce_width(value, width)


def write_target(offset: int, width: int | None) -> tuple[str, int] | None:
    """Make partial writes depend on their full enclosing register for liveness."""
    access = register_access(offset, width)
    return None if access is None else access[:2]


def write_register(versions: dict[str, S.SsaExpr], offset: int, value: S.SsaExpr) -> S.LowerFailure | None:
    """Preserve upper bits for i386 byte/word writes, including AH/CH/DH/BH."""
    access = register_access(offset, value.width)
    if access is None:
        return S.LowerFailure("unsupported_ir", f"unsupported register write {offset}:{value.width}")
    name, bits, shift = access
    if value.width == bits:
        versions[name] = value
        return None
    previous = versions.get(name, S.SsaExpr("input", bits, name=name))
    mask = ((1 << bits) - 1) ^ (((1 << value.width) - 1) << shift)
    kept = S.SsaExpr("and", bits, (previous, S.SsaExpr("const", bits, value=mask)))
    inserted = S._coerce_width(value, bits)
    if shift:
        inserted = S.SsaExpr("shl", bits, (inserted, S.SsaExpr("const", bits, value=shift)))
    versions[name] = S.SsaExpr("or", bits, (kept, inserted))
    return None


def lower_expr(expr: pyvex.expr.IRExpr, **kwargs: Any) -> S.SsaExpr | S.LowerFailure:  # noqa: ANN401
    # kwargs crosses the private VEX lowering API; all values are forwarded unchanged.
    """Abstract the known pure lazy-flag helpers; refuse all other CCalls."""
    if isinstance(expr, pyvex.expr.Const) and not isinstance(expr.con.value, int):
        return S.LowerFailure("unsupported_ir", "floating-point constants are outside the integer proof model")
    if not isinstance(expr, pyvex.expr.CCall):
        return _ORIGINAL_LOWER(expr, **kwargs)
    arities = {"x86g_calculate_condition": 5, "x86g_calculate_eflags_c": 4, "x86g_calculate_eflags_all": 4}
    if len(expr.args) != arities.get(expr.cee.name):
        return S.LowerFailure("unsupported_ir", f"unsupported CCall: {expr.cee.name}")
    args: list[S.SsaExpr] = []
    for argument in expr.args:
        lowered = lower_expr(argument, **kwargs)
        if isinstance(lowered, S.LowerFailure):
            return lowered
        args.append(lowered)
    return S.SsaExpr(f"summary_{expr.cee.name}", expr.result_size(kwargs["tyenv"]), tuple(args))


def declared_bounds_only(*, project: angr.Project, function_base: int, successor: int) -> bool:
    """Keep region scans within complete function bounds supplied by the listing."""
    return False


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
        for guard, destination in reversed(state.exits):
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
    body["id"] = S.stable_id("ssa-function", body)
    return [body], [], 1



def quick_compare(oracle: dict[str, Any], candidate: dict[str, Any], *, skip_binary_equal: bool) -> dict[str, Any] | None:
    """Raw SSA identity is sufficient only when neither side rewrites constants."""
    if oracle.get('_constant_normalization') or candidate.get('_constant_normalization'):
        return None
    return _ORIGINAL_QUICK(oracle, candidate, skip_binary_equal=skip_binary_equal)


@contextmanager
def installed(
    control_targets: dict[int, int] | None = None, *, region: bool = False
) -> Iterator[None]:
    """Install and restore every seam, including maps, even on exceptions."""
    global CONTROL_TARGETS
    prior_targets = CONTROL_TARGETS
    CONTROL_TARGETS = control_targets
    replacements = {
        "_load_lifter_project": load32,
        "_vex_live_statement_indices": all_statements,
        "REG_BY_OFFSET": REG32,
        "RAW_OUTPUT_REGS": GPRS,
        "BYTE_REGISTER_ACCESS": {},
        "_lower_expr": lower_expr,
        "_read_register": read_register,
        "_write_register": write_register,
        "_register_write_target": write_target,
        "_finish_irsb_lowering": _ORIGINAL_FINISH if region else finish_lowering,
        "_prepare_layout_normalized_functions": strict_layout,
        "_quick_compare_functions": quick_compare,
    }
    if region:
        # Region mode lowers through the native multi-block scan; the leaf
        # single-block _lower_function override is intentionally absent.
        # Out-of-bounds successors refuse instead of scanning into neighbours.
        replacements["_can_add_dynamic_successor_range"] = declared_bounds_only
    else:
        replacements["_lower_function"] = lower_function
    # This is the explicitly isolated monkey-patch boundary, not owned data access.
    previous = {name: getattr(S, name) for name in replacements}
    try:
        for name, value in replacements.items():
            setattr(S, name, value)
        yield
    finally:
        CONTROL_TARGETS = prior_targets
        for name, value in previous.items():
            setattr(S, name, value)
