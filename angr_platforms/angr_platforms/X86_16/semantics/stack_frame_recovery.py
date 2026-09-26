"""Stack frame recovery for BP/SP-based stack access semantics.

Layer: Semantics.
Responsibility: owns instruction effects, flags, branch meaning, and expression interpretation.
This module classifies frame evidence before alias consumes normalized stack
addresses.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.

AGENTS rule: SS:BP+offset → stack slot → variable (REQUIRED).
This must happen BEFORE alias sees the IR addresses.

Pipeline position:
    IR (raw) → stack_frame_recovery → normalized IR → Alias

Frame models:
    BP frame:  push bp; mov bp,sp; sub sp,N  — SS:BP+offset → STABLE stack slot
    SP frame:  sub sp,N  (no BP)            — SS:SP+offset → PROVISIONAL (no derived BP)
    none:      no SS accesses                — no stack

Rule:
    BP + constant         → STABLE stack slot
    SP + known delta      → STABLE stack slot
    raw SP / push / call  → PROVISIONAL stack access (DO NOT invent BP)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..pipeline.errors import PipelineHardError


@dataclass(frozen=True)
class StackFrameInfo8616:
    """Recovered stack-frame shape before alias consumes stack addresses."""

    function_addr: int | None
    uses_bp_frame: bool = False
    uses_sp_frame: bool = False
    bp_established: bool = False
    sp_delta_known: bool = False
    frame_base: str | None = None
    frame_kind: str = "none"
    evidence: tuple[str, ...] = ()


def _dynamic_angr_attr_8616(obj: object | None, name: str, default: object | None = None) -> object | None:
    """Dynamic angr/VEX/Capstone boundary: read optional external object attributes."""
    if obj is None:
        return default
    return getattr(obj, name, default)


def _tuple_dynamic_attr_8616(obj: object | None, name: str) -> tuple[object, ...]:
    """Return a tuple from an optional dynamic angr/VEX/Capstone sequence attribute."""
    value = _dynamic_angr_attr_8616(obj, name)
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return ()


def _semantic_access_addr_8616(access: object) -> IRAddress | None:
    """Extract an owned IRAddress from a semantic access object or tuple."""
    if isinstance(access, tuple) and len(access) >= 2 and isinstance(access[1], IRAddress):
        return access[1]
    addr = _dynamic_angr_attr_8616(access, "addr")
    return addr if isinstance(addr, IRAddress) else None


def _semantic_access_mode_8616(access: object) -> int:
    """Extract the access mode from a semantic access object or tuple."""
    if isinstance(access, tuple) and len(access) >= 1 and isinstance(access[0], int):
        return access[0]
    mode = _dynamic_angr_attr_8616(access, "mode", 0)
    return mode if isinstance(mode, int) else 0


def _is_ss(addr: object) -> bool:
    return isinstance(addr, IRAddress) and addr.space == MemSpace.SS


def _is_bp_stable(addr: object) -> bool:
    return (
        isinstance(addr, IRAddress)
        and addr.space == MemSpace.SS
        and addr.base == ("bp",)
        and isinstance(addr.offset, int)
        and addr.status == AddressStatus.STABLE
    )


def _is_sp_stable(addr: object) -> bool:
    """SP+known_delta must be proven upstream — not guessed here."""
    return (
        isinstance(addr, IRAddress)
        and addr.space == MemSpace.SS
        and addr.base == ("sp",)
        and isinstance(addr.offset, int)
        and addr.status == AddressStatus.STABLE
    )


def _count_ss_accesses(semantic_accesses: Iterable[object]) -> int:
    n = 0
    for acc in semantic_accesses:
        addr = _semantic_access_addr_8616(acc)
        if _is_ss(addr):
            n += 1
    return n


def _count_sp_provisional(semantic_accesses: Iterable[object]) -> int:
    n = 0
    for acc in semantic_accesses:
        addr = _semantic_access_addr_8616(acc)
        if (
            isinstance(addr, IRAddress)
            and addr.space == MemSpace.SS
            and addr.status == AddressStatus.PROVISIONAL
            and addr.base != ("bp",)
        ):
            n += 1
    return n


def _count_sp_stable(semantic_accesses: Iterable[object]) -> int:
    n = 0
    for acc in semantic_accesses:
        addr = _semantic_access_addr_8616(acc)
        if _is_sp_stable(addr):
            n += 1
    return n


def _count_bp_stable(semantic_accesses: Iterable[object]) -> int:
    n = 0
    for acc in semantic_accesses:
        addr = _semantic_access_addr_8616(acc)
        if _is_bp_stable(addr):
            n += 1
    return n


def _has_any_bp_base(semantic_accesses: Iterable[object]) -> bool:
    for acc in semantic_accesses:
        addr = _semantic_access_addr_8616(acc)
        if isinstance(addr, IRAddress) and addr.space == MemSpace.SS and addr.base == ("bp",):
            return True
    return False


def _has_any_sp_stable(semantic_accesses: Iterable[object]) -> bool:
    for acc in semantic_accesses:
        addr = _semantic_access_addr_8616(acc)
        if _is_sp_stable(addr):
            return True
    return False


def _looks_like_frame_evidence(obj: object) -> bool:
    def _impl() -> bool:
        """Check for BP frame evidence using structured IR artifacts, NOT text parsing.

        Accepts CapstoneInsn objects (already-parsed structured disassembly)
        or VEX IRSB objects.  Rejects plain strings / COD text.
        """
        import sys

        sys.stderr.flush()

        # ── Capstone instruction (structured, NOT text) ──
        mnemonic = _dynamic_angr_attr_8616(obj, "mnemonic")
        if mnemonic is not None:
            return _capstone_insn_is_frame_evidence(obj, str(mnemonic).lower())

        # ── VEX IRSB (direct) — check statement tags for push-bp / mov-bp-sp ──
        statements = _dynamic_angr_attr_8616(obj, "statements")
        if statements is not None:
            return _vex_irsb_has_bp_frame(obj)

        # ── angr Block — iterate capstone instructions for frame patterns ──
        capstone = _dynamic_angr_attr_8616(obj, "capstone")
        if capstone is not None:
            insns = _tuple_dynamic_attr_8616(capstone, "insns")
            if insns is not None:
                return _capstone_block_has_frame_evidence(insns)

        # ── Reject string/COD artifacts ──
        if isinstance(obj, str):
            return False

        return False

    return _impl()


def _capstone_insn_is_frame_evidence(obj: object, mnem_str: str) -> bool:
    """Match a single capstone instruction against push-bp / mov-bp-sp."""
    operands = _tuple_dynamic_attr_8616(obj, "operands")

    # push bp — register-based detection using capstone reg IDs
    if mnem_str == "push":
        for op in operands:
            reg_val = _dynamic_angr_attr_8616(op, "reg")
            if isinstance(reg_val, int) and reg_val == 6:  # X86_REG_BP = 6
                return True

    # mov bp, sp
    elif mnem_str == "mov" and len(operands) >= 2:
        dst_reg = _dynamic_angr_attr_8616(operands[0], "reg")
        src_reg = _dynamic_angr_attr_8616(operands[1], "reg")
        if isinstance(dst_reg, int) and dst_reg == 6 and isinstance(src_reg, int) and src_reg == 47:
            return True

    return False


def _capstone_block_has_frame_evidence(insns: Iterable[object]) -> bool:
    """True when any capstone instruction in the block shows frame setup."""
    for insn in insns:
        if _looks_like_frame_evidence(insn):
            return True
    return False


def _irsb_register_offsets_8616(irsb: object) -> tuple[object, object] | None:
    """Resolve (sp_offset, bp_offset) for a VEX IRSB, or None when unavailable."""
    try:
        arch = _dynamic_angr_attr_8616(irsb, "arch")
        if arch is None:
            return None
        sp_off = _dynamic_angr_attr_8616(arch, "sp_offset")
        bp_off = _dynamic_angr_attr_8616(arch, "bp_offset")
        if sp_off is None or bp_off is None:
            return None
    except Exception:
        return None
    return sp_off, bp_off


def _vex_irsb_has_bp_frame(irsb: object) -> bool:
    def _impl() -> bool:
        """Inspect VEX IRSB statements for BP frame setup patterns.

        push bp  → Ist_Store(base=SS*16+SP-2, data=GET(BP))  after  Ist_Put(SP)=SUB(GET(SP), 2)
        mov bp,sp → Ist_Put(BP) = GET(SP)
        """
        offsets = _irsb_register_offsets_8616(irsb)
        if offsets is None:
            return False
        sp_off, bp_off = offsets

        has_push_bp = False
        has_mov_bp_sp = False
        for stmt in _tuple_dynamic_attr_8616(irsb, "statements"):
            tag = _dynamic_angr_attr_8616(stmt, "tag", "")
            if tag != "Ist_Put":
                continue
            put_off = _dynamic_angr_attr_8616(stmt, "offset")
            data = _dynamic_angr_attr_8616(stmt, "data")
            if put_off == bp_off and data is not None:
                # PUT(BP) = GET(SP)  →  mov bp, sp
                if _is_reg_get(data, sp_off):
                    has_mov_bp_sp = True
            elif put_off == sp_off and data is not None:  # noqa: SIM102
                # PUT(SP) = SUB(GET(SP), 2)  →  sub sp, 2 (push)
                if _is_sub_constant(data, 2):
                    has_push_bp = True

        return has_push_bp and has_mov_bp_sp

    return _impl()


def _is_reg_get(vex_expr: object, reg_offset: object) -> bool:
    """True when vex_expr is a pure GET(reg_offset)."""
    if _dynamic_angr_attr_8616(vex_expr, "tag", "") != "Iex_Get":
        return False
    return _dynamic_angr_attr_8616(vex_expr, "offset") == reg_offset


def _is_sub_constant(vex_expr: object, constant: int) -> bool:
    """True when vex_expr is Binop(Sub, Iex_Get(...), Iex_Const(constant))."""
    if _dynamic_angr_attr_8616(vex_expr, "tag", "") != "Iex_Binop":
        return False
    if str(_dynamic_angr_attr_8616(vex_expr, "op", "")) not in ("Iop_Sub32", "Iop_Sub16"):
        return False
    rhs = _tuple_dynamic_attr_8616(vex_expr, "child_expressions")
    if rhs is None:
        return False
    try:
        const_expr = rhs[1]
    except (IndexError, TypeError):
        return False
    if _dynamic_angr_attr_8616(const_expr, "tag", "") != "Iex_Const":
        return False
    const_val = _dynamic_angr_attr_8616(const_expr, "con")
    return const_val is not None and _dynamic_angr_attr_8616(const_val, "value") == constant


def _gather_ir_artifacts_from_function_blocks(project: object | None, function_addr: int) -> list[object]:
    """Collect angr Block objects for IR-based frame detection.

    Returns empty list if project/kb/function is unavailable.
    """
    kb = _dynamic_angr_attr_8616(project, "kb")
    if kb is None:
        return []
    functions = _dynamic_angr_attr_8616(kb, "functions")
    function_lookup = _dynamic_angr_attr_8616(functions, "function")
    func = function_lookup(addr=function_addr, create=False) if callable(function_lookup) else None
    if func is None:
        return []
    artifacts: list[object] = []
    for blk in _tuple_dynamic_attr_8616(func, "blocks"):
        artifacts.append(blk)  # noqa: PERF402
    return artifacts


def _detect_sp_proven_delta_from_blocks(project: object | None, function_addr: int) -> int | None:
    def _impl() -> int | None:
        """Detect proven SP delta from IR/VEX block analysis.

        Returns the SP delta (e.g. -8, -12) if proven, or None if not determinable.
        The delta is the function's frame size from ``sub sp, N`` after BP setup.

        Uses VEX IRSB statement analysis, NOT text parsing.
        """
        irsbs = _function_irsbs_8616(project, function_addr)
        if not irsbs:
            return None

        seen_bp_established = False
        sp_delta = None

        for irsb in irsbs:
            offsets = _irsb_register_offsets_8616(irsb)
            if offsets is None:
                continue
            sp_off, bp_off = offsets
            seen_bp_established, found = _irsb_frame_sp_delta_8616(irsb, sp_off, bp_off, seen_bp_established)
            if found is not None:
                sp_delta = found

        return sp_delta

    return _impl()


def _function_irsbs_8616(project: object | None, function_addr: int) -> list[object]:
    """Gather all VEX IRSBs for a function, or empty when unavailable."""
    kb = _dynamic_angr_attr_8616(project, "kb")
    if kb is None:
        return []
    functions = _dynamic_angr_attr_8616(kb, "functions")
    function_lookup = _dynamic_angr_attr_8616(functions, "function")
    func = function_lookup(addr=function_addr, create=False) if callable(function_lookup) else None
    if func is None:
        return []

    irsbs: list[object] = []
    for blk in _tuple_dynamic_attr_8616(func, "blocks"):
        irsb = _dynamic_angr_attr_8616(blk, "vex") or _dynamic_angr_attr_8616(blk, "irsb")
        if irsb is not None:
            irsbs.append(irsb)
    return irsbs


def _irsb_frame_sp_delta_8616(
    irsb: object, sp_off: object, bp_off: object, seen_bp_established: bool
) -> tuple[bool, int | None]:
    """Scan one IRSB for BP-establishment and the first ``sub sp, N`` delta."""
    sp_delta = None
    for stmt in _tuple_dynamic_attr_8616(irsb, "statements"):
        tag = _dynamic_angr_attr_8616(stmt, "tag", "")
        if tag != "Ist_Put":
            continue

        put_off = _dynamic_angr_attr_8616(stmt, "offset")
        data = _dynamic_angr_attr_8616(stmt, "data")
        if put_off is None or data is None:
            continue

        # Detect mov bp, sp → BP frame established
        if put_off == bp_off and _is_reg_get(data, sp_off):
            seen_bp_established = True
            continue

        # Detect sub sp, N → compute frame size only AFTER BP established
        if seen_bp_established and put_off == sp_off:
            delta = _extract_sub_constant(data)
            if delta is not None and delta < 0:
                sp_delta = delta
                break  # first sub sp,N after mov bp,sp is the frame size
    return seen_bp_established, sp_delta


def _extract_sub_constant(vex_expr: object) -> int | None:
    """Extract the constant operand from SUB(GET(reg), Const(N)), returning N.

    Returns None if expression doesn't match SUB(binop) pattern.
    """
    if _dynamic_angr_attr_8616(vex_expr, "tag", "") != "Iex_Binop":
        return None
    op_name = str(_dynamic_angr_attr_8616(vex_expr, "op", ""))
    if "Sub" not in op_name:
        return None
    # Look for GET(reg) on left, Const on right
    try:
        args = _tuple_dynamic_attr_8616(vex_expr, "child_expressions")
        if args is None or len(args) < 2:
            return None
        lhs = args[0]
        rhs = args[1]
    except (IndexError, TypeError):
        return None

    if _dynamic_angr_attr_8616(lhs, "tag", "") != "Iex_Get":
        return None
    if _dynamic_angr_attr_8616(rhs, "tag", "") != "Iex_Const":
        return None
    const_val = _dynamic_angr_attr_8616(rhs, "con")
    if const_val is None:
        return None
    value = _dynamic_angr_attr_8616(const_val, "value")
    if isinstance(value, int):
        return -value  # SUB(X, N) → delta = -N
    return None


def detect_stack_frame_8616(
    *,
    function_addr: int | None = None,
    ir_artifacts: Iterable[object] = (),
    semantic_accesses: Iterable[tuple[int, IRAddress]] = (),
) -> StackFrameInfo8616:
    """Classify the function stack-frame model from structured IR evidence."""
    evidence: list[str] = []

    if _has_any_bp_base(semantic_accesses):
        evidence.append("ss:bp semantic access")
        return StackFrameInfo8616(
            function_addr=function_addr,
            uses_bp_frame=True,
            bp_established=True,
            frame_base="bp",
            frame_kind="bp",
            evidence=tuple(evidence),
        )

    for artifact in ir_artifacts:
        if _looks_like_frame_evidence(artifact):
            evidence.append("frame setup instruction evidence")
            return StackFrameInfo8616(
                function_addr=function_addr,
                uses_bp_frame=True,
                bp_established=True,
                frame_base="bp",
                frame_kind="bp",
                evidence=tuple(evidence),
            )

    if _has_any_sp_stable(semantic_accesses):
        evidence.append("ss:sp stable semantic access (delta known)")
        return StackFrameInfo8616(
            function_addr=function_addr,
            uses_sp_frame=True,
            sp_delta_known=True,
            frame_base="sp",
            frame_kind="sp",
            evidence=tuple(evidence),
        )

    ss_count = _count_ss_accesses(semantic_accesses)
    if ss_count > 0:
        evidence.append(f"ss:sp dynamic access (count={ss_count})")
        return StackFrameInfo8616(
            function_addr=function_addr,
            uses_sp_frame=True,
            sp_delta_known=False,
            frame_base="sp",
            frame_kind="sp",
            evidence=tuple(evidence),
        )

    return StackFrameInfo8616(
        function_addr=function_addr,
        frame_kind="none",
        evidence=(),
    )


def compute_bp_offset(addr: IRAddress, frame: StackFrameInfo8616) -> int | None:
    """Return the stable BP-relative offset for an SS address when proven."""
    if not isinstance(addr, IRAddress) or addr.space != MemSpace.SS:
        return None

    if not isinstance(addr.offset, int):
        return None

    if _is_bp_stable(addr):
        return addr.offset

    if _is_sp_stable(addr):
        return addr.offset

    if frame.uses_bp_frame and frame.bp_established:  # noqa: SIM102
        if addr.base in {("ss",), ("sp",), ()} and addr.status == AddressStatus.STABLE:
            return addr.offset

    return None


def normalize_stack_address_8616(addr: IRAddress, frame: StackFrameInfo8616) -> IRAddress:
    """Normalize proven SS stack addresses to stable BP-relative form."""
    if not isinstance(addr, IRAddress):
        return addr

    if addr.space != MemSpace.SS:
        return addr

    if _is_bp_stable(addr):
        return addr

    if _is_sp_stable(addr):
        return addr

    if frame.uses_bp_frame and frame.bp_established:
        bp_offset = compute_bp_offset(addr, frame)
        if bp_offset is not None:
            return IRAddress(
                space=MemSpace.SS,
                base=("bp",),
                offset=bp_offset,
                size=addr.size,
                status=AddressStatus.STABLE,
                segment_origin=addr.segment_origin if addr.segment_origin is not None else SegmentOrigin.PROVEN,
                expr=addr.expr,
            )

    return addr


def normalize_semantic_accesses_8616(
    semantic_accesses: Iterable[object],
    frame: StackFrameInfo8616,
) -> list[tuple[int, IRAddress]]:
    """Normalize semantic access addresses before alias fact production."""
    normalized: list[tuple[int, IRAddress]] = []
    for acc in semantic_accesses:
        mode = _semantic_access_mode_8616(acc)
        addr = _semantic_access_addr_8616(acc)
        if isinstance(addr, IRAddress):
            addr = normalize_stack_address_8616(addr, frame)
            normalized.append((mode, addr))
    return normalized


def assert_no_unresolved_stable_ss_before_alias_8616(
    semantic_accesses: Iterable[object],
) -> None:
    """Fail when stable SS addresses reach alias without BP/SP identity."""
    for acc in semantic_accesses:
        addr = _semantic_access_addr_8616(acc)
        if not isinstance(addr, IRAddress) or addr.space != MemSpace.SS:
            continue

        if addr.status != AddressStatus.STABLE:
            continue

        if addr.base in {("bp",), ("sp",)}:
            continue

        raise PipelineHardError(
            f"stable SS address is not BP/SP-relative before alias: base={addr.base} offset={addr.offset}",
            layer="semantics.stack_frame_recovery",
        )


__all__ = [
    "StackFrameInfo8616",
    "_count_bp_stable",
    "_count_sp_provisional",
    "_count_sp_stable",
    "_count_ss_accesses",
    "_detect_sp_proven_delta_from_blocks",
    "_gather_ir_artifacts_from_function_blocks",
    "_looks_like_frame_evidence",
    "assert_no_unresolved_stable_ss_before_alias_8616",
    "compute_bp_offset",
    "detect_stack_frame_8616",
    "normalize_semantic_accesses_8616",
    "normalize_stack_address_8616",
]
