"""Native source-bound symbolic near-jump controls for region discovery.

Layer: tests.
Responsibility: preserve full loaded targets and refuse corrupted VEX, selector
wrap, indirect transfers and source drift without treating candidates as proof.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import cast

import capstone
import pytest
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from pyvex.types import Arch

import tools.dosunit.catalog.binary_callee_region_scan as scanner
import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.catalog.binary_callee_control_target import proven_terminal_target
from tools.dosunit.catalog.binary_callee_region_contracts import (
    EdgeKind,
    RegionScanBudget,
    RegionScanOutcome,
    RegionScanRefusalReason,
    RegionScanRequest,
    RegionScanStatus,
    ScanWindow,
)


def _native(code: bytes, address: int) -> pyvex.IRSB:
    """Lift exact real16 bytes through the production native lifter."""
    # pyvex declares a narrower Arch protocol than archinfo register/endness types.
    return pyvex.IRSB(code, address, cast(Arch, Arch86_16()), opt_level=0)


def _scan(
    code: bytes, address: int = 0x1260, *,
    mutate: Callable[[pyvex.IRSB], None] | None = None,
    live_bytes: bytes | None = None,
) -> RegionScanOutcome:
    """Use actual VEX and exact native instruction records in the real scanner."""
    def lift(start: int, size: int) -> S.LiftedBlock:
        blob = code[start - address:start - address + size]
        block = _native(blob, start)
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        records = [{"linear": insn.address, "size": insn.size,
                    "bytes": bytes(insn.bytes).hex(), "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str}
                   for insn in decoder.disasm(blob[:block.size], start)]
        if mutate is not None and start == address:
            mutate(block)
        return S.LiftedBlock(irsb=block, instructions=records, lifted=True)

    def read(start: int, size: int) -> bytes | None:
        image = code if live_bytes is None else live_bytes
        offset = start - address
        if offset < 0 or offset + size > len(image):
            return None
        return image[offset:offset + size]

    return scanner.scan_candidate_region(RegionScanRequest(
        address, ScanWindow(address, address + len(code)),
        RegionScanBudget(max_blocks=4, max_instructions=8, max_bytes=32, max_span=32),
        lift, read, mode_bits=16,
    ))


@pytest.mark.parametrize("address", [0x1260, 0x11260])
def test_native_symbolic_jump_scan_keeps_full_loaded_target(address: int) -> None:
    """A symbolic JMP+0 reaches the real RET without losing the upper address."""
    code = bytes.fromhex("eb00c3")
    block = _native(code, address)
    assert isinstance(block.next, pyvex.expr.RdTmp)
    assert proven_terminal_target(block, code[:2], head=address, size=2) == address + 2
    result = _scan(code, address)
    assert result.status is RegionScanStatus.COMPLETED, result
    assert result.terminals == (address + 2,)
    edge = result.blocks[0].edges[0]
    assert edge.kind is EdgeKind.DIRECT_DEFAULT_NEXT
    assert edge.target == address + 2
    assert result.blocks[0].next_repr.startswith("t")


def test_same_bytes_with_wrong_vex_displacement_refuses() -> None:
    """Matching source bytes do not authorize a contradictory symbolic next."""
    def mutate(block: pyvex.IRSB) -> None:
        forged = _native(bytes.fromhex("eb01"), block.addr)
        block.statements = forged.statements
        block.next = forged.next
        block.tyenv = forged.tyenv

    result = _scan(bytes.fromhex("eb00c3"), mutate=mutate)
    assert result.status is RegionScanStatus.REFUSED
    assert result.refusal is not None
    assert result.refusal.reason is RegionScanRefusalReason.INDIRECT_CONTROL


def test_changed_high_control_bits_refuse() -> None:
    """The original low word cannot validate an altered full physical next."""
    def mutate(block: pyvex.IRSB) -> None:
        block.next = pyvex.expr.Binop("Iop_Add32", [block.next, pyvex.expr.Const(pyvex.const.U32(0x10000))])

    result = _scan(bytes.fromhex("eb00c3"), mutate=mutate)
    assert result.status is RegionScanStatus.REFUSED
    assert result.refusal is not None
    assert result.refusal.reason is RegionScanRefusalReason.INDIRECT_CONTROL


@pytest.mark.parametrize("code,address", [("eb00c3", 0x1FFFE), ("ffe0c3", 0x1260)],
                         ids=["selector_wrap", "indirect_register"])
def test_selector_dependent_or_indirect_control_refuses(code: str, address: int) -> None:
    """A decoded target that varies by CS, or an indirect JMP, stays unresolved."""
    result = _scan(bytes.fromhex(code), address)
    assert result.status is RegionScanStatus.REFUSED
    assert result.refusal is not None
    assert result.refusal.reason is RegionScanRefusalReason.INDIRECT_CONTROL


def test_proved_target_cannot_expand_scan_window() -> None:
    """Even a proven physical successor must remain in the declared window."""
    result = _scan(bytes.fromhex("eb06c3"))
    assert result.status is RegionScanStatus.REFUSED
    assert result.refusal is not None
    assert result.refusal.reason is RegionScanRefusalReason.EXTERNAL_EDGE


def test_live_source_drift_refuses() -> None:
    """Valid lift evidence cannot survive a different loaded instruction byte."""
    result = _scan(bytes.fromhex("eb00c3"), live_bytes=bytes.fromhex("eb01c3"))
    assert result.status is RegionScanStatus.REFUSED
    assert result.refusal is not None
    assert result.refusal.reason is RegionScanRefusalReason.BYTES_MISMATCH
