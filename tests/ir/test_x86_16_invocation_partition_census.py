"""Layer: tests. Responsibility: preserve native CFG partitions and byte census."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
import inertia.ir.real16_invocation_domain as dom
from inertia.ir.core import IRBlock, IRInstr
from tests.ir.test_x86_16_invocation_domain_boundaries import (
    _assert_ledger_closed,
    _assert_proven,
    _boot,
    _prove_stub,
)


def test_invocation_census_accepts_native_split_before_branch_target() -> None:
    """A MOV prefix ends at another branch's target, before natural decode ends."""
    code = bytes.fromhex("31c0 7403 bb3412 90 e8c5ff c3")
    premise, _project, raw = _prove_stub(_boot(code), code, 0x1038)
    prefix = next(block for block in raw.blocks if block.addr == 0x1034)
    assert {instruction.addr for instruction in prefix.instrs} == {0x1034}
    assert prefix.successor_addrs == (0x1037,)
    _assert_proven(premise)
    _assert_ledger_closed(premise)


def test_census_rejects_dropped_suffix_with_unchanged_frontend_extent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Claiming fewer IR rows must never shrink the independent byte obligation."""
    machine = {0x1000: (1, b"\x90"), 0x1001: (1, b"\x90")}
    monkeypatch.setattr(dom, "_machine_census_8616", lambda *args: machine)
    boundary = SimpleNamespace(blocks=(SimpleNamespace(addr=0x1000, size=2),))
    block = IRBlock(
        addr=0x1000, instrs=(IRInstr(op="NOP", dst=None, args=(), size=1, addr=0x1000),),
        refusals=(), successor_addrs=(),
    )
    ctx = SimpleNamespace(selector=0x100)
    failure = dom._census_block_bytes_8616(ctx, block, stop_after=None, boundary=boundary)
    assert failure is dom.Real16InvocationFailure8616.PATH_DECODE_MISMATCH
