"""Independent architectural-view/version and duplicate-capture controls.

Layer: Widening regression tests.
Responsibility: keep captured word and producer projections coherent while
refusing contradictory register views, absent versions and duplicate producers.
"""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.widening import entry_word_transport as _TRANSPORT
from angr_platforms.X86_16.widening import entry_word_transport_snapshots as _SNAPSHOTS
from angr_platforms.X86_16.widening import entry_word_transport_state as _STATE
from test_x86_16_entry_word_transport import EXTERNAL, TARGET, _const, _mov, _reg, _tmp
from test_x86_16_entry_word_transport_snapshots import _prove, _snap


def test_word_snapshot_cannot_use_a_32bit_register_name_as_a_16bit_view() -> None:
    """The EAX name describes a 32-bit view, not an AX capture in disguise."""
    proof = _prove([
        _mov(_reg("eax"), _reg("cx")),
        _mov(_tmp(9), _reg("eax")),
        _mov(_reg("dx"), _snap("eax", 9)),
    ], index=2)
    assert proof.verdict is _TRANSPORT.EntryWordTransportVerdict8616.REFUSED


@pytest.mark.parametrize("register,version", [("cx", None), ("ecx", 0)])
def test_snapshot_origin_requires_a_known_full_word_version(
    register: str, version: int | None,
) -> None:
    """An unversioned or contradictory source cannot earn capture evidence."""
    source = IRValue(MemSpace.REG, name=register, size=2, version=version)
    assert _SNAPSHOTS.snapshot_capture_view_8616(source) is None


def test_duplicate_producer_invalidates_retained_capture_as_well_as_word() -> None:
    """A refused duplicate cannot retain a competing True snapshot projection."""
    source = IRValue(MemSpace.REG, name="cx", size=2, version=0)
    run, _ = _STATE.transfer_block_8616(
        block_addr=TARGET,
        ssa_instrs=(_mov(_tmp(9), _const(0)), _mov(_tmp(9), source)),
        entry_regs={"cx": True}, stop_index=2, seed_index=None,
        seed_name="", seed_version=None, successor_addrs=(EXTERNAL,),
    )
    assert run.refusals
    assert run.temps[9].word is False
    assert run.temps[9].capture is None
