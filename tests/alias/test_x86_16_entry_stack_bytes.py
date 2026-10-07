"""Entry-block-prefix SS byte-read proof: materialization and determinism.

Cheap binary-free tests for ``prove_entry_stack_bytes_8616``. Refusal
obligations live in ``test_x86_16_entry_stack_byte_refusals.py``; snapshot-owner
obligations live in ``test_x86_16_entry_stack_pointer_snapshots.py``; the native
POINT.EXE replay stays in external diagnostics.
"""

from __future__ import annotations

import pytest
from inertia.ir.core import IRAddress, IRInstr, MemSpace
from tests.fixtures.entry_stack_byte_test_support import (
    ENTRY_8616,
    _artifact,
    _binop,
    _capture,
    _const,
    _load,
    _mov,
    _refusal_kinds,
    _reg,
    _ss_addr,
)

from inertia.alias.entry_stack_byte_contracts import (
    EntryStackByteRefusalKind8616,
    EntryStackByteScope8616,
    EntryStackByteVerdict8616,
)
from inertia.alias.entry_stack_bytes import prove_entry_stack_bytes_8616


def test_exact_local_pair() -> None:
    """Two captured byte reads at entry-SP 0 and 1 must materialize."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), _load(1, _ss_addr(0, 1)), _load(2, _ss_addr(1, 1))])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PROVEN
    assert proof.scope is EntryStackByteScope8616.ENTRY_BLOCK_PREFIX
    assert [fact.byte_offsets for fact in proof.facts] == [(0,), (1,)]
    assert proof.facts[0].producer_tmp == 1
    assert proof.raw_fact_count == proof.materialized_count == 2
    assert proof.failure_count == 0


def test_word_load_materializes() -> None:
    """A 2-byte load materializes both byte offsets."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), _load(1, _ss_addr(2, 2), size=2)])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PROVEN
    assert proof.facts[0].byte_offsets == (2, 3)
    assert proof.facts[0].width == 2


def test_capture_survives_sp_update() -> None:
    """An observed tmp capture stays exact across a later SP write."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _load(1, _ss_addr(0, 1)),
            _binop("Iop_Add16", 9, _reg("sp", source_tmp=0), _const(2)),
            _mov(_reg("sp"), _reg("sp", offset=2, expr=("Iop_Add16",), source_tmp=9)),
            _load(2, _ss_addr(1, 1, base_tmp=0)),
            _load(3, _ss_addr(0, 1, base_tmp=None)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PROVEN
    assert [fact.byte_offsets for fact in proof.facts] == [(0,), (1,), (2,)]


@pytest.mark.parametrize(
    "store_addr",
    [_ss_addr(4, 1), IRAddress(space=MemSpace.UNKNOWN, size=1)],
    ids=["exact_store", "unknown_store"],
)
def test_prior_store_closes_but_retains_reads(store_addr: IRAddress) -> None:
    """A store after a read leaves the earlier fact; later loads refuse."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _load(1, _ss_addr(0, 1)),
            IRInstr(op="STORE", dst=None, args=(store_addr, _const(0, 1)), size=1, addr=ENTRY_8616),
            _load(2, _ss_addr(1, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PARTIAL
    assert [fact.byte_offsets for fact in proof.facts] == [(0,)]
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.PRIOR_MEMORY_WRITE]
    assert proof.prefix_closed_by is not None
    assert proof.prefix_closed_by is EntryStackByteRefusalKind8616.PRIOR_MEMORY_WRITE


def test_full_parent_write_poisons_live_sp_only() -> None:
    """An ``esp`` write poisons the live coordinate; observed captures hold."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _load(1, _ss_addr(0, 1)),
            _mov(_reg("esp", 4), _reg("esp", 4)),
            _load(2, _ss_addr(1, 1, base_tmp=0)),
            _load(3, _ss_addr(0, 1, base_tmp=None)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PARTIAL
    assert [fact.byte_offsets for fact in proof.facts] == [(0,), (1,)]
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_wrap_geometry_refused_but_edge_byte_ok() -> None:
    """The 0xFFFF byte materializes; a wrapping 2-byte range refuses."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _load(1, _ss_addr(0xFFFF, 1)),
            _load(2, _ss_addr(0xFFFF, 2), size=2),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PARTIAL
    assert [fact.byte_offsets for fact in proof.facts] == [(0xFFFF,)]
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.WRAP_GEOMETRY]


def test_negative_coordinate_canonicalizes_mod16() -> None:
    """A Sub16 capture resolves canonical modular offsets when re-presented."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _binop("Iop_Sub16", 4, _reg("sp", source_tmp=0), _const(4)),
            _load(5, _ss_addr(0, 2, base_tmp=4, base_offset=-4,
                              base_expr=("Iop_Sub16",)), size=2),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PROVEN
    assert proof.facts[0].byte_offsets == (0xFFFC, 0xFFFD)


def test_registered_iop_stays_open_but_not_frame() -> None:
    """A registered VEX op is pure; its product earns no frame coordinate."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _binop("Iop_Xor16", 7, _reg("sp", source_tmp=0), _const(1)),
            _load(1, _ss_addr(0, 1, base_tmp=7)),
            _load(2, _ss_addr(1, 1, base_tmp=0)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PARTIAL
    assert [fact.byte_offsets for fact in proof.facts] == [(1,)]
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_deterministic_projection_without_object_ids() -> None:
    """Equivalent artifacts serialize identically; object identity is internal."""
    artifact_a = _artifact([_capture(), _load(1, _ss_addr(0, 1))])
    artifact_b = _artifact([_capture(), _load(1, _ss_addr(0, 1))])
    left = prove_entry_stack_bytes_8616(artifact_a)
    right = prove_entry_stack_bytes_8616(artifact_b)
    assert left.artifact is artifact_a
    assert left.artifact is not artifact_b
    assert left.to_dict() == right.to_dict()


def test_classified_without_materialized_refuses() -> None:
    """classified>0 with materialized==0 can never silently succeed."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_load(1, _ss_addr(0, 1, base_tmp=999))])
    )
    assert proof.classified_fact_count > 0
    assert proof.materialized_count == 0
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
