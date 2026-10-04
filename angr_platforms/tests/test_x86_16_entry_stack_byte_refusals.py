"""Entry-block-prefix SS byte-read proof: typed refusal obligations.

Every malformed, forged, contradictory, or unsupported shape must refuse
explicitly with a typed refusal kind — never silently materialize. Positive
materialization obligations live in ``test_x86_16_entry_stack_bytes.py``.
"""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.alias.entry_stack_byte_contracts import (
    EntryStackByteRefusalKind8616,
    EntryStackByteVerdict8616,
)
from angr_platforms.X86_16.alias.entry_stack_bytes import prove_entry_stack_bytes_8616
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from entry_stack_byte_test_support import (
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
    _tmp,
)


@pytest.mark.parametrize(
    ("dst", "size"),
    [
        (IRValue(MemSpace.TMP, name="t9", size=1), 1),
        (_reg("cx", 1), 1),
    ],
    ids=["missing_source_tmp", "register_destination"],
)
def test_bad_destination_refused(dst: IRValue, size: int) -> None:
    """A non-temporary or producer-less LOAD dst refuses."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), IRInstr(op="LOAD", dst=dst, args=(_ss_addr(0, 1),), size=size)])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.BAD_DESTINATION]


@pytest.mark.parametrize("size", [0, 4])
def test_unsupported_width_refused(size: int) -> None:
    """Only 1- or 2-byte loads are supported."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), _load(1, _ss_addr(0, size), size=size)])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.UNSUPPORTED_WIDTH]


def test_width_disagreement_refused() -> None:
    """Address, instruction, and dst widths must agree."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), IRInstr(
            op="LOAD", dst=_tmp(1, 1), args=(_ss_addr(0, 2),), size=1, addr=ENTRY_8616,
        )])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.WIDTH_DISAGREEMENT]


@pytest.mark.parametrize(
    "base_values",
    [
        (_reg("sp", source_tmp=999),),
        (_reg("sp", expr=("forged",)),),
        (_reg("bx", source_tmp=0),),
    ],
    ids=["unobserved_tmp", "expr_decoration", "wrong_register_name"],
)
def test_forged_base_refused(base_values: tuple[IRValue, ...]) -> None:
    """Unobserved, decorated, or misnamed bases refuse."""
    address = IRAddress(
        space=MemSpace.SS, base=("sp",), offset=0, size=1,
        status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN,
        base_values=base_values,
    )
    proof = prove_entry_stack_bytes_8616(_artifact([_capture(), _load(1, address)]))
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_wide_capture_refused() -> None:
    """A 32-bit decorated capture is not word-exact frame provenance."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _mov(_tmp(3, 4), _reg("sp", size=4, expr=("Iop_16Uto32",), source_tmp=0)),
            _load(4, _ss_addr(0, 1, base_tmp=3)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_wrong_source_lineage_refused() -> None:
    """A tmp produced from a non-frame source refuses."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_mov(_tmp(5), _reg("ax")), _load(6, _ss_addr(0, 1, base_tmp=5))])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_prior_call_refuses() -> None:
    """A CALL closes the prefix for later loads."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            IRInstr(op="CALL", dst=None, args=(_const(0x1234, 4),), size=0, addr=ENTRY_8616),
            _load(1, _ss_addr(0, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.PRIOR_CALL]


def test_prior_ss_write_loses_identity() -> None:
    """An ss write forfeits entry-SS identity."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), _mov(_reg("ss"), _reg("ds")), _load(1, _ss_addr(0, 1))])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.SS_IDENTITY_LOST]


def test_unknown_op_closes_prefix() -> None:
    """Unrecognized ops conservatively close the prefix."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            IRInstr(op="UNKNOWN_OP", dst=None, args=(), size=0, addr=ENTRY_8616),
            _load(1, _ss_addr(0, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION]


def test_raw_ir_refusal_fails_closed() -> None:
    """Raw IR refusals refuse every candidate."""
    proof = prove_entry_stack_bytes_8616(
        _artifact(
            [_capture(), _load(1, _ss_addr(0, 1))],
            refusals=(IRRefusal("unsupported_stmt", "Ist_MBE unsupported", ENTRY_8616),),
        )
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert proof.materialized_count == 0
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.RAW_IR_REFUSAL, EntryStackByteRefusalKind8616.RAW_IR_REFUSAL]


def test_raw_ir_refusal_with_zero_loads() -> None:
    """A structural raw-IR refusal is retained even without candidates."""
    proof = prove_entry_stack_bytes_8616(
        _artifact(
            [_capture()],
            refusals=(IRRefusal("unsupported_stmt", "Ist_MBE unsupported", ENTRY_8616),),
        )
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert proof.raw_fact_count == 0
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.RAW_IR_REFUSAL]
    assert proof.failure_count == 1


def test_missing_entry_block_refused() -> None:
    """No block at function_addr refuses structurally."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture()], function_addr=ENTRY_8616, block_addr=0x20000)
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_ENTRY_BLOCK]


def test_duplicate_entry_block_refused() -> None:
    """Duplicate entry blocks refuse structurally."""
    artifact = IRFunctionArtifact(
        function_addr=ENTRY_8616,
        blocks=(
            IRBlock(addr=ENTRY_8616, instrs=(_capture(), _load(1, _ss_addr(0, 1)))),
            IRBlock(addr=ENTRY_8616, instrs=(_capture(), _load(2, _ss_addr(1, 1)))),
        ),
    )
    proof = prove_entry_stack_bytes_8616(artifact)
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.DUPLICATE_ENTRY_BLOCK]


def test_entry_reentry_refused() -> None:
    """An incoming edge to the entry block refuses initial-entry coordinates."""
    artifact = IRFunctionArtifact(
        function_addr=ENTRY_8616,
        blocks=(
            IRBlock(addr=ENTRY_8616, instrs=(_capture(), _load(1, _ss_addr(0, 1)))),
            IRBlock(addr=0x20000, instrs=(), successor_addrs=(ENTRY_8616,)),
        ),
    )
    proof = prove_entry_stack_bytes_8616(artifact)
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.ENTRY_REENTRY]


def test_ds_address_refused() -> None:
    """A DS-space load refuses as non-SS."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), _load(1, _ss_addr(0, 1, space=MemSpace.DS))])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.NON_SS_ADDRESS]


def test_unstable_address_refused() -> None:
    """A non-STABLE address status refuses."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), _load(1, _ss_addr(0, 1, status=AddressStatus.UNKNOWN))])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.UNSTABLE_ADDRESS]


def test_defaulted_segment_refused() -> None:
    """A non-PROVEN segment origin refuses."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([_capture(), _load(1, _ss_addr(0, 1, origin=SegmentOrigin.DEFAULTED))])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.UNPROVEN_SEGMENT]


def test_dropped_affine_decoration_refused() -> None:
    """A matching source_tmp without the earned decoration is inconsistent."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _binop("Iop_Sub16", 4, _reg("sp", source_tmp=0), _const(4)),
            _load(5, _ss_addr(0, 2, base_tmp=4), size=2),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_unearned_not16_decoration_refused() -> None:
    """An Iop_Not16 label a plain capture never earned refuses."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _load(1, _ss_addr(0, 1, base_tmp=0, base_expr=("Iop_Not16",))),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_wide_destination_borrows_no_word_origin() -> None:
    """A 4-byte MOV from a 2-byte source is width-incoherent and closes the
    prefix; a wide destination is never borrowed as a word frame capture."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            IRInstr(op="MOV", dst=_tmp(0, 4), args=(_reg("sp"),), size=4, addr=ENTRY_8616),
            _load(1, _ss_addr(0, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION]


def test_redefined_frame_temp_refused() -> None:
    """Redefining the captured tmp invalidates its earlier coordinate."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            _mov(_tmp(0), _const(0x9000)),
            _load(1, _ss_addr(0, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_unregistered_iop_closes_prefix() -> None:
    """An unregistered Iop_* name is unknown classification, not pure evidence."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            IRInstr(
                op="Iop_NotARegisteredVexOperation", dst=_tmp(3),
                args=(_const(0),), size=2, addr=ENTRY_8616,
            ),
            _capture(),
            _load(1, _ss_addr(0, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION]
    assert proof.prefix_closed_by is not None
    assert proof.prefix_closed_by is EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION


def test_registered_iop_memory_destination_closes_prefix() -> None:
    """Registered op membership is not destination-shape evidence: a
    memory-space destination is a write that closes the prefix."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            IRInstr(
                op="Iop_Add16", dst=IRValue(MemSpace.DS, size=2),
                args=(_const(1), _const(2)), size=2, addr=ENTRY_8616,
            ),
            _capture(),
            _load(1, _ss_addr(0, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.PRIOR_MEMORY_WRITE]
    assert proof.prefix_closed_by is not None
    assert proof.prefix_closed_by is EntryStackByteRefusalKind8616.PRIOR_MEMORY_WRITE


def test_mov_instruction_width_disagreement_closes_prefix() -> None:
    """A word instruction writing a byte destination is unrecognized shape."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            IRInstr(
                op="MOV", dst=_tmp(3, 1), args=(_reg("ax", 1),), size=2,
                addr=ENTRY_8616,
            ),
            _capture(),
            _load(1, _ss_addr(0, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION]
    assert proof.prefix_closed_by is not None
    assert proof.prefix_closed_by is EntryStackByteRefusalKind8616.PRIOR_UNKNOWN_OPERATION


def test_non_scalar_mov_destination_closes_prefix() -> None:
    """MOV to a memory-space destination is a write, not a pure transfer."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            IRInstr(
                op="MOV", dst=IRValue(MemSpace.SS, name="entry_byte", size=1),
                args=(_const(0xAB, 1),), size=1, addr=ENTRY_8616,
            ),
            _capture(),
            _load(1, _ss_addr(0, 1)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.PRIOR_MEMORY_WRITE]


def test_decorated_affine_constant_earns_no_coordinate() -> None:
    """A decorated CONST operand makes the affine production opaque."""
    decorated_const = IRValue(
        MemSpace.CONST, const=2, size=2, expr=("Iop_Add16",)
    )
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            IRInstr(
                op="Iop_Add16", dst=_tmp(8),
                args=(_reg("sp", source_tmp=0), decorated_const), size=2,
                addr=ENTRY_8616,
            ),
            _load(1, _ss_addr(0, 1, base_tmp=8, base_offset=2,
                              base_expr=("Iop_Add16",))),
            _load(2, _ss_addr(1, 1, base_tmp=0)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.PARTIAL
    assert [fact.byte_offsets for fact in proof.facts] == [(1,)]
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]


def test_shifted_frame_mov_destination_poisons_coordinate() -> None:
    """A shifted/decorated frame-register MOV poisons the live SP coordinate."""
    proof = prove_entry_stack_bytes_8616(
        _artifact([
            _capture(),
            IRInstr(
                op="MOV",
                dst=IRValue(MemSpace.REG, name="sp", size=2, index_shift=1),
                args=(_reg("sp", source_tmp=0),), size=2, addr=ENTRY_8616,
            ),
            _load(1, _ss_addr(0, 1, base_tmp=None)),
        ])
    )
    assert proof.verdict is EntryStackByteVerdict8616.REFUSED
    assert _refusal_kinds(proof) == [EntryStackByteRefusalKind8616.MISSING_FRAME_BASE]
