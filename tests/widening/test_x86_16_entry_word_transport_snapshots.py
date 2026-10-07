"""Definition-preserving block-local register-snapshot transport controls.

Layer: Widening regression tests.
Responsibility: retain register view/version coherence, producer identity,
capture-time word state and refusal of unsupported or out-of-block views.
"""

from __future__ import annotations

import pytest
from inertia.ir.core import IRValue, MemSpace
import inertia.widening.entry_word_transport as _transport
import inertia.widening.entry_word_transport_state as _state
from tests.widening.test_x86_16_entry_word_transport import (
    ENTRY_8616,
    EXTERNAL,
    LEFT,
    SEED_INDEX,
    TARGET,
    _artifact,
    _binop,
    _block,
    _const,
    _mov,
    _reg,
    _seed_instrs,
    _tmp,
)

from inertia.alias.entry_stack_bytes import prove_entry_stack_bytes_8616
from inertia.widening.entry_stack_word_values import prove_entry_stack_word_value_8616
from inertia.widening.entry_word_transport_contracts import (
    EntryWordTransportRefusalKind8616 as _Refusal,
)
from inertia.widening.entry_word_transport_contracts import (
    EntryWordTransportVerdict8616 as _Verdict,
)


def _snap(register: str, tmp_id: int, **fields: object) -> IRValue:
    """One captured-register view of a word register via a TMP producer."""
    return IRValue(MemSpace.REG, name=register, size=2, source_tmp=tmp_id, **fields)


def _prove(instrs: list, index: int = 0) -> object:
    """entry seeds cx; TARGET block carries the supplied instruction list."""
    artifact = _artifact([
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(LEFT, [], (TARGET,)),
        _block(TARGET, instrs, (EXTERNAL,)),
    ])
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    word = prove_entry_stack_word_value_8616(artifact, byte_proof, SEED_INDEX)
    return _transport.prove_entry_word_transport_8616(
        artifact, word, TARGET, index,
    )


def _captured_run() -> object:
    """One transfer run whose block defines ``t9 = MOV cx`` with cx proven."""
    producer = IRValue(MemSpace.REG, name="cx", size=2, version=0)
    run, _exit = _state.transfer_block_8616(
        block_addr=TARGET,
        ssa_instrs=(_mov(_tmp(9), producer),),
        entry_regs={"cx": True},
        stop_index=1,
        seed_index=None,
        seed_name="",
        seed_version=None,
        successor_addrs=(EXTERNAL,),
    )
    return run


def test_same_block_register_snapshot_proves() -> None:
    """``t9 = MOV cx`` captures cx; a later snapshot read transports the word."""
    proof = _prove(
        [_mov(_tmp(9), _reg("cx")), _mov(_reg("dx"), _snap("cx", 9))],
        index=1,
    )
    assert proof.verdict is _Verdict.PROVEN
    assert proof.fact is not None and proof.fact.target_name == "dx"


def test_snapshot_survives_later_register_clobber() -> None:
    """The capture freezes cx at production; rewriting cx does not erase it."""
    proof = _prove(
        [
            _mov(_tmp(9), _reg("cx")),
            _mov(_reg("cx"), _const(0)),
            _mov(_reg("dx"), _snap("cx", 9)),
        ],
        index=2,
    )
    assert proof.verdict is _Verdict.PROVEN


def test_out_of_block_capture_refuses() -> None:
    """TMP producers are block-local; LEFT's t9 cannot prove TARGET's view."""
    artifact = _artifact([
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(LEFT, [_mov(_tmp(9), _reg("cx"))], (TARGET,)),
        _block(TARGET, [_mov(_reg("dx"), _snap("cx", 9))], (EXTERNAL,)),
    ])
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    word = prove_entry_stack_word_value_8616(artifact, byte_proof, SEED_INDEX)
    proof = _transport.prove_entry_word_transport_8616(artifact, word, TARGET, 0)
    assert proof.verdict is _Verdict.REFUSED


@pytest.mark.parametrize("producer", [
    pytest.param([], id="missing_producer"),
    pytest.param(
        [_binop("Iop_Add16", 9, _reg("cx"), _const(1))], id="non_mov_origin",
    ),
    pytest.param([_mov(_tmp(9), _reg("si"))], id="wrong_register"),
])
def test_incoherent_snapshot_producer_refuses(producer: list) -> None:
    """Absent, non-MOV, or wrong-register producers cannot carry the word."""
    proof = _prove(
        [*producer, _mov(_reg("dx"), _snap("cx", 9))], index=len(producer),
    )
    assert proof.verdict is _Verdict.REFUSED


def test_decorated_snapshot_view_refuses() -> None:
    """A displaced captured view is not an exact read of the producer."""
    proof = _prove(
        [
            _mov(_tmp(9), _reg("cx")),
            _mov(_reg("dx"), _snap("cx", 9, offset=1)),
        ],
        index=1,
    )
    assert proof.verdict is _Verdict.REFUSED


def test_snapshot_view_version_mismatch_refuses() -> None:
    """The snapshot version is the captured register's version, not TMP's."""
    run = _captured_run()
    assert run.read_word(_snap("cx", 9, version=0)) is True
    run = _captured_run()
    assert run.read_word(_snap("cx", 9, version=7)) is False
    assert _Refusal.STALE_TMP_VERSION in {
        refusal.kind for refusal in run.refusals
    }


def test_snapshot_missing_producer_in_state_refuses() -> None:
    """No retained producer means no evidence — refuse, never guess."""
    run = _captured_run()
    assert run.read_word(_snap("cx", 99, version=0)) is False
    assert _Refusal.UNSUPPORTED_OPERAND in {
        refusal.kind for refusal in run.refusals
    }
