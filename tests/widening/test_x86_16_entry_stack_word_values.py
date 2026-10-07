"""Typed controls for the single-entry-word value proof.

Layer: Widening regression tests.
Responsibility: exercise ``prove_entry_stack_word_value_8616`` over typed IR
fixtures only — the canonical Alias byte proof is computed per artifact, the
engine builds its own block SSA, and assertions read typed verdict/refusal
fields, never rendered text or detail substrings. Negative controls may
surface honest engine defects; assertions are not weakened to fit them.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from inertia.ir.core import IRFunctionArtifact, IRInstr, IRValue, MemSpace
from tests.fixtures.entry_stack_byte_test_support import (
    _artifact,
    _binop,
    _capture,
    _const,
    _load,
    _mov,
    _reg,
    _ss_addr,
    _tmp,
)

from inertia.alias.entry_stack_byte_contracts import (
    EntryStackByteProof8616,
    EntryStackByteVerdict8616,
)
from inertia.alias.entry_stack_bytes import (
    prove_entry_stack_bytes_8616,
)
from inertia.widening.entry_stack_word_value_contracts import (
    EntryStackWordProof8616,
)
from inertia.widening.entry_stack_word_value_contracts import (
    EntryStackWordRefusalKind8616 as Refusal,
)
from inertia.widening.entry_stack_word_value_contracts import (
    EntryStackWordVerdict8616 as Verdict,
)
from inertia.widening.entry_stack_word_values import prove_entry_stack_word_value_8616

_TARGET = 7


def _use(tmp_id: int, size: int = 2, expr: tuple[str, ...] | None = None) -> IRValue:
    """A TMP read of producer ``tmp_id`` with an optional view decoration."""
    return replace(_tmp(tmp_id, size), expr=expr)


def _word_instrs(register: str = "cx") -> list[IRInstr]:
    """The proven shape: two bytes, unsigned lanes, shl-8, or, word def."""
    return [
        _capture(),
        _load(1, _ss_addr(0, 1)),
        _mov(_tmp(2), _use(1, expr=("Iop_8Uto16",))),
        _load(3, _ss_addr(1, 1)),
        _mov(_tmp(4), _use(3, expr=("Iop_8Uto16",))),
        _binop("Iop_Shl16", 5, _use(4, expr=("Iop_8Uto16",)), _const(8, 1)),
        _binop("Iop_Or16", 6, _use(2, expr=("Iop_8Uto16",)),
               _use(5, expr=("Iop_Shl16",))),
        _mov(_reg(register), _use(6, expr=("Iop_Or16",))),
    ]


def _prove(
    instrs: list[IRInstr],
    target_index: int = _TARGET,
    *,
    artifact: IRFunctionArtifact | None = None,
    byte_proof: EntryStackByteProof8616 | None = None,
) -> EntryStackWordProof8616:
    """Build the artifact, canonical byte proof, then the word proof."""
    artifact = _artifact(instrs) if artifact is None else artifact
    byte_proof = (
        prove_entry_stack_bytes_8616(artifact) if byte_proof is None else byte_proof
    )
    return prove_entry_stack_word_value_8616(artifact, byte_proof, target_index)


def _kinds(proof: EntryStackWordProof8616) -> list[Refusal]:
    """Ordered typed refusal kinds of one word proof."""
    return [refusal.kind for refusal in proof.refusals]


@pytest.mark.parametrize("register", ["cx", "dx", "si"])
def test_positive_ordered_byte_word(register: str) -> None:
    """A recomposed little-endian word on three independent registers proves."""
    artifact = _artifact(_word_instrs(register))
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    proof = prove_entry_stack_word_value_8616(artifact, byte_proof, _TARGET)
    assert proof.verdict is Verdict.PROVEN
    assert proof.artifact is artifact and proof.byte_proof is byte_proof
    assert (proof.raw_fact_count, proof.normalized_fact_count,
            proof.classified_fact_count, proof.materialized_count,
            proof.failure_count) == (1, 1, 1, 1, 0)
    fact = proof.fact
    assert fact is not None
    assert fact.instr_index == _TARGET and fact.target_name == register
    assert fact.low_byte.byte_offsets == (0,)
    assert fact.high_byte.byte_offsets == (1,)
    assert fact.low_byte.producer_tmp == 1 and fact.high_byte.producer_tmp == 3
    lanes = fact.to_dict()["lane_provenance"]
    assert lanes == (
        [{"producer_index": 1, "bit_index": i} for i in range(8)]
        + [{"producer_index": 3, "bit_index": i} for i in range(8)]
    )


def test_signed_low_extension_refused() -> None:
    """A signed low-byte extension cannot produce the proven zero lanes."""
    instrs = _word_instrs()
    instrs[2] = _mov(_tmp(2), _use(1, expr=("Iop_8Sto16",)))
    instrs[6] = _binop("Iop_Or16", 6, _use(2, expr=("Iop_8Sto16",)),
                       _use(5, expr=("Iop_Shl16",)))
    proof = _prove(instrs)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.MISSING_BYTE_LANES]


def test_shift_by_seven_refused() -> None:
    """An in-range but wrong shift count misaligns the high byte lanes."""
    instrs = _word_instrs()
    instrs[5] = _binop("Iop_Shl16", 5, _use(4, expr=("Iop_8Uto16",)), _const(7, 1))
    proof = _prove(instrs)
    assert proof.verdict is Verdict.REFUSED


def test_unknown_shift_count_refused() -> None:
    """A non-constant shift count is not composition evidence."""
    instrs = _word_instrs()
    instrs.insert(5, _binop("Iop_Mul16", 9, _reg("ax"), _reg("bx")))
    instrs[6] = _binop("Iop_Shl16", 5, _use(4, expr=("Iop_8Uto16",)), _use(9))
    proof = _prove(instrs, 8)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.UNSUPPORTED_PRODUCER_OP]


def test_reversed_byte_order_refused() -> None:
    """Swapped byte offsets place the origins in the wrong order."""
    instrs = _word_instrs()
    instrs[1] = _load(1, _ss_addr(1, 1))
    instrs[3] = _load(3, _ss_addr(0, 1))
    proof = _prove(instrs)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.NON_ADJACENT_BYTES]


def test_nonadjacent_byte_offsets_refused() -> None:
    """Origins two bytes apart are not one adjacent word."""
    instrs = _word_instrs()
    instrs[3] = _load(3, _ss_addr(2, 1))
    proof = _prove(instrs)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.NON_ADJACENT_BYTES]


def test_unearned_operator_read_expr_refused() -> None:
    """A decoration the producer never earned is refused, not projected."""
    instrs = _word_instrs()
    instrs[7] = _mov(_reg("cx"), _use(6, expr=("Iop_Xor16",)))
    proof = _prove(instrs)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.BAD_PROJECTION]


def test_forward_tmp_reference_refused() -> None:
    """A read whose producer does not exist at the use site refuses."""
    instrs = _word_instrs()
    instrs[7] = _mov(_reg("cx"), _use(42))
    proof = _prove(instrs)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.NO_PRODUCER_SITE]


def test_missing_byte_proof_refused() -> None:
    """An honestly refused byte proof with zero facts cannot seed a word."""
    instrs = [_capture(), _mov(_reg("cx"), _const(0))]
    proof = _prove(instrs, 1)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.BYTE_PREFIX_NOT_PROVEN]


def test_cloned_artifact_cross_proof_refused() -> None:
    """A byte proof bound to one artifact object rejects an equal clone."""
    artifact = _artifact(_word_instrs())
    clone = _artifact(_word_instrs())
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    proof = prove_entry_stack_word_value_8616(clone, byte_proof, _TARGET)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.CROSS_ARTIFACT_PROOF]


def test_forged_alias_fact_rejected_by_replay() -> None:
    """A mutated byte fact fails the replay equality against the raw artifact."""
    artifact = _artifact(_word_instrs())
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    forged = replace(
        byte_proof,
        facts=(replace(byte_proof.facts[0], byte_offsets=(9,)), *byte_proof.facts[1:]),
    )
    proof = prove_entry_stack_word_value_8616(artifact, forged, _TARGET)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.STALE_BYTE_PROOF]


def test_later_unrelated_load_refusal_does_not_poison() -> None:
    """A refused LOAD after the target leaves earlier proven bytes usable."""
    instrs = _word_instrs()
    instrs.append(_load(8, _ss_addr(0, 1, space=MemSpace.DS)))
    artifact = _artifact(instrs)
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    assert byte_proof.verdict is EntryStackByteVerdict8616.PARTIAL
    proof = prove_entry_stack_word_value_8616(artifact, byte_proof, _TARGET)
    assert proof.verdict is Verdict.PROVEN
    assert proof.fact is not None


def test_partial_register_clobber_refuses_downstream_read() -> None:
    """A narrow sibling write destroys the wider register value proof."""
    instrs = [*_word_instrs("dx"),
        _mov(_reg("dl", 1), _const(0, 1)),
        _mov(_reg("cx"), _reg("dx")),
    ]
    proof = _prove(instrs, 9)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.NO_PRODUCER_SITE]


def test_byte_width_target_refused() -> None:
    """A non-16-bit target definition is not a word proof."""
    instrs = [*_word_instrs(), _mov(_reg("cl", 1), _const(0, 1))]
    proof = _prove(instrs, 8)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.UNSUPPORTED_TARGET_WIDTH]


def test_determinism_and_same_artifact_ownership() -> None:
    """Two in-process proofs agree; identity fields stay object-bound."""
    artifact = _artifact(_word_instrs())
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    first = prove_entry_stack_word_value_8616(artifact, byte_proof, _TARGET)
    second = prove_entry_stack_word_value_8616(artifact, byte_proof, _TARGET)
    assert first.to_dict() == second.to_dict()
    assert first.artifact is artifact and first.byte_proof is byte_proof
