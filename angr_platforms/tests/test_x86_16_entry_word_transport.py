"""Exact entry-word transport over a known acyclic target cone.

Layer: Widening regression tests.
Responsibility: retain canonical Alias/Word prerequisites, exact register
effects, CFG meets, selected-site geometry and typed refusals. A cone relation
never proves a full frontier, callee, frame, pointer or generated-C body.
"""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.alias.entry_stack_bytes import prove_entry_stack_bytes_8616
from angr_platforms.X86_16.ir import scalar_instruction_effects as _effects
from angr_platforms.X86_16.ir.core import (
    IRAddress,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.ir.scalar_instruction_effects import (
    ScalarInstructionEffectKind8616 as EffectKind,
)
from angr_platforms.X86_16.widening import entry_word_transport as _transport
from angr_platforms.X86_16.widening.entry_stack_word_values import prove_entry_stack_word_value_8616
from angr_platforms.X86_16.widening.entry_word_transport_contracts import EntryWordTransportProof8616
from angr_platforms.X86_16.widening.entry_word_transport_contracts import (
    EntryWordTransportRefusalKind8616 as Refusal,
)
from angr_platforms.X86_16.widening.entry_word_transport_contracts import (
    EntryWordTransportVerdict8616 as Verdict,
)
from entry_stack_byte_test_support import (
    ENTRY_8616,
    _capture,
    _const,
    _mov,
    _reg,
    _ss_addr,
    _tmp,
)

LEFT = 0x105C3
MID = 0x105C9
RIGHT = 0x105CD
TARGET = 0x105D1
DEAD = 0x105D9
EXTERNAL = 0x103D6
SEED_INDEX = 7


def _use(tmp_id: int, size: int = 2, expr: tuple[str, ...] | None = None) -> IRValue:
    return IRValue(MemSpace.TMP, name=f"t{tmp_id}", size=size,
                   source_tmp=tmp_id, expr=expr)


def _load(tmp_id: int, offset: int) -> IRInstr:
    return IRInstr(op="LOAD", dst=_tmp(tmp_id, 1), args=(_ss_addr(offset, 1),),
                   size=1, addr=ENTRY_8616)


def _binop(op: str, tmp_id: int, left: IRValue, right: IRValue, size: int = 2) -> IRInstr:
    return IRInstr(op=op, dst=_tmp(tmp_id), args=(left, right), size=size,
                   addr=ENTRY_8616)


def _seed_instrs(register: str = "cx") -> list[IRInstr]:
    """The canonical proven word shape: ordered SS:SP bytes into ``register``."""
    return [
        _capture(),
        _load(1, 0),
        _mov(_tmp(2), _use(1, expr=("Iop_8Uto16",))),
        _load(3, 1),
        _mov(_tmp(4), _use(3, expr=("Iop_8Uto16",))),
        _binop("Iop_Shl16", 5, _use(4, expr=("Iop_8Uto16",)), _const(8, 1)),
        _binop("Iop_Or16", 6, _use(2, expr=("Iop_8Uto16",)),
               _use(5, expr=("Iop_Shl16",))),
        _mov(_reg(register), _use(6, expr=("Iop_Or16",))),
    ]


def _cjmp(addr: int = TARGET) -> IRInstr:
    cond = IRCondition(op="eq", args=(_const(1, 1),))
    return IRInstr(op="CJMP", dst=None, args=(cond, _const(addr)), size=0,
                   addr=addr)


def _block(addr: int, instrs: list[IRInstr], succs: tuple[int, ...]) -> IRBlock:
    return IRBlock(addr=addr, instrs=tuple(instrs), successor_addrs=succs)


def _artifact(blocks: list[IRBlock], entry: int = ENTRY_8616) -> IRFunctionArtifact:
    return IRFunctionArtifact(function_addr=entry, blocks=tuple(blocks))


def _prove(
    artifact: IRFunctionArtifact, target: int = TARGET, index: int = 0,
) -> EntryWordTransportProof8616:
    """Use the exact canonical byte/word owners for a selected later site."""
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    word = prove_entry_stack_word_value_8616(artifact, byte_proof, SEED_INDEX)
    return _transport.prove_entry_word_transport_8616(
        artifact, word, target, index,
    )


def _kinds(proof: EntryWordTransportProof8616) -> list[Refusal]:
    """Read typed refusal identities without parsing diagnostic detail text."""
    return [refusal.kind for refusal in proof.refusals]


def _chain_artifact(mid_instrs: list[IRInstr] | None = None,
                    target_instrs: list[IRInstr] | None = None,
                    mid_succs: tuple[int, ...] = (TARGET,),
                    entry_succs: tuple[int, ...] = (LEFT,),
                    extra_blocks: list[IRBlock] | None = None) -> IRFunctionArtifact:
    """entry -> LEFT -> TARGET with one optional mid hop and extra blocks."""
    blocks = [
        _block(ENTRY_8616, _seed_instrs(), entry_succs),
        _block(LEFT, mid_instrs if mid_instrs is not None else [], mid_succs),
        _block(TARGET, target_instrs or [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ]
    return _artifact(blocks + list(extra_blocks or []))


def test_straight_chain_transport() -> None:
    """entry seeds cx; an untouched path copies it into dx at the target."""
    proof = _prove(_chain_artifact())
    assert proof.verdict is Verdict.PROVEN
    assert proof.materialized_count == 1 and proof.failure_count == 0
    fact = proof.fact
    assert fact is not None
    assert fact.source.block_addr == ENTRY_8616 and fact.source.instr_index == SEED_INDEX
    assert fact.target.block_addr == TARGET and fact.target_name == "dx"
    assert fact.seed_register == "cx"
    assert EXTERNAL in fact.retained_exits
    assert fact.traversed_blocks == (ENTRY_8616, LEFT, TARGET)


def test_mid_block_mov_copy_transport() -> None:
    """A mid-block identity copy cx -> si then si -> dx still transports."""
    artifact = _chain_artifact(
        mid_instrs=[_mov(_reg("si"), _reg("cx"))],
        target_instrs=[_mov(_reg("dx"), _reg("si"))],
    )
    proof = _prove(artifact)
    assert proof.verdict is Verdict.PROVEN


def test_tmp_identity_copy_in_target() -> None:
    """A tmp relay inside the target block keeps the word."""
    artifact = _chain_artifact(
        target_instrs=[
            _mov(_tmp(9), _reg("cx")),
            _mov(_reg("dx"), _use(9)),
        ],
    )
    proof = _prove(artifact, index=1)
    assert proof.verdict is Verdict.PROVEN


def test_agreeing_diamond() -> None:
    """Both branches preserve cx; the join target transport proves."""
    blocks = [
        _block(ENTRY_8616, _seed_instrs(), (LEFT, RIGHT)),
        _block(LEFT, [IRInstr(op="Iop_CmpEQ16", dst=_tmp(20, 1),
                              args=(_reg("bx"), _reg("ax")), size=1,
                              addr=LEFT),
                      _cjmp(TARGET)], (TARGET, EXTERNAL)),
        _block(RIGHT, [_mov(_reg("si"), _reg("bx"))], (TARGET,)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ]
    proof = _prove(_artifact(blocks))
    assert proof.verdict is Verdict.PROVEN


def test_clobbered_diamond_refuses() -> None:
    """One branch writes CL; CX cannot carry the word on all paths."""
    blocks = [
        _block(ENTRY_8616, _seed_instrs(), (LEFT, RIGHT)),
        _block(LEFT, [], (TARGET,)),
        _block(RIGHT, [_mov(_reg("cl", 1), _const(0, 1))], (TARGET,)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ]
    proof = _prove(_artifact(blocks))
    assert proof.verdict is Verdict.REFUSED
    assert Refusal.DIVERGENT_INCOMING_WORD in _kinds(proof)


def test_call_kills_register_evidence() -> None:
    """A CALL on the path clears tracked register evidence."""
    artifact = _chain_artifact(
        mid_instrs=[IRInstr(op="CALL", dst=_const(0x2000), args=(), size=0)],
    )
    proof = _prove(artifact)
    assert proof.verdict is Verdict.REFUSED
    assert Refusal.UNKNOWN_EFFECT in _kinds(proof)
    assert Refusal.DIVERGENT_INCOMING_WORD in _kinds(proof)


def test_seed_bypass_pred_refuses() -> None:
    """An unreachable predecessor edge into the target is unseeded."""
    artifact = _chain_artifact(
        extra_blocks=[_block(DEAD, [_mov(_reg("ax"), _const(1))], (TARGET,))],
    )
    proof = _prove(artifact)
    assert proof.verdict is Verdict.REFUSED
    assert Refusal.UNSEEDED_PREDECESSOR in _kinds(proof)


def test_cfg_cycle_refuses() -> None:
    """A cycle inside the target cone refuses."""
    blocks = [
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(LEFT, [], (MID,)),
        _block(MID, [], (TARGET, LEFT)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ]
    proof = _prove(_artifact(blocks))
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.CFG_CYCLE]


def test_same_tmp_id_across_blocks_not_carried() -> None:
    """TMP ids are block-local: t9 in LEFT never proves t9 in TARGET."""
    artifact = _artifact([
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(LEFT, [_mov(_tmp(9), _reg("cx"))], (TARGET,)),
        _block(TARGET, [_mov(_tmp(9), _const(7)), _mov(_reg("dx"), _use(9))],
               (EXTERNAL,)),
    ])
    proof = _prove(artifact, index=1)
    assert proof.verdict is Verdict.REFUSED


def test_byte_width_mov_not_transportable() -> None:
    """An 8-bit destination cannot carry the proven 16-bit word."""
    artifact = _chain_artifact(
        mid_instrs=[_mov(_reg("cl", 1), _reg("cx", 1))],
        target_instrs=[_mov(_reg("dx"), _reg("cx"))],
    )
    proof = _prove(artifact)
    assert proof.verdict is Verdict.REFUSED


def test_unknown_op_kills() -> None:
    """An unrecognized op is an unknown effect and kills tracking."""
    artifact = _chain_artifact(
        mid_instrs=[IRInstr(op="Iop_Sar16", dst=_tmp(8),
                            args=(_reg("ax"), _const(1)), size=2)],
    )
    proof = _prove(artifact)
    assert proof.verdict is Verdict.REFUSED
    assert Refusal.UNKNOWN_EFFECT in _kinds(proof)


def test_cross_artifact_proof_refused() -> None:
    """A word proof bound to another raw artifact is rejected."""
    artifact = _chain_artifact()
    other = _chain_artifact()
    byte_proof = prove_entry_stack_bytes_8616(other)
    word = prove_entry_stack_word_value_8616(other, byte_proof, SEED_INDEX)
    proof = _transport.prove_entry_word_transport_8616(
        artifact, word, TARGET, 0,
    )
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.CROSS_ARTIFACT_PROOF]


def test_forged_word_proof_refused() -> None:
    """A mutated word proof fails canonical replay."""
    from dataclasses import replace

    artifact = _chain_artifact()
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    word = prove_entry_stack_word_value_8616(artifact, byte_proof, SEED_INDEX)
    forged = replace(word, materialized_count=99)
    proof = _transport.prove_entry_word_transport_8616(
        artifact, forged, TARGET, 0,
    )
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.STALE_WORD_PROOF]


def test_missing_entry_and_duplicate_blocks() -> None:
    """Missing entry block and duplicated block addresses refuse."""
    blocks = [_block(LEFT, [], (TARGET,)),
              _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,))]
    artifact = _artifact(blocks)
    byte_proof = prove_entry_stack_bytes_8616(artifact)
    word = prove_entry_stack_word_value_8616(artifact, byte_proof, 0)
    proof = _transport.prove_entry_word_transport_8616(artifact, word, TARGET, 0)
    assert proof.verdict is Verdict.REFUSED

    dup = _artifact([
        _block(ENTRY_8616, _seed_instrs(), (LEFT,)),
        _block(ENTRY_8616, [], (LEFT,)),
        _block(LEFT, [], (TARGET,)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ])
    byte_proof = prove_entry_stack_bytes_8616(dup)
    word = prove_entry_stack_word_value_8616(dup, byte_proof, SEED_INDEX)
    proof = _transport.prove_entry_word_transport_8616(dup, word, TARGET, 0)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) in ([Refusal.AMBIGUOUS_BLOCK_ADDR],
                            [Refusal.SEED_NOT_PROVEN])


def test_unreachable_target_refuses() -> None:
    """A target block with no entry path refuses."""
    artifact = _artifact([
        _block(ENTRY_8616, _seed_instrs(), (EXTERNAL,)),
        _block(TARGET, [_mov(_reg("dx"), _reg("cx"))], (EXTERNAL,)),
    ])
    proof = _prove(artifact)
    assert proof.verdict is Verdict.REFUSED
    assert _kinds(proof) == [Refusal.UNREACHABLE_TARGET]


def test_non_scalar_and_bad_index_targets() -> None:
    """Non-MOV or out-of-range target sites refuse."""
    artifact = _chain_artifact(
        target_instrs=[_binop("Iop_Add16", 9, _reg("cx"), _const(1))],
    )
    proof = _prove(artifact)
    assert proof.verdict is Verdict.REFUSED
    assert Refusal.NON_SCALAR_TARGET in _kinds(proof)
    bad = _prove(_chain_artifact(), index=99)
    assert _kinds(bad) == [Refusal.BAD_TARGET_INDEX]


def test_determinism() -> None:
    """The same inputs produce identical serialized results."""
    artifact = _chain_artifact()
    first = _prove(artifact).to_dict()
    second = _prove(artifact).to_dict()
    assert first == second


@pytest.mark.parametrize("instr,expected", [
    (_mov(_reg("dx"), _reg("cx")), EffectKind.CLOSED_DESTINATION),
    (IRInstr(op="STORE", dst=None,
             args=(IRAddress(space=MemSpace.DS, offset=4, size=2), _reg("ax")),
             size=2), EffectKind.NO_REGISTER_WRITE),
    (_cjmp(), EffectKind.INSTRUCTION_POINTER_WRITE),
    (IRInstr(op="Iop_CmpEQ16", dst=_tmp(1, 1),
             args=(_reg("ax"), _const(3)), size=1), EffectKind.CLOSED_DESTINATION),
    (IRInstr(op="Iop_CmpLTU8", dst=_tmp(1, 1),
             args=(_reg("al", 1), _reg("bl", 1)), size=1), EffectKind.UNKNOWN),
    (IRInstr(op="Iop_CmpLES32", dst=_tmp(1, 1),
             args=(_reg("eax", 4), _reg("ebx", 4)), size=1), EffectKind.UNKNOWN),
    (IRInstr(op="Iop_CmpLT32U", dst=_tmp(1, 1),
             args=(_reg("eax", 4), _reg("ebx", 4)), size=1), EffectKind.CLOSED_DESTINATION),
    (IRInstr(op="Iop_CmpEQ16", dst=_tmp(1, 2),
             args=(_reg("ax"), _const(3)), size=2), EffectKind.UNKNOWN),
    (IRInstr(op="CJMP", dst=_reg("ax"),
             args=(IRCondition(op="eq", args=(_const(1, 1),)), _const(4)),
             size=0), EffectKind.UNKNOWN),
    (IRInstr(op="STORE", dst=_reg("ax"),
             args=(IRAddress(space=MemSpace.DS, offset=4, size=2), _reg("ax")),
             size=2), EffectKind.UNKNOWN),
    (IRInstr(op="CALL", dst=_const(0x2000), args=(), size=0), EffectKind.UNKNOWN),
    (IRInstr(op="Iop_Sar16", dst=_tmp(1), args=(_reg("ax"), _const(1)),
             size=2), EffectKind.UNKNOWN),
    (IRInstr(op="MOV", dst=_tmp(1), args=(_reg("ax"), _reg("bx")),
             size=2), EffectKind.UNKNOWN),
])
def test_scalar_instruction_effect_classifier(instr: IRInstr, expected: EffectKind) -> None:
    """The staged IR effect owner classifies validated shapes only."""
    assert _effects.scalar_instruction_effect_8616(instr).kind is expected


def test_retained_off_target_exit_not_closure() -> None:
    """A mid-cone external exit is retained, never mistaken for closure."""
    artifact = _chain_artifact(mid_succs=(TARGET, 0x10777))
    proof = _prove(artifact)
    assert proof.verdict is Verdict.PROVEN
    assert proof.fact is not None
    assert 0x10777 in proof.fact.retained_exits
