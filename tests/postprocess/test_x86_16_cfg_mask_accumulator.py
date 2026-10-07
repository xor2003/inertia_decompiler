from __future__ import annotations

from types import SimpleNamespace

import inertia.postprocess.decompiler_postprocess_stage as stage
from inertia.postprocess.decompiler_postprocess_jcc import _DecodedCmpGuard8616


def _jcc_insn(address: int, mnemonic: str, target: int):
    return SimpleNamespace(
        address=address,
        mnemonic=mnemonic,
        operands=(SimpleNamespace(type=2, imm=target),),
    )


def test_cfg_mask_accumulator_uses_linear_jcc_evidence_not_incomplete_block_set(monkeypatch):
    jccs = (
        (0x1010, _jcc_insn(0x1016, "jg", 0x101B)),
        (0x101F, _jcc_insn(0x1025, "jge", 0x102A)),
        (0x102E, _jcc_insn(0x1034, "jl", 0x1039)),
        (0x103D, _jcc_insn(0x1043, "jle", 0x1048)),
        (0x104C, _jcc_insn(0x1052, "je", 0x1057)),
        (0x105B, _jcc_insn(0x1061, "jne", 0x1066)),
    )
    target_imms = {
        0x101B: 1,
        0x102A: 2,
        0x1039: 4,
        0x1048: 8,
        0x1057: 16,
        0x1066: 32,
    }

    def fail_block_graph_lookup(*_args, **_kwargs):
        raise AssertionError("mask accumulator must use linear JCC evidence")

    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=fail_block_graph_lookup)),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    monkeypatch.setattr(stage, "_linear_jcc_block_starts_8616", lambda _project, _codegen: jccs)
    monkeypatch.setattr(stage, "_selector_targets_from_32bit_jcc_chain_8616", lambda *_args: None)
    monkeypatch.setattr(stage, "_equality_return_target_from_32bit_jcc_chain_8616", lambda *_args: None)
    monkeypatch.setattr(stage, "_inequality_target_from_32bit_jcc_chain_8616", lambda *_args: None)
    monkeypatch.setattr(stage, "_or_stack_update_imm_8616", lambda _project, target, _slot: target_imms.get(target))
    monkeypatch.setattr(stage, "_expr_fingerprint", lambda expr, _project: expr)

    def decode(_project, _codegen, _block_addr, jcc_addr):
        return _DecodedCmpGuard8616(None, None, "", expr=f"cond_{jcc_addr:x}")

    monkeypatch.setattr(stage._jcc, "_translate_cmp_jcc_guard_8616", decode)

    pairs = stage._ordered_32bit_mask_update_pairs_from_cfg_8616(project, codegen, -2)

    assert [condition for condition, _imm in pairs] == [
        "cond_1016",
        "cond_1025",
        "cond_1034",
        "cond_1043",
        "cond_1052",
        "cond_1061",
    ]
    assert [imm for _condition, imm in pairs] == [1, 2, 4, 8, 16, 32]
