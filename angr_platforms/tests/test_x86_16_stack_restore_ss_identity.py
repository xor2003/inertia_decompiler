"""Keep stack byte identity scoped to the selector used for each memory access.

Layer: Tests.
Responsibility: require SS writes to invalidate saved storage, while retaining
values already loaded and permitting fresh same-selector saves. Word SP and
parent ESP clobbers remain independently refused. No whole-callee claim.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
    build_x86_16_segment_stack_restore_artifact,
    build_x86_16_stack_register_restore_artifact_8616,
)
from angr_platforms.X86_16.ir import (
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.core import AddressStatus
from test_x86_16_segment_stack_restore import _lift_function


@pytest.mark.parametrize("register", ("bp", "ds"))
def test_restore_artifact_retains_exact_ir_lineage(register: str) -> None:
    """Same-address replacement IR cannot authorize an earlier restore fact."""
    artifact = _lift_function(bytes.fromhex("55 5d c3" if register == "bp" else "1e 1f c3"))
    result = (
        build_x86_16_stack_register_restore_artifact_8616(artifact, tracked_registers=frozenset({register}))
        if register == "bp" else build_x86_16_segment_stack_restore_artifact(artifact)
    )
    assert any(fact.verdict is SegmentStackRestoreVerdict8616.PROVEN for fact in result.facts)
    assert result.source_artifact is artifact
    assert result.is_bound_to(artifact)
    replacement = replace(artifact)
    assert replacement == artifact and replacement is not artifact
    assert not result.is_bound_to(replacement)
    assert result.to_dict()["source_function_addr"] == artifact.function_addr


def _require_write(artifact: IRFunctionArtifact, register: str, address: int) -> IRInstr:
    """Observe the intended register mutation in typed IR before classifying it."""
    writes = [item for block in artifact.blocks for item in block.instrs
              if item.addr == address and item.dst is not None
              and item.dst.space is MemSpace.REG and item.dst.name == register]
    assert len(writes) == 1, (register, address, writes)
    return writes[0]


def _require_store(artifact: IRFunctionArtifact, address: int) -> None:
    """Observe real SS save bytes rather than trusting the input spelling."""
    assert any(item.op == "STORE" and item.addr == address and item.args
               and isinstance(item.args[0], IRAddress) and item.args[0].space is MemSpace.SS
               for block in artifact.blocks for item in block.instrs)


def _track_bp(artifact: IRFunctionArtifact) -> list[SegmentStackRestoreFact8616]:
    """Require coherent accounting for every classified save/restore fact."""
    result = build_x86_16_stack_register_restore_artifact_8616(artifact, tracked_registers=frozenset({"bp"}))
    proven = sum(fact.verdict is SegmentStackRestoreVerdict8616.PROVEN for fact in result.facts)
    assert result.summary["raw_fact_count"] == result.summary["normalized_fact_count"] == len(result.facts)
    assert result.summary["classified_fact_count"] == result.summary["materialized_count"] == proven
    assert result.summary["failure_count"] == len(result.facts) - proven
    return list(result.facts)


def _word_address() -> IRAddress:
    """Name the current SS:SP word, distinct from selector identity."""
    return IRAddress(MemSpace.SS, ("sp",), 0, 2, AddressStatus.STABLE, SegmentOrigin.PROVEN)


def _push_bp_ir(address: int) -> tuple[IRInstr, ...]:
    """Supply a complete word-save effect for cross-block/captured-value cases."""
    return (
        IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2),
                (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),), addr=address),
        IRInstr("STORE", None, (_word_address(), IRValue(MemSpace.REG, name="bp", size=2)), addr=address),
    )


def _load_bp_ir(address: int, temporary: int) -> IRInstr:
    """Capture memory bits once, before any later selector transition."""
    return IRInstr("LOAD", IRValue(MemSpace.TMP, name="saved_bp_word", size=2, source_tmp=temporary),
                   (_word_address(),), addr=address)


def _write_captured_bp_ir(address: int, temporary: int) -> IRInstr:
    """Consume retained value provenance, not a fresh memory access."""
    return IRInstr("MOV", IRValue(MemSpace.REG, name="bp", size=2),
                   (IRValue(MemSpace.TMP, name="saved_bp_word", size=2, source_tmp=temporary),), addr=address)


def _pop_bp_ir(address: int, temporary: int) -> tuple[IRInstr, ...]:
    """Load the word under current SS, then advance the word stack pointer."""
    return (_load_bp_ir(address, temporary), _write_captured_bp_ir(address, temporary),
            IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2),
                    (IRValue(MemSpace.REG, name="sp", offset=2, size=2),), addr=address))


def _mov_ss_ir(address: int | None) -> IRInstr:
    """Retain the same typed SS-selector mutation observed in real lifted IR."""
    return IRInstr("MOV", IRValue(MemSpace.REG, name="ss", size=2),
                   (IRValue(MemSpace.REG, name="ax", size=2),), addr=address)


def test_same_selector_bp_save_restore_is_proven() -> None:
    """Ordinary PUSH/POP restores both exact entry-relative bytes."""
    artifact = _lift_function(bytes.fromhex("55 5d c3"))
    _require_store(artifact, 0x1000)
    _require_write(artifact, "bp", 0x1001)
    facts = _track_bp(artifact)
    assert len(facts) == 1
    fact = facts[0]
    assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert fact.saved_register == fact.restore_register == "bp"
    assert (fact.saved_instruction_addr, fact.restore_instruction_addr, fact.stack_offsets) == (0x1000, 0x1001, (-2, -1))


def test_ss_change_between_real_push_pop_refuses_old_storage() -> None:
    """Equal offsets across two unproved SS selectors are not storage identity."""
    artifact = _lift_function(bytes.fromhex("55 8e d0 5d c3"))
    _require_store(artifact, 0x1000)
    _require_write(artifact, "ss", 0x1001)
    _require_write(artifact, "bp", 0x1003)
    facts = _track_bp(artifact)
    assert len(facts) == 1
    assert facts[0].restore_register == "bp" and facts[0].restore_instruction_addr == 0x1003
    assert facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


@pytest.mark.parametrize("mutation_address", (0x6010, None))
def test_ss_change_across_supplied_edge_refuses_old_storage(mutation_address: int | None) -> None:
    """A predecessor's saved-byte map cannot cross a later selector write."""
    artifact = IRFunctionArtifact(0x6000, (
        IRBlock(0x6000, _push_bp_ir(0x6000), successor_addrs=(0x6010,)),
        IRBlock(0x6010, (_mov_ss_ir(mutation_address), *_pop_bp_ir(0x6012, 40))),
    ))
    facts = _track_bp(artifact)
    assert len(facts) == 1
    assert (facts[0].block_addr, facts[0].restore_register, facts[0].restore_instruction_addr) == (0x6010, "bp", 0x6012)
    assert facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


def test_ss_change_across_real_binary_edge_refuses_old_storage() -> None:
    """The same refusal survives a real binary CFG and VEX lifting."""
    artifact = _lift_function(bytes.fromhex("55 eb 00 8e d0 5d c3"))
    assert len(artifact.blocks) >= 2
    assert any(0x1003 in block.successor_addrs for block in artifact.blocks if block.addr == 0x1000)
    _require_store(artifact, 0x1000)
    _require_write(artifact, "ss", 0x1003)
    _require_write(artifact, "bp", 0x1005)
    facts = _track_bp(artifact)
    assert len(facts) == 1
    assert facts[0].restore_instruction_addr == 0x1005
    assert facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


@pytest.mark.parametrize("code,register,pop_address", [
    ("55 bc 00 10 5d c3", "sp", 0x1004),
    ("55 66 bc 00 10 00 00 5d c3", "esp", 0x1007),
])
def test_word_and_parent_sp_clobbers_refuse(code: str, register: str, pop_address: int) -> None:
    """An unproved word or parent-register write breaks the stack coordinate."""
    artifact = _lift_function(bytes.fromhex(code))
    _require_store(artifact, 0x1000)
    write = _require_write(artifact, register, 0x1001)
    assert write.dst is not None and write.dst.size == (4 if register == "esp" else 2)
    assert any(isinstance(arg, IRValue) and arg.space is MemSpace.CONST for arg in write.args)
    _require_write(artifact, "bp", pop_address)
    facts = _track_bp(artifact)
    assert len(facts) == 1
    assert (facts[0].restore_register, facts[0].restore_instruction_addr) == ("bp", pop_address)
    assert facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


def test_fresh_save_after_ss_change_remains_proven() -> None:
    """A new save/load pair proves only the post-transition storage origin."""
    artifact = _lift_function(bytes.fromhex("55 8e d0 55 5d c3"))
    _require_store(artifact, 0x1000)
    _require_write(artifact, "ss", 0x1001)
    _require_store(artifact, 0x1003)
    _require_write(artifact, "bp", 0x1004)
    facts = _track_bp(artifact)
    assert len(facts) == 1
    assert facts[0].verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert facts[0].saved_register == facts[0].restore_register == "bp"
    assert (facts[0].saved_instruction_addr, facts[0].restore_instruction_addr, facts[0].stack_offsets) == (0x1003, 0x1004, (-4, -3))


def test_old_captured_load_remains_proven_after_ss_change() -> None:
    """Invalidating memory cannot erase an already captured immutable value."""
    artifact = IRFunctionArtifact(0x6000, (IRBlock(0x6000, (
        *_push_bp_ir(0x6000), _load_bp_ir(0x6002, 40),
        _mov_ss_ir(0x6004), _write_captured_bp_ir(0x6006, 40),
    )),))
    facts = _track_bp(artifact)
    assert len(facts) == 1
    fact = facts[0]
    assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert fact.saved_register == fact.restore_register == "bp"
    assert (fact.saved_instruction_addr, fact.restore_instruction_addr, fact.stack_offsets) == (0x6000, 0x6006, (-2, -1))
