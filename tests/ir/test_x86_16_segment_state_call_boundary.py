"""Tests for the unmodeled-CALL boundary refusal in segment-state transfer.

Layer: Tests.
Responsibility: cover the IR segment-state solver's refusal to preserve segment
or general-register proxy identities across a CALL whose callee effects are
unmodeled, and the proven controls (alias restore, joins, post-call writes)
around that boundary.
"""

from __future__ import annotations

import io

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRCallStackEffect8616,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    SegmentValueKind8616,
    build_x86_16_function_ssa,
    build_x86_16_segment_state_artifact,
)
from inertia.ir.segment_state import SegmentStateArtifact
from inertia.ir.segment_state_transfer import SegmentRestoreSource
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

from inertia.alias.segment_stack_restore import (
    build_x86_16_segment_stack_restore_artifact,
)


def _const(value: int, size: int = 2) -> IRValue:
    return IRValue(MemSpace.CONST, const=value, size=size)


def _reg(name: str) -> IRValue:
    return IRValue(MemSpace.REG, name=name, size=2)


def _call(addr: int, target: int = 0x2000) -> IRInstr:
    return IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=target, size=4),), addr=addr)


def _segment_state(
    artifact: IRFunctionArtifact,
    restore_sources: tuple[SegmentRestoreSource, ...] = (),
) -> SegmentStateArtifact:
    return build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
        restore_sources=restore_sources,
    )


def _lift_caller(code: bytes, base: int = 0x1000) -> IRFunctionArtifact:
    """Lift exact bytes into a typed IR artifact for the entry function."""
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": base,
            "entry_point": base,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    cfg = project.analyses.CFGFast(normalize=True)
    return build_x86_16_ir_function_artifact(project, cfg.functions[base])


def _push_ds_ir(addr: int) -> tuple[IRInstr, ...]:
    ds = IRValue(MemSpace.REG, name="ds", size=2)
    return (
        IRInstr(
            "MOV",
            IRValue(MemSpace.REG, name="sp", size=2),
            (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),),
            addr=addr,
        ),
        IRInstr(
            "Iop_Shr16",
            IRValue(MemSpace.TMP, name="saved_ds_high", size=2),
            (ds, _const(8)),
            addr=addr,
        ),
        IRInstr(
            "STORE",
            None,
            (
                IRAddress(MemSpace.SS, ("sp",), 0, 1, AddressStatus.STABLE, SegmentOrigin.PROVEN),
                IRValue(MemSpace.REG, name="ds", size=1, expr=("Iop_16to8",)),
            ),
            addr=addr,
        ),
        IRInstr(
            "STORE",
            None,
            (
                IRAddress(MemSpace.SS, ("sp",), 1, 1, AddressStatus.STABLE, SegmentOrigin.PROVEN),
                IRValue(MemSpace.TMP, name="expr:Iop_Shr16", size=1, expr=("Iop_16to8",)),
            ),
            addr=addr,
        ),
    )


def _pop_ds_ir(addr: int) -> tuple[IRInstr, ...]:
    return (
        IRInstr(
            "LOAD",
            IRValue(MemSpace.TMP, name="saved_ds_low", size=1),
            (IRAddress(MemSpace.SS, ("sp",), 0, 1, AddressStatus.STABLE, SegmentOrigin.PROVEN),),
            addr=addr,
        ),
        IRInstr(
            "LOAD",
            IRValue(MemSpace.TMP, name="loaded_ds_high", size=1),
            (IRAddress(MemSpace.SS, ("sp",), 1, 1, AddressStatus.STABLE, SegmentOrigin.PROVEN),),
            addr=addr,
        ),
        IRInstr(
            "Iop_Shl16",
            IRValue(MemSpace.TMP, name="restored_ds_high", size=2),
            (IRValue(MemSpace.TMP, name="load_loaded_ds_high", size=1), _const(8)),
            addr=addr,
        ),
        IRInstr(
            "Iop_Or16",
            IRValue(MemSpace.TMP, name="restored_ds", size=2),
            (
                IRValue(MemSpace.TMP, name="load_saved_ds_low", size=1),
                IRValue(MemSpace.TMP, name="expr:Iop_Shl16", size=2),
            ),
            addr=addr,
        ),
        IRInstr(
            "MOV",
            IRValue(MemSpace.REG, name="sp", size=2),
            (IRValue(MemSpace.REG, name="sp", offset=2, size=2),),
            addr=addr,
        ),
        IRInstr(
            "MOV",
            IRValue(MemSpace.REG, name="ds", size=2),
            (IRValue(MemSpace.TMP, name="expr:Iop_Or16", size=2),),
            addr=addr,
        ),
    )


def test_unmodeled_call_drops_ds_equals_ss_copy() -> None:
    """A proven DS:=SS copy must not survive a CALL with unmodeled effects."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("MOV", _reg("ds"), (_reg("ss"),), addr=0x1000),
                    _call(0x1002),
                    IRInstr("LOAD", None, (), addr=0x1005),
                ),
            ),
        ),
    )

    state = _segment_state(artifact)

    before = state.state_before_instruction(0x1002, "ds")
    assert before is not None and before.origin is SegmentOrigin.PROVEN
    assert before.source == "ss"
    after = state.state_after_instruction(0x1002, "ds")
    assert after is not None and after.origin is SegmentOrigin.UNKNOWN
    assert after.value_kind is SegmentValueKind8616.CALL_BOUNDARY
    post = state.state_before_instruction(0x1005, "ds")
    assert post is not None and post.origin is SegmentOrigin.UNKNOWN
    exit_ds = state.state_at_block_exit(0x1000, "ds")
    assert exit_ds is not None and exit_ds.origin is SegmentOrigin.UNKNOWN


def test_unmodeled_call_drops_numeric_segment_value() -> None:
    """A proven numeric DS write must not survive an unknown callee."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("MOV", _reg("ds"), (_const(0xB800),), addr=0x1000),
                    _call(0x1002),
                ),
            ),
        ),
    )

    state = _segment_state(artifact)

    before = state.state_before_instruction(0x1002, "ds")
    assert before is not None and before.constant_value() == 0xB800
    after = state.state_after_instruction(0x1002, "ds")
    assert after is not None and after.origin is SegmentOrigin.UNKNOWN
    assert after.value_kind is SegmentValueKind8616.CALL_BOUNDARY


def test_unmodeled_call_drops_general_register_proxy() -> None:
    """A stale AX copy of DS must not resurrect DS after the CALL."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("MOV", _reg("ax"), (_reg("ds"),), addr=0x1000),
                    _call(0x1002),
                    IRInstr("MOV", _reg("ds"), (_reg("ax"),), addr=0x1005),
                ),
            ),
        ),
    )

    state = _segment_state(artifact)

    restored = state.state_after_instruction(0x1005, "ds")
    assert restored is not None and restored.origin is SegmentOrigin.UNKNOWN
    assert restored.value_kind is SegmentValueKind8616.UNKNOWN_WRITE


def test_call_exit_state_marks_every_segment_register_call_bound() -> None:
    """Every tracked segment identity is unproved across the CALL, not just DS."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("MOV", _reg("es"), (_reg("ds"),), addr=0x1000),
                    _call(0x1002),
                ),
            ),
        ),
    )

    state = _segment_state(artifact)

    exit_states = state.instruction_exit_states[0x1002]
    assert set(exit_states) == {"cs", "ds", "es", "ss", "fs", "gs"}
    for register, register_state in exit_states.items():
        assert register_state.origin is SegmentOrigin.UNKNOWN, register
        assert register_state.value_kind is SegmentValueKind8616.CALL_BOUNDARY, register


def test_call_stack_effect_is_not_segment_preservation() -> None:
    """A complete typed stack effect proves BP/SP storage only, not segments."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("MOV", _reg("ds"), (_reg("ss"),), addr=0x1000),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=0x2000, size=4),),
                        addr=0x1002,
                        call_stack_effect=IRCallStackEffect8616(
                            net_stack_delta=0,
                            complete=True,
                            bp_preserved=True,
                        ),
                    ),
                ),
            ),
        ),
    )

    state = _segment_state(artifact)

    after = state.state_after_instruction(0x1002, "ds")
    assert after is not None and after.origin is SegmentOrigin.UNKNOWN


def test_calling_predecessor_poisons_join() -> None:
    """A join is unproved when only one predecessor crossed a CALL."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(IRInstr("MOV", _reg("ds"), (_reg("ss"),), addr=0x1000),),
                successor_addrs=(0x1010, 0x1020),
            ),
            IRBlock(
                addr=0x1010,
                instrs=(_call(0x1010),),
                successor_addrs=(0x1030,),
            ),
            IRBlock(addr=0x1020, successor_addrs=(0x1030,)),
            IRBlock(
                addr=0x1030,
                instrs=(IRInstr("LOAD", None, (), addr=0x1030),),
            ),
        ),
    )

    state = _segment_state(artifact)

    calling_entry = state.state_at_block_entry(0x1010, "ds")
    assert calling_entry is not None and calling_entry.origin is SegmentOrigin.PROVEN
    calling_exit = state.state_at_block_exit(0x1010, "ds")
    assert calling_exit is not None and calling_exit.origin is SegmentOrigin.UNKNOWN
    quiet_exit = state.state_at_block_exit(0x1020, "ds")
    assert quiet_exit is not None and quiet_exit.origin is SegmentOrigin.PROVEN
    joined = state.state_at_block_entry(0x1030, "ds")
    assert joined is not None and joined.origin is SegmentOrigin.UNKNOWN


def test_explicit_segment_write_after_call_reproves_identity() -> None:
    """A new explicit segment definition after the CALL is still provable."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("MOV", _reg("ds"), (_reg("ss"),), addr=0x1000),
                    _call(0x1002),
                    IRInstr("MOV", _reg("ds"), (_const(0xB800),), addr=0x1005),
                ),
            ),
        ),
    )

    state = _segment_state(artifact)

    pre_write = state.state_before_instruction(0x1005, "ds")
    assert pre_write is not None and pre_write.origin is SegmentOrigin.UNKNOWN
    rewritten = state.state_after_instruction(0x1005, "ds")
    assert rewritten is not None and rewritten.origin is SegmentOrigin.PROVEN
    assert rewritten.value_kind is SegmentValueKind8616.CONST_WRITE
    assert rewritten.constant_value() == 0xB800


def test_call_boundary_counts_in_closed_evidence_counters() -> None:
    """A CALL without a segment dst is still a counted, refused boundary fact."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("MOV", _reg("ds"), (_reg("ss"),), addr=0x1000),
                    _call(0x1002),
                ),
            ),
        ),
    )

    state = _segment_state(artifact)

    summary = state.summary
    assert summary["call_boundary_count"] == 1
    assert summary["explicit_write_count"] == 1
    assert summary["raw_fact_count"] == 2
    assert summary["normalized_fact_count"] == 2
    assert summary["classified_fact_count"] == 1
    assert summary["materialized_count"] == 1
    assert summary["failure_count"] == 1


def test_alias_proved_stack_restore_survives_call() -> None:
    """An Alias-proved PUSH DS/POP DS pair still restores DS across a CALL."""
    artifact = IRFunctionArtifact(
        function_addr=0x4000,
        blocks=(
            IRBlock(addr=0x4000, instrs=_push_ds_ir(0x4000), successor_addrs=(0x4010,)),
            IRBlock(
                addr=0x4010,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="sp", size=2),
                        (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),),
                        addr=0x4010,
                    ),
                    IRInstr(
                        "STORE",
                        None,
                        (
                            IRAddress(
                                MemSpace.SS,
                                ("sp",),
                                -4,
                                2,
                                AddressStatus.STABLE,
                                SegmentOrigin.PROVEN,
                            ),
                            _const(0x4013),
                        ),
                        addr=0x4010,
                    ),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=0x5000, size=4),),
                        addr=0x4010,
                        call_stack_effect=IRCallStackEffect8616(
                            net_stack_delta=0,
                            complete=True,
                        ),
                    ),
                ),
                successor_addrs=(0x4020,),
            ),
            IRBlock(addr=0x4020, instrs=_pop_ds_ir(0x4020)),
        ),
    )

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    assert restoration.summary["materialized_count"] == 1
    state = _segment_state(artifact, restoration.restore_sources)

    call_exit = state.state_after_instruction(0x4010, "ds")
    assert call_exit is not None and call_exit.origin is SegmentOrigin.UNKNOWN
    restored = state.state_after_instruction(0x4020, "ds")
    assert restored is not None and restored.origin is SegmentOrigin.PROVEN
    assert restored.value_kind is SegmentValueKind8616.STACK_RESTORE
    assert restored.source == "ds"


def test_lifted_call_boundary_drops_byte_proven_ds_identity() -> None:
    """Real lifted PUSH SS/POP DS/CALL keeps pre-call proof and drops it after."""
    # push ss; pop ds; call 0x1007; ret; nop; callee: ret
    artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    assert len(restoration.restore_sources) == 1

    state = _segment_state(artifact, restoration.restore_sources)

    before = state.state_before_instruction(0x1002, "ds")
    assert before is not None and before.origin is SegmentOrigin.PROVEN
    assert before.source == "ss"
    after = state.state_after_instruction(0x1002, "ds")
    assert after is not None and after.origin is SegmentOrigin.UNKNOWN
    assert after.value_kind is SegmentValueKind8616.CALL_BOUNDARY
    return_entry = state.state_at_block_entry(0x1005, "ds")
    assert return_entry is not None and return_entry.origin is SegmentOrigin.UNKNOWN
    assert state.summary["call_boundary_count"] == 1
