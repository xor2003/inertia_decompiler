from __future__ import annotations

import io

import angr

from inertia.alias.segment_stack_fragments import (
    SegmentStackByteOrigin8616,
    store_stack_fragments_8616,
)
from inertia.alias.segment_stack_restore import (
    SegmentStackRestoreVerdict8616,
    _solve_stack_states,
    build_x86_16_segment_stack_restore_artifact,
    build_x86_16_stack_register_restore_artifact_8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.lift_86_16 import (
    Lifter86_16,  # noqa: F401 -- register the native lifter for standalone tests
)
from inertia.ir import (
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
    build_x86_16_segment_function_contract,
    build_x86_16_segment_state_artifact,
)
from inertia.ir.call_stack_coordinates import IRCallStackCoordinates8616
from inertia.ir.core import AddressStatus
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.semantics.call_stack_coordinates import prove_call_stack_coordinates_8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.structuring.decompiler_structuring_stage import DECOMPILER_STRUCTURING_PASSES


def _lift_function(code: bytes) -> IRFunctionArtifact:
    apply_x86_16_bootstrap()
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(normalize=True)
    return build_x86_16_ir_function_artifact(project, cfg.functions[0x1000])


def _const(value: int) -> IRValue:
    return IRValue(MemSpace.CONST, const=value, size=2)


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


def test_real_vex_push_pop_restores_ds_through_exact_stack_bytes() -> None:
    artifact = _lift_function(bytes.fromhex("1e b8 00 b8 8e d8 1f c3"))

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    assert restoration.summary == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "cross_block_restore_count": 0,
    }
    assert len(restoration.facts) == 1
    fact = restoration.facts[0]
    assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert fact.saved_register == "ds"
    assert fact.restore_register == "ds"
    assert fact.stack_offsets == (-2, -1)

    state = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
        restore_sources=restoration.restore_sources,
    )
    changed = state.state_after_instruction(0x1004, "ds")
    restored = state.state_after_instruction(0x1006, "ds")
    assert changed is not None and changed.origin is SegmentOrigin.PROVEN
    assert changed.value_kind is SegmentValueKind8616.SEGMENT_COPY
    assert changed.source == "0xb800"
    assert restored is not None and restored.value_kind is SegmentValueKind8616.STACK_RESTORE
    assert restored.source == "ds"
    assert restored.origin is SegmentOrigin.PROVEN

    contract = build_x86_16_segment_function_contract(artifact, state)
    assert "ds" in contract.restored_registers
    assert "ds" not in contract.clobbered_registers


def test_unknown_incoming_sp_keeps_local_ss_to_ds_byte_proof() -> None:
    """A relative proof in one block must not publish its arbitrary SP origin."""
    artifact = _lift_function(bytes.fromhex("89 c4 eb 00 16 1f c3"))

    assert _solve_stack_states(artifact)[0x1004].sp_delta is None
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)

    assert restoration.summary["materialized_count"] == 1
    assert restoration.summary["failure_count"] == 0
    assert restoration.summary["cross_block_restore_count"] == 0
    assert len(restoration.facts) == 1
    fact = restoration.facts[0]
    assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert fact.saved_instruction_addr == 0x1004
    assert fact.restore_instruction_addr == 0x1005
    assert fact.saved_register == "ss"
    assert fact.restore_register == "ds"
    assert fact.stack_offsets == (-2, -1)

    state = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
        restore_sources=restoration.restore_sources,
    )
    copied = state.state_after_instruction(0x1005, "ds")
    assert copied is not None and copied.origin is SegmentOrigin.PROVEN
    assert copied.value_kind is SegmentValueKind8616.STACK_RESTORE
    assert copied.source == "ss"


def test_unknown_incoming_sp_refuses_local_pair_after_sp_clobber() -> None:
    """An unproved SP write breaks the local relative coordinate."""
    artifact = _lift_function(bytes.fromhex("89 c4 eb 00 16 89 c4 1f c3"))

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)

    assert restoration.restore_sources == ()
    assert restoration.summary["materialized_count"] == 0
    assert restoration.summary["failure_count"] == 1
    assert restoration.facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


def test_unknown_incoming_sp_refuses_uncertain_ss_store() -> None:
    """An SS store through unknown BX may overwrite the locally saved bytes."""
    artifact = _lift_function(bytes.fromhex("89 c4 eb 00 16 36 89 07 1f c3"))

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)

    assert restoration.restore_sources == ()
    assert restoration.summary["materialized_count"] == 0
    assert restoration.summary["failure_count"] == 1
    assert restoration.facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


def test_unknown_incoming_sp_relative_proof_does_not_cross_blocks() -> None:
    """The arbitrary local coordinate cannot reach a successor POP block."""
    artifact = _lift_function(bytes.fromhex("89 c4 eb 00 16 eb 00 1f c3"))

    assert _solve_stack_states(artifact)[0x1004].sp_delta is None
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)

    assert restoration.restore_sources == ()
    assert restoration.summary["materialized_count"] == 0
    assert restoration.summary["failure_count"] == 1
    assert restoration.facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


def test_real_vex_push_pop_restores_ax_through_exact_stack_bytes() -> None:
    """The generic Alias owner proves a mid-function AX save/restore pair."""
    artifact = _lift_function(bytes.fromhex("50 b8 00 00 58 c3"))

    restoration = build_x86_16_stack_register_restore_artifact_8616(
        artifact,
        tracked_registers=frozenset({"ax"}),
    )

    assert restoration.summary == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "cross_block_restore_count": 0,
    }
    fact = restoration.facts[0]
    assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert fact.saved_register == "ax"
    assert fact.restore_register == "ax"
    assert fact.stack_offsets == (-2, -1)


def test_unknown_incoming_sp_keeps_local_gp_stack_restore() -> None:
    """The generic register builder shares the same nonescaping local proof."""
    artifact = _lift_function(bytes.fromhex("89 c4 eb 00 50 58 c3"))

    restoration = build_x86_16_stack_register_restore_artifact_8616(
        artifact,
        tracked_registers=frozenset({"ax"}),
    )

    assert _solve_stack_states(artifact, frozenset({"ax"}))[0x1004].sp_delta is None
    assert restoration.summary["materialized_count"] == 1
    assert restoration.summary["failure_count"] == 0
    assert restoration.summary["cross_block_restore_count"] == 0
    assert restoration.facts[0].saved_register == "ax"
    assert restoration.facts[0].restore_register == "ax"
    assert restoration.facts[0].stack_offsets == (-2, -1)


def test_real_vex_push_immediate_transfers_exact_constant_to_ds() -> None:
    """Alias preserves both immediate bytes across a PUSH/POP segment transfer."""
    artifact = _lift_function(bytes.fromhex("68 4e 28 1f c3"))

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)

    assert restoration.summary == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
        "cross_block_restore_count": 0,
    }
    fact = restoration.facts[0]
    assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert fact.saved_instruction_addr == 0x1000
    assert fact.saved_register is None
    assert fact.restore_register == "ds"
    assert fact.stack_offsets == (-2, -1)
    assert fact.constant_value == 0x284E
    assert restoration.restore_sources == ()


def test_unknown_ss_alias_invalidates_saved_stack_identity() -> None:
    stack_bytes = {
        -2: SegmentStackByteOrigin8616("ds", 0x2000, 0, 0, -2),
        -1: SegmentStackByteOrigin8616("ds", 0x2000, 1, 1, -1),
    }

    store_stack_fragments_8616(
        IRAddress(
            MemSpace.SS,
            ("bp",),
            0,
            1,
            AddressStatus.STABLE,
            SegmentOrigin.PROVEN,
        ),
        IRValue(MemSpace.CONST, const=0, size=1),
        frozenset(),
        0,
        stack_bytes,
    )

    assert stack_bytes == {}


def test_unproved_stack_value_refuses_segment_restoration() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x3000,
        blocks=(
            IRBlock(
                addr=0x3000,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.TMP, name="unproved_stack_value", size=2),),
                        addr=0x3000,
                    ),
                ),
            ),
        ),
    )

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)

    assert restoration.restore_sources == ()
    assert restoration.summary["classified_fact_count"] == 0
    assert restoration.summary["materialized_count"] == 0
    assert restoration.summary["failure_count"] == 1
    assert restoration.facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


def test_cross_block_stack_bytes_restore_entry_ds_identity() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x4000,
        blocks=(
            IRBlock(addr=0x4000, instrs=_push_ds_ir(0x4000), successor_addrs=(0x4010,)),
            IRBlock(
                addr=0x4010,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (_const(0xB800),),
                        addr=0x4010,
                    ),
                    *_pop_ds_ir(0x4012),
                ),
            ),
        ),
    )

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    assert restoration.summary["cross_block_restore_count"] == 1
    assert restoration.summary["materialized_count"] == 1

    state = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=build_x86_16_function_ssa(artifact),
        restore_sources=restoration.restore_sources,
    )
    restored = state.state_after_instruction(0x4012, "ds")
    assert restored is not None and restored.value_kind is SegmentValueKind8616.STACK_RESTORE
    assert restored.source == "ds"
    contract = build_x86_16_segment_function_contract(artifact, state)
    assert contract.restored_registers == ("ds",)
    assert "ds" not in contract.clobbered_registers


def test_neutral_call_contract_discards_only_transient_return_push() -> None:
    """A complete neutral CALL preserves caller stack bytes across its VEX push."""
    call_addr = 0x4010
    artifact = IRFunctionArtifact(
        function_addr=0x4000,
        blocks=(
            IRBlock(addr=0x4000, instrs=_push_ds_ir(0x4000), successor_addrs=(call_addr,)),
            IRBlock(
                addr=call_addr,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="sp", size=2),
                        (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),),
                        addr=call_addr,
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
                        addr=call_addr,
                    ),
                    IRInstr(
                        "CALL",
                        None,
                        (_const(0x5000),),
                        addr=call_addr,
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
    assert restoration.summary["cross_block_restore_count"] == 1


def _call_boundary_blocks(
    call_addr: int, effect: IRCallStackEffect8616,
) -> tuple[IRBlock, ...]:
    """PUSH DS before one CALL, POP DS after it, through real block topology."""
    return (
        IRBlock(addr=0x4000, instrs=_push_ds_ir(0x4000), successor_addrs=(call_addr,)),
        IRBlock(
            addr=call_addr,
            instrs=(
                IRInstr(
                    "MOV",
                    IRValue(MemSpace.REG, name="sp", size=2),
                    (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),),
                    addr=call_addr,
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
                        _const(call_addr + 3),
                    ),
                    addr=call_addr,
                ),
                IRInstr("CALL", None, (_const(0x5000),), addr=call_addr,
                        call_stack_effect=effect),
            ),
            successor_addrs=(0x4020,),
        ),
        IRBlock(addr=0x4020, instrs=_pop_ds_ir(0x4020)),
    )


def _proven_boundary_coordinates(call_addr: int, purge: int) -> IRCallStackCoordinates8616:
    """Supply the unit's CALL with a real admitted binary/callee SP proof."""
    apply_x86_16_bootstrap()
    code = bytearray(b"\x90" * 0x1003)
    code[:4] = bytes.fromhex("1ee90c00")
    offset = call_addr - 0x4000
    code[offset:offset + 3] = b"\xe8" + (0x5000 - call_addr - 3).to_bytes(2, "little")
    code[0x13:0x16] = bytes.fromhex("e90a00")
    code[0x20:0x22] = bytes.fromhex("1fc3")
    ret = b"\xc3" if purge == 0 else b"\xc2" + purge.to_bytes(2, "little")
    code[0x1000:0x1000 + len(ret)] = ret
    project = angr.Project(io.BytesIO(bytes(code)), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x4000, "entry_point": 0x4000,
    })
    project.analyses.CFGFast(normalize=True)
    block = _call_boundary_blocks(call_addr, IRCallStackEffect8616())[1]
    summary = CallsiteSummary8616(
        callsite_addr=call_addr, target_addr=0x5000, return_addr=call_addr + 3,
        kind="direct_near", arg_count=0, arg_widths=(), stack_cleanup=None,
        return_register=None, return_used=None,
    )
    coordinates = prove_call_stack_coordinates_8616(
        project, summary, instruction=block.instrs[-1], block=block,
    )
    assert coordinates.has_proven_sp_delta
    return coordinates


def test_proven_call_sp_coordinate_survives_unproven_memory_effect() -> None:
    """An independently evidenced SP delta outlives a refused byte census."""
    call_addr = 0x4010
    effect = IRCallStackEffect8616(
        complete=False,
        net_stack_delta=2,
        stack_coordinates=_proven_boundary_coordinates(call_addr, 2),
    )
    artifact = IRFunctionArtifact(
        function_addr=0x4000, blocks=_call_boundary_blocks(call_addr, effect),
    )

    # -2 from PUSH DS before the boundary, +2 proven callee purge after it.
    assert _solve_stack_states(artifact)[call_addr].sp_delta == 0

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    # Byte identities never survive without their own preservation proof.
    assert restoration.summary["materialized_count"] == 0
    assert restoration.facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


def test_proven_call_sp_coordinate_composes_with_byte_census() -> None:
    """A proven coordinate alone drives both SP tracking and byte survival."""
    call_addr = 0x4010
    effect = IRCallStackEffect8616(
        complete=True,
        net_stack_delta=0,
        stack_coordinates=_proven_boundary_coordinates(call_addr, 0),
    )
    artifact = IRFunctionArtifact(
        function_addr=0x4000, blocks=_call_boundary_blocks(call_addr, effect),
    )

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)

    assert _solve_stack_states(artifact)[call_addr].sp_delta == -2
    assert restoration.summary["materialized_count"] == 1
    assert restoration.summary["cross_block_restore_count"] == 1


def test_conflicting_predecessor_without_save_refuses_cross_block_restore() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x5000,
        blocks=(
            IRBlock(addr=0x5000, successor_addrs=(0x5010, 0x5020)),
            IRBlock(addr=0x5010, instrs=_push_ds_ir(0x5010), successor_addrs=(0x5030,)),
            IRBlock(addr=0x5020, successor_addrs=(0x5030,)),
            IRBlock(addr=0x5030, instrs=_pop_ds_ir(0x5030)),
        ),
    )

    restoration = build_x86_16_segment_stack_restore_artifact(artifact)

    assert restoration.restore_sources == ()
    assert restoration.summary["classified_fact_count"] == 0
    assert restoration.summary["failure_count"] == 1
    assert restoration.facts[0].verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE


def test_structuring_stage_runs_alias_restoration_before_segment_state() -> None:
    names = tuple(spec.name for spec in DECOMPILER_STRUCTURING_PASSES)

    vex_index = names.index("_vex_ir_artifact_8616")
    restoration_index = names.index("_segment_stack_restore_artifact_8616")
    state_index = names.index("_segment_state_artifact_8616")
    contract_index = names.index("_segment_function_contract_8616")
    assert vex_index < restoration_index < state_index < contract_index
