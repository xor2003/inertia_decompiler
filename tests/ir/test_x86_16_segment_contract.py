from __future__ import annotations

from types import SimpleNamespace

from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_function_ssa,
    build_x86_16_segment_state_artifact,
)
from inertia.ir.segment_contract import (
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentWriteKind,
    apply_x86_16_segment_function_contract,
    build_x86_16_segment_function_contract,
)


def _address(space: MemSpace) -> IRAddress:
    return IRAddress(
        space=space,
        base=("si",),
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def test_segment_contract_records_exact_accesses_and_local_restore() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ax", size=2),
                        (IRValue(MemSpace.REG, name="ds", size=2),),
                        addr=0x1000,
                    ),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.CONST, const=0xB800, size=2),),
                        addr=0x1002,
                    ),
                    IRInstr(
                        "STORE",
                        None,
                        (_address(MemSpace.DS), IRValue(MemSpace.CONST, const=1, size=2)),
                        addr=0x1004,
                    ),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.REG, name="ax", size=2),),
                        addr=0x1006,
                    ),
                    IRInstr(
                        "LOAD",
                        IRValue(MemSpace.TMP, name="t0", size=2),
                        (_address(MemSpace.DS),),
                        addr=0x1008,
                    ),
                ),
            ),
        ),
    )
    state = build_x86_16_segment_state_artifact(artifact, build_x86_16_function_ssa(artifact))

    contract = build_x86_16_segment_function_contract(artifact, state)

    assert contract.entry_requirements == ("ds",)
    assert tuple(access.kind for access in contract.accesses) == (
        SegmentAccessKind.WRITE,
        SegmentAccessKind.READ,
    )
    assert tuple(access.physical_source for access in contract.accesses) == ("0xb800", "ds")
    assert tuple(write.kind for write in contract.writes) == (
        SegmentWriteKind.ASSIGN,
        SegmentWriteKind.RESTORE,
    )
    assert contract.clobbered_registers == ()
    assert contract.restored_registers == ("ds",)
    ds_store_state = next(
        fact for fact in contract.instruction_states if fact.instruction_addr == 0x1004 and fact.register == "ds"
    )
    assert ds_store_state.physical_source == "0xb800"
    assert ds_store_state.verdict is SegmentFactVerdict.PROVEN
    assert contract.summary == {
        "raw_fact_count": 34,
        "normalized_fact_count": 34,
        "classified_fact_count": 34,
        "materialized_count": 34,
        "failure_count": 0,
        "access_count": 2,
        "write_count": 2,
        "instruction_state_count": 30,
    }


def test_segment_contract_refuses_unknown_or_unlocated_access_state() -> None:
    artifact = IRFunctionArtifact(
        function_addr=0x2000,
        blocks=(
            IRBlock(
                addr=0x2000,
                instrs=(
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="es", size=2),
                        (IRValue(MemSpace.REG, name="ax", size=2),),
                        addr=0x2000,
                    ),
                    IRInstr(
                        "LOAD",
                        IRValue(MemSpace.TMP, name="t0", size=2),
                        (_address(MemSpace.ES),),
                        addr=0x2002,
                    ),
                    IRInstr(
                        "STORE",
                        None,
                        (_address(MemSpace.DS), IRValue(MemSpace.CONST, const=1, size=2)),
                    ),
                ),
            ),
        ),
    )
    state = build_x86_16_segment_state_artifact(artifact, build_x86_16_function_ssa(artifact))

    contract = build_x86_16_segment_function_contract(artifact, state)

    assert tuple(access.verdict for access in contract.accesses) == (
        SegmentFactVerdict.UNKNOWN_REFUSE,
        SegmentFactVerdict.UNKNOWN_REFUSE,
    )
    assert contract.writes[0].verdict is SegmentFactVerdict.UNKNOWN_REFUSE
    assert contract.clobbered_registers == ("es",)
    assert contract.summary["failure_count"] == 4
    assert contract.summary["materialized_count"] == 11


def test_apply_segment_contract_attaches_owned_typed_artifact() -> None:
    artifact = IRFunctionArtifact(function_addr=0x3000, blocks=(IRBlock(addr=0x3000),))
    state = build_x86_16_segment_state_artifact(artifact, build_x86_16_function_ssa(artifact))
    codegen = SimpleNamespace(
        _inertia_vex_ir_artifact=artifact,
        _inertia_segment_state_artifact=state,
    )

    changed = apply_x86_16_segment_function_contract(None, codegen)

    assert changed is False
    assert codegen._inertia_segment_function_contract.function_addr == 0x3000


def test_segment_contract_keeps_clobber_on_external_branch() -> None:
    """An internal restoring path cannot hide a second escaping edge."""
    artifact = IRFunctionArtifact(
        function_addr=0x4000,
        blocks=(
            IRBlock(
                addr=0x4000,
                instrs=(
                    IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2),
                            (IRValue(MemSpace.REG, name="ds", size=2),), addr=0x4000),
                    IRInstr("MOV", IRValue(MemSpace.REG, name="ds", size=2),
                            (IRValue(MemSpace.CONST, const=0xB800, size=2),), addr=0x4002),
                ),
                successor_addrs=(0x4010, 0x5000),
            ),
            IRBlock(
                addr=0x4010,
                instrs=(IRInstr(
                    "MOV", IRValue(MemSpace.REG, name="ds", size=2),
                    (IRValue(MemSpace.REG, name="ax", size=2),), addr=0x4010,
                ),),
            ),
        ),
    )
    state = build_x86_16_segment_state_artifact(artifact, build_x86_16_function_ssa(artifact))
    # Supply a proven restoring-path state to isolate exit enumeration from
    # the local solver's inability to carry the saved AX across blocks.
    state.exit_states[0x4010]["ds"] = state.entry_states[0x4000]["ds"]
    contract = build_x86_16_segment_function_contract(artifact, state)
    assert "ds" in contract.clobbered_registers
    assert "ds" not in contract.restored_registers
