from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable
import inertia.structuring.decompiler_structuring_stage as stage
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.real_mode_linear as real_mode_linear
from inertia.lowering.callee_saved_frame import (
    CalleeSavedFrameCarrierKind8616,
    CalleeSavedFrameInstructionRole8616,
    CalleeSavedFramePruneFact8616,
    CalleeSavedFramePruneRecord8616,
)
from capstone.x86_const import (
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_OP_REG,
    X86_REG_SI,
)

from inertia.validation.tail_validation_frame_spills import (
    callee_saved_frame_prune_delta_8616,
)


class _Codegen:
    def __init__(self, project: object) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _project_codegen() -> tuple[SimpleNamespace, _Codegen]:
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    root = CStatements([], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        arg_list=[],
        variables_in_use={},
        unified_local_vars={},
    )
    return project, codegen


def _register(project: SimpleNamespace, codegen: _Codegen, name: str) -> CVariable:
    offset, size = project.arch.registers[name]
    return CVariable(
        SimRegisterVariable(offset, size, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _segmented_sp_store(
    project: SimpleNamespace,
    codegen: _Codegen,
    *,
    ins_addr: int,
) -> CAssignment:
    ss = _register(project, codegen, "ss")
    sp = _register(project, codegen, "sp")
    si = _register(project, codegen, "si")
    scaled_ss = CBinaryOp(
        "Mul",
        ss,
        CConstant(16, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    stack_offset = CBinaryOp(
        "Sub",
        sp,
        CConstant(3, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    linear = CBinaryOp("Add", scaled_ss, stack_offset, codegen=codegen)
    linear._type = SimTypePointer(SimTypeShort(False)).with_arch(project.arch)
    lhs = CUnaryOp("Dereference", linear, codegen=codegen)
    return CAssignment(lhs, si, codegen=codegen, tags={"ins_addr": ins_addr})


def _register_instruction(address: int, instruction_id: int) -> SimpleNamespace:
    operand = SimpleNamespace(type=X86_OP_REG, reg=X86_REG_SI)
    return SimpleNamespace(
        address=address,
        id=instruction_id,
        operands=(operand,),
        reg_name=lambda register: "si" if register == X86_REG_SI else "",
    )


def _frame_instructions(*, argument_push: bool = False) -> tuple[SimpleNamespace, ...]:
    instructions = [_register_instruction(0x4014, X86_INS_PUSH)]
    if argument_push:
        instructions.append(_register_instruction(0x4020, X86_INS_PUSH))
    instructions.extend(
        (
            _register_instruction(0x4030, X86_INS_POP),
            SimpleNamespace(address=0x4031, id=X86_INS_RET, operands=()),
        )
    )
    return tuple(instructions)


def _prune_fact() -> CalleeSavedFramePruneFact8616:
    return CalleeSavedFramePruneFact8616(
        function_addr=0x4010,
        register_name="si",
        push_addr=0x4014,
        pop_addr=0x4030,
        instruction_addr=0x4014,
        carrier_ordinal=0,
        instruction_role=CalleeSavedFrameInstructionRole8616.PUSH,
        carrier_kind=CalleeSavedFrameCarrierKind8616.SEGMENTED_STACK_WRITE,
        stack_displacement=-3,
        access_width=2,
    )


def _validation(location: str = "deref:Add(Mul(reg:ss,const:16),reg:sp,const:-3)") -> dict[str, object]:
    return {
        "changed": True,
        "status": "changed",
        "mode": "live_out",
        "delta": {
            "segmented_writes": {
                "added": (),
                "removed": (location,),
            }
        },
    }


def test_callee_saved_frame_prune_delta_accepts_exact_closed_evidence() -> None:
    record = CalleeSavedFramePruneRecord8616.closed((_prune_fact(),))

    assert record.closes_evidence is True
    assert callee_saved_frame_prune_delta_8616(record, _validation()) is True


def test_callee_saved_frame_prune_delta_accepts_angr_normalized_stack_store() -> None:
    normalized_fact = replace(
        _prune_fact(),
        carrier_kind=CalleeSavedFrameCarrierKind8616.STACK_SLOT_WRITE,
        stack_displacement=-16,
    )
    record = CalleeSavedFramePruneRecord8616.closed((normalized_fact,))

    assert record.frame_stack_store_evidence == (normalized_fact,)
    assert callee_saved_frame_prune_delta_8616(record, _validation()) is True


@pytest.mark.parametrize(
    ("record", "validation"),
    (
        (None, _validation()),
        (
            replace(CalleeSavedFramePruneRecord8616.closed((_prune_fact(),)), failure_count=1),
            _validation(),
        ),
        (
            CalleeSavedFramePruneRecord8616.closed((_prune_fact(),)),
            _validation("deref:Add(Mul(reg:ss,const:16),reg:sp,const:-4)"),
        ),
        (
            CalleeSavedFramePruneRecord8616.closed((_prune_fact(),)),
            _validation("deref:Add(Mul(reg:ss,const:16),reg:bp,const:-3)"),
        ),
        (
            CalleeSavedFramePruneRecord8616.closed(
                (
                    replace(
                        _prune_fact(),
                        instruction_role=CalleeSavedFrameInstructionRole8616.POP,
                        instruction_addr=0x4030,
                    ),
                )
            ),
            _validation(),
        ),
        (
            CalleeSavedFramePruneRecord8616.closed(
                (
                    replace(
                        _prune_fact(),
                        carrier_kind=CalleeSavedFrameCarrierKind8616.STACK_SLOT_WRITE,
                        stack_displacement=-16,
                        access_width=None,
                    ),
                )
            ),
            _validation(),
        ),
    ),
)
def test_callee_saved_frame_prune_delta_refuses_unproven_changes(
    record: CalleeSavedFramePruneRecord8616 | None,
    validation: dict[str, object],
) -> None:
    assert callee_saved_frame_prune_delta_8616(record, validation) is False


def test_callee_saved_frame_prune_delta_refuses_additions_and_other_fields() -> None:
    record = CalleeSavedFramePruneRecord8616.closed((_prune_fact(),))
    validation = _validation()
    delta = validation["delta"]
    assert isinstance(delta, dict)
    segmented = delta["segmented_writes"]
    assert isinstance(segmented, dict)
    segmented["added"] = ("deref:Add(Mul(reg:ss,const:16),reg:sp,const:-3)",)
    delta["register_writes"] = {"added": (), "removed": ("reg:si",)}

    assert callee_saved_frame_prune_delta_8616(record, validation) is False


def test_lowering_publishes_exact_segmented_frame_prune_record(monkeypatch: pytest.MonkeyPatch) -> None:
    project, codegen = _project_codegen()
    assignment = _segmented_sp_store(project, codegen, ins_addr=0x4014)
    codegen.cfunc.statements.statements.append(assignment)
    monkeypatch.setattr(
        real_mode_linear,
        "_decode_function_insns_8616",
        lambda *_args, **_kwargs: _frame_instructions(),
    )

    assert real_mode_linear.prune_callee_saved_stack_spills_8616(codegen, project) is True
    assert codegen.cfunc.statements.statements == []
    record = codegen._inertia_callee_saved_frame_prune_record_8616
    assert isinstance(record, CalleeSavedFramePruneRecord8616)
    assert record.closes_evidence is True
    assert record.segmented_stack_write_evidence == (_prune_fact(),)


def test_lowering_refuses_later_argument_push_without_publishing_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen = _project_codegen()
    assignment = _segmented_sp_store(project, codegen, ins_addr=0x4020)
    codegen.cfunc.statements.statements.append(assignment)
    monkeypatch.setattr(
        real_mode_linear,
        "_decode_function_insns_8616",
        lambda *_args, **_kwargs: _frame_instructions(argument_push=True),
    )

    assert real_mode_linear.prune_callee_saved_stack_spills_8616(codegen, project) is False
    assert codegen.cfunc.statements.statements == [assignment]
    assert not hasattr(codegen, "_inertia_callee_saved_frame_prune_record_8616")


def test_structuring_consumes_only_exact_frame_prune_delta() -> None:
    project = SimpleNamespace(kb=SimpleNamespace(functions=None))
    record = CalleeSavedFramePruneRecord8616.closed((_prune_fact(),))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_callee_saved_frame_prune_record_8616=record,
    )
    validation = _validation()

    accepted = stage._try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="final",
    )

    assert accepted is True
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation
    assert codegen._inertia_structuring_callee_saved_frame_validation_accepts_8616 == 1
