from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements, CVariable
from angr.sim_type import SimTypeChar
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    DirectStackUpdateOp8616,
    materialize_direct_stack_incdec_instructions_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_SHL,
    X86_INS_SHR,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_CL,
    X86_REG_INVALID,
)


class _DummyCodegen:
    def __init__(self, project: SimpleNamespace) -> None:
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


def _project() -> tuple[SimpleNamespace, _DummyCodegen]:
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _DummyCodegen(project)
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


def _register_operand(register: int, *, size: int = 1) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_REG, size=size, reg=register)


def _immediate_operand(value: int, *, size: int = 1) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_IMM, size=size, imm=value)


def _bp_memory_operand(offset: int, *, size: int = 1) -> SimpleNamespace:
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=size,
        mem=SimpleNamespace(base=X86_REG_BP, index=X86_REG_INVALID, disp=offset),
    )


def _stack_cvar(codegen: _DummyCodegen, offset: int, name: str) -> CVariable:
    variable = SimStackVariable(offset, 1, base="bp", name=name, region=0x4010)
    cvar = CVariable(variable, variable_type=SimTypeChar(False), codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.unified_local_vars[variable] = {(cvar, SimTypeChar(False))}
    return cvar


def test_direct_stack_shift_collapses_duplicate_tagged_assignments() -> None:
    project, codegen = _project()
    value = _stack_cvar(codegen, -2, "value")
    wrong = CAssignment(
        value,
        CConstant(99, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4012},
    )
    duplicate = CAssignment(
        value,
        CBinaryOp(
            "Shl",
            value,
            CConstant(5, SimTypeChar(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4012},
    )
    codegen.cfunc.statements.statements.extend((wrong, duplicate))
    load_count = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_register_operand(X86_REG_CL), _immediate_operand(5)),
    )
    shift = SimpleNamespace(
        address=0x4012,
        id=X86_INS_SHL,
        operands=(_bp_memory_operand(-2), _register_operand(X86_REG_CL)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load_count, shift))),),
    )

    changed = materialize_direct_stack_incdec_instructions_8616(
        codegen, project=project, function=function
    )

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Shl"
    assert assignment.rhs.lhs is value
    assert assignment.rhs.rhs.value == 5
    evidence = dict(codegen._inertia_direct_stack_update_evidence_8616[0])
    assert evidence["operation"] is DirectStackUpdateOp8616.SHIFT_LEFT


def test_direct_stack_shift_masks_stack_derived_count() -> None:
    project, codegen = _project()
    count = _stack_cvar(codegen, -2, "count")
    value = _stack_cvar(codegen, -4, "value")
    wrong = CAssignment(
        value,
        CConstant(99, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4013},
    )
    codegen.cfunc.statements.statements.append(wrong)
    load_count = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(_register_operand(X86_REG_CL), _bp_memory_operand(-2)),
    )
    shift = SimpleNamespace(
        address=0x4013,
        id=X86_INS_SHR,
        operands=(_bp_memory_operand(-4), _register_operand(X86_REG_CL)),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load_count, shift))),),
    )

    changed = materialize_direct_stack_incdec_instructions_8616(
        codegen, project=project, function=function
    )

    assert changed is True
    assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Shr"
    assert assignment.rhs.lhs is value
    assert isinstance(assignment.rhs.rhs, CBinaryOp)
    assert assignment.rhs.rhs.op == "And"
    assert assignment.rhs.rhs.lhs is count
    assert assignment.rhs.rhs.rhs.value == 0x1F
    evidence = dict(codegen._inertia_direct_stack_update_evidence_8616[0])
    assert evidence["operation"] is DirectStackUpdateOp8616.SHIFT_RIGHT
