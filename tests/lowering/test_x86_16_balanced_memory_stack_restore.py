"""Focused tests for exact memory PUSH/POP stack-object rebinding."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.errors import SimEngineError
from angr.sim_type import SimTypeChar
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.lowering.balanced_memory_stack_restore import (
    materialize_balanced_immediate_register_restores_8616,
    rebind_balanced_memory_stack_restores_8616,
)
from inertia.lowering.gp_register_state import runtime_gp_name_for_variable_8616
from archinfo import ArchX86
from capstone.x86_const import (
    X86_GRP_JUMP,
    X86_INS_CALL,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
)


class _Codegen(SimpleNamespace):
    """Minimal structured-codegen identity allocator."""

    _next_index = 0
    cstyle_null_cmp = False

    def next_node_idx(self) -> int:
        """Return one deterministic node identity."""
        self._next_index += 1
        return self._next_index

    def next_ident(self, name: str) -> str:
        """Return one deterministic display identity."""
        return name


def _instruction(address: int, instruction_id: int, *, displacement: int | None = None) -> SimpleNamespace:
    operand = (
        SimpleNamespace(
            type=X86_OP_MEM,
            size=2,
            mem=SimpleNamespace(segment=0, base=0, index=0, scale=1, disp=displacement),
        )
        if displacement is not None
        else None
    )
    return SimpleNamespace(
        address=address,
        id=instruction_id,
        operands=() if operand is None else (operand,),
        groups=(),
    )


def _stack_variable(codegen: _Codegen, offset: int, name: str) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimStackVariable(offset, 1, base="bp", name=name, region=0x1000),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )


def _memory_variable(codegen: _Codegen) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimMemoryVariable(0x42, 1, name="g_0042"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )


def test_materializes_immediate_push_register_pop_across_neutral_call() -> None:
    """A caller cleanup POP retains its exact pushed selector value."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    si_offset, si_size = codegen.project.arch.registers["si"]
    sp_offset, sp_size = codegen.project.arch.registers["sp"]
    marker = structured_c.CAssignment(
        structured_c.CVariable(
            SimRegisterVariable(sp_offset, sp_size, name="sp"),
            codegen=codegen,
        ),
        structured_c.CConstant(0, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    si_read = structured_c.CBinaryOp(
        "Add",
        structured_c.CVariable(
            SimRegisterVariable(si_offset, si_size, name="si"),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([marker, si_read], codegen=codegen),
    )
    push_operand = SimpleNamespace(type=X86_OP_IMM, size=2, imm=2)
    pop_operand = SimpleNamespace(type=X86_OP_REG, size=2, reg=7)
    instructions = (
        SimpleNamespace(address=0x100, id=X86_INS_PUSH, operands=(push_operand,), groups=()),
        _instruction(0x103, X86_INS_CALL),
        SimpleNamespace(
            address=0x108,
            id=X86_INS_POP,
            operands=(pop_operand,),
            groups=(),
            reg_name=lambda register_id: "si" if register_id == 7 else "",
        ),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),)
    )

    assert materialize_balanced_immediate_register_restores_8616(
        codegen,
        function,
    ) is True
    assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(assignment, structured_c.CAssignment)
    assert runtime_gp_name_for_variable_8616(assignment.lhs.variable) == "esi"
    replacement = codegen.cfunc.statements.statements[2]
    assert isinstance(replacement, structured_c.CBinaryOp)
    assert isinstance(replacement.lhs, structured_c.CBinaryOp)
    assert runtime_gp_name_for_variable_8616(replacement.lhs.lhs.variable) == "esi"
    stats = codegen._inertia_balanced_immediate_register_restore_stats_8616
    assert stats.raw_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0


def test_rebinds_memory_restore_across_caller_neutral_call() -> None:
    """A POP of the same saved memory object reads the PUSH stack carrier."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    pushed = _stack_variable(codegen, -2, "local_2")
    popped = _stack_variable(codegen, -4, "local_4")
    push_assignment = structured_c.CAssignment(
        pushed,
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        popped,
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([push_assignment, pop_assignment], codegen=codegen)
    )
    instructions = (
        _instruction(0x100, X86_INS_PUSH, displacement=0x42),
        _instruction(0x103, X86_INS_CALL),
        _instruction(0x108, X86_INS_POP, displacement=0x42),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),)
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is True
    assert isinstance(pop_assignment.rhs, structured_c.CVariable)
    assert pop_assignment.rhs.variable.offset == -2
    assert pop_assignment.rhs.variable.name == "local_2"


def test_rebinds_lifo_register_restores_across_neutral_calls() -> None:
    """Register saves keep their PUSH-owned stack slots across nested calls."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    bx_save = _stack_variable(codegen, -2, "saved_bx")
    ax_save = _stack_variable(codegen, -4, "saved_ax")
    shifted_ax_read = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="shifted_ax", region=0x1000),
        codegen=codegen,
    )
    shifted_bx_read = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="shifted_bx", region=0x1000),
        codegen=codegen,
    )
    push_bx = structured_c.CAssignment(
        bx_save,
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    push_bx_high = structured_c.CAssignment(
        _stack_variable(codegen, 0, "saved_bx_high"),
        structured_c.CConstant(0, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    push_ax = structured_c.CAssignment(
        ax_save,
        structured_c.CConstant(2, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x101},
    )
    pop_dx = structured_c.CAssignment(
        _memory_variable(codegen),
        shifted_ax_read,
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    pop_ax = structured_c.CAssignment(
        _memory_variable(codegen),
        shifted_bx_read,
        codegen=codegen,
        tags={"ins_addr": 0x109},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [push_bx, push_bx_high, push_ax, pop_dx, pop_ax],
            codegen=codegen,
        )
    )

    def register_instruction(address: int, instruction_id: int, register: int) -> SimpleNamespace:
        return SimpleNamespace(
            address=address,
            id=instruction_id,
            operands=(SimpleNamespace(type=X86_OP_REG, size=2, reg=register),),
            groups=(),
        )

    instructions = (
        register_instruction(0x100, X86_INS_PUSH, 1),
        register_instruction(0x101, X86_INS_PUSH, 2),
        _instruction(0x103, X86_INS_CALL),
        _instruction(0x106, X86_INS_CALL),
        register_instruction(0x108, X86_INS_POP, 3),
        register_instruction(0x109, X86_INS_POP, 4),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),)
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is True
    assert isinstance(pop_dx.rhs, structured_c.CVariable)
    assert isinstance(pop_ax.rhs, structured_c.CVariable)
    assert pop_dx.rhs.variable.name == "saved_ax"
    assert pop_dx.rhs.variable.offset == -4
    assert pop_dx.rhs.variable.size == 2
    assert pop_ax.rhs.variable.name == "saved_bx"
    assert pop_ax.rhs.variable.offset == -2
    assert pop_ax.rhs.variable.size == 2


def test_refuses_mismatched_memory_restore() -> None:
    """Different PUSH/POP memory operands do not establish save ownership."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    push_assignment = structured_c.CAssignment(
        _stack_variable(codegen, -2, "local_2"),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        _stack_variable(codegen, -4, "local_4"),
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([push_assignment, pop_assignment], codegen=codegen)
    )
    instructions = (
        _instruction(0x100, X86_INS_PUSH, displacement=0x42),
        _instruction(0x108, X86_INS_POP, displacement=0x44),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),)
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is False
    assert pop_assignment.rhs.variable.offset == -4


def test_branch_ends_only_current_pairing_window() -> None:
    """An earlier branch does not hide a later straight-line save/restore pair."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    push_assignment = structured_c.CAssignment(
        _stack_variable(codegen, -2, "local_2"),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x110},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        _stack_variable(codegen, -4, "local_4"),
        codegen=codegen,
        tags={"ins_addr": 0x118},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([push_assignment, pop_assignment], codegen=codegen)
    )
    branch = _instruction(0x108, 0)
    branch.groups = (X86_GRP_JUMP,)
    instructions = (
        _instruction(0x100, X86_INS_PUSH, displacement=0x30),
        branch,
        _instruction(0x110, X86_INS_PUSH, displacement=0x42),
        _instruction(0x113, X86_INS_CALL),
        _instruction(0x118, X86_INS_POP, displacement=0x42),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),)
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is True
    assert pop_assignment.rhs.variable.offset == -2


def test_accepts_semantically_identical_overlapping_block_decode() -> None:
    """Duplicate wrappers from overlapping angr blocks retain one exact pair."""
    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    push_assignment = structured_c.CAssignment(
        _stack_variable(codegen, -2, "local_2"),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        _stack_variable(codegen, -4, "local_4"),
        codegen=codegen,
        tags={"ins_addr": 0x108},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([push_assignment, pop_assignment], codegen=codegen)
    )
    first = (
        _instruction(0x100, X86_INS_PUSH, displacement=0x42),
        _instruction(0x108, X86_INS_POP, displacement=0x42),
    )
    duplicate = tuple(
        _instruction(instruction.address, instruction.id, displacement=0x42)
        for instruction in first
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(capstone=SimpleNamespace(insns=first)),
            SimpleNamespace(capstone=SimpleNamespace(insns=duplicate)),
        )
    )

    assert rebind_balanced_memory_stack_restores_8616(codegen, function) is True
    assert pop_assignment.rhs.variable.offset == -2


def test_rebased_decode_skips_unmapped_original_candidate() -> None:
    """Original AST tags map to slice bytes after an unmapped candidate refusal."""
    delta = 0x10000
    push = _instruction(0x100, X86_INS_PUSH, displacement=0x42)
    pop = _instruction(0x108, X86_INS_POP, displacement=0x42)
    decoded = {push.address: push, pop.address: pop}

    class _Factory:
        def block(self, address: int, *, num_inst: int, opt_level: int) -> SimpleNamespace:
            assert num_inst == 1
            assert opt_level == 0
            instruction = decoded.get(address)
            if instruction is None:
                raise SimEngineError(f"no bytes at {address:#x}")
            wrapper = SimpleNamespace(insn=instruction)
            return SimpleNamespace(capstone=SimpleNamespace(insns=(wrapper,)))

    project = SimpleNamespace(
        arch=ArchX86(),
        factory=_Factory(),
        _inertia_original_linear_delta=delta,
    )
    codegen = _Codegen(project=project)
    pushed = _stack_variable(codegen, -2, "local_2")
    popped = _stack_variable(codegen, -4, "local_4")
    push_assignment = structured_c.CAssignment(
        pushed,
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": push.address + delta},
    )
    pop_assignment = structured_c.CAssignment(
        _memory_variable(codegen),
        popped,
        codegen=codegen,
        tags={"ins_addr": pop.address + delta},
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [push_assignment, pop_assignment],
            codegen=codegen,
        )
    )
    function = SimpleNamespace(blocks=())

    assert rebind_balanced_memory_stack_restores_8616(
        codegen,
        function,
        project=project,
    ) is True
    assert pop_assignment.rhs.variable.offset == -2
