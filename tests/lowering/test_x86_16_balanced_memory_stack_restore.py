"""Focused tests for exact memory PUSH/POP stack-object rebinding."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.errors import SimEngineError
from angr.sim_type import SimTypeChar
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
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

from inertia.lowering.balanced_memory_stack_restore import (
    _balanced_immediate_register_transfers_8616,
    _balanced_pairs_8616,
    materialize_balanced_immediate_register_restores_8616,
    rebind_balanced_memory_stack_restores_8616,
)
from inertia.lowering.gp_register_state import runtime_gp_name_for_variable_8616


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


@pytest.mark.parametrize("immediate", [False, True])
@pytest.mark.parametrize("unknown_address", [False, True])
def test_unmatched_pop_preserves_independent_pairing_windows(immediate, unknown_address) -> None:
    """A reset POP cannot erase closed windows or pair across a branch."""
    def push(address):
        if not immediate:
            return _instruction(address, X86_INS_PUSH, displacement=0x42)
        return SimpleNamespace(address=address, id=X86_INS_PUSH, groups=(),
                               operands=(SimpleNamespace(type=X86_OP_IMM, size=2, imm=7),))

    def pop(address):
        if not immediate:
            return _instruction(address, X86_INS_POP, displacement=0x42)
        return SimpleNamespace(address=address, id=X86_INS_POP, groups=(),
                               operands=(SimpleNamespace(type=X86_OP_REG, size=2, reg=7),),
                               reg_name=lambda _: "si")

    branch = _instruction(0x120, 0)
    branch.groups = (X86_GRP_JUMP,)
    rows = [push(0x100), pop(0x108), push(0x110), branch, pop(0x128),
            push(0x130), pop(0x138), pop(0x140)]
    # An unknown operand still occupies its LIFO slot and cannot acquire a pair.
    rows.extend((_instruction(0x148, X86_INS_PUSH), pop(0x150)))
    if unknown_address:
        rows.append(_instruction(None, X86_INS_POP))
    if immediate:
        result = tuple((pair.push_addr, pair.pop_addr)
                       for pair in _balanced_immediate_register_transfers_8616(rows))
    else:
        result = tuple((start, end) for start, end, _ in _balanced_pairs_8616(rows))
    assert result == (() if unknown_address else ((0x100, 0x108), (0x130, 0x138)))


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


@pytest.mark.parametrize("shared_storage", [False, True])
def test_word_recomposition_rebind_preserves_original_byte_identity(shared_storage: bool) -> None:
    """Widening a shared PUSH carrier must not invalidate its POP match."""
    from angr.sim_type import SimTypeShort

    from inertia.lowering.balanced_memory_stack_restore import _rebind_pair_8616
    from inertia.lowering.semantic_cast import CSemanticCast8616
    from inertia.lowering.stack_word_recomposition import recognize_stack_word_recomposition_8616

    codegen = _Codegen(project=SimpleNamespace(arch=ArchX86()))
    pushed = _stack_variable(codegen, -4, "saved")
    popped = pushed if shared_storage else _stack_variable(codegen, -8, "read")
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    def constant(value: int) -> structured_c.CConstant:
        return structured_c.CConstant(value, word, codegen=codegen)

    def cast_word(value: structured_c.CExpression) -> CSemanticCast8616:
        return CSemanticCast8616(None, word, value, codegen=codegen)
    ss_offset, ss_size = codegen.project.arch.registers["ss"]
    ss = structured_c.CVariable(SimRegisterVariable(ss_offset, ss_size), codegen=codegen)
    address = structured_c.CBinaryOp(
        "Add", structured_c.CBinaryOp("Shl", ss, constant(4), codegen=codegen),
        structured_c.CBinaryOp("Add", structured_c.CUnaryOp("Reference", popped, codegen=codegen),
                              constant(1), codegen=codegen), codegen=codegen)
    high = structured_c.CUnaryOp("Dereference", address, codegen=codegen)
    expression = structured_c.CBinaryOp("Or", popped, cast_word(structured_c.CBinaryOp(
        "Shl", cast_word(high), constant(8), codegen=codegen)), codegen=codegen)
    assert recognize_stack_word_recomposition_8616(expression) is not None
    push = structured_c.CAssignment(pushed, constant(9), tags={"ins_addr": 0x100}, codegen=codegen)
    cx_offset, cx_size = codegen.project.arch.registers["cx"]
    pop = structured_c.CAssignment(
        structured_c.CVariable(SimRegisterVariable(cx_offset, cx_size), codegen=codegen),
        expression, tags={"ins_addr": 0x108}, codegen=codegen)
    root = structured_c.CStatements([push, pop], codegen=codegen)
    _rebind_pair_8616(project=None, function=object(), statements=(push, pop),
                     push_addr=0x100, pop_addr=0x108, pair_width=2, root=root)
    assert isinstance(pop.rhs, structured_c.CVariable)
    assert pop.rhs.variable is pushed.variable
    assert pop.rhs.variable.size == 2
