from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.interrupt_contract import interrupt_core_addr_8616
from inertia.ir.core import (
    IRBinaryValue,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from inertia.lowering.gp_register_state import runtime_gp_state_expr_8616
from inertia.lowering.software_interrupt_calls import (
    materialize_software_interrupt_calls_8616,
)
from inertia.lowering.software_interrupt_status_outputs import (
    SoftwareInterruptStatusOutputStats8616,
    materialize_software_interrupt_status_outputs_8616,
)
from inertia.pipeline.errors import PipelineHardError

from inertia.semantics.software_interrupt_inputs import (
    SoftwareInterruptInputArtifact8616,
    SoftwareInterruptInputFact8616,
    SoftwareInterruptInputStats8616,
    build_software_interrupt_input_artifact_8616,
    software_interrupt_value_fingerprint_8616,
)
from inertia.structuring.return_chains import (
    TerminalCallResultReturnCallbacks8616,
)
from inertia.structuring.software_interrupt_returns import (
    SoftwareInterruptResultStatus8616,
    materialize_software_interrupt_terminal_results_8616,
)
from inertia.validation.validation_interrupt_calls import (
    SoftwareInterruptValidationIssueKind8616,
    validate_software_interrupt_inputs_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _Insn:
    def __init__(
        self,
        address: int,
        mnemonic: str,
        operands: tuple[object, ...] = (),
        *,
        size: int = 1,
    ) -> None:
        self.address = address
        self.mnemonic = mnemonic
        self.operands = operands
        self.size = size

    def reg_name(self, reg: int) -> str:
        return {1: "ax", 2: "sp", 3: "bp"}.get(reg, "")


def _imm(value: int) -> object:
    return SimpleNamespace(type=2, imm=value)


def _reg(value: int) -> object:
    return SimpleNamespace(type=1, reg=value)


def _block(*insns: _Insn) -> object:
    return SimpleNamespace(capstone=SimpleNamespace(insns=insns))


def _callbacks(
    blocks: dict[int, object],
    ranges: tuple[tuple[int, int], ...],
    successors: dict[int, tuple[int, ...]],
) -> TerminalCallResultReturnCallbacks8616:
    return TerminalCallResultReturnCallbacks8616(
        iter_c_nodes_deep=lambda root: (root,),
        function_block_ranges=lambda: ranges,
        load_block=lambda addr, _size: blocks.get(addr),
        successor_addrs=lambda addr: successors.get(addr, ()),
        branch_target_imm=lambda insn: (
            int(insn.operands[0].imm) if insn.operands else None
        ),
    )


def _const(value: int, codegen: _Codegen) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def _interrupt_ir() -> IRFunctionArtifact:
    ax = IRValue(MemSpace.REG, name="ax", size=2)
    cx = IRValue(MemSpace.REG, name="cx", size=2)
    dx = IRValue(MemSpace.REG, name="dx", size=2)
    x = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    y = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    one = IRValue(MemSpace.CONST, const=1, size=2)
    return IRFunctionArtifact(
        function_addr=0x100,
        blocks=(
            IRBlock(
                addr=0x100,
                instrs=(
                    IRInstr("MOV", ax, (IRValue(MemSpace.CONST, const=4, size=2),), size=2, addr=0x100),
                    IRInstr("MOV", cx, (IRBinaryValue("Shl", x, one, size=2),), size=2, addr=0x102),
                    IRInstr("MOV", dx, (y,), size=2, addr=0x104),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=interrupt_core_addr_8616(0x33), size=2),),
                        size=2,
                        addr=0x106,
                    ),
                ),
            ),
        ),
    )


def _constant_fact() -> SoftwareInterruptInputFact8616:
    return SoftwareInterruptInputFact8616(
        callsite_addr=0x104,
        target_addr=interrupt_core_addr_8616(0x33),
        vector=0x33,
        selector_value=4,
        argument_registers=("ax", "cx", "dx"),
        argument_values=tuple(
            IRValue(MemSpace.CONST, const=value, size=2) for value in (4, 5, 6)
        ),
        result_register="ax",
    )


def _artifact(fact: SoftwareInterruptInputFact8616) -> SoftwareInterruptInputArtifact8616:
    return SoftwareInterruptInputArtifact8616(
        facts=(fact,),
        stats=SoftwareInterruptInputStats8616(1, 1, 1, 1, 0),
    )


def _stale_result_ast(
    codegen: _Codegen,
    fact: SoftwareInterruptInputFact8616,
) -> tuple[
    structured_c.CStatements,
    structured_c.CStatements,
    structured_c.CStatements,
    structured_c.CFunctionCall,
]:
    call = structured_c.CFunctionCall(
        "interrupt_int33",
        None,
        [_const(value, codegen) for value in (4, 5, 6)],
        tags={"ins_addr": fact.callsite_addr},
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call_container = structured_c.CStatements(
        statements=[
            structured_c.CExpressionStatement(_const(1, codegen), codegen=codegen),
            structured_c.CAssignment(carrier, call, codegen=codegen),
        ],
        codegen=codegen,
    )
    return_container = structured_c.CStatements(
        statements=[
            structured_c.CExpressionStatement(_const(2, codegen), codegen=codegen),
            structured_c.CReturn(
                _const(fact.selector_value, codegen),
                tags={"ins_addr": 0x108},
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements(
        statements=[call_container, return_container],
        codegen=codegen,
    )
    return root, call_container, return_container, call


def test_semantics_recovers_mouse_interrupt_inputs_and_ax_result() -> None:
    artifact = build_software_interrupt_input_artifact_8616(_interrupt_ir())

    assert artifact.stats == SoftwareInterruptInputStats8616(1, 1, 1, 1, 0)
    assert len(artifact.facts) == 1
    fact = artifact.facts[0]
    assert fact.result_register == "ax"
    assert tuple(
        software_interrupt_value_fingerprint_8616(value)
        for value in fact.argument_values
    ) == (
        "const:0x4:size2",
        "Shl(stack:SS:BP+0x4:size2,const:0x1:size2):size2",
        "stack:SS:BP+0x6:size2",
    )


def test_semantics_recovers_dos_allocate_paragraph_count_after_increment() -> None:
    ah = IRValue(MemSpace.REG, name="ah", size=1)
    bx = IRValue(MemSpace.REG, name="bx", size=2)
    incremented = IRValue(MemSpace.TMP, name="t0", size=2, source_tmp=0)
    artifact = IRFunctionArtifact(
        function_addr=0x200,
        blocks=(
            IRBlock(
                addr=0x200,
                instrs=(
                    IRInstr(
                        "Iop_Add16",
                        incremented,
                        (bx, IRValue(MemSpace.CONST, const=1, size=2)),
                        size=2,
                        addr=0x200,
                    ),
                    IRInstr("MOV", bx, (incremented,), size=2, addr=0x200),
                    IRInstr(
                        "MOV",
                        ah,
                        (IRValue(MemSpace.CONST, const=0x48, size=1),),
                        size=1,
                        addr=0x202,
                    ),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=interrupt_core_addr_8616(0x21), size=2),),
                        size=2,
                        addr=0x204,
                    ),
                ),
            ),
        ),
    )

    recovered = build_software_interrupt_input_artifact_8616(artifact)

    assert recovered.stats == SoftwareInterruptInputStats8616(1, 1, 1, 1, 0)
    assert recovered.facts[0].argument_registers == ("bx",)
    assert recovered.facts[0].result_register == "ax"
    assert software_interrupt_value_fingerprint_8616(recovered.facts[0].argument_values[0]) == (
        "Add(reg:bx:size2,const:0x1:size2):size2"
    )


def test_semantics_preserves_untouched_dos_allocate_input_register() -> None:
    ah = IRValue(MemSpace.REG, name="ah", size=1)
    artifact = IRFunctionArtifact(
        function_addr=0x200,
        blocks=(
            IRBlock(
                addr=0x200,
                instrs=(
                    IRInstr(
                        "MOV",
                        ah,
                        (IRValue(MemSpace.CONST, const=0x48, size=1),),
                        size=1,
                        addr=0x200,
                    ),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=interrupt_core_addr_8616(0x21), size=2),),
                        size=2,
                        addr=0x202,
                    ),
                ),
            ),
        ),
    )

    recovered = build_software_interrupt_input_artifact_8616(artifact)

    assert recovered.stats == SoftwareInterruptInputStats8616(1, 1, 1, 1, 0)
    assert software_interrupt_value_fingerprint_8616(recovered.facts[0].argument_values[0]) == "reg:bx:size2"


def test_semantics_refuses_explicitly_unresolved_dos_allocate_input_register() -> None:
    ah = IRValue(MemSpace.REG, name="ah", size=1)
    bx = IRValue(MemSpace.REG, name="bx", size=2)
    artifact = IRFunctionArtifact(
        function_addr=0x200,
        blocks=(
            IRBlock(
                addr=0x200,
                instrs=(
                    IRInstr(
                        "MOV",
                        bx,
                        (IRValue(MemSpace.DS, name="di", size=2),),
                        size=2,
                        addr=0x200,
                    ),
                    IRInstr(
                        "MOV",
                        ah,
                        (IRValue(MemSpace.CONST, const=0x48, size=1),),
                        size=1,
                        addr=0x202,
                    ),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=interrupt_core_addr_8616(0x21), size=2),),
                        size=2,
                        addr=0x204,
                    ),
                ),
            ),
        ),
    )

    recovered = build_software_interrupt_input_artifact_8616(artifact)

    assert recovered.stats == SoftwareInterruptInputStats8616(1, 1, 1, 0, 1)
    assert recovered.facts == ()
    assert recovered.refusals[0][2] == "bx"


def test_lowering_ignores_same_callsite_interrupt_status_helper() -> None:
    codegen = _Codegen()
    ah = IRValue(MemSpace.REG, name="ah", size=1)
    ir_artifact = IRFunctionArtifact(
        function_addr=0x200,
        blocks=(
            IRBlock(
                addr=0x200,
                instrs=(
                    IRInstr(
                        "MOV",
                        ah,
                        (IRValue(MemSpace.CONST, const=0x48, size=1),),
                        size=1,
                        addr=0x200,
                    ),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=interrupt_core_addr_8616(0x21), size=2),),
                        size=2,
                        addr=0x202,
                    ),
                ),
            ),
        ),
    )
    service_call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(0x21),
        None,
        [],
        tags={"ins_addr": 0x202},
        codegen=codegen,
    )
    status_call = structured_c.CFunctionCall(
        "dos_int21_flags",
        None,
        [],
        tags={"ins_addr": 0x202},
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [
            structured_c.CExpressionStatement(service_call, codegen=codegen),
            structured_c.CExpressionStatement(status_call, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x200, statements=root, arg_list=[])
    codegen._inertia_vex_ir_artifact = ir_artifact

    assert materialize_software_interrupt_calls_8616(codegen) is True
    assert materialize_software_interrupt_calls_8616(codegen) is False
    assert len(service_call.args) == 1
    assert status_call.args == []
    assert validate_software_interrupt_inputs_8616(codegen, root).passed

    runtime_bx = runtime_gp_state_expr_8616("bx", codegen=codegen, function_addr=0x200)
    assert runtime_bx is not None
    service_call.args = [runtime_bx]

    assert materialize_software_interrupt_calls_8616(codegen) is False
    assert validate_software_interrupt_inputs_8616(codegen, root).passed


def test_lowering_materializes_all_interrupt_arguments() -> None:
    codegen = _Codegen()
    call = structured_c.CFunctionCall(
        "interrupt_int33",
        None,
        [],
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    root = structured_c.CStatements(
        statements=[structured_c.CExpressionStatement(call, codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root, arg_list=[])
    codegen._inertia_vex_ir_artifact = IRFunctionArtifact(
        function_addr=0x100,
        blocks=(
            IRBlock(
                addr=0x100,
                instrs=tuple(
                    [
                        IRInstr(
                            "MOV",
                            IRValue(MemSpace.REG, name=name, size=2),
                            (IRValue(MemSpace.CONST, const=value, size=2),),
                            size=2,
                            addr=0x100 + index,
                        )
                        for index, (name, value) in enumerate(
                            (("ax", 4), ("cx", 5), ("dx", 6))
                        )
                    ]
                    + [
                        IRInstr(
                            "CALL",
                            None,
                            (IRValue(MemSpace.CONST, const=interrupt_core_addr_8616(0x33), size=2),),
                            size=2,
                            addr=0x106,
                        )
                    ]
                ),
            ),
        ),
    )

    assert materialize_software_interrupt_calls_8616(codegen)
    assert [argument.value for argument in call.args] == [4, 5, 6]


def test_lowering_rematerializes_missing_stack_arguments_from_semantics() -> None:
    codegen = _Codegen()
    call = structured_c.CFunctionCall(
        "interrupt_int33",
        None,
        [],
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    root = structured_c.CStatements(
        statements=[structured_c.CExpressionStatement(call, codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=root, arg_list=[])
    codegen._inertia_vex_ir_artifact = _interrupt_ir()

    assert materialize_software_interrupt_calls_8616(codegen)

    assert call.args[0].value == 4
    assert isinstance(call.args[1], structured_c.CBinaryOp)
    x_variable = call.args[1].lhs.variable
    y_variable = call.args[2].variable
    assert isinstance(x_variable, SimStackVariable)
    assert isinstance(y_variable, SimStackVariable)
    assert (x_variable.base, x_variable.offset, x_variable.name) == ("bp", 4, "arg_4")
    assert (y_variable.base, y_variable.offset, y_variable.name) == ("bp", 6, "arg_6")


def test_structuring_materializes_cross_container_terminal_interrupt_result() -> None:
    codegen = _Codegen()
    fact = _constant_fact()
    codegen._inertia_software_interrupt_input_artifact_8616 = _artifact(fact)
    root, call_container, return_container, call = _stale_result_ast(codegen, fact)
    callbacks = _callbacks(
        {
            0x100: _block(_Insn(0x104, "int", (_imm(0x33),))),
            0x106: _block(_Insn(0x106, "ret")),
        },
        ((0x100, 6), (0x106, 1)),
        {0x100: (0x106,), 0x106: ()},
    )

    assert materialize_software_interrupt_terminal_results_8616(
        root,
        codegen,
        callbacks,
    )
    stats = codegen._inertia_software_interrupt_result_stats_8616
    assert stats.status is SoftwareInterruptResultStatus8616.MATERIALIZED
    assert stats.path_block_addrs == (0x100, 0x106)
    assert len(call_container.statements) == 1
    assert isinstance(return_container.statements[1], structured_c.CReturn)
    assert return_container.statements[1].retval is call


def test_structuring_restores_interrupt_call_sunk_past_condition() -> None:
    """A returned interrupt call is restored before a later carry branch."""
    codegen = _Codegen()
    fact = _constant_fact()
    codegen._inertia_software_interrupt_input_artifact_8616 = _artifact(fact)
    branch = structured_c.CIfElse(
        [(_const(1, codegen), structured_c.CStatements([], codegen=codegen))],
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(fact.vector),
        None,
        [],
        tags={"ins_addr": fact.callsite_addr},
        codegen=codegen,
    )
    stale_pre_call_expression = structured_c.CBinaryOp(
        "Shl",
        call,
        _const(12, codegen),
        tags={"ins_addr": 0x101},
        codegen=codegen,
    )
    returned_call = structured_c.CReturn(
        stale_pre_call_expression,
        tags={"ins_addr": 0x108},
        codegen=codegen,
    )
    branch_container = structured_c.CStatements([branch], codegen=codegen)
    return_container = structured_c.CStatements([returned_call], codegen=codegen)
    root = structured_c.CStatements(
        [branch_container, return_container],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=root)
    callbacks = _callbacks(
        {
            0x100: _block(_Insn(fact.callsite_addr, "int", (_imm(fact.vector),))),
            0x106: _block(_Insn(0x106, "jb", (_imm(0x200),), size=2)),
            0x108: _block(_Insn(0x108, "ret")),
        },
        ((0x100, 6), (0x106, 2), (0x108, 1)),
        {0x100: (0x106,), 0x106: (0x108,), 0x108: ()},
    )

    assert materialize_software_interrupt_terminal_results_8616(
        root,
        codegen,
        callbacks,
    )

    assignment = root.statements[0]
    assert isinstance(assignment, structured_c.CAssignment)
    assert assignment.rhs is call
    assert root.statements[1] is branch_container
    replacement = return_container.statements[0]
    assert isinstance(replacement, structured_c.CReturn)
    assert isinstance(replacement.retval, structured_c.CVariable)
    assert replacement.retval.variable.reg == codegen.project.arch.registers["ax"][0]


def test_structuring_refuses_post_interrupt_ax_clobber() -> None:
    codegen = _Codegen()
    fact = _constant_fact()
    codegen._inertia_software_interrupt_input_artifact_8616 = _artifact(fact)
    root, _call_container, _return_container, _call = _stale_result_ast(codegen, fact)
    callbacks = _callbacks(
        {
            0x100: _block(
                _Insn(0x104, "int", (_imm(0x33),)),
                _Insn(0x106, "mov", (_reg(1), _imm(0))),
                _Insn(0x109, "ret"),
            )
        },
        ((0x100, 10),),
        {0x100: ()},
    )

    with pytest.raises(PipelineHardError, match="interrupt result"):
        materialize_software_interrupt_terminal_results_8616(
            root,
            codegen,
            callbacks,
        )
    assert (
        codegen._inertia_software_interrupt_result_stats_8616.status
        is SoftwareInterruptResultStatus8616.CFG_PROOF_REFUSED
    )


def test_tail_validation_rejects_stale_interrupt_selector_return() -> None:
    codegen = _Codegen()
    fact = _constant_fact()
    codegen._inertia_software_interrupt_input_artifact_8616 = _artifact(fact)
    root, _call_container, _return_container, _call = _stale_result_ast(codegen, fact)

    report = validate_software_interrupt_inputs_8616(codegen, root)

    assert not report.passed
    assert report.materialized_count == 0
    assert tuple(issue.kind for issue in report.issues) == (
        SoftwareInterruptValidationIssueKind8616.STALE_RESULT_SELECTOR,
    )


def test_lowering_materializes_dos_interrupt_carry_output_before_branch() -> None:
    """A DOS carry branch consumes an explicit post-interrupt FLAGS output."""
    codegen = _Codegen()
    flags_offset, flags_size = codegen.project.arch.registers["flags"]
    result = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="result", region=0x100, ident="ax_1"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    flags = structured_c.CDirtyExpression(
        VirtualVariable(
            codegen.next_idx("flags"),
            17,
            flags_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=flags_offset,
        ),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(0x21),
        None,
        [],
        tags={"ins_addr": 0x104},
        codegen=codegen,
    )
    branch = structured_c.CIfElse(
        [
            (
                structured_c.CBinaryOp(
                    "And",
                    flags,
                    _const(1, codegen),
                    tags={"ins_addr": 0x106},
                    codegen=codegen,
                ),
                structured_c.CStatements([], codegen=codegen),
            )
        ],
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [structured_c.CAssignment(result, call, codegen=codegen), branch],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root)

    assert materialize_software_interrupt_status_outputs_8616(codegen) is True

    definition = root.statements[1]
    assert isinstance(definition, structured_c.CAssignment)
    assert isinstance(definition.lhs, structured_c.CVariable)
    assert definition.lhs.variable.reg == flags_offset
    assert definition.rhs.callee_target == "dos_int21_flags"
    assert root.statements[2] is branch
    rewritten_flags = branch.condition_and_nodes[0][0].lhs
    assert isinstance(rewritten_flags, structured_c.CVariable)
    assert rewritten_flags.variable.reg == flags_offset
    assert codegen._inertia_software_interrupt_status_output_stats_8616 == (
        SoftwareInterruptStatusOutputStats8616(1, 1, 1, 1, 0)
    )
    assert materialize_software_interrupt_status_outputs_8616(codegen) is False


def test_lowering_invalidates_pre_interrupt_flags_projection() -> None:
    """A later carry test uses interrupt FLAGS, not an inlined older FLAGS value."""
    codegen = _Codegen()
    flags_offset, _flags_size = codegen.project.arch.registers["flags"]
    flags = structured_c.CVariable(
        SimRegisterVariable(flags_offset, 2, name="flags"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale_flags = structured_c.CBinaryOp(
        "Or",
        structured_c.CBinaryOp(
            "And",
            flags,
            _const(0xF72A, codegen),
            tags={"ins_addr": 0x102},
            codegen=codegen,
        ),
        _const(0x8D4, codegen),
        tags={"ins_addr": 0x102},
        codegen=codegen,
    )
    condition = structured_c.CBinaryOp(
        "And",
        stale_flags,
        _const(1, codegen),
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(0x21),
        None,
        [],
        tags={"ins_addr": 0x104},
        codegen=codegen,
    )
    branch = structured_c.CIfElse(
        [(condition, structured_c.CStatements([], codegen=codegen))],
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    root = structured_c.CStatements([call, branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert materialize_software_interrupt_status_outputs_8616(codegen) is True

    assert isinstance(condition.lhs, structured_c.CVariable)
    assert condition.lhs.variable.reg == flags_offset
    assert condition.rhs.value == 1


def test_status_output_lowering_ignores_non_register_dirty_expression() -> None:
    """A legal non-register angr dirty payload is not a FLAGS carrier."""
    codegen = _Codegen()
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(name="non_register_expression"),
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [structured_c.CExpressionStatement(dirty, codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root)

    assert materialize_software_interrupt_status_outputs_8616(codegen) is False


def test_lowering_coalesces_cloned_reads_of_one_flags_register() -> None:
    """Cloned boolean uses still consume one physical interrupt status output."""
    codegen = _Codegen()
    flags_offset, flags_size = codegen.project.arch.registers["flags"]

    def flags_read() -> structured_c.CDirtyExpression:
        """Build one structured clone of the same physical FLAGS register."""
        return structured_c.CDirtyExpression(
            VirtualVariable(
                codegen.next_idx("flags"),
                17,
                flags_size * 8,
                VirtualVariableCategory.REGISTER,
                oident=flags_offset,
            ),
            codegen=codegen,
        )

    call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(0x21),
        None,
        [],
        tags={"ins_addr": 0x104},
        codegen=codegen,
    )
    condition = structured_c.CBinaryOp(
        "LogicalOr",
        structured_c.CBinaryOp("And", flags_read(), _const(1, codegen), codegen=codegen),
        structured_c.CBinaryOp("And", flags_read(), _const(0x40, codegen), codegen=codegen),
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    branch = structured_c.CIfElse(
        [(condition, structured_c.CStatements([], codegen=codegen))],
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    root = structured_c.CStatements([call, branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    assert materialize_software_interrupt_status_outputs_8616(codegen) is True
    definition = root.statements[1]
    assert isinstance(definition, structured_c.CAssignment)
    assert isinstance(definition.lhs, structured_c.CVariable)
    assert definition.lhs.variable.reg == flags_offset
    assert definition.rhs.callee_target == "dos_int21_flags"
    assert codegen._inertia_software_interrupt_status_output_stats_8616 == (
        SoftwareInterruptStatusOutputStats8616(1, 1, 1, 1, 0)
    )


def test_lowering_canonicalizes_dirty_flags_after_untagged_nested_interrupt() -> None:
    """A nested call owner supplies provenance and a renderable FLAGS carrier."""
    codegen = _Codegen()
    flags_offset, flags_size = codegen.project.arch.registers["flags"]
    result = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="result", region=0x100, ident="ax_1"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        interrupt_core_addr_8616(0x21),
        None,
        [],
        codegen=codegen,
    )
    call_statement = structured_c.CAssignment(
        result,
        call,
        tags={"ins_addr": 0x104},
        codegen=codegen,
    )
    dirty_flags = structured_c.CDirtyExpression(
        VirtualVariable(
            codegen.next_idx("flags"),
            17,
            flags_size * 8,
            VirtualVariableCategory.REGISTER,
            oident=flags_offset,
        ),
        codegen=codegen,
    )
    condition = structured_c.CBinaryOp(
        "And",
        dirty_flags,
        _const(1, codegen),
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    branch = structured_c.CIfElse(
        [(condition, structured_c.CStatements([], codegen=codegen))],
        tags={"ins_addr": 0x106},
        codegen=codegen,
    )
    call_container = structured_c.CStatements([call_statement], codegen=codegen)
    branch_container = structured_c.CStatements([branch], codegen=codegen)
    root = structured_c.CStatements(
        [call_container, branch_container],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root)

    assert materialize_software_interrupt_status_outputs_8616(codegen) is True

    definition = root.statements[1]
    assert isinstance(definition, structured_c.CAssignment)
    assert definition.tags["ins_addr"] == 0x104
    assert isinstance(definition.lhs, structured_c.CVariable)
    assert definition.lhs.variable.reg == flags_offset
    rewritten_branch = branch_container.statements[0]
    assert isinstance(rewritten_branch, structured_c.CIfElse)
    rewritten_condition = rewritten_branch.condition_and_nodes[0][0]
    assert isinstance(rewritten_condition, structured_c.CBinaryOp)
    assert isinstance(rewritten_condition.lhs, structured_c.CVariable)
    assert rewritten_condition.lhs.variable.reg == flags_offset
    assert definition.rhs.callee_target == "dos_int21_flags"
