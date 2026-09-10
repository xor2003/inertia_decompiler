"""A later machine reload must not overwrite an earlier register consumer."""

from types import SimpleNamespace
from typing import Protocol, cast

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CStatements,
    CSwitchCase,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.lowering.real_mode_linear import (
    materialize_direct_stack_mov_instructions_8616,
)
from angr_platforms.X86_16.lowering.register_reload_consumers import instruction_local_register_read_8616
from capstone.x86 import X86_INS_MOV, X86_REG_AX
from test_x86_16_segmented_runtime_lowering import (
    _bp_mem_operand,
    _imm_operand,
    _reg,
    _reg_operand,
)
from test_x86_16_segmented_runtime_lowering import (
    _project as _fixture_project,
)

RELOAD_ADDRESS = 0x4020
STORED_VALUE = 7


class _CodegenSurface(Protocol):
    cfunc: SimpleNamespace


def _project() -> tuple[SimpleNamespace, _CodegenSurface]:
    project, codegen = _fixture_project()
    return project, cast(_CodegenSurface, codegen)


@pytest.mark.parametrize("origin", [RELOAD_ADDRESS, 0x4024, None])
def test_reload_placement_preserves_earlier_register_consumer(origin):
    project, codegen = _project()
    local = SimStackVariable(-2, 2, base="bp", name="counter", region=0x4010)
    local_expr = CVariable(local, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[local] = local_expr
    register = _reg(project, "ax", codegen)
    earlier = CExpressionStatement(
        CFunctionCall("sub_2000", None, [register], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    later = CExpressionStatement(
        CFunctionCall("sub_3000", None, [register], codegen=codegen),
        codegen=codegen,
        tags={} if origin is None else {"ins_addr": origin},
    )
    store = CAssignment(
        local_expr, CConstant(STORED_VALUE, SimTypeShort(False), codegen=codegen),
        codegen=codegen, tags={"ins_addr": 0x4018},
    )
    statements = codegen.cfunc.statements.statements
    statements.extend([earlier, store, later])
    instructions = (
        SimpleNamespace(address=0x4018, id=X86_INS_MOV,
                        operands=(_bp_mem_operand(-2), _imm_operand(STORED_VALUE))),
        SimpleNamespace(address=RELOAD_ADDRESS, id=X86_INS_MOV,
                        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2))),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert statements[0] is earlier
    assert statements[-1] is later
    if origin != RELOAD_ADDRESS:
        assert statements == [earlier, store, later]
        return
    reload = statements[-2]
    assert isinstance(reload, CAssignment)
    assert reload.lhs.variable is register.variable
    assert isinstance(reload.rhs, CConstant)
    assert reload.rhs.value == STORED_VALUE


@pytest.mark.parametrize("header_reads_register", [False, True])
def test_reload_does_not_borrow_a_register_identity_from_loop_body(header_reads_register):
    project, codegen = _project()
    word = SimTypeShort(False)
    local = SimStackVariable(-2, 2, base="bp", name="counter", region=0x4010)
    source = CVariable(local, variable_type=word, codegen=codegen)
    codegen.cfunc.variables_in_use[local] = source
    header_register = CVariable(
        SimRegisterVariable(0, 2, ident="header", region=0x4010),
        variable_type=word, vvar_id=1, codegen=codegen,
    )
    body_register = CVariable(
        SimRegisterVariable(0, 2, ident="body", region=0x4010),
        variable_type=word, vvar_id=2, codegen=codegen,
    )
    condition = header_register if header_reads_register else CConstant(1, word, codegen=codegen)
    body_read = CExpressionStatement(
        CFunctionCall("consumer", None, [body_register], codegen=codegen),
        codegen=codegen, tags={"ins_addr": 0x4040},
    )
    loop = CWhileLoop(condition, CStatements([body_read], codegen=codegen),
                      codegen=codegen, tags={"ins_addr": RELOAD_ADDRESS})
    store = CAssignment(source, CConstant(STORED_VALUE, word, codegen=codegen),
                        codegen=codegen, tags={"ins_addr": 0x4018})
    statements = codegen.cfunc.statements.statements
    statements.extend([store, loop])
    instructions = (
        SimpleNamespace(address=0x4018, id=X86_INS_MOV,
                        operands=(_bp_mem_operand(-2), _imm_operand(STORED_VALUE))),
        SimpleNamespace(address=RELOAD_ADDRESS, id=X86_INS_MOV,
                        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2))),
    )
    function = SimpleNamespace(addr=0x4010, blocks=(SimpleNamespace(
        capstone=SimpleNamespace(insns=instructions)),))

    materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert loop.body.statements == [body_read]
    if header_reads_register:
        reload = statements[-2]
        assert isinstance(reload, CAssignment)
        assert reload.lhs.variable is header_register.variable
    else:
        assert statements == [store, loop]


@pytest.mark.parametrize("switch", [False, True])
@pytest.mark.parametrize("header_read", [False, True])
def test_branch_bodies_cannot_supply_the_header_register(switch, header_read):
    project, codegen = _project()
    register = _reg(project, "ax", codegen)
    header = register if header_read else CConstant(1, SimTypeShort(False), codegen=codegen)
    body = CStatements([CExpressionStatement(
        CFunctionCall("consumer", None, [register], codegen=codegen), codegen=codegen,
    )], codegen=codegen)
    statement = (
        CSwitchCase(header, [(1, body)], None, codegen=codegen) if switch
        else CIfElse([(header, body)], None, codegen=codegen)
    )

    assert instruction_local_register_read_8616(statement, "ax", 2) is (register if header_read else None)


@pytest.mark.parametrize("distinct_identity", [False, True])
def test_multiple_reads_require_one_exact_identity(distinct_identity):
    project, codegen = _project()
    register = _reg(project, "ax", codegen)
    other = _reg(project, "ax", codegen) if distinct_identity else register
    expression = CBinaryOp("Add", register, other, codegen=codegen)

    assert instruction_local_register_read_8616(expression, "ax", 2) is (None if distinct_identity else register)


@pytest.mark.parametrize("read_width", [1, 2, 4])
def test_reload_requires_the_exact_register_view_width(read_width):
    _project_value, codegen = _project()
    word_width = 2
    register = CVariable(SimRegisterVariable(0, read_width), codegen=codegen)

    selected = instruction_local_register_read_8616(register, "ax", word_width)

    assert selected is (register if read_width == word_width else None)
