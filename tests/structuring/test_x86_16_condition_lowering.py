from __future__ import annotations

from types import SimpleNamespace

import capstone
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable

import inertia.semantics.register_source_block_inventory as register_inventory_owner
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import (
    SEGMENTED_LOAD_ADDRESS_TAG_8616,
    IRCondition,
    IRValue,
    MemSpace,
)
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.semantics.register_source_block_inventory import (
    RegisterSourceBlockEvidence8616,
    RegisterSourceBlockInventory8616,
)
from inertia.structuring.condition_lowering import (
    condition_origin_tags_8616,
    lower_ir_value_to_c_expr_8616,
    materialize_reaching_register_projection_8616,
)
from inertia.structuring.condition_materialization import (
    materialize_condition_ir_expression_8616,
)

INDEXED_DATA_OFFSET = 0xB4C

class _Codegen:
    def __init__(self, project):
        self._next_idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name):
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_condition_origin_tags_preserve_branch_provenance():
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.SS, name="bp", offset=4, size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x100F,
        block_addr=0x1009,
        producer_insn=0x100B,
    )

    assert condition_origin_tags_8616(condition) == {
        "typed_condition": True,
        "ins_addr": 0x100F,
        "vex_block_addr": 0x1009,
        "condition_producer_insn": 0x100B,
    }


def test_condition_origin_tags_keep_ircondition_fallback_minimal():
    condition = IRCondition(
        op="ne",
        args=(
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.CONST, const=0, size=2),
        ),
    )

    assert condition_origin_tags_8616(condition) == {"typed_condition": True}


@pytest.mark.parametrize("load_address", [0x1030, None])
def test_stack_condition_keeps_operand_provenance_distinct_from_branch(load_address):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.SS, name="bp", offset=-2, size=2,
                    memory_access_size=2, memory_access_insn=load_address),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x1043,
        block_addr=0x1030,
        producer_insn=0x1040,
    )
    expression = materialize_condition_ir_expression_8616(project, codegen, condition)
    assert expression is not None
    assert expression.tags["ins_addr"] == condition.src_insn
    if load_address is None:
        assert "inertia_source_instruction_addrs" not in expression.lhs.tags
    else:
        assert expression.lhs.tags["inertia_source_instruction_addrs"] == (load_address,)


def test_materialized_segmented_condition_preserves_operand_access_provenance():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    condition = ConditionIR(
        op="sle",
        lhs=IRValue(
            MemSpace.DS,
            offset=0x134,
            size=2,
            memory_access_insn=0x103E,
        ),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x1043,
        block_addr=0x103E,
        producer_insn=0x1040,
    )

    expression = materialize_condition_ir_expression_8616(project, codegen, condition)

    assert expression is not None
    helpers = [
        node
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall)
        and SEGMENTED_LOAD_ADDRESS_TAG_8616 in node.tags
    ]
    assert len(helpers) == 1
    assert helpers[0].tags["inertia_source_instruction_addrs"] == (0x103E,)


@pytest.mark.parametrize("load_address", [0x1030, None])
def test_direct_stack_value_lowering_preserves_only_supplied_provenance(load_address):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    operand = IRValue(MemSpace.SS, name="bp", offset=-2, size=2,
                      memory_access_insn=load_address)
    expression = lower_ir_value_to_c_expr_8616(operand, project, codegen)
    assert expression is not None
    expected = () if load_address is None else (load_address,)
    assert expression.tags.get("inertia_source_instruction_addrs", ()) == expected


def test_materialized_segmented_condition_refuses_branch_only_provenance():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    condition = ConditionIR(
        op="sle",
        lhs=IRValue(MemSpace.DS, offset=0x134, size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x1043,
        block_addr=0x103E,
        producer_insn=0x1040,
    )

    expression = materialize_condition_ir_expression_8616(project, codegen, condition)

    assert expression is not None
    helper = next(
        node
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall)
        and SEGMENTED_LOAD_ADDRESS_TAG_8616 in node.tags
    )
    assert "inertia_source_instruction_addrs" not in helper.tags


def test_materialized_indexed_segmented_condition_keeps_address_and_access():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    condition = ConditionIR(
        op="sgt",
        lhs=IRValue(
            MemSpace.DS,
            offset=INDEXED_DATA_OFFSET,
            size=1,
            index=IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
            index_shift=1,
            memory_access_size=1,
            memory_access_insn=0x10AC8,
        ),
        rhs=IRValue(MemSpace.CONST, const=0, size=1),
        src_insn=0x10ACB,
        block_addr=0x10AC8,
        producer_insn=0x10AC9,
    )

    expression = materialize_condition_ir_expression_8616(project, codegen, condition)

    assert expression is not None
    helper = next(
        node
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall)
        and SEGMENTED_LOAD_ADDRESS_TAG_8616 in node.tags
    )
    address = helper.tags[SEGMENTED_LOAD_ADDRESS_TAG_8616]
    assert address.offset == INDEXED_DATA_OFFSET
    assert address.size == 1
    assert helper.tags["inertia_source_instruction_addrs"] == (0x10AC8,)


REACH_FUNC_ADDR = 0x2000
REACH_CALLSITE = 0x2000
REACH_BLOCK = 0x2003
REACH_PRODUCER = 0x2003
REACH_SRC = 0x2006


def _reach_decoded_block(address, predecessors, data):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    return RegisterSourceBlockEvidence8616(
        address,
        predecessors,
        tuple(
            SimpleNamespace(address=insn.address, mnemonic=insn.mnemonic, insn=insn)
            for insn in decoder.disasm(data, address)
        ),
    )


def _install_reach_inventory(monkeypatch, project, codegen, blocks, function_addr=REACH_FUNC_ADDR):
    evidence = tuple(_reach_decoded_block(*block) for block in blocks)
    count = len(evidence)
    inventory = RegisterSourceBlockInventory8616(
        function_addr, evidence, count, count, count, count, 0,
    )
    monkeypatch.setattr(
        register_inventory_owner,
        "collect_register_source_block_inventory_8616",
        lambda _function: inventory,
    )
    function = SimpleNamespace(addr=function_addr)
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda **_kw: function)
    )


def _temporary(codegen, tmp_id=4):
    return CVariable(
        SimTemporaryVariable(tmp_id, 2),
        variable_type=SimTypeShort(signed=False),
        codegen=codegen,
    )


def _word_insert_assignment(codegen, value, *, ins_addr, block_addr, variable=None):
    variable = variable or SimRegisterVariable(0, 4)
    preserved = CBinaryOp(
        "And",
        CVariable(variable, variable_type=SimTypeLong(signed=False), codegen=codegen),
        CConstant(0xFFFF0000, SimTypeLong(signed=False), codegen=codegen),
        codegen=codegen,
    )
    inserted = CBinaryOp(
        "And",
        value,
        CConstant(0xFFFF, SimTypeLong(signed=False), codegen=codegen),
        codegen=codegen,
    )
    return CAssignment(
        CVariable(variable, variable_type=SimTypeLong(signed=False), codegen=codegen),
        CBinaryOp("Or", preserved, inserted, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": ins_addr, "vex_block_addr": block_addr},
    )


def _reach_codegen(project, statements=()):
    codegen = _Codegen(project)
    codegen.cfunc = SimpleNamespace(
        addr=REACH_FUNC_ADDR,
        statements=CStatements(tuple(statements), codegen=codegen),
    )
    return codegen


def _reach_condition(operand_name="ax", size=2, producer=REACH_PRODUCER):
    return ConditionIR(
        "eq",
        IRValue(MemSpace.REG, name=operand_name, size=size),
        IRValue(MemSpace.CONST, const=897, size=2),
        width_bits=16,
        src_insn=REACH_SRC,
        block_addr=REACH_BLOCK,
        producer_insn=producer,
    )


def test_reaching_projection_binds_captured_call_result(monkeypatch):
    """A call-result word insert reaching the producer binds the capture temp."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    captured = _temporary(codegen)
    assignment = _word_insert_assignment(
        codegen, captured, ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR,
    )
    codegen.cfunc.statements = CStatements((assignment,), codegen=codegen)
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\x3d\x81\x03\x74\x05"),
        ),
    )
    condition = _reach_condition()

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2),
        condition,
        project,
        codegen,
    )

    assert result.expression is captured
    assert not any(
        isinstance(node, CFunctionCall)
        for node in _iter_c_nodes_deep_8616(result.expression)
    )

    expression = materialize_condition_ir_expression_8616(project, codegen, condition)
    assert expression is not None
    assert expression.op == "CmpEQ"
    assert expression.lhs is captured
    assert expression.rhs.value == 897


def test_reaching_projection_keeps_wide_temporary_word_mask(monkeypatch):
    """An AX condition observes low 16 bits of a wider captured result."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    captured = CVariable(
        SimTemporaryVariable(4, 4), variable_type=SimTypeLong(signed=False), codegen=codegen,
    )
    assignment = _word_insert_assignment(
        codegen, captured, ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR,
    )
    codegen.cfunc.statements = CStatements((assignment,), codegen=codegen)
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\x3d\x81\x03\x74\x05"),
        ),
    )
    expression = materialize_condition_ir_expression_8616(project, codegen, _reach_condition())
    assert expression is not None and expression.op == "CmpEQ"
    masked = expression.lhs
    assert isinstance(masked, CBinaryOp) and masked.op == "And"
    assert masked.lhs is captured and masked.rhs.value == 0xFFFF
    for value in (0, 897, 65536 + 897, 0xFFFFFFFF):
        assert ((value & masked.rhs.value) == expression.rhs.value) == ((value & 0xFFFF) == 897)


def test_reaching_projection_refuses_full_ax_clobber(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    captured = _temporary(codegen)
    codegen.cfunc.statements = CStatements(
        (_word_insert_assignment(codegen, captured, ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR),),
        codegen=codegen,
    )
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\xb8\x34\x12\x3d\x81\x03\x74\x05"),
        ),
    )
    condition = _reach_condition(producer=REACH_BLOCK + 3)

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2), condition, project, codegen,
    )
    assert result.expression is None


def test_reaching_projection_refuses_partial_ax_clobber(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    captured = _temporary(codegen)
    codegen.cfunc.statements = CStatements(
        (_word_insert_assignment(codegen, captured, ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR),),
        codegen=codegen,
    )
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\xb0\x12\x3d\x81\x03\x74\x05"),
        ),
    )
    condition = _reach_condition(producer=REACH_BLOCK + 2)

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2), condition, project, codegen,
    )
    assert result.expression is None


def test_reaching_projection_refuses_conflicting_predecessor_definitions(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    first = _word_insert_assignment(
        codegen, _temporary(codegen, 4), ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR,
    )
    second = _word_insert_assignment(
        codegen, _temporary(codegen, 7), ins_addr=0x3000, block_addr=0x3000,
    )
    codegen.cfunc.statements = CStatements((first, second), codegen=codegen)
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (0x1000, (), b"\x90"),
            (REACH_FUNC_ADDR, (0x1000,), b"\xe8\x00\x00"),
            (0x3000, (0x1000,), b"\xe8\x00\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR, 0x3000), b"\x3d\x81\x03\x74\x05"),
        ),
        function_addr=0x1000,
    )
    condition = _reach_condition()

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2), condition, project, codegen,
    )
    assert result.expression is None


def test_reaching_projection_refuses_unrepresented_predecessor_write(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    codegen.cfunc.statements = CStatements(
        (_word_insert_assignment(codegen, _temporary(codegen), ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR),),
        codegen=codegen,
    )
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (0x1000, (), b"\x90"),
            (REACH_FUNC_ADDR, (0x1000,), b"\xe8\x00\x00"),
            (0x3000, (0x1000,), b"\xb8\x99\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR, 0x3000), b"\x3d\x81\x03\x74\x05"),
        ),
        function_addr=0x1000,
    )
    condition = _reach_condition()

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2), condition, project, codegen,
    )
    assert result.expression is None


def test_reaching_projection_keeps_call_containing_lane_value_in_assignment(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    call = CFunctionCall("sub_2000", None, (), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        (_word_insert_assignment(codegen, call, ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR),),
        codegen=codegen,
    )
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\x3d\x81\x03\x74\x05"),
        ),
    )
    condition = _reach_condition()

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2), condition, project, codegen,
    )
    assert isinstance(result.expression, CBinaryOp) and result.expression.op == "And"
    assignment = codegen.cfunc.statements.statements[0]
    assert result.expression.lhs is assignment.lhs
    assert not any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(result.expression))
    assert sum(node is call for node in _iter_c_nodes_deep_8616(assignment)) == 1


def test_reaching_projection_refuses_stale_source_premise(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    codegen.cfunc.statements = CStatements(
        (_word_insert_assignment(codegen, _temporary(codegen), ins_addr=0x4000, block_addr=0x4000),),
        codegen=codegen,
    )
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
            (0x4000, (), b"\x90"),
            (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\x3d\x81\x03\x74\x05"),
        ),
    )
    condition = _reach_condition()

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2), condition, project, codegen,
    )
    assert result.expression is None


def test_reaching_projection_refuses_width_mismatch(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    codegen.cfunc.statements = CStatements(
        (_word_insert_assignment(codegen, _temporary(codegen), ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR),),
        codegen=codegen,
    )
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\x3d\x81\x03\x74\x05"),
        ),
    )

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="dx", size=2),
        _reach_condition(),
        project,
        codegen,
    )
    assert result.expression is None


def test_reaching_projection_refuses_conflicting_same_addr_ssa(monkeypatch):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    first = _word_insert_assignment(
        codegen, _temporary(codegen, 4), ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR,
    )
    second = _word_insert_assignment(
        codegen, _temporary(codegen, 9), ins_addr=REACH_CALLSITE, block_addr=REACH_FUNC_ADDR,
    )
    codegen.cfunc.statements = CStatements((first, second), codegen=codegen)
    _install_reach_inventory(
        monkeypatch, project, codegen,
        (
            (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
            (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\x3d\x81\x03\x74\x05"),
        ),
    )
    condition = _reach_condition()

    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2), condition, project, codegen,
    )
    assert result.expression is None


@pytest.mark.parametrize("clobber,offset", [(b"", 0), (b"\xb0\x12", 0), (b"", 4)])
def test_reaching_projection_reads_low_word_of_stored_call_once(monkeypatch, clobber, offset):
    """A retained wide call carrier supplies AX only at its unique native definition."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    call = CFunctionCall("callee", None, (), codegen=codegen)
    stored = CVariable(SimRegisterVariable(offset, 4), variable_type=SimTypeLong(False), codegen=codegen)
    assignment = CAssignment(stored, call, codegen=codegen,
                             tags={"ins_addr": REACH_CALLSITE, "vex_block_addr": REACH_FUNC_ADDR})
    codegen.cfunc.statements = CStatements((assignment,), codegen=codegen)
    _install_reach_inventory(monkeypatch, project, codegen, (
        (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
        (REACH_BLOCK, (REACH_FUNC_ADDR,), clobber + b"\x3d\x81\x03\x74\x05"),
    ))
    result = materialize_reaching_register_projection_8616(
        IRValue(MemSpace.REG, name="ax", size=2),
        _reach_condition(producer=REACH_BLOCK + len(clobber)), project, codegen,
    )
    if clobber or offset:
        assert result.expression is None
        return
    assert isinstance(result.expression, CBinaryOp) and result.expression.op == "And"
    assert result.expression.lhs is stored and result.expression.rhs.value == 0xFFFF
    assert not any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(result.expression))
    assert assignment.rhs is call and codegen.cfunc.statements.statements == (assignment,)


def test_stored_low_word_signed_predicate_ignores_upper_half(monkeypatch):
    """The signed AX view casts masked storage before comparing 0xffff as -1."""
    from dataclasses import replace

    from angr.analyses.decompiler.structured_codegen.c import CTypeCast

    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    stored = CVariable(SimRegisterVariable(0, 4), variable_type=SimTypeLong(False), codegen=codegen)
    assignment = CAssignment(stored, CFunctionCall("callee", None, (), codegen=codegen), codegen=codegen,
                             tags={"ins_addr": REACH_CALLSITE, "vex_block_addr": REACH_FUNC_ADDR})
    codegen.cfunc.statements = CStatements((assignment,), codegen=codegen)
    _install_reach_inventory(monkeypatch, project, codegen, (
        (REACH_FUNC_ADDR, (), b"\xe8\x00\x00"),
        (REACH_BLOCK, (REACH_FUNC_ADDR,), b"\x3d\x00\x00\x7c\x05"),
    ))
    condition = replace(_reach_condition(), op="slt", rhs=IRValue(MemSpace.CONST, const=0, size=2))
    expression = materialize_condition_ir_expression_8616(project, codegen, condition)
    assert expression is not None and expression.op == "CmpLT"
    view = expression.lhs
    assert isinstance(view, CTypeCast) and isinstance(view.dst_type, SimTypeShort) and view.dst_type.signed
    masked = view.expr
    assert isinstance(masked, CBinaryOp) and masked.op == "And"
    assert masked.lhs is stored and masked.rhs.value == 0xFFFF
    for raw in (0xFFFF, 0x1234FFFF, 0xFFFFFFFF):
        word = raw & masked.rhs.value
        signed = word - 0x10000 if word & 0x8000 else word
        assert signed == -1 and signed < 0


@pytest.mark.parametrize("damage", [None, "missing", "partial", "call", "foreign", "late_write", "wrong_region"])
def test_loop_guard_reads_proven_runtime_storage(monkeypatch, damage):
    """A mutable runtime lane joins writes, but never missing or stale effects."""
    from inertia.lowering.gp_register_state import runtime_gp_expression_view_8616, runtime_gp_state_expr_8616

    project = SimpleNamespace(arch=Arch86_16())
    codegen = _reach_codegen(project)
    entry, update, compare = REACH_FUNC_ADDR, 0x3100, 0x3200
    first = runtime_gp_state_expr_8616("edx", codegen=codegen, function_addr=entry)
    second = runtime_gp_state_expr_8616("ecx" if damage == "foreign" else "edx", codegen=codegen, function_addr=entry)
    if damage == "wrong_region":
        first.variable.region = entry + 1
        second.variable.region = entry + 1
    statements = [CAssignment(first, CConstant(0, SimTypeLong(False), codegen=codegen),
                             codegen=codegen, tags={"ins_addr": entry, "vex_block_addr": entry})]
    if damage != "missing":
        statements.append(CAssignment(second, CBinaryOp("Add", second, CConstant(1, SimTypeLong(False), codegen=codegen), codegen=codegen),
                                      codegen=codegen, tags={"ins_addr": update, "vex_block_addr": update}))
    codegen.cfunc.statements = CStatements(statements, codegen=codegen)
    update_bytes = {"partial": b"\xfe\xc2", "call": b"\xe8\x00\x00"}.get(damage, b"\x42")
    late = b"\xba\x63\x00" if damage == "late_write" else b""
    _install_reach_inventory(monkeypatch, project, codegen, (
        (entry, (), b"\x31\xd2"),
        (update, (compare,), update_bytes),
        (compare, (entry, update), b"\x3b\x56\x04" + late + b"\x7c\x00"),
    ))
    condition = ConditionIR("slt", IRValue(MemSpace.REG, name="dx", size=2),
                            IRValue(MemSpace.CONST, const=6, size=2), width_bits=16,
                            producer_insn=compare, src_insn=compare + 3 + len(late), block_addr=compare)
    result = materialize_reaching_register_projection_8616(condition.lhs, condition, project, codegen)
    if damage is None:
        assert result.expression is not None
        view = runtime_gp_expression_view_8616(result.expression)
        assert view is not None and view.register_name == "dx"
    else:
        assert result.expression is None
