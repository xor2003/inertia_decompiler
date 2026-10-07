from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.structured_intrinsics import (
    lower_structured_insert_call_8616,
    lower_structured_insert_intrinsics_8616,
    prune_unused_structured_insert_intrinsics_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        root = CStatements([], codegen=self)
        self.cfunc = SimpleNamespace(statements=root)

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _constant(value: int, codegen: _DummyCodegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def test_unused_pure_insert_intrinsic_is_removed_before_c_emission() -> None:
    codegen = _DummyCodegen()
    insert = CFunctionCall("_INSERT", None, [_constant(3, codegen)], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(insert, codegen=codegen)],
        codegen=codegen,
    )

    changed = prune_unused_structured_insert_intrinsics_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_structured_intrinsic_lowering_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_complete_insert_intrinsic_lowers_to_exact_little_endian_bit_insert() -> None:
    codegen = _DummyCodegen()
    base = _constant(0x1234, codegen)
    offset = _constant(0, codegen)
    value = CFunctionCall("SEG_U8", None, [_constant(0, codegen), _constant(1, codegen)], codegen=codegen)
    insert = CFunctionCall("_INSERT", None, [base, offset, value], codegen=codegen)
    carrier = CVariable(SimRegisterVariable(0, 2, ident=1, region=0x1000), codegen=codegen)
    assignment = CAssignment(carrier, insert, codegen=codegen)
    codegen.cfunc.statements = CStatements([assignment], codegen=codegen)

    changed = lower_structured_insert_intrinsics_8616(codegen)

    assert changed is True
    lowered = assignment.rhs
    assert isinstance(lowered, CBinaryOp)
    assert lowered.op == "Or"
    assert isinstance(lowered.lhs, CBinaryOp)
    assert lowered.lhs.op == "And"
    assert lowered.lhs.rhs.value == 0xFF00
    assert isinstance(lowered.rhs, CBinaryOp)
    assert lowered.rhs.op == "And"
    assert lowered.rhs.rhs.value == 0xFF
    stats = codegen._inertia_structured_intrinsic_lowering_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_insert_intrinsic_uses_wider_result_type_after_base_is_narrowed() -> None:
    codegen = _DummyCodegen()
    base = CVariable(SimRegisterVariable(0, 1, ident=1, region=0x1000), codegen=codegen)
    offset = _constant(1, codegen)
    value = CConstant(0, SimTypeChar(False), codegen=codegen)
    insert = CFunctionCall("_INSERT", None, [base, offset, value], codegen=codegen)

    lowered = lower_structured_insert_call_8616(insert)

    assert isinstance(lowered, CBinaryOp)
    assert lowered.op == "Or"
    assert isinstance(lowered.lhs, CBinaryOp)
    assert lowered.lhs.rhs.value == 0xFF
    assert isinstance(lowered.rhs, CBinaryOp)
    assert lowered.rhs.op == "Shl"


def test_direct_unused_insert_expression_is_removed_from_statement_list() -> None:
    codegen = _DummyCodegen()
    insert = CFunctionCall("_INSERT", None, [_constant(3, codegen)], codegen=codegen)
    codegen.cfunc.statements = CStatements([insert], codegen=codegen)

    changed = prune_unused_structured_insert_intrinsics_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements == []


def test_unused_insert_assignment_to_unread_exact_carrier_is_removed() -> None:
    codegen = _DummyCodegen()
    carrier = CVariable(SimRegisterVariable(0, 2, ident=1, region=0x1000), codegen=codegen)
    insert = CFunctionCall("_INSERT", None, [_constant(3, codegen)], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [CAssignment(carrier, insert, codegen=codegen)],
        codegen=codegen,
    )

    changed = prune_unused_structured_insert_intrinsics_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements == []


def test_insert_assignment_with_exact_carrier_read_is_retained() -> None:
    codegen = _DummyCodegen()
    register = SimRegisterVariable(0, 2, ident=1, region=0x1000)
    carrier_lhs = CVariable(register, codegen=codegen)
    carrier_read = CVariable(register, codegen=codegen)
    insert = CFunctionCall("_INSERT", None, [_constant(3, codegen)], codegen=codegen)
    assignment = CAssignment(carrier_lhs, insert, codegen=codegen)
    read_statement = CExpressionStatement(carrier_read, codegen=codegen)
    codegen.cfunc.statements = CStatements([assignment, read_statement], codegen=codegen)

    changed = prune_unused_structured_insert_intrinsics_8616(codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements == [assignment, read_statement]


def test_insert_assignment_with_shared_carrier_node_read_is_retained() -> None:
    codegen = _DummyCodegen()
    carrier = CVariable(SimRegisterVariable(0, 2, ident=1, region=0x1000), codegen=codegen)
    insert = CFunctionCall("_INSERT", None, [_constant(3, codegen)], codegen=codegen)
    assignment = CAssignment(carrier, insert, codegen=codegen)
    read_statement = CExpressionStatement(carrier, codegen=codegen)
    codegen.cfunc.statements = CStatements([assignment, read_statement], codegen=codegen)

    changed = prune_unused_structured_insert_intrinsics_8616(codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements == [assignment, read_statement]


def test_insert_intrinsic_with_effectful_argument_is_retained() -> None:
    codegen = _DummyCodegen()
    effectful_argument = CFunctionCall("sub_1234", None, [], codegen=codegen)
    insert = CFunctionCall("_INSERT", None, [effectful_argument], codegen=codegen)
    statement = CExpressionStatement(insert, codegen=codegen)
    codegen.cfunc.statements = CStatements([statement], codegen=codegen)

    changed = prune_unused_structured_insert_intrinsics_8616(codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements == [statement]
    stats = codegen._inertia_structured_intrinsic_lowering_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
