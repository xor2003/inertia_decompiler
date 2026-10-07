"""Regress exact consumed-PUSH lowering for late structured lvalue shapes."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CIndexedVariable,
    CStatements,
    CStructField,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    prune_consumed_call_push_stack_assignments_8616,
)
from capstone.x86_const import X86_INS_MOV, X86_INS_PUSH


class _Codegen:
    """Minimal structured-codegen boundary needed by C AST fixtures."""

    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
        self.cstyle_null_cmp = False
        root = CStatements([], addr=0x4010, codegen=self)
        self.cfunc = SimpleNamespace(
            addr=0x4010,
            statements=root,
            body=root,
            arg_list=[],
            variables_in_use={},
            unified_local_vars={},
        )

    def next_idx(self, _name: str) -> int:
        """Return a stable synthetic C AST index."""
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _dirty(
    codegen: _Codegen,
    ident: int,
    *,
    ins_addr: int | None = None,
) -> CDirtyExpression:
    """Build one unresolved angr virtual-value carrier."""
    dirty = SimpleNamespace(varid=ident)
    if ins_addr is not None:
        dirty.tags = {"ins_addr": ins_addr}
    return CDirtyExpression(dirty, codegen=codegen)


def _dereference_store(codegen: _Codegen, ins_addr: int) -> CAssignment:
    """Mirror the late ``*(vvar + vvar) = vvar`` PUSH artifact."""
    address = CBinaryOp(
        "Add",
        _dirty(codegen, 1),
        _dirty(codegen, 2),
        codegen=codegen,
    )
    return CAssignment(
        CUnaryOp("Dereference", address, codegen=codegen),
        _dirty(codegen, 3),
        codegen=codegen,
        tags={"ins_addr": ins_addr},
    )


def _function_with_instruction(ins_addr: int, instruction_id: int) -> SimpleNamespace:
    """Build exact decoded instruction provenance for one lowering fixture."""
    return SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(SimpleNamespace(address=ins_addr, id=instruction_id),),
                ),
            ),
        ),
    )


def _indexed_global_field(codegen: _Codegen, *, field_offset: int = 0) -> CVariableField:
    """Build one indexed global struct-field value like a recovered call argument."""
    char_type = SimTypeChar(False)
    entry_type = SimStruct(
        {"field_0": char_type, "field_1": char_type},
        name="entry",
    )
    base = CVariable(
        SimMemoryVariable(0xB4C, 2, name="g_entries"),
        variable_type=entry_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    indexed = CIndexedVariable(base, index, variable_type=entry_type, codegen=codegen)
    return CVariableField(
        indexed,
        CStructField(
            entry_type,
            field_offset,
            f"field_{field_offset}",
            codegen=codegen,
        ),
        codegen=codegen,
    )


def test_consumed_push_prunes_unresolved_dereference_stack_effect() -> None:
    codegen = _Codegen()
    push_addr = 0x4016
    artifact = _dereference_store(codegen, push_addr)
    codegen.cfunc.statements.statements.append(artifact)

    changed = prune_consumed_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
        frozenset({push_addr}),
        function=_function_with_instruction(push_addr, X86_INS_PUSH),
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_consumed_push_prunes_cast_wrapped_high_byte_stack_carrier() -> None:
    codegen = _Codegen()
    push_addr = 0x4016
    word_type = SimTypeShort(False).with_arch(codegen.project.arch)
    byte_type = SimTypeChar(False).with_arch(codegen.project.arch)
    carrier = CVariable(
        SimStackVariable(-2, 2, base="bp", name="carrier", region=0x4010),
        variable_type=word_type,
        codegen=codegen,
    )
    argument = CVariable(
        SimStackVariable(6, 2, base="bp", name="argument", region=0x4010),
        variable_type=word_type,
        codegen=codegen,
    )
    artifact = CAssignment(
        CTypeCast(
            word_type,
            byte_type,
            CBinaryOp(
                "Shr",
                carrier,
                CConstant(8, word_type, codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        argument,
        codegen=codegen,
        tags={"ins_addr": push_addr},
    )
    codegen.cfunc.statements.statements.append(artifact)

    changed = prune_consumed_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
        frozenset({push_addr}),
        materialized_args_by_push_instruction_addr={push_addr: (argument,)},
        function=_function_with_instruction(push_addr, X86_INS_PUSH),
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []


def test_consumed_push_keeps_unresolved_dereference_without_push_provenance() -> None:
    codegen = _Codegen()
    mov_addr = 0x4018
    artifact = _dereference_store(codegen, mov_addr)
    codegen.cfunc.statements.statements.append(artifact)

    changed = prune_consumed_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
        frozenset({mov_addr}),
        function=_function_with_instruction(mov_addr, X86_INS_MOV),
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [artifact]
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_consumed_push_uses_exact_nested_lvalue_provenance_after_outer_retag() -> None:
    codegen = _Codegen()
    push_addr = 0x4016
    call_addr = 0x4018
    address = CBinaryOp(
        "Add",
        _dirty(codegen, 1, ins_addr=push_addr),
        _dirty(codegen, 2, ins_addr=push_addr),
        codegen=codegen,
    )
    artifact = CAssignment(
        CUnaryOp("Dereference", address, codegen=codegen),
        _dirty(codegen, 3),
        codegen=codegen,
        tags={"ins_addr": call_addr},
    )
    codegen.cfunc.statements.statements.append(artifact)

    changed = prune_consumed_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
        frozenset({push_addr}),
        function=_function_with_instruction(push_addr, X86_INS_PUSH),
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.raw_fact_count == stats.normalized_fact_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0


def test_consumed_push_refuses_ambiguous_nested_lvalue_provenance() -> None:
    codegen = _Codegen()
    first_push_addr = 0x4016
    second_push_addr = 0x4017
    address = CBinaryOp(
        "Add",
        _dirty(codegen, 1, ins_addr=first_push_addr),
        _dirty(codegen, 2, ins_addr=second_push_addr),
        codegen=codegen,
    )
    artifact = CAssignment(
        CUnaryOp("Dereference", address, codegen=codegen),
        _dirty(codegen, 3),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    codegen.cfunc.statements.statements.append(artifact)
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(
            SimpleNamespace(
                addr=0x4010,
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(address=first_push_addr, id=X86_INS_PUSH),
                        SimpleNamespace(address=second_push_addr, id=X86_INS_PUSH),
                    )
                ),
            ),
        ),
    )

    changed = prune_consumed_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
        frozenset({first_push_addr, second_push_addr}),
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [artifact]
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 0
    assert stats.classified_fact_count == stats.materialized_count == 0
    assert stats.failure_count == 1


def test_consumed_push_prunes_global_field_value_repeated_by_call_argument() -> None:
    codegen = _Codegen()
    push_addr = 0x4016
    pushed_value = _indexed_global_field(codegen)
    materialized_arg = _indexed_global_field(codegen)
    artifact = _dereference_store(codegen, push_addr)
    artifact.rhs = pushed_value
    codegen.cfunc.statements.statements.append(artifact)

    changed = prune_consumed_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
        frozenset({push_addr}),
        materialized_args_by_push_instruction_addr={push_addr: (materialized_arg,)},
        function=_function_with_instruction(push_addr, X86_INS_PUSH),
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_consumed_push_keeps_global_field_value_not_present_in_call_arguments() -> None:
    codegen = _Codegen()
    push_addr = 0x4016
    artifact = _dereference_store(codegen, push_addr)
    artifact.rhs = _indexed_global_field(codegen)
    codegen.cfunc.statements.statements.append(artifact)

    changed = prune_consumed_call_push_stack_assignments_8616(
        codegen.project,
        codegen,
        frozenset({push_addr}),
        materialized_args_by_push_instruction_addr={
            push_addr: (CConstant(7, SimTypeShort(False), codegen=codegen),)
        },
        function=_function_with_instruction(push_addr, X86_INS_PUSH),
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [artifact]
    stats = codegen._inertia_consumed_call_push_carrier_prune_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
