from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering import real_mode_linear
from angr_platforms.X86_16.lowering.assignment_lvalue_casts import (
    AssignmentLvalueCastStats8616,
    normalize_scalar_assignment_lvalues_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc: object | None = None

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _assignment_codegen(*, cast_type: object) -> tuple[_Codegen, structured_c.CVariable]:
    codegen = _Codegen()
    storage_type = SimTypeShort(False).with_arch(codegen.project.arch)
    variable = structured_c.CVariable(
        SimStackVariable(-4, 1, base="bp", name="local_4"),
        variable_type=storage_type,
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        structured_c.CTypeCast(
            storage_type,
            cast_type,
            variable,
            codegen=codegen,
        ),
        structured_c.CConstant(0xFF, storage_type, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([assignment], codegen=codegen)
    )
    return codegen, variable


def test_equal_width_scalar_assignment_cast_becomes_direct_lvalue() -> None:
    codegen, variable = _assignment_codegen(
        cast_type=SimTypeChar(True).with_arch(Arch86_16())
    )

    assert normalize_scalar_assignment_lvalues_8616(codegen) is True
    assignment = codegen.cfunc.statements.statements[0]
    assert assignment.lhs is variable
    assert codegen._inertia_assignment_lvalue_cast_stats_8616 == AssignmentLvalueCastStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def test_width_mismatched_assignment_cast_is_refused() -> None:
    codegen, _variable = _assignment_codegen(
        cast_type=SimTypeShort(False).with_arch(Arch86_16())
    )

    assert normalize_scalar_assignment_lvalues_8616(codegen) is False
    assignment = codegen.cfunc.statements.statements[0]
    assert isinstance(assignment.lhs, structured_c.CTypeCast)
    assert codegen._inertia_assignment_lvalue_cast_stats_8616.failure_count == 1


@pytest.mark.parametrize("write", [False, True])
def test_stack_lowering_requests_lvalues_only_for_assignment_targets(monkeypatch, write):
    codegen = _Codegen()
    scalar_type = SimTypeShort(False).with_arch(codegen.project.arch)
    memory = structured_c.CUnaryOp(
        "Dereference", structured_c.CConstant(0x200, scalar_type, codegen=codegen), codegen=codegen,
    )
    scalar = structured_c.CConstant(7, scalar_type, codegen=codegen)
    destination = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp"), variable_type=scalar_type, codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        memory if write else destination, scalar if write else memory, codegen=codegen,
    )
    root = structured_c.CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000, statements=root, body=root, arg_list=[], variables_in_use={}, unified_local_vars={},
    )
    requests = []

    def materialize(_codegen, _access, *, require_lvalue=False, **_kwargs):
        requests.append(require_lvalue)
        return None if require_lvalue else scalar

    monkeypatch.setattr(real_mode_linear, "match_stable_ss_linear_stack_access_8616",
                        lambda *_args: real_mode_linear.RealModeLinearStackAccess8616(-2, 1))
    monkeypatch.setattr(real_mode_linear, "_has_stack_storage_evidence_for_displacement_8616", lambda *_args: True)
    monkeypatch.setattr(real_mode_linear, "stack_cvar_for_stable_ss_linear_access_8616", materialize)

    real_mode_linear.lower_stable_ss_linear_stack_dereferences_8616(codegen, project=codegen.project)

    assert requests == [write]
    assert assignment.lhs is (memory if write else destination)
    assert assignment.rhs is scalar
