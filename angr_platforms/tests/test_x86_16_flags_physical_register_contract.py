"""Regressions for physical-register identity consumed by flag cleanup."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CFunctionCall,
    CIfElse,
    CStatements,
    CSwitchCase,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_flags import (
    _prune_overwritten_flag_assignments_8616,
    _prune_unused_flag_assignments_8616,
)


class _Codegen:
    """Provide the small structured-codegen contract needed by C AST nodes."""

    def __init__(self, project: SimpleNamespace) -> None:
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = project
        root = CStatements([], addr=0x4010, codegen=self)
        self.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    def next_idx(self, _name: str) -> int:
        """Return one deterministic C AST index."""
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        """Return one deterministic C AST node index."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Keep deterministic identifiers in focused tests."""
        return name


def _project() -> SimpleNamespace:
    """Build the owned project boundary needed by flag cleanup."""
    return SimpleNamespace(arch=Arch86_16())


def _register_vvar(
    project: SimpleNamespace,
    codegen: _Codegen,
    name: str,
    varid: int,
) -> CDirtyExpression:
    """Build a current-angr virtual variable with exact register identity."""
    reg_offset, reg_size = project.arch.registers[name]
    virtual = VirtualVariable(
        codegen.next_idx("ail_vvar"),
        varid,
        reg_size * 8,
        VirtualVariableCategory.REGISTER,
        oident=reg_offset,
    )
    return CDirtyExpression(virtual, codegen=codegen)


def _constant(codegen: _Codegen, value: int) -> CConstant:
    """Build one unsigned 16-bit C constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _install_statements(codegen: _Codegen, statements: list[object]) -> CStatements:
    """Install one focused function body on the test codegen."""
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    return root


def test_unused_flag_pruning_recognizes_virtual_register_oident() -> None:
    """An unread flags vvar must not survive because its identity is in oident."""
    project = _project()
    codegen = _Codegen(project)
    statement = CAssignment(
        _register_vvar(project, codegen, "flags", 12),
        _constant(codegen, 0x40),
        codegen=codegen,
    )
    root = _install_statements(codegen, [statement])

    changed = _prune_unused_flag_assignments_8616(project, codegen)

    assert changed is True
    assert root.statements == []


def test_unused_flag_pruning_keeps_read_virtual_register_oident() -> None:
    """A condition read through the same physical flags register stays live."""
    project = _project()
    codegen = _Codegen(project)
    write = CAssignment(
        _register_vvar(project, codegen, "flags", 12),
        _constant(codegen, 0x40),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "And",
        _register_vvar(project, codegen, "flags", 13),
        _constant(codegen, 0x40),
        codegen=codegen,
    )
    branch = CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)
    root = _install_statements(codegen, [write, branch])

    changed = _prune_unused_flag_assignments_8616(project, codegen)

    assert changed is False
    assert root.statements == [write, branch]


def test_overwritten_flag_pruning_recognizes_virtual_register_oident() -> None:
    """Dead overwritten flag chains reach a fixed point for real angr vvars."""
    project = _project()
    codegen = _Codegen(project)
    first_flags = _register_vvar(project, codegen, "flags", 12)
    second_flags = _register_vvar(project, codegen, "flags", 13)
    first = CAssignment(first_flags, _constant(codegen, 1), codegen=codegen)
    second = CAssignment(
        second_flags,
        CBinaryOp("Or", first_flags, _constant(codegen, 2), codegen=codegen),
        codegen=codegen,
    )
    root = _install_statements(codegen, [first, second])

    changed = _prune_overwritten_flag_assignments_8616(project, codegen)

    assert changed is True
    assert root.statements == []


def test_overwritten_flag_pruning_descends_into_switch_case() -> None:
    """A dead flags chain inside a switch arm must reach cleanup and vanish."""
    project = _project()
    codegen = _Codegen(project)
    first_flags = _register_vvar(project, codegen, "flags", 12)
    second_flags = _register_vvar(project, codegen, "flags", 13)
    first = CAssignment(first_flags, _constant(codegen, 1), codegen=codegen)
    second = CAssignment(
        second_flags,
        CBinaryOp("Or", first_flags, _constant(codegen, 2), codegen=codegen),
        codegen=codegen,
    )
    case_body = CStatements([first, second], codegen=codegen)
    switch = CSwitchCase(_constant(codegen, 84), [(84, case_body)], None, codegen=codegen)
    _install_statements(codegen, [switch])

    changed = _prune_overwritten_flag_assignments_8616(project, codegen)

    assert changed is True
    assert case_body.statements == []


@pytest.mark.parametrize("loop_type", [CWhileLoop, CDoWhileLoop])
def test_flag_definition_read_by_enclosing_loop_guard_survives(
    loop_type: type[CWhileLoop] | type[CDoWhileLoop],
) -> None:
    """The end of a nested block is not the end of a flag value's lifetime."""
    project = _project()
    codegen = _Codegen(project)
    flags = _register_vvar(project, codegen, "flags", 12)
    write = CAssignment(flags, _constant(codegen, 0x40), codegen=codegen)
    body = CStatements([write], codegen=codegen)
    guard = CBinaryOp("And", flags, _constant(codegen, 0x40), codegen=codegen)
    loop = loop_type(guard, body, codegen=codegen)
    _install_statements(codegen, [loop])

    assert _prune_overwritten_flag_assignments_8616(project, codegen) is False
    assert body.statements == [write]


def test_different_flag_ssa_definition_does_not_overwrite_captured_value() -> None:
    """A later physical FLAGS write cannot kill an earlier captured SSA read."""
    project = _project()
    codegen = _Codegen(project)
    first_flags = _register_vvar(project, codegen, "flags", 12)
    second_flags = _register_vvar(project, codegen, "flags", 13)
    first = CAssignment(first_flags, _constant(codegen, 1), codegen=codegen)
    second = CAssignment(second_flags, _constant(codegen, 2), codegen=codegen)
    branch = CIfElse([(first_flags, CStatements([], codegen=codegen))], codegen=codegen)
    root = _install_statements(codegen, [first, second, branch])

    _prune_overwritten_flag_assignments_8616(project, codegen)

    assert first in root.statements
    assert branch in root.statements


@pytest.mark.parametrize("rhs_kind", ["call", "opaque", "cycle"])
def test_unread_flags_cleanup_refuses_unproven_dead_evaluation(rhs_kind: str) -> None:
    """A dead destination does not prove its evaluation can be discarded."""
    project = _project()
    codegen = _Codegen(project)
    flags = _register_vvar(project, codegen, "flags", 12)
    if rhs_kind == "call":
        rhs = CFunctionCall("observe", None, [], codegen=codegen)
    elif rhs_kind == "opaque":
        rhs = CDirtyExpression(SimpleNamespace(), codegen=codegen)
    else:
        rhs = CBinaryOp("Or", flags, _constant(codegen, 1), codegen=codegen)
    write = CAssignment(flags, rhs, codegen=codegen)
    root = _install_statements(codegen, [write])

    assert _prune_overwritten_flag_assignments_8616(project, codegen) is False
    assert root.statements == [write]


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("same_vvar", [False, True])
def test_flag_identity_across_codegen_representations(reverse: bool, same_vvar: bool) -> None:
    """Exact vvar IDs bridge representations without conflating distinct SSA values."""
    project = _project()
    codegen = _Codegen(project)
    offset, size = project.arch.registers["flags"]
    variable = CVariable(SimRegisterVariable(offset, size, ident="ir_1"), vvar_id=12, codegen=codegen)
    virtual = _register_vvar(project, codegen, "flags", 12 if same_vvar else 13)
    lhs, read = (virtual, variable) if reverse else (variable, virtual)
    write = CAssignment(lhs, _constant(codegen, 1), codegen=codegen)
    branch = CIfElse([(read, CStatements([], codegen=codegen))], codegen=codegen)
    root = _install_statements(codegen, [write, branch])

    assert _prune_overwritten_flag_assignments_8616(project, codegen) is not same_vvar
    assert any(statement is write for statement in root.statements) is same_vvar


@pytest.mark.parametrize("with_vvar_ids", [False, True])
def test_shared_unified_flag_variable_preserves_definition(with_vvar_ids: bool) -> None:
    """Shared emitted storage remains live even when original SSA identities differ."""
    project = _project()
    codegen = _Codegen(project)
    offset, size = project.arch.registers["flags"]
    unified = SimRegisterVariable(offset, size, ident="ir_unified")
    lhs = CVariable(
        SimRegisterVariable(offset, size, ident="ir_1"), unified_variable=unified,
        vvar_id=12 if with_vvar_ids else None, codegen=codegen,
    )
    read = CVariable(
        SimRegisterVariable(offset, size, ident="ir_2"), unified_variable=unified,
        vvar_id=13 if with_vvar_ids else None, codegen=codegen,
    )
    write = CAssignment(lhs, _constant(codegen, 1), codegen=codegen)
    branch = CIfElse([(read, CStatements([], codegen=codegen))], codegen=codegen)
    root = _install_statements(codegen, [write, branch])

    assert _prune_overwritten_flag_assignments_8616(project, codegen) is False
    assert root.statements == [write, branch]


@pytest.mark.parametrize("assignment_target", [False, True])
@pytest.mark.parametrize("has_varid", [False, True])
def test_opaque_flag_consumer_refuses_cleanup(assignment_target: bool, has_varid: bool) -> None:
    """Opaque payloads cannot hide reads, including on non-plain assignment targets."""
    project = _project()
    codegen = _Codegen(project)
    flags = _register_vvar(project, codegen, "flags", 12)
    payload = SimpleNamespace(callee="observe_flags", operands=[flags.dirty])
    if has_varid:
        payload.varid = 99
    opaque = CDirtyExpression(payload, codegen=codegen)
    consumer = (
        CAssignment(opaque, _constant(codegen, 0), codegen=codegen)
        if assignment_target else CIfElse([(opaque, CStatements([], codegen=codegen))], codegen=codegen)
    )
    write = CAssignment(flags, _constant(codegen, 1), codegen=codegen)
    root = _install_statements(codegen, [write, consumer])

    assert _prune_overwritten_flag_assignments_8616(project, codegen) is False
    assert root.statements == [write, consumer]
