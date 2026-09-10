"""Focused tests for explicit packed-FLAGS runtime live-ins."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.status_flag_lift_context import StatusFlagLiftArtifact8616
from angr_platforms.X86_16.lowering import packed_flags_state
from angr_platforms.X86_16.postprocess.optimization.dce import _dead_code_elimination_8616

_PRESERVATION_SITE = 0x104


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


def test_packed_preservation_matches_rebased_instruction_address() -> None:
    """Typed lift evidence retains its original-to-slice linear delta."""
    artifact = StatusFlagLiftArtifact8616(
        0x1000,
        (),
        frozenset({0x13CE9}),
        0x12C93,
    )

    assert artifact.covers_packed_preservation_8616(0x1056)


@pytest.mark.parametrize("guard_kind", ["if", "while", "do-while"])
def test_packed_flags_live_in_expires_only_after_its_consumer(monkeypatch, guard_kind) -> None:
    """DCE retains a consumed FLAGS live-in and removes its dead chain atomically."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    incoming_flags = structured_c.CVariable(
        SimRegisterVariable(36, 2, ident="ir_9", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_flags = structured_c.CVariable(
        SimRegisterVariable(36, 2, ident="ir_11", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    update = structured_c.CAssignment(
        outgoing_flags,
        structured_c.CBinaryOp(
            "And",
            incoming_flags,
            structured_c.CConstant(0xF72A, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": _PRESERVATION_SITE},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([update], codegen=codegen),
    )
    monkeypatch.setattr(
        packed_flags_state,
        "active_status_flag_lift_artifact_8616",
        lambda _addr: SimpleNamespace(
            covers_packed_preservation_8616=lambda address: address == _PRESERVATION_SITE,
        ),
    )
    monkeypatch.setattr(packed_flags_state, "record_global_declaration_spec_8616", lambda *_args, **_kwargs: None)

    assert packed_flags_state.lower_packed_flags_live_in_8616(codegen) is True
    initializer = codegen.cfunc.statements.statements[0]
    assert isinstance(initializer, structured_c.CAssignment)
    assert isinstance(initializer.rhs, structured_c.CVariable)
    assert isinstance(initializer.rhs.variable, SimMemoryVariable)
    assert initializer.rhs.variable.name == "inertia_flags"
    assert isinstance(initializer.lhs, structured_c.CVariable)
    assert initializer.lhs.variable.ident == "ir_9"
    assert codegen._inertia_packed_flags_state_live_ins_8616 == (initializer.lhs, "ir_9")
    assert codegen.cfunc.statements.statements[1] is update

    condition = structured_c.CIfElse(
        [
            (
                structured_c.CBinaryOp(
                    "And",
                    outgoing_flags,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CStatements([], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    if guard_kind != "if":
        guard, body = condition.condition_and_nodes[0]
        loop_type = structured_c.CWhileLoop if guard_kind == "while" else structured_c.CDoWhileLoop
        condition = loop_type(guard, body, codegen=codegen)
    codegen.cfunc.statements.statements.append(condition)
    assert _dead_code_elimination_8616(codegen) is False
    assert codegen.cfunc.statements.statements == [initializer, update, condition]

    codegen.cfunc.statements.statements.remove(condition)
    codegen.cfunc.statements.statements.remove(update)
    assert _dead_code_elimination_8616(codegen) is True
    assert codegen.cfunc.statements.statements == []


def test_initializes_dirty_ssa_flags_identity_from_physical_view(monkeypatch) -> None:
    """angr dirty FLAGS carriers retain their exact SSA and register identity."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    incoming_flags = structured_c.CDirtyExpression(
        SimpleNamespace(varid=2, reg=36, bits=16),
        codegen=codegen,
    )
    outgoing_flags = structured_c.CDirtyExpression(
        SimpleNamespace(varid=5, reg=36, bits=16),
        codegen=codegen,
    )
    update = structured_c.CAssignment(
        outgoing_flags,
        structured_c.CBinaryOp(
            "And",
            incoming_flags,
            structured_c.CConstant(0xF72A, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": _PRESERVATION_SITE},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([update], codegen=codegen),
    )
    monkeypatch.setattr(
        packed_flags_state,
        "active_status_flag_lift_artifact_8616",
        lambda _addr: SimpleNamespace(
            covers_packed_preservation_8616=lambda address: address == _PRESERVATION_SITE,
        ),
    )
    monkeypatch.setattr(packed_flags_state, "record_global_declaration_spec_8616", lambda *_args, **_kwargs: None)

    assert packed_flags_state.lower_packed_flags_live_in_8616(codegen) is True
    initializer = codegen.cfunc.statements.statements[0]
    assert isinstance(initializer, structured_c.CAssignment)
    assert isinstance(initializer.lhs, structured_c.CDirtyExpression)
    assert initializer.lhs.dirty.varid == incoming_flags.dirty.varid
    assert isinstance(initializer.rhs, structured_c.CVariable)
    assert initializer.rhs.variable.name == "inertia_flags"


def test_initializes_flags_read_by_covered_non_flags_assignment(monkeypatch) -> None:
    """A covered partial-write helper RHS may expose FLAGS through temp assignments."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    incoming_flags = structured_c.CDirtyExpression(
        SimpleNamespace(varid=2, reg=36, bits=16),
        codegen=codegen,
    )
    temp = structured_c.CDirtyExpression(
        SimpleNamespace(varid=28, bits=8),
        codegen=codegen,
    )
    update_helper = structured_c.CAssignment(
        temp,
        structured_c.CBinaryOp(
            "And",
            incoming_flags,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": _PRESERVATION_SITE},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([update_helper], codegen=codegen),
    )
    monkeypatch.setattr(
        packed_flags_state,
        "active_status_flag_lift_artifact_8616",
        lambda _addr: SimpleNamespace(
            covers_packed_preservation_8616=lambda address: address == _PRESERVATION_SITE,
            packed_preservation_addresses=frozenset({_PRESERVATION_SITE}),
        ),
    )
    monkeypatch.setattr(packed_flags_state, "record_global_declaration_spec_8616", lambda *_args, **_kwargs: None)

    assert packed_flags_state.lower_packed_flags_live_in_8616(codegen) is True
    initializer = codegen.cfunc.statements.statements[0]
    assert isinstance(initializer, structured_c.CAssignment)
    assert isinstance(initializer.lhs, structured_c.CDirtyExpression)
    assert initializer.lhs.dirty.varid == incoming_flags.dirty.varid


def test_initializes_exact_flags_ssa_root_without_covered_owner(monkeypatch) -> None:
    """A FLAGS identity read but never defined in-function is an architectural live-in."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    incoming_flags = structured_c.CVariable(
        SimRegisterVariable(36, 2, ident="ir_5", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_flags = structured_c.CVariable(
        SimRegisterVariable(36, 2, ident="ir_4", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    update = structured_c.CAssignment(
        outgoing_flags,
        incoming_flags,
        codegen=codegen,
        tags={"ins_addr": 0x100},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([update], codegen=codegen),
    )
    monkeypatch.setattr(
        packed_flags_state,
        "active_status_flag_lift_artifact_8616",
        lambda _addr: SimpleNamespace(
            covers_packed_preservation_8616=lambda _address: False,
            packed_preservation_addresses=frozenset(),
            candidates=(),
        ),
    )
    monkeypatch.setattr(packed_flags_state, "record_global_declaration_spec_8616", lambda *_args, **_kwargs: None)

    assert packed_flags_state.lower_packed_flags_live_in_8616(codegen) is True
    initializer = codegen.cfunc.statements.statements[0]
    assert isinstance(initializer, structured_c.CAssignment)
    assert isinstance(initializer.lhs, structured_c.CVariable)
    assert initializer.lhs.variable.ident == "ir_5"


def test_initializes_unique_self_dependent_flags_root_without_coverage(monkeypatch) -> None:
    """A unique partial-FLAGS recurrence requires an explicit entry seed."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    loop_flags = structured_c.CVariable(
        SimRegisterVariable(36, 2, ident="ir_9", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    update = structured_c.CAssignment(
        loop_flags,
        structured_c.CBinaryOp(
            "Or",
            structured_c.CBinaryOp(
                "And",
                loop_flags,
                structured_c.CConstant(0xF72A, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(0x80, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=structured_c.CStatements([update], codegen=codegen),
    )
    monkeypatch.setattr(
        packed_flags_state,
        "active_status_flag_lift_artifact_8616",
        lambda _addr: SimpleNamespace(
            covers_packed_preservation_8616=lambda _address: False,
            packed_preservation_addresses=frozenset(),
            candidates=(),
        ),
    )
    monkeypatch.setattr(packed_flags_state, "record_global_declaration_spec_8616", lambda *_args, **_kwargs: None)

    assert packed_flags_state.lower_packed_flags_live_in_8616(codegen) is True
    initializer = codegen.cfunc.statements.statements[0]
    assert isinstance(initializer, structured_c.CAssignment)
    assert isinstance(initializer.lhs, structured_c.CVariable)
    assert initializer.lhs.variable.ident == "ir_9"
    assert isinstance(initializer.rhs, structured_c.CVariable)
    assert initializer.rhs.variable.name == "inertia_flags"
    assert codegen.cfunc.statements.statements[1] is update


def test_wraps_structured_branch_root_before_flags_initialization(monkeypatch) -> None:
    """A structured branch root still receives its architectural entry seed."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    incoming_flags = structured_c.CVariable(
        SimRegisterVariable(36, 2, ident="ir_31", region=0x100),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    use = structured_c.CAssignment(
        structured_c.CVariable(
            SimRegisterVariable(0, 2, ident="ir_37", region=0x100),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        incoming_flags,
        codegen=codegen,
        tags={"ins_addr": _PRESERVATION_SITE},
    )
    root = structured_c.CIfElse(
        [
            (
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                structured_c.CStatements([use], codegen=codegen),
            )
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=root)
    monkeypatch.setattr(
        packed_flags_state,
        "active_status_flag_lift_artifact_8616",
        lambda _addr: SimpleNamespace(
            covers_packed_preservation_8616=lambda address: address == _PRESERVATION_SITE,
            packed_preservation_addresses=frozenset({_PRESERVATION_SITE}),
            candidates=(),
        ),
    )
    monkeypatch.setattr(packed_flags_state, "record_global_declaration_spec_8616", lambda *_args, **_kwargs: None)

    assert packed_flags_state.lower_packed_flags_live_in_8616(codegen) is True
    assert isinstance(codegen.cfunc.statements, structured_c.CStatements)
    initializer, preserved_root = codegen.cfunc.statements.statements
    assert isinstance(initializer, structured_c.CAssignment)
    assert isinstance(initializer.lhs, structured_c.CVariable)
    assert initializer.lhs.variable.ident == "ir_31"
    assert preserved_root is root
